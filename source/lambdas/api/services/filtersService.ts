// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { Logger } from '@aws-lambda-powertools/logger';
import { ConditionalCheckFailedException } from '@aws-sdk/client-dynamodb';
import { DynamoDBDocumentClient } from '@aws-sdk/lib-dynamodb';
import {
  CreateFilterRequest,
  NotificationConfigurationItem,
  ResourceFilter,
  UpdateFilterRequest,
} from '@asr/data-models';
import { FiltersRepository } from '../../common/repositories/filtersRepository';
import { NotificationConfigurationRepository } from '../../common/repositories/notificationConfigurationRepository';
import { NotificationBatchRepository } from '../../common/repositories/notificationBatchRepository';
import { getClock } from '../../common/utils/clock';
import { createDynamoDBClient } from '../../common/utils/dynamodb';
import { BadRequestError, ConflictError, VersionConflictError } from '../../common/utils/httpErrors';
import { getIdGenerator } from '../../common/utils/idGenerator';
import { isEnforcementEnabledConfig } from '../../common/utils/remediationDeadline';
import { apiLambdaEnvironment } from '../apiLambdaEnvironment';
import { ControlsService } from './controlsService';

export interface DeleteFilterResult {
  /**
   * False when the filter row was not removed: either it never existed, or some controls still
   * reference it (`stillAttachedControlIds`) and deleting it would leave dangling references.
   */
  deleted: boolean;
  /** True when no filter existed under the id, so there was nothing to detach or delete. */
  alreadyAbsent: boolean;
  /**
   * Controls this request detached the filter from. When `deleted` is false these controls have
   * still been widened — the filter no longer narrows their remediation scope — which is why the
   * caller must be told about them rather than shown a single "not deleted" message.
   */
  detachedControlIds: string[];
  /** Controls that still reference the filter after this request (their detach lost a version check). */
  stillAttachedControlIds: string[];
}

export class FiltersService {
  private dynamoDBClient: DynamoDBDocumentClient | undefined;
  private filtersRepository: FiltersRepository | undefined;
  private notificationConfigurationRepository: NotificationConfigurationRepository | undefined;
  private notificationBatchRepository: NotificationBatchRepository | undefined;

  constructor(
    private readonly logger: Logger,
    private readonly controlsService: ControlsService,
  ) {}

  private getDynamoDBClient(): DynamoDBDocumentClient {
    this.dynamoDBClient ??= createDynamoDBClient({ maxAttempts: 10 });
    return this.dynamoDBClient;
  }

  private getRepository(): FiltersRepository {
    this.filtersRepository ??= new FiltersRepository(
      apiLambdaEnvironment().RESOURCE_FILTERS_TABLE_NAME,
      this.getDynamoDBClient(),
    );
    return this.filtersRepository;
  }

  private getNotificationConfigurationRepository(): NotificationConfigurationRepository {
    this.notificationConfigurationRepository ??= new NotificationConfigurationRepository(
      apiLambdaEnvironment().NOTIFICATION_CONFIG_TABLE_NAME,
      this.getDynamoDBClient(),
    );
    return this.notificationConfigurationRepository;
  }

  /**
   * Lazily constructs the NotificationBatches repository used to enqueue reconciliation tasks,
   * mirroring {@link NotificationConfigurationService}. Returns `undefined` when the table name is
   * absent — deployments where the API Lambda is not granted access to the table — so callers treat
   * that as "reconciliation unavailable" and skip gracefully.
   */
  private getNotificationBatchRepository(): NotificationBatchRepository | undefined {
    const tableName = apiLambdaEnvironment().NOTIFICATION_BATCHES_TABLE_NAME;
    if (!tableName) return undefined;
    this.notificationBatchRepository ??= new NotificationBatchRepository(
      'FiltersService',
      tableName,
      this.getDynamoDBClient(),
    );
    return this.notificationBatchRepository;
  }

  private async validateFilterNameUniqueness(name: string, excludeFilterId?: string): Promise<void> {
    const existingFilters = await this.getRepository().findByName(name);
    const conflict = existingFilters.find((f) => f.filterId !== excludeFilterId);
    if (conflict) {
      throw new BadRequestError(`A filter with the name "${name}" already exists`);
    }
  }

  async getAllFilters(): Promise<{ filters: ResourceFilter[] }> {
    const filters = await this.getRepository().findAll();

    this.logger.info('Successfully retrieved resource filters', { count: filters.length });

    return { filters };
  }

  async createFilter(request: CreateFilterRequest, createdBy: string): Promise<ResourceFilter> {
    const filterId = getIdGenerator().randomUUID();
    const createdAt = getClock().now().toISOString();

    await this.validateFilterNameUniqueness(request.name);

    this.logger.info('Creating resource filter', { filterId, createdBy });

    try {
      const filter = await this.getRepository().createFilter(filterId, request, createdBy, createdAt);

      this.logger.info('Successfully created resource filter', { filterId });

      return filter;
    } catch (error) {
      if (error instanceof ConditionalCheckFailedException) {
        throw new ConflictError('A filter with this ID already exists');
      }
      throw error;
    }
  }

  async updateFilter(filterId: string, request: UpdateFilterRequest, modifiedBy: string): Promise<ResourceFilter> {
    const lastModified = getClock().now().toISOString();

    await this.validateFilterNameUniqueness(request.name, filterId);

    this.logger.info('Updating resource filter', { filterId, modifiedBy });

    let updatedFilter: ResourceFilter;
    try {
      updatedFilter = await this.getRepository().updateFilter(filterId, request, modifiedBy, lastModified);
    } catch (error) {
      // The repository distinguishes absent (NotFoundError, propagates as 404) from stale
      // (VersionConflictError). Only the latter is a conflict; re-throw it in the same
      // machine-readable shape the notification service uses so the caller can see the
      // version it must refresh to.
      if (error instanceof VersionConflictError) {
        throw new ConflictError('Data was modified by another user, please refresh', {
          code: 'VERSION_CONFLICT',
          context: { filterId, expectedVersion: request.version, currentVersion: error.currentVersion },
        });
      }
      throw error;
    }

    this.logger.info('Successfully updated resource filter', { filterId });

    // Best-effort reconciliation. Kept outside the conditional-write try/catch so a reconciliation
    // failure can never be mis-reported as a version conflict or fail an already-successful update.
    await this.enqueueFilterChangeReconciliation(filterId);

    return updatedFilter;
  }

  /**
   * Enqueues a `filterChange` reconciliation task for every enforcement-enabled notification
   * configuration that applies this resource filter, so deadline enforcement re-evaluates the
   * affected findings against the filter's new definition (stamping newly-matching findings and
   * clearing those that no longer match). The config itself is unchanged, so the task carries the
   * live config as both snapshots; the reconciliation engine treats structurally-identical snapshots
   * as a filter-definition change and re-evaluates every targeted finding.
   *
   * Best-effort: the filter write has already succeeded, so a missing table name or a per-config
   * write failure is logged and swallowed rather than failing the API request. Non-enforcing configs
   * are skipped because they contribute no deadline stamps.
   */
  private async enqueueFilterChangeReconciliation(filterId: string): Promise<void> {
    const batchRepository = this.getNotificationBatchRepository();
    if (!batchRepository) {
      this.logger.warn('NotificationBatches table name unavailable; skipping filter change reconciliation', {
        filterId,
      });
      return;
    }

    let affectedConfigs: NotificationConfigurationItem[];
    try {
      affectedConfigs = await this.getNotificationConfigurationRepository().findByResourceFilterId(filterId);
    } catch (error) {
      this.logger.warn('Failed to load notification configurations for filter change reconciliation', {
        filterId,
        error,
      });
      return;
    }

    const enforcingConfigs = affectedConfigs.filter(isEnforcementEnabledConfig);
    if (enforcingConfigs.length === 0) return;

    for (const config of enforcingConfigs) {
      try {
        const task = await batchRepository.createReconciliationTask('filterChange', config, config);
        this.logger.info('Created filterChange reconciliation task for resource filter update', {
          filterId,
          configId: config.configId,
          reconciliationTaskId: task.configId,
        });
      } catch (error) {
        this.logger.warn('Failed to create filterChange reconciliation task for resource filter update', {
          filterId,
          configId: config.configId,
          error,
        });
      }
    }
  }

  /**
   * Which controls still reference the filter after a detach that refused some writes.
   *
   * `removeFilterFromAllControls` runs across every control, so a refused write on a control that
   * never carried the filter is noise (a transient conflict on an unrelated row) and must not
   * block the delete. But a control that was *not* in the pre-detach scan can still be attached:
   * a concurrent request may have added the filter after the scan, which bumps that control's
   * version and refuses the detach for exactly that reason. Intersecting with the scan alone
   * dropped that case and deleted the filter out from under the new attachment.
   *
   * So: a refused control that the scan knew about is still attached, full stop. A refused
   * control the scan did not know about is re-read strongly consistently and counted only if it
   * carries the filter now. A re-read that fails propagates, so the delete never proceeds on
   * evidence it could not gather.
   */
  private async controlsStillReferencing(
    filterId: string,
    attachedBefore: readonly string[],
    failedControlIds: readonly string[],
  ): Promise<string[]> {
    const known = new Set(attachedBefore);
    const unknown = failedControlIds.filter((controlId) => !known.has(controlId));
    if (unknown.length === 0) return [...failedControlIds];

    const stillUsingSet = new Set(await this.controlsService.controlsStillUsingFilter(filterId, unknown));
    return failedControlIds.filter((controlId) => known.has(controlId) || stillUsingSet.has(controlId));
  }

  /**
   * Detaches the filter from every control that references it, then deletes the filter row.
   *
   * The two steps are not one transaction, and the first can partially succeed: a control whose
   * detach loses its version check keeps the filter while its siblings have already been
   * widened. The filter is then deliberately left in place — deleting it would leave the
   * still-attached controls pointing at a filter that no longer exists — but the widening has
   * already happened, so the result names the detached controls explicitly rather than folding
   * everything into "not deleted". The split starts from the transaction result — the controls
   * whose conditional write failed — refined by {@link controlsStillReferencing} for controls
   * the pre-detach scan did not know about.
   *
   * Before the row is removed, a strongly consistent scan re-checks that nothing references the
   * filter any more, catching a control attached after the detach completed. That narrows the
   * remaining window to the instant between that scan and the delete; it cannot be closed from
   * here, because the controls and filters tables are not written in one transaction and the
   * attach path does not itself check that the filter row exists. An attach landing in that
   * instant leaves a dangling reference, exactly as an attach after a completed delete does.
   */
  async deleteFilter(filterId: string, deletedBy: string): Promise<DeleteFilterResult> {
    this.logger.info('Deleting resource filter', { filterId, deletedBy });

    const attachedBefore = await this.controlsService.findControlsUsingFilter(filterId);

    if (attachedBefore.length > 0) {
      const result = await this.controlsService.removeFilterFromAllControls(filterId, deletedBy);

      this.logger.info('Removed filter from associated controls', {
        filterId,
        successCount: result.successCount,
        failedCount: result.failedControlIds.length,
      });

      const stillAttachedControlIds = await this.controlsStillReferencing(
        filterId,
        attachedBefore,
        result.failedControlIds,
      );

      if (stillAttachedControlIds.length > 0) {
        const stillAttached = new Set(stillAttachedControlIds);
        const detachedControlIds = attachedBefore.filter((controlId) => !stillAttached.has(controlId));

        this.logger.warn('Some controls still reference the filter after detaching; filter not deleted', {
          filterId,
          detachedControlIds,
          stillAttachedControlIds,
        });

        return { deleted: false, alreadyAbsent: false, detachedControlIds, stillAttachedControlIds };
      }
    }

    // Last look before the irreversible step. Strongly consistent, so an attach that landed
    // after the detach transaction (which produced no refused write to notice) is seen here.
    const attachedNow = await this.controlsService.findControlsUsingFilter(filterId, { consistent: true });
    if (attachedNow.length > 0) {
      this.logger.warn('Controls attached the filter after it was detached; filter not deleted', {
        filterId,
        stillAttachedControlIds: attachedNow,
      });
      return {
        deleted: false,
        alreadyAbsent: false,
        detachedControlIds: attachedBefore,
        stillAttachedControlIds: attachedNow,
      };
    }

    const { deleted } = await this.getRepository().deleteFilter(filterId);

    if (deleted) {
      this.logger.info('Successfully deleted resource filter', { filterId, detachedControlIds: attachedBefore });
    } else if (attachedBefore.length > 0) {
      // Dangling references: the row was already gone but controls still pointed at it, and this
      // request cleaned those up. That is real work, so it must not read as a no-op.
      this.logger.info('Resource filter row was already absent; detached its dangling references', {
        filterId,
        detachedControlIds: attachedBefore,
      });
    } else {
      this.logger.info('Resource filter was already absent; nothing to delete', { filterId });
    }

    return {
      deleted,
      alreadyAbsent: !deleted && attachedBefore.length === 0,
      detachedControlIds: attachedBefore,
      stillAttachedControlIds: [],
    };
  }
}
