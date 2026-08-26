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
import { BadRequestError, ConflictError } from '../../common/utils/httpErrors';
import { getIdGenerator } from '../../common/utils/idGenerator';
import { isEnforcementEnabledConfig } from '../../common/utils/remediationDeadline';
import { apiLambdaEnvironment } from '../apiLambdaEnvironment';
import { ControlsService } from './controlsService';

export interface DeleteFilterResult {
  affectedControlIds: string[];
  failedControlIds: string[];
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
      if (error instanceof ConditionalCheckFailedException) {
        throw new ConflictError('Data was modified by another user, please refresh');
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

  async deleteFilter(filterId: string, deletedBy: string): Promise<DeleteFilterResult> {
    this.logger.info('Deleting resource filter', { filterId, deletedBy });

    const affectedControlIds = await this.controlsService.findControlsUsingFilter(filterId);

    if (affectedControlIds.length > 0) {
      const result = await this.controlsService.removeFilterFromAllControls(filterId, deletedBy);

      this.logger.info('Removed filter from associated controls', {
        filterId,
        successCount: result.successCount,
        failedCount: result.failedControlIds.length,
      });

      if (result.failedControlIds.length > 0) {
        this.logger.warn('Some controls failed to update during filter deletion, filter not deleted', {
          filterId,
          failedControlIds: result.failedControlIds,
        });

        return { affectedControlIds, failedControlIds: result.failedControlIds };
      }
    }

    await this.getRepository().deleteFilter(filterId);

    this.logger.info('Successfully deleted resource filter', { filterId, affectedControlIds });

    return { affectedControlIds, failedControlIds: [] };
  }
}
