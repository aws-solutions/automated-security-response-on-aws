// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { Logger } from '@aws-lambda-powertools/logger';
import { BulkEditRequest, SecurityControl } from '@asr/data-models';
import { ControlsRepository, BulkUpdateResult } from '../../common/repositories/controlsRepository';
import { Clock, getClock } from '../../common/utils/clock';
import { createDynamoDBClient } from '../../common/utils/dynamodb';
import { BadRequestError } from '../../common/utils/httpErrors';
import { sendMetrics } from '../../common/utils/metricsUtils';
import { apiLambdaEnvironment } from '../apiLambdaEnvironment';
import { computeRemediationToggle } from '../adminActivity/controlsDiff';
import { AdminActivityNotifier, AdminActorContext } from './adminActivityNotifier';

export { BulkUpdateResult };

export class ControlsService {
  private controlsRepository: ControlsRepository | undefined;

  constructor(
    private readonly logger: Logger,
    private readonly clock: Clock = getClock(),
    private readonly adminActivityNotifier: AdminActivityNotifier = new AdminActivityNotifier(logger),
  ) {}

  private getRepository(): ControlsRepository {
    if (!this.controlsRepository) {
      const tableName = apiLambdaEnvironment().REMEDIATION_CONFIG_TABLE_NAME;
      const dynamoDBClient = createDynamoDBClient({ maxAttempts: 10 });
      this.controlsRepository = new ControlsRepository(tableName, dynamoDBClient);
    }

    return this.controlsRepository;
  }

  async getAllControls(): Promise<{ controls: SecurityControl[] }> {
    const controls = await this.getRepository().findAll();

    this.logger.info('Successfully retrieved security controls', { count: controls.length });

    return { controls };
  }

  /**
   * Returns the current automated-remediation state for the given control ids, keyed by control id.
   * Reads only the requested controls so the cost scales with the request, not the whole table.
   */
  async getRemediationStateByControlIds(controlIds: string[]): Promise<Map<string, boolean>> {
    return this.getRepository().findRemediationStateByControlIds(controlIds);
  }

  /**
   * Executes a bulk-edit request end to end: performs the requested mutation and emits the admin
   * notification for any security-critical change — a real automated-remediation toggle, or a
   * filter applied/removed across all controls. Only changes that took effect are reported:
   * controls that failed the update are excluded, and filter operations notify only when at least
   * one control was affected. Control updates additionally emit the `control_configuration_changes`
   * metric. The notifier is fail-open, so a notification failure never fails the bulk edit.
   */
  async processBulkEdit(request: BulkEditRequest, actor: AdminActorContext): Promise<BulkUpdateResult> {
    if (request.operation === 'update') {
      // Read just the requested controls (not a full table scan) so the remediation decision below
      // can compare the update against the prior state.
      const previousRemediationByControlId = await this.getRemediationStateByControlIds(
        request.data.map((control) => control.controlId),
      );

      const result = await this.bulkUpdateControls(request.data, actor.actorEmail);

      const failedIds = new Set(result.failedControlIds);
      const successfulControls = request.data.filter((control) => !failedIds.has(control.controlId));

      if (successfulControls.length > 0) {
        await sendMetrics({
          control_configuration_changes: successfulControls.map((control) => ({
            control_id: control.controlId,
            control_enabled: control.automatedRemediationEnabled,
            filters_applied: control.filters?.length ?? 0,
          })),
        });

        const remediationToggle = computeRemediationToggle(successfulControls, previousRemediationByControlId);
        if (remediationToggle) {
          await this.adminActivityNotifier.notify({
            action: remediationToggle.action,
            actorEmail: actor.actorEmail,
            actorGroups: actor.actorGroups,
            resourceType: 'control',
            affectedControlCount: remediationToggle.affectedControlCount,
          });
        }
      }

      return result;
    }

    if (request.operation === 'applyFilterToAll') {
      const result = await this.applyFilterToAllControls(request.data, actor.actorEmail);
      await this.notifyBulkFilterChange(actor, result.successCount);
      return result;
    }

    if (request.operation === 'removeFilterFromAll') {
      const result = await this.removeFilterFromAllControls(request.data, actor.actorEmail);
      await this.notifyBulkFilterChange(actor, result.successCount);
      return result;
    }

    throw new BadRequestError('Unsupported bulk-edit operation');
  }

  private async notifyBulkFilterChange(actor: AdminActorContext, affectedControlCount: number): Promise<void> {
    if (affectedControlCount === 0) return;
    await this.adminActivityNotifier.notify({
      action: 'BULK_FILTER_CHANGE',
      actorEmail: actor.actorEmail,
      actorGroups: actor.actorGroups,
      resourceType: 'control',
      affectedControlCount,
    });
  }

  async bulkUpdateControls(controls: SecurityControl[], modifiedBy: string): Promise<BulkUpdateResult> {
    const lastModified = this.clock.now().toISOString();

    this.logger.info('Starting bulk update of controls', {
      count: controls.length,
      modifiedBy,
    });

    const result = await this.getRepository().bulkUpdateControls(controls, modifiedBy, lastModified);

    this.logger.info('Bulk update completed', {
      successCount: result.successCount,
      failedCount: result.failedControlIds.length,
    });

    return result;
  }

  async applyFilterToAllControls(filterId: string, modifiedBy: string): Promise<BulkUpdateResult> {
    const lastModified = this.clock.now().toISOString();

    this.logger.info('Starting apply filter to all controls', {
      filterId,
      modifiedBy,
    });

    const result = await this.getRepository().applyFilterToAllControls(filterId, modifiedBy, lastModified);

    this.logger.info('Apply filter to all controls completed', {
      successCount: result.successCount,
      failedCount: result.failedControlIds.length,
    });

    return result;
  }

  async findControlsUsingFilter(filterId: string): Promise<string[]> {
    return this.getRepository().findControlsUsingFilter(filterId);
  }

  async removeFilterFromAllControls(filterId: string, modifiedBy: string): Promise<BulkUpdateResult> {
    const lastModified = this.clock.now().toISOString();

    this.logger.info('Starting remove filter from all controls', {
      filterId,
      modifiedBy,
    });

    const result = await this.getRepository().removeFilterFromAllControls(filterId, modifiedBy, lastModified);

    this.logger.info('Remove filter from all controls completed', {
      successCount: result.successCount,
      failedCount: result.failedControlIds.length,
    });

    return result;
  }
}
