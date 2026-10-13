// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { Logger } from '@aws-lambda-powertools/logger';
import { BulkEditRequest, SecurityControl, ROLLBACK_ELIGIBLE_FINDING_TYPES } from '@asr/data-models';
import { ControlsRepository, BulkUpdateResult } from '../../common/repositories/controlsRepository';
import { CustomRunbookRepository, DeployedRunbookControl } from '../../common/repositories/customRunbookRepository';
import { Clock, getClock } from '../../common/utils/clock';
import { createDynamoDBClient } from '../../common/utils/dynamodb';
import { BadRequestError, ServiceUnavailableError } from '../../common/utils/httpErrors';
import { sendMetrics } from '../../common/utils/metricsUtils';
import { apiLambdaEnvironment, optionalCustomRunbookEnvironment } from '../apiLambdaEnvironment';
import { computeRemediationToggle, computeRollbackToggle } from '../adminActivity/controlsDiff';
import { AdminActivityNotifier, AdminActorContext } from './adminActivityNotifier';

export { BulkUpdateResult };

export class ControlsService {
  private controlsRepository: ControlsRepository | undefined;
  private customRunbookRepository: CustomRunbookRepository | undefined;

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

  private getCustomRunbookRepository(): CustomRunbookRepository | undefined {
    if (!this.customRunbookRepository) {
      const config = optionalCustomRunbookEnvironment();
      if (!config) return undefined;
      const dynamoDBClient = createDynamoDBClient({ maxAttempts: 10 });
      this.customRunbookRepository = new CustomRunbookRepository(config.tableName, dynamoDBClient);
    }
    return this.customRunbookRepository;
  }

  async getAllControls(): Promise<{ controls: (SecurityControl & { rollbackSupported: boolean })[] }> {
    // Every control the config table holds — built-ins AND any custom-runbook control that
    // has already been persisted there. Named for that rather than for built-ins, since the
    // `source === 'custom'` branch below only makes sense because custom rows are included.
    const persistedControls = await this.getRepository().findAll();
    const persistedControlIds = new Set(persistedControls.map((c) => c.controlId));

    // The live deployed version per custom control, chosen by deployment recency (see
    // loadDeployedCustomRunbookVersions). Two consumers need it: a control not yet in the
    // config table is synthesized from it, and a custom control already persisted in the
    // table is enriched with its runbookVersion — without this the persisted row is a
    // custom control that never reports which version actually runs.
    const deployedVersionByControlId = await this.loadDeployedCustomRunbookVersions();

    const persistedWithVersion = persistedControls.map((control) => {
      // Enrich only genuine custom rows: a built-in must never inherit a custom runbook's
      // version (the deploy preflight prevents that collision, but this keeps the read side
      // correct regardless).
      if (control.source !== 'custom') return control;
      const runbookVersion = deployedVersionByControlId.get(control.controlId)?.version;
      return runbookVersion === undefined ? control : { ...control, runbookVersion };
    });

    const synthesizedCustomControls = this.synthesizeCustomControls(deployedVersionByControlId, persistedControlIds);
    const allControls = [...persistedWithVersion, ...synthesizedCustomControls];

    this.logger.info('Successfully retrieved security controls', {
      count: allControls.length,
    });

    return {
      controls: allControls.map((control) => ({
        ...control,
        rollbackSupported: ROLLBACK_ELIGIBLE_FINDING_TYPES.has(control.controlId),
      })),
    };
  }

  /**
   * The live deployed runbook per custom control, keyed by control id.
   *
   * One control can have several DEPLOYED versions (deploying a new version does not demote
   * the previous one, and a rollback re-deploys an older version). The live one is the most
   * recently DEPLOYED — ordered by `deployedAt`, then version as a tiebreak — which matches
   * how the Orchestrator's `_select_current_deployed_runbook` resolves it. Ordering by
   * version number instead would name the rolled-back version as current after a rollback.
   *
   * A custom-runbook read failure degrades to an empty map (built-ins only) rather than
   * failing the whole controls list, which every access tier depends on.
   */
  private async loadDeployedCustomRunbookVersions(): Promise<Map<string, DeployedRunbookControl>> {
    const customRepo = this.getCustomRunbookRepository();
    if (!customRepo) return new Map();

    try {
      const liveByControlId = new Map<string, DeployedRunbookControl>();
      for (const runbook of await customRepo.findDeployedVersions()) {
        const current = liveByControlId.get(runbook.controlId);
        if (!current || this.isMoreRecentlyDeployed(runbook, current)) {
          liveByControlId.set(runbook.controlId, runbook);
        }
      }
      return liveByControlId;
    } catch (error) {
      this.logger.warn('Failed to fetch custom runbooks for controls list', {
        error: error instanceof Error ? error.message : String(error),
      });
      return new Map();
    }
  }

  /**
   * Deployment-recency ordering matching the Orchestrator's `_select_current_deployed_runbook`
   * key, `(deployedAt or createdAt, version, runbookId)`, applied with `max`. `||` rather than
   * `??` so that an empty-string deployedAt falls through to createdAt exactly as Python's `or`
   * does, and runbookId as the final tiebreak so a full tie resolves deterministically to the
   * same record on both sides — never to whichever the scan returned first. The two orderings
   * must agree on every record or the console and the resolver could name different live
   * versions.
   */
  private isMoreRecentlyDeployed(candidate: DeployedRunbookControl, current: DeployedRunbookControl): boolean {
    const candidateRecency = candidate.deployedAt || candidate.createdAt || '';
    const currentRecency = current.deployedAt || current.createdAt || '';
    if (candidateRecency !== currentRecency) return candidateRecency > currentRecency;
    if (candidate.version !== current.version) return candidate.version > current.version;
    return candidate.runbookId > current.runbookId;
  }

  /**
   * Custom controls to add to the list because a deployed runbook serves them and neither
   * the built-in table nor a persisted config row already represents them.
   */
  private synthesizeCustomControls(
    deployedVersionByControlId: Map<string, DeployedRunbookControl>,
    existingControlIds: Set<string>,
  ): SecurityControl[] {
    return [...deployedVersionByControlId.values()]
      .filter((runbook) => !existingControlIds.has(runbook.controlId))
      .map(
        (runbook): SecurityControl => ({
          controlId: runbook.controlId,
          description: runbook.description || `Custom runbook for ${runbook.controlId}`,
          automatedRemediationEnabled: false,
          filters: [],
          filterMode: 'include',
          version: 0,
          lastModified: runbook.createdAt || this.clock.now().toISOString(),
          modifiedBy: runbook.createdBy || 'custom-runbook',
          source: 'custom',
          runbookVersion: runbook.version,
        }),
      );
  }

  /**
   * Returns the current automated-remediation state for the given control ids, keyed by control id.
   * Reads only the requested controls so the cost scales with the request, not the whole table.
   */
  async getRemediationStateByControlIds(controlIds: string[]): Promise<Map<string, boolean>> {
    return this.getRepository().findRemediationStateByControlIds(controlIds);
  }

  async getRollbackStateByControlIds(controlIds: string[]): Promise<Map<string, boolean>> {
    return this.getRepository().findRollbackStateByControlIds(controlIds);
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
      return this.processControlUpdates(request.data, actor);
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

  /**
   * The `update` operation: refuse what must not be written, write the rest, then report the
   * changes that took effect.
   *
   * Split out of {@link processBulkEdit} so that method stays a dispatcher over the three
   * operations rather than one long branch.
   */
  private async processControlUpdates(
    controls: SecurityControl[],
    actor: AdminActorContext,
  ): Promise<BulkUpdateResult> {
    // Read just the requested controls (not a full table scan) so the toggle decisions below
    // can compare the update against the prior state.
    const controlIds = controls.map((control) => control.controlId);
    // All three reads hit the same keys; issue them concurrently rather than serialising the round-trips.
    const [previousRemediationByControlId, previousRollbackByControlId, customControlLookup] = await Promise.all([
      this.getRemediationStateByControlIds(controlIds),
      this.getRollbackStateByControlIds(controlIds),
      this.getRepository().findCustomControlIds(controlIds),
    ]);

    // Refuse the whole update rather than decide the guard below on a partial read. A control
    // missing from an incomplete answer reads as built-in, so carrying on would enable
    // automated remediation for exactly the custom control the guard exists to refuse —
    // failing open. Retryable, since the read is the thing that fell short.
    if (!customControlLookup.isComplete) {
      throw new ServiceUnavailableError(
        'Could not determine which controls are served by a custom runbook; please retry the update.',
      );
    }
    const customControlIds = customControlLookup.customControlIds;

    // A custom runbook only ever runs on a manual trigger, so enabling automated
    // remediation for one stores a flag the resolver ignores — the console would read
    // "Enabled" while nothing is remediated. Refused here rather than in the Web UI
    // alone, because the MCP `update_controls` tool reaches this same route.
    //
    // Gated on the TRANSITION into enabled, not the submitted value: the UI resends the
    // whole SecurityControl on every save, so a custom control enabled before this guard
    // existed still carries automatedRemediationEnabled: true when the operator edits only
    // its filters or rollback. Rejecting on the value alone would make such a control
    // permanently uneditable. Disabling and no-op edits stay allowed; only a false→true
    // flip on a custom control is refused.
    const rejectedControlIds = controls
      .filter(
        (control) =>
          control.automatedRemediationEnabled &&
          !previousRemediationByControlId.get(control.controlId) &&
          customControlIds.has(control.controlId),
      )
      .map((control) => control.controlId);
    if (rejectedControlIds.length > 0) {
      this.logger.warn('Refusing to enable automated remediation for custom-runbook controls', {
        controlIds: rejectedControlIds,
        actor: actor.actorEmail,
      });
    }

    // Everything else in the batch still applies: one custom control must not block a
    // bulk edit over built-ins.
    const updatableControls = controls.filter((control) => !rejectedControlIds.includes(control.controlId));
    const writeResult =
      updatableControls.length > 0
        ? await this.bulkUpdateControls(updatableControls, actor.actorEmail)
        : { successCount: 0, failedControlIds: [] };
    const result: BulkUpdateResult = {
      successCount: writeResult.successCount,
      failedControlIds: [...writeResult.failedControlIds, ...rejectedControlIds],
      ...(rejectedControlIds.length > 0 ? { rejectedControlIds } : {}),
    };

    const failedIds = new Set(result.failedControlIds);
    const successfulControls = controls.filter((control) => !failedIds.has(control.controlId));
    await this.reportAppliedControlUpdates(
      successfulControls,
      actor,
      previousRemediationByControlId,
      previousRollbackByControlId,
    );

    return result;
  }

  /**
   * Emit the metric and the admin notifications for updates that actually took effect.
   *
   * Only the applied subset is passed in, so a control that failed its write is never
   * reported as a change. Both notifications are fail-open in the notifier, so neither can
   * fail the bulk edit that already succeeded.
   */
  private async reportAppliedControlUpdates(
    appliedControls: SecurityControl[],
    actor: AdminActorContext,
    previousRemediationByControlId: Map<string, boolean>,
    previousRollbackByControlId: Map<string, boolean>,
  ): Promise<void> {
    if (appliedControls.length === 0) return;

    await sendMetrics({
      control_configuration_changes: appliedControls.map((control) => ({
        control_id: control.controlId,
        control_enabled: control.automatedRemediationEnabled,
        rollback_enabled: control.rollbackEnabled !== false,
        filters_applied: control.filters?.length ?? 0,
      })),
    });

    const toggles = [
      computeRemediationToggle(appliedControls, previousRemediationByControlId),
      computeRollbackToggle(appliedControls, previousRollbackByControlId),
    ];
    for (const toggle of toggles) {
      if (!toggle) continue;
      await this.adminActivityNotifier.notify({
        action: toggle.action,
        actorEmail: actor.actorEmail,
        actorGroups: actor.actorGroups,
        resourceType: 'control',
        affectedControlCount: toggle.affectedControlCount,
      });
    }
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

  async findControlsUsingFilter(filterId: string, options: { consistent?: boolean } = {}): Promise<string[]> {
    return this.getRepository().findControlsUsingFilter(filterId, options);
  }

  /** Strongly consistent: which of `controlIds` still list `filterId` right now. */
  async controlsStillUsingFilter(filterId: string, controlIds: readonly string[]): Promise<string[]> {
    return this.getRepository().controlsStillUsingFilter(filterId, controlIds);
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
