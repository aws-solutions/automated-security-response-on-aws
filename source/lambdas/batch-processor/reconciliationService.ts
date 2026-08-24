// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import type { Logger } from '@aws-lambda-powertools/logger';
import type {
  FindingTableItem,
  NormalizedFinding,
  NotificationConfigurationItem,
  ReconciliationTask,
} from '@asr/data-models';
import { FindingRepository, OverdueFindingProjection } from '../common/repositories/findingRepository';
import { NotificationConfigurationRepository } from '../common/repositories/notificationConfigurationRepository';
import { Clock, getClock } from '../common/utils/clock';
import { ErrorUtils } from '../common/utils/errorUtils';
import { extractASFFFinding } from '../common/utils/findingExtraction';
import { controlIdToFindingType } from '../common/utils/findingUtils';
import { computeRemediationDueBy, isEnforcementEnabledConfig } from '../common/utils/remediationDeadline';
import { asffToNormalized } from '../pre-processor/Normalizer/findingMappers';
import { FilterDefinitionCache, ResourceFilterEvaluator } from '../pre-processor/ResourceFilterEvaluator';

/**
 * Default ceiling on the number of findings a single reconciliation task may process within one
 * Batch Processor invocation. Bounding the work ensures reconciliation never starves notification
 * batch processing or overdue remediation; any overflow resumes on the next invocation.
 */
export const DEFAULT_RECONCILIATION_FINDING_LIMIT = 500;

/**
 * Maximum number of findings within a single page processed concurrently. Findings in a page are
 * distinct items and their writes are idempotent and independent, so they can be reconciled in
 * parallel to cut the wall-clock cost of the per-finding DynamoDB round-trips. The bound keeps
 * concurrent writes well within DynamoDB's burst capacity and avoids unbounded fan-out.
 */
const RECONCILIATION_WRITE_CONCURRENCY = 20;

/**
 * Reserved bookmark `controlId` marking a task that is walking every stamped finding via the
 * sparse `remediationDueBy-GSI` (the scan-all mode used for match-all configurations) rather than a
 * specific control's partition. The leading null byte cannot collide with a real `findingType`, so
 * {@link ReconciliationService.runSegments} never mistakes it for a control segment and the
 * scan-all resume path can recognise its own bookmark unambiguously.
 */
export const SCAN_ALL_BOOKMARK_CONTROL_ID = '\u0000scan-all';

/**
 * Outcome of a single {@link ReconciliationService.processTask} invocation. The Batch Processor
 * handler uses this to persist the task's progress: it adds `itemsProcessed` to the
 * task's running `itemCount`, and either marks the task COMPLETED (`isComplete`) or saves
 * `lastProcessedKey` and leaves it IN_PROGRESS for the next invocation.
 */
export interface ReconciliationResult {
  /** True when every targeted finding has been processed; false when the per-invocation limit was hit. */
  isComplete: boolean;
  /** Number of findings examined during this invocation. */
  itemsProcessed: number;
  /** Bookmark to resume from on the next invocation. Present only when `isComplete` is false. */
  lastProcessedKey?: Record<string, unknown>;
}

/**
 * Resume position within a reconciliation task. `controlId` identifies which control's findings
 * were being walked; `exclusiveStartKey` is the DynamoDB pagination key within that control's
 * query (absent means start from the beginning of the control).
 */
interface ReconciliationBookmark {
  controlId: string;
  exclusiveStartKey?: Record<string, unknown>;
}

/**
 * A unit of reconciliation work for one control ID: how to query its findings and what to do with
 * each. The four task types are expressed as ordered lists of these segments, which lets a single
 * bounded engine ({@link ReconciliationService.runSegments}) drive every scenario and resume
 * mid-task from a bookmark.
 */
interface ReconciliationSegment {
  controlId: string;
  /** When true, the query restricts the page to `NOT_STARTED` findings (used when stamping new matches). */
  onlyNotStarted: boolean;
  handleFinding: (finding: FindingTableItem) => Promise<void>;
}

/**
 * The subset of finding fields the clear/recompute handlers need. Both the full {@link
 * FindingTableItem} (controlId path) and the lightweight {@link OverdueFindingProjection} (match-all
 * scan-all path) satisfy this shape, so the same handlers drive both paths without the scan-all path
 * ever fetching the base-table item or decompressing `findingJSON`.
 */
type ReconcilableFinding = Pick<
  FindingTableItem,
  'findingId' | 'findingType' | 'creationTime' | 'enforcementConfigIds'
>;

/**
 * Reconciles findings' `remediationDueBy` and `enforcementConfigIds` when a notification
 * configuration's enforcement settings change. Driven by {@link ReconciliationTask}s written to the
 * NotificationBatches table by the API and picked up by the Batch Processor.
 *
 * Four task types are handled (see {@link processTask}): `enable`, `disable`, `deadlineChange`, and
 * `filterChange`. Every scenario reads **live** configuration state from DynamoDB for value
 * computation — the task's `oldConfig`/`newConfig` snapshots are used only to determine which
 * control IDs to query and what changed — so reconciliation converges to the correct state
 * regardless of the order in which rapid config changes are processed.
 */
export class ReconciliationService {
  /** Per-invocation cache of live config reads, reset at the start of each {@link processTask}. */
  private liveConfigCache = new Map<string, Promise<NotificationConfigurationItem | null>>();

  /**
   * Per-invocation cache of resource-filter definition lookups, reset at the start of each
   * {@link processTask}. A control's findings are all evaluated against the same config's filter
   * set, so caching the definition fetch turns N per-finding DynamoDB reads into one.
   */
  private filterDefinitionCache: FilterDefinitionCache = new Map();

  constructor(
    private readonly findingRepository: FindingRepository,
    private readonly notificationConfigurationRepository: NotificationConfigurationRepository,
    private readonly resourceFilterEvaluator: ResourceFilterEvaluator,
    private readonly logger: Logger,
    private readonly clock: Clock = getClock(),
    private readonly maxFindingsPerInvocation: number = DEFAULT_RECONCILIATION_FINDING_LIMIT,
  ) {}

  /**
   * Reconciles findings affected by a single configuration change, bounded to
   * {@link maxFindingsPerInvocation} findings. Dispatches on the task type to build an ordered list
   * of control-scoped segments, then runs them through the shared bounded engine.
   */
  async processTask(task: ReconciliationTask): Promise<ReconciliationResult> {
    this.liveConfigCache = new Map();
    this.filterDefinitionCache = new Map();
    const bookmark = this.decodeBookmark(task.lastProcessedKey);

    this.logger.info('Processing reconciliation task', {
      configId: task.configId,
      taskType: task.taskType,
      resuming: bookmark !== undefined,
    });

    switch (task.taskType) {
      case 'enable':
        return this.processEnable(task, bookmark);
      case 'disable':
        return this.processDisable(task, bookmark);
      case 'deadlineChange':
        return this.processDeadlineChange(task, bookmark);
      case 'filterChange':
        return this.processFilterChange(task, bookmark);
    }
  }

  /**
   * Enforcement was switched on for a configuration. Stamp every matching `NOT_STARTED` finding
   * under the config's control IDs. The shortest-deadline-wins conditional `stampRemediationDueBy`
   * keeps the value correct when other configs already contributed.
   */
  private async processEnable(
    task: ReconciliationTask,
    bookmark: ReconciliationBookmark | undefined,
  ): Promise<ReconciliationResult> {
    const configId = task.newConfig?.configId ?? task.oldConfig?.configId;
    if (!configId) {
      this.logger.warn('enable task has no configuration snapshot; nothing to reconcile');
      return completed();
    }

    const liveConfig = await this.loadLiveConfig(configId);
    if (!liveConfig || !isEnforcementEnabledConfig(liveConfig)) {
      this.logger.info('Config is no longer enforcement-enabled; nothing to enable', { configId });
      return completed();
    }

    const controlIds = uniqueValues(liveConfig.controlIds ?? []);
    if (controlIds.length === 0) {
      this.logger.warn('Config matches all controls (empty controlIds); targeted enable reconciliation skipped', {
        configId,
      });
      return completed();
    }

    const segments = controlIds.map((controlId) => this.buildStampSegment(controlId, liveConfig));
    return this.runSegments(segments, bookmark);
  }

  /**
   * Enforcement was switched off, the config was disabled, or the config was deleted. Remove the
   * config ID from every finding that references it and either clear `remediationDueBy` (no other
   * configs contribute) or recompute it from the remaining live configs.
   */
  private async processDisable(
    task: ReconciliationTask,
    bookmark: ReconciliationBookmark | undefined,
  ): Promise<ReconciliationResult> {
    const snapshot = task.oldConfig ?? task.newConfig;
    if (!snapshot) {
      this.logger.warn('disable task has no configuration snapshot; nothing to reconcile');
      return completed();
    }

    const controlIds = uniqueValues(snapshot.controlIds ?? []);
    if (controlIds.length === 0) {
      this.logger.info('Disabled config matches all controls (empty controlIds); enumerating stamped findings', {
        configId: snapshot.configId,
      });
      return this.runScanAll((finding) => this.removeConfigFromFinding(finding, snapshot.configId), bookmark);
    }

    const segments = controlIds.map((controlId) => this.buildRemoveConfigSegment(controlId, snapshot.configId));
    return this.runSegments(segments, bookmark);
  }

  /**
   * The deadline day count changed. Recompute `remediationDueBy` for every finding that references
   * the config, taking the minimum across all of the finding's currently contributing live configs.
   */
  private async processDeadlineChange(
    task: ReconciliationTask,
    bookmark: ReconciliationBookmark | undefined,
  ): Promise<ReconciliationResult> {
    const configId = task.newConfig?.configId ?? task.oldConfig?.configId;
    if (!configId) {
      this.logger.warn('deadlineChange task has no configuration snapshot; nothing to reconcile');
      return completed();
    }

    const liveConfig = await this.loadLiveConfig(configId);
    const controlIds = uniqueValues(
      liveConfig?.controlIds ?? task.newConfig?.controlIds ?? task.oldConfig?.controlIds ?? [],
    );
    if (controlIds.length === 0) {
      this.logger.info('Config matches all controls (empty controlIds); enumerating stamped findings', {
        configId,
      });
      return this.runScanAll((finding) => this.recalculateContributingFinding(finding, configId), bookmark);
    }

    const segments = controlIds.map((controlId) => this.buildRecalculateSegment(controlId, configId));
    return this.runSegments(segments, bookmark);
  }

  /**
   * The config's control IDs and/or resource filters changed. To avoid re-querying every control,
   * the diff is computed at the control-ID level:
   * - removed controls: remove the config ID from their findings (and recompute/clear);
   * - added controls: stamp matching `NOT_STARTED` findings;
   * - unchanged controls (only when resource filters changed): re-evaluate, stamping newly matching
   *   findings and clearing those that no longer match.
   */
  private async processFilterChange(
    task: ReconciliationTask,
    bookmark: ReconciliationBookmark | undefined,
  ): Promise<ReconciliationResult> {
    const { oldConfig, newConfig } = task;
    if (!oldConfig || !newConfig) {
      this.logger.warn('filterChange task requires both old and new snapshots; nothing to reconcile');
      return completed();
    }

    const configId = newConfig.configId;
    const oldControlIds = new Set(oldConfig.controlIds);
    const newControlIds = new Set(newConfig.controlIds);

    // When the config is (or just became) match-all, its findings span arbitrary controlIds, so a
    // per-control query cannot reach them. Walk every stamped finding via the GSI and perform the
    // CLEAR side only — remove this config and clear/recompute the deadline. Newly-matching findings
    // are intentionally left to write-time stamping and the Synchronization Lambda refresh.
    if (oldControlIds.size === 0 || newControlIds.size === 0) {
      this.logger.info('filterChange targets a match-all config; enumerating stamped findings to clear', {
        configId,
      });
      return this.runScanAll((finding) => this.removeConfigFromFinding(finding, configId), bookmark);
    }

    const removedControlIds = uniqueValues(oldConfig.controlIds ?? []).filter(
      (controlId) => !newControlIds.has(controlId),
    );
    const addedControlIds = uniqueValues(newConfig.controlIds ?? []).filter(
      (controlId) => !oldControlIds.has(controlId),
    );
    const resourceFiltersChanged = !sameStringSet(oldConfig.resourceFilterIds ?? [], newConfig.resourceFilterIds ?? []);
    // A filterChange task whose snapshots are structurally identical (same controlIds and same
    // resourceFilterIds) is only ever enqueued when an applied resource filter's *definition*
    // changed while the config itself did not — the config-update path never enqueues a filterChange
    // without a controlIds or resourceFilterIds diff. In that case every retained control must be
    // re-evaluated against the now-changed live filters, so treat them all as needing re-evaluation.
    const filterDefinitionChanged =
      removedControlIds.length === 0 && addedControlIds.length === 0 && !resourceFiltersChanged;
    const reevaluateControlIds =
      resourceFiltersChanged || filterDefinitionChanged
        ? uniqueValues(newConfig.controlIds ?? []).filter((controlId) => oldControlIds.has(controlId))
        : [];

    const liveConfig = await this.loadLiveConfig(configId);
    const isEnforcing = liveConfig !== undefined && isEnforcementEnabledConfig(liveConfig);

    // Removed controls are processed first so the ordered list (and therefore bookmark resumption)
    // is deterministic across invocations.
    const segments: ReconciliationSegment[] = removedControlIds.map((controlId) =>
      this.buildRemoveConfigSegment(controlId, configId),
    );

    if (isEnforcing && liveConfig) {
      segments.push(
        ...addedControlIds.map((controlId) => this.buildStampSegment(controlId, liveConfig)),
        ...reevaluateControlIds.map((controlId) => this.buildReevaluateSegment(controlId, liveConfig)),
      );
    } else if (addedControlIds.length > 0 || reevaluateControlIds.length > 0) {
      this.logger.info('Config is no longer enforcement-enabled; only removed controls are reconciled', { configId });
    }

    return this.runSegments(segments, bookmark);
  }

  /**
   * Bounded engine shared by all four scenarios. Walks the ordered segments, paging each control's
   * findings, and stops once {@link maxFindingsPerInvocation} findings have been examined — saving a
   * bookmark so the next invocation resumes exactly where this one stopped. Reconciliation writes
   * are idempotent, so the at-most-once-page overlap that a resumed bookmark can cause is safe.
   */
  private async runSegments(
    segments: ReconciliationSegment[],
    startBookmark: ReconciliationBookmark | undefined,
  ): Promise<ReconciliationResult> {
    let processed = 0;

    let startIndex = 0;
    let initialStartKey = startBookmark?.exclusiveStartKey;
    if (startBookmark) {
      const bookmarkedIndex = segments.findIndex((segment) => segment.controlId === startBookmark.controlId);
      if (bookmarkedIndex >= 0) {
        startIndex = bookmarkedIndex;
      } else {
        // The bookmarked control is no longer part of the work (config changed again); restart cleanly.
        initialStartKey = undefined;
      }
    }

    for (let index = startIndex; index < segments.length; index++) {
      const segment = segments[index];
      let exclusiveStartKey = index === startIndex ? initialStartKey : undefined;

      do {
        if (processed >= this.maxFindingsPerInvocation) {
          return {
            isComplete: false,
            itemsProcessed: processed,
            lastProcessedKey: this.encodeBookmark({ controlId: segment.controlId, exclusiveStartKey }),
          };
        }

        const remaining = this.maxFindingsPerInvocation - processed;
        const page = await this.findingRepository.queryByControlId(segment.controlId, {
          exclusiveStartKey,
          limit: remaining,
          ...(segment.onlyNotStarted && { remediationStatusEquals: 'NOT_STARTED' as const }),
        });

        await this.processFindingsConcurrently(page.items, (finding) => segment.handleFinding(finding), {
          controlId: segment.controlId,
        });

        // Advance by items DynamoDB examined, not just those handled. With the NOT_STARTED
        // FilterExpression, `Limit` caps items scanned before filtering, so counting only matches
        // would let a control partition dominated by non-matching findings be walked entirely in a
        // single invocation, defeating the per-invocation bound. ScannedCount keeps it bounded; it
        // falls back to the page size for callers/tests that do not report it.
        processed += page.scannedCount ?? page.items.length;

        exclusiveStartKey = page.lastEvaluatedKey;
      } while (exclusiveStartKey);
    }

    return { isComplete: true, itemsProcessed: processed };
  }

  /**
   * Bounded engine for match-all configurations, whose affected findings span arbitrary control IDs
   * and therefore cannot be reached by per-control queries. Walks every currently-stamped finding
   * via the sparse `remediationDueBy-GSI` ({@link FindingRepository.queryAllStampedFindings}),
   * applying `handleFinding` to each. The handlers ({@link removeConfigFromFinding},
   * {@link recalculateContributingFinding}) self-filter on whether the finding carries the affected
   * config ID, so non-matching findings are cheap no-ops. The GSI projection supplies
   * `enforcementConfigIds` and `creationTime`, so this path needs no base-table BatchGetItem and no
   * `findingJSON` decompression. Stops once {@link maxFindingsPerInvocation} findings are examined,
   * saving a scan-all bookmark so the next invocation resumes from the same GSI position.
   */
  private async runScanAll(
    handleFinding: (finding: OverdueFindingProjection) => Promise<void>,
    startBookmark: ReconciliationBookmark | undefined,
  ): Promise<ReconciliationResult> {
    let processed = 0;
    let exclusiveStartKey =
      startBookmark?.controlId === SCAN_ALL_BOOKMARK_CONTROL_ID ? startBookmark.exclusiveStartKey : undefined;

    do {
      if (processed >= this.maxFindingsPerInvocation) {
        return {
          isComplete: false,
          itemsProcessed: processed,
          lastProcessedKey: this.encodeBookmark({ controlId: SCAN_ALL_BOOKMARK_CONTROL_ID, exclusiveStartKey }),
        };
      }

      const remaining = this.maxFindingsPerInvocation - processed;
      const page = await this.findingRepository.queryAllStampedFindings({ exclusiveStartKey, limit: remaining });

      await this.processFindingsConcurrently(page.items, handleFinding);
      // Mirror runSegments' counting: advance by items DynamoDB examined. queryAllStampedFindings
      // applies no FilterExpression today, so scannedCount equals items.length and the fallback is
      // what runs — using the same expression keeps the two engines consistent and correct should a
      // server-side filter ever be added to this path.
      processed += page.scannedCount ?? page.items.length;

      exclusiveStartKey = page.lastEvaluatedKey;
    } while (exclusiveStartKey);

    return { isComplete: true, itemsProcessed: processed };
  }

  /**
   * Processes a page's findings in bounded-concurrency chunks. Findings within a page are distinct
   * items and their handlers issue independent, idempotent writes, so reconciling them in parallel
   * is safe and cuts the wall-clock cost of the per-finding DynamoDB round-trips. Chunks run
   * sequentially so no more than {@link RECONCILIATION_WRITE_CONCURRENCY} writes are in flight at
   * once. Within a chunk the handlers are started in array order, preserving the deterministic
   * ordering callers rely on.
   *
   * Each finding's handler is isolated: reconciliation writes are idempotent and best-effort, so a
   * single finding that throws (e.g. a transient write failure or a conditional-check loss on a
   * concurrent update) is logged and skipped rather than aborting the whole task — mirroring how the
   * task runner isolates individual task failures. Write-time stamping and the Synchronization
   * Lambda refresh re-converge any finding skipped here.
   */
  private async processFindingsConcurrently<T extends { findingId: string }>(
    items: readonly T[],
    handle: (item: T) => Promise<void>,
    logContext?: Record<string, string>,
  ): Promise<void> {
    for (let start = 0; start < items.length; start += RECONCILIATION_WRITE_CONCURRENCY) {
      const chunk = items.slice(start, start + RECONCILIATION_WRITE_CONCURRENCY);
      await Promise.all(chunk.map((item) => this.reconcileFinding(item, handle, logContext)));
    }
  }

  /** Runs one finding's handler, isolating and logging a failure so it cannot abort the page or task. */
  private async reconcileFinding<T extends { findingId: string }>(
    item: T,
    handle: (item: T) => Promise<void>,
    logContext?: Record<string, string>,
  ): Promise<void> {
    try {
      await handle(item);
    } catch (error) {
      this.logger.warn('Failed to reconcile finding; skipping', {
        findingId: item.findingId,
        ...logContext,
        error: ErrorUtils.formatErrorMessage(error),
      });
    }
  }

  private buildStampSegment(controlId: string, config: NotificationConfigurationItem): ReconciliationSegment {
    return {
      controlId: controlIdToFindingType(controlId),
      onlyNotStarted: true,
      handleFinding: (finding) => this.stampMatchingFinding(finding, config),
    };
  }

  private buildRemoveConfigSegment(controlId: string, configId: string): ReconciliationSegment {
    return {
      controlId: controlIdToFindingType(controlId),
      onlyNotStarted: false,
      handleFinding: (finding) => this.removeConfigFromFinding(finding, configId),
    };
  }

  private buildRecalculateSegment(controlId: string, configId: string): ReconciliationSegment {
    return {
      controlId: controlIdToFindingType(controlId),
      onlyNotStarted: false,
      handleFinding: (finding) => this.recalculateContributingFinding(finding, configId),
    };
  }

  private buildReevaluateSegment(controlId: string, config: NotificationConfigurationItem): ReconciliationSegment {
    return {
      controlId: controlIdToFindingType(controlId),
      onlyNotStarted: false,
      handleFinding: (finding) => this.reevaluateFinding(finding, config),
    };
  }

  /** Stamps a `NOT_STARTED` finding that matches the config's resource filters. */
  private async stampMatchingFinding(finding: FindingTableItem, config: NotificationConfigurationItem): Promise<void> {
    if (finding.remediationStatus !== 'NOT_STARTED') return;

    const deadlineDays = config.contentOptions.remediationDeadlineDays;
    if (deadlineDays === undefined) return;

    if (!(await this.findingMatchesResourceFilters(finding, config.resourceFilterIds ?? []))) return;

    const remediationDueBy = computeRemediationDueBy(finding.creationTime, deadlineDays, this.clock.now());
    await this.findingRepository.stampRemediationDueBy(finding.findingId, finding.findingType, remediationDueBy, [
      config.configId,
    ]);
  }

  /** Removes the given config ID from a finding that references it, then clears or recomputes the deadline. */
  private async removeConfigFromFinding(finding: ReconcilableFinding, configId: string): Promise<void> {
    const contributingConfigIds = toStringArray(finding.enforcementConfigIds);
    if (!contributingConfigIds.includes(configId)) return;

    await this.recomputeDeadline(finding, [configId]);
  }

  /** Recomputes the deadline of a finding that references the config, keeping all contributing configs. */
  private async recalculateContributingFinding(finding: ReconcilableFinding, configId: string): Promise<void> {
    const contributingConfigIds = toStringArray(finding.enforcementConfigIds);
    if (!contributingConfigIds.includes(configId)) return;

    await this.recomputeDeadline(finding, []);
  }

  /**
   * Re-evaluates a finding against a config whose resource filters changed. Stamps the finding when
   * it newly matches (and is still `NOT_STARTED`); removes the config and recomputes/clears the
   * deadline when it no longer matches.
   */
  private async reevaluateFinding(finding: FindingTableItem, config: NotificationConfigurationItem): Promise<void> {
    const resourceFilterIds = config.resourceFilterIds ?? [];
    const isCurrentlyStamped = toStringArray(finding.enforcementConfigIds).includes(config.configId);

    let isMatchingNow: boolean;
    if (resourceFilterIds.length === 0) {
      // No resource filters means the config matches every finding under the control, so there is no
      // need to decompress the payload to decide.
      isMatchingNow = true;
    } else {
      const normalized = this.normalizeFinding(finding);
      if (!normalized) return;
      isMatchingNow = await this.matchesResourceFilters(normalized, resourceFilterIds);
    }

    if (isMatchingNow) {
      if (!isCurrentlyStamped && finding.remediationStatus === 'NOT_STARTED') {
        const deadlineDays = config.contentOptions.remediationDeadlineDays;
        if (deadlineDays === undefined) return;
        const remediationDueBy = computeRemediationDueBy(finding.creationTime, deadlineDays, this.clock.now());
        await this.findingRepository.stampRemediationDueBy(finding.findingId, finding.findingType, remediationDueBy, [
          config.configId,
        ]);
      }
      return;
    }

    if (isCurrentlyStamped) {
      await this.recomputeDeadline(finding, [config.configId]);
    }
  }

  /**
   * Removes `configIdsToRemove` from the finding's contributing set and writes the result: clears
   * both enforcement attributes when nothing remains, otherwise force-stamps `remediationDueBy` with
   * the minimum deadline across the remaining configs that still enforce (read live from DynamoDB).
   */
  private async recomputeDeadline(finding: ReconcilableFinding, configIdsToRemove: string[]): Promise<void> {
    const remainingConfigIds = toStringArray(finding.enforcementConfigIds).filter(
      (configId) => !configIdsToRemove.includes(configId),
    );

    if (remainingConfigIds.length === 0) {
      await this.findingRepository.clearRemediationDueBy(finding.findingId, finding.findingType);
      return;
    }

    const enforcingConfigIds: string[] = [];
    const deadlineDays: number[] = [];
    for (const configId of remainingConfigIds) {
      const config = await this.loadLiveConfig(configId);
      if (config && isEnforcementEnabledConfig(config) && config.contentOptions.remediationDeadlineDays !== undefined) {
        enforcingConfigIds.push(configId);
        deadlineDays.push(config.contentOptions.remediationDeadlineDays);
      }
    }

    if (enforcingConfigIds.length === 0) {
      await this.findingRepository.clearRemediationDueBy(finding.findingId, finding.findingType);
      return;
    }

    const remediationDueBy = computeRemediationDueBy(finding.creationTime, Math.min(...deadlineDays), this.clock.now());
    await this.findingRepository.forceStampRemediationDueBy(
      finding.findingId,
      finding.findingType,
      remediationDueBy,
      enforcingConfigIds,
    );
  }

  /**
   * Whether a finding matches the config's resource filters. Short-circuits to `true` when no
   * filters are configured, skipping `findingJSON` decompression entirely. When filters are present
   * the finding is normalized first; an undecodable payload is treated as a non-match so the finding
   * is left unstamped, matching the prior behavior.
   */
  private async findingMatchesResourceFilters(
    finding: FindingTableItem,
    resourceFilterIds: string[],
  ): Promise<boolean> {
    if (resourceFilterIds.length === 0) {
      return true;
    }
    const normalized = this.normalizeFinding(finding);
    if (!normalized) {
      return false;
    }
    return this.matchesResourceFilters(normalized, resourceFilterIds);
  }

  private async matchesResourceFilters(finding: NormalizedFinding, resourceFilterIds: string[] = []): Promise<boolean> {
    const result = await this.resourceFilterEvaluator.evaluateFilters(
      finding,
      resourceFilterIds,
      'include',
      this.filterDefinitionCache,
    );
    return result.passed;
  }

  /** Decompresses and normalizes a finding's stored ASFF payload, returning undefined on corruption. */
  private normalizeFinding(finding: FindingTableItem): NormalizedFinding | undefined {
    try {
      return asffToNormalized(extractASFFFinding(finding));
    } catch (error) {
      this.logger.warn('Failed to decompress finding during reconciliation; skipping', {
        findingId: finding.findingId,
        error: ErrorUtils.formatErrorMessage(error),
      });
      return undefined;
    }
  }

  /**
   * Reads a config from DynamoDB once per invocation, memoizing the in-flight promise (including
   * misses). Caching the promise rather than the resolved value means concurrent callers — which
   * arise when a page's findings are reconciled in parallel — share a single `findConfigById` call
   * instead of each triggering their own. A rejected read is evicted so it is not cached as a
   * permanent failure.
   */
  private async loadLiveConfig(configId: string): Promise<NotificationConfigurationItem | undefined> {
    let pending = this.liveConfigCache.get(configId);
    if (pending === undefined) {
      pending = this.notificationConfigurationRepository
        .findConfigById(configId)
        .then((config) => config ?? null)
        .catch((error) => {
          this.liveConfigCache.delete(configId);
          throw error;
        });
      this.liveConfigCache.set(configId, pending);
    }
    return (await pending) ?? undefined;
  }

  private decodeBookmark(lastProcessedKey?: Record<string, unknown>): ReconciliationBookmark | undefined {
    if (!lastProcessedKey || typeof lastProcessedKey.controlId !== 'string') {
      return undefined;
    }
    return {
      controlId: lastProcessedKey.controlId,
      exclusiveStartKey: lastProcessedKey.exclusiveStartKey as Record<string, unknown> | undefined,
    };
  }

  private encodeBookmark(bookmark: ReconciliationBookmark): Record<string, unknown> {
    return {
      controlId: bookmark.controlId,
      ...(bookmark.exclusiveStartKey && { exclusiveStartKey: bookmark.exclusiveStartKey }),
    };
  }
}

/** A finished result with nothing left to process. */
function completed(): ReconciliationResult {
  return { isComplete: true, itemsProcessed: 0 };
}

/** Normalizes a DynamoDB String Set (or array) of config IDs to a plain string array. */
function toStringArray(value: Set<string> | string[] | undefined): string[] {
  if (!value) return [];
  return value instanceof Set ? Array.from(value) : value;
}

/** Returns the distinct values of an array, preserving first-seen order. */
function uniqueValues(values: string[] = []): string[] {
  return [...new Set(values)];
}

/** Compares two ID lists as unordered sets. */
function sameStringSet(a: string[] = [], b: string[] = []): boolean {
  if (a.length !== b.length) return false;
  const setA = new Set(a);
  return b.every((value) => setA.has(value));
}
