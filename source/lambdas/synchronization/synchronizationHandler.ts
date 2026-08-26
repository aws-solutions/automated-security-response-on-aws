// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import type { LambdaInterface } from '@aws-lambda-powertools/commons/types';
import { Context } from 'aws-lambda';
import { SecurityHubClient } from '@aws-sdk/client-securityhub';
import { getLogger } from '../common/utils/logger';
import { resolveControlId } from '../common/utils/findingUtils';
import { getTracer } from '../common/utils/tracer';
import { createDynamoDBClient } from '../common/utils/dynamodb';
import { sendMetrics } from '../common/utils/metricsUtils';
import { SecurityHubUtils } from '../common/utils/securityHub';
import { FindingDataService, FindingMetricEnrichment } from '../common/services/findingDataService';
import { FiltersRepository } from '../common/repositories/filtersRepository';
import { FindingRepository } from '../common/repositories/findingRepository';
import { NotificationConfigurationRepository } from '../common/repositories/notificationConfigurationRepository';
import { ResourceFilterEvaluator } from '../pre-processor/ResourceFilterEvaluator';
import {
  FindingNotificationConfigEvaluator,
  EligibilityResult,
  FindingConfigEvaluation,
  emptyFindingConfigEvaluation,
} from '../pre-processor/findingNotificationConfigEvaluator';
import { RemediationConfigChecker, ControlConfig } from '../pre-processor/RemediationConfigChecker';
import { asffToNormalized } from '../pre-processor/Normalizer/findingMappers';
import { ASFFFinding, FindingTableItem } from '@asr/data-models';
import {
  getAutomatedRemediationEnabledControlIds,
  getSupportedControlIds,
} from '../common/constants/securityStandardFilters';
import { SyncCursorRepository } from '../common/repositories/syncCursorRepository';
import { runSyncSlice, SliceResult } from '../common/services/runSyncSlice';
import { SecurityHubMemberAccountSource } from '../common/services/accountSource';
import { synchronizationFindingsEnvironment } from './synchronizationFindingsEnvironment';
import { Clock, getClock } from '../common/utils/clock';
import { LambdaCache } from '../common/utils/lambdaCache';

const BATCH_SIZE = 10;
// five minutes is a reasonable time for a single lambda invocation which should take no more than 15 minutes.
// if stale data becomes a problem, this can be further reduced.
const CONTROL_CONFIG_CACHE_TTL_MS = 5 * 60 * 1000;

// Stop the slice this many ms before the Lambda hard-timeout so there is room to checkpoint and exit
// cleanly. The remaining backlog resumes on the next invocation from the persisted cursor.
const SLICE_SAFETY_MARGIN_MS = 30_000;

/**
 * Tasks the sweep state machine invokes the Lambda with. These use an explicit `task`
 * discriminator: the state-machine-driven path is unambiguous, and the state machine — not the
 * Lambda — owns all orchestration (fan-out across accounts and the resume loop within one account).
 * Each task is one Step Functions state.
 */
export interface EnumerateAccountsTask {
  task: 'enumerate-accounts';
}
export interface SyncAccountSliceTask {
  task: 'sync-account-slice';
  accountId: string;
}
export interface MarkSweepDoneTask {
  task: 'mark-sweep-done';
}
type SweepStateMachineTask = EnumerateAccountsTask | SyncAccountSliceTask | MarkSweepDoneTask;

/** Result of the `enumerate-accounts` task — the Map's item source plus the sweep denominator. */
export interface EnumerateAccountsResult {
  accountIds: string[];
  totalAccounts: number;
}

/**
 * Result of a `sync-account-slice` task. `done` / `madeProgress` are top-level so the state machine's
 * Choice can branch on them directly (invoked with `payloadResponseOnly`): loop the same account while
 * it is making progress but not yet done, otherwise complete the branch.
 *
 * These two fields intentionally break the `is`/`has` boolean-naming convention: their names are the
 * Step Functions state-machine contract, read verbatim as `$.slice.done` / `$.slice.madeProgress` in
 * the CDK Choice (and the deploy snapshot). Renaming them here would silently break the sweep.
 */
export interface AccountSliceResult {
  accountId: string;
  done: boolean;
  madeProgress: boolean;
  processedFindings: number;
  processedControlIds: number;
  totalControlIds: number;
  apiCallCount: number;
}

/** Result of the `mark-sweep-done` task. */
export interface MarkSweepDoneResult {
  done: true;
  totalAccounts: number;
}

/** Any sweep state-machine task result — the plain object a task returns as its state output. */
type SweepStateMachineTaskResult = EnumerateAccountsResult | AccountSliceResult | MarkSweepDoneResult;

/** Fleet-position context for the account this slice just synced, for progress reporting. */
interface AccountProgress {
  accountId: string;
  completedAccounts: number;
  totalAccounts: number;
}

interface BatchResult {
  successCount: number;
  failedCount: number;
  errorCount: number;
  filteredCount: number;
}

/** Running totals accumulated across all batches of a single account slice. */
interface SyncCounts {
  totalProcessed: number;
  totalSuccessful: number;
  totalFailed: number;
  totalError: number;
  totalFiltered: number;
}

type FindingProcessingStatus = 'SUCCESS' | 'FAILED' | 'ERROR' | 'FILTERED';

const env = synchronizationFindingsEnvironment();

const findingsTableName = env.FINDINGS_TABLE_NAME;
const remediationConfigTableName = env.REMEDIATION_CONFIG_TABLE_NAME;
const resourceFiltersTableName = env.RESOURCE_FILTERS_TABLE_NAME;
const notificationConfigTableName = env.NOTIFICATION_CONFIG_TABLE_NAME;

const tracer = getTracer(env.SOLUTION_TRADEMARKEDNAME);
const logger = getLogger(env.SOLUTION_TRADEMARKEDNAME);

// The Synchronization Lambda owns every write to the findings table under a single
// principal so `lastUpdatedBy` stays consistent across the initial sync write and the
// later deadline-stamp update.
const SYNCHRONIZATION_PRINCIPAL = 'synchronization';

const moduleDynamoDBClient = tracer.captureAWSv3Client(createDynamoDBClient({ maxAttempts: 10 }));
const filtersRepository = new FiltersRepository(resourceFiltersTableName, moduleDynamoDBClient);
const resourceFilterEvaluator = new ResourceFilterEvaluator(filtersRepository, logger);
const findingRepository = new FindingRepository(SYNCHRONIZATION_PRINCIPAL, findingsTableName, moduleDynamoDBClient);
const notificationConfigurationRepository = new NotificationConfigurationRepository(
  notificationConfigTableName,
  moduleDynamoDBClient,
);
const defaultFindingNotificationConfigEvaluator = new FindingNotificationConfigEvaluator(
  notificationConfigurationRepository,
  resourceFilterEvaluator,
  getClock(),
  logger,
);

export class Synchronization implements LambdaInterface {
  private readonly controlConfigCache: LambdaCache<ControlConfig>;
  private readonly clock: Clock;
  private readonly findingNotificationConfigEvaluator: FindingNotificationConfigEvaluator;

  constructor(
    clock: Clock = getClock(),
    findingNotificationConfigEvaluator: FindingNotificationConfigEvaluator = defaultFindingNotificationConfigEvaluator,
  ) {
    this.clock = clock;
    this.findingNotificationConfigEvaluator = findingNotificationConfigEvaluator;
    this.controlConfigCache = new LambdaCache<ControlConfig>({
      ttlMs: CONTROL_CONFIG_CACHE_TTL_MS,
      fetchFn: (controlId) => this.createConfigChecker(controlId).getControlConfig(),
      onWarmUpError: (controlId, error) => {
        logger.warn(`Failed to warm cache for controlId ${controlId}, will retry on next access`, { error });
      },
      clock: this.clock,
    });
  }

  @tracer.captureLambdaHandler()
  @logger.injectLambdaContext()
  async handler(task: SweepStateMachineTask, context: Context): Promise<SweepStateMachineTaskResult> {
    try {
      return await this.handleStateMachineTask(task, context);
    } catch (error) {
      logger.error(`Synchronization failed: ${error}`, {
        errorType: error instanceof Error ? error.constructor.name : 'unknown',
        task,
      });
      throw error;
    }
  }

  /**
   * Dispatches a sweep state-machine task. Each returns a plain object: the state machine invokes with
   * `payloadResponseOnly`, so the returned object IS the state output its Choice/Map branches on. The
   * state machine — not the Lambda — owns all orchestration (fan-out across accounts and the resume
   * loop within one account), so these tasks carry no self-invoke, next-account, or lock logic.
   */
  private async handleStateMachineTask(
    task: SweepStateMachineTask,
    context: Context,
  ): Promise<SweepStateMachineTaskResult> {
    switch (task.task) {
      case 'enumerate-accounts':
        return this.enumerateAccountsTask();
      case 'sync-account-slice':
        return this.syncAccountSliceTask(task.accountId, context);
      case 'mark-sweep-done':
        return this.markSweepDoneTask();
      default:
        // Exhaustive over SweepStateMachineTask; an unrecognized task is a malformed input and must
        // fail loudly rather than resolve to undefined.
        return this.rejectUnknownTask(task);
    }
  }

  /** Compile-time exhaustiveness guard: `task` is `never` when every known task is handled above. */
  private rejectUnknownTask(task: never): never {
    throw new Error(`Unknown synchronization task: ${JSON.stringify(task)}`);
  }

  /**
   * `enumerate-accounts` task: list the member accounts and (re)initialize the sweep record with the
   * account total. Returns the account list for the state machine's Map to fan out over.
   */
  private async enumerateAccountsTask(): Promise<EnumerateAccountsResult> {
    const clients = this.buildClients();
    const accountSource = new SecurityHubMemberAccountSource(clients.securityHubClient);

    const accountIds = await accountSource.listAccountIds();
    await clients.cursorRepository.resetSweep(accountIds.length);
    logger.info('Started synchronization sweep', { totalAccounts: accountIds.length });

    return { accountIds, totalAccounts: accountIds.length };
  }

  /**
   * `sync-account-slice` task: run one time-bounded slice for a single account. The state machine owns
   * the resume loop, so this task does NOT self-invoke or pick the next account — it just reports
   * `done` / `madeProgress` for the Choice to branch on. No sweep lock is taken: the state machine
   * serializes work per account (one slice at a time per Map branch), and accounts are independent.
   */
  private async syncAccountSliceTask(accountId: string, context: Context): Promise<AccountSliceResult> {
    const clients = this.buildClients();
    const { sliceResult } = await this.syncAccount(accountId, clients, context);
    return {
      accountId,
      done: sliceResult.isDone,
      madeProgress: sliceResult.hasMadeProgress,
      processedFindings: sliceResult.processedFindings,
      processedControlIds: sliceResult.processedControlIds,
      totalControlIds: sliceResult.totalControlIds,
      apiCallCount: sliceResult.apiCallCount,
    };
  }

  /** `mark-sweep-done` task: the state machine's terminal step once every account branch completed. */
  private async markSweepDoneTask(): Promise<MarkSweepDoneResult> {
    const clients = this.buildClients();
    await clients.cursorRepository.saveSweepDone();
    const sweep = await clients.cursorRepository.getSweep();
    logger.info('Synchronization sweep complete; all accounts synced', {
      totalAccounts: sweep?.totalAccounts ?? 0,
    });
    return { done: true, totalAccounts: sweep?.totalAccounts ?? 0 };
  }

  private buildClients() {
    const securityHubClient = tracer.captureAWSv3Client(new SecurityHubClient({}));
    return {
      dynamoDBDocumentClient: moduleDynamoDBClient,
      securityHubClient,
      securityHubUtils: new SecurityHubUtils(securityHubClient),
      findingDataService: new FindingDataService(findingsTableName, moduleDynamoDBClient, SYNCHRONIZATION_PRINCIPAL),
      cursorRepository: new SyncCursorRepository(SYNCHRONIZATION_PRINCIPAL, findingsTableName, moduleDynamoDBClient),
    };
  }

  /** Runs one time-bounded, resumable slice for a single account and reports the per-finding tallies. */
  private async syncAccount(
    accountId: string,
    clients: ReturnType<Synchronization['buildClients']>,
    context: Context,
  ): Promise<{ sliceResult: SliceResult }> {
    const startTime = this.clock.now().getTime();
    logger.info('Processing account synchronization slice', {
      accountId,
      startTime: new Date(startTime).toISOString(),
    });

    const { dynamoDBDocumentClient, securityHubUtils, findingDataService, cursorRepository } = clients;

    // Per-finding tallies, accumulated by the batch processor across every page of the slice.
    let totalSuccessful = 0;
    let totalError = 0;
    let totalFailed = 0;
    let totalFiltered = 0;
    let totalProcessed = 0;

    try {
      const automatedRemediationEnabledControlIds = await getAutomatedRemediationEnabledControlIds(
        dynamoDBDocumentClient,
        remediationConfigTableName,
      );

      const sliceResult: SliceResult = await runSyncSlice(
        {
          cursorRepository,
          securityHubUtils,
          accountId,
          getAllControlIds: () => getSupportedControlIds(dynamoDBDocumentClient, remediationConfigTableName),
          isAutomatedRemediationEnabled: (controlId) => automatedRemediationEnabledControlIds.has(controlId),
          processBatch: async (findings) => {
            totalProcessed += findings.length;
            const batchResult = await this.processFindingsInBatch(findings, findingDataService);
            totalSuccessful += batchResult.successCount;
            totalFailed += batchResult.failedCount;
            totalError += batchResult.errorCount;
            totalFiltered += batchResult.filteredCount;
          },
        },
        {
          budgetMs: SLICE_SAFETY_MARGIN_MS,
          getRemainingTimeMs: () => context.getRemainingTimeInMillis(),
        },
      );

      // Derive progress from the done cursors rather than a maintained counter: under parallel
      // fan-out several account slices finish at once, and a read-modify-write counter would lose
      // increments to write races. This slice has already checkpointed its own cursor above, so the
      // count already reflects it when it just completed.
      const sweep = await cursorRepository.getSweep();
      const accountProgress: AccountProgress = {
        accountId,
        completedAccounts: await cursorRepository.countCompletedAccounts(),
        totalAccounts: sweep?.totalAccounts ?? 0,
      };

      await this.handleSyncSuccess(
        startTime,
        { totalProcessed, totalSuccessful, totalFailed, totalError, totalFiltered },
        sliceResult,
        accountProgress,
      );
      return { sliceResult };
    } catch (error) {
      await this.handleSyncError(error, startTime, totalSuccessful, totalFailed, totalError, totalFiltered);
      throw error;
    }
  }

  /**
   * Process findings using batch operations for better performance
   * Processes findings concurrently in smaller batches to improve throughput
   */
  private async processFindingsInBatch(
    findings: ASFFFinding[],
    findingDataService: FindingDataService,
  ): Promise<BatchResult> {
    let successCount = 0;
    let failedCount = 0;
    let errorCount = 0;
    let filteredCount = 0;

    for (let i = 0; i < findings.length; i += BATCH_SIZE) {
      const batch = findings.slice(i, i + BATCH_SIZE);

      await this.warmControlConfigCache(batch);

      const batchPromises = batch.map((finding) => this.processSingleFinding(finding, findingDataService));
      const batchResults = await Promise.all(batchPromises);

      const batchCounts = this.countBatchResults(batchResults);
      successCount += batchCounts.success;
      failedCount += batchCounts.failed;
      errorCount += batchCounts.error;
      filteredCount += batchCounts.filtered;

      this.logBatchProgress(i, batchCounts);
    }

    return { successCount, failedCount, errorCount, filteredCount };
  }

  private createConfigChecker(controlId: string): RemediationConfigChecker {
    return new RemediationConfigChecker(controlId, moduleDynamoDBClient, remediationConfigTableName, logger);
  }

  /**
   * Pre-fetches control configurations for all distinct controlIds in a batch concurrently.
   * Without this, each finding in a Promise.all batch would independently call the cache's get(),
   * causing O(N) sequential or racing DynamoDB reads for the same controlId. By warming the cache
   * before processing, we reduce this to O(distinct controlIds) reads per batch and avoid redundant
   * network calls for findings that share a controlId.
   */
  private async warmControlConfigCache(findings: ASFFFinding[]): Promise<void> {
    const controlIds = findings.map((f) => f.Compliance?.SecurityControlId).filter((id): id is string => !!id);

    await this.controlConfigCache.warmKeys(controlIds);
  }

  private async processSingleFinding(
    finding: ASFFFinding,
    findingDataService: FindingDataService,
  ): Promise<FindingProcessingStatus> {
    try {
      const filtered = await this.isFilteredOut(finding);
      if (filtered) return 'FILTERED';

      const evaluation = await this.evaluateFindingConfigsSafely(finding);
      const result = await this.updateFindingData(finding, findingDataService, evaluation);
      if (result.status === 'SUCCESS') {
        await this.stampEnforcementDeadline(finding, result.findingTableItem, evaluation.enforcement);
      }
      return result.status;
    } catch (error) {
      logger.error(`Failed to process finding ${finding.Id}: ${error}`);
      return 'ERROR';
    }
  }

  private async isFilteredOut(finding: ASFFFinding): Promise<boolean> {
    const controlId = finding.Compliance?.SecurityControlId;
    if (!controlId) return false;

    try {
      const controlConfig = await this.controlConfigCache.get(controlId);

      if (!controlConfig || controlConfig.filters.length === 0) return false;

      const normalized = asffToNormalized(finding);
      const filterResult = await resourceFilterEvaluator.evaluateFilters(
        normalized,
        controlConfig.filters,
        controlConfig.filterMode,
      );
      if (!filterResult.passed) {
        logger.info('Finding blocked by resource filters, skipping sync', {
          findingId: finding.Id,
          reason: filterResult.reason,
          filterMode: controlConfig.filterMode,
          filterCount: controlConfig.filters.length,
        });
        return true;
      }
      return false;
    } catch (error) {
      logger.warn('Error evaluating resource filters, proceeding with finding sync (fail-open)', {
        findingId: finding.Id,
        controlId,
        error,
      });
      return false;
    }
  }

  private async updateFindingData(
    finding: ASFFFinding,
    findingDataService: FindingDataService,
    evaluation: FindingConfigEvaluation,
  ): Promise<{ status: FindingProcessingStatus; findingTableItem?: FindingTableItem }> {
    const metricEnrichment: FindingMetricEnrichment = {
      hasFindingNotificationsEnabled: evaluation.hasNotificationsEnabled,
      hasFindingRemediationDeadlineConfigured: evaluation.hasDeadlineConfigured,
    };
    // The findings reaching this path come from the Security Hub sweep in runSyncSlice, whose filters
    // (getOptimizedFindingFilters) constrain GeneratorId to a PREFIX match on
    // STANDARDS_WITH_REMEDIATIONS and ProductArn to `arn:aws:securityhub`. A multi-service finding
    // matches neither, so every finding here is a Security Hub control finding and its key comes from
    // the ARN. resolveControlId throws if that ever stops holding, rather than guessing. A
    // multi-service source added to that sweep would need to resolve its key from the mapper instead.
    // See ADR 0010.
    const result = await findingDataService.updateWithIncomingData(
      finding,
      resolveControlId(finding),
      undefined,
      true,
      undefined,
      metricEnrichment,
    );
    this.logFindingResult(finding.Id, result.status);
    return result;
  }

  /**
   * Evaluates a synced finding against enabled finding-type notification configs to derive the
   * metric-enrichment flags (persisted in the finding write) and deadline enforcement eligibility
   * (stamped after the write). Runs before the write; failures are swallowed and safe defaults
   * returned so the sync path always succeeds. Findings without a Security Hub control id are not
   * evaluated (defaults returned).
   */
  private async evaluateFindingConfigsSafely(finding: ASFFFinding): Promise<FindingConfigEvaluation> {
    const controlId = finding.Compliance?.SecurityControlId;
    if (!controlId) {
      return emptyFindingConfigEvaluation();
    }
    try {
      const normalized = asffToNormalized(finding);
      return await this.findingNotificationConfigEvaluator.evaluateFindingConfigs(normalized, controlId);
    } catch (error) {
      logger.warn('Finding config evaluation failed during sync, continuing without enrichment or enforcement', {
        findingId: finding.Id,
        error,
      });
      return emptyFindingConfigEvaluation();
    }
  }

  /**
   * Stamps `remediationDueBy` + `enforcementConfigIds` when a freshly synced finding is eligible
   * for deadline enforcement. Only findings actually written to the table (a `findingTableItem` is
   * returned) and still NOT_STARTED are stamped — archived findings and findings already under
   * remediation are skipped. Uses the pre-computed enforcement result (no re-evaluation) and
   * swallows write failures so the sync path always succeeds.
   */
  private async stampEnforcementDeadline(
    finding: ASFFFinding,
    findingTableItem: FindingTableItem | undefined,
    enforcement: EligibilityResult,
  ): Promise<void> {
    if (findingTableItem?.remediationStatus !== 'NOT_STARTED') return;
    if (!enforcement.isEligible || !enforcement.remediationDueBy) return;

    try {
      await findingRepository.stampRemediationDueBy(
        findingTableItem.findingId,
        findingTableItem.findingType,
        enforcement.remediationDueBy,
        enforcement.matchingConfigIds,
      );
    } catch (error) {
      logger.warn('Failed to stamp remediation deadline during sync, continuing', {
        findingId: finding.Id,
        error,
      });
    }
  }

  private logFindingResult(findingId: string, status: FindingProcessingStatus): void {
    const statusMessages: Record<FindingProcessingStatus, string> = {
      SUCCESS: `Successfully processed finding ${findingId}`,
      FAILED: `Failed to process finding ${findingId} - result: ${status}`,
      ERROR: `Error processing finding ${findingId} - result: ${status}`,
      FILTERED: `Finding ${findingId} filtered out by resource filters`,
    };

    logger.debug(statusMessages[status]);
  }

  private countBatchResults(batchResults: FindingProcessingStatus[]): {
    success: number;
    failed: number;
    error: number;
    filtered: number;
  } {
    return {
      success: batchResults.filter((r) => r === 'SUCCESS').length,
      failed: batchResults.filter((r) => r === 'FAILED').length,
      error: batchResults.filter((r) => r === 'ERROR').length,
      filtered: batchResults.filter((r) => r === 'FILTERED').length,
    };
  }

  private logBatchProgress(
    currentIndex: number,
    counts: { success: number; failed: number; error: number; filtered: number },
  ): void {
    const batchNumber = Math.floor(currentIndex / BATCH_SIZE) + 1;
    logger.debug(
      `Batch ${batchNumber}: ${counts.success} successful, ${counts.failed} failed, ${counts.error} error, ${counts.filtered} filtered`,
    );
  }

  private calculateExecutionMetrics(
    startTime: number,
    totalProcessed: number,
    totalFiltered: number,
  ): { endTime: number; executionTimeMs: number; executionTimeSeconds: number; filterEffectivenessRatio: number } {
    const endTime = this.clock.now().getTime();
    const executionTimeMs = endTime - startTime;
    const executionTimeSeconds = Math.round((executionTimeMs / 1000) * 100) / 100;
    const filterEffectivenessRatio =
      totalProcessed > 0 ? Math.round((totalFiltered / totalProcessed) * 100 * 100) / 100 : 0;

    return {
      endTime,
      executionTimeMs,
      executionTimeSeconds,
      filterEffectivenessRatio,
    };
  }

  private async handleSyncSuccess(
    startTime: number,
    counts: SyncCounts,
    sliceResult: SliceResult,
    accountProgress: AccountProgress,
  ): Promise<void> {
    const { totalProcessed, totalSuccessful, totalFailed, totalError, totalFiltered } = counts;
    const metrics = this.calculateExecutionMetrics(startTime, totalProcessed, totalFiltered);

    // A single invocation runs one time-bounded slice; `done` tells the state machine's Choice whether
    // this account's backlog has been imported or whether another slice is needed to continue it.
    const message = sliceResult.isDone
      ? 'Synchronization completed successfully'
      : 'Synchronization slice completed; more findings remain (state machine will continue)';

    logger.info(message, {
      accountId: accountProgress.accountId,
      completedAccounts: accountProgress.completedAccounts,
      totalAccounts: accountProgress.totalAccounts,
      totalProcessed,
      totalSuccessful,
      totalFailed,
      totalError,
      totalFiltered,
      done: sliceResult.isDone,
      processedControlIds: sliceResult.processedControlIds,
      totalControlIds: sliceResult.totalControlIds,
      processedFindings: sliceResult.processedFindings,
      apiCallCount: sliceResult.apiCallCount,
      filterEffectivenessRatio: metrics.filterEffectivenessRatio,
      executionTimeMs: metrics.executionTimeMs,
      executionTimeSeconds: metrics.executionTimeSeconds,
      startTime: new Date(startTime).toISOString(),
      endTime: new Date(metrics.endTime).toISOString(),
    });

    await sendMetrics({
      synchronization_status: 'SUCCESS',
      account_id: accountProgress.accountId,
      completed_accounts: accountProgress.completedAccounts,
      total_accounts: accountProgress.totalAccounts,
      total_processed: totalProcessed,
      total_successful: totalSuccessful,
      total_failed: totalFailed,
      total_error: totalError,
      total_filtered: totalFiltered,
      filter_effectiveness_ratio: metrics.filterEffectivenessRatio,
      sync_done: sliceResult.isDone,
      processed_control_ids: sliceResult.processedControlIds,
      total_control_ids: sliceResult.totalControlIds,
      processed_findings: sliceResult.processedFindings,
      api_call_count: sliceResult.apiCallCount,
      execution_time_ms: metrics.executionTimeMs,
      execution_time_seconds: metrics.executionTimeSeconds,
    });
  }

  private async handleSyncError(
    error: unknown,
    startTime: number,
    totalSuccessful: number,
    totalFailed: number,
    totalError: number,
    totalFiltered: number,
  ): Promise<void> {
    const totalProcessed = totalSuccessful + totalFailed + totalError + totalFiltered;
    const metrics = this.calculateExecutionMetrics(startTime, totalProcessed, totalFiltered);

    logger.error(`Scheduled sync failed: ${error}`, {
      totalSuccessful,
      totalFailed,
      totalError,
      totalFiltered,
      filterEffectivenessRatio: metrics.filterEffectivenessRatio,
      executionTimeMs: metrics.executionTimeMs,
      executionTimeSeconds: metrics.executionTimeSeconds,
      startTime: new Date(startTime).toISOString(),
      endTime: new Date(metrics.endTime).toISOString(),
    });

    await sendMetrics({
      synchronization_status: 'FAILED',
      total_processed: totalProcessed,
      total_error: totalError,
      total_successful: totalSuccessful,
      total_failed: totalFailed,
      total_filtered: totalFiltered,
      filter_effectiveness_ratio: metrics.filterEffectivenessRatio,
      execution_time_ms: metrics.executionTimeMs,
      execution_time_seconds: metrics.executionTimeSeconds,
      error_message: error instanceof Error ? error.message : 'Unknown error',
    });
  }
}

const synchronizationClass = new Synchronization();

/**
 * Lambda entry point. The sync Lambda serves only the sweep state machine, so every invocation is one
 * of the three Step Functions tasks. Overloaded so each task resolves to its own precise result type
 * (which the state machine reads as state output) with no casting at the call sites.
 */
export function handler(event: EnumerateAccountsTask, context: Context): Promise<EnumerateAccountsResult>;
export function handler(event: SyncAccountSliceTask, context: Context): Promise<AccountSliceResult>;
export function handler(event: MarkSweepDoneTask, context: Context): Promise<MarkSweepDoneResult>;
export function handler(event: SweepStateMachineTask, context: Context): Promise<SweepStateMachineTaskResult> {
  return synchronizationClass.handler(event, context);
}
