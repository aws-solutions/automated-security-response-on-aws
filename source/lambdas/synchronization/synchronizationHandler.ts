// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import type { LambdaInterface } from '@aws-lambda-powertools/commons/types';
import { Context } from 'aws-lambda';
import { SecurityHubClient } from '@aws-sdk/client-securityhub';
import { getLogger } from '../common/utils/logger';
import { getTracer } from '../common/utils/tracer';
import { createDynamoDBClient } from '../common/utils/dynamodb';
import { sendMetrics } from '../common/utils/metricsUtils';
import { SecurityHubUtils } from '../common/utils/securityHub';
import { FindingDataService } from '../common/services/findingDataService';
import { ASFFFinding } from '@asr/data-models';
import { applyFilters } from '../common/utils/filterUtils';
import {
  getAutomatedRemediationEnabledControlIds,
  getSupportedControlIds,
} from '../common/constants/securityStandardFilters';
import { SyncCursorRepository } from '../common/repositories/syncCursorRepository';
import { runSyncSlice, SliceResult } from '../common/services/runSyncSlice';
import { SecurityHubMemberAccountSource } from '../common/services/accountSource';

const BATCH_SIZE = 10;

// Stop the slice this many ms before the Lambda hard-timeout so there is room to checkpoint and exit
// cleanly. The remaining backlog resumes on the next invocation from the persisted cursor.
const SLICE_SAFETY_MARGIN_MS = 30_000;

// Identifies this run as the principal on writes.
const SYNC_PRINCIPAL = 'synchronization';

/**
 * Tasks the sweep state machine invokes the Lambda with. These use an explicit `task`
 * discriminator rather than the EventBridge `detail-type` shapes, so the state-machine-driven path is
 * unambiguous and fully separate from the schedule / custom-resource / self-invoke event paths. Each
 * task is one Step Functions state, and the state machine — not the Lambda — owns all orchestration
 * (fan-out across accounts and the resume loop within one account).
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

type FindingProcessingStatus = 'SUCCESS' | 'FAILED' | 'ERROR' | 'FILTERED';

const SOLUTION_TRADEMARKEDNAME = process.env.SOLUTION_TRADEMARKEDNAME ?? 'automated-security-response-on-aws';
const FINDINGS_TABLE_ARN = process.env.FINDINGS_TABLE_ARN;
const REMEDIATION_CONFIG_TABLE_ARN = process.env.REMEDIATION_CONFIG_TABLE_ARN;
const FINDINGS_TABLE_NAME = FINDINGS_TABLE_ARN?.split('/')[1];
const REMEDIATION_CONFIG_TABLE_NAME = REMEDIATION_CONFIG_TABLE_ARN?.split('/')[1];

if (!FINDINGS_TABLE_ARN) throw new Error('FINDINGS_TABLE_ARN environment variable is required');
if (!FINDINGS_TABLE_NAME) throw new Error('Unable to extract table name from FINDINGS_TABLE_ARN');
if (!REMEDIATION_CONFIG_TABLE_ARN) throw new Error('REMEDIATION_CONFIG_TABLE_ARN environment variable is required');
if (!REMEDIATION_CONFIG_TABLE_NAME) throw new Error('Unable to extract table name from REMEDIATION_CONFIG_TABLE_ARN');

const tracer = getTracer(SOLUTION_TRADEMARKEDNAME);
const logger = getLogger(SOLUTION_TRADEMARKEDNAME);

export class Synchronization implements LambdaInterface {
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
    const dynamoDBDocumentClient = tracer.captureAWSv3Client(createDynamoDBClient({ maxAttempts: 10 }));
    const securityHubClient = tracer.captureAWSv3Client(new SecurityHubClient({}));
    return {
      dynamoDBDocumentClient,
      securityHubClient,
      securityHubUtils: new SecurityHubUtils(securityHubClient),
      findingDataService: new FindingDataService(FINDINGS_TABLE_NAME!, dynamoDBDocumentClient, SYNC_PRINCIPAL),
      cursorRepository: new SyncCursorRepository(SYNC_PRINCIPAL, FINDINGS_TABLE_NAME!, dynamoDBDocumentClient),
    };
  }

  /** Runs one time-bounded, resumable slice for a single account and reports the per-finding tallies. */
  private async syncAccount(
    accountId: string,
    clients: ReturnType<Synchronization['buildClients']>,
    context: Context,
  ): Promise<{ sliceResult: SliceResult }> {
    const startTime = Date.now();
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
        REMEDIATION_CONFIG_TABLE_NAME!,
      );

      const sliceResult: SliceResult = await runSyncSlice(
        {
          cursorRepository,
          securityHubUtils,
          accountId,
          getAllControlIds: () => getSupportedControlIds(dynamoDBDocumentClient, REMEDIATION_CONFIG_TABLE_NAME!),
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
      // count already reflects it when it just completed. Bound the count to cursors finished during
      // THIS sweep (lastSyncedAt >= the sweep's startedAt): cursors are reset lazily per account, not
      // cleared at sweep start, so an unbounded count would report last sweep's leftovers and sit near
      // the total from the first slice instead of climbing from zero.
      const sweep = await cursorRepository.getSweep();
      const accountProgress: AccountProgress = {
        accountId,
        completedAccounts: await cursorRepository.countCompletedAccounts(sweep?.startedAt),
        totalAccounts: sweep?.totalAccounts ?? 0,
      };

      await this.handleSyncSuccess(
        startTime,
        totalProcessed,
        totalSuccessful,
        totalFailed,
        totalError,
        totalFiltered,
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

  private async processSingleFinding(
    finding: ASFFFinding,
    findingDataService: FindingDataService,
  ): Promise<FindingProcessingStatus> {
    try {
      const filterResult = await applyFilters(finding, logger);

      if (!filterResult.passed) {
        logger.debug(`Finding filtered out: ${finding.Id}`, {
          appliedFilter: filterResult.appliedFilter,
          findingId: finding.Id,
        });
        return 'FILTERED';
      }

      return await this.updateFindingData(finding, findingDataService);
    } catch (filterError) {
      return await this.handleFilterError(finding, findingDataService, filterError);
    }
  }

  private async updateFindingData(
    finding: ASFFFinding,
    findingDataService: FindingDataService,
  ): Promise<FindingProcessingStatus> {
    const result = await findingDataService.updateWithIncomingData(finding, undefined, true);
    this.logFindingResult(finding.Id, result.status);
    return result.status;
  }

  private async handleFilterError(
    finding: ASFFFinding,
    findingDataService: FindingDataService,
    filterError: unknown,
  ): Promise<FindingProcessingStatus> {
    if (filterError instanceof Error && filterError.message.includes('filter')) {
      logger.error(`Filter error for finding ${finding.Id}, processing anyway`, {
        error: filterError,
        findingId: finding.Id,
      });
    }

    try {
      const result = await findingDataService.updateWithIncomingData(finding, undefined, true);
      return result.status;
    } catch (error) {
      logger.error(`Failed to process finding ${finding.Id}: ${error}`);
      return 'ERROR';
    }
  }

  private logFindingResult(findingId: string, status: FindingProcessingStatus): void {
    const statusMessages = {
      SUCCESS: `Successfully processed finding ${findingId}`,
      FAILED: `Failed to process finding ${findingId} - result: ${status}`,
      ERROR: `Error processing finding ${findingId} - result: ${status}`,
      FILTERED: `Finding filtered out: ${findingId}`,
    };

    if (statusMessages[status]) {
      logger.debug(statusMessages[status]);
    }
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

  private calculateExecutionMetrics(startTime: number, totalProcessed: number, totalFiltered: number) {
    const endTime = Date.now();
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
    totalProcessed: number,
    totalSuccessful: number,
    totalFailed: number,
    totalError: number,
    totalFiltered: number,
    sliceResult: SliceResult,
    accountProgress: AccountProgress,
  ): Promise<void> {
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
  ) {
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
