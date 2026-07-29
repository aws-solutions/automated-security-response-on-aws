// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { ASFFFinding } from '@asr/data-models';
import { getOptimizedFindingFiltersByControlId } from '../constants/securityStandardFilters';
import { SyncCursor, SyncCursorRepository } from '../repositories/syncCursorRepository';
import { SecurityHubUtils } from '../utils/securityHub';
import { getLogger } from '../utils/logger';

const logger = getLogger('runSyncSlice');

const DEFAULT_CHUNK_SIZE = 20;

/** Collaborators the slice engine needs. Injected so the engine is unit-testable in isolation. */
export interface RunSyncSliceDeps {
  cursorRepository: SyncCursorRepository;
  securityHubUtils: SecurityHubUtils;
  /** The account this slice syncs; used as the cursor scope so each account resumes independently. */
  accountId: string;
  /** Returns every supported controlId. The engine de-duplicates the result, so callers need not. */
  getAllControlIds: () => Promise<string[]>;
  /** Processes one page of findings (filter + upsert + count). Reused verbatim from the caller. */
  processBatch: (findings: ASFFFinding[]) => Promise<void>;
  /**
   * Whether a control has automated remediation enabled. Controls that do are chunked first so
   * remediation can start on the highest-value findings before the whole account finishes. Optional:
   * when omitted the control order is left unchanged.
   */
  isAutomatedRemediationEnabled?: (controlId: string) => boolean;
  /** Controls per chunk / GetFindings filter. Defaults to 20 (Security Hub filter-value ceiling). */
  chunkSize?: number;
}

/** Time budget for a single slice. */
export interface RunSyncSliceBudget {
  /** Stop before remaining time drops below this many ms (leaves room to checkpoint and exit cleanly). */
  budgetMs: number;
  /** Remaining execution time, in ms (e.g. Lambda's `context.getRemainingTimeInMillis`). */
  getRemainingTimeMs: () => number;
}

export interface SliceResult {
  processedControlIds: number;
  totalControlIds: number;
  processedFindings: number;
  isDone: boolean;
  /**
   * True if THIS slice advanced the account — completed a control or imported at least one finding.
   * A continuation should only re-invoke while progress is being made, so a wedged slice cannot spin
   * forever.
   */
  hasMadeProgress: boolean;
  /**
   * Number of Security Hub `GetFindings` calls this slice made, summed across every chunk/page it
   * paged. Reported per-slice (this invocation), not cumulatively across the account's sweep, matching
   * the pre-slicing behaviour of the sync handler's usage metric.
   */
  apiCallCount: number;
}

/** True for the Security Hub error raised when a NextToken is invalid or has expired. */
function isExpiredTokenError(error: unknown): boolean {
  if (!(error instanceof Error)) return false;
  return error.name === 'InvalidInputException' || /token/i.test(error.message);
}

/**
 * Runs one time-bounded slice of the finding synchronization sweep.
 *
 * Resumes from the persisted cursor, walks the pending controlId chunks (paging Security Hub and
 * upserting each page), and checkpoints after every page so a mid-slice timeout loses no progress.
 * Stops cleanly when the remaining time approaches `budgetMs`; sets `done` when the whole set is
 * imported. A subsequent call after a completed pass starts a fresh pass.
 *
 * Two correctness guards: cursor writes are version-conditional (a stale writer that lost the lock
 * race is rejected), and an expired Security Hub resume token restarts the affected chunk rather than
 * failing — safe because upserts are idempotent.
 */
export async function runSyncSlice(deps: RunSyncSliceDeps, budget: RunSyncSliceBudget): Promise<SliceResult> {
  const { cursorRepository, accountId, getAllControlIds } = deps;
  const chunkSize = deps.chunkSize ?? DEFAULT_CHUNK_SIZE;
  const { budgetMs, getRemainingTimeMs } = budget;

  const budgetSpent = () => getRemainingTimeMs() <= budgetMs;

  // De-duplicate up front (getSupportedControlIds can emit duplicates); a Set also gives O(1) membership.
  // Order auto-remediation-enabled controls first so their findings import — and can be remediated —
  // before the rest of the account is drained.
  const allControlIds = orderAutomatedRemediationFirst(
    Array.from(new Set(await getAllControlIds())),
    deps.isAutomatedRemediationEnabled,
  );
  const allControlIdSet = new Set(allControlIds);

  let cursor = await loadOrResetCursor(cursorRepository, accountId, allControlIds.length);
  // Keep the denominator honest if the control set changed since the pass began. Not persisted on its
  // own — it rides along on the next saveCursor via the spread.
  if (cursor.totalControlIds !== allControlIds.length) {
    cursor = { ...cursor, totalControlIds: allControlIds.length };
  }

  // Baseline to detect whether THIS slice advanced the account (for continuation loop-safety).
  const startingCompletedCount = cursor.completedControlIds.length;
  const startingProcessedFindings = cursor.processedFindings;

  // Security Hub GetFindings calls made by THIS slice, summed across every chunk/page it walks. Reported
  // as the per-slice usage metric.
  let apiCallCount = 0;

  // Every cursor mutation flows through saveCursor and its returned value becomes the current cursor —
  // there is no in-place mutation, so the latest cursor is always the one just reassigned here.
  while (!budgetSpent()) {
    cursor = await dropStaleInProgressChunk(cursor, allControlIdSet, deps);

    const completed = new Set(cursor.completedControlIds);
    const pending = allControlIds.filter((id) => !completed.has(id));

    if (pending.length === 0 && !cursor.inProgress) {
      cursor = await cursorRepository.saveCursor(accountId, { ...cursor, done: true });
      break;
    }

    const selection = await selectChunk(cursor, pending, chunkSize, deps);
    cursor = selection.cursor;

    const chunkResult = await processChunk(selection.chunk, selection.startToken, cursor, deps, budgetSpent);
    cursor = chunkResult.cursor;
    apiCallCount += chunkResult.apiCallCount;

    if (chunkResult.wasStopped) {
      break; // budget hit mid-chunk; the checkpoint in onPageProcessed already recorded the resume point
    }

    // Chunk exhausted: mark its controls complete and clear the in-progress slot.
    cursor = await cursorRepository.saveCursor(accountId, {
      ...cursor,
      completedControlIds: [...completed, ...selection.chunk],
      inProgress: null,
    });
  }

  return {
    processedControlIds: cursor.completedControlIds.length,
    totalControlIds: cursor.totalControlIds,
    processedFindings: cursor.processedFindings,
    isDone: cursor.done,
    hasMadeProgress:
      cursor.completedControlIds.length > startingCompletedCount ||
      cursor.processedFindings > startingProcessedFindings,
    apiCallCount,
  };
}

/** The chunk to work next, alongside the cursor after any claim-write that selecting it required. */
interface ChunkSelection {
  cursor: SyncCursor;
  chunk: string[];
  startToken: string | undefined;
}

/**
 * Drops an in-progress chunk whose controls are no longer all in the supported set — its Security Hub
 * filter/token would no longer match, so it must be re-chunked. Returns the cursor unchanged (no write)
 * when the in-progress chunk is still valid or absent.
 */
async function dropStaleInProgressChunk(
  cursor: SyncCursor,
  supportedControlIds: Set<string>,
  deps: RunSyncSliceDeps,
): Promise<SyncCursor> {
  if (!cursor.inProgress || cursor.inProgress.controlIds.every((id) => supportedControlIds.has(id))) {
    return cursor;
  }
  logger.warn('In-progress chunk references a control that is no longer supported; re-chunking', {
    inProgressControlIds: cursor.inProgress.controlIds,
  });
  return deps.cursorRepository.saveCursor(deps.accountId, { ...cursor, inProgress: null });
}

/**
 * Chooses the chunk to work next: resume the in-progress chunk with its saved resume token, or claim
 * the next `chunkSize` pending controls (persisting the claim first so a crash resumes on them).
 */
async function selectChunk(
  cursor: SyncCursor,
  pending: string[],
  chunkSize: number,
  deps: RunSyncSliceDeps,
): Promise<ChunkSelection> {
  if (cursor.inProgress) {
    return { cursor, chunk: cursor.inProgress.controlIds, startToken: cursor.inProgress.nextToken };
  }
  const chunk = pending.slice(0, chunkSize);
  const claimed = await deps.cursorRepository.saveCursor(deps.accountId, {
    ...cursor,
    inProgress: { controlIds: chunk },
  });
  return { cursor: claimed, chunk, startToken: undefined };
}

/** The cursor after a chunk was paged, the Security Hub calls it took, and whether the budget cut it short. */
interface ChunkProcessingResult {
  cursor: SyncCursor;
  apiCallCount: number;
  wasStopped: boolean;
}

/**
 * Pages one chunk through Security Hub, checkpointing the cursor after each page. Returns the final
 * cursor state, the Security Hub call count, and whether the run stopped on the time budget (resumable)
 * rather than draining the chunk. Retries once from the start of the chunk if the resume token is
 * rejected as expired — safe because upserts are idempotent.
 */
async function processChunk(
  chunkControlIds: string[],
  resumeToken: string | undefined,
  startingCursor: SyncCursor,
  deps: RunSyncSliceDeps,
  budgetSpent: () => boolean,
): Promise<ChunkProcessingResult> {
  const { cursorRepository, securityHubUtils, accountId, processBatch } = deps;
  let cursor = startingCursor;
  let apiCallCount = 0;

  const filters = await getOptimizedFindingFiltersByControlId(chunkControlIds, accountId);

  const onPageProcessed = async (nextToken: string | undefined, pageCount: number): Promise<void> => {
    cursor = await cursorRepository.saveCursor(accountId, {
      ...cursor,
      processedFindings: cursor.processedFindings + pageCount,
      inProgress: { controlIds: chunkControlIds, ...(nextToken !== undefined && { nextToken }) },
    });
  };

  const runOptions = { shouldStop: budgetSpent, onPageProcessed };

  try {
    const result = await securityHubUtils.processAllFindings(processBatch, filters, {
      ...runOptions,
      startToken: resumeToken,
    });
    apiCallCount += result.apiCallCount;
    return { cursor, apiCallCount, wasStopped: result.wasStopped };
  } catch (error) {
    if (resumeToken && isExpiredTokenError(error)) {
      logger.warn('Security Hub resume token was rejected; restarting the chunk from the beginning', {
        chunkControlIds,
        error: error instanceof Error ? error.message : String(error),
      });
      cursor = await cursorRepository.saveCursor(accountId, { ...cursor, inProgress: { controlIds: chunkControlIds } });
      const retry = await securityHubUtils.processAllFindings(processBatch, filters, {
        ...runOptions,
        startToken: undefined,
      });
      apiCallCount += retry.apiCallCount;
      return { cursor, apiCallCount, wasStopped: retry.wasStopped };
    }
    throw error;
  }
}

/**
 * Loads the account's cursor, starting a fresh pass when none exists or the previous pass completed.
 */
async function loadOrResetCursor(
  cursorRepository: SyncCursorRepository,
  accountId: string,
  totalControlIds: number,
): Promise<SyncCursor> {
  const existing = await cursorRepository.getCursor(accountId);
  if (!existing) {
    logger.info('No sync cursor found; starting a fresh pass', { accountId });
    return cursorRepository.resetCursor(accountId, totalControlIds);
  }
  if (existing.done) {
    logger.info('Previous sync pass was complete; starting a fresh pass', { accountId });
    return cursorRepository.resetCursor(accountId, totalControlIds);
  }
  logger.info('Resuming sync from persisted cursor', {
    accountId,
    completedControlIds: existing.completedControlIds.length,
    totalControlIds: existing.totalControlIds,
    processedFindings: existing.processedFindings,
  });
  return existing;
}

/**
 * Returns the controlIds with automated-remediation-enabled ones moved to the front (order among
 * equals preserved). When no predicate is supplied the input order is returned unchanged.
 */
function orderAutomatedRemediationFirst(
  controlIds: string[],
  isAutomatedRemediationEnabled?: (controlId: string) => boolean,
): string[] {
  if (!isAutomatedRemediationEnabled) return controlIds;

  const remediationEnabled: string[] = [];
  const rest: string[] = [];
  for (const controlId of controlIds) {
    (isAutomatedRemediationEnabled(controlId) ? remediationEnabled : rest).push(controlId);
  }
  return [...remediationEnabled, ...rest];
}
