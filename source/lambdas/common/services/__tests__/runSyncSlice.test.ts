// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Focused tests for the three correctness guards in the slice engine that the handler-level
// integration test cannot reach deterministically, because nothing in the live wiring can trigger
// them on demand:
//   1. an expired Security Hub resume token restarting a chunk without data loss;
//   2. reconciling an in-progress chunk whose control was disabled between runs;
//   3. the optimistic-concurrency guard rejecting a stale cursor writer.
//
// Per the unit-testing guide these use a REAL SyncCursorRepository against DynamoDB Local (the cursor
// persistence is never mocked); only Security Hub — a true system boundary — is faked.

import { ASFFFinding } from '@asr/data-models';
import { DynamoDBDocumentClient } from '@aws-sdk/lib-dynamodb';
import { getOptimizedFindingFiltersByControlId } from '../../constants/securityStandardFilters';
import { StaleCursorError, SyncCursor, SyncCursorRepository } from '../../repositories/syncCursorRepository';
import { ProcessAllFindingsOptions, ProcessAllFindingsResult, SecurityHubUtils } from '../../utils/securityHub';
import { DynamoDBTestSetup } from '../../__tests__/dynamodbSetup';
import { findingsTableName } from '../../__tests__/envSetup';
import { runSyncSlice } from '../runSyncSlice';

/**
 * Scriptable stand-in for SecurityHubUtils. Honors the same startToken / shouldStop / onPageProcessed
 * contract as the real pagination, and can be told to reject a resume token once (to simulate an
 * expired NextToken).
 */
class FakeSecurityHubUtils {
  private pagesByChunk = new Map<string, ASFFFinding[][]>();
  private expireTokenOnceFor = new Set<string>();
  private alreadyThrewFor = new Set<string>();

  setChunkPages(controlIds: string[], pages: ASFFFinding[][]): void {
    this.pagesByChunk.set([...controlIds].sort().join(','), pages);
  }

  rejectResumeTokenOnceFor(controlIds: string[]): void {
    this.expireTokenOnceFor.add([...controlIds].sort().join(','));
  }

  processAllFindings = async (
    processBatch: (findings: ASFFFinding[]) => Promise<void>,
    filters: NonNullable<Awaited<ReturnType<typeof getOptimizedFindingFiltersByControlId>>>,
    options?: ProcessAllFindingsOptions,
  ): Promise<ProcessAllFindingsResult> => {
    const controlIds = (filters.ComplianceSecurityControlId ?? []).map((f) => f.Value as string);
    const key = [...controlIds].sort().join(',');

    if (this.expireTokenOnceFor.has(key) && options?.startToken && !this.alreadyThrewFor.has(key)) {
      this.alreadyThrewFor.add(key);
      const error = new Error('The provided NextToken is invalid');
      error.name = 'InvalidInputException';
      throw error;
    }

    const pages = this.pagesByChunk.get(key) ?? [];
    let totalProcessed = 0;
    let apiCallCount = 0;
    let index = options?.startToken ? Number(options.startToken.replace('page-', '')) : 0;

    for (; index < pages.length; index++) {
      if (options?.shouldStop?.()) {
        return { totalProcessed, apiCallCount, nextToken: `page-${index}`, wasStopped: true };
      }
      apiCallCount++;
      const page = pages[index];
      await processBatch(page);
      totalProcessed += page.length;
      const nextToken = index + 1 < pages.length ? `page-${index + 1}` : undefined;
      await options?.onPageProcessed?.(nextToken, page.length);
    }

    return { totalProcessed, apiCallCount, nextToken: undefined, wasStopped: false };
  };
}

const finding = (id: string): ASFFFinding => ({ Id: id }) as ASFFFinding;

// A budget that never runs out.
const unboundedBudget = { budgetMs: 0, getRemainingTimeMs: () => Number.MAX_SAFE_INTEGER };

describe('runSyncSlice correctness guards (real cursor persistence)', () => {
  const principal = 'synchronization';
  let dynamoDBDocumentClient: DynamoDBDocumentClient;
  let cursorRepository: SyncCursorRepository;
  let securityHubUtils: FakeSecurityHubUtils;
  let processedFindingIds: string[];

  const accountId = '111122223333';

  const buildDeps = (getAllControlIds: () => Promise<string[]>) => ({
    cursorRepository,
    securityHubUtils: securityHubUtils as unknown as SecurityHubUtils,
    accountId,
    getAllControlIds,
    processBatch: async (findings: ASFFFinding[]) => {
      processedFindingIds.push(...findings.map((f) => f.Id));
    },
  });

  beforeAll(async () => {
    dynamoDBDocumentClient = DynamoDBTestSetup.getDocClient();
    await DynamoDBTestSetup.createFindingsTable(findingsTableName);
  });

  afterAll(async () => {
    await DynamoDBTestSetup.deleteTable(findingsTableName);
  });

  beforeEach(async () => {
    await DynamoDBTestSetup.clearTable(findingsTableName, 'findings');
    cursorRepository = new SyncCursorRepository(principal, findingsTableName, dynamoDBDocumentClient);
    securityHubUtils = new FakeSecurityHubUtils();
    processedFindingIds = [];
  });

  it('restarts a chunk when its Security Hub resume token is rejected as expired', async () => {
    // GIVEN a cursor mid-chunk with a resume token, and Security Hub that rejects that token once
    await cursorRepository.resetCursor(accountId, 1);
    const cursor = (await cursorRepository.getCursor(accountId)) as SyncCursor;
    cursor.inProgress = { controlIds: ['Lambda.3'], nextToken: 'page-1' };
    await cursorRepository.saveCursor(accountId, cursor);

    securityHubUtils.rejectResumeTokenOnceFor(['Lambda.3']);
    securityHubUtils.setChunkPages(['Lambda.3'], [[finding('a')], [finding('b')]]);

    // WHEN a slice runs
    const result = await runSyncSlice(
      buildDeps(async () => ['Lambda.3']),
      unboundedBudget,
    );

    // THEN the chunk restarts from the first page (both findings re-fetched — safe, upserts are
    // idempotent) and the pass completes
    expect(processedFindingIds).toEqual(['a', 'b']);
    expect(result.isDone).toBe(true);
    const finalCursor = await cursorRepository.getCursor(accountId);
    expect(finalCursor?.completedControlIds).toEqual(['Lambda.3']);
  });

  it('drops an in-progress chunk that references a control no longer supported, then re-chunks', async () => {
    // GIVEN a persisted in-progress chunk over [A.1, B.1], but B.1 is no longer a supported control
    await cursorRepository.resetCursor(accountId, 2);
    const cursor = (await cursorRepository.getCursor(accountId)) as SyncCursor;
    cursor.inProgress = { controlIds: ['A.1', 'B.1'], nextToken: 'page-1' };
    await cursorRepository.saveCursor(accountId, cursor);

    securityHubUtils.setChunkPages(['A.1'], [[finding('a-only')]]);

    // WHEN a slice runs with only A.1 supported
    const result = await runSyncSlice(
      buildDeps(async () => ['A.1']),
      unboundedBudget,
    );

    // THEN the stale in-progress chunk is discarded and work re-chunks over the current control set
    expect(processedFindingIds).toEqual(['a-only']);
    expect(result.isDone).toBe(true);
    expect(result.totalControlIds).toBe(1);
    const finalCursor = await cursorRepository.getCursor(accountId);
    expect(finalCursor?.completedControlIds).toEqual(['A.1']);
  });

  it('rejects a stale cursor writer via the optimistic-concurrency guard', async () => {
    // GIVEN a persisted cursor that has since advanced (version moved on)
    const fresh = await cursorRepository.resetCursor(accountId, 1); // version 1
    const staleHandle: SyncCursor = { ...fresh };
    await cursorRepository.saveCursor(accountId, fresh); // advances stored version to 2

    // WHEN a writer tries to save based on the now-stale version
    // THEN the conditional write is rejected rather than clobbering the newer cursor
    await expect(cursorRepository.saveCursor(accountId, staleHandle)).rejects.toBeInstanceOf(StaleCursorError);
  });

  it('chunks auto-remediation-enabled controls before the rest', async () => {
    // GIVEN five controls, two of which have automated remediation enabled, and a chunk size of 2
    // so the ordering is observable across chunk boundaries
    securityHubUtils.setChunkPages(['rem-1', 'rem-2'], [[finding('r1')]]);
    securityHubUtils.setChunkPages(['plain-1', 'plain-2'], [[finding('p1')]]);
    securityHubUtils.setChunkPages(['plain-3'], [[finding('p3')]]);

    const remediationEnabled = new Set(['rem-1', 'rem-2']);

    // WHEN a slice runs with the ordering predicate
    const result = await runSyncSlice(
      {
        ...buildDeps(async () => ['plain-1', 'rem-1', 'plain-2', 'rem-2', 'plain-3']),
        isAutomatedRemediationEnabled: (controlId) => remediationEnabled.has(controlId),
        chunkSize: 2,
      },
      unboundedBudget,
    );

    // THEN the remediation-enabled controls are completed as the first chunk, ahead of the rest
    expect(result.isDone).toBe(true);
    const finalCursor = await cursorRepository.getCursor(accountId);
    expect(finalCursor?.completedControlIds?.slice(0, 2)).toEqual(['rem-1', 'rem-2']);

    // AND the slice sums its Security Hub API calls across every chunk it walked (3 chunks × 1 page)
    expect(result.apiCallCount).toBe(3);
  });
});
