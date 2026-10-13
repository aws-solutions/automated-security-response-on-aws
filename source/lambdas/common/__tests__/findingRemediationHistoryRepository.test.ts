// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { DynamoDBDocumentClient, PutCommand } from '@aws-sdk/lib-dynamodb';
import { FindingRemediationHistoryRepository } from '../repositories/findingRemediationHistoryRepository';
import { DynamoDBTestSetup } from './dynamodbSetup';
import { remediationHistoryTableName } from './envSetup';

// ADR 0003 / unit-testing.md: DynamoDB access is exercised against DynamoDB
// Local, not aws-sdk-client-mock, so the GSI query, the findingType fallback,
// and the finding-id filter are validated against a real key schema rather than
// a stub that would accept any expression.

const CONTROL_ARN = 'arn:aws:securityhub:us-east-1:111122223333:security-control/S3.1/finding';
const FINDING_ID = `${CONTROL_ARN}/aaaa-bbbb`;
const OTHER_FINDING_ID = `${CONTROL_ARN}/cccc-dddd`;

describe('FindingRemediationHistoryRepository (DynamoDB Local)', () => {
  let dynamoDBDocumentClient: DynamoDBDocumentClient;
  let repository: FindingRemediationHistoryRepository;

  beforeAll(async () => {
    await DynamoDBTestSetup.initialize();
    dynamoDBDocumentClient = DynamoDBTestSetup.getDocClient();
    await DynamoDBTestSetup.createRemediationHistoryTable(remediationHistoryTableName);
  });

  afterAll(async () => {
    await DynamoDBTestSetup.deleteTable(remediationHistoryTableName);
  });

  beforeEach(async () => {
    await DynamoDBTestSetup.clearTable(remediationHistoryTableName, 'remediationHistory');
    repository = new FindingRemediationHistoryRepository(remediationHistoryTableName, dynamoDBDocumentClient);
  });

  /**
   * Writes a history record keyed for both the primary table and the findingId GSI.
   *
   * `omitGsiKey` leaves out `lastUpdatedTime#findingId`; the GSI is sparse on that attribute,
   * so such rows are reachable only through the findingType fallback query.
   */
  async function putRecord(overrides: {
    findingId: string;
    executionId: string;
    findingType?: string;
    remediationStatus?: string;
    lastUpdatedTime?: string;
    resourceId?: string;
    rollbackAvailable?: boolean;
    omitGsiKey?: boolean;
  }): Promise<void> {
    const findingType = overrides.findingType ?? 'security-control/S3.1';
    const lastUpdatedTime = overrides.lastUpdatedTime ?? '2026-01-01T00:00:00Z';
    await dynamoDBDocumentClient.send(
      new PutCommand({
        TableName: remediationHistoryTableName,
        Item: {
          findingType,
          'findingId#executionId': `${overrides.findingId}#${overrides.executionId}`,
          findingId: overrides.findingId,
          ...(!overrides.omitGsiKey && { 'lastUpdatedTime#findingId': `${lastUpdatedTime}#${overrides.findingId}` }),
          executionId: overrides.executionId,
          remediationStatus: overrides.remediationStatus ?? 'SUCCESS',
          lastUpdatedTime,
          resourceId: overrides.resourceId ?? 'bucket-1',
          ...(overrides.rollbackAvailable !== undefined && { rollbackAvailable: overrides.rollbackAvailable }),
        },
      }),
    );
  }

  it('returns the finding history via the findingId GSI, newest first', async () => {
    await putRecord({ findingId: FINDING_ID, executionId: 'exec-1', lastUpdatedTime: '2026-01-01T00:00:00Z' });
    await putRecord({ findingId: FINDING_ID, executionId: 'exec-2', lastUpdatedTime: '2026-01-02T00:00:00Z' });

    const { entries, accessDenied } = await repository.findByFindingId(FINDING_ID, 10);

    expect(accessDenied).toBe(false);
    expect(entries.map((e) => e.executionId)).toEqual(['exec-2', 'exec-1']);
  });

  it('honors the maxResults limit', async () => {
    for (let i = 0; i < 5; i++) {
      await putRecord({
        findingId: FINDING_ID,
        executionId: `exec-${i}`,
        lastUpdatedTime: `2026-01-0${i + 1}T00:00:00Z`,
      });
    }

    const { entries } = await repository.findByFindingId(FINDING_ID, 3);

    expect(entries).toHaveLength(3);
  });

  it('returns an empty result (not accessDenied) when the finding has no history', async () => {
    const { entries, accessDenied } = await repository.findByFindingId(FINDING_ID, 10);

    expect(entries).toEqual([]);
    expect(accessDenied).toBe(false);
  });

  it('reports isRollbackEligible from status + capability, narrowed to the newest row per finding', async () => {
    // Four rows for the same finding, oldest to newest: an eligible SUCCESS, a retryable
    // ROLLBACK_FAILED, an already-rolled-back row (still rollbackAvailable: true in storage),
    // and a newest SUCCESS with no rollback capability. Only the newest row may claim
    // eligibility — and here it cannot — so every row reads false, matching what the REST
    // remediations search reports for the same finding. Evaluating rows in isolation would
    // have left the two oldest marked eligible long after later attempts superseded them.
    await putRecord({
      findingId: FINDING_ID,
      executionId: 'exec-success',
      remediationStatus: 'SUCCESS',
      rollbackAvailable: true,
      lastUpdatedTime: '2026-01-01T00:00:00Z',
    });
    await putRecord({
      findingId: FINDING_ID,
      executionId: 'exec-rollback-failed',
      remediationStatus: 'ROLLBACK_FAILED',
      rollbackAvailable: true,
      lastUpdatedTime: '2026-01-02T00:00:00Z',
    });
    await putRecord({
      findingId: FINDING_ID,
      executionId: 'exec-rolled-back',
      remediationStatus: 'ROLLBACK_SUCCESS',
      rollbackAvailable: true,
      lastUpdatedTime: '2026-01-03T00:00:00Z',
    });
    await putRecord({
      findingId: FINDING_ID,
      executionId: 'exec-no-capability',
      remediationStatus: 'SUCCESS',
      lastUpdatedTime: '2026-01-04T00:00:00Z',
    });

    const { entries } = await repository.findByFindingId(FINDING_ID, 10);

    expect(Object.fromEntries(entries.map((e) => [e.executionId, e.isRollbackEligible]))).toEqual({
      'exec-success': false,
      'exec-rollback-failed': false,
      'exec-rolled-back': false,
      'exec-no-capability': false,
    });
  });

  it('keeps eligibility only on the newest row when that row is itself eligible', async () => {
    await putRecord({
      findingId: FINDING_ID,
      executionId: 'exec-old-success',
      remediationStatus: 'SUCCESS',
      rollbackAvailable: true,
      lastUpdatedTime: '2026-01-01T00:00:00Z',
    });
    await putRecord({
      findingId: FINDING_ID,
      executionId: 'exec-newest-retryable',
      remediationStatus: 'ROLLBACK_FAILED',
      rollbackAvailable: true,
      lastUpdatedTime: '2026-01-02T00:00:00Z',
    });

    const { entries } = await repository.findByFindingId(FINDING_ID, 10);

    expect(Object.fromEntries(entries.map((e) => [e.executionId, e.isRollbackEligible]))).toEqual({
      'exec-old-success': false,
      'exec-newest-retryable': true,
    });
  });

  it('does not let a stale eligible row survive when the superseding row shares its timestamp', async () => {
    // A SUCCESS and the ROLLBACK_SUCCESS that undid it can be stamped in the same instant. Both
    // then tie as "newest"; the tie must resolve against eligibility, not in its favour.
    await putRecord({
      findingId: FINDING_ID,
      executionId: 'exec-success',
      remediationStatus: 'SUCCESS',
      rollbackAvailable: true,
      lastUpdatedTime: '2026-01-02T00:00:00Z',
    });
    await putRecord({
      findingId: FINDING_ID,
      executionId: 'exec-rolled-back',
      remediationStatus: 'ROLLBACK_SUCCESS',
      rollbackAvailable: true,
      lastUpdatedTime: '2026-01-02T00:00:00Z',
    });

    const { entries } = await repository.findByFindingId(FINDING_ID, 10);

    expect(entries).toHaveLength(2);
    expect(entries.every((e) => e.isRollbackEligible === false)).toBe(true);
  });

  it('keeps exactly one row eligible when two eligible rows tie for newest', async () => {
    // Two SUCCESS rows stamped in the same instant. Neither is superseded, but "at most one row
    // per finding" still has to hold, so the tie is broken deterministically on executionId.
    await putRecord({
      findingId: FINDING_ID,
      executionId: 'exec-a',
      remediationStatus: 'SUCCESS',
      rollbackAvailable: true,
      lastUpdatedTime: '2026-01-01T00:00:00Z',
    });
    await putRecord({
      findingId: FINDING_ID,
      executionId: 'exec-b',
      remediationStatus: 'SUCCESS',
      rollbackAvailable: true,
      lastUpdatedTime: '2026-01-01T00:00:00Z',
    });

    const { entries } = await repository.findByFindingId(FINDING_ID, 10);

    expect(entries).toHaveLength(2);
    expect(entries.filter((e) => e.isRollbackEligible).map((e) => e.executionId)).toEqual(['exec-b']);
  });

  it('does not let a stale eligible row survive on a finding that has since been rolled back', async () => {
    await putRecord({
      findingId: FINDING_ID,
      executionId: 'exec-success',
      remediationStatus: 'SUCCESS',
      rollbackAvailable: true,
      lastUpdatedTime: '2026-01-01T00:00:00Z',
    });
    await putRecord({
      findingId: FINDING_ID,
      executionId: 'exec-rolled-back',
      remediationStatus: 'ROLLBACK_SUCCESS',
      rollbackAvailable: true,
      lastUpdatedTime: '2026-01-02T00:00:00Z',
    });

    const { entries } = await repository.findByFindingId(FINDING_ID, 10);

    expect(entries.every((e) => e.isRollbackEligible === false)).toBe(true);
  });

  it('keeps the newest-by-time row when the findingType fallback is truncated to maxResults', async () => {
    // Rows reachable only via the fallback. The base table sorts them by executionId, so the
    // newest-by-time ROLLBACK_SUCCESS row ('exec-a...') would sort *last* and be dropped by a
    // maxResults slice taken before sorting by time — leaving the older SUCCESS row as the
    // apparent newest and still advertising rollback.
    await putRecord({
      findingId: FINDING_ID,
      executionId: 'exec-a-rolled-back',
      remediationStatus: 'ROLLBACK_SUCCESS',
      rollbackAvailable: true,
      lastUpdatedTime: '2026-01-03T00:00:00Z',
      omitGsiKey: true,
    });
    await putRecord({
      findingId: FINDING_ID,
      executionId: 'exec-b-success',
      remediationStatus: 'SUCCESS',
      rollbackAvailable: true,
      lastUpdatedTime: '2026-01-02T00:00:00Z',
      omitGsiKey: true,
    });
    await putRecord({
      findingId: FINDING_ID,
      executionId: 'exec-c-old',
      remediationStatus: 'SUCCESS',
      rollbackAvailable: true,
      lastUpdatedTime: '2026-01-01T00:00:00Z',
      omitGsiKey: true,
    });

    const { entries } = await repository.findByFindingId(FINDING_ID, 2);

    expect(entries.map((e) => e.executionId)).toEqual(['exec-a-rolled-back', 'exec-b-success']);
    expect(entries.every((e) => e.isRollbackEligible === false)).toBe(true);
  });

  it('finds the finding on the fallback path even when the control has many other findings', async () => {
    // The fallback queries the control-scoped partition. A query over that partition with a
    // fixed over-fetch Limit and no sort-key narrowing reads rows in sort-key order
    // (`findingId#executionId`, descending) and would exhaust on other findings before reaching
    // this one — so the neighbours here are given ids that sort *after* ours in that order
    // (`zzzz-…` > `aaaa-bbbb`) and outnumber any plausible Limit. Only a query keyed to this
    // finding's sort-key prefix can find its rows.
    for (let i = 0; i < 60; i++) {
      await putRecord({
        findingId: `${CONTROL_ARN}/zzzz-${String(i).padStart(4, '0')}`,
        executionId: `other-${i}`,
        omitGsiKey: true,
      });
    }
    await putRecord({
      findingId: FINDING_ID,
      executionId: 'exec-success',
      remediationStatus: 'SUCCESS',
      rollbackAvailable: true,
      lastUpdatedTime: '2026-01-01T00:00:00Z',
      omitGsiKey: true,
    });
    await putRecord({
      findingId: FINDING_ID,
      executionId: 'exec-rolled-back',
      remediationStatus: 'ROLLBACK_SUCCESS',
      rollbackAvailable: true,
      lastUpdatedTime: '2026-01-02T00:00:00Z',
      omitGsiKey: true,
    });

    const { entries } = await repository.findByFindingId(FINDING_ID, 10);

    expect(entries.map((e) => e.executionId)).toEqual(['exec-rolled-back', 'exec-success']);
    expect(entries.every((e) => e.isRollbackEligible === false)).toBe(true);
  });
});
