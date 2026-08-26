// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { deflate } from 'pako';
import { Logger } from '@aws-lambda-powertools/logger';
import type { ASFFFinding, FindingId, FindingTableItem } from '@asr/data-models';
import { OverdueRemediationService } from '../overdueRemediationService';
import { FindingRepository, OverdueFindingProjection } from '../../common/repositories/findingRepository';
import { RemediationHistoryRepository } from '../../common/repositories/remediationHistoryRepository';
import { executeOrchestrator } from '../../common/utils/orchestrator';
import { Clock } from '../../common/utils/clock';
import { IdGenerator } from '../../common/utils/idGenerator';

jest.mock('../../common/utils/orchestrator');

const executeOrchestratorMock = executeOrchestrator as jest.MockedFunction<typeof executeOrchestrator>;

const FIXED_NOW = new Date('2025-06-01T00:00:00.000Z');

const buildAsffFinding = (overrides: Partial<ASFFFinding> = {}): ASFFFinding => ({
  SchemaVersion: '2018-10-08',
  Id: 'arn:aws:securityhub:us-east-1:111111111111:security-control/S3.1/finding/abc',
  ProductArn: 'arn:aws:securityhub:us-east-1::product/aws/securityhub',
  GeneratorId: 'security-control/S3.1',
  AwsAccountId: '111111111111',
  Region: 'us-east-1',
  Types: [],
  CreatedAt: '2025-01-01T00:00:00Z',
  UpdatedAt: '2025-01-01T00:00:00Z',
  Severity: {},
  Title: 'Overdue finding',
  Resources: [],
  Compliance: { SecurityControlId: 'S3.1' },
  ...overrides,
});

const buildProjection = (
  overrides: Partial<Omit<OverdueFindingProjection, 'findingId'>> & { findingId?: string } = {},
): OverdueFindingProjection => {
  const { findingId = 'finding-001', ...rest } = overrides;
  return {
    findingType: 'security-control/S3.1',
    findingId: findingId as FindingId,
    remediationStatus: 'NOT_STARTED',
    suppressed: false,
    remediationDueBy: '2025-05-01T00:00:00.000Z',
    accountId: '111111111111',
    resourceId: 'arn:aws:s3:::bucket-001',
    creationTime: '2025-04-01T00:00:00.000Z',
    FINDING_CONSTANT: 'finding',
    ...rest,
  };
};

const buildFindingItem = (
  findingId: string,
  asffOverrides: Partial<ASFFFinding> = {},
  itemOverrides: Partial<FindingTableItem> = {},
): FindingTableItem =>
  ({
    findingType: 'security-control/S3.1',
    findingId,
    remediationStatus: 'NOT_STARTED',
    accountId: '111111111111',
    resourceId: 'arn:aws:s3:::bucket-001',
    remediationDueBy: '2025-05-01T00:00:00.000Z',
    enforcementConfigIds: new Set(['config-a']),
    findingJSON: deflate(JSON.stringify(buildAsffFinding(asffOverrides))),
    ...itemOverrides,
  }) as unknown as FindingTableItem;

describe('OverdueRemediationService', () => {
  let queryFindingsByDueBy: jest.Mock;
  let findByKeys: jest.Mock;
  let clearRemediationDueBy: jest.Mock;
  let createRemediationHistoryWithFindingUpdate: jest.Mock;
  let findingRepository: FindingRepository;
  let remediationHistoryRepository: RemediationHistoryRepository;
  let logger: Logger;
  let clock: Clock;
  let idGenerator: IdGenerator;

  const buildService = (perRunCap: number): OverdueRemediationService =>
    new OverdueRemediationService(
      findingRepository,
      remediationHistoryRepository,
      logger,
      clock,
      perRunCap,
      idGenerator,
    );

  beforeEach(() => {
    jest.clearAllMocks();

    queryFindingsByDueBy = jest.fn();
    findByKeys = jest.fn();
    clearRemediationDueBy = jest.fn().mockResolvedValue(undefined);
    createRemediationHistoryWithFindingUpdate = jest.fn().mockResolvedValue(undefined);

    findingRepository = { queryFindingsByDueBy, findByKeys, clearRemediationDueBy } as unknown as FindingRepository;
    remediationHistoryRepository = {
      createRemediationHistoryWithFindingUpdate,
    } as unknown as RemediationHistoryRepository;

    logger = { debug: jest.fn(), info: jest.fn(), warn: jest.fn(), error: jest.fn() } as unknown as Logger;
    clock = { now: () => FIXED_NOW };
    idGenerator = { randomUUID: () => 'test-uuid' };

    executeOrchestratorMock.mockResolvedValue('arn:aws:states:us-east-1:111111111111:execution:orchestrator:exec');
  });

  describe('Property 5: scan eligibility', () => {
    it('triggers only NOT_STARTED, non-suppressed findings and tallies each skip reason', async () => {
      // ARRANGE — a mix of statuses and suppression states; only finding-001 and finding-005 are eligible
      queryFindingsByDueBy.mockResolvedValueOnce({
        items: [
          buildProjection({ findingId: 'finding-001', remediationStatus: 'NOT_STARTED', suppressed: false }),
          buildProjection({ findingId: 'finding-002', remediationStatus: 'IN_PROGRESS' }),
          buildProjection({ findingId: 'finding-003', remediationStatus: 'NOT_STARTED', suppressed: true }),
          buildProjection({ findingId: 'finding-004', remediationStatus: 'FAILED' }),
          buildProjection({ findingId: 'finding-005', remediationStatus: 'NOT_STARTED', suppressed: false }),
        ],
        lastEvaluatedKey: undefined,
      });
      findByKeys.mockResolvedValueOnce([buildFindingItem('finding-001'), buildFindingItem('finding-005')]);

      // ACT
      const result = await buildService(50).remediateOverdueFindings();

      // ASSERT
      expect(result.findingsEvaluated).toBe(5);
      expect(result.findingsSkippedIneligible).toBe(2);
      expect(result.findingsSkippedSuppressedASR).toBe(1);
      expect(result.remediationsTriggered).toBe(2);
      expect(result.findingsRemaining).toBe(0);
      expect(findByKeys).toHaveBeenCalledWith([
        { findingType: 'security-control/S3.1', findingId: 'finding-001' },
        { findingType: 'security-control/S3.1', findingId: 'finding-005' },
      ]);
    });

    it('skips findings suppressed at the Security Hub level after decompression', async () => {
      // ARRANGE — eligible at the GSI level, but the decompressed payload is SH-suppressed
      queryFindingsByDueBy.mockResolvedValueOnce({
        items: [buildProjection({ findingId: 'finding-001' })],
        lastEvaluatedKey: undefined,
      });
      findByKeys.mockResolvedValueOnce([buildFindingItem('finding-001', { Workflow: { Status: 'SUPPRESSED' } })]);

      // ACT
      const result = await buildService(50).remediateOverdueFindings();

      // ASSERT
      expect(result.findingsSkippedSuppressedSH).toBe(1);
      expect(result.remediationsTriggered).toBe(0);
      expect(executeOrchestratorMock).not.toHaveBeenCalled();
      expect(createRemediationHistoryWithFindingUpdate).not.toHaveBeenCalled();
      // The stamp is cleared so the SH-suppressed finding drops out of the GSI on future scans.
      expect(clearRemediationDueBy).toHaveBeenCalledWith('finding-001', 'security-control/S3.1');
    });

    it('fetches nothing and triggers nothing when no overdue finding is eligible', async () => {
      // ARRANGE — every overdue finding is ineligible (status) or ASR-suppressed
      queryFindingsByDueBy.mockResolvedValueOnce({
        items: [
          buildProjection({ findingId: 'finding-001', remediationStatus: 'IN_PROGRESS' }),
          buildProjection({ findingId: 'finding-002', remediationStatus: 'NOT_STARTED', suppressed: true }),
        ],
        lastEvaluatedKey: undefined,
      });

      // ACT
      const result = await buildService(50).remediateOverdueFindings();

      // ASSERT
      expect(result.findingsEvaluated).toBe(2);
      expect(result.remediationsTriggered).toBe(0);
      expect(findByKeys).not.toHaveBeenCalled();
      expect(executeOrchestratorMock).not.toHaveBeenCalled();
    });
  });

  describe('Property 6: orchestrator-first status management', () => {
    it('invokes the orchestrator before writing finding status and delegates the stamp-clearing write on success', async () => {
      // ARRANGE
      queryFindingsByDueBy.mockResolvedValueOnce({
        items: [buildProjection({ findingId: 'finding-001' })],
        lastEvaluatedKey: undefined,
      });
      findByKeys.mockResolvedValueOnce([buildFindingItem('finding-001')]);
      executeOrchestratorMock.mockResolvedValueOnce('exec-1');

      // ACT
      const result = await buildService(50).remediateOverdueFindings();

      // ASSERT — orchestrator call strictly precedes the status write
      expect(result.remediationsTriggered).toBe(1);
      expect(executeOrchestratorMock.mock.invocationCallOrder[0]).toBeLessThan(
        createRemediationHistoryWithFindingUpdate.mock.invocationCallOrder[0],
      );
      // The status-change transaction (which clears remediationDueBy + enforcementConfigIds) is
      // invoked with an IN_PROGRESS finding, the deadline-enforcement principal, and the execution id.
      expect(createRemediationHistoryWithFindingUpdate).toHaveBeenCalledWith(
        expect.objectContaining({
          findingId: 'finding-001',
          remediationStatus: 'IN_PROGRESS',
          executionId: 'exec-1',
          lastUpdatedBy: 'DeadlineEnforcement',
        }),
        'exec-1',
      );
    });

    it('does not write finding status when the orchestrator invocation throws', async () => {
      // ARRANGE
      queryFindingsByDueBy.mockResolvedValueOnce({
        items: [buildProjection({ findingId: 'finding-001' })],
        lastEvaluatedKey: undefined,
      });
      findByKeys.mockResolvedValueOnce([buildFindingItem('finding-001')]);
      executeOrchestratorMock.mockRejectedValueOnce(new Error('StepFunctions unavailable'));

      // ACT
      const result = await buildService(50).remediateOverdueFindings();

      // ASSERT
      expect(result.remediationsTriggered).toBe(0);
      expect(result.findingsSkippedError).toBe(1);
      expect(createRemediationHistoryWithFindingUpdate).not.toHaveBeenCalled();
    });

    it('does not write finding status when the orchestrator returns no execution id', async () => {
      // ARRANGE
      queryFindingsByDueBy.mockResolvedValueOnce({
        items: [buildProjection({ findingId: 'finding-001' })],
        lastEvaluatedKey: undefined,
      });
      findByKeys.mockResolvedValueOnce([buildFindingItem('finding-001')]);
      executeOrchestratorMock.mockResolvedValueOnce(undefined);

      // ACT
      const result = await buildService(50).remediateOverdueFindings();

      // ASSERT
      expect(result.remediationsTriggered).toBe(0);
      expect(result.findingsSkippedError).toBe(1);
      expect(createRemediationHistoryWithFindingUpdate).not.toHaveBeenCalled();
    });
  });

  describe('Property 7: per-run cap', () => {
    it('triggers at most perRunCap findings and reports the remainder', async () => {
      // ARRANGE — 5 eligible findings, cap of 2
      const projections = ['f-1', 'f-2', 'f-3', 'f-4', 'f-5'].map((findingId) => buildProjection({ findingId }));
      queryFindingsByDueBy.mockResolvedValueOnce({ items: projections, lastEvaluatedKey: undefined });
      findByKeys.mockResolvedValueOnce([buildFindingItem('f-1'), buildFindingItem('f-2')]);

      // ACT
      const result = await buildService(2).remediateOverdueFindings();

      // ASSERT
      expect(result.findingsEvaluated).toBe(5);
      expect(result.remediationsTriggered).toBe(2);
      expect(result.findingsRemaining).toBe(3);
      expect(findByKeys).toHaveBeenCalledWith([
        { findingType: 'security-control/S3.1', findingId: 'f-1' },
        { findingType: 'security-control/S3.1', findingId: 'f-2' },
      ]);
    });
  });

  describe('Property 8: oldest-overdue-first ordering', () => {
    it('processes findings in GSI (oldest-overdue-first) order even when BatchGetItem returns them shuffled', async () => {
      // ARRANGE — GSI returns ascending by remediationDueBy; BatchGetItem returns them out of order
      queryFindingsByDueBy.mockResolvedValueOnce({
        items: [
          buildProjection({ findingId: 'oldest', remediationDueBy: '2025-01-01T00:00:00.000Z' }),
          buildProjection({ findingId: 'middle', remediationDueBy: '2025-02-01T00:00:00.000Z' }),
          buildProjection({ findingId: 'newest', remediationDueBy: '2025-03-01T00:00:00.000Z' }),
        ],
        lastEvaluatedKey: undefined,
      });
      findByKeys.mockResolvedValueOnce([
        buildFindingItem('newest'),
        buildFindingItem('oldest'),
        buildFindingItem('middle'),
      ]);

      // ACT
      const result = await buildService(50).remediateOverdueFindings();

      // ASSERT
      expect(result.remediationsTriggered).toBe(3);
      const processedOrder = createRemediationHistoryWithFindingUpdate.mock.calls.map((call) => call[0].findingId);
      expect(processedOrder).toEqual(['oldest', 'middle', 'newest']);
    });
  });

  describe('pagination', () => {
    it('pages through the GSI until perRunCap eligible findings are accumulated', async () => {
      // ARRANGE — first page is fully ineligible, the cap is met on the second page
      queryFindingsByDueBy
        .mockResolvedValueOnce({
          items: [buildProjection({ findingId: 'page1-ineligible', remediationStatus: 'IN_PROGRESS' })],
          lastEvaluatedKey: { findingId: 'page1-ineligible' },
        })
        .mockResolvedValueOnce({
          items: [buildProjection({ findingId: 'page2-eligible' })],
          lastEvaluatedKey: undefined,
        });
      findByKeys.mockResolvedValueOnce([buildFindingItem('page2-eligible')]);

      // ACT
      const result = await buildService(50).remediateOverdueFindings();

      // ASSERT
      expect(queryFindingsByDueBy).toHaveBeenCalledTimes(2);
      expect(queryFindingsByDueBy).toHaveBeenLastCalledWith(FIXED_NOW.toISOString(), {
        exclusiveStartKey: { findingId: 'page1-ineligible' },
      });
      expect(result.findingsEvaluated).toBe(2);
      expect(result.findingsSkippedIneligible).toBe(1);
      expect(result.remediationsTriggered).toBe(1);
    });
  });

  describe('error handling', () => {
    it('skips a finding whose findingJSON is corrupt without aborting the run', async () => {
      // ARRANGE — first item has unparseable findingJSON, second is healthy
      queryFindingsByDueBy.mockResolvedValueOnce({
        items: [buildProjection({ findingId: 'corrupt' }), buildProjection({ findingId: 'healthy' })],
        lastEvaluatedKey: undefined,
      });
      findByKeys.mockResolvedValueOnce([
        buildFindingItem('corrupt', {}, { findingJSON: new Uint8Array([1, 2, 3, 4]) }),
        buildFindingItem('healthy'),
      ]);

      // ACT
      const result = await buildService(50).remediateOverdueFindings();

      // ASSERT
      expect(result.findingsSkippedError).toBe(1);
      expect(result.remediationsTriggered).toBe(1);
      expect(createRemediationHistoryWithFindingUpdate).toHaveBeenCalledTimes(1);
    });

    it('skips enforcement for the invocation when the GSI query fails', async () => {
      // ARRANGE
      queryFindingsByDueBy.mockRejectedValueOnce(new Error('DynamoDB unavailable'));

      // ACT
      const result = await buildService(50).remediateOverdueFindings();

      // ASSERT — zero-valued result, no remediation attempted
      expect(result.findingsEvaluated).toBe(0);
      expect(result.remediationsTriggered).toBe(0);
      expect(findByKeys).not.toHaveBeenCalled();
      expect(executeOrchestratorMock).not.toHaveBeenCalled();
    });

    it('processes only the findings BatchGetItem returns when some keys are unprocessed', async () => {
      // ARRANGE — two eligible findings, but BatchGetItem returns only one
      queryFindingsByDueBy.mockResolvedValueOnce({
        items: [buildProjection({ findingId: 'returned' }), buildProjection({ findingId: 'unprocessed' })],
        lastEvaluatedKey: undefined,
      });
      findByKeys.mockResolvedValueOnce([buildFindingItem('returned')]);

      // ACT
      const result = await buildService(50).remediateOverdueFindings();

      // ASSERT — only the returned finding is remediated; the missing one is left for next invocation
      // and is tallied into findingsSkippedError so the per-finding accounting stays balanced.
      expect(result.remediationsTriggered).toBe(1);
      expect(result.findingsSkippedError).toBe(1);
      expect(createRemediationHistoryWithFindingUpdate).toHaveBeenCalledTimes(1);
      expect(createRemediationHistoryWithFindingUpdate).toHaveBeenCalledWith(
        expect.objectContaining({ findingId: 'returned' }),
        expect.any(String),
      );
    });
  });

  describe('construction', () => {
    it('defaults to the crypto id generator when one is not supplied', async () => {
      // ARRANGE — construct without the optional idGenerator argument
      const service = new OverdueRemediationService(findingRepository, remediationHistoryRepository, logger, clock, 50);
      queryFindingsByDueBy.mockResolvedValueOnce({
        items: [buildProjection({ findingId: 'finding-001' })],
        lastEvaluatedKey: undefined,
      });
      findByKeys.mockResolvedValueOnce([buildFindingItem('finding-001')]);

      // ACT
      const result = await service.remediateOverdueFindings();

      // ASSERT
      expect(result.remediationsTriggered).toBe(1);
    });
  });
});
