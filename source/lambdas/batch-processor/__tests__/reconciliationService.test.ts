// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { deflate } from 'pako';
import { Logger } from '@aws-lambda-powertools/logger';
import type {
  ASFFFinding,
  FindingTableItem,
  NotificationConfigurationItem,
  ReconciliationTask,
} from '@asr/data-models';
import { RECONCILIATION_CONFIG_ID_PREFIX } from '@asr/data-models';
import {
  DEFAULT_RECONCILIATION_FINDING_LIMIT,
  ReconciliationService,
  SCAN_ALL_BOOKMARK_CONTROL_ID,
} from '../reconciliationService';
import { FindingRepository } from '../../common/repositories/findingRepository';
import { NotificationConfigurationRepository } from '../../common/repositories/notificationConfigurationRepository';
import { ResourceFilterEvaluator } from '../../pre-processor/ResourceFilterEvaluator';
import { Clock } from '../../common/utils/clock';
import { asConfigId, asFindingId } from '../../common/__tests__/utils';

const CONTROL_ID = 'security-control/S3.1';
// The bare Security Hub control id as stored on a notification configuration. The findings table
// partitions on the prefixed `findingType` (CONTROL_ID), so reconciliation maps config control ids
// to that form via controlIdToFindingType before querying — these tests assert that mapping.
const CONFIG_CONTROL_ID = 'S3.1';
const CONFIG_A = asConfigId('config-a');
const CONFIG_B = asConfigId('config-b');
const CREATION_TIME = '2025-01-01T00:00:00.000Z';
const FIXED_NOW = new Date('2025-06-01T00:00:00.000Z');

// CREATION_TIME (2025-01-01) plus any deadline-day count lands well before FIXED_NOW + 24h, so the
// 24-hour Minimum_Grace_Period floor inside computeRemediationDueBy always wins: every stamp the
// service writes for these backlog findings is clamped to FIXED_NOW + 24h.
const GRACE_FLOOR_DUE_BY = '2025-06-02T00:00:00.000Z'; // FIXED_NOW + 24h

// Seed value for an already-stamped finding's remediationDueBy in GSI projections (input data, not
// an expected output, so it is unaffected by the grace-period floor).
const DUE_BY_10_DAYS = '2025-01-11T00:00:00.000Z';

const buildAsffFinding = (overrides: Partial<ASFFFinding> = {}): ASFFFinding => ({
  SchemaVersion: '2018-10-08',
  Id: 'arn:aws:securityhub:us-east-1:111111111111:security-control/S3.1/finding/abc',
  ProductArn: 'arn:aws:securityhub:us-east-1::product/aws/securityhub',
  GeneratorId: 'security-control/S3.1',
  AwsAccountId: '111111111111',
  Region: 'us-east-1',
  Types: [],
  CreatedAt: CREATION_TIME,
  UpdatedAt: CREATION_TIME,
  Severity: {},
  Title: 'Reconciliation finding',
  Resources: [],
  Compliance: { SecurityControlId: 'S3.1' },
  ...overrides,
});

const createFindingItem = (
  overrides: Partial<Omit<FindingTableItem, 'findingId'>> & { findingId?: string; corruptFindingJSON?: boolean } = {},
): FindingTableItem => {
  const { corruptFindingJSON = false, findingId = 'finding-001', ...rest } = overrides;
  return {
    findingType: CONTROL_ID,
    findingId: asFindingId(findingId),
    accountId: '111111111111',
    resourceId: 'arn:aws:s3:::bucket-001',
    resourceType: 'AwsS3Bucket',
    resourceTypeNormalized: 's3',
    severity: 'HIGH',
    severityNormalized: 70,
    region: 'us-east-1',
    remediationStatus: 'NOT_STARTED',
    lastUpdatedTime: CREATION_TIME,
    findingDescription: 'Reconciliation finding',
    securityHubUpdatedAtTime: CREATION_TIME,
    suppressed: false,
    creationTime: CREATION_TIME,
    'securityHubUpdatedAtTime#findingId': `${CREATION_TIME}#${findingId}`,
    'severityNormalized#securityHubUpdatedAtTime#findingId': `70#${CREATION_TIME}#${findingId}`,
    findingJSON: corruptFindingJSON ? new Uint8Array([1, 2, 3, 4]) : deflate(JSON.stringify(buildAsffFinding())),
    findingIdControl: `${findingId}#${CONTROL_ID}`,
    FINDING_CONSTANT: 'finding',
    expireAt: 0,
    ...rest,
  };
};

const createConfig = (
  overrides: Partial<NotificationConfigurationItem> & { deadlineDays?: number } = {},
): NotificationConfigurationItem => {
  const { deadlineDays = 10, contentOptions, ...rest } = overrides;
  return {
    configId: CONFIG_A,
    name: 'Enforcement Config',
    enabled: true,
    notificationType: 'finding',
    severityFilter: ['All'],
    controlIds: [CONFIG_CONTROL_ID],
    resourceFilterIds: [],
    deliveryChannels: [],
    batchWindow: { enabled: false },
    contentOptions: {
      includeManualRemediationLink: false,
      includeRemediationDeadline: true,
      remediationDeadlineDays: deadlineDays,
      enforceDeadline: true,
      includeIaCSnippet: false,
      includeEnableAutomationLink: false,
      ...contentOptions,
    },
    version: 1,
    createdAt: '2025-01-01T00:00:00Z',
    createdBy: 'admin@example.com',
    ...rest,
  };
};

const createTask = (overrides: Partial<ReconciliationTask> = {}): ReconciliationTask => ({
  configId: `${RECONCILIATION_CONFIG_ID_PREFIX}task-uuid`,
  windowEnd: FIXED_NOW.toISOString(),
  status: 'IN_PROGRESS',
  taskType: 'enable',
  itemCount: 0,
  expireAt: 0,
  ...overrides,
});

describe('ReconciliationService', () => {
  const logger = new Logger({ logLevel: 'SILENT' });
  const stubClock: Clock = { now: () => FIXED_NOW };

  let queryByControlId: jest.Mock;
  let queryAllStampedFindings: jest.Mock;
  let stampRemediationDueBy: jest.Mock;
  let forceStampRemediationDueBy: jest.Mock;
  let clearRemediationDueBy: jest.Mock;
  let findConfigById: jest.Mock;
  let evaluateFilters: jest.Mock;

  let findingRepository: FindingRepository;
  let notificationConfigurationRepository: NotificationConfigurationRepository;
  let resourceFilterEvaluator: ResourceFilterEvaluator;

  const buildService = (
    maxFindingsPerInvocation: number = DEFAULT_RECONCILIATION_FINDING_LIMIT,
  ): ReconciliationService =>
    new ReconciliationService(
      findingRepository,
      notificationConfigurationRepository,
      resourceFilterEvaluator,
      logger,
      stubClock,
      maxFindingsPerInvocation,
    );

  beforeEach(() => {
    jest.clearAllMocks();

    queryByControlId = jest.fn().mockResolvedValue({ items: [], lastEvaluatedKey: undefined });
    queryAllStampedFindings = jest.fn().mockResolvedValue({ items: [], lastEvaluatedKey: undefined });
    stampRemediationDueBy = jest.fn().mockResolvedValue({ configIdsUpdated: true, dueByUpdated: true });
    forceStampRemediationDueBy = jest.fn().mockResolvedValue(undefined);
    clearRemediationDueBy = jest.fn().mockResolvedValue(undefined);
    findConfigById = jest.fn().mockResolvedValue(undefined);
    evaluateFilters = jest.fn().mockResolvedValue({ passed: true, reason: 'all_filters_matched' });

    findingRepository = {
      queryByControlId,
      queryAllStampedFindings,
      stampRemediationDueBy,
      forceStampRemediationDueBy,
      clearRemediationDueBy,
    } as unknown as FindingRepository;
    notificationConfigurationRepository = { findConfigById } as unknown as NotificationConfigurationRepository;
    resourceFilterEvaluator = { evaluateFilters } as unknown as ResourceFilterEvaluator;
  });

  describe('enable', () => {
    it('stamps NOT_STARTED findings that match resource filters and skips ineligible or non-matching ones', async () => {
      // ARRANGE — one live enforcement config targeting CONTROL_ID with a resource filter. The query
      // page deliberately includes findings the in-code guards must reject (Requirement 9.9 statuses,
      // corrupt payload, failing resource filter) alongside the single finding that should be stamped.
      findConfigById.mockResolvedValue(createConfig({ resourceFilterIds: ['filter-1'], deadlineDays: 10 }));
      queryByControlId.mockResolvedValueOnce({
        items: [
          createFindingItem({ findingId: 'in-progress', remediationStatus: 'IN_PROGRESS' }),
          createFindingItem({ findingId: 'success', remediationStatus: 'SUCCESS' }),
          createFindingItem({ findingId: 'corrupt', corruptFindingJSON: true }),
          createFindingItem({ findingId: 'matches' }),
          createFindingItem({ findingId: 'no-match' }),
        ],
        lastEvaluatedKey: undefined,
      });
      evaluateFilters.mockResolvedValueOnce({ passed: true }).mockResolvedValueOnce({ passed: false });

      // ACT
      const result = await buildService().processTask(createTask({ taskType: 'enable', newConfig: createConfig() }));

      // ASSERT — only the matching NOT_STARTED finding is stamped, with the shortest-deadline-wins
      // conditional method and this config's deadline.
      expect(result).toEqual({ isComplete: true, itemsProcessed: 5 });
      expect(stampRemediationDueBy).toHaveBeenCalledTimes(1);
      expect(stampRemediationDueBy).toHaveBeenCalledWith('matches', CONTROL_ID, GRACE_FLOOR_DUE_BY, [CONFIG_A]);
      expect(queryByControlId).toHaveBeenCalledWith(CONTROL_ID, {
        exclusiveStartKey: undefined,
        limit: DEFAULT_RECONCILIATION_FINDING_LIMIT,
        remediationStatusEquals: 'NOT_STARTED',
      });
    });

    it('isolates a finding whose write throws so the task completes and remaining findings are stamped', async () => {
      // ARRANGE — two matching NOT_STARTED findings; the first finding's stamp write fails.
      findConfigById.mockResolvedValue(createConfig({ deadlineDays: 10 }));
      queryByControlId.mockResolvedValueOnce({
        items: [createFindingItem({ findingId: 'boom' }), createFindingItem({ findingId: 'ok' })],
        lastEvaluatedKey: undefined,
      });
      stampRemediationDueBy
        .mockRejectedValueOnce(new Error('conditional check failed'))
        .mockResolvedValueOnce({ configIdsUpdated: true, dueByUpdated: true });

      // ACT
      const result = await buildService().processTask(createTask({ taskType: 'enable', newConfig: createConfig() }));

      // ASSERT — the failing finding is skipped, the task still completes, and the healthy finding is stamped.
      expect(result).toEqual({ isComplete: true, itemsProcessed: 2 });
      expect(stampRemediationDueBy).toHaveBeenCalledTimes(2);
      expect(stampRemediationDueBy).toHaveBeenCalledWith('ok', CONTROL_ID, GRACE_FLOOR_DUE_BY, [CONFIG_A]);
    });

    it('stamps NOT_STARTED findings without evaluating filters or decompressing when the config has no resource filters', async () => {
      // ARRANGE — live config with no resource filters. The page includes a corrupt-payload finding
      // to prove this path never decompresses findingJSON: with no filters, every NOT_STARTED finding
      // matches and is stamped regardless of payload.
      findConfigById.mockResolvedValue(createConfig({ resourceFilterIds: [], deadlineDays: 10 }));
      queryByControlId.mockResolvedValueOnce({
        items: [
          createFindingItem({ findingId: 'plain' }),
          createFindingItem({ findingId: 'corrupt', corruptFindingJSON: true }),
        ],
        lastEvaluatedKey: undefined,
      });

      // ACT
      const result = await buildService().processTask(createTask({ taskType: 'enable', newConfig: createConfig() }));

      // ASSERT — both stamped with this config's deadline; resource-filter evaluation skipped entirely.
      expect(result).toEqual({ isComplete: true, itemsProcessed: 2 });
      expect(evaluateFilters).not.toHaveBeenCalled();
      expect(stampRemediationDueBy).toHaveBeenCalledTimes(2);
      expect(stampRemediationDueBy).toHaveBeenCalledWith('plain', CONTROL_ID, GRACE_FLOOR_DUE_BY, [CONFIG_A]);
      expect(stampRemediationDueBy).toHaveBeenCalledWith('corrupt', CONTROL_ID, GRACE_FLOOR_DUE_BY, [CONFIG_A]);
    });

    it('does nothing when the live config is no longer enforcement-enabled', async () => {
      // ARRANGE — the config was disabled between task creation and processing.
      findConfigById.mockResolvedValue(createConfig({ enabled: false }));

      // ACT
      const result = await buildService().processTask(createTask({ taskType: 'enable', newConfig: createConfig() }));

      // ASSERT
      expect(result).toEqual({ isComplete: true, itemsProcessed: 0 });
      expect(queryByControlId).not.toHaveBeenCalled();
      expect(stampRemediationDueBy).not.toHaveBeenCalled();
    });

    it('does not enumerate or stamp for a match-all (empty controlIds) config', async () => {
      // ARRANGE — a match-all enable relies on write-time stamping + sync refresh, never a full scan.
      findConfigById.mockResolvedValue(createConfig({ controlIds: [] }));

      // ACT
      const result = await buildService().processTask(createTask({ taskType: 'enable', newConfig: createConfig() }));

      // ASSERT
      expect(result).toEqual({ isComplete: true, itemsProcessed: 0 });
      expect(queryByControlId).not.toHaveBeenCalled();
      expect(queryAllStampedFindings).not.toHaveBeenCalled();
      expect(stampRemediationDueBy).not.toHaveBeenCalled();
    });

    it('does nothing when the task carries no configuration snapshot', async () => {
      // ARRANGE — neither newConfig nor oldConfig present.

      // ACT
      const result = await buildService().processTask(createTask({ taskType: 'enable' }));

      // ASSERT
      expect(result).toEqual({ isComplete: true, itemsProcessed: 0 });
      expect(findConfigById).not.toHaveBeenCalled();
    });
  });

  describe('Property 10: config disable', () => {
    it('clears remediationDueBy when the disabled config was the only contributor', async () => {
      // ARRANGE — finding references only the disabled config.
      const disabled = createConfig({ configId: CONFIG_A });
      queryByControlId.mockResolvedValueOnce({
        items: [createFindingItem({ findingId: 'finding-1', enforcementConfigIds: new Set([CONFIG_A]) })],
        lastEvaluatedKey: undefined,
      });

      // ACT
      const result = await buildService().processTask(createTask({ taskType: 'disable', oldConfig: disabled }));

      // ASSERT
      expect(result).toEqual({ isComplete: true, itemsProcessed: 1 });
      expect(clearRemediationDueBy).toHaveBeenCalledTimes(1);
      expect(clearRemediationDueBy).toHaveBeenCalledWith('finding-1', CONTROL_ID);
      expect(forceStampRemediationDueBy).not.toHaveBeenCalled();
    });

    it('leaves findings that never referenced the disabled config untouched', async () => {
      // ARRANGE — finding references a different config only.
      queryByControlId.mockResolvedValueOnce({
        items: [createFindingItem({ findingId: 'finding-1', enforcementConfigIds: new Set([CONFIG_B]) })],
        lastEvaluatedKey: undefined,
      });

      // ACT
      const result = await buildService().processTask(
        createTask({ taskType: 'disable', oldConfig: createConfig({ configId: CONFIG_A }) }),
      );

      // ASSERT
      expect(result.itemsProcessed).toBe(1);
      expect(clearRemediationDueBy).not.toHaveBeenCalled();
      expect(forceStampRemediationDueBy).not.toHaveBeenCalled();
    });

    it('recalculates remediationDueBy from the remaining contributing config when one is disabled (multi-config overlap)', async () => {
      // ARRANGE — finding contributed to by two configs (stored as a plain array); CONFIG_A is being
      // disabled and CONFIG_B (live, 30-day deadline) still enforces.
      // enforcementConfigIds may be unmarshalled as a plain array depending on DynamoDB client
      // configuration; cast exercises that runtime path through toStringArray.
      queryByControlId.mockResolvedValueOnce({
        items: [
          createFindingItem({
            findingId: 'finding-1',
            enforcementConfigIds: [CONFIG_A, CONFIG_B] as unknown as Set<string>,
          }),
        ],
        lastEvaluatedKey: undefined,
      });
      findConfigById.mockImplementation(async (configId: string) =>
        configId === CONFIG_B ? createConfig({ configId: CONFIG_B, deadlineDays: 30 }) : undefined,
      );

      // ACT
      const result = await buildService().processTask(
        createTask({ taskType: 'disable', oldConfig: createConfig({ configId: CONFIG_A }) }),
      );

      // ASSERT — re-stamped with the remaining config's deadline only.
      expect(result.itemsProcessed).toBe(1);
      expect(forceStampRemediationDueBy).toHaveBeenCalledTimes(1);
      expect(forceStampRemediationDueBy).toHaveBeenCalledWith('finding-1', CONTROL_ID, GRACE_FLOOR_DUE_BY, [CONFIG_B]);
      expect(clearRemediationDueBy).not.toHaveBeenCalled();
    });

    it('clears remediationDueBy when every remaining contributing config no longer enforces', async () => {
      // ARRANGE — CONFIG_A disabled; the only remaining contributor CONFIG_B is itself disabled.
      queryByControlId.mockResolvedValueOnce({
        items: [createFindingItem({ findingId: 'finding-1', enforcementConfigIds: new Set([CONFIG_A, CONFIG_B]) })],
        lastEvaluatedKey: undefined,
      });
      findConfigById.mockImplementation(async (configId: string) =>
        configId === CONFIG_B ? createConfig({ configId: CONFIG_B, enabled: false }) : undefined,
      );

      // ACT
      await buildService().processTask(
        createTask({ taskType: 'disable', oldConfig: createConfig({ configId: CONFIG_A }) }),
      );

      // ASSERT
      expect(clearRemediationDueBy).toHaveBeenCalledWith('finding-1', CONTROL_ID);
      expect(forceStampRemediationDueBy).not.toHaveBeenCalled();
    });

    it('does nothing when the disable task carries no snapshot', async () => {
      // ARRANGE / ACT
      const result = await buildService().processTask(createTask({ taskType: 'disable' }));

      // ASSERT
      expect(result).toEqual({ isComplete: true, itemsProcessed: 0 });
      expect(queryByControlId).not.toHaveBeenCalled();
    });
  });

  describe('Property 11: deadline change', () => {
    it('force-stamps every contributing finding with the recomputed deadline', async () => {
      // ARRANGE — the live config now has a 5-day deadline. Two findings reference it; the live config
      // should be read only once thanks to per-invocation memoization.
      findConfigById.mockResolvedValue(createConfig({ configId: CONFIG_A, deadlineDays: 5 }));
      queryByControlId.mockResolvedValueOnce({
        items: [
          createFindingItem({ findingId: 'finding-1', enforcementConfigIds: new Set([CONFIG_A]) }),
          createFindingItem({ findingId: 'finding-2', enforcementConfigIds: new Set([CONFIG_A]) }),
        ],
        lastEvaluatedKey: undefined,
      });

      // ACT
      const result = await buildService().processTask(
        createTask({ taskType: 'deadlineChange', newConfig: createConfig({ configId: CONFIG_A, deadlineDays: 5 }) }),
      );

      // ASSERT
      expect(result.itemsProcessed).toBe(2);
      expect(forceStampRemediationDueBy).toHaveBeenCalledTimes(2);
      expect(forceStampRemediationDueBy).toHaveBeenNthCalledWith(1, 'finding-1', CONTROL_ID, GRACE_FLOOR_DUE_BY, [
        CONFIG_A,
      ]);
      expect(forceStampRemediationDueBy).toHaveBeenNthCalledWith(2, 'finding-2', CONTROL_ID, GRACE_FLOOR_DUE_BY, [
        CONFIG_A,
      ]);
      expect(findConfigById).toHaveBeenCalledTimes(1);
      expect(stampRemediationDueBy).not.toHaveBeenCalled();
    });

    it('skips findings that do not reference the changed config', async () => {
      // ARRANGE
      findConfigById.mockResolvedValue(createConfig({ configId: CONFIG_A, deadlineDays: 5 }));
      queryByControlId.mockResolvedValueOnce({
        items: [createFindingItem({ findingId: 'finding-1', enforcementConfigIds: new Set([CONFIG_B]) })],
        lastEvaluatedKey: undefined,
      });

      // ACT
      const result = await buildService().processTask(
        createTask({ taskType: 'deadlineChange', newConfig: createConfig({ configId: CONFIG_A, deadlineDays: 5 }) }),
      );

      // ASSERT
      expect(result.itemsProcessed).toBe(1);
      expect(forceStampRemediationDueBy).not.toHaveBeenCalled();
    });

    it('does nothing when the deadlineChange task carries no configuration snapshot', async () => {
      // ARRANGE — neither newConfig nor oldConfig is present, so no config ID can be resolved.

      // ACT
      const result = await buildService().processTask(createTask({ taskType: 'deadlineChange' }));

      // ASSERT
      expect(result).toEqual({ isComplete: true, itemsProcessed: 0 });
      expect(findConfigById).not.toHaveBeenCalled();
      expect(queryByControlId).not.toHaveBeenCalled();
      expect(forceStampRemediationDueBy).not.toHaveBeenCalled();
    });

    it('floors the recompute to the recompute time (clock.now) plus 24h for a backlog finding but not a recent one', async () => {
      // ARRANGE — a live 10-day config and two contributing findings: one created recently (its
      // creation-time deadline is beyond the grace floor) and one backlog finding (its deadline is
      // already in the past). The recompute clock is FIXED_NOW, so the floor is FIXED_NOW + 24h.
      findConfigById.mockResolvedValue(createConfig({ configId: CONFIG_A, deadlineDays: 10 }));
      queryByControlId.mockResolvedValueOnce({
        items: [
          createFindingItem({
            findingId: 'recent',
            creationTime: '2025-06-01T00:00:00.000Z',
            enforcementConfigIds: new Set([CONFIG_A]),
          }),
          createFindingItem({
            findingId: 'backlog',
            creationTime: CREATION_TIME,
            enforcementConfigIds: new Set([CONFIG_A]),
          }),
        ],
        lastEvaluatedKey: undefined,
      });

      // ACT
      const result = await buildService().processTask(
        createTask({ taskType: 'deadlineChange', newConfig: createConfig({ configId: CONFIG_A, deadlineDays: 10 }) }),
      );

      // ASSERT — the recent finding keeps its creation + 10 days deadline; the backlog finding is
      // clamped to the recompute time + 24h rather than recomputing to an already-past value.
      expect(result.itemsProcessed).toBe(2);
      expect(forceStampRemediationDueBy).toHaveBeenNthCalledWith(1, 'recent', CONTROL_ID, '2025-06-11T00:00:00.000Z', [
        CONFIG_A,
      ]);
      expect(forceStampRemediationDueBy).toHaveBeenNthCalledWith(2, 'backlog', CONTROL_ID, GRACE_FLOOR_DUE_BY, [
        CONFIG_A,
      ]);
    });
  });

  describe('filterChange', () => {
    it('removes the config from findings under controls dropped from the config', async () => {
      // ARRANGE — CONTROL_ID dropped, resource filters unchanged so no unchanged-control re-evaluation.
      const oldConfig = createConfig({ configId: CONFIG_A, controlIds: [CONFIG_CONTROL_ID, 'S3.2'] });
      const newConfig = createConfig({ configId: CONFIG_A, controlIds: ['S3.2'] });
      findConfigById.mockResolvedValue(newConfig);
      queryByControlId.mockResolvedValueOnce({
        items: [createFindingItem({ findingId: 'removed-finding', enforcementConfigIds: new Set([CONFIG_A]) })],
        lastEvaluatedKey: undefined,
      });

      // ACT
      const result = await buildService().processTask(createTask({ taskType: 'filterChange', oldConfig, newConfig }));

      // ASSERT — only the dropped control is queried, and its finding is cleared.
      expect(result.itemsProcessed).toBe(1);
      expect(queryByControlId).toHaveBeenCalledTimes(1);
      expect(queryByControlId).toHaveBeenCalledWith(CONTROL_ID, {
        exclusiveStartKey: undefined,
        limit: DEFAULT_RECONCILIATION_FINDING_LIMIT,
      });
      expect(clearRemediationDueBy).toHaveBeenCalledWith('removed-finding', CONTROL_ID);
      expect(stampRemediationDueBy).not.toHaveBeenCalled();
    });

    it('stamps matching NOT_STARTED findings under controls newly added to the config', async () => {
      // ARRANGE — S3.3 added, resource filters unchanged.
      const addedConfigControlId = 'S3.3';
      const addedControlId = 'security-control/S3.3';
      const oldConfig = createConfig({ configId: CONFIG_A, controlIds: [CONFIG_CONTROL_ID] });
      const newConfig = createConfig({
        configId: CONFIG_A,
        controlIds: [CONFIG_CONTROL_ID, addedConfigControlId],
        deadlineDays: 10,
      });
      findConfigById.mockResolvedValue(newConfig);
      queryByControlId.mockResolvedValueOnce({
        items: [createFindingItem({ findingType: addedControlId, findingId: 'added-finding' })],
        lastEvaluatedKey: undefined,
      });

      // ACT
      const result = await buildService().processTask(createTask({ taskType: 'filterChange', oldConfig, newConfig }));

      // ASSERT
      expect(result.itemsProcessed).toBe(1);
      expect(queryByControlId).toHaveBeenCalledWith(addedControlId, {
        exclusiveStartKey: undefined,
        limit: DEFAULT_RECONCILIATION_FINDING_LIMIT,
        remediationStatusEquals: 'NOT_STARTED',
      });
      expect(stampRemediationDueBy).toHaveBeenCalledWith('added-finding', addedControlId, GRACE_FLOOR_DUE_BY, [
        CONFIG_A,
      ]);
    });

    it('re-evaluates unchanged controls when resource filters change, stamping new matches and clearing stale ones', async () => {
      // ARRANGE — same control, different (and differently sized) resource filter set. One finding now
      // matches for the first time; another that previously matched no longer does.
      const oldConfig = createConfig({
        configId: CONFIG_A,
        controlIds: [CONFIG_CONTROL_ID],
        resourceFilterIds: ['f-old'],
      });
      const newConfig = createConfig({
        configId: CONFIG_A,
        controlIds: [CONFIG_CONTROL_ID],
        resourceFilterIds: ['f-new', 'f-extra'],
        deadlineDays: 10,
      });
      findConfigById.mockResolvedValue(newConfig);
      queryByControlId.mockResolvedValueOnce({
        items: [
          createFindingItem({ findingId: 'newly-matching' }),
          createFindingItem({ findingId: 'no-longer-matching', enforcementConfigIds: new Set([CONFIG_A]) }),
        ],
        lastEvaluatedKey: undefined,
      });
      evaluateFilters.mockResolvedValueOnce({ passed: true }).mockResolvedValueOnce({ passed: false });

      // ACT
      const result = await buildService().processTask(createTask({ taskType: 'filterChange', oldConfig, newConfig }));

      // ASSERT
      expect(result.itemsProcessed).toBe(2);
      expect(stampRemediationDueBy).toHaveBeenCalledTimes(1);
      expect(stampRemediationDueBy).toHaveBeenCalledWith('newly-matching', CONTROL_ID, GRACE_FLOOR_DUE_BY, [CONFIG_A]);
      expect(clearRemediationDueBy).toHaveBeenCalledTimes(1);
      expect(clearRemediationDueBy).toHaveBeenCalledWith('no-longer-matching', CONTROL_ID);
    });

    it('re-evaluates retained controls when the snapshots are identical (an applied filter definition changed)', async () => {
      // ARRANGE — FiltersService enqueues a filterChange with the unchanged live config as both
      // snapshots when an applied resource filter's definition changes. controlIds and
      // resourceFilterIds are identical, so the engine must still re-evaluate every retained control.
      const config = createConfig({ configId: CONFIG_A, controlIds: [CONFIG_CONTROL_ID], resourceFilterIds: ['f-1'] });
      findConfigById.mockResolvedValue(config);
      queryByControlId.mockResolvedValueOnce({
        items: [
          createFindingItem({ findingId: 'newly-matching' }),
          createFindingItem({ findingId: 'no-longer-matching', enforcementConfigIds: new Set([CONFIG_A]) }),
        ],
        lastEvaluatedKey: undefined,
      });
      evaluateFilters.mockResolvedValueOnce({ passed: true }).mockResolvedValueOnce({ passed: false });

      // ACT
      const result = await buildService().processTask(
        createTask({ taskType: 'filterChange', oldConfig: config, newConfig: config }),
      );

      // ASSERT — the retained control is re-evaluated even with no structural diff.
      expect(result.itemsProcessed).toBe(2);
      expect(stampRemediationDueBy).toHaveBeenCalledTimes(1);
      expect(stampRemediationDueBy).toHaveBeenCalledWith('newly-matching', CONTROL_ID, GRACE_FLOOR_DUE_BY, [CONFIG_A]);
      expect(clearRemediationDueBy).toHaveBeenCalledTimes(1);
      expect(clearRemediationDueBy).toHaveBeenCalledWith('no-longer-matching', CONTROL_ID);
    });

    it('leaves an already-stamped finding unchanged when it still matches the new filters', async () => {
      // ARRANGE — finding already references the config and still matches; no write needed.
      const oldConfig = createConfig({
        configId: CONFIG_A,
        controlIds: [CONFIG_CONTROL_ID],
        resourceFilterIds: ['f-old'],
      });
      const newConfig = createConfig({
        configId: CONFIG_A,
        controlIds: [CONFIG_CONTROL_ID],
        resourceFilterIds: ['f-new'],
      });
      findConfigById.mockResolvedValue(newConfig);
      queryByControlId.mockResolvedValueOnce({
        items: [createFindingItem({ findingId: 'still-matching', enforcementConfigIds: new Set([CONFIG_A]) })],
        lastEvaluatedKey: undefined,
      });
      evaluateFilters.mockResolvedValue({ passed: true });

      // ACT
      await buildService().processTask(createTask({ taskType: 'filterChange', oldConfig, newConfig }));

      // ASSERT
      expect(stampRemediationDueBy).not.toHaveBeenCalled();
      expect(clearRemediationDueBy).not.toHaveBeenCalled();
      expect(forceStampRemediationDueBy).not.toHaveBeenCalled();
    });

    it('reconciles only removed controls when the config is no longer enforcement-enabled', async () => {
      // ARRANGE — config deleted (no live config). Added controls must NOT be stamped, but removed
      // controls must still be cleaned up.
      const oldConfig = createConfig({ configId: CONFIG_A, controlIds: [CONFIG_CONTROL_ID, 'S3.2'] });
      const newConfig = createConfig({ configId: CONFIG_A, controlIds: ['S3.2', 'S3.3'] });
      findConfigById.mockResolvedValue(undefined);
      queryByControlId.mockResolvedValueOnce({
        items: [createFindingItem({ findingId: 'removed-finding', enforcementConfigIds: new Set([CONFIG_A]) })],
        lastEvaluatedKey: undefined,
      });

      // ACT
      const result = await buildService().processTask(createTask({ taskType: 'filterChange', oldConfig, newConfig }));

      // ASSERT — only the removed control was queried; nothing was stamped.
      expect(result.itemsProcessed).toBe(1);
      expect(queryByControlId).toHaveBeenCalledTimes(1);
      expect(queryByControlId).toHaveBeenCalledWith(CONTROL_ID, expect.any(Object));
      expect(clearRemediationDueBy).toHaveBeenCalledWith('removed-finding', CONTROL_ID);
      expect(stampRemediationDueBy).not.toHaveBeenCalled();
    });

    it('does nothing when a filterChange task is missing either snapshot', async () => {
      // ARRANGE / ACT
      const result = await buildService().processTask(
        createTask({ taskType: 'filterChange', oldConfig: createConfig() }),
      );

      // ASSERT
      expect(result).toEqual({ isComplete: true, itemsProcessed: 0 });
      expect(queryByControlId).not.toHaveBeenCalled();
    });
  });

  describe('pagination', () => {
    it('saves a controlId + exclusiveStartKey bookmark and reports incomplete when the per-invocation limit is reached', async () => {
      // ARRANGE — limit of 2; the single page returns two findings and signals more remain.
      queryByControlId.mockResolvedValueOnce({
        items: [
          createFindingItem({ findingId: 'finding-1', enforcementConfigIds: new Set([CONFIG_A]) }),
          createFindingItem({ findingId: 'finding-2', enforcementConfigIds: new Set([CONFIG_A]) }),
        ],
        lastEvaluatedKey: { findingId: 'finding-2' },
      });

      // ACT
      const result = await buildService(2).processTask(
        createTask({ taskType: 'disable', oldConfig: createConfig({ configId: CONFIG_A }) }),
      );

      // ASSERT
      expect(result).toEqual({
        isComplete: false,
        itemsProcessed: 2,
        lastProcessedKey: { controlId: CONTROL_ID, exclusiveStartKey: { findingId: 'finding-2' } },
      });
      expect(queryByControlId).toHaveBeenCalledTimes(1);
      expect(queryByControlId).toHaveBeenCalledWith(CONTROL_ID, { exclusiveStartKey: undefined, limit: 2 });
    });

    it('bounds the per-invocation budget by items scanned, not just those matched', async () => {
      // ARRANGE — limit of 2. The page returns a single matching finding but reports that DynamoDB
      // scanned 2 items (a NOT_STARTED FilterExpression skipped one), and signals more remain. If the
      // budget counted only matches it would keep paging and could walk the whole partition at once.
      queryByControlId.mockResolvedValueOnce({
        items: [createFindingItem({ findingId: 'finding-1', enforcementConfigIds: new Set([CONFIG_A]) })],
        scannedCount: 2,
        lastEvaluatedKey: { findingId: 'finding-2' },
      });

      // ACT
      const result = await buildService(2).processTask(
        createTask({ taskType: 'disable', oldConfig: createConfig({ configId: CONFIG_A }) }),
      );

      // ASSERT — the two scanned items exhaust the budget, so the task stops and bookmarks after a
      // single query rather than continuing to scan.
      expect(result).toEqual({
        isComplete: false,
        itemsProcessed: 2,
        lastProcessedKey: { controlId: CONTROL_ID, exclusiveStartKey: { findingId: 'finding-2' } },
      });
      expect(queryByControlId).toHaveBeenCalledTimes(1);
      expect(clearRemediationDueBy).toHaveBeenCalledWith('finding-1', CONTROL_ID);
    });

    it('resumes a bookmarked task from the saved control and exclusiveStartKey', async () => {
      // ARRANGE — resume token points into CONTROL_ID; the remaining page completes the work.
      queryByControlId.mockResolvedValueOnce({
        items: [createFindingItem({ findingId: 'finding-3', enforcementConfigIds: new Set([CONFIG_A]) })],
        lastEvaluatedKey: undefined,
      });

      // ACT
      const result = await buildService(2).processTask(
        createTask({
          taskType: 'disable',
          oldConfig: createConfig({ configId: CONFIG_A }),
          lastProcessedKey: { controlId: CONTROL_ID, exclusiveStartKey: { findingId: 'finding-2' } },
        }),
      );

      // ASSERT
      expect(result).toEqual({ isComplete: true, itemsProcessed: 1 });
      expect(queryByControlId).toHaveBeenCalledWith(CONTROL_ID, {
        exclusiveStartKey: { findingId: 'finding-2' },
        limit: 2,
      });
      expect(clearRemediationDueBy).toHaveBeenCalledWith('finding-3', CONTROL_ID);
    });

    it('restarts cleanly when the bookmarked control is no longer part of the work', async () => {
      // ARRANGE — bookmark references a control that the (current) task no longer targets.
      queryByControlId.mockResolvedValueOnce({
        items: [createFindingItem({ findingId: 'finding-1', enforcementConfigIds: new Set([CONFIG_A]) })],
        lastEvaluatedKey: undefined,
      });

      // ACT
      const result = await buildService().processTask(
        createTask({
          taskType: 'disable',
          oldConfig: createConfig({ configId: CONFIG_A }),
          lastProcessedKey: { controlId: 'security-control/Gone', exclusiveStartKey: { findingId: 'x' } },
        }),
      );

      // ASSERT — the active control is queried from the beginning (no carried-over start key).
      expect(result).toEqual({ isComplete: true, itemsProcessed: 1 });
      expect(queryByControlId).toHaveBeenCalledWith(CONTROL_ID, {
        exclusiveStartKey: undefined,
        limit: DEFAULT_RECONCILIATION_FINDING_LIMIT,
      });
    });

    it('ignores a malformed bookmark and processes from the beginning', async () => {
      // ARRANGE — lastProcessedKey lacks a string controlId, so it is treated as no bookmark.
      queryByControlId.mockResolvedValueOnce({
        items: [createFindingItem({ findingId: 'finding-1', enforcementConfigIds: new Set([CONFIG_A]) })],
        lastEvaluatedKey: undefined,
      });

      // ACT
      const result = await buildService().processTask(
        createTask({ taskType: 'disable', oldConfig: createConfig({ configId: CONFIG_A }), lastProcessedKey: {} }),
      );

      // ASSERT
      expect(result.isComplete).toBe(true);
      expect(clearRemediationDueBy).toHaveBeenCalledWith('finding-1', CONTROL_ID);
    });
  });

  describe('match-all (empty controlIds) reconciliation', () => {
    // GSI projection returned by queryAllStampedFindings: lightweight, carries enforcementConfigIds
    // and creationTime so the scan-all path never fetches the base item or decompresses findingJSON.
    const buildProjection = (
      overrides: { findingId?: string; findingType?: string; enforcementConfigIds?: Set<string> } = {},
    ) => ({
      findingType: CONTROL_ID,
      findingId: 'finding-001',
      remediationStatus: 'NOT_STARTED',
      accountId: '111111111111',
      resourceId: 'arn:aws:s3:::bucket-001',
      creationTime: CREATION_TIME,
      remediationDueBy: DUE_BY_10_DAYS,
      FINDING_CONSTANT: 'finding',
      ...overrides,
    });

    describe('Property 10: config disable', () => {
      it('removes the config from carrying findings, clearing or recalculating, and leaves others untouched', async () => {
        // ARRANGE — three stamped findings spanning different controls: one carries only the disabled
        // config (cleared), one carries it alongside a still-live config (recalculated), one does not
        // carry it at all (untouched). No per-control query can reach this set, so it is enumerated.
        queryAllStampedFindings.mockResolvedValueOnce({
          items: [
            buildProjection({
              findingId: 'only-a',
              findingType: 'security-control/S3.1',
              enforcementConfigIds: new Set([CONFIG_A]),
            }),
            buildProjection({
              findingId: 'a-and-b',
              findingType: 'security-control/EC2.1',
              enforcementConfigIds: new Set([CONFIG_A, CONFIG_B]),
            }),
            buildProjection({
              findingId: 'only-b',
              findingType: 'security-control/RDS.1',
              enforcementConfigIds: new Set([CONFIG_B]),
            }),
          ],
          lastEvaluatedKey: undefined,
        });
        findConfigById.mockImplementation(async (configId: string) =>
          configId === CONFIG_B ? createConfig({ configId: CONFIG_B, deadlineDays: 30 }) : undefined,
        );

        // ACT
        const result = await buildService().processTask(
          createTask({ taskType: 'disable', oldConfig: createConfig({ configId: CONFIG_A, controlIds: [] }) }),
        );

        // ASSERT — every stamped finding examined; only those carrying CONFIG_A are written.
        expect(result).toEqual({ isComplete: true, itemsProcessed: 3 });
        expect(queryByControlId).not.toHaveBeenCalled();
        expect(clearRemediationDueBy).toHaveBeenCalledTimes(1);
        expect(clearRemediationDueBy).toHaveBeenCalledWith('only-a', 'security-control/S3.1');
        expect(forceStampRemediationDueBy).toHaveBeenCalledTimes(1);
        expect(forceStampRemediationDueBy).toHaveBeenCalledWith(
          'a-and-b',
          'security-control/EC2.1',
          GRACE_FLOOR_DUE_BY,
          [CONFIG_B],
        );
      });
    });

    describe('Property 11: deadline change', () => {
      it('force-stamps carrying findings with the recomputed minimum across remaining contributing configs', async () => {
        // ARRANGE — match-all config CONFIG_A now has a 5-day deadline; the carrying finding also
        // contributes to CONFIG_B (10 days), so the min (5) wins and both IDs are retained.
        findConfigById.mockImplementation(async (configId: string) =>
          configId === CONFIG_A
            ? createConfig({ configId: CONFIG_A, controlIds: [], deadlineDays: 5 })
            : createConfig({ configId: CONFIG_B, deadlineDays: 10 }),
        );
        queryAllStampedFindings.mockResolvedValueOnce({
          items: [
            buildProjection({ findingId: 'carrying', enforcementConfigIds: new Set([CONFIG_A, CONFIG_B]) }),
            buildProjection({ findingId: 'unrelated', enforcementConfigIds: new Set([CONFIG_B]) }),
          ],
          lastEvaluatedKey: undefined,
        });

        // ACT
        const result = await buildService().processTask(
          createTask({
            taskType: 'deadlineChange',
            newConfig: createConfig({ configId: CONFIG_A, controlIds: [], deadlineDays: 5 }),
          }),
        );

        // ASSERT
        expect(result).toEqual({ isComplete: true, itemsProcessed: 2 });
        expect(queryByControlId).not.toHaveBeenCalled();
        expect(forceStampRemediationDueBy).toHaveBeenCalledTimes(1);
        expect(forceStampRemediationDueBy).toHaveBeenCalledWith('carrying', CONTROL_ID, GRACE_FLOOR_DUE_BY, [
          CONFIG_A,
          CONFIG_B,
        ]);
      });
    });

    it('performs the clear side only for a match-all filterChange, never stamping new matches', async () => {
      // ARRANGE — match-all config whose resource filters changed; controlIds stay empty. Carrying
      // findings are cleared/recalculated; newly-matching findings are left to write-time stamping.
      const oldConfig = createConfig({ configId: CONFIG_A, controlIds: [], resourceFilterIds: ['f-old'] });
      const newConfig = createConfig({ configId: CONFIG_A, controlIds: [], resourceFilterIds: ['f-new'] });
      findConfigById.mockResolvedValue(newConfig);
      queryAllStampedFindings.mockResolvedValueOnce({
        items: [buildProjection({ findingId: 'carrying', enforcementConfigIds: new Set([CONFIG_A]) })],
        lastEvaluatedKey: undefined,
      });

      // ACT
      const result = await buildService().processTask(createTask({ taskType: 'filterChange', oldConfig, newConfig }));

      // ASSERT
      expect(result).toEqual({ isComplete: true, itemsProcessed: 1 });
      expect(queryByControlId).not.toHaveBeenCalled();
      expect(clearRemediationDueBy).toHaveBeenCalledWith('carrying', CONTROL_ID);
      expect(stampRemediationDueBy).not.toHaveBeenCalled();
      expect(evaluateFilters).not.toHaveBeenCalled();
    });

    it('saves a scan-all bookmark and reports incomplete when the per-invocation limit is reached', async () => {
      // ARRANGE — limit of 2; the page returns two carrying findings and signals more remain.
      queryAllStampedFindings.mockResolvedValueOnce({
        items: [
          buildProjection({ findingId: 'finding-1', enforcementConfigIds: new Set([CONFIG_A]) }),
          buildProjection({ findingId: 'finding-2', enforcementConfigIds: new Set([CONFIG_A]) }),
        ],
        lastEvaluatedKey: { findingId: 'finding-2' },
      });

      // ACT
      const result = await buildService(2).processTask(
        createTask({ taskType: 'disable', oldConfig: createConfig({ configId: CONFIG_A, controlIds: [] }) }),
      );

      // ASSERT — incomplete with the reserved scan-all controlId in the bookmark.
      expect(result).toEqual({
        isComplete: false,
        itemsProcessed: 2,
        lastProcessedKey: {
          controlId: SCAN_ALL_BOOKMARK_CONTROL_ID,
          exclusiveStartKey: { findingId: 'finding-2' },
        },
      });
      expect(queryAllStampedFindings).toHaveBeenCalledTimes(1);
      expect(queryAllStampedFindings).toHaveBeenCalledWith({ exclusiveStartKey: undefined, limit: 2 });
    });

    it('resumes a scan-all task from the saved bookmark', async () => {
      // ARRANGE — resume token carries the reserved scan-all controlId and a GSI start key.
      queryAllStampedFindings.mockResolvedValueOnce({
        items: [buildProjection({ findingId: 'finding-3', enforcementConfigIds: new Set([CONFIG_A]) })],
        lastEvaluatedKey: undefined,
      });

      // ACT
      const result = await buildService(2).processTask(
        createTask({
          taskType: 'disable',
          oldConfig: createConfig({ configId: CONFIG_A, controlIds: [] }),
          lastProcessedKey: { controlId: SCAN_ALL_BOOKMARK_CONTROL_ID, exclusiveStartKey: { findingId: 'finding-2' } },
        }),
      );

      // ASSERT
      expect(result).toEqual({ isComplete: true, itemsProcessed: 1 });
      expect(queryAllStampedFindings).toHaveBeenCalledWith({
        exclusiveStartKey: { findingId: 'finding-2' },
        limit: 2,
      });
      expect(clearRemediationDueBy).toHaveBeenCalledWith('finding-3', CONTROL_ID);
    });
  });
});
