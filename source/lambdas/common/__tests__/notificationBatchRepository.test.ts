// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { DynamoDBDocumentClient, GetCommand, PutCommand } from '@aws-sdk/lib-dynamodb';
import {
  NotificationBatchItem,
  FindingId,
  NotificationConfigurationItem,
  RECONCILIATION_CONFIG_ID_PREFIX,
  RECONCILIATION_QUEUE_VALUE,
  ReconciliationTask,
} from '@asr/data-models';
import { BatchOverflowError, NotificationBatchRepository } from '../repositories/notificationBatchRepository';
import { Clock } from '../utils/clock';
import { IdGenerator } from '../utils/idGenerator';
import { calculateTtlTimestamp } from '../utils/ttlUtils';
import { DynamoDBTestSetup } from './dynamodbSetup';
import { notificationBatchesTableName } from './envSetup';
import { asConfigId } from './utils';

const createMockBatch = (overrides: Partial<NotificationBatchItem> = {}): NotificationBatchItem => ({
  configId: 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee',
  windowEnd: '2024-01-01T01:00:00.000Z',
  status: 'open',
  findingIds: [],
  remediationIds: [],
  itemCount: 0,
  expireAt: Math.floor(Date.now() / 1000) + 86400,
  createdAt: '2024-01-01T00:00:00.000Z',
  ...overrides,
});

describe('NotificationBatchRepository', () => {
  const principal = 'test-user@example.com';
  let docClient: DynamoDBDocumentClient;
  let repository: NotificationBatchRepository;

  beforeAll(async () => {
    await DynamoDBTestSetup.initialize();
    docClient = DynamoDBTestSetup.getDocClient();
    await DynamoDBTestSetup.createNotificationBatchesTable(notificationBatchesTableName);
  });

  afterAll(async () => {
    await DynamoDBTestSetup.deleteTable(notificationBatchesTableName);
  });

  beforeEach(async () => {
    await DynamoDBTestSetup.clearTable(notificationBatchesTableName, 'notificationBatches');
    repository = new NotificationBatchRepository(principal, notificationBatchesTableName, docClient);
  });

  describe('findById', () => {
    it('should return existing batch by configId and windowEnd', async () => {
      const batch = createMockBatch();
      await docClient.send(new PutCommand({ TableName: notificationBatchesTableName, Item: batch }));

      const result = await repository.findById(batch.configId, batch.windowEnd);

      expect(result).toBeDefined();
      expect(result!.configId).toBe(batch.configId);
      expect(result!.windowEnd).toBe(batch.windowEnd);
      expect(result!.status).toBe('open');
    });

    it('should return undefined for non-existent batch', async () => {
      const result = await repository.findById('non-existent', '2024-01-01T00:00:00.000Z');
      expect(result).toBeUndefined();
    });
  });

  describe('appendEventId', () => {
    it('should create a new batch item when appending to non-existent key', async () => {
      // ARRANGE
      const configId = '11111111-1111-1111-1111-111111111111';
      const windowEnd = '2024-01-01T02:00:00.000Z';
      const expireAt = Math.floor(Date.now() / 1000) + 86400;

      // ACT
      await repository.appendEventId(configId, windowEnd, 'finding-1', 'findingIds', expireAt);

      // ASSERT
      const result = await docClient.send(
        new GetCommand({ TableName: notificationBatchesTableName, Key: { configId, windowEnd } }),
      );
      expect(result.Item).toBeDefined();
      expect(result.Item!.findingIds).toHaveLength(1);
      expect(result.Item!.findingIds[0]).toBe('finding-1');
      expect(result.Item!.itemCount).toBe(1);
      expect(result.Item!.status).toBe('open');
    });

    it('should append to existing batch finding IDs list', async () => {
      // ARRANGE
      const batch = createMockBatch({ findingIds: ['existing-id' as FindingId], itemCount: 1 });
      await docClient.send(new PutCommand({ TableName: notificationBatchesTableName, Item: batch }));

      // ACT
      await repository.appendEventId(batch.configId, batch.windowEnd, 'new-id', 'findingIds', batch.expireAt);

      // ASSERT
      const result = await docClient.send(
        new GetCommand({
          TableName: notificationBatchesTableName,
          Key: { configId: batch.configId, windowEnd: batch.windowEnd },
        }),
      );
      expect(result.Item!.findingIds).toHaveLength(2);
      expect(result.Item!.itemCount).toBe(2);
    });

    it('should append remediation IDs', async () => {
      // ARRANGE
      const configId = '22222222-2222-2222-2222-222222222222';
      const windowEnd = '2024-01-01T03:00:00.000Z';
      const expireAt = Math.floor(Date.now() / 1000) + 86400;

      // ACT
      await repository.appendEventId(configId, windowEnd, 'rem-1', 'remediationIds', expireAt);

      // ASSERT
      const result = await docClient.send(
        new GetCommand({ TableName: notificationBatchesTableName, Key: { configId, windowEnd } }),
      );
      expect(result.Item!.remediationIds).toHaveLength(1);
      expect(result.Item!.remediationIds[0]).toBe('rem-1');
    });

    it('should create an overflow item when the primary batch is at MAX_ITEMS capacity', async () => {
      // ARRANGE — seed a batch that is already at the 2000-item cap
      const configId = '55555555-5555-5555-5555-555555555555';
      const windowEnd = '2024-02-01T01:00:00.000Z';
      const expireAt = Math.floor(Date.now() / 1000) + 86400;
      const fullBatch = createMockBatch({
        configId,
        windowEnd,
        itemCount: 2000,
        findingIds: Array.from({ length: 2000 }, (_, i) => `f-${i}` as FindingId),
      });
      await docClient.send(new PutCommand({ TableName: notificationBatchesTableName, Item: fullBatch }));

      // ACT
      await repository.appendEventId(configId, windowEnd, 'overflow-1', 'findingIds', expireAt);

      // ASSERT — primary batch is unchanged, overflow item exists at sequence 0001
      const primary = await docClient.send(
        new GetCommand({ TableName: notificationBatchesTableName, Key: { configId, windowEnd } }),
      );
      expect(primary.Item!.itemCount).toBe(2000);

      const overflow = await docClient.send(
        new GetCommand({
          TableName: notificationBatchesTableName,
          Key: { configId, windowEnd: `~${windowEnd}#0001` },
        }),
      );
      expect(overflow.Item).toBeDefined();
      expect(overflow.Item!.findingIds).toEqual(['overflow-1']);
      expect(overflow.Item!.itemCount).toBe(1);
    });

    it('should advance to the next overflow sequence when earlier slots are full', async () => {
      // ARRANGE — primary and first overflow slot are both full
      const configId = '66666666-6666-6666-6666-666666666666';
      const windowEnd = '2024-02-01T02:00:00.000Z';
      const expireAt = Math.floor(Date.now() / 1000) + 86400;
      const full = (overrides: Partial<NotificationBatchItem> = {}) =>
        createMockBatch({
          configId,
          windowEnd,
          itemCount: 2000,
          findingIds: Array.from({ length: 2000 }, (_, i) => `f-${i}` as FindingId),
          ...overrides,
        });
      await docClient.send(new PutCommand({ TableName: notificationBatchesTableName, Item: full() }));
      await docClient.send(
        new PutCommand({
          TableName: notificationBatchesTableName,
          Item: full({ windowEnd: `~${windowEnd}#0001` }),
        }),
      );

      // ACT
      await repository.appendEventId(configId, windowEnd, 'overflow-2', 'findingIds', expireAt);

      // ASSERT — new event lands in sequence 0002
      const result = await docClient.send(
        new GetCommand({
          TableName: notificationBatchesTableName,
          Key: { configId, windowEnd: `~${windowEnd}#0002` },
        }),
      );
      expect(result.Item).toBeDefined();
      expect(result.Item!.findingIds).toEqual(['overflow-2']);
    });

    it('should throw BatchOverflowError when the primary batch and every overflow slot are full', async () => {
      // ARRANGE — seed 1 primary + 100 overflow items, all at the itemCount cap.
      // Only itemCount needs to be at the cap to trigger the conditional check failure,
      // so we keep the findingIds list short to keep the test fast.
      const configId = '77777777-7777-7777-7777-777777777777';
      const windowEnd = '2024-02-01T03:00:00.000Z';
      const expireAt = Math.floor(Date.now() / 1000) + 86400;

      await docClient.send(
        new PutCommand({
          TableName: notificationBatchesTableName,
          Item: createMockBatch({ configId, windowEnd, itemCount: 2000 }),
        }),
      );
      for (let sequence = 1; sequence <= 100; sequence++) {
        await docClient.send(
          new PutCommand({
            TableName: notificationBatchesTableName,
            Item: createMockBatch({
              configId,
              windowEnd: `~${windowEnd}#${String(sequence).padStart(4, '0')}`,
              itemCount: 2000,
            }),
          }),
        );
      }

      // ACT / ASSERT — exhausts the primary and all overflow slots and surfaces a typed error
      await expect(
        repository.appendEventId(configId, windowEnd, 'overflow-fail', 'findingIds', expireAt),
      ).rejects.toMatchObject({
        name: 'BatchOverflowError',
        configId,
        windowEnd,
        maxSequences: 100,
      });
      await expect(
        repository.appendEventId(configId, windowEnd, 'overflow-fail', 'findingIds', expireAt),
      ).rejects.toBeInstanceOf(BatchOverflowError);
    }, 30000);
  });

  describe('updateStatus', () => {
    it('should update batch status to processing', async () => {
      const batch = createMockBatch();
      await docClient.send(new PutCommand({ TableName: notificationBatchesTableName, Item: batch }));

      await repository.updateStatus(batch.configId, batch.windowEnd, 'processing');

      const result = await docClient.send(
        new GetCommand({
          TableName: notificationBatchesTableName,
          Key: { configId: batch.configId, windowEnd: batch.windowEnd },
        }),
      );
      expect(result.Item!.status).toBe('processing');
      expect(result.Item!.lastUpdatedBy).toBe(principal);
    });

    it('should update batch status to dispatched', async () => {
      const batch = createMockBatch({ status: 'processing' });
      await docClient.send(new PutCommand({ TableName: notificationBatchesTableName, Item: batch }));

      await repository.updateStatus(batch.configId, batch.windowEnd, 'dispatched');

      const result = await docClient.send(
        new GetCommand({
          TableName: notificationBatchesTableName,
          Key: { configId: batch.configId, windowEnd: batch.windowEnd },
        }),
      );
      expect(result.Item!.status).toBe('dispatched');
    });

    it('should reject processing claim when batch is already processing within the stale threshold', async () => {
      // ARRANGE — a fresh 'processing' batch (claimed moments ago)
      const batch = createMockBatch({
        status: 'processing',
        processingStartedAt: new Date().toISOString(),
      });
      await docClient.send(new PutCommand({ TableName: notificationBatchesTableName, Item: batch }));

      await expect(repository.updateStatus(batch.configId, batch.windowEnd, 'processing')).rejects.toThrow(
        /Cannot transition batch to processing/,
      );
    });

    it('should recover a batch stuck in processing beyond the stale threshold', async () => {
      // ARRANGE — a processing batch claimed 20 minutes ago (stale threshold is 16 minutes)
      const staleAt = new Date(Date.now() - 20 * 60 * 1000).toISOString();
      const batch = createMockBatch({
        status: 'processing',
        processingStartedAt: staleAt,
      });
      await docClient.send(new PutCommand({ TableName: notificationBatchesTableName, Item: batch }));

      await repository.updateStatus(batch.configId, batch.windowEnd, 'processing');

      const result = await docClient.send(
        new GetCommand({
          TableName: notificationBatchesTableName,
          Key: { configId: batch.configId, windowEnd: batch.windowEnd },
        }),
      );
      expect(result.Item!.status).toBe('processing');
      expect(result.Item!.processingStartedAt).not.toBe(staleAt);
    });

    it('should reject dispatch from non-processing status', async () => {
      const batch = createMockBatch({ status: 'open' });
      await docClient.send(new PutCommand({ TableName: notificationBatchesTableName, Item: batch }));

      await expect(repository.updateStatus(batch.configId, batch.windowEnd, 'dispatched')).rejects.toThrow(
        /Cannot transition batch to dispatched/,
      );
    });
  });

  describe('queryOpenBatchesReady', () => {
    it('should return open batches whose window has elapsed', async () => {
      const configId = '33333333-3333-3333-3333-333333333333';
      const pastBatch = createMockBatch({ configId, windowEnd: '2024-01-01T01:00:00.000Z', status: 'open' });
      const futureBatch = createMockBatch({ configId, windowEnd: '2099-01-01T01:00:00.000Z', status: 'open' });
      const dispatchedBatch = createMockBatch({
        configId,
        windowEnd: '2024-01-01T02:00:00.000Z',
        status: 'dispatched',
      });

      await docClient.send(new PutCommand({ TableName: notificationBatchesTableName, Item: pastBatch }));
      await docClient.send(new PutCommand({ TableName: notificationBatchesTableName, Item: futureBatch }));
      await docClient.send(new PutCommand({ TableName: notificationBatchesTableName, Item: dispatchedBatch }));

      const results = await repository.queryOpenBatchesReady(configId, '2024-06-01T00:00:00.000Z');

      expect(results).toHaveLength(1);
      expect(results[0].windowEnd).toBe('2024-01-01T01:00:00.000Z');
      expect(results[0].status).toBe('open');
    });

    it('should return empty array when no open batches are ready', async () => {
      const results = await repository.queryOpenBatchesReady('non-existent', '2024-01-01T00:00:00.000Z');
      expect(results).toEqual([]);
    });

    it('should exclude overflow continuation items from the ready-batch query', async () => {
      // ARRANGE — primary batch plus an overflow item. The overflow key starts with `~`,
      // which sorts after every digit-leading ISO timestamp, so the key-range condition
      // `windowEnd <= :windowEndBefore` naturally skips it.
      const configId = '88888888-8888-8888-8888-888888888888';
      const primaryWindowEnd = '2024-01-01T01:00:00.000Z';
      const primary = createMockBatch({ configId, windowEnd: primaryWindowEnd, status: 'open' });
      const overflow = createMockBatch({ configId, windowEnd: `~${primaryWindowEnd}#0001`, status: 'open' });
      await docClient.send(new PutCommand({ TableName: notificationBatchesTableName, Item: primary }));
      await docClient.send(new PutCommand({ TableName: notificationBatchesTableName, Item: overflow }));

      const results = await repository.queryOpenBatchesReady(configId, '2024-06-01T00:00:00.000Z');

      expect(results).toHaveLength(1);
      expect(results[0].windowEnd).toBe(primaryWindowEnd);
    });
  });

  describe('queryOverflowItems', () => {
    it('should return every overflow continuation for a primary batch', async () => {
      // ARRANGE — primary with two overflow items and an unrelated primary that must
      // not be returned because it shares a configId but not the windowEnd prefix.
      const configId = '99999999-9999-9999-9999-999999999999';
      const primaryWindowEnd = '2024-03-01T01:00:00.000Z';
      const unrelatedPrimary = '2024-03-01T02:00:00.000Z';
      const items = [
        createMockBatch({ configId, windowEnd: primaryWindowEnd }),
        createMockBatch({ configId, windowEnd: `~${primaryWindowEnd}#0001` }),
        createMockBatch({ configId, windowEnd: `~${primaryWindowEnd}#0002` }),
        createMockBatch({ configId, windowEnd: unrelatedPrimary }),
        createMockBatch({ configId, windowEnd: `~${unrelatedPrimary}#0001` }),
      ];
      for (const item of items) {
        await docClient.send(new PutCommand({ TableName: notificationBatchesTableName, Item: item }));
      }

      const results = await repository.queryOverflowItems(configId, primaryWindowEnd);

      const windowEnds = results.map((r) => r.windowEnd).sort();
      expect(windowEnds).toEqual([`~${primaryWindowEnd}#0001`, `~${primaryWindowEnd}#0002`]);
    });

    it('should return empty array when no overflow items exist', async () => {
      const results = await repository.queryOverflowItems('non-existent', '2024-01-01T00:00:00.000Z');
      expect(results).toEqual([]);
    });
  });

  describe('putInBatches', () => {
    it('should write multiple batch items', async () => {
      const batch1 = createMockBatch({
        configId: '44444444-4444-4444-4444-444444444444',
        windowEnd: '2024-01-01T01:00:00.000Z',
      });
      const batch2 = createMockBatch({
        configId: '44444444-4444-4444-4444-444444444444',
        windowEnd: '2024-01-01T02:00:00.000Z',
      });

      await repository.putInBatches([batch1, batch2]);

      const r1 = await repository.findById(batch1.configId, batch1.windowEnd);
      const r2 = await repository.findById(batch2.configId, batch2.windowEnd);
      expect(r1).toBeDefined();
      expect(r2).toBeDefined();
    });
  });

  // Reconciliation tasks share the NotificationBatches table with notification batches, keyed by a
  // reserved `reconciliation#<uuid>` configId. These suites exercise the reconciliation task
  // access methods that live on this repository.
  const FIXED_TIME = '2024-06-15T12:00:00.000Z';
  const FIXED_UUID = '12345678-1234-1234-1234-123456789abc';
  const fixedClock: Clock = { now: () => new Date(FIXED_TIME) };
  const fixedIdGenerator: IdGenerator = { randomUUID: () => FIXED_UUID };

  const createMockConfig = (overrides: Partial<NotificationConfigurationItem> = {}): NotificationConfigurationItem => ({
    configId: asConfigId('aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'),
    name: 'Test Config',
    enabled: true,
    notificationType: 'finding',
    severityFilter: ['High'],
    controlIds: ['S3.1', 'IAM.1'],
    resourceFilterIds: [],
    deliveryChannels: [
      { type: 'email', enabled: true, recipients: [{ recipientType: 'custom', emailAddresses: ['test@example.com'] }] },
    ],
    batchWindow: { enabled: false },
    contentOptions: {
      includeManualRemediationLink: false,
      includeRemediationDeadline: true,
      remediationDeadlineDays: 30,
      enforceDeadline: true,
      includeIaCSnippet: false,
      includeEnableAutomationLink: false,
    },
    version: 1,
    createdAt: '2024-01-01T00:00:00.000Z',
    createdBy: 'admin@example.com',
    ...overrides,
  });

  const putTask = async (
    overrides: Partial<ReconciliationTask> & Pick<ReconciliationTask, 'configId'>,
  ): Promise<void> => {
    const task: ReconciliationTask = {
      windowEnd: FIXED_TIME,
      status: 'PENDING',
      taskType: 'enable',
      itemCount: 0,
      expireAt: calculateTtlTimestamp(FIXED_TIME, 7),
      ...overrides,
    };
    // Mirror the production invariant: outstanding tasks carry the sparse-GSI attribute so they
    // appear in OUTSTANDING_RECONCILIATION_GSI; COMPLETED tasks drop it and fall out of the index.
    if (task.status === 'COMPLETED') {
      delete task.reconciliationQueue;
    } else {
      task.reconciliationQueue = RECONCILIATION_QUEUE_VALUE;
    }
    await docClient.send(new PutCommand({ TableName: notificationBatchesTableName, Item: task }));
  };

  const fetchTask = async (configId: string, windowEnd: string): Promise<ReconciliationTask> => {
    const result = await docClient.send(
      new GetCommand({ TableName: notificationBatchesTableName, Key: { configId, windowEnd } }),
    );
    return result.Item as ReconciliationTask;
  };

  describe('createReconciliationTask', () => {
    const buildRepository = (idGenerator: IdGenerator = fixedIdGenerator): NotificationBatchRepository =>
      new NotificationBatchRepository(principal, notificationBatchesTableName, docClient, {
        clock: fixedClock,
        idGenerator,
      });

    it('initializes default fields and persists the task to the table', async () => {
      // ARRANGE
      const newConfig = createMockConfig();

      // ACT
      const task = await buildRepository().createReconciliationTask('enable', undefined, newConfig);
      const persisted = await fetchTask(task.configId, task.windowEnd);

      // ASSERT
      expect(task.configId).toBe(`${RECONCILIATION_CONFIG_ID_PREFIX}${FIXED_UUID}`);
      expect(task.windowEnd).toBe(FIXED_TIME);
      expect(task.status).toBe('PENDING');
      expect(task.taskType).toBe('enable');
      expect(task.itemCount).toBe(0);
      expect(task.expireAt).toBe(calculateTtlTimestamp(FIXED_TIME, 7));
      expect(task.reconciliationQueue).toBe(RECONCILIATION_QUEUE_VALUE);
      expect(persisted).toEqual(task);
    });

    it('stores the newConfig snapshot and omits oldConfig for an enable task', async () => {
      // ARRANGE
      const newConfig = createMockConfig();

      // ACT
      const task = await buildRepository().createReconciliationTask('enable', undefined, newConfig);
      const persisted = await fetchTask(task.configId, task.windowEnd);

      // ASSERT
      expect(persisted.newConfig).toEqual(newConfig);
      expect(persisted.oldConfig).toBeUndefined();
      expect('oldConfig' in persisted).toBe(false);
    });

    it('stores the oldConfig snapshot and omits newConfig for a disable task', async () => {
      // ARRANGE
      const oldConfig = createMockConfig();

      // ACT
      const task = await buildRepository().createReconciliationTask('disable', oldConfig, undefined);
      const persisted = await fetchTask(task.configId, task.windowEnd);

      // ASSERT
      expect(task.taskType).toBe('disable');
      expect(persisted.oldConfig).toEqual(oldConfig);
      expect(persisted.newConfig).toBeUndefined();
      expect('newConfig' in persisted).toBe(false);
    });

    it('falls back to the system clock and id generator when none are injected', async () => {
      // ARRANGE
      const before = Date.now();
      const repositoryWithDefaults = new NotificationBatchRepository(
        principal,
        notificationBatchesTableName,
        docClient,
      );

      // ACT
      const task = await repositoryWithDefaults.createReconciliationTask('enable', undefined, createMockConfig());
      const persisted = await fetchTask(task.configId, task.windowEnd);

      // ASSERT
      expect(task.configId).toMatch(
        new RegExp(`^${RECONCILIATION_CONFIG_ID_PREFIX}[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`),
      );
      expect(new Date(task.windowEnd).getTime()).toBeGreaterThanOrEqual(before);
      expect(persisted.configId).toBe(task.configId);
    });

    it('retains both snapshots for a change task and generates a unique configId per call', async () => {
      // ARRANGE
      const oldConfig = createMockConfig();
      const newConfig = createMockConfig({
        contentOptions: { ...oldConfig.contentOptions, remediationDeadlineDays: 60 },
      });
      let counter = 0;
      const incrementingIdGenerator: IdGenerator = {
        randomUUID: () => `00000000-0000-0000-0000-00000000000${counter++}`,
      };
      const repository = buildRepository(incrementingIdGenerator);

      // ACT
      const firstTask = await repository.createReconciliationTask('deadlineChange', oldConfig, newConfig);
      const secondTask = await repository.createReconciliationTask('filterChange', oldConfig, newConfig);
      const persistedFirst = await fetchTask(firstTask.configId, firstTask.windowEnd);

      // ASSERT
      expect(persistedFirst.oldConfig).toEqual(oldConfig);
      expect(persistedFirst.newConfig).toEqual(newConfig);
      expect(firstTask.taskType).toBe('deadlineChange');
      expect(secondTask.taskType).toBe('filterChange');
      expect(firstTask.configId).not.toBe(secondTask.configId);
    });
  });

  describe('queryOutstandingReconciliationTasks', () => {
    it('returns only reconciliation-prefixed PENDING and IN_PROGRESS tasks, excluding COMPLETED and non-reconciliation items', async () => {
      // ARRANGE — a mix of reconciliation tasks in every status plus a plain notification batch item
      // sharing the same table.
      await putTask({ configId: `${RECONCILIATION_CONFIG_ID_PREFIX}pending`, status: 'PENDING' });
      await putTask({ configId: `${RECONCILIATION_CONFIG_ID_PREFIX}in-progress`, status: 'IN_PROGRESS' });
      await putTask({ configId: `${RECONCILIATION_CONFIG_ID_PREFIX}completed`, status: 'COMPLETED' });
      await docClient.send(
        new PutCommand({
          TableName: notificationBatchesTableName,
          Item: { configId: 'plain-config-id', windowEnd: FIXED_TIME, status: 'open', itemCount: 1 },
        }),
      );

      // ACT
      const tasks = await repository.queryOutstandingReconciliationTasks();

      // ASSERT — only the two outstanding reconciliation tasks are returned, in either order.
      const configIds = tasks.map((task) => task.configId).sort();
      expect(configIds).toEqual([
        `${RECONCILIATION_CONFIG_ID_PREFIX}in-progress`,
        `${RECONCILIATION_CONFIG_ID_PREFIX}pending`,
      ]);
    });

    it('returns an empty array when no outstanding reconciliation tasks exist', async () => {
      // ARRANGE — only a COMPLETED reconciliation task is present.
      await putTask({ configId: `${RECONCILIATION_CONFIG_ID_PREFIX}done`, status: 'COMPLETED' });

      // ACT
      const tasks = await repository.queryOutstandingReconciliationTasks();

      // ASSERT
      expect(tasks).toEqual([]);
    });
  });

  describe('recordReconciliationTaskResult', () => {
    it('marks the task COMPLETED, advances itemCount, and removes the resume bookmark when complete', async () => {
      // ARRANGE — an in-progress task that already processed 10 findings and carries a bookmark.
      const configId = `${RECONCILIATION_CONFIG_ID_PREFIX}complete-me`;
      await putTask({
        configId,
        status: 'IN_PROGRESS',
        itemCount: 10,
        lastProcessedKey: { controlId: 'S3.1', exclusiveStartKey: { findingId: 'f-1' } },
      });

      // ACT — final invocation processed 5 more findings and finished.
      await repository.recordReconciliationTaskResult(await fetchTask(configId, FIXED_TIME), {
        isComplete: true,
        itemsProcessed: 5,
      });
      const persisted = await fetchTask(configId, FIXED_TIME);

      // ASSERT
      expect(persisted.status).toBe('COMPLETED');
      expect(persisted.itemCount).toBe(15);
      expect(persisted.lastProcessedKey).toBeUndefined();
      expect(persisted.reconciliationQueue).toBeUndefined();
    });

    it('keeps the task IN_PROGRESS, advances itemCount, and saves the bookmark when incomplete', async () => {
      // ARRANGE — a fresh PENDING task being picked up for the first time.
      const configId = `${RECONCILIATION_CONFIG_ID_PREFIX}resume-me`;
      await putTask({ configId, status: 'PENDING', itemCount: 0 });
      const bookmark = { controlId: 'S3.2', exclusiveStartKey: { findingId: 'f-99' } };

      // ACT — processed 500 findings but more remain.
      await repository.recordReconciliationTaskResult(await fetchTask(configId, FIXED_TIME), {
        isComplete: false,
        itemsProcessed: 500,
        lastProcessedKey: bookmark,
      });
      const persisted = await fetchTask(configId, FIXED_TIME);

      // ASSERT
      expect(persisted.status).toBe('IN_PROGRESS');
      expect(persisted.itemCount).toBe(500);
      expect(persisted.lastProcessedKey).toEqual(bookmark);
      expect(persisted.reconciliationQueue).toBe(RECONCILIATION_QUEUE_VALUE);
    });

    it('saves an empty bookmark when an incomplete result carries no lastProcessedKey', async () => {
      // ARRANGE — defensive path: incomplete result without a resume bookmark.
      const configId = `${RECONCILIATION_CONFIG_ID_PREFIX}no-bookmark`;
      await putTask({ configId, status: 'PENDING', itemCount: 2 });

      // ACT
      await repository.recordReconciliationTaskResult(await fetchTask(configId, FIXED_TIME), {
        isComplete: false,
        itemsProcessed: 3,
      });
      const persisted = await fetchTask(configId, FIXED_TIME);

      // ASSERT
      expect(persisted.status).toBe('IN_PROGRESS');
      expect(persisted.itemCount).toBe(5);
      expect(persisted.lastProcessedKey).toEqual({});
    });
  });
});
