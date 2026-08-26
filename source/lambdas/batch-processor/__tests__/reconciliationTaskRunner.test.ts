// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { Logger } from '@aws-lambda-powertools/logger';
import { RECONCILIATION_CONFIG_ID_PREFIX, ReconciliationTask } from '@asr/data-models';
import { ReconciliationTaskRunner } from '../reconciliationTaskRunner';
import { ReconciliationService, ReconciliationResult } from '../reconciliationService';
import { NotificationBatchRepository } from '../../common/repositories/notificationBatchRepository';

const createTask = (
  overrides: Partial<ReconciliationTask> & Pick<ReconciliationTask, 'configId'>,
): ReconciliationTask => ({
  windowEnd: '2024-06-15T12:00:00.000Z',
  status: 'PENDING',
  taskType: 'enable',
  itemCount: 0,
  expireAt: 0,
  ...overrides,
});

const COMPLETE_RESULT: ReconciliationResult = { isComplete: true, itemsProcessed: 3 };

describe('ReconciliationTaskRunner', () => {
  const logger = new Logger({ logLevel: 'SILENT' });

  let processTask: jest.Mock;
  let queryOutstandingReconciliationTasks: jest.Mock;
  let recordReconciliationTaskResult: jest.Mock;
  let reconciliationService: ReconciliationService;
  let notificationBatchRepository: NotificationBatchRepository;

  const buildRunner = (): ReconciliationTaskRunner =>
    new ReconciliationTaskRunner(reconciliationService, notificationBatchRepository, logger);

  beforeEach(() => {
    jest.clearAllMocks();
    processTask = jest.fn().mockResolvedValue(COMPLETE_RESULT);
    reconciliationService = { processTask } as unknown as ReconciliationService;
    queryOutstandingReconciliationTasks = jest.fn();
    recordReconciliationTaskResult = jest.fn().mockResolvedValue(undefined);
    notificationBatchRepository = {
      queryOutstandingReconciliationTasks,
      recordReconciliationTaskResult,
    } as unknown as NotificationBatchRepository;
  });

  it('processes every outstanding task and persists each result', async () => {
    // ARRANGE — two outstanding tasks; each returns a distinct processing result.
    const pendingTask = createTask({ configId: `${RECONCILIATION_CONFIG_ID_PREFIX}a`, status: 'PENDING' });
    const incompleteResult: ReconciliationResult = {
      isComplete: false,
      itemsProcessed: 500,
      lastProcessedKey: { controlId: 'S3.1' },
    };
    queryOutstandingReconciliationTasks.mockResolvedValue([pendingTask]);
    processTask.mockResolvedValueOnce(incompleteResult);

    // ACT
    await buildRunner().runOutstandingReconciliationTasks();

    // ASSERT — the task is processed and its result is persisted via the repository.
    expect(processTask).toHaveBeenCalledTimes(1);
    expect(processTask).toHaveBeenCalledWith(pendingTask);
    expect(recordReconciliationTaskResult).toHaveBeenCalledWith(pendingTask, incompleteResult);
  });

  it('processes IN_PROGRESS tasks before PENDING tasks so started work is finished first', async () => {
    // ARRANGE — the query returns a PENDING task ahead of an IN_PROGRESS task; the runner must reorder.
    const pendingTask = createTask({ configId: `${RECONCILIATION_CONFIG_ID_PREFIX}pending`, status: 'PENDING' });
    const inProgressTask = createTask({
      configId: `${RECONCILIATION_CONFIG_ID_PREFIX}in-progress`,
      status: 'IN_PROGRESS',
    });
    queryOutstandingReconciliationTasks.mockResolvedValue([pendingTask, inProgressTask]);

    // ACT
    await buildRunner().runOutstandingReconciliationTasks();

    // ASSERT — IN_PROGRESS is handed to processTask first, PENDING second.
    expect(processTask.mock.calls.map((call) => call[0])).toEqual([inProgressTask, pendingTask]);
  });

  it('does nothing beyond the query when there are no outstanding tasks', async () => {
    // ARRANGE
    queryOutstandingReconciliationTasks.mockResolvedValue([]);

    // ACT
    await buildRunner().runOutstandingReconciliationTasks();

    // ASSERT
    expect(processTask).not.toHaveBeenCalled();
    expect(recordReconciliationTaskResult).not.toHaveBeenCalled();
  });

  it('swallows a failing task and continues processing the remaining tasks', async () => {
    // ARRANGE — the first task throws; the second must still be processed and persisted.
    const failingTask = createTask({ configId: `${RECONCILIATION_CONFIG_ID_PREFIX}boom`, status: 'IN_PROGRESS' });
    const healthyTask = createTask({ configId: `${RECONCILIATION_CONFIG_ID_PREFIX}ok`, status: 'PENDING' });
    queryOutstandingReconciliationTasks.mockResolvedValue([failingTask, healthyTask]);
    processTask.mockRejectedValueOnce(new Error('processing boom')).mockResolvedValueOnce(COMPLETE_RESULT);

    // ACT / ASSERT — the runner resolves despite the failure.
    await expect(buildRunner().runOutstandingReconciliationTasks()).resolves.toBeUndefined();
    expect(processTask).toHaveBeenCalledTimes(2);
    // Only the healthy task's result is persisted; the failed task is not.
    expect(recordReconciliationTaskResult).toHaveBeenCalledTimes(1);
    expect(recordReconciliationTaskResult).toHaveBeenCalledWith(healthyTask, COMPLETE_RESULT);
  });
});
