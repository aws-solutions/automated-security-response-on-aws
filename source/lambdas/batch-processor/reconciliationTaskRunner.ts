// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import type { Logger } from '@aws-lambda-powertools/logger';
import { ReconciliationTask } from '@asr/data-models';
import { ReconciliationService } from './reconciliationService';
import { ErrorUtils } from '../common/utils/errorUtils';
import { NotificationBatchRepository } from '../common/repositories/notificationBatchRepository';

/**
 * Picks up outstanding {@link ReconciliationTask}s from the NotificationBatches table and drives
 * each one through {@link ReconciliationService.processTask}, persisting the resulting progress
 * (COMPLETED, or IN_PROGRESS with a resume bookmark) back to the task.
 *
 * Tasks already `IN_PROGRESS` are processed before `PENDING` ones so partially completed work is
 * finished before new work is started and never starved. Each task is processed independently:
 * a failure on one task is logged and the runner moves on, so a single poison task cannot block the
 * rest of reconciliation — consistent with how the handler treats reconciliation and overdue
 * remediation as best-effort relative to notification batch processing.
 */
export class ReconciliationTaskRunner {
  constructor(
    private readonly reconciliationService: ReconciliationService,
    private readonly notificationBatchRepository: NotificationBatchRepository,
    private readonly logger: Logger,
  ) {}

  /** Processes all outstanding reconciliation tasks, IN_PROGRESS first then PENDING. */
  async runOutstandingReconciliationTasks(): Promise<void> {
    const tasks = await this.notificationBatchRepository.queryOutstandingReconciliationTasks();
    const orderedTasks = orderInProgressBeforePending(tasks);

    if (orderedTasks.length === 0) {
      this.logger.info('No outstanding reconciliation tasks to process');
      return;
    }

    this.logger.info('Processing outstanding reconciliation tasks', { taskCount: orderedTasks.length });

    for (const task of orderedTasks) {
      await this.processSingleTask(task);
    }
  }

  /** Processes one task and persists its progress; swallows and logs any failure so others proceed. */
  private async processSingleTask(task: ReconciliationTask): Promise<void> {
    try {
      const result = await this.reconciliationService.processTask(task);
      await this.notificationBatchRepository.recordReconciliationTaskResult(task, result);
      this.logger.info('Reconciliation task processed', {
        configId: task.configId,
        taskType: task.taskType,
        isComplete: result.isComplete,
        itemsProcessed: result.itemsProcessed,
      });
    } catch (error) {
      this.logger.error('Reconciliation task failed; continuing with remaining tasks', {
        configId: task.configId,
        taskType: task.taskType,
        error: ErrorUtils.formatErrorMessage(error),
      });
    }
  }
}

/**
 * Orders tasks so every `IN_PROGRESS` task precedes every `PENDING` task, preserving the original
 * relative order within each group. This finishes already-started work before picking up new work.
 */
function orderInProgressBeforePending(tasks: ReconciliationTask[]): ReconciliationTask[] {
  const inProgress = tasks.filter((task) => task.status === 'IN_PROGRESS');
  const pending = tasks.filter((task) => task.status === 'PENDING');
  return [...inProgress, ...pending];
}
