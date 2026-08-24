// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { DynamoDBDocumentClient, DeleteCommand, PutCommand, QueryCommand, UpdateCommand } from '@aws-sdk/lib-dynamodb';
import { ConditionalCheckFailedException } from '@aws-sdk/client-dynamodb';
import {
  NotificationBatchItem,
  NotificationConfigurationItem,
  OUTSTANDING_RECONCILIATION_GSI,
  RECONCILIATION_CONFIG_ID_PREFIX,
  RECONCILIATION_QUEUE_ATTRIBUTE,
  RECONCILIATION_QUEUE_VALUE,
  ReconciliationTask,
  ReconciliationTaskProgress,
  ReconciliationTaskType,
} from '@asr/data-models';
import { AbstractRepository } from './abstractRepository';
import { Clock, getClock } from '../utils/clock';
import { IdGenerator, getIdGenerator } from '../utils/idGenerator';
import { calculateTtlTimestamp } from '../utils/ttlUtils';

const DEDUP_KEY_PREFIX = 'DEDUP#';

/**
 * Number of days a reconciliation task survives before DynamoDB TTL removes it. Acts as a
 * safety net: tasks are normally processed and marked COMPLETED within minutes, but an
 * orphaned task should not linger indefinitely.
 */
const RECONCILIATION_TASK_TTL_DAYS = 7;

// Conservative limit to stay well under DynamoDB's 400KB item size.
// A typical finding ARN is ~150 bytes; 2000 * 150 = ~300KB with overhead headroom.
const MAX_ITEMS_PER_BATCH = 2000;

// Upper bound on the number of overflow slots probed when the primary batch is full.
// Supports up to MAX_OVERFLOW_SEQUENCES * MAX_ITEMS_PER_BATCH events per window
// (100 * 2000 = 200,000). Reached only in extreme fan-in scenarios; worst-case probing
// is O(MAX_OVERFLOW_SEQUENCES) sequential DynamoDB writes within a single invocation.
const MAX_OVERFLOW_SEQUENCES = 100;

// Overflow slot index at which we start emitting a warning, signalling the window is
// approaching saturation so operators can intervene before the cap is hit.
const OVERFLOW_WARN_THRESHOLD = 10;

// Overflow sort-key format: `${OVERFLOW_KEY_PREFIX}${primaryWindowEnd}${OVERFLOW_SEQUENCE_SEPARATOR}NNNN`
// Example: `~2024-01-01T01:00:00.000Z#0001`.
//
// The leading `~` (ASCII 0x7E) sorts lexicographically after every character that can
// appear at the start of an ISO 8601 timestamp (digits 0–9, ASCII 0x30–0x39). This means
// overflow items fall outside the `windowEnd <= :windowEndBefore` range condition used
// by queryOpenBatchesReady without any filter expression or in-memory post-processing,
// and they will never be picked up as independent batches. A prefix-based `begins_with`
// query reclaims them for aggregation in queryOverflowItems.
const OVERFLOW_KEY_PREFIX = '~';
const OVERFLOW_SEQUENCE_SEPARATOR = '#';

function buildOverflowKey(primaryWindowEnd: string, sequence: number): string {
  return `${OVERFLOW_KEY_PREFIX}${primaryWindowEnd}${OVERFLOW_SEQUENCE_SEPARATOR}${String(sequence).padStart(4, '0')}`;
}

// Buffer added on top of the Lambda timeout to decide when a 'processing' batch is abandoned.
// Covers worst-case clock skew, SDK retries, and time spent in the DynamoDB call itself.
const STALE_PROCESSING_BUFFER_MS = 60 * 1000; // 1 minute

// Fallback stale threshold when the caller does not supply one. Sized for the worst case
// allowed by Lambda (15-minute maximum timeout) plus STALE_PROCESSING_BUFFER_MS. Services
// that know their own timeout should pass it explicitly to recover stuck batches sooner.
const DEFAULT_STALE_PROCESSING_MS = 15 * 60 * 1000 + STALE_PROCESSING_BUFFER_MS;

/**
 * Compute an appropriate `staleProcessingMs` from a Lambda timeout expressed in seconds.
 * Adds `STALE_PROCESSING_BUFFER_MS` to account for clock skew and in-flight DynamoDB calls.
 * Falls back to {@link DEFAULT_STALE_PROCESSING_MS} when the input is not a positive number.
 */
export function computeStaleProcessingMs(lambdaTimeoutSeconds: string): number {
  const seconds = Number(lambdaTimeoutSeconds);
  if (!Number.isFinite(seconds) || seconds <= 0) return DEFAULT_STALE_PROCESSING_MS;
  return seconds * 1000 + STALE_PROCESSING_BUFFER_MS;
}

export interface NotificationBatchRepositoryOptions {
  /** Custom clock (default: system clock). */
  readonly clock?: Clock;
  /** Custom UUID generator for reconciliation task IDs (default: crypto-backed generator). */
  readonly idGenerator?: IdGenerator;
  /**
   * How long a batch may remain in the 'processing' state before a competing worker can
   * re-claim it as abandoned. Defaults to 16 minutes to match the worst-case Lambda timeout.
   * Callers that know their Lambda timeout should pass `(lambdaTimeoutMs + buffer)` instead
   * so stuck batches are recovered promptly.
   */
  readonly staleProcessingMs?: number;
}

/**
 * Thrown when a conditional state transition on a notification batch cannot be
 * performed because the batch is missing or in an incompatible status (for
 * example, another processor has already claimed it, or it has been dispatched).
 */
export class BatchStateTransitionError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'BatchStateTransitionError';
  }
}

/**
 * Thrown by {@link NotificationBatchRepository.appendEventId} when the primary batch
 * and every overflow slot (1..{@link MAX_OVERFLOW_SEQUENCES}) have reached the per-item
 * item-count cap. Distinct from generic errors so callers can handle overflow
 * saturation (for example by sending to a dead-letter queue, alarming, or dropping the
 * event) without masking unrelated failures.
 */
export class BatchOverflowError extends Error {
  constructor(
    message: string,
    public readonly configId: string,
    public readonly windowEnd: string,
    public readonly maxSequences: number,
  ) {
    super(message);
    this.name = 'BatchOverflowError';
  }
}

export class NotificationBatchRepository extends AbstractRepository<NotificationBatchItem> {
  protected readonly partitionKeyName = 'configId';
  protected readonly sortKeyName = 'windowEnd';

  private readonly clock: Clock;
  private readonly idGenerator: IdGenerator;
  private readonly staleProcessingMs: number;

  constructor(
    principal: string,
    tableName: string,
    dynamoDBClient: DynamoDBDocumentClient,
    options: NotificationBatchRepositoryOptions = {},
  ) {
    super(principal, tableName, dynamoDBClient);
    this.clock = options.clock ?? getClock();
    this.idGenerator = options.idGenerator ?? getIdGenerator();
    this.staleProcessingMs = options.staleProcessingMs ?? DEFAULT_STALE_PROCESSING_MS;
  }

  /** Query all batches for a given configId, optionally up to a windowEnd ceiling */
  async queryByConfigId(configId: string, windowEndBefore?: string): Promise<NotificationBatchItem[]> {
    const items: NotificationBatchItem[] = [];
    let exclusiveStartKey: Record<string, unknown> | undefined;

    do {
      const response = await this.dynamoDBClient.send(
        new QueryCommand({
          TableName: this.tableName,
          KeyConditionExpression: windowEndBefore ? 'configId = :pk AND windowEnd <= :sk' : 'configId = :pk',
          ExpressionAttributeValues: {
            ':pk': configId,
            ...(windowEndBefore && { ':sk': windowEndBefore }),
          },
          ExclusiveStartKey: exclusiveStartKey,
        }),
      );
      if (response.Items) {
        items.push(...(response.Items as NotificationBatchItem[]));
      }
      exclusiveStartKey = response.LastEvaluatedKey;
    } while (exclusiveStartKey);

    return items;
  }

  /**
   * Query open primary batches whose window has elapsed. For each primary, any overflow
   * continuations are transparently merged into the returned item's `findingIds` and
   * `remediationIds` so callers see a single logical batch per window. Also recovers
   * primary batches stuck in 'processing' (Lambda timeout).
   *
   * Overflow items are excluded from the top-level range query by key design: their
   * sort keys start with {@link OVERFLOW_KEY_PREFIX} (`~`), which sorts lexicographically
   * after every digit-leading ISO 8601 timestamp, so the `windowEnd <= :windowEndBefore`
   * condition skips them naturally. See the constant declaration for rationale.
   */
  async queryOpenBatchesReady(configId: string, windowEndBefore: string): Promise<NotificationBatchItem[]> {
    const primaries = await this.queryPrimaryBatchesReady(configId, windowEndBefore);
    return Promise.all(primaries.map((primary) => this.mergeOverflow(primary)));
  }

  /** Query primary batches whose window has elapsed, without merging overflow. */
  private async queryPrimaryBatchesReady(configId: string, windowEndBefore: string): Promise<NotificationBatchItem[]> {
    const items: NotificationBatchItem[] = [];
    let exclusiveStartKey: Record<string, unknown> | undefined;
    const staleThreshold = new Date(this.clock.now().getTime() - this.staleProcessingMs).toISOString();

    do {
      const response = await this.dynamoDBClient.send(
        new QueryCommand({
          TableName: this.tableName,
          KeyConditionExpression: 'configId = :pk AND windowEnd <= :windowEndBefore',
          FilterExpression:
            '#s = :open OR (#s = :processing AND (attribute_not_exists(processingStartedAt) OR processingStartedAt < :staleThreshold))',
          ExpressionAttributeNames: { '#s': 'status' },
          ExpressionAttributeValues: {
            ':pk': configId,
            ':windowEndBefore': windowEndBefore,
            ':open': 'open',
            ':processing': 'processing',
            ':staleThreshold': staleThreshold,
          },
          ExclusiveStartKey: exclusiveStartKey,
        }),
      );
      if (response.Items) {
        items.push(...(response.Items as NotificationBatchItem[]));
      }
      exclusiveStartKey = response.LastEvaluatedKey;
    } while (exclusiveStartKey);

    return items;
  }

  /**
   * Merge every overflow continuation for `primary` into a single logical batch item.
   * Returns `primary` unchanged when no overflow items exist (the common path).
   */
  private async mergeOverflow(primary: NotificationBatchItem): Promise<NotificationBatchItem> {
    const overflowItems = await this.queryOverflowItems(primary.configId, primary.windowEnd);
    if (overflowItems.length === 0) return primary;

    this.logger.info('Merged overflow continuations into primary batch', {
      configId: primary.configId,
      windowEnd: primary.windowEnd,
      overflowCount: overflowItems.length,
    });

    return {
      ...primary,
      findingIds: [...(primary.findingIds ?? []), ...overflowItems.flatMap((item) => item.findingIds ?? [])],
      remediationIds: [
        ...(primary.remediationIds ?? []),
        ...overflowItems.flatMap((item) => item.remediationIds ?? []),
      ],
      itemCount: (primary.itemCount ?? 0) + overflowItems.reduce((sum, item) => sum + (item.itemCount ?? 0), 0),
    };
  }

  /**
   * Query every overflow continuation item for a given primary batch. Public so tests
   * and operational tooling can inspect continuations directly; normal batch processing
   * gets them transparently merged via {@link queryOpenBatchesReady}.
   */
  async queryOverflowItems(configId: string, primaryWindowEnd: string): Promise<NotificationBatchItem[]> {
    const items: NotificationBatchItem[] = [];
    let exclusiveStartKey: Record<string, unknown> | undefined;
    const overflowPrefix = `${OVERFLOW_KEY_PREFIX}${primaryWindowEnd}${OVERFLOW_SEQUENCE_SEPARATOR}`;

    do {
      const response = await this.dynamoDBClient.send(
        new QueryCommand({
          TableName: this.tableName,
          KeyConditionExpression: 'configId = :pk AND begins_with(windowEnd, :prefix)',
          ExpressionAttributeValues: {
            ':pk': configId,
            ':prefix': overflowPrefix,
          },
          ExclusiveStartKey: exclusiveStartKey,
        }),
      );
      if (response.Items) {
        items.push(...(response.Items as NotificationBatchItem[]));
      }
      exclusiveStartKey = response.LastEvaluatedKey;
    } while (exclusiveStartKey);

    return items;
  }

  /**
   * Attempt to claim an event for a config. Returns true if the event is new (caller
   * should proceed to append it to a batch). Returns false if the event was already
   * claimed (duplicate delivery — caller should skip silently).
   * Uses a conditional PutItem with the same TTL as the batch so dedup records auto-expire.
   */
  async tryClaimEvent(configId: string, eventId: string, expireAt: number): Promise<boolean> {
    try {
      await this.dynamoDBClient.send(
        new PutCommand({
          TableName: this.tableName,
          Item: { configId, windowEnd: `${DEDUP_KEY_PREFIX}${eventId}`, expireAt },
          ConditionExpression: 'attribute_not_exists(configId)',
        }),
      );
      return true;
    } catch (error) {
      if (error instanceof ConditionalCheckFailedException) return false;
      throw error;
    }
  }

  /** Remove a previously-claimed dedup record (best-effort rollback on append failure). */
  async deleteEventClaim(configId: string, eventId: string): Promise<void> {
    await this.dynamoDBClient.send(
      new DeleteCommand({
        TableName: this.tableName,
        Key: { configId, windowEnd: `${DEDUP_KEY_PREFIX}${eventId}` },
      }),
    );
  }

  /**
   * Append a finding or remediation ID to an existing batch (upsert). Creates overflow
   * items if the primary batch is full.
   *
   * Overflow behavior: when the primary item for the given `configId`/`windowEnd` has
   * reached {@link MAX_ITEMS_PER_BATCH}, this method probes overflow items keyed by
   * {@link buildOverflowKey} with sequence numbers 1..{@link MAX_OVERFLOW_SEQUENCES}
   * sequentially until one accepts the write. Each probe is a single conditional
   * `UpdateItem`, so the worst case is {@link MAX_OVERFLOW_SEQUENCES} serial DynamoDB
   * writes in one invocation — acceptable given the cap is only reached in extreme
   * fan-in scenarios. A warning is logged once sequence numbers cross
   * {@link OVERFLOW_WARN_THRESHOLD} so saturation is visible before the absolute cap
   * is hit.
   *
   * @throws {BatchOverflowError} when the primary batch and every overflow slot are full.
   *   Callers SHOULD treat this as a terminal condition for the event (dead-letter,
   *   alarm, or drop) rather than retrying indefinitely.
   */
  async appendEventId(
    configId: string,
    windowEnd: string,
    eventId: string,
    eventType: 'findingIds' | 'remediationIds',
    expireAt: number,
  ): Promise<void> {
    try {
      await this.appendToSlot(configId, windowEnd, eventId, eventType, expireAt);
      return;
    } catch (error) {
      if (!(error instanceof ConditionalCheckFailedException)) throw error;
    }

    // Primary batch item is full — probe overflow slots sequentially.
    for (let sequence = 1; sequence <= MAX_OVERFLOW_SEQUENCES; sequence++) {
      if (sequence === OVERFLOW_WARN_THRESHOLD) {
        this.logger.warn('Batch overflow slots filling up', {
          configId,
          windowEnd,
          sequence,
          maxSequence: MAX_OVERFLOW_SEQUENCES,
        });
      }
      try {
        await this.appendToSlot(configId, buildOverflowKey(windowEnd, sequence), eventId, eventType, expireAt);
        return;
      } catch (error) {
        if (error instanceof ConditionalCheckFailedException) continue;
        throw error;
      }
    }

    throw new BatchOverflowError(
      `All overflow slots exhausted for configId=${configId}, windowEnd=${windowEnd} after ${MAX_OVERFLOW_SEQUENCES} sequences`,
      configId,
      windowEnd,
      MAX_OVERFLOW_SEQUENCES,
    );
  }

  /**
   * Conditional `UpdateItem` that upserts a single event into the batch slot identified
   * by `(configId, slotKey)`. Throws {@link ConditionalCheckFailedException} when the
   * slot has already reached {@link MAX_ITEMS_PER_BATCH}; appendEventId interprets that
   * as a signal to probe the next overflow slot.
   */
  private async appendToSlot(
    configId: string,
    slotKey: string,
    eventId: string,
    eventType: 'findingIds' | 'remediationIds',
    expireAt: number,
  ): Promise<void> {
    await this.dynamoDBClient.send(
      new UpdateCommand({
        TableName: this.tableName,
        Key: { configId, windowEnd: slotKey },
        UpdateExpression:
          'SET #items = list_append(if_not_exists(#items, :empty), :evt), ' +
          'itemCount = if_not_exists(itemCount, :zero) + :one, ' +
          '#s = if_not_exists(#s, :open), ' +
          'createdAt = if_not_exists(createdAt, :now), ' +
          'lastUpdatedBy = :principal, ' +
          'expireAt = :expireAt',
        ConditionExpression: 'attribute_not_exists(itemCount) OR itemCount < :maxItems',
        ExpressionAttributeNames: { '#items': eventType, '#s': 'status' },
        ExpressionAttributeValues: {
          ':evt': [eventId],
          ':empty': [],
          ':zero': 0,
          ':one': 1,
          ':open': 'open',
          ':now': this.clock.now().toISOString(),
          ':principal': this.principal,
          ':expireAt': expireAt,
          ':maxItems': MAX_ITEMS_PER_BATCH,
        },
      }),
    );
  }

  /** Mark a batch as `processing` (atomic claim) or `dispatched` (publish ack). */
  async updateStatus(configId: string, windowEnd: string, status: 'processing' | 'dispatched'): Promise<void> {
    if (status === 'processing') {
      await this.claimForProcessing(configId, windowEnd);
    } else {
      await this.markDispatched(configId, windowEnd);
    }
  }

  /**
   * Atomic claim transition: `open` → `processing`, or `processing` → `processing` when the
   * existing claim has expired past the stale threshold. Only one worker can succeed at a time.
   */
  private async claimForProcessing(configId: string, windowEnd: string): Promise<void> {
    const currentTime = this.clock.now();
    const now = currentTime.toISOString();
    const staleThreshold = new Date(currentTime.getTime() - this.staleProcessingMs).toISOString();

    try {
      await this.dynamoDBClient.send(
        new UpdateCommand({
          TableName: this.tableName,
          Key: { configId, windowEnd },
          UpdateExpression: 'SET #s = :status, lastUpdatedBy = :principal, processingStartedAt = :now',
          ConditionExpression:
            'attribute_exists(configId) AND (#s = :open OR (#s = :processing AND (attribute_not_exists(processingStartedAt) OR processingStartedAt < :staleThreshold)))',
          ExpressionAttributeNames: { '#s': 'status' },
          ExpressionAttributeValues: {
            ':status': 'processing',
            ':principal': this.principal,
            ':now': now,
            ':open': 'open',
            ':processing': 'processing',
            ':staleThreshold': staleThreshold,
          },
        }),
      );
    } catch (error) {
      if (error instanceof ConditionalCheckFailedException) {
        throw new BatchStateTransitionError(
          `Cannot transition batch to processing: configId=${configId}, windowEnd=${windowEnd} (already claimed or invalid state)`,
        );
      }
      throw error;
    }
  }

  /** Terminal transition: `processing` → `dispatched`. Rejects from any other state. */
  private async markDispatched(configId: string, windowEnd: string): Promise<void> {
    try {
      await this.dynamoDBClient.send(
        new UpdateCommand({
          TableName: this.tableName,
          Key: { configId, windowEnd },
          UpdateExpression: 'SET #s = :status, lastUpdatedBy = :principal',
          ConditionExpression: 'attribute_exists(configId) AND #s = :processing',
          ExpressionAttributeNames: { '#s': 'status' },
          ExpressionAttributeValues: {
            ':status': 'dispatched',
            ':principal': this.principal,
            ':processing': 'processing',
          },
        }),
      );
    } catch (error) {
      if (error instanceof ConditionalCheckFailedException) {
        throw new BatchStateTransitionError(
          `Cannot transition batch to dispatched: configId=${configId}, windowEnd=${windowEnd} (already claimed or invalid state)`,
        );
      }
      throw error;
    }
  }

  /** Roll a batch back to 'open' for retry. Only allowed from 'processing' status to prevent re-opening dispatched batches. */
  async rollbackToOpen(configId: string, windowEnd: string): Promise<void> {
    try {
      await this.dynamoDBClient.send(
        new UpdateCommand({
          TableName: this.tableName,
          Key: { configId, windowEnd },
          UpdateExpression: 'SET #s = :open, lastUpdatedBy = :principal',
          ConditionExpression: 'attribute_exists(configId) AND #s = :processing',
          ExpressionAttributeNames: { '#s': 'status' },
          ExpressionAttributeValues: { ':open': 'open', ':processing': 'processing', ':principal': this.principal },
        }),
      );
    } catch (error) {
      if (error instanceof ConditionalCheckFailedException) {
        throw new BatchStateTransitionError(
          `Cannot roll back batch to open: configId=${configId}, windowEnd=${windowEnd} (not found or not in 'processing' status)`,
        );
      }
      throw error;
    }
  }

  /**
   * Build and persist a new {@link ReconciliationTask} to the table.
   *
   * The task is created in the `PENDING` state with `itemCount` 0 and `windowEnd` set to the
   * current time, then picked up by the Batch Processor on its next invocation.
   *
   * @returns The task that was written, so callers can log or assert on its generated `configId`.
   */
  async createReconciliationTask(
    taskType: ReconciliationTaskType,
    oldConfig: NotificationConfigurationItem | undefined,
    newConfig: NotificationConfigurationItem | undefined,
  ): Promise<ReconciliationTask> {
    const creationTime = this.clock.now().toISOString();

    const task: ReconciliationTask = {
      configId: `${RECONCILIATION_CONFIG_ID_PREFIX}${this.idGenerator.randomUUID()}`,
      windowEnd: creationTime,
      status: 'PENDING',
      taskType,
      itemCount: 0,
      expireAt: calculateTtlTimestamp(creationTime, RECONCILIATION_TASK_TTL_DAYS),
      reconciliationQueue: RECONCILIATION_QUEUE_VALUE,
      ...(oldConfig && { oldConfig }),
      ...(newConfig && { newConfig }),
    };

    await this.dynamoDBClient.send(new PutCommand({ TableName: this.tableName, Item: task }));

    return task;
  }

  /**
   * Fetch every outstanding {@link ReconciliationTask} — those still `PENDING` or `IN_PROGRESS`.
   *
   * Reconciliation tasks each occupy their own partition (a unique `reconciliation#<uuid>`
   * configId), so they cannot be retrieved with a single partition Query on the base table. Rather
   * than scanning the shared NotificationBatches table on every Batch Processor invocation, each
   * outstanding task carries a constant {@link RECONCILIATION_QUEUE_ATTRIBUTE} that places it in the
   * sparse {@link OUTSTANDING_RECONCILIATION_GSI}. The attribute is removed when a task COMPLETES
   * (see {@link recordReconciliationTaskResult}), so the index contains only outstanding work and is
   * empty in the common steady state — this Query returns immediately without reading batch or dedup
   * items, and its cost is independent of the base table's size.
   */
  async queryOutstandingReconciliationTasks(): Promise<ReconciliationTask[]> {
    const tasks: ReconciliationTask[] = [];
    let exclusiveStartKey: Record<string, unknown> | undefined;

    do {
      const response = await this.dynamoDBClient.send(
        new QueryCommand({
          TableName: this.tableName,
          IndexName: OUTSTANDING_RECONCILIATION_GSI,
          KeyConditionExpression: '#queue = :queue',
          ExpressionAttributeNames: { '#queue': RECONCILIATION_QUEUE_ATTRIBUTE },
          ExpressionAttributeValues: { ':queue': RECONCILIATION_QUEUE_VALUE },
          ExclusiveStartKey: exclusiveStartKey,
        }),
      );
      if (response.Items) {
        tasks.push(...(response.Items as ReconciliationTask[]));
      }
      exclusiveStartKey = response.LastEvaluatedKey;
    } while (exclusiveStartKey);

    return tasks;
  }

  /**
   * Persist the outcome of processing a reconciliation task. The task's running `itemCount` is
   * always advanced by `progress.itemsProcessed`. When the task is complete it transitions to
   * `COMPLETED`, its resume bookmark is removed, and its {@link RECONCILIATION_QUEUE_ATTRIBUTE} is
   * dropped so it leaves the sparse {@link OUTSTANDING_RECONCILIATION_GSI} and is never re-queried;
   * otherwise it stays `IN_PROGRESS` with `lastProcessedKey` saved so the next Batch Processor
   * invocation resumes exactly where this one stopped.
   */
  async recordReconciliationTaskResult(task: ReconciliationTask, progress: ReconciliationTaskProgress): Promise<void> {
    const nextItemCount = task.itemCount + progress.itemsProcessed;

    if (progress.isComplete) {
      await this.dynamoDBClient.send(
        new UpdateCommand({
          TableName: this.tableName,
          Key: { configId: task.configId, windowEnd: task.windowEnd },
          UpdateExpression: 'SET #status = :completed, itemCount = :itemCount REMOVE lastProcessedKey, #queue',
          ExpressionAttributeNames: { '#status': 'status', '#queue': RECONCILIATION_QUEUE_ATTRIBUTE },
          ExpressionAttributeValues: { ':completed': 'COMPLETED', ':itemCount': nextItemCount },
        }),
      );
      return;
    }

    await this.dynamoDBClient.send(
      new UpdateCommand({
        TableName: this.tableName,
        Key: { configId: task.configId, windowEnd: task.windowEnd },
        UpdateExpression: 'SET #status = :inProgress, itemCount = :itemCount, lastProcessedKey = :lastProcessedKey',
        ExpressionAttributeNames: { '#status': 'status' },
        ExpressionAttributeValues: {
          ':inProgress': 'IN_PROGRESS',
          ':itemCount': nextItemCount,
          ':lastProcessedKey': progress.lastProcessedKey ?? {},
        },
      }),
    );
  }
}
