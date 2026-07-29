// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { ConditionalCheckFailedException } from '@aws-sdk/client-dynamodb';
import {
  DynamoDBDocumentClient,
  GetCommand,
  GetCommandInput,
  PutCommand,
  PutCommandInput,
  QueryCommand,
  QueryCommandInput,
} from '@aws-sdk/lib-dynamodb';
import { AbstractRepository, DynamoDBItem } from './abstractRepository';
import { Clock, getClock } from '../utils/clock';

/**
 * The one chunk of controlIds currently being paged through Security Hub.
 * `nextToken` is a Security Hub pagination token and is NOT durable — it can
 * expire between runs, so a resume must be prepared to discard it (see runSyncSlice).
 */
export interface SyncCursorInProgress {
  controlIds: string[];
  nextToken?: string;
}

/**
 * Resumable position of one account's finding synchronization.
 *
 * `completedControlIds` is a set in spirit but is persisted as a DynamoDB List
 * (`L`), never a String Set (`SS`) — an empty String Set cannot be written, and
 * a fresh-start cursor legitimately has zero completed controls.
 */
export interface SyncCursor {
  completedControlIds: string[];
  inProgress: SyncCursorInProgress | null;
  totalControlIds: number;
  processedFindings: number;
  done: boolean;
  /** Monotonic version for optimistic concurrency on saveCursor. */
  version: number;
  lastSyncedAt: string;
}

/**
 * Fleet-wide sweep metadata: the account denominator, when it started, and whether it has finished.
 * The completed-account *count* is intentionally NOT stored here — it is derived from the done account
 * cursors via {@link SyncCursorRepository.countCompletedAccounts} so parallel slices finishing at once
 * cannot lose an increment to a write race.
 */
export interface SyncSweep {
  totalAccounts: number;
  startedAt: string;
  done: boolean;
  /** Monotonic version for optimistic concurrency on saveSweep. */
  version: number;
}

/** Thrown by saveCursor/saveSweep when the persisted record has moved on (another writer won the race). */
export class StaleCursorError extends Error {
  constructor(expectedVersion: number) {
    super(`Sync record was modified concurrently (expected version ${expectedVersion}); refusing to overwrite.`);
    this.name = 'StaleCursorError';
  }
}

// Dedicated partition values that are never a real controlId (findingType), so the cursor and sweep
// items sit outside every reader GSI. See the class doc for the full isolation rationale.
const CURSOR_PARTITION = 'SYNC_CURSOR';
const SWEEP_PARTITION = 'SYNC_SWEEP';
const SWEEP_SORT_KEY = 'global';

/** Shape of the persisted `inProgress` attribute — a nested DynamoDB map. */
interface StoredInProgress {
  controlIds: string[];
  nextToken?: string;
}

/**
 * Persistence for the finding-synchronization cursors and the sweep progress record. A "sweep" is one
 * end-to-end synchronization pass that imports every finding from AWS Security Hub across all member
 * accounts. Both are ordinary items in the findings table; neither carries `FINDING_CONSTANT`,
 * `accountId`, `resourceId`, `severity`, or any GSI sort-key attribute, so they never surface in a
 * findings query or scan.
 *
 * Each account is an independent resumable unit keyed by its accountId scope
 * (`SYNC_CURSOR#<accountId>`); the sweep record (`SYNC_SWEEP#global`) tracks fleet-wide progress.
 * Concurrent runs are serialized by the sweep state machine (a `MaxConcurrency: 1` Map), so this
 * repository holds no lock of its own.
 */
export class SyncCursorRepository extends AbstractRepository<SyncCursor> {
  protected readonly partitionKeyName = 'findingType';
  protected readonly sortKeyName = 'findingId';

  constructor(
    principal: string,
    tableName: string,
    dynamoDBClient: DynamoDBDocumentClient,
    private readonly clock: Clock = getClock(),
  ) {
    super(principal, tableName, dynamoDBClient);
  }

  /** Returns the persisted cursor for the given account scope, or null if that account has never synced. */
  async getCursor(accountId: string): Promise<SyncCursor | null> {
    const params: GetCommandInput = {
      TableName: this.tableName,
      Key: { [this.partitionKeyName]: CURSOR_PARTITION, [this.sortKeyName]: accountId },
    };

    const response = await this.dynamoDBClient.send(new GetCommand(params));
    if (!response.Item) return null;

    return this.toCursor(response.Item);
  }

  /**
   * Persists an account's cursor with an optimistic-concurrency guard on `version`. The write only
   * succeeds if the stored version still matches `cursor.version` (or no cursor exists yet);
   * otherwise a {@link StaleCursorError} is thrown. Returns the persisted cursor with its incremented
   * version and refreshed timestamp — pass this returned object to the next save.
   */
  async saveCursor(accountId: string, cursor: SyncCursor): Promise<SyncCursor> {
    const persisted: SyncCursor = {
      ...cursor,
      version: cursor.version + 1,
      lastSyncedAt: this.clock.now().toISOString(),
    };

    const params: PutCommandInput = {
      TableName: this.tableName,
      Item: {
        [this.partitionKeyName]: CURSOR_PARTITION,
        [this.sortKeyName]: accountId,
        ...this.toItem(persisted),
        lastUpdatedBy: this.principal,
      },
      ConditionExpression: 'attribute_not_exists(version) OR version = :expectedVersion',
      ExpressionAttributeValues: { ':expectedVersion': cursor.version },
    };

    try {
      await this.dynamoDBClient.send(new PutCommand(params));
      return persisted;
    } catch (error) {
      if (error instanceof ConditionalCheckFailedException) {
        this.logger.warn('Refused to save sync cursor: version mismatch', {
          accountId,
          expectedVersion: cursor.version,
        });
        throw new StaleCursorError(cursor.version);
      }
      throw error;
    }
  }

  /**
   * Overwrites an account's cursor with a fresh pass starting at version 1. Used when the previous
   * pass completed (`done`) and a new trigger should start over. Unconditional — the sweep state
   * machine (`MaxConcurrency: 1`) serializes runs, so no reset can race another.
   */
  async resetCursor(accountId: string, totalControlIds: number): Promise<SyncCursor> {
    const fresh: SyncCursor = {
      completedControlIds: [],
      inProgress: null,
      totalControlIds,
      processedFindings: 0,
      done: false,
      version: 1,
      lastSyncedAt: this.clock.now().toISOString(),
    };

    const params: PutCommandInput = {
      TableName: this.tableName,
      Item: {
        [this.partitionKeyName]: CURSOR_PARTITION,
        [this.sortKeyName]: accountId,
        ...this.toItem(fresh),
        lastUpdatedBy: this.principal,
      },
    };

    await this.dynamoDBClient.send(new PutCommand(params));
    return fresh;
  }

  /** Returns the fleet-wide sweep progress record, or null if no sweep has started. */
  async getSweep(): Promise<SyncSweep | null> {
    const params: GetCommandInput = {
      TableName: this.tableName,
      Key: { [this.partitionKeyName]: SWEEP_PARTITION, [this.sortKeyName]: SWEEP_SORT_KEY },
    };

    const response = await this.dynamoDBClient.send(new GetCommand(params));
    if (!response.Item) return null;

    return {
      totalAccounts: (response.Item.totalAccounts as number) ?? 0,
      startedAt: (response.Item.startedAt as string) ?? '',
      done: (response.Item.done as boolean) ?? false,
      version: (response.Item.version as number) ?? 0,
    };
  }

  /**
   * Counts how many per-account cursors are marked `done`. This derives sweep progress from the
   * account cursors themselves rather than from a maintained counter, so parallel account slices
   * finishing at once cannot lose an increment to a write race. All account cursors share the
   * `SYNC_CURSOR` partition, so this is a single partition query (paginated), and a server-side
   * filter returns only the done ones.
   *
   * Pass `completedAtOrAfter` (the current sweep's `startedAt`) to count only accounts that finished
   * *this* sweep. Cursors are not cleared when a sweep starts — each is reset lazily when its own turn
   * comes up — so without this bound every cursor still carries `done: true` from the previous sweep
   * and the count would report almost the full total from the first slice instead of climbing from
   * zero. `lastSyncedAt` is refreshed to "now" on every reset and checkpoint, so a cursor completed in
   * the current sweep necessarily has `lastSyncedAt >= startedAt`, while last sweep's leftovers fall
   * below it. Omit the argument to count all done cursors regardless of sweep (legacy behaviour).
   */
  async countCompletedAccounts(completedAtOrAfter?: string): Promise<number> {
    let completed = 0;
    let exclusiveStartKey: Record<string, unknown> | undefined;

    do {
      const params: QueryCommandInput = {
        TableName: this.tableName,
        KeyConditionExpression: '#partitionKey = :cursorPartition',
        FilterExpression: completedAtOrAfter
          ? '#done = :true AND #lastSyncedAt >= :completedAtOrAfter'
          : '#done = :true',
        ExpressionAttributeNames: {
          '#partitionKey': this.partitionKeyName,
          '#done': 'done',
          ...(completedAtOrAfter && { '#lastSyncedAt': 'lastSyncedAt' }),
        },
        ExpressionAttributeValues: {
          ':cursorPartition': CURSOR_PARTITION,
          ':true': true,
          ...(completedAtOrAfter && { ':completedAtOrAfter': completedAtOrAfter }),
        },
        Select: 'COUNT',
        ...(exclusiveStartKey && { ExclusiveStartKey: exclusiveStartKey }),
      };

      const response = await this.dynamoDBClient.send(new QueryCommand(params));
      completed += response.Count ?? 0;
      exclusiveStartKey = response.LastEvaluatedKey;
    } while (exclusiveStartKey);

    return completed;
  }

  /**
   * Persists the sweep record with an optimistic-concurrency guard on `version`, mirroring
   * {@link saveCursor}. Pass version 0 to create the initial record. Returns the persisted record
   * with its incremented version — pass this returned object to the next save.
   */
  async saveSweep(sweep: SyncSweep): Promise<SyncSweep> {
    const persisted: SyncSweep = { ...sweep, version: sweep.version + 1 };

    const params: PutCommandInput = {
      TableName: this.tableName,
      Item: {
        [this.partitionKeyName]: SWEEP_PARTITION,
        [this.sortKeyName]: SWEEP_SORT_KEY,
        totalAccounts: persisted.totalAccounts,
        startedAt: persisted.startedAt,
        done: persisted.done,
        version: persisted.version,
        lastUpdatedBy: this.principal,
      },
      ConditionExpression: 'attribute_not_exists(version) OR version = :expectedVersion',
      ExpressionAttributeValues: { ':expectedVersion': sweep.version },
    };

    try {
      await this.dynamoDBClient.send(new PutCommand(params));
      return persisted;
    } catch (error) {
      if (error instanceof ConditionalCheckFailedException) {
        this.logger.warn('Refused to save sync sweep: version mismatch', { expectedVersion: sweep.version });
        throw new StaleCursorError(sweep.version);
      }
      throw error;
    }
  }

  /**
   * Marks the current sweep done. Reads the latest record and saves it with `done: true` under the
   * version guard. No-op when no sweep record exists.
   */
  async saveSweepDone(): Promise<void> {
    const sweep = await this.getSweep();
    if (!sweep) {
      this.logger.warn('No sweep record found while marking sweep done');
      return;
    }
    await this.saveSweep({ ...sweep, done: true });
  }

  /**
   * Overwrites the sweep record with a fresh sweep at version 1, capturing the total account count
   * and start time. Used when a new sweep is triggered. Unconditional — the sweep state machine
   * (`MaxConcurrency: 1`) serializes runs, so no reset can race another.
   */
  async resetSweep(totalAccounts: number): Promise<SyncSweep> {
    const fresh: SyncSweep = {
      totalAccounts,
      startedAt: this.clock.now().toISOString(),
      done: false,
      version: 1,
    };

    const params: PutCommandInput = {
      TableName: this.tableName,
      Item: {
        [this.partitionKeyName]: SWEEP_PARTITION,
        [this.sortKeyName]: SWEEP_SORT_KEY,
        totalAccounts: fresh.totalAccounts,
        startedAt: fresh.startedAt,
        done: fresh.done,
        version: fresh.version,
        lastUpdatedBy: this.principal,
      },
    };

    await this.dynamoDBClient.send(new PutCommand(params));
    return fresh;
  }

  /** Maps a stored DynamoDB item to a SyncCursor, dropping storage-only attributes. */
  private toCursor(item: DynamoDBItem): SyncCursor {
    const storedInProgress = item.inProgress as StoredInProgress | null | undefined;
    const inProgress: SyncCursorInProgress | null = storedInProgress
      ? {
          controlIds: storedInProgress.controlIds ?? [],
          ...(storedInProgress.nextToken !== undefined && { nextToken: storedInProgress.nextToken }),
        }
      : null;

    return {
      completedControlIds: (item.completedControlIds as string[]) ?? [],
      inProgress,
      totalControlIds: (item.totalControlIds as number) ?? 0,
      processedFindings: (item.processedFindings as number) ?? 0,
      done: (item.done as boolean) ?? false,
      version: (item.version as number) ?? 0,
      lastSyncedAt: (item.lastSyncedAt as string) ?? '',
    };
  }

  /**
   * Serializes a cursor to a DynamoDB-safe item. The document client is
   * configured to reject `undefined`, so `nextToken` is omitted (not set to
   * undefined) when absent, and `inProgress` is either a clean map or null.
   */
  private toItem(cursor: SyncCursor): DynamoDBItem {
    const inProgress: StoredInProgress | null =
      cursor.inProgress === null
        ? null
        : {
            controlIds: cursor.inProgress.controlIds,
            ...(cursor.inProgress.nextToken !== undefined && { nextToken: cursor.inProgress.nextToken }),
          };

    return {
      completedControlIds: cursor.completedControlIds,
      inProgress,
      totalControlIds: cursor.totalControlIds,
      processedFindings: cursor.processedFindings,
      done: cursor.done,
      version: cursor.version,
      lastSyncedAt: cursor.lastSyncedAt,
    };
  }
}
