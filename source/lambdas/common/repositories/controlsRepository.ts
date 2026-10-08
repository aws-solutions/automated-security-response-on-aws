// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import {
  DynamoDBDocumentClient,
  PutCommand,
  TransactWriteCommand,
  TransactWriteCommandInput,
  UpdateCommand,
} from '@aws-sdk/lib-dynamodb';
import { SecurityControl, SecurityControlDynamoDBItem } from '@asr/data-models';
import { toStringArray } from '../utils/dynamodb';
import { Sleeper } from '../utils/sleeper';
import { AbstractRepository } from './abstractRepository';

export interface BulkUpdateResult {
  successCount: number;
  failedControlIds: string[];
  rejectedControlIds?: string[];
}

interface ControlVersionInfo {
  controlId: string;
  version: number;
}

interface TransactUpdateItem {
  Update: {
    TableName: string;
    Key: Record<string, unknown>;
    UpdateExpression: string;
    ConditionExpression: string;
    ExpressionAttributeValues: Record<string, unknown>;
  };
}

const DYNAMODB_TRANSACTION_BATCH_SIZE = 100;

/**
 * How many times a batch may be re-driven for a *transient* cancellation before its remaining
 * items are reported as failed. Each re-drive waits `TRANSIENT_RETRY_BASE_DELAY_MS * 2^attempt`.
 */
const TRANSIENT_RETRY_MAX_ATTEMPTS = 3;
const TRANSIENT_RETRY_BASE_DELAY_MS = 50;
/**
 * Pause before re-driving a batch that lost only *permanent* items (a stale version, say). Such
 * passes need no budget — the batch strictly shrinks, so at most `DYNAMODB_TRANSACTION_BATCH_SIZE`
 * of them can happen — but without a pause a bulk edit racing another writer can issue them
 * back-to-back as one tight loop against the table.
 */
const PERMANENT_REDRIVE_DELAY_MS = 20;
/**
 * Hard cap on how many times one batch is written, counting the first attempt and every re-drive
 * of either kind. Permanent-only re-drives spend no transient budget and the batch shrinks by at
 * least one each time, so without this they were bounded only by the batch size: a concurrent
 * writer bumping a different version on every pass could cost up to 100 serial round-trips inside
 * one API request. At the cap the contended items are reported failed and the collateral items get
 * the same single final write as when the transient budget runs out. The final write itself is not
 * counted: it can never re-drive, so the true ceiling is `MAX_PASSES_PER_BATCH + 1` transactions.
 */
const MAX_PASSES_PER_BATCH = 8;

/**
 * Request-level errors that mean "nothing was written, try the same request again". Unlike a
 * `TransactionCanceledException` they carry no per-item reasons, so the whole batch is treated
 * as contended and re-driven under the same transient budget. The SDK's standard retry mode has
 * already retried these a few times before they reach this code; this is a further bounded layer,
 * not the first.
 *
 * Only codes that guarantee the transaction was rejected before any write belong here. A 5xx
 * (`InternalServerError`, `ServiceUnavailable`) does not: the transaction may have committed, and
 * a blind re-drive would then trip every item's version condition and report a write that
 * succeeded as a permanent failure. Those fall through to `'failed'` with the outcome logged as
 * unknown.
 */
const REQUEST_LEVEL_THROTTLE_ERRORS: ReadonlySet<string> = new Set([
  'ThrottlingException',
  'ProvisionedThroughputExceededException',
  'RequestLimitExceeded',
]);
const AMBIGUOUS_OUTCOME_ERRORS: ReadonlySet<string> = new Set(['InternalServerError', 'ServiceUnavailable']);

/**
 * Cancellation codes that mean "this item, as submitted, will never succeed". Only these
 * blame the item and remove it from the retry set.
 *
 * `ConditionalCheckFailed` is a lost version check. `ValidationError` and
 * `ItemCollectionSizeLimitExceeded` describe the item itself. Everything else DynamoDB can
 * report per item — `TransactionConflict` (the item is being written by a concurrent
 * transaction), `ThrottlingError`, `ProvisionedThroughputExceeded` — is transient: retrying
 * the item unchanged can succeed, so classifying it as a permanent failure silently dropped
 * a valid update under concurrent bulk edits and reported it as a version conflict.
 */
const PERMANENT_CANCELLATION_CODES: ReadonlySet<string> = new Set([
  'ConditionalCheckFailed',
  'ValidationError',
  'ItemCollectionSizeLimitExceeded',
]);

type CancellationReason = { Code?: string };

/** True when a cancellation reason blames this item rather than marking it collateral. */
function isPermanentFailure(reason: CancellationReason | undefined): boolean {
  return reason?.Code !== undefined && PERMANENT_CANCELLATION_CODES.has(reason.Code);
}

/** True when a cancellation reason is per-item and transient (worth re-driving unchanged). */
function isTransientFailure(reason: CancellationReason | undefined): boolean {
  return reason?.Code !== undefined && reason.Code !== 'None' && !PERMANENT_CANCELLATION_CODES.has(reason.Code);
}

/**
 * Splits a cancelled batch by what each item's own reason says about it. `reasons` is positionally
 * aligned with `batch`. Items whose reason is `None` were valid and rolled back only because they
 * shared the transaction with an item that was not.
 */
function classifyCancellation<T>(
  batch: readonly T[],
  reasons: readonly CancellationReason[],
): { unretryable: T[]; contended: T[]; collateral: T[] } {
  const unretryable: T[] = [];
  const contended: T[] = [];
  const collateral: T[] = [];
  batch.forEach((item, index) => {
    const reason = reasons[index];
    if (isPermanentFailure(reason)) unretryable.push(item);
    else if (isTransientFailure(reason)) contended.push(item);
    else collateral.push(item);
  });
  return { unretryable, contended, collateral };
}

export interface ControlExistenceCheckResult {
  readonly foundControlIds: string[];
  readonly isComplete: boolean;
}

/**
 * Which of the requested controls are served by a custom runbook, and whether the read
 * covered every key. See {@link ControlsRepository.findCustomControlIds} for why the second
 * field is not optional to consume.
 */
export interface CustomControlLookupResult {
  readonly customControlIds: ReadonlySet<string>;
  readonly isComplete: boolean;
}

export interface CustomControlConfiguration {
  readonly controlId: string;
  readonly description: string;
  readonly modifiedBy: string;
  readonly lastModified: string;
}

export class ControlsRepository extends AbstractRepository<SecurityControl> {
  protected readonly partitionKeyName = 'controlId';
  protected readonly sortKeyName = '';

  constructor(tableName: string, dynamoDBClient: DynamoDBDocumentClient, sleeper?: Sleeper) {
    super('ControlsRepository', tableName, dynamoDBClient, sleeper);
  }

  async batchFindByIds(controlIds: string[]): Promise<ControlExistenceCheckResult> {
    if (controlIds.length === 0) return { foundControlIds: [], isComplete: true };

    const uniqueIds = Array.from(new Set(controlIds));
    const keys = uniqueIds.map((id) => ({ controlId: id }));

    const { items, unprocessedKeys } = await this.batchGetWithRetry<{ controlId: string }>(keys, {
      requestItemOptions: { ProjectionExpression: 'controlId' },
    });

    // Trust the generic type parameter — batchGetWithRetry constrains TItem extends DynamoDBItem
    // and ProjectionExpression guarantees only controlId is returned.
    const foundControlIds = items.map((item) => item.controlId);

    return { foundControlIds, isComplete: unprocessedKeys.length === 0 };
  }

  async findAll(): Promise<SecurityControl[]> {
    return this.findAllWithTransform((item) => this.transformToSecurityControl(item as SecurityControlDynamoDBItem));
  }

  /**
   * Creates the persisted Controls entry for a successfully deployed Custom Runbook.
   * An administrator's enable/disable or filter configuration is never overwritten:
   * when a row already exists only the missing `source` marker is filled in.
   */
  async createCustomControlIfAbsent(configuration: CustomControlConfiguration): Promise<void> {
    const item: SecurityControlDynamoDBItem = {
      controlId: configuration.controlId,
      description: configuration.description,
      automatedRemediationEnabled: false,
      filterMode: 'include',
      version: 0,
      lastModified: configuration.lastModified,
      modifiedBy: configuration.modifiedBy,
      source: 'custom',
    };

    try {
      await this.dynamoDBClient.send(
        new PutCommand({
          TableName: this.tableName,
          Item: item,
          ConditionExpression: 'attribute_not_exists(controlId)',
        }),
      );
    } catch (error) {
      if (error instanceof Error && error.name === 'ConditionalCheckFailedException') {
        await this.markExistingControlAsCustom(configuration);
        return;
      }
      throw error;
    }
  }

  /**
   * Stamps `source: 'custom'` onto a Controls row that already exists.
   *
   * The row is usually the one seeded at stack deploy for every built-in-supported
   * control (`remediation_config_provider.py`), which carries no `source` attribute at
   * all and therefore reads back as `builtin` (see `transformToSecurityControl`). Left
   * unstamped it makes `findCustomControlIds` miss the control, which fails the
   * `update_controls` guard OPEN: automated remediation gets enabled for a
   * manual-trigger-only custom runbook that `resolve_ssm_doc_for_finding` will never run.
   *
   * Stamping cannot mislabel a control that a built-in actually serves. The seeded row
   * spans every control in the standard mapping, which is a superset of the controls a
   * built-in document exists for, so the row's presence is not evidence of a built-in —
   * that was the faulty inference this method replaced. The real check is upstream:
   * `RunbookDeploymentService` describes the effective built-in document, remap included,
   * in every requested member account and rejects the whole deploy on any hit, so a
   * control that reaches here provably has no built-in to be confused with.
   *
   * Only `source` is written, so an administrator's `automatedRemediationEnabled`,
   * `filterMode` and filter configuration survive untouched. The condition makes this
   * idempotent and stops a redeploy from relabelling a row that already declares a
   * source — `source` is a DynamoDB reserved word, hence the alias.
   */
  private async markExistingControlAsCustom(configuration: CustomControlConfiguration): Promise<void> {
    try {
      await this.dynamoDBClient.send(
        new UpdateCommand({
          TableName: this.tableName,
          Key: { controlId: configuration.controlId },
          UpdateExpression: 'SET #source = :custom',
          ConditionExpression: 'attribute_exists(controlId) AND attribute_not_exists(#source)',
          ExpressionAttributeNames: { '#source': 'source' },
          ExpressionAttributeValues: { ':custom': 'custom' },
        }),
      );
    } catch (error) {
      if (error instanceof Error && error.name === 'ConditionalCheckFailedException') {
        return;
      }
      throw error;
    }
  }

  /**
   * The subset of the given control ids whose remediation is served by a custom runbook, plus
   * whether the read covered every requested key.
   *
   * Used to refuse enabling automated remediation for those controls: custom runbooks are
   * manual-trigger only (`resolve_ssm_doc_for_finding` gates on the event type), so the
   * flag would be stored, honoured by the pre-processor, and then ignored by the resolver.
   *
   * `isComplete` is reported rather than swallowed because this Set drives a guard that
   * fails OPEN when it is short: a custom control missing from it reads as built-in, and the
   * enable it was meant to refuse goes through. `batchGetWithRetry` currently re-queues
   * unprocessed keys until none remain, so a short read means it stopped reporting them —
   * exactly the change this would have to survive. The caller refuses the update instead of
   * deciding on a partial answer, the same way `batchFindByIds` is handled.
   *
   * A control absent from the table is not reported as custom — an unknown control fails
   * the update for its own reasons rather than being mislabelled here. `source` is a
   * DynamoDB reserved word, hence the alias.
   */
  async findCustomControlIds(controlIds: string[]): Promise<CustomControlLookupResult> {
    if (controlIds.length === 0) return { customControlIds: new Set(), isComplete: true };

    const uniqueIds = Array.from(new Set(controlIds));
    const keys = uniqueIds.map((id) => ({ controlId: id }));

    const { items, unprocessedKeys } = await this.batchGetWithRetry<{ controlId: string; source?: string }>(keys, {
      requestItemOptions: {
        ProjectionExpression: 'controlId, #source',
        ExpressionAttributeNames: { '#source': 'source' },
      },
    });

    return {
      customControlIds: new Set(items.filter((item) => item.source === 'custom').map((item) => item.controlId)),
      isComplete: unprocessedKeys.length === 0,
    };
  }

  /**
   * Reads the current automated-remediation state for the given control ids, keyed by control id.
   * Uses a projected BatchGetItem so the read is bounded by the number of requested controls rather
   * than the whole table. Controls that do not exist are simply absent from the returned map.
   */
  async findRemediationStateByControlIds(controlIds: string[]): Promise<Map<string, boolean>> {
    if (controlIds.length === 0) return new Map();

    const uniqueIds = Array.from(new Set(controlIds));
    const keys = uniqueIds.map((id) => ({ controlId: id }));

    const { items } = await this.batchGetWithRetry<{ controlId: string; automatedRemediationEnabled?: boolean }>(keys, {
      requestItemOptions: { ProjectionExpression: 'controlId, automatedRemediationEnabled' },
    });

    return new Map(items.map((item) => [item.controlId, item.automatedRemediationEnabled === true]));
  }

  /**
   * Reads the per-control rollback state, keyed by control id. Absent rollbackEnabled counts as
   * enabled, matching the Orchestrator gate. Controls that do not exist are absent from the map.
   */
  async findRollbackStateByControlIds(controlIds: string[]): Promise<Map<string, boolean>> {
    if (controlIds.length === 0) return new Map();

    const uniqueIds = Array.from(new Set(controlIds));
    const keys = uniqueIds.map((id) => ({ controlId: id }));

    const { items } = await this.batchGetWithRetry<{ controlId: string; rollbackEnabled?: boolean }>(keys, {
      requestItemOptions: { ProjectionExpression: 'controlId, rollbackEnabled' },
    });

    return new Map(items.map((item) => [item.controlId, item.rollbackEnabled !== false]));
  }

  /**
   * Of `controlIds`, the ones whose row currently lists `filterId` in `filters`.
   *
   * A strongly consistent read, unlike {@link findControlsUsingFilter}'s scan: this answers
   * "does this control reference the filter *now*", after a detach transaction, for controls
   * whose conditional write was refused. `batchGetWithRetry` drains its queue or throws, so a
   * returned list is complete; a read failure propagates and the caller must not treat the
   * unread controls as detached.
   */
  async controlsStillUsingFilter(filterId: string, controlIds: readonly string[]): Promise<string[]> {
    if (controlIds.length === 0) return [];

    const keys = Array.from(new Set(controlIds)).map((id) => ({ controlId: id }));
    const { items } = await this.batchGetWithRetry<{ controlId: string; filters?: Set<string> | string[] }>(keys, {
      requestItemOptions: { ProjectionExpression: 'controlId, filters', ConsistentRead: true },
    });
    return items.filter((item) => toStringArray(item.filters).includes(filterId)).map((item) => item.controlId);
  }

  /**
   * Every control whose `filters` lists `filterId`.
   *
   * `consistent` makes the scan strongly consistent (double the read cost): use it for the
   * last check before an irreversible step, where an eventually consistent image could show a
   * control as detached that was attached a moment ago.
   */
  async findControlsUsingFilter(filterId: string, options: { consistent?: boolean } = {}): Promise<string[]> {
    return this.findAllWithTransform(
      (item) => {
        const controlId = item.controlId;
        if (typeof controlId !== 'string') {
          throw new TypeError(`Expected controlId to be a string, got ${typeof controlId}`);
        }
        return controlId;
      },
      {
        FilterExpression: 'contains(filters, :filterId)',
        ExpressionAttributeValues: { ':filterId': filterId },
        ProjectionExpression: 'controlId',
        ...(options.consistent && { ConsistentRead: true }),
      },
    );
  }

  async bulkUpdateControls(
    controls: SecurityControl[],
    modifiedBy: string,
    lastModified: string,
  ): Promise<BulkUpdateResult> {
    return this.executeBatchedTransactions(
      controls,
      (control) => control.controlId,
      (control) => this.buildUpdateTransactItem(control, modifiedBy, lastModified),
      'Bulk update',
    );
  }

  async applyFilterToAllControls(
    filterId: string,
    modifiedBy: string,
    lastModified: string,
  ): Promise<BulkUpdateResult> {
    const controlVersions = await this.getAllControlVersions();

    return this.executeBatchedTransactions(
      controlVersions,
      (control) => control.controlId,
      (control) =>
        this.buildAddFilterTransactItem(control.controlId, control.version, filterId, modifiedBy, lastModified),
      'Apply filter to all controls',
    );
  }

  async removeFilterFromAllControls(
    filterId: string,
    modifiedBy: string,
    lastModified: string,
  ): Promise<BulkUpdateResult> {
    const controlVersions = await this.getAllControlVersions();

    return this.executeBatchedTransactions(
      controlVersions,
      (control) => control.controlId,
      (control) =>
        this.buildRemoveFilterTransactItem(control.controlId, control.version, filterId, modifiedBy, lastModified),
      'Remove filter from all controls',
    );
  }

  /**
   * Executes DynamoDB transactions in batches, handling errors and tracking success/failure.
   * @param items - Array of items to process
   * @param getControlId - Function to extract controlId from an item
   * @param buildTransactItem - Function to build a TransactWrite item from an item
   * @param operationName - Name of the operation for logging
   */
  private async executeBatchedTransactions<T>(
    items: T[],
    getControlId: (item: T) => string,
    buildTransactItem: (item: T) => TransactUpdateItem,
    operationName: string,
  ): Promise<BulkUpdateResult> {
    const failedControlIds: string[] = [];
    let successCount = 0;

    for (let i = 0; i < items.length; i += DYNAMODB_TRANSACTION_BATCH_SIZE) {
      const batch = items.slice(i, i + DYNAMODB_TRANSACTION_BATCH_SIZE);
      const outcome = await this.executeTransactionBatch(batch, getControlId, buildTransactItem, operationName, i);
      successCount += outcome.successCount;
      failedControlIds.push(...outcome.failedControlIds);
    }

    this.logger.info(`${operationName} completed`, { successCount, failedCount: failedControlIds.length });

    return { successCount, failedControlIds };
  }

  /**
   * Writes one batch, and on a cancellation re-drives only the items that were not themselves at
   * fault.
   *
   * A `TransactWrite` is all-or-nothing: one stale version fails the whole batch. Reporting
   * every control in the batch as failed hid which entry was at fault and made the
   * partial-success path (HTTP 207) unreachable within a batch.
   *
   * `TransactionCanceledException.CancellationReasons` is positionally aligned with
   * `TransactItems`. Items that were valid and rolled back only as collateral carry `None`. The
   * rest fall into two groups with opposite handling:
   *
   * - A permanent code (`ConditionalCheckFailed`, a lost version check) blames the item. It is
   *   reported in `failedControlIds` and removed before the remainder is re-driven, so each
   *   pass is strictly smaller.
   * - A transient code (`TransactionConflict`, throttling) does not: the item was fine, it
   *   simply collided with a concurrent writer or a capacity limit. It stays in the retry set,
   *   which is re-driven after a bounded exponential backoff. Only when the attempts run out
   *   is it reported as failed — and then the items that were merely rolled back alongside it
   *   get exactly one final write without it (see {@link writeCollateralOnce}), so a control is
   *   never reported failed only because a neighbour in its batch stayed contended.
   *
   * Without `CancellationReasons` (older mocks, an unexpected shape) it falls back to failing
   * the whole batch.
   */
  private async executeTransactionBatch<T>(
    batch: T[],
    getControlId: (item: T) => string,
    buildTransactItem: (item: T) => TransactUpdateItem,
    operationName: string,
    batchStart: number,
    transientAttempt = 0,
    pass = 1,
  ): Promise<{ successCount: number; failedControlIds: string[] }> {
    if (batch.length === 0) return { successCount: 0, failedControlIds: [] };

    const reasons = await this.sendBatch(batch, buildTransactItem, operationName, batchStart);
    if (reasons === 'written') return { successCount: batch.length, failedControlIds: [] };
    if (reasons === 'failed') return { successCount: 0, failedControlIds: batch.map(getControlId) };

    const { unretryable, contended, collateral } = classifyCancellation(batch, reasons);
    if (unretryable.length === 0 && contended.length === 0) {
      // A cancellation that blames no item at all is not something a retry can act on.
      this.logger.warn('Transaction cancelled but no item was blamed; failing the batch', {
        batchStart,
        batchSize: batch.length,
      });
      return { successCount: 0, failedControlIds: batch.map(getControlId) };
    }
    const unretryableIds = unretryable.map(getControlId);
    const survivors = [...contended, ...collateral];
    if (survivors.length === 0) {
      this.logger.warn('Transaction cancelled: every item lost its version check', {
        batchStart,
        batchSize: batch.length,
      });
      return { successCount: 0, failedControlIds: unretryableIds };
    }

    // The budget is spent on every pass that saw a transient code, whether or not a permanent
    // offender was also removed: the count is what bounds a persistently contended item, and
    // letting mixed passes skip it would let one such item ride along for up to a batch-size
    // worth of extra transactions.
    const nextTransientAttempt = contended.length > 0 ? transientAttempt + 1 : transientAttempt;
    const budgetExhausted = nextTransientAttempt > TRANSIENT_RETRY_MAX_ATTEMPTS;
    const capReached = pass >= MAX_PASSES_PER_BATCH;
    if (budgetExhausted || capReached) {
      // Either bound ends the re-drives the same way: the contended items are reported failed,
      // and the collateral items — never at fault themselves — get exactly one final write
      // without them (see writeCollateralOnce).
      const contendedIds = contended.map(getControlId);
      this.logger.warn(
        budgetExhausted
          ? 'Transaction still cancelled by transient conflicts after retries; failing the contended items'
          : 'Transaction cancelled on the last permitted pass; failing the contended items',
        {
          batchStart,
          batchSize: batch.length,
          attempts: transientAttempt,
          passes: pass,
          contendedControlIds: contendedIds,
          finalPassControlIds: collateral.map(getControlId),
        },
      );
      // One more pause first: the transient code may have been throttling, which removing the
      // contended items does nothing about.
      if (collateral.length > 0) {
        await this.sleeper.sleep(this.redriveDelayMs(contended.length, transientAttempt));
      }
      const finalPass = await this.writeCollateralOnce(
        collateral,
        getControlId,
        buildTransactItem,
        operationName,
        batchStart,
      );
      return {
        successCount: finalPass.successCount,
        failedControlIds: [...unretryableIds, ...contendedIds, ...finalPass.failedControlIds],
      };
    }

    this.logger.warn('Transaction cancelled; retrying the items that were not at fault', {
      batchStart,
      batchSize: batch.length,
      unretryableControlIds: unretryableIds,
      contendedCount: contended.length,
      retryCount: survivors.length,
      transientAttempt: nextTransientAttempt,
      pass: pass + 1,
    });
    await this.sleeper.sleep(this.redriveDelayMs(contended.length, transientAttempt));
    // Survivors keep their original batch order so the next pass's reasons line up the same way.
    const retried = await this.executeTransactionBatch(
      batch.filter((item) => survivors.includes(item)),
      getControlId,
      buildTransactItem,
      operationName,
      batchStart,
      nextTransientAttempt,
      pass + 1,
    );
    return {
      successCount: retried.successCount,
      failedControlIds: [...unretryableIds, ...retried.failedControlIds],
    };
  }

  /**
   * Backoff before re-driving a cancelled batch: exponential when a transient conflict is still
   * present (it may be throttling), a flat pause when only permanent offenders were removed.
   */
  private redriveDelayMs(contendedCount: number, transientAttempt: number): number {
    return contendedCount > 0 ? TRANSIENT_RETRY_BASE_DELAY_MS * 2 ** transientAttempt : PERMANENT_REDRIVE_DELAY_MS;
  }

  /**
   * Sends one `TransactWrite`. Returns `'written'` on success, the positional
   * `CancellationReasons` when the transaction was cancelled with a usable reason per item, one
   * synthetic transient reason per item for a request-level throttle or service error, and
   * `'failed'` for anything the caller cannot act on item by item (any other error, or a
   * cancellation with no per-item reasons).
   */
  private async sendBatch<T>(
    batch: T[],
    buildTransactItem: (item: T) => TransactUpdateItem,
    operationName: string,
    batchStart: number,
  ): Promise<'written' | 'failed' | CancellationReason[]> {
    try {
      const command: TransactWriteCommandInput = { TransactItems: batch.map(buildTransactItem) };
      await this.dynamoDBClient.send(new TransactWriteCommand(command));
      return 'written';
    } catch (error) {
      const errorName = (error as Error).name;
      if (REQUEST_LEVEL_THROTTLE_ERRORS.has(errorName)) {
        this.logger.warn(`${operationName} throttled; treating every item as contended`, {
          errorName,
          batchStart,
          batchSize: batch.length,
        });
        return batch.map(() => ({ Code: errorName }));
      }
      if (AMBIGUOUS_OUTCOME_ERRORS.has(errorName)) {
        // Not re-driven: the write may have landed, and the version conditions would then report
        // it as a permanent failure. The caller re-reads and decides.
        this.logger.error(
          `${operationName} failed with an unknown outcome; the items may or may not have been written`,
          {
            errorName,
            batchStart,
            batchSize: batch.length,
          },
        );
        return 'failed';
      }
      if (errorName !== 'TransactionCanceledException') {
        this.logger.error(`${operationName} failed`, {
          errorName,
          errorMessage: (error as Error).message,
          batchStart,
          batchSize: batch.length,
        });
        return 'failed';
      }
      const reasons = (error as { CancellationReasons?: CancellationReason[] }).CancellationReasons;
      if (reasons?.length !== batch.length) {
        this.logger.warn('Transaction cancelled without usable cancellation reasons; failing the batch', {
          batchStart,
          batchSize: batch.length,
        });
        return 'failed';
      }
      return reasons;
    }
  }

  /**
   * The single, final write for items that were only ever cancelled as collateral of a
   * contended neighbour. Deliberately not a re-drive: whatever this transaction refuses — a
   * per-item cancellation or a request-level throttle alike — is reported as not written, as-is. Recursing here instead would let a mixed cancellation (a newly
   * contended item plus fresh `None` collateral) run this pass again and again with the retry
   * budget already spent, back-to-back and bounded only by the batch size.
   */
  private async writeCollateralOnce<T>(
    collateral: T[],
    getControlId: (item: T) => string,
    buildTransactItem: (item: T) => TransactUpdateItem,
    operationName: string,
    batchStart: number,
  ): Promise<{ successCount: number; failedControlIds: string[] }> {
    if (collateral.length === 0) return { successCount: 0, failedControlIds: [] };
    const reasons = await this.sendBatch(collateral, buildTransactItem, operationName, batchStart);
    if (reasons === 'written') return { successCount: collateral.length, failedControlIds: [] };
    if (reasons !== 'failed') {
      // Whether this was a per-item cancellation or a request-level throttle, the outcome is the
      // same: the items were not written and no further attempt is made, because the retry
      // budget or pass cap that brought us here is what bounds the request. `failedControlIds`
      // means "not written"; the 207 response carries it and the caller may retry. Only the
      // wording differs, so the log says which it was.
      const throttled = reasons.every(
        (reason) => reason.Code !== undefined && REQUEST_LEVEL_THROTTLE_ERRORS.has(reason.Code),
      );
      this.logger.warn(
        throttled
          ? 'Final collateral pass was throttled; reporting its items as not written without another re-drive'
          : 'Final collateral pass was cancelled; reporting its items as not written without another re-drive',
        {
          batchStart,
          batchSize: collateral.length,
          codes: reasons.map((reason) => reason.Code ?? 'None'),
        },
      );
    }
    return { successCount: 0, failedControlIds: collateral.map(getControlId) };
  }

  /**
   * Retrieves all control IDs and their current versions from DynamoDB.
   * Uses a projected scan to minimize data transfer.
   * Defaults version to 1 if not present on the item.
   */
  private async getAllControlVersions(): Promise<ControlVersionInfo[]> {
    return this.findAllWithTransform(
      (item) => {
        const controlId = item.controlId;
        if (typeof controlId !== 'string') {
          throw new TypeError(`Expected controlId to be a string, got ${typeof controlId}`);
        }
        return {
          controlId,
          version: (typeof item.version === 'number' ? item.version : undefined) || 1,
        };
      },
      { ProjectionExpression: 'controlId, version' },
    );
  }

  /**
   * Builds a DynamoDB TransactWrite item that adds a filter to a control's filter set.
   * Uses ADD operation to append to the Set (idempotent if filter already exists).
   * Includes optimistic locking via version condition check to prevent concurrent modification conflicts.
   */
  private buildAddFilterTransactItem(
    controlId: string,
    version: number,
    filterId: string,
    modifiedBy: string,
    lastModified: string,
  ): TransactUpdateItem {
    // If the version attribute does not exist, it is treated as 0 to allow the update to proceed.
    const conditionExpression =
      'attribute_exists(controlId) AND (version = :expectedVersion OR attribute_not_exists(version))';

    return {
      Update: {
        TableName: this.tableName,
        Key: { controlId },
        UpdateExpression:
          'ADD filters :filterId SET version = if_not_exists(version, :zero) + :inc, lastModified = :lastModified, modifiedBy = :modifiedBy',
        ConditionExpression: conditionExpression,
        ExpressionAttributeValues: {
          ':filterId': new Set([filterId]),
          ':inc': 1,
          ':zero': 1,
          ':expectedVersion': version,
          ':lastModified': lastModified,
          ':modifiedBy': modifiedBy,
        },
      },
    };
  }

  /**
   * Builds a DynamoDB TransactWrite item that removes a filter from a control's filter set.
   * Uses DELETE operation to remove from the Set (idempotent if filter doesn't exist).
   * Includes optimistic locking via version condition check to prevent concurrent modification conflicts.
   */
  private buildRemoveFilterTransactItem(
    controlId: string,
    version: number,
    filterId: string,
    modifiedBy: string,
    lastModified: string,
  ): TransactUpdateItem {
    // If the version attribute does not exist, it is treated as 0 to allow the update to proceed.
    const conditionExpression =
      'attribute_exists(controlId) AND (version = :expectedVersion OR attribute_not_exists(version))';

    return {
      Update: {
        TableName: this.tableName,
        Key: { controlId },
        UpdateExpression:
          'DELETE filters :filterId SET version = if_not_exists(version, :zero) + :inc, lastModified = :lastModified, modifiedBy = :modifiedBy',
        ConditionExpression: conditionExpression,
        ExpressionAttributeValues: {
          ':filterId': new Set([filterId]),
          ':inc': 1,
          ':zero': 1,
          ':expectedVersion': version,
          ':lastModified': lastModified,
          ':modifiedBy': modifiedBy,
        },
      },
    };
  }

  /**
   * Builds a DynamoDB TransactWrite item that updates all mutable fields of a control.
   * Handles filters conditionally: sets the filters attribute if present, removes it if empty.
   * Includes optimistic locking via version condition check to prevent concurrent modification conflicts.
   */
  private buildUpdateTransactItem(
    control: SecurityControl,
    modifiedBy: string,
    lastModified: string,
  ): TransactUpdateItem {
    const hasFilters = control.filters && control.filters.length > 0;
    const baseExpression =
      'SET automatedRemediationEnabled = :enabled, ' +
      'filterMode = :filterMode, ' +
      'description = :description, ' +
      'version = if_not_exists(version, :zero) + :inc, ' +
      'lastModified = :lastModified, ' +
      'modifiedBy = :modifiedBy';

    const hasRollbackEnabled = control.rollbackEnabled !== undefined;

    // REMOVE is idempotent - if filters attribute doesn't exist, it's a no-op
    const updateExpression =
      baseExpression +
      (hasRollbackEnabled ? ', rollbackEnabled = :rollbackEnabled' : '') +
      (hasFilters ? ', filters = :filters' : ' REMOVE filters');

    // If the version attribute does not exist, it is treated as 0 to allow the update to proceed.
    const conditionExpression =
      'attribute_exists(controlId) AND (version = :expectedVersion OR attribute_not_exists(version))';

    const expressionAttributeValues: Record<string, unknown> = {
      ':enabled': control.automatedRemediationEnabled,
      ':filterMode': control.filterMode,
      ':description': control.description,
      ':inc': 1,
      ':zero': 1,
      ':expectedVersion': control.version,
      ':lastModified': lastModified,
      ':modifiedBy': modifiedBy,
    };

    if (hasRollbackEnabled) {
      expressionAttributeValues[':rollbackEnabled'] = control.rollbackEnabled;
    }

    if (hasFilters) {
      expressionAttributeValues[':filters'] = new Set(control.filters);
    }

    return {
      Update: {
        TableName: this.tableName,
        Key: { controlId: control.controlId },
        UpdateExpression: updateExpression,
        ConditionExpression: conditionExpression,
        ExpressionAttributeValues: expressionAttributeValues,
      },
    };
  }

  private transformToSecurityControl(item: SecurityControlDynamoDBItem): SecurityControl {
    this.logger.debug('Transforming DynamoDB item to SecurityControl object', { item });

    return {
      controlId: item.controlId,
      description: item.description,
      automatedRemediationEnabled: item.automatedRemediationEnabled,
      rollbackEnabled: item.rollbackEnabled,
      filters: toStringArray(item.filters),
      filterMode: (item.filterMode as 'include' | 'exclude') || 'include',
      version: item.version,
      lastModified: item.lastModified || '',
      modifiedBy: item.modifiedBy || '',
      source: item.source ?? 'builtin',
    };
  }
}
