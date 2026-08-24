// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import {
  FindingId,
  FindingTableItem,
  PaginationToken,
  remediationStatus,
  SearchCriteria,
  SearchFilter,
  SearchResult,
} from '@asr/data-models';
import { ConditionalCheckFailedException } from '@aws-sdk/client-dynamodb';
import { unmarshall } from '@aws-sdk/util-dynamodb';
import {
  DeleteCommand,
  DeleteCommandInput,
  DynamoDBDocumentClient,
  PutCommand,
  PutCommandInput,
  QueryCommand,
  QueryCommandInput,
  UpdateCommand,
  UpdateCommandInput,
} from '@aws-sdk/lib-dynamodb';
import { Sleeper } from '../utils/sleeper';
import { ErrorUtils } from '../utils/errorUtils';
import {
  getControlIdFromFindingId,
  partitionFindingIdsByKeyDerivability,
  sanitizeControlId,
} from '../utils/findingUtils';
import { AbstractRepository, DynamoDBKey, ExpressionAttributeValues, QueryResult } from './abstractRepository';

const FINDINGS_PAGE_SIZE = 50;

/**
 * Thrown when a repository method is called with invalid arguments. This is an
 * HTTP-agnostic domain error; the API layer is responsible for translating it
 * into an appropriate response (e.g. a 400) when surfaced through an endpoint.
 */
export class ValidationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ValidationError';
  }
}

export interface StampRemediationDueByResult {
  configIdsUpdated: boolean;
  dueByUpdated: boolean;
}

/**
 * Result of {@link FindingRepository.findByFindingIds}.
 *
 * `nonDerivableIds` are ids whose findings-table partition key could not be derived from the id, so
 * they were never queried. Callers must not treat them as "not found". See ADR 0010.
 */
export interface FindByFindingIdsResult {
  findings: FindingTableItem[];
  nonDerivableIds: FindingId[];
}

export type OverdueFindingProjection = Pick<
  FindingTableItem,
  'findingType' | 'findingId' | 'remediationStatus' | 'accountId' | 'resourceId' | 'creationTime'
> & {
  suppressed?: boolean;
  remediationDueBy: string;
  enforcementConfigIds?: Set<string>;
  FINDING_CONSTANT: string;
};

// DynamoDB-specific query parameters
interface DynamoDBQueryParams {
  indexName: string;
  partitionKeyName: string;
  partitionKeyValue: string;
  filterExpression?: string;
  expressionAttributeNames?: Record<string, string>;
  expressionAttributeValues?: ExpressionAttributeValues;
}

export class FindingRepository extends AbstractRepository<FindingTableItem> {
  private cachedItem: FindingTableItem | null = null;

  protected readonly partitionKeyName = 'findingType';
  protected readonly sortKeyName = 'findingId';

  // GSI key structure mapping - defines the expected key fields for each index
  protected override readonly GSI_KEY_STRUCTURES: Record<string, string[]> = {
    'allFindings-securityHubUpdatedAtTime-GSI': [
      'findingId',
      'FINDING_CONSTANT',
      'securityHubUpdatedAtTime#findingId',
      'findingType',
    ],
    'allFindings-severityNormalized-GSI': [
      'findingId',
      'FINDING_CONSTANT',
      'severityNormalized#securityHubUpdatedAtTime#findingId',
      'findingType',
    ],
    'accountId-securityHubUpdatedAtTime-GSI': [
      'findingId',
      'accountId',
      'securityHubUpdatedAtTime#findingId',
      'findingType',
    ],
    'resourceId-securityHubUpdatedAtTime-GSI': [
      'findingId',
      'resourceId',
      'securityHubUpdatedAtTime#findingId',
      'findingType',
    ],
    'findingId-GSI': ['findingId', 'FINDING_CONSTANT', 'securityHubUpdatedAtTime#findingId', 'findingType'],
    'securityHubUpdatedAtTime-findingId-LSI': ['findingType', 'securityHubUpdatedAtTime#findingId', 'findingId'],
    'remediationDueBy-GSI': ['FINDING_CONSTANT', 'remediationDueBy'],
  };

  constructor(principal: string, tableName: string, dynamoDBClient: DynamoDBDocumentClient, sleeper?: Sleeper) {
    super(principal, tableName, dynamoDBClient, sleeper);
  }

  /** Updates finding only if securityHubUpdatedAtTime is newer than existing record or record doesn't exist */
  async putIfNewer(findingItem: FindingTableItem): Promise<'SUCCESS' | 'FAILED'> {
    try {
      // firstDetectedTime is Security Hub's first-observed time, which is stable across
      // updates. Only set it when the incoming finding carries it, so a finding that was
      // created before this attribute existed gets backfilled on its next update without
      // ever overwriting a present value with undefined.
      const setsFirstDetectedTime = findingItem.firstDetectedTime !== undefined;
      // Metric-enrichment flags are only present when the ingestion path evaluated
      // notification configs; other write paths (e.g. API replay) omit them, so they are
      // conditionally appended to avoid writing undefined and clobbering existing values.
      const setsNotificationsEnabled = findingItem.hasFindingNotificationsEnabled !== undefined;
      const setsDeadlineConfigured = findingItem.hasFindingRemediationDeadlineConfigured !== undefined;

      const updateExpression =
        'SET findingDescription = :desc, accountId = :accountId, suppressed = :suppressed, lastUpdatedBy = :lastUpdatedBy, resourceId = :resourceId, resourceType = :resourceType, resourceTypeNormalized = :resourceTypeNormalized, severity = :severity, severityNormalized = :severityNormalized, #region = :region, securityHubUpdatedAtTime = :secHubUpdated, lastUpdatedTime = :lastUpdated, #lsiSortKey = :lsiSortKey, #severitySortKey = :severitySortKey, findingJSON = :findingJson, FINDING_CONSTANT = :findingConstant, remediationStatus = :remediationStatus' +
        (setsFirstDetectedTime ? ', firstDetectedTime = :firstDetectedTime' : '') +
        (setsNotificationsEnabled ? ', hasFindingNotificationsEnabled = :hasFindingNotificationsEnabled' : '') +
        (setsDeadlineConfigured
          ? ', hasFindingRemediationDeadlineConfigured = :hasFindingRemediationDeadlineConfigured'
          : '');

      const expressionAttributeValues: ExpressionAttributeValues = {
        ':desc': findingItem.findingDescription,
        ':accountId': findingItem.accountId,
        ':resourceId': findingItem.resourceId,
        ':resourceType': findingItem.resourceType,
        ':resourceTypeNormalized': findingItem.resourceTypeNormalized,
        ':severity': findingItem.severity,
        ':severityNormalized': findingItem.severityNormalized,
        ':region': findingItem.region,
        ':secHubUpdated': findingItem.securityHubUpdatedAtTime,
        ':lastUpdated': findingItem.lastUpdatedTime,
        ':findingJson': findingItem.findingJSON,
        ':lsiSortKey': findingItem['securityHubUpdatedAtTime#findingId'],
        ':severitySortKey': findingItem['severityNormalized#securityHubUpdatedAtTime#findingId'],
        ':findingConstant': findingItem.FINDING_CONSTANT,
        ':suppressed': findingItem.suppressed,
        ':remediationStatus': findingItem.remediationStatus,
        ':lastUpdatedBy': this.principal,
        ...(setsFirstDetectedTime && { ':firstDetectedTime': findingItem.firstDetectedTime }),
        ...(setsNotificationsEnabled && {
          ':hasFindingNotificationsEnabled': findingItem.hasFindingNotificationsEnabled,
        }),
        ...(setsDeadlineConfigured && {
          ':hasFindingRemediationDeadlineConfigured': findingItem.hasFindingRemediationDeadlineConfigured,
        }),
      };

      const command = new UpdateCommand({
        TableName: this.tableName,
        Key: {
          [this.partitionKeyName]: findingItem.findingType,
          [this.sortKeyName]: findingItem.findingId,
        },
        UpdateExpression: updateExpression,
        ConditionExpression:
          'securityHubUpdatedAtTime < :secHubUpdated OR attribute_not_exists(securityHubUpdatedAtTime)',
        ExpressionAttributeNames: {
          '#region': 'region',
          '#lsiSortKey': 'securityHubUpdatedAtTime#findingId',
          '#severitySortKey': 'severityNormalized#securityHubUpdatedAtTime#findingId',
        },
        ExpressionAttributeValues: expressionAttributeValues,
      } satisfies UpdateCommandInput);

      await this.dynamoDBClient.send(command);
      this.logger.debug('Updated finding', { findingType: findingItem.findingType, findingId: findingItem.findingId });
      return 'SUCCESS';
    } catch (error) {
      if (error instanceof ConditionalCheckFailedException) {
        this.logger.debug(
          `Findings table already has more recent update for finding ${findingItem.findingId}, hence skipping current data sync.`,
          {
            securityHubUpdatedAt: findingItem.securityHubUpdatedAtTime,
          },
        );
        return 'FAILED';
      } else {
        throw error;
      }
    }
  }

  async createIfNotExists(findingItem: FindingTableItem): Promise<'SUCCESS' | 'FAILED'> {
    try {
      const command = new PutCommand({
        TableName: this.tableName,
        ConditionExpression: 'attribute_not_exists(findingId)',
        Item: { ...findingItem, lastUpdatedBy: this.principal },
      } satisfies PutCommandInput);

      await this.dynamoDBClient.send(command);
      this.logger.debug('Created finding', { findingType: findingItem.findingType, findingId: findingItem.findingId });
      return 'SUCCESS';
    } catch (error) {
      if (error instanceof ConditionalCheckFailedException) {
        this.logger.debug(
          `attribute_not_exists(${findingItem.findingId}) condition check failed, indicating the finding has already been created. Hence, skipping creation.`,
        );
        return 'FAILED';
      } else {
        throw error;
      }
    }
  }

  async deleteIfExists(findingId: string, findingType: string): Promise<'SUCCESS' | 'FAILED'> {
    try {
      const command = new DeleteCommand({
        TableName: this.tableName,
        Key: {
          [this.partitionKeyName]: findingType,
          [this.sortKeyName]: findingId,
        },
        ConditionExpression: 'attribute_exists(findingId)',
      } satisfies DeleteCommandInput);

      await this.dynamoDBClient.send(command);
      this.logger.debug('Deleted finding', { findingType, findingId });
      return 'SUCCESS';
    } catch (error) {
      if (error instanceof ConditionalCheckFailedException) {
        this.logger.debug(`Finding ${findingId} does not exist, hence skipping deletion.`);
        return 'FAILED';
      } else {
        throw error;
      }
    }
  }

  /**
   * Guard the DynamoDB key components used by the stamp/clear operations.
   * controlId is the partition key and findingId is the sort key, so an empty
   * value would either be rejected by DynamoDB or address the wrong item.
   */
  private assertValidFindingKey(findingId: string, controlId: string): void {
    if (!findingId || findingId.trim().length === 0) {
      throw new ValidationError('findingId must be a non-empty string');
    }
    if (!controlId || controlId.trim().length === 0) {
      throw new ValidationError('controlId must be a non-empty string');
    }
  }

  /**
   * Guard remediationDueBy, which is written as the `remediationDueBy-GSI` sort
   * key. An empty value would corrupt GSI ordering and the conditional compare.
   */
  private assertNonEmptyRemediationDueBy(remediationDueBy: string): void {
    if (!remediationDueBy || remediationDueBy.trim().length === 0) {
      throw new ValidationError('remediationDueBy must be a non-empty string');
    }
  }

  /**
   * Atomically records an auto-remediation attempt: increments
   * `remediationAttempts` by one and sets `lastRemediationAttemptTime`. Uses an
   * atomic DynamoDB `ADD` so concurrent pre-processor invocations for the same
   * finding cannot lose increments (no read-modify-write race). Called each time
   * the pre-processor launches a remediation; read back by the retry-cap gate to
   * bound and space out retries on a repeatedly-failing finding.
   */
  async recordRemediationAttempt(findingId: string, controlId: string, attemptTime: string): Promise<void> {
    this.assertValidFindingKey(findingId, controlId);
    const command = new UpdateCommand({
      TableName: this.tableName,
      Key: {
        [this.partitionKeyName]: controlId,
        [this.sortKeyName]: findingId,
      },
      UpdateExpression: 'SET lastRemediationAttemptTime = :now ADD remediationAttempts :one',
      ExpressionAttributeValues: {
        ':now': attemptTime,
        ':one': 1,
      },
    } satisfies UpdateCommandInput);

    await this.dynamoDBClient.send(command);
    this.logger.debug('Recorded remediation attempt', { findingId, controlId });
  }

  async stampRemediationDueBy(
    findingId: string,
    controlId: string,
    remediationDueBy: string,
    configIds: string[],
  ): Promise<StampRemediationDueByResult> {
    this.assertValidFindingKey(findingId, controlId);
    this.assertNonEmptyRemediationDueBy(remediationDueBy);
    if (configIds.length === 0) {
      throw new ValidationError('configIds must contain at least one element');
    }

    const key = {
      [this.partitionKeyName]: controlId,
      [this.sortKeyName]: findingId,
    };

    // Two-call design: if call 1 succeeds but call 2 throws (non-conditional error),
    // enforcementConfigIds is written but remediationDueBy is not. This is safe because
    // ADD is idempotent — a retry of the entire operation will converge to the correct state.

    // Call 1 (unconditional): ADD enforcementConfigIds — idempotent, always merges
    const addConfigIdsCommand = new UpdateCommand({
      TableName: this.tableName,
      Key: key,
      UpdateExpression: 'ADD enforcementConfigIds :configIds',
      ExpressionAttributeValues: {
        ':configIds': new Set(configIds),
      },
    } satisfies UpdateCommandInput);

    await this.dynamoDBClient.send(addConfigIdsCommand);
    this.logger.debug('Added enforcement config IDs to finding', { findingId, controlId, configIds });

    // Call 2 (conditional): SET remediationDueBy only if earlier than existing value
    const dueByUpdated = await this.tryUpdateRemediationDueBy(key, controlId, findingId, remediationDueBy);

    return { configIdsUpdated: true, dueByUpdated };
  }

  /**
   * Conditionally SET remediationDueBy only when it is earlier than the existing value.
   * Returns true if the value was updated, false if an earlier-or-equal value already exists.
   */
  private async tryUpdateRemediationDueBy(
    key: DynamoDBKey,
    controlId: string,
    findingId: string,
    remediationDueBy: string,
  ): Promise<boolean> {
    try {
      const setDueByCommand = new UpdateCommand({
        TableName: this.tableName,
        Key: key,
        UpdateExpression: 'SET remediationDueBy = :newValue',
        ConditionExpression: 'attribute_not_exists(remediationDueBy) OR remediationDueBy > :newValue',
        ExpressionAttributeValues: {
          ':newValue': remediationDueBy,
        },
      } satisfies UpdateCommandInput);

      await this.dynamoDBClient.send(setDueByCommand);
      this.logger.debug('Stamped remediationDueBy on finding', { findingId, controlId, remediationDueBy });
      return true;
    } catch (error) {
      if (error instanceof ConditionalCheckFailedException) {
        this.logger.debug('Existing remediationDueBy is already earlier or equal, skipping update', {
          findingId,
          controlId,
          attemptedValue: remediationDueBy,
        });
        return false;
      }
      throw error;
    }
  }

  async exists(findingId: string, findingType: string): Promise<boolean> {
    if (this.cachedItem && this.cachedItem.findingId === findingId) return true;

    const item = await this.findByIdWithCache(findingId, findingType);
    return !!item;
  }

  async findByIdWithCache(findingId: string, findingType: string): Promise<FindingTableItem | undefined> {
    if (this.cachedItem && this.cachedItem.findingId === findingId) return this.cachedItem;

    const item = await this.findById(findingType, findingId);
    if (item) this.cachedItem = item;
    return item;
  }

  /**
   * Atomically acquire the rollback lock on a finding by transitioning its
   * remediationStatus to ROLLBACK_IN_PROGRESS. The conditional write is the
   * double-rollback guard: only one concurrent caller can win.
   *
   * Acquisition succeeds when the finding is in a rollback-initiable state
   * (SUCCESS — original containment succeeded, or ROLLBACK_FAILED — retry a
   * previously failed rollback) or when a prior ROLLBACK_IN_PROGRESS lock has
   * gone stale (rollbackStartedAt older than `staleBefore`).
   *
   * Returns:
   *   'ACQUIRED'    — this caller now holds the lock.
   *   'IN_PROGRESS' — a fresh rollback is already running; reject the request.
   *   'INELIGIBLE'  — the finding is not in a state from which rollback may start.
   */
  async tryAcquireRollbackLock(
    findingType: string,
    findingId: FindingId,
    now: string,
    staleBefore: string,
  ): Promise<'ACQUIRED' | 'IN_PROGRESS' | 'INELIGIBLE'> {
    try {
      const command = new UpdateCommand({
        TableName: this.tableName,
        Key: {
          [this.partitionKeyName]: findingType,
          [this.sortKeyName]: findingId,
        },
        UpdateExpression:
          'SET remediationStatus = :inProgress, rollbackStartedAt = :now, lastUpdatedTime = :now, lastUpdatedBy = :lastUpdatedBy',
        ConditionExpression:
          'remediationStatus IN (:success, :rollbackFailed) OR (remediationStatus = :inProgress AND (attribute_not_exists(rollbackStartedAt) OR rollbackStartedAt < :staleBefore))',
        ExpressionAttributeValues: {
          ':inProgress': 'ROLLBACK_IN_PROGRESS',
          ':success': 'SUCCESS',
          ':rollbackFailed': 'ROLLBACK_FAILED',
          ':now': now,
          ':staleBefore': staleBefore,
          ':lastUpdatedBy': this.principal,
        },
        ReturnValuesOnConditionCheckFailure: 'ALL_OLD',
      } satisfies UpdateCommandInput);

      await this.dynamoDBClient.send(command);
      this.logger.debug('Acquired rollback lock', { findingType, findingId });
      return 'ACQUIRED';
    } catch (error) {
      if (!(error instanceof ConditionalCheckFailedException)) {
        throw error;
      }
      // The condition failed: either a fresh rollback is in progress, or the
      // finding is in a non-initiable state. Read the item state returned
      // atomically with the failure (ReturnValuesOnConditionCheckFailure)
      // rather than a second findById, so a concurrent status change between
      // the failed write and a follow-up read cannot misreport the reason.
      const unmarshalledItem = error.Item ? unmarshall(error.Item) : undefined;
      const failedStatus =
        typeof unmarshalledItem?.remediationStatus === 'string' ? unmarshalledItem.remediationStatus : undefined;
      if (failedStatus === 'ROLLBACK_IN_PROGRESS') {
        this.logger.debug('Rollback already in progress', { findingType, findingId });
        return 'IN_PROGRESS';
      }
      this.logger.debug('Finding not eligible for rollback', {
        findingType,
        findingId,
        remediationStatus: failedStatus,
      });
      return 'INELIGIBLE';
    }
  }

  /**
   * Find multiple findings by FindingIds using batch get operation.
   *
   * Returns `nonDerivableIds` alongside the findings: those ids carry no derivable partition key,
   * so they were never queried. That is materially different from an id that was queried and not
   * found, and callers that conflate the two report the wrong reason. Such ids need an explicit
   * `{ findingId, findingType }` key or the findingId GSI instead. See ADR 0010.
   *
   * Preserves the historical public contract for `findings`: if the batch operation fails (either
   * because DynamoDB throws or because retries are exhausted with unprocessed keys remaining), this
   * method logs the problem and returns the partial results we did obtain — up to and
   * including an empty list. Callers should treat `findings` as "best-effort, may be incomplete"
   * rather than "guaranteed complete".
   */
  async findByFindingIds(findingIds: FindingId[]): Promise<FindByFindingIdsResult> {
    if (findingIds.length === 0) {
      return { findings: [], nonDerivableIds: [] };
    }

    // Deduplicate before BatchGetItem: DynamoDB rejects duplicate keys in a single request
    // with ValidationException, and callers can legitimately pass duplicates when aggregating
    // from multiple sources (e.g., merged overflow batches, concatenated finding and
    // remediation ID lists).
    const uniqueFindingIds = [...new Set(findingIds)];

    // The findings table partition key is named `findingType`. For consolidated Security Hub rows
    // it holds the prefixed control id (e.g. security-control/AutoScaling.1), for unconsolidated
    // rows the standard-and-version path, and for multi-service rows the remediation id (e.g.
    // GuardDuty.IAMUser). It is derived from the findingId ARN, which is only possible for ids that
    // encode it — the rest are surfaced to the caller as nonDerivableIds. See ADR 0010.
    const { keys: findingItemKeys, nonDerivableIds } = partitionFindingIdsByKeyDerivability(uniqueFindingIds);

    if (nonDerivableIds.length > 0) {
      this.logger.warn('Some findingIds have no derivable partition key and were not queried', {
        totalCount: findingIds.length,
        uniqueCount: uniqueFindingIds.length,
        nonDerivableCount: nonDerivableIds.length,
        validCount: findingItemKeys.length,
      });
    }

    if (findingItemKeys.length === 0) {
      return { findings: [], nonDerivableIds };
    }

    try {
      const results = await this.batchGetByIds(findingItemKeys);
      this.logger.debug('Batch get findings completed', {
        requestedCount: findingIds.length,
        validCount: findingItemKeys.length,
        retrievedCount: results.length,
      });
      return { findings: results, nonDerivableIds };
    } catch (error) {
      this.logger.error('Error finding by FindingIds', { findingIds, error });
      return { findings: [], nonDerivableIds };
    }
  }

  /**
   * Batch get findings using DynamoDB keys. Returns the items that were successfully
   * fetched; keys that could not be retrieved after exhausting retries are logged and
   * skipped so callers continue to see partial results.
   */
  private async batchGetByIds(
    findingItemKeys: Array<{ findingId: string; findingType: string }>,
  ): Promise<FindingTableItem[]> {
    if (findingItemKeys.length === 0) {
      return [];
    }

    const keys = findingItemKeys.map(({ findingId, findingType }) => ({
      [this.partitionKeyName]: findingType,
      [this.sortKeyName]: findingId,
    }));

    const { items } = await this.batchGetWithRetry<FindingTableItem>(keys);

    return items;
  }

  /**
   * Batch-get findings by explicit (findingType, findingId) key pairs. Unlike findByFindingIds,
   * this does NOT re-derive findingType from the findingId — callers that already know the
   * partition key (e.g. from a GSI projection) pass it directly, avoiding a fragile ARN regex
   * round-trip. Returns best-effort partial results: keys that could not be retrieved after
   * BatchGetItem retries are omitted, so callers should treat the list as "may be incomplete".
   */
  async findByKeys(keys: Array<{ findingType: string; findingId: string }>): Promise<FindingTableItem[]> {
    if (keys.length === 0) {
      return [];
    }

    try {
      return await this.batchGetByIds(keys);
    } catch (error) {
      this.logger.error('Error batch-getting findings by keys', {
        keyCount: keys.length,
        error: ErrorUtils.formatErrorMessage(error),
      });
      return [];
    }
  }

  async clearRemediationDueBy(findingId: string, controlId: string): Promise<void> {
    this.assertValidFindingKey(findingId, controlId);
    const command = new UpdateCommand({
      TableName: this.tableName,
      Key: {
        [this.partitionKeyName]: controlId,
        [this.sortKeyName]: findingId,
      },
      UpdateExpression: 'REMOVE remediationDueBy, enforcementConfigIds',
    } satisfies UpdateCommandInput);

    await this.dynamoDBClient.send(command);
    this.logger.debug('Cleared remediationDueBy and enforcementConfigIds', { findingId, controlId });
  }

  async forceStampRemediationDueBy(
    findingId: string,
    controlId: string,
    remediationDueBy: string,
    configIds: string[],
  ): Promise<void> {
    this.assertValidFindingKey(findingId, controlId);
    this.assertNonEmptyRemediationDueBy(remediationDueBy);
    if (configIds.length === 0) {
      throw new ValidationError('configIds must contain at least one element');
    }

    const command = new UpdateCommand({
      TableName: this.tableName,
      Key: {
        [this.partitionKeyName]: controlId,
        [this.sortKeyName]: findingId,
      },
      UpdateExpression: 'SET remediationDueBy = :remediationDueBy, enforcementConfigIds = :configIds',
      ExpressionAttributeValues: {
        ':remediationDueBy': remediationDueBy,
        ':configIds': new Set(configIds),
      },
    } satisfies UpdateCommandInput);

    await this.dynamoDBClient.send(command);
    this.logger.debug('Force-stamped remediationDueBy and enforcementConfigIds', {
      findingId,
      controlId,
      remediationDueBy,
    });
  }

  async queryFindingsByDueBy(
    currentTime: string,
    options?: { exclusiveStartKey?: DynamoDBKey; limit?: number },
  ): Promise<QueryResult<OverdueFindingProjection>> {
    const params: QueryCommandInput = {
      TableName: this.tableName,
      IndexName: 'remediationDueBy-GSI',
      KeyConditionExpression: 'FINDING_CONSTANT = :pk AND remediationDueBy < :currentTime',
      ExpressionAttributeValues: {
        ':pk': 'finding',
        ':currentTime': currentTime,
      },
      ScanIndexForward: true,
      // Always bound the page: default to FINDINGS_PAGE_SIZE when the caller
      // omits a limit, and clamp any caller-supplied limit to that maximum, so a
      // single Query cannot pull up to DynamoDB's 1MB response cap into memory.
      Limit: Math.min(options?.limit ?? FINDINGS_PAGE_SIZE, FINDINGS_PAGE_SIZE),
      ...(options?.exclusiveStartKey && { ExclusiveStartKey: options.exclusiveStartKey }),
    };

    const response = await this.dynamoDBClient.send(new QueryCommand(params));

    this.logger.debug('queryFindingsByDueBy result', {
      itemCount: response.Items?.length ?? 0,
      hasMorePages: !!response.LastEvaluatedKey,
    });

    // Cast is safe: the GSI INCLUDE projection (defined in CDK and dynamodbSetup.ts) guarantees
    // exactly the fields declared in OverdueFindingProjection are returned.
    return {
      items: (response.Items ?? []) as OverdueFindingProjection[],
      lastEvaluatedKey: response.LastEvaluatedKey,
    };
  }

  /**
   * Enumerates every currently-stamped finding via the sparse `remediationDueBy-GSI`. Unlike
   * {@link queryFindingsByDueBy}, this applies no `remediationDueBy` sort-key condition, so it
   * returns all stamped findings — both overdue and not-yet-overdue — rather than only the overdue
   * subset. Used by reconciliation to walk every stamped finding when a match-all configuration
   * (empty `controlIds`) changes, where no per-control query can target the affected findings.
   *
   * Results are sorted ascending by `remediationDueBy` and paginated with `limit` +
   * `exclusiveStartKey`, matching {@link queryFindingsByDueBy}. The lightweight GSI projection
   * supplies `enforcementConfigIds` and `creationTime`, so reconciliation needs no base-table
   * BatchGetItem or `findingJSON` decompression on this path.
   */
  async queryAllStampedFindings(options?: {
    exclusiveStartKey?: DynamoDBKey;
    limit?: number;
  }): Promise<QueryResult<OverdueFindingProjection>> {
    const params: QueryCommandInput = {
      TableName: this.tableName,
      IndexName: 'remediationDueBy-GSI',
      KeyConditionExpression: 'FINDING_CONSTANT = :pk',
      ExpressionAttributeValues: {
        ':pk': 'finding',
      },
      ScanIndexForward: true,
      ...(options?.limit && { Limit: options.limit }),
      ...(options?.exclusiveStartKey && { ExclusiveStartKey: options.exclusiveStartKey }),
    };

    const response = await this.dynamoDBClient.send(new QueryCommand(params));

    this.logger.debug('queryAllStampedFindings result', {
      itemCount: response.Items?.length ?? 0,
      hasMorePages: !!response.LastEvaluatedKey,
    });

    // Cast is safe: the GSI INCLUDE projection (defined in CDK and dynamodbSetup.ts) guarantees
    // exactly the fields declared in OverdueFindingProjection are returned.
    return {
      items: (response.Items ?? []) as OverdueFindingProjection[],
      lastEvaluatedKey: response.LastEvaluatedKey,
    };
  }

  /**
   * Queries the main table for all findings under a single control ID (the `findingType` partition
   * key), one page at a time. Used by reconciliation to walk the findings of each control a changed
   * notification configuration targets. An optional `remediationStatusEquals` applies a
   * server-side FilterExpression so callers can restrict the page to, for example, `NOT_STARTED`
   * findings. Pagination follows the same `exclusiveStartKey`/`lastEvaluatedKey` contract as the
   * other query methods.
   */
  async queryByControlId(
    controlId: string,
    options?: { exclusiveStartKey?: DynamoDBKey; limit?: number; remediationStatusEquals?: remediationStatus },
  ): Promise<QueryResult<FindingTableItem>> {
    const params: QueryCommandInput = {
      TableName: this.tableName,
      KeyConditionExpression: '#partitionKey = :controlId',
      ExpressionAttributeNames: {
        '#partitionKey': this.partitionKeyName,
        ...(options?.remediationStatusEquals && { '#remediationStatus': 'remediationStatus' }),
      },
      ExpressionAttributeValues: {
        ':controlId': controlId,
        ...(options?.remediationStatusEquals && { ':remediationStatus': options.remediationStatusEquals }),
      },
      ...(options?.remediationStatusEquals && { FilterExpression: '#remediationStatus = :remediationStatus' }),
      ...(options?.limit && { Limit: options.limit }),
      ...(options?.exclusiveStartKey && { ExclusiveStartKey: options.exclusiveStartKey }),
    };

    const response = await this.dynamoDBClient.send(new QueryCommand(params));

    this.logger.debug('queryByControlId result', {
      controlId,
      itemCount: response.Items?.length ?? 0,
      scannedCount: response.ScannedCount ?? 0,
      hasMorePages: !!response.LastEvaluatedKey,
    });

    return {
      items: (response.Items ?? []) as FindingTableItem[],
      lastEvaluatedKey: response.LastEvaluatedKey,
      scannedCount: response.ScannedCount,
    };
  }

  /**
   * Override queryIndexPK to use the correct GSI partition key name
   * instead of the main table's partition key name
   */
  override async queryIndexPK({
    indexName,
    partitionKeyName,
    partitionKeyValue,
    scanIndexForward = true,
    limit,
    exclusiveStartKey,
  }: {
    indexName: string;
    partitionKeyName: string;
    partitionKeyValue: string;
    scanIndexForward?: boolean;
    limit?: number;
    exclusiveStartKey?: DynamoDBKey;
  }): Promise<QueryResult<FindingTableItem>> {
    return await super.queryIndexPK({
      indexName,
      partitionKeyName,
      partitionKeyValue,
      scanIndexForward,
      limit,
      exclusiveStartKey,
    });
  }

  /**
   * Query an index with additional FilterExpression for optimized filtering
   */
  override async queryIndexWithFilter({
    indexName,
    partitionKeyName,
    partitionKeyValue,
    scanIndexForward = true,
    limit,
    exclusiveStartKey,
    filterExpression,
    expressionAttributeNames,
    expressionAttributeValues,
  }: {
    indexName: string;
    partitionKeyName: string;
    partitionKeyValue: string;
    scanIndexForward?: boolean;
    limit?: number;
    exclusiveStartKey?: DynamoDBKey;
    filterExpression?: string;
    expressionAttributeNames?: Record<string, string>;
    expressionAttributeValues?: ExpressionAttributeValues;
  }): Promise<QueryResult<FindingTableItem>> {
    return await super.queryIndexWithFilter({
      indexName,
      partitionKeyName,
      partitionKeyValue,
      scanIndexForward,
      limit,
      exclusiveStartKey,
      filterExpression,
      expressionAttributeNames,
      expressionAttributeValues,
    });
  }

  async searchFindings(criteria: SearchCriteria): Promise<SearchResult<FindingTableItem>> {
    try {
      const findingIdFilters = this.extractFindingIdFilters(criteria.filters);
      // Direct table lookup requires deriving the partition key (findingType) from the findingId,
      // which is only possible for Security Hub ARNs. Non-ARN ids (e.g. Macie's bare-hash
      // FindingInfoUid) are resolved through the GSI path, which matches findingId as a
      // FilterExpression.
      if (findingIdFilters.length && findingIdFilters.every((id) => getControlIdFromFindingId(id))) {
        return this.executeDirectTableQueries(findingIdFilters, criteria);
      }

      // Fall back to regular GSI search for queries without findingId
      const exclusiveStartKey = this.parseNextToken(criteria.nextToken);
      const scanIndexForward = criteria.sortOrder === 'asc';
      const queryParams = this.buildOptimizedQuery(criteria.filters, criteria.sortField);

      this.logger.debug('Built optimized query parameters', {
        queryParams,
        filtersCount: criteria.filters?.length || 0,
        filters: criteria.filters,
      });

      const paginationResult = await this.executePaginatedQuery(
        queryParams,
        scanIndexForward,
        exclusiveStartKey,
        criteria.pageSize,
      );

      const findings = paginationResult.items;
      let nextToken: string | undefined;

      if (paginationResult.nextTokenKey) {
        const nextTokenData = JSON.stringify(paginationResult.nextTokenKey);
        nextToken = Buffer.from(nextTokenData, 'utf-8').toString('base64');
      }

      this.logger.debug('Search completed successfully', {
        findingsCount: findings.length,
        hasNextToken: !!nextToken,
      });

      return {
        items: findings,
        nextToken,
      };
    } catch (error) {
      this.logger.error('Error searching findings', {
        criteria: {
          ...criteria,
          nextToken: criteria.nextToken && `${criteria.nextToken.substring(0, 20)}...`,
        },
        error: error instanceof Error ? error.message : String(error),
        stack: error instanceof Error ? error.stack : undefined,
      });
      throw error;
    }
  }

  private parseNextToken(nextToken?: string): PaginationToken | undefined {
    if (!nextToken) return undefined;

    try {
      const decodedToken = Buffer.from(nextToken, 'base64').toString('utf-8');
      const parsedKey = JSON.parse(decodedToken);

      // Check if the token has the basic required field that all GSIs have
      if (parsedKey['findingType'] !== undefined) {
        // Additional validation: check if it has at least one of the expected sort key patterns
        const hasSortKey =
          parsedKey['securityHubUpdatedAtTime#findingId'] !== undefined ||
          parsedKey['severityNormalized#securityHubUpdatedAtTime#findingId'] !== undefined;

        if (hasSortKey) {
          return parsedKey;
        }
      }
      return undefined;
    } catch (error) {
      this.logger.info('Invalid NextToken provided, starting from beginning', {
        nextToken,
        error: error instanceof Error ? error.message : String(error),
      });
      return undefined;
    }
  }

  private async executePaginatedQuery(
    queryParams: DynamoDBQueryParams,
    scanIndexForward: boolean,
    exclusiveStartKey?: PaginationToken,
    pageSize: number = FINDINGS_PAGE_SIZE,
  ): Promise<{ items: FindingTableItem[]; nextTokenKey?: PaginationToken }> {
    const allFindings: FindingTableItem[] = [];
    let currentExclusiveStartKey = exclusiveStartKey;
    let totalQueriesExecuted = 0;
    const maxQueries = 10;
    let lastEvaluatedKeyStructure: string[] = [];

    while (allFindings.length < pageSize && totalQueriesExecuted < maxQueries) {
      const dbResult = await this.queryIndexWithFilter({
        indexName: queryParams.indexName,
        partitionKeyName: queryParams.partitionKeyName,
        partitionKeyValue: queryParams.partitionKeyValue,
        scanIndexForward,
        limit: pageSize * 2,
        exclusiveStartKey: currentExclusiveStartKey,
        filterExpression: queryParams.filterExpression,
        expressionAttributeNames: queryParams.expressionAttributeNames,
        expressionAttributeValues: queryParams.expressionAttributeValues,
      });

      totalQueriesExecuted++;

      if (dbResult.lastEvaluatedKey && lastEvaluatedKeyStructure.length === 0) {
        lastEvaluatedKeyStructure = Object.keys(dbResult.lastEvaluatedKey);
      }

      allFindings.push(...dbResult.items);
      currentExclusiveStartKey = dbResult.lastEvaluatedKey as PaginationToken;

      if (!dbResult.lastEvaluatedKey) {
        this.logger.info('No more results available');
        break;
      }
      if (allFindings.length >= pageSize) {
        break;
      }
    }

    const pageFindings = allFindings.slice(0, pageSize);
    const nextTokenKey = this.determineNextTokenKey(
      allFindings,
      pageFindings,
      currentExclusiveStartKey,
      queryParams.indexName,
      lastEvaluatedKeyStructure,
      pageSize,
    );

    this.logger.debug('Pagination completed', {
      totalQueriesExecuted,
      totalItemsFound: allFindings.length,
      hasMoreResults: !!nextTokenKey,
    });

    return { items: pageFindings, nextTokenKey };
  }

  private determineNextTokenKey(
    allFindings: FindingTableItem[],
    pageFindings: FindingTableItem[],
    currentExclusiveStartKey?: PaginationToken,
    indexName?: string,
    lastEvaluatedKeyStructure?: string[],
    pageSize: number = FINDINGS_PAGE_SIZE,
  ): PaginationToken | undefined {
    const hasMoreResults = allFindings.length > pageSize || currentExclusiveStartKey;

    if (!hasMoreResults) {
      return undefined;
    }

    if (allFindings.length > pageSize) {
      return this.createNextTokenFromLastItem(pageFindings, indexName, lastEvaluatedKeyStructure);
    } else if (currentExclusiveStartKey) {
      return currentExclusiveStartKey;
    }
    return undefined;
  }

  private async executeDirectTableQueries(
    findingIdValues: string[],
    criteria: SearchCriteria,
  ): Promise<SearchResult<FindingTableItem>> {
    this.logger.debug('Using direct table queries', {
      findingIds: findingIdValues,
      count: findingIdValues.length,
    });

    // Create criteria with non-findingId filters for additional filtering
    const otherCriteria: SearchCriteria = {
      ...criteria,
      filters: criteria.filters.filter((f) => f.fieldName !== 'findingId'),
    };

    // Fetch findings by IDs with additional filtering
    const findings: FindingTableItem[] = [];
    for (const findingId of findingIdValues) {
      const finding = await this.fetchSingleFindingById(findingId, otherCriteria);
      if (finding) {
        findings.push(finding);
      }
    }

    return {
      items: findings,
      nextToken: undefined,
    };
  }

  private async fetchSingleFindingById(
    findingId: string,
    otherCriteria: SearchCriteria,
  ): Promise<FindingTableItem | null> {
    const rawFindingType = getControlIdFromFindingId(findingId);
    if (!rawFindingType) {
      return null;
    }
    const findingType = sanitizeControlId(rawFindingType);

    try {
      const finding = await this.findById(findingType, findingId);
      if (finding && this.matchesCriteria(finding, otherCriteria)) {
        return finding;
      }
      return null;
    } catch (error) {
      this.logger.warn('Error querying findingId directly', {
        findingId,
        findingType,
        error: error instanceof Error ? error.message : String(error),
      });
      return null;
    }
  }

  /**
   * Checks if a finding matches the given search criteria (in-memory filtering)
   * Handles simple filters and composite filters with AND/OR operators
   */
  private matchesCriteria(finding: FindingTableItem, criteria: SearchCriteria): boolean {
    // If no filters, match everything
    if (!criteria.filters || criteria.filters.length === 0) {
      return true;
    }

    // Group filters by field name (same as buildFilterExpression logic)
    const fieldGroups = this.analyzeFilters(criteria.filters);

    // Each field group must match (AND between different fields)
    for (const [_fieldName, filters] of Object.entries(fieldGroups)) {
      // At least one filter in the group must match (OR within same field)
      let fieldMatches = false;
      for (const filter of filters) {
        if (this.matchesSingleFilter(finding, filter)) {
          fieldMatches = true;
          break; // Found a match for this field, no need to check other filters for same field
        }
      }

      // If no filter matched for this field, the finding doesn't match
      if (!fieldMatches) {
        return false;
      }
    }

    return true;
  }

  /**
   * Builds optimized DynamoDB query by selecting the most efficient index
   * and creating FilterExpression for remaining filters
   */
  private buildOptimizedQuery(filters: SearchFilter[], sortField?: string): DynamoDBQueryParams {
    if (sortField === 'severityNormalized') {
      const filterExpression =
        filters && filters.length > 0 ? this.buildFilterExpression(this.analyzeFilters(filters)) : {};
      return {
        indexName: 'allFindings-severityNormalized-GSI',
        partitionKeyName: 'FINDING_CONSTANT',
        partitionKeyValue: 'finding',
        ...filterExpression,
      };
    }

    if (!filters || filters.length === 0) {
      // No filters - use allFindings GSI
      return {
        indexName: 'allFindings-securityHubUpdatedAtTime-GSI',
        partitionKeyName: 'FINDING_CONSTANT',
        partitionKeyValue: 'finding',
      };
    }

    // Analyze filters to determine the best index
    const fieldGroups = this.analyzeFilters(filters);

    // Priority order for index selection (most selective first)
    const indexPriority = [
      { field: 'resourceId', indexName: 'resourceId-securityHubUpdatedAtTime-GSI', partitionKey: 'resourceId' },
      { field: 'severity', indexName: 'severity-securityHubUpdatedAtTime-GSI', partitionKey: 'severity' },
      { field: 'findingType', indexName: 'securityHubUpdatedAtTime-findingId-LSI', partitionKey: 'findingType' },
      { field: 'accountId', indexName: 'accountId-securityHubUpdatedAtTime-GSI', partitionKey: 'accountId' },
    ];

    // Find the best index to use
    const selectedIndex = this.selectOptimalIndex(fieldGroups, indexPriority);

    // If no specific index found, use allFindings GSI
    if (!selectedIndex) {
      const filterExpression = this.buildFilterExpression(fieldGroups);
      return {
        indexName: 'allFindings-securityHubUpdatedAtTime-GSI',
        partitionKeyName: 'FINDING_CONSTANT',
        partitionKeyValue: 'finding',
        ...filterExpression,
      };
    }

    // Build FilterExpression for remaining filters
    const remainingFieldGroups = this.removeMatchingFilters(fieldGroups, selectedIndex);

    const filterExpression = this.buildFilterExpression(remainingFieldGroups);

    return {
      indexName: selectedIndex.indexName,
      partitionKeyName: selectedIndex.partitionKey,
      partitionKeyValue: selectedIndex.value,
      ...filterExpression,
    };
  }
}
