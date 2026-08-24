// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { DynamoDBDocumentClient, TransactWriteCommand, TransactWriteCommandInput } from '@aws-sdk/lib-dynamodb';
import { SecurityControl, SecurityControlDynamoDBItem } from '@asr/data-models';
import { toStringArray } from '../utils/dynamodb';
import { Sleeper } from '../utils/sleeper';
import { AbstractRepository } from './abstractRepository';

export interface BulkUpdateResult {
  successCount: number;
  failedControlIds: string[];
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

export interface ControlExistenceCheckResult {
  readonly foundControlIds: string[];
  readonly isComplete: boolean;
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

  async findControlsUsingFilter(filterId: string): Promise<string[]> {
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

      try {
        const transactItems = batch.map(buildTransactItem);

        const command: TransactWriteCommandInput = {
          TransactItems: transactItems,
        };

        await this.dynamoDBClient.send(new TransactWriteCommand(command));
        successCount += batch.length;
      } catch (error) {
        const errorName = (error as Error).name;

        if (errorName === 'TransactionCanceledException') {
          this.logger.warn('Transaction cancelled due to condition check failure (version conflict)', {
            batchStart: i,
            batchSize: batch.length,
          });
        } else {
          this.logger.error(`${operationName} failed`, {
            errorName,
            errorMessage: (error as Error).message,
            batchStart: i,
            batchSize: batch.length,
          });
        }
        failedControlIds.push(...batch.map(getControlId));
      }
    }

    this.logger.info(`${operationName} completed`, { successCount, failedCount: failedControlIds.length });

    return { successCount, failedControlIds };
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

    // REMOVE is idempotent - if filters attribute doesn't exist, it's a no-op
    const updateExpression = hasFilters ? baseExpression + ', filters = :filters' : baseExpression + ' REMOVE filters';

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
      filters: toStringArray(item.filters),
      filterMode: (item.filterMode as 'include' | 'exclude') || 'include',
      version: item.version,
      lastModified: item.lastModified || '',
      modifiedBy: item.modifiedBy || '',
    };
  }
}
