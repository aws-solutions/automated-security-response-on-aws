// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import {
  BatchWriteCommand,
  BatchWriteCommandInput,
  DynamoDBDocumentClient,
  GetCommand,
  GetCommandInput,
  PutCommand,
  PutCommandInput,
  QueryCommand,
  QueryCommandInput,
  QueryCommandOutput,
} from '@aws-sdk/lib-dynamodb';
import type { NativeAttributeValue } from '@aws-sdk/util-dynamodb';
import { PaginationAttributeValue, PaginationToken, SearchFilter } from '@asr/data-models';
import { getLogger } from '../utils/logger';

export type DynamoDBAttributeValue = NativeAttributeValue;

export interface DynamoDBItem extends Record<string, DynamoDBAttributeValue> {}

export interface DynamoDBKey extends Record<string, DynamoDBAttributeValue> {}

export interface ExpressionAttributeValues extends Record<string, DynamoDBAttributeValue> {}

export interface QueryResult<T = DynamoDBItem> {
  items: T[];
  lastEvaluatedKey?: DynamoDBKey;
}

type BatchWriteRequestItems = NonNullable<BatchWriteCommandInput['RequestItems']>;
// The Repository Pattern hides the underlying database implementation (DynamoDB) from the business application code
// and provides convenient CRUD operations for a given entity type T
export abstract class AbstractRepository<T> {
  // Implementation of the repository has to set the names of the keys for the base table
  protected abstract readonly partitionKeyName: string;
  protected abstract readonly sortKeyName: string;
  // GSI key structure mapping - defines the expected key fields for each index
  protected readonly GSI_KEY_STRUCTURES: Record<string, string[]> = {};
  protected readonly logger = getLogger(this.constructor.name);

  // Implementation of the Repository has to set the identity (principal) and key names for the base table
  protected constructor(
    protected readonly principal: string,
    protected readonly tableName: string,
    protected readonly dynamoDBClient: DynamoDBDocumentClient,
  ) {}

  async findById(partitionKey: string, sortKey: string): Promise<T | undefined> {
    try {
      const params: GetCommandInput = {
        TableName: this.tableName,
        Key: {
          [this.partitionKeyName]: partitionKey,
          [this.sortKeyName]: sortKey,
        },
      };

      const response = await this.dynamoDBClient.send(new GetCommand(params));

      const item = response.Item;
      if (!item) return undefined;

      return item as T;
    } catch (error) {
      this.logger.debug('Could not find item by ID', { partitionKey, sortKey });
      return undefined;
    }
  }

  async put(item: T): Promise<void> {
    return await this.putUntyped(item);
  }

  async putAll(...items: T[]): Promise<void> {
    return await this.putInBatches(items);
  }

  async putUntyped<C>(item: C): Promise<void> {
    try {
      const params: PutCommandInput = {
        TableName: this.tableName,
        Item: { ...(item as DynamoDBItem), lastUpdatedBy: this.principal },
      };

      await this.dynamoDBClient.send(new PutCommand(params));
    } catch (error) {
      this.logger.error('Error putting item');
      throw error;
    }
  }

  /**
   * Queries DynamoDB index with pagination support and sorting control.
   * Returns a single page of results with LastEvaluatedKey for pagination.
   */
  private async queryIndexWithPagination(
    indexName: string,
    keyConditionExpression: string,
    expressionAttributeValues: ExpressionAttributeValues,
    scanIndexForward: boolean = true,
    limit?: number,
    exclusiveStartKey?: DynamoDBKey,
  ): Promise<QueryResult<T>> {
    const params: QueryCommandInput = {
      TableName: this.tableName,
      IndexName: indexName,
      KeyConditionExpression: keyConditionExpression,
      ExpressionAttributeValues: expressionAttributeValues,
      ScanIndexForward: scanIndexForward,
      ...(limit && { Limit: limit }),
      ...(exclusiveStartKey && { ExclusiveStartKey: exclusiveStartKey }),
    };

    const response: QueryCommandOutput = await this.dynamoDBClient.send(new QueryCommand(params));

    const items: DynamoDBItem[] = response.Items || [];

    return {
      items: items as T[],
      lastEvaluatedKey: response.LastEvaluatedKey,
    };
  }

  async putInBatches<C>(items: C[]): Promise<void> {
    const batchSize = 25;
    const batches: Array<{ RequestItems: BatchWriteRequestItems }> = [];

    // Split items into batches
    for (let i = 0; i < items.length; i += batchSize) {
      const batchItems = items.slice(i, i + batchSize);
      const params = {
        RequestItems: {
          [this.tableName]: batchItems.map((item) => ({
            PutRequest: {
              Item: { ...(item as DynamoDBItem), lastUpdatedBy: this.principal },
            },
          })),
        } as BatchWriteRequestItems,
      };
      batches.push(params);
    }

    // Process batches in sequence
    for (const params of batches) {
      let unprocessed: BatchWriteRequestItems = params.RequestItems;
      let attempts = 0;
      const maxAttempts = 3;

      while (Object.keys(unprocessed).length > 0 && attempts < maxAttempts) {
        try {
          const response = await this.dynamoDBClient.send(
            new BatchWriteCommand({
              RequestItems: unprocessed,
            }),
          );

          unprocessed = (response.UnprocessedItems as BatchWriteRequestItems) || {};
          if (Object.keys(unprocessed).length > 0) {
            // Exponential backoff before retry
            await new Promise((resolve) => setTimeout(resolve, Math.pow(2, attempts) * 100));
          }
        } catch (error) {
          this.logger.error('Error batch writing items to DynamoDB:', { error });
          throw error;
        }
        attempts++;
      }

      if (Object.keys(unprocessed).length > 0) {
        throw new Error(`Failed to process all items after ${maxAttempts} attempts`);
      }
    }
  }

  async queryIndexPK({
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
  }): Promise<QueryResult<T>> {
    const keyConditionExpression = `${partitionKeyName} = :partitionKey`;

    const expressionAttributeValues = {
      ':partitionKey': partitionKeyValue,
    };

    this.logger.debug('DynamoDB query parameters', {
      tableName: this.tableName,
      indexName,
      keyConditionExpression,
      expressionAttributeValues,
      scanIndexForward,
      limit,
    });

    try {
      const result = await this.queryIndexWithPagination(
        indexName,
        keyConditionExpression,
        expressionAttributeValues,
        scanIndexForward,
        limit,
        exclusiveStartKey,
      );
      this.logger.debug('queryIndexPK result', {
        itemCount: result.items.length,
        lastEvaluatedKey: result.lastEvaluatedKey,
        firstItem: result.items.length > 0 ? result.items[0] : null,
      });
      return result;
    } catch (error) {
      this.logger.error('queryIndexPK failed', {
        indexName,
        partitionKeyName,
        partitionKeyValue,
        error: error instanceof Error ? error.message : String(error),
      });
      throw error;
    }
  }

  /**
   * Query an index with additional FilterExpression for optimized filtering
   */
  async queryIndexWithFilter({
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
  }): Promise<QueryResult<T>> {
    const keyConditionExpression = `${partitionKeyName} = :partitionKey`;

    // Merge expression attribute values
    const mergedExpressionAttributeValues = {
      ':partitionKey': partitionKeyValue,
      ...(expressionAttributeValues || {}),
    };

    const params: QueryCommandInput = {
      TableName: this.tableName,
      IndexName: indexName,
      KeyConditionExpression: keyConditionExpression,
      ExpressionAttributeValues: mergedExpressionAttributeValues,
      ScanIndexForward: scanIndexForward,
      ...(limit && { Limit: limit }),
      ...(exclusiveStartKey && { ExclusiveStartKey: exclusiveStartKey }),
      ...(filterExpression && { FilterExpression: filterExpression }),
      ...(expressionAttributeNames && { ExpressionAttributeNames: expressionAttributeNames }),
    };

    try {
      const response = await this.dynamoDBClient.send(new QueryCommand(params));

      const items: DynamoDBItem[] = response.Items || [];
      const result = {
        items: items as T[],
        lastEvaluatedKey: response.LastEvaluatedKey,
      };

      this.logger.debug('queryIndexWithFilter result', {
        itemCount: result.items.length,
        lastEvaluatedKey: result.lastEvaluatedKey,
        firstItem: result.items.length ? result.items[0] : null,
      });

      return result;
    } catch (error) {
      this.logger.error('queryIndexWithFilter failed', {
        indexName,
        partitionKeyName,
        partitionKeyValue,
        filterExpression,
        error: error instanceof Error ? error.message : String(error),
      });
      throw error;
    }
  }

  /**
   * Removes filters that match the selected index from field groups
   * @param fieldGroups - The original field groups object
   * @param selectedIndex - The selected index containing field and value
   * @returns Updated field groups with matching filters removed
   */
  protected removeMatchingFilters(
    fieldGroups: Record<string, SearchFilter[]>,
    selectedIndex: { field: string; value: string },
  ): Record<string, SearchFilter[]> {
    const remainingFieldGroups = { ...fieldGroups };

    if (selectedIndex.field in remainingFieldGroups) {
      const indexFieldFilters = remainingFieldGroups[selectedIndex.field];
      const nonEqualsFilters = indexFieldFilters.filter(
        (f) => f.comparison !== 'EQUALS' || f.value !== selectedIndex.value,
      );

      if (nonEqualsFilters.length) {
        remainingFieldGroups[selectedIndex.field] = nonEqualsFilters;
      } else {
        delete remainingFieldGroups[selectedIndex.field];
      }
    }

    return remainingFieldGroups;
  }

  /**
   * Finds the best index to use from a priority list based on field groups
   * @param fieldGroups - Analyzed filters grouped by field name
   * @param indexPriority - Array of index configurations in priority order
   * @returns Selected index with field, indexName, partitionKey, and value, or null if none found
   */
  protected selectOptimalIndex(
    fieldGroups: Record<string, SearchFilter[]>,
    indexPriority: Array<{ field: string; indexName: string; partitionKey: string }>,
  ): { field: string; indexName: string; partitionKey: string; value: string } | null {
    let selectedIndex: { field: string; indexName: string; partitionKey: string; value: string } | null = null;

    for (const index of indexPriority) {
      const fieldFilters = fieldGroups[index.field];

      if (fieldFilters && fieldFilters.length === 1) {
        // Only use this index if there's exactly one filter and it's EQUALS
        const filter = fieldFilters[0];
        if (filter.comparison === 'EQUALS') {
          selectedIndex = {
            ...index,
            value: filter.value,
          };
          break;
        }
      }
    }

    return selectedIndex;
  }

  /**
   * Checks if an item matches a single filter
   * @param item - The item to check against the filter
   * @param filter - The search filter to apply
   * @returns True if the item matches the filter, false otherwise
   */
  protected matchesSingleFilter(item: T, filter: SearchFilter): boolean {
    const fieldValue = (item as DynamoDBItem)[filter.fieldName];

    if (fieldValue === undefined || fieldValue === null) {
      return false;
    }

    const fieldValueStr = String(fieldValue);
    const filterValueStr = String(filter.value);

    switch (filter.comparison) {
      case 'EQUALS':
        return fieldValueStr === filterValueStr;
      case 'NOT_EQUALS':
        return fieldValueStr !== filterValueStr;
      case 'CONTAINS':
        return fieldValueStr.includes(filterValueStr);
      case 'NOT_CONTAINS':
        return !fieldValueStr.includes(filterValueStr);
      default:
        return false; // Unknown comparison operator
    }
  }

  /**
   * Groups filters by field name for analysis
   * @param filters - Array of search filters
   * @returns Record mapping field names to arrays of filters
   */
  protected analyzeFilters(filters: SearchFilter[]): Record<string, SearchFilter[]> {
    const fieldGroups: Record<string, SearchFilter[]> = {};

    for (const filter of filters) {
      const fieldName = filter.fieldName;
      if (!fieldGroups[fieldName]) {
        fieldGroups[fieldName] = [];
      }
      fieldGroups[fieldName].push(filter);
    }

    return fieldGroups;
  }

  /**
   * Builds DynamoDB FilterExpression from grouped filters
   * @param fieldGroups - Filters grouped by field name
   * @returns Object containing filterExpression, expressionAttributeNames, and expressionAttributeValues
   */
  protected buildFilterExpression(fieldGroups: Record<string, SearchFilter[]>): {
    filterExpression?: string;
    expressionAttributeNames?: Record<string, string>;
    expressionAttributeValues?: ExpressionAttributeValues;
  } {
    if (Object.keys(fieldGroups).length === 0) {
      return {};
    }

    const filterConditions: string[] = [];
    const expressionAttributeNames: Record<string, string> = {};
    const expressionAttributeValues: ExpressionAttributeValues = {};
    let valueCounter = 0;

    Object.entries(fieldGroups).forEach(([fieldName, filters]) => {
      const fieldConditions: string[] = [];
      const fieldNameAlias = `#${fieldName}`;
      expressionAttributeNames[fieldNameAlias] = fieldName;

      filters.forEach((filter) => {
        const valueAlias = `:val${valueCounter++}`;
        expressionAttributeValues[valueAlias] = filter.value;

        switch (filter.comparison) {
          case 'EQUALS':
            fieldConditions.push(`${fieldNameAlias} = ${valueAlias}`);
            break;
          case 'NOT_EQUALS':
            fieldConditions.push(`${fieldNameAlias} <> ${valueAlias}`);
            break;
          case 'CONTAINS':
            fieldConditions.push(`contains(${fieldNameAlias}, ${valueAlias})`);
            break;
          case 'NOT_CONTAINS':
            fieldConditions.push(`NOT contains(${fieldNameAlias}, ${valueAlias})`);
            break;
          case 'GREATER_THAN_OR_EQUAL':
            fieldConditions.push(`${fieldNameAlias} >= ${valueAlias}`);
            break;
          case 'LESS_THAN_OR_EQUAL':
            fieldConditions.push(`${fieldNameAlias} <= ${valueAlias}`);
            break;
        }
      });

      if (fieldConditions.length) {
        filterConditions.push(fieldConditions.length === 1 ? fieldConditions[0] : `(${fieldConditions.join(' OR ')})`);
      }
    });

    return {
      filterExpression: (filterConditions.length && filterConditions.join(' AND ')) || undefined,
      expressionAttributeNames: (Object.keys(expressionAttributeNames).length && expressionAttributeNames) || undefined,
      expressionAttributeValues:
        (Object.keys(expressionAttributeValues).length && expressionAttributeValues) || undefined,
    };
  }

  /**
   * Extracts findingId filters with EQUALS comparison for direct queries
   * @param filters - Array of search filters
   * @returns Array of unique findingId values
   */
  protected extractFindingIdFilters(filters: SearchFilter[]): string[] {
    const findingIdValues: string[] = [];

    for (const filter of filters) {
      if (filter.fieldName === 'findingId' && filter.comparison === 'EQUALS') {
        findingIdValues.push(filter.value);
      }
    }

    return findingIdValues.length ? Array.from(new Set(findingIdValues)) : findingIdValues;
  }

  /**
   * Creates a pagination token from the last item in a page
   * @param pageItems - Array of items in the current page
   * @param indexName - Optional GSI index name to determine key structure
   * @param lastEvaluatedKeyStructure - Optional key structure from DynamoDB LastEvaluatedKey
   * @returns Pagination token for the next page, or undefined if no more pages
   */
  protected createNextTokenFromLastItem(
    pageItems: T[],
    indexName?: string,
    lastEvaluatedKeyStructure?: string[],
  ): PaginationToken | undefined {
    const lastReturnedItem = pageItems[pageItems.length - 1];
    const expectedKeyStructure = (indexName && this.GSI_KEY_STRUCTURES[indexName]) || lastEvaluatedKeyStructure;

    if (!expectedKeyStructure?.length) {
      return undefined;
    }

    const nextTokenKey: PaginationToken = {};
    const item = lastReturnedItem as T & Record<string, PaginationAttributeValue>;

    expectedKeyStructure.forEach((field) => {
      const value = item[field];
      if (value !== undefined) {
        nextTokenKey[field] = value;
      }
    });

    return nextTokenKey;
  }
}
