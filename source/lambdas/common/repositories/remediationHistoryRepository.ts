// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { DynamoDBDocumentClient, PutCommand, TransactWriteCommand } from '@aws-sdk/lib-dynamodb';
import {
  PaginationToken,
  SearchCriteria,
  SearchFilter,
  SearchResult,
  FindingTableItem,
  RemediationHistoryTableItem,
} from '@asr/data-models';
import { calculateHistoryTtlTimestamp } from '../utils/ttlUtils';
import { AbstractRepository, DynamoDBKey, ExpressionAttributeValues, QueryResult } from './abstractRepository';
import { mapRemediationStatus } from '../utils/remediationStatusMapper';

interface QueryParameters {
  indexName: string;
  partitionKeyName: string;
  partitionKeyValue: string;
  filterExpression?: string;
  expressionAttributeNames?: Record<string, string>;
  expressionAttributeValues?: ExpressionAttributeValues;
}

interface PaginatedQueryResult {
  items: RemediationHistoryTableItem[];
  nextTokenKey?: PaginationToken;
}

export class RemediationHistoryRepository extends AbstractRepository<RemediationHistoryTableItem> {
  protected readonly partitionKeyName = 'findingType';
  protected readonly sortKeyName = 'findingId#executionId';

  // GSI key structure mapping - defines the expected key fields for each index
  protected override readonly GSI_KEY_STRUCTURES: Record<string, string[]> = {
    'allRemediations-lastUpdatedTime-GSI': [
      'REMEDIATION_CONSTANT',
      'lastUpdatedTime#findingId',
      'findingType',
      'findingId#executionId',
    ],
    'accountId-lastUpdatedTime-GSI': ['accountId', 'lastUpdatedTime#findingId', 'findingType', 'findingId#executionId'],
    'resourceId-lastUpdatedTime-GSI': [
      'resourceId',
      'lastUpdatedTime#findingId',
      'findingType',
      'findingId#executionId',
    ],
    'findingId-lastUpdatedTime-GSI': ['findingId', 'lastUpdatedTime#findingId', 'findingType', 'findingId#executionId'],
    'userId-lastUpdatedTime-GSI': [
      'lastUpdatedBy',
      'lastUpdatedTime#findingId',
      'findingType',
      'findingId#executionId',
    ],
  };

  constructor(
    principal: string,
    tableName: string,
    dynamoDBClient: DynamoDBDocumentClient,
    private readonly findingsTableName: string,
  ) {
    super(principal, tableName, dynamoDBClient);
  }

  /**
   * Creates a remediation history item mapping from finding data
   * @param finding - The finding data to create history for
   * @param executionId - The orchestrator execution ID
   * @param timestamp - The timestamp for the history item
   * @param user - The user creating the history item
   * @returns RemediationHistoryTableItem
   */
  private createRemediationHistoryItem(
    finding: FindingTableItem,
    executionId: string,
    timestamp: string,
    user: string,
  ): RemediationHistoryTableItem {
    return {
      findingType: finding.findingType,
      findingId: finding.findingId,
      'findingId#executionId': `${finding.findingId}#${executionId}`,
      accountId: finding.accountId,
      resourceId: finding.resourceId,
      resourceType: finding.resourceType,
      resourceTypeNormalized: finding.resourceTypeNormalized,
      severity: finding.severity,
      region: finding.region,
      remediationStatus: mapRemediationStatus(finding.remediationStatus),
      lastUpdatedTime: timestamp,
      'lastUpdatedTime#findingId': `${timestamp}#${finding.findingId}`,
      REMEDIATION_CONSTANT: 'remediation',
      lastUpdatedBy: user,
      executionId,
      error: finding.error,
      expireAt: calculateHistoryTtlTimestamp(timestamp),
    };
  }

  /**
   * Creates a remediation history item without updating the finding
   * @param finding - The finding data to create history
   * @param executionId - The orchestrator execution ID
   */
  async createRemediationHistory(finding: FindingTableItem, executionId: string): Promise<void> {
    const timestamp = new Date().toISOString();
    const user = finding.lastUpdatedBy || this.principal;

    const remediationHistoryItem = this.createRemediationHistoryItem(finding, executionId, timestamp, user);

    try {
      await this.dynamoDBClient.send(
        new PutCommand({
          TableName: this.tableName,
          Item: remediationHistoryItem,
        }),
      );

      this.logger.debug('Successfully created remediation history', {
        findingId: finding.findingId,
        executionId,
        user,
        timestamp,
      });
    } catch (error) {
      this.logger.error('Failed to create remediation history', {
        findingId: finding.findingId,
        executionId,
        user,
        error: error instanceof Error ? error.message : String(error),
      });
      throw error;
    }
  }

  async createRemediationHistoryWithFindingUpdate(finding: FindingTableItem, executionId: string): Promise<void> {
    const timestamp = new Date().toISOString();
    const user = finding.lastUpdatedBy || this.principal;

    const remediationHistoryItem = this.createRemediationHistoryItem(finding, executionId, timestamp, user);

    const updatedFinding: FindingTableItem = {
      ...finding,
      remediationStatus: mapRemediationStatus(finding.remediationStatus),
      lastUpdatedTime: timestamp,
      lastUpdatedBy: user,
    };

    const transactItems = [
      {
        Put: {
          TableName: this.tableName,
          Item: remediationHistoryItem,
        },
      },
      {
        Put: {
          TableName: this.findingsTableName,
          Item: updatedFinding,
        },
      },
    ];

    try {
      await this.dynamoDBClient.send(
        new TransactWriteCommand({
          TransactItems: transactItems,
        }),
      );

      this.logger.debug('Successfully created remediation history and updated finding', {
        findingId: finding.findingId,
        user,
        timestamp,
      });
    } catch (error) {
      this.logger.error('Failed to create remediation history with finding update', {
        findingId: finding.findingId,
        user,
        error: error instanceof Error ? error.message : String(error),
      });
      throw error;
    }
  }

  async searchRemediations(criteria: SearchCriteria): Promise<SearchResult<RemediationHistoryTableItem>> {
    try {
      const findingIdFilters = this.extractFindingIdFilters(criteria.filters);
      if (findingIdFilters?.length) {
        return this.executeDirectQueries(findingIdFilters, criteria);
      }

      const exclusiveStartKey = this.parseNextToken(criteria.nextToken);
      const scanIndexForward = criteria.sortOrder === 'asc';
      const queryParams = this.buildOptimizedQuery(criteria.filters);

      this.logger.debug('Built optimized remediation query parameters', {
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

      const remediations = paginationResult.items;
      let nextToken: string | undefined;

      if (paginationResult.nextTokenKey) {
        const nextTokenData = JSON.stringify(paginationResult.nextTokenKey);
        nextToken = Buffer.from(nextTokenData, 'utf-8').toString('base64');
      }

      this.logger.debug('Remediation search completed successfully', {
        remediationsCount: remediations.length,
        hasNextToken: !!nextToken,
      });

      return {
        items: remediations,
        nextToken,
      };
    } catch (error) {
      this.logger.error('Error searching remediations', {
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

      const requiredFields = ['findingType', 'lastUpdatedTime#findingId'];
      const hasRequiredFields = requiredFields.every((field) => parsedKey[field] !== undefined);

      if (hasRequiredFields) {
        return parsedKey;
      }
      return undefined;
    } catch (error) {
      this.logger.warn('Invalid NextToken provided, starting from beginning', {
        nextToken,
        error: error instanceof Error ? error.message : String(error),
      });
      return undefined;
    }
  }

  private async executePaginatedQuery(
    queryParams: QueryParameters,
    scanIndexForward: boolean,
    exclusiveStartKey?: PaginationToken,
    pageSize: number = 50,
  ): Promise<PaginatedQueryResult> {
    const allRemediations: RemediationHistoryTableItem[] = [];
    let currentExclusiveStartKey = exclusiveStartKey;
    let totalQueriesExecuted = 0;
    const maxQueries = 10;
    let lastEvaluatedKeyStructure: string[] = [];

    while (allRemediations.length < pageSize && totalQueriesExecuted < maxQueries) {
      const dbResult = await this.queryIndexWithFilter({
        indexName: queryParams.indexName,
        partitionKeyName: queryParams.partitionKeyName,
        partitionKeyValue: queryParams.partitionKeyValue,
        scanIndexForward,
        limit: pageSize * 2,
        exclusiveStartKey: currentExclusiveStartKey as DynamoDBKey,
        filterExpression: queryParams.filterExpression,
        expressionAttributeNames: queryParams.expressionAttributeNames,
        expressionAttributeValues: queryParams.expressionAttributeValues,
      });

      totalQueriesExecuted++;

      if (dbResult.lastEvaluatedKey && lastEvaluatedKeyStructure.length === 0) {
        lastEvaluatedKeyStructure = Object.keys(dbResult.lastEvaluatedKey);
      }

      allRemediations.push(...dbResult.items);
      currentExclusiveStartKey = dbResult.lastEvaluatedKey as PaginationToken;

      if (!dbResult.lastEvaluatedKey) {
        this.logger.debug('No more remediation results available');
        break;
      }
      if (allRemediations.length >= pageSize) {
        break;
      }
    }

    const pageRemediations = allRemediations.slice(0, pageSize);
    const nextTokenKey = this.determineNextTokenKey(
      allRemediations,
      pageRemediations,
      currentExclusiveStartKey,
      queryParams.indexName,
      lastEvaluatedKeyStructure,
      pageSize,
    );

    this.logger.debug('Remediation pagination completed', {
      totalQueriesExecuted,
      totalItemsFound: allRemediations.length,
      hasMoreResults: !!nextTokenKey,
    });

    return { items: pageRemediations, nextTokenKey };
  }

  private determineNextTokenKey(
    allRemediations: RemediationHistoryTableItem[],
    pageRemediations: RemediationHistoryTableItem[],
    currentExclusiveStartKey?: PaginationToken,
    indexName?: string,
    lastEvaluatedKeyStructure?: string[],
    pageSize: number = 50,
  ): PaginationToken | undefined {
    const hasMoreResults = allRemediations.length > pageSize || currentExclusiveStartKey;

    if (!hasMoreResults) {
      return undefined;
    }

    if (allRemediations.length > pageSize) {
      return this.createNextTokenFromLastItem(pageRemediations, indexName, lastEvaluatedKeyStructure);
    } else if (currentExclusiveStartKey) {
      return currentExclusiveStartKey;
    }
    return undefined;
  }

  private buildOptimizedQuery(filters: SearchFilter[]): QueryParameters {
    if (!filters || filters.length === 0) {
      return {
        indexName: 'allRemediations-lastUpdatedTime-GSI',
        partitionKeyName: 'REMEDIATION_CONSTANT',
        partitionKeyValue: 'remediation',
      };
    }

    const fieldGroups = this.analyzeFilters(filters);

    const indexPriority = [
      { field: 'accountId', indexName: 'accountId-lastUpdatedTime-GSI', partitionKey: 'accountId' },
      { field: 'resourceId', indexName: 'resourceId-lastUpdatedTime-GSI', partitionKey: 'resourceId' },
      { field: 'findingId', indexName: 'findingId-lastUpdatedTime-GSI', partitionKey: 'findingId' },
    ];

    const selectedIndex = this.selectOptimalIndex(fieldGroups, indexPriority);

    if (!selectedIndex) {
      const filterExpression = this.buildFilterExpression(fieldGroups);
      return {
        indexName: 'allRemediations-lastUpdatedTime-GSI',
        partitionKeyName: 'REMEDIATION_CONSTANT',
        partitionKeyValue: 'remediation',
        ...filterExpression,
      };
    }

    const remainingFieldGroups = this.removeMatchingFilters(fieldGroups, selectedIndex);

    const filterExpression = this.buildFilterExpression(remainingFieldGroups);

    return {
      indexName: selectedIndex.indexName,
      partitionKeyName: selectedIndex.partitionKey,
      partitionKeyValue: selectedIndex.value,
      ...filterExpression,
    };
  }

  private async executeDirectQueries(
    findingIdValues: string[],
    criteria: SearchCriteria,
  ): Promise<SearchResult<RemediationHistoryTableItem>> {
    this.logger.debug('Using direct findingId queries for remediations', {
      findingIds: findingIdValues,
      count: findingIdValues.length,
    });

    const otherCriteria: SearchCriteria = {
      ...criteria,
      filters: criteria.filters.filter((f) => f.fieldName !== 'findingId'),
    };

    const remediations: RemediationHistoryTableItem[] = [];
    for (const findingId of findingIdValues) {
      const findingRemediations = await this.fetchRemediationsByFindingId(findingId, otherCriteria);
      remediations.push(...findingRemediations);
    }

    remediations.sort((a, b) => {
      const timeA = new Date(a.lastUpdatedTime).getTime();
      const timeB = new Date(b.lastUpdatedTime).getTime();
      return criteria.sortOrder === 'asc' ? timeA - timeB : timeB - timeA;
    });

    return {
      items: remediations,
      nextToken: undefined,
    };
  }

  private async fetchRemediationsByFindingId(
    findingId: string,
    otherCriteria: SearchCriteria,
  ): Promise<RemediationHistoryTableItem[]> {
    try {
      const result = await this.queryIndexPK({
        indexName: 'findingId-lastUpdatedTime-GSI',
        partitionKeyName: 'findingId',
        partitionKeyValue: findingId,
        scanIndexForward: otherCriteria.sortOrder === 'asc',
      });

      if (result.items?.length) {
        const remediations = result.items;

        if (otherCriteria.filters?.length) {
          return remediations.filter((remediation) => this.matchesCriteria(remediation, otherCriteria));
        }

        return remediations;
      }

      return [];
    } catch (error) {
      this.logger.warn('Error querying remediations by findingId', {
        findingId,
        error: error instanceof Error ? error.message : String(error),
      });
      return [];
    }
  }

  private matchesCriteria(remediation: RemediationHistoryTableItem, criteria: SearchCriteria): boolean {
    if (!criteria.filters || criteria.filters.length === 0) {
      return true;
    }

    const fieldGroups = this.analyzeFilters(criteria.filters);

    for (const [_fieldName, filters] of Object.entries(fieldGroups)) {
      let fieldMatches = false;
      for (const filter of filters) {
        if (this.matchesSingleFilter(remediation, filter)) {
          fieldMatches = true;
          break; // Found a match for this field, no need to check other filters for same field
        }
      }

      if (!fieldMatches) {
        return false;
      }
    }

    return true;
  }
}
