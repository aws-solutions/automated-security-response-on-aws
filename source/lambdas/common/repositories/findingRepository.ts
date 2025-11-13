// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { FindingTableItem, PaginationToken, SearchCriteria, SearchFilter, SearchResult } from '@asr/data-models';
import { ConditionalCheckFailedException } from '@aws-sdk/client-dynamodb';
import {
  BatchGetCommand,
  BatchGetCommandInput,
  BatchGetCommandOutput,
  DeleteCommand,
  DeleteCommandInput,
  DynamoDBDocumentClient,
  PutCommand,
  PutCommandInput,
  UpdateCommand,
  UpdateCommandInput,
} from '@aws-sdk/lib-dynamodb';
import { AbstractRepository, DynamoDBKey, ExpressionAttributeValues, QueryResult } from './abstractRepository';

// DynamoDB-specific constants and configurations
const FINDINGS_PAGE_SIZE = 50;

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
  };

  constructor(principal: string, tableName: string, dynamoDBClient: DynamoDBDocumentClient) {
    super(principal, tableName, dynamoDBClient);
  }

  /** Updates finding only if securityHubUpdatedAtTime is newer than existing record or record doesn't exist */
  async putIfNewer(findingItem: FindingTableItem): Promise<'SUCCESS' | 'FAILED'> {
    try {
      const updateExpression =
        'SET findingDescription = :desc, accountId = :accountId, suppressed = :suppressed, lastUpdatedBy = :lastUpdatedBy, resourceId = :resourceId, resourceType = :resourceType, resourceTypeNormalized = :resourceTypeNormalized, severity = :severity, severityNormalized = :severityNormalized, #region = :region, securityHubUpdatedAtTime = :secHubUpdated, lastUpdatedTime = :lastUpdated, #lsiSortKey = :lsiSortKey, #severitySortKey = :severitySortKey, findingJSON = :findingJson, FINDING_CONSTANT = :findingConstant, remediationStatus = :remediationStatus';

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
   * Find multiple findings by FindingIds using batch get operation
   */
  async findByFindingIds(findingIds: string[]): Promise<FindingTableItem[]> {
    if (findingIds.length === 0) {
      return [];
    }

    try {
      const findingItemKeys = findingIds
        .map((findingId) => ({
          findingId,
          findingType: this.getControlIdFromFindingId(findingId),
        }))
        .filter((key): key is { findingId: string; findingType: string } => key.findingType !== undefined);

      const invalidCount = findingIds.length - findingItemKeys.length;
      if (invalidCount > 0) {
        this.logger.warn('Some findingIds could not be processed', {
          totalCount: findingIds.length,
          invalidCount,
          validCount: findingItemKeys.length,
        });
      }

      if (findingItemKeys.length === 0) {
        return [];
      }

      const results = await this.batchGetByIds(findingItemKeys);

      this.logger.debug('Batch get findings completed', {
        requestedCount: findingIds.length,
        validCount: findingItemKeys.length,
        retrievedCount: results.length,
      });

      return results;
    } catch (error) {
      this.logger.error('Error finding by FindingIds', { findingIds, error });
      return [];
    }
  }

  /**
   * Batch get findings using DynamoDB keys
   */
  private async batchGetByIds(
    findingItemKeys: Array<{ findingId: string; findingType: string }>,
  ): Promise<FindingTableItem[]> {
    const allResults: FindingTableItem[] = [];
    const batchSize = 100; // DynamoDB batch get limit

    // Prepare all keys for batch get
    const allKeys = findingItemKeys.map(({ findingId, findingType }) => ({
      [this.partitionKeyName]: findingType,
      [this.sortKeyName]: findingId,
    }));

    for (let i = 0; i < allKeys.length; i += batchSize) {
      const batchKeys = allKeys.slice(i, i + batchSize);
      const params: BatchGetCommandInput = {
        RequestItems: {
          [this.tableName]: {
            Keys: batchKeys,
          },
        },
      };

      try {
        const response: BatchGetCommandOutput = await this.dynamoDBClient.send(new BatchGetCommand(params));

        if (response.Responses?.[this.tableName]) {
          const items = response.Responses[this.tableName] as FindingTableItem[];
          allResults.push(...items);
        }

        if (response.UnprocessedKeys && Object.keys(response.UnprocessedKeys).length) {
          this.logger.warn('Some keys were unprocessed in batch get', {
            unprocessedCount: Object.keys(response.UnprocessedKeys).length,
          });
        }
      } catch (error) {
        this.logger.error('Error in batch get operation', { error, batchSize: batchKeys.length });
        throw error;
      }
    }

    return allResults;
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
      if (findingIdFilters.length) {
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
    const findingType = this.getControlIdFromFindingId(findingId);
    if (!findingType) {
      return null;
    }

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

  private getControlIdFromFindingId(findingId: string): string | undefined {
    // finding id structure depends on consolidation settings
    // https://aws.amazon.com/blogs/security/consolidating-controls-in-security-hub-the-new-controls-view-and-consolidated-findings/
    const UNCONSOLIDATED_FINDING_ID_REGEX =
      /^arn:(?:aws|aws-cn|aws-us-gov):securityhub:[a-z]{2}(?:-gov)?-[a-z]+-\d:\d{12}:subscription\/(.+)\/finding\/.+$/g;
    const CONSOLIDATED_FINDING_ID_REGEX =
      /^arn:(?:aws|aws-cn|aws-us-gov):securityhub:[a-z]{2}(?:-gov)?-[a-z]+-\d:\d{12}:(.+)\/finding\/.+$/g;

    const unconsolidatedMatch = UNCONSOLIDATED_FINDING_ID_REGEX.exec(findingId);
    if (unconsolidatedMatch) return unconsolidatedMatch[1]; // example: 'cis-aws-foundations-benchmark/v/1.4.0/4.8'

    const consolidatedMatch = CONSOLIDATED_FINDING_ID_REGEX.exec(findingId);
    if (consolidatedMatch) return consolidatedMatch[1]; // example: 'security-control/Lambda.3'

    return undefined;
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
