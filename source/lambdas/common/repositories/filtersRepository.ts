// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { DynamoDBDocumentClient, DeleteCommand, PutCommand, UpdateCommand } from '@aws-sdk/lib-dynamodb';
import { CreateFilterRequest, ResourceFilter, ResourceFilterDynamoDBItem, UpdateFilterRequest } from '@asr/data-models';
import { toStringArray } from '../utils/dynamodb';
import { Sleeper } from '../utils/sleeper';
import { AbstractRepository } from './abstractRepository';

interface FilterKey {
  filterId: string;
}

export class FiltersRepository extends AbstractRepository<ResourceFilter> {
  protected readonly partitionKeyName = 'filterId';
  protected readonly sortKeyName = '';

  constructor(tableName: string, dynamoDBClient: DynamoDBDocumentClient, sleeper?: Sleeper) {
    super('FiltersRepository', tableName, dynamoDBClient, sleeper);
  }

  /**
   * Returns the filter records for the requested IDs. DynamoDB BatchGetItem silently omits keys that
   * do not exist, so a configured-but-deleted filter is simply absent from the result rather than
   * reported as an error. Callers that must fail closed on a missing filter (the finding evaluator)
   * compare the returned filters against the requested IDs; callers that tolerate deletion (the
   * notification dispatcher) match the survivors.
   */
  async batchFindByIds(filterIds: string[]): Promise<ResourceFilterDynamoDBItem[]> {
    if (filterIds.length === 0) {
      return [];
    }

    const uniqueFilterIds = [...new Set(filterIds)];
    const keys: FilterKey[] = uniqueFilterIds.map((filterId) => ({ filterId }));

    const { items } = await this.batchGetWithRetry<ResourceFilterDynamoDBItem>(keys);
    return items;
  }

  async findAll(): Promise<ResourceFilter[]> {
    return this.findAllWithTransform((item) => this.transformToResourceFilter(item as ResourceFilterDynamoDBItem));
  }

  async findByName(name: string): Promise<ResourceFilter[]> {
    const result = await this.queryIndexPK({
      indexName: 'NameIndex',
      partitionKeyName: 'name',
      partitionKeyValue: name,
    });
    return result.items.map((item) => this.transformToResourceFilter(item as unknown as ResourceFilterDynamoDBItem));
  }

  async createFilter(
    filterId: string,
    request: CreateFilterRequest,
    createdBy: string,
    createdAt: string,
  ): Promise<ResourceFilter> {
    const item: ResourceFilterDynamoDBItem = {
      filterId,
      name: request.name,
      tags: request.tags,
      version: 1,
      createdAt,
      createdBy,
      lastModified: createdAt,
      modifiedBy: createdBy,
      ...(request.accountIds.length > 0 && { accountIds: new Set(request.accountIds) }),
      ...(request.organizationalUnits.length > 0 && { organizationalUnits: new Set(request.organizationalUnits) }),
      ...(request.arnPatterns.length > 0 && { arnPatterns: new Set(request.arnPatterns) }),
    };

    await this.dynamoDBClient.send(
      new PutCommand({
        TableName: this.tableName,
        Item: item,
        ConditionExpression: 'attribute_not_exists(filterId)',
      }),
    );

    return this.transformToResourceFilter(item);
  }

  async updateFilter(
    filterId: string,
    request: UpdateFilterRequest,
    modifiedBy: string,
    lastModified: string,
  ): Promise<ResourceFilter> {
    const hasAccountIds = request.accountIds.length > 0;
    const hasOUs = request.organizationalUnits.length > 0;
    const hasArnPatterns = request.arnPatterns.length > 0;

    const setExpressions: string[] = [
      '#name = :name',
      'version = version + :inc',
      'lastModified = :lastModified',
      'modifiedBy = :modifiedBy',
      'tags = :tags',
    ];
    const removeExpressions: string[] = [];

    const expressionAttributeNames: Record<string, string> = {
      '#name': 'name',
    };

    const expressionAttributeValues: Record<string, unknown> = {
      ':name': request.name,
      ':inc': 1,
      ':expectedVersion': request.version,
      ':lastModified': lastModified,
      ':modifiedBy': modifiedBy,
      ':tags': request.tags,
    };

    if (hasAccountIds) {
      setExpressions.push('accountIds = :accountIds');
      expressionAttributeValues[':accountIds'] = new Set(request.accountIds);
    } else {
      removeExpressions.push('accountIds');
    }

    if (hasOUs) {
      setExpressions.push('organizationalUnits = :organizationalUnits');
      expressionAttributeValues[':organizationalUnits'] = new Set(request.organizationalUnits);
    } else {
      removeExpressions.push('organizationalUnits');
    }

    if (hasArnPatterns) {
      setExpressions.push('arnPatterns = :arnPatterns');
      expressionAttributeValues[':arnPatterns'] = new Set(request.arnPatterns);
    } else {
      removeExpressions.push('arnPatterns');
    }

    let updateExpression = `SET ${setExpressions.join(', ')}`;
    if (removeExpressions.length > 0) {
      updateExpression += ` REMOVE ${removeExpressions.join(', ')}`;
    }

    const command = new UpdateCommand({
      TableName: this.tableName,
      Key: { filterId },
      UpdateExpression: updateExpression,
      ConditionExpression: 'attribute_exists(filterId) AND version = :expectedVersion',
      ExpressionAttributeNames: expressionAttributeNames,
      ExpressionAttributeValues: expressionAttributeValues,
      ReturnValues: 'ALL_NEW',
    });

    const response = await this.dynamoDBClient.send(command);
    return this.transformToResourceFilter(response.Attributes as ResourceFilterDynamoDBItem);
  }

  async deleteFilter(filterId: string): Promise<void> {
    await this.dynamoDBClient.send(
      new DeleteCommand({
        TableName: this.tableName,
        Key: { filterId },
      }),
    );
  }

  private transformToResourceFilter(item: ResourceFilterDynamoDBItem): ResourceFilter {
    this.logger.debug('Transforming DynamoDB item to ResourceFilter object', { item });

    return {
      filterId: item.filterId,
      name: item.name,
      accountIds: toStringArray(item.accountIds),
      organizationalUnits: toStringArray(item.organizationalUnits),
      tags: item.tags || [],
      arnPatterns: toStringArray(item.arnPatterns),
      version: item.version,
      createdAt: item.createdAt || '',
      createdBy: item.createdBy || '',
      lastModified: item.lastModified || '',
      modifiedBy: item.modifiedBy || '',
    };
  }
}
