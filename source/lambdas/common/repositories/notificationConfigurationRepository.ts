// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import {
  DynamoDBDocumentClient,
  DeleteCommand,
  GetCommand,
  PutCommand,
  TransactWriteCommand,
} from '@aws-sdk/lib-dynamodb';
import { ConditionalCheckFailedException } from '@aws-sdk/client-dynamodb';
import { unmarshall } from '@aws-sdk/util-dynamodb';
import { NotificationConfigurationItem, NotificationType, SearchResult } from '@asr/data-models';
import { AbstractRepository } from './abstractRepository';
import { Clock, getClock } from '../utils/clock';
import { BadRequestError, NotFoundError, VersionConflictError } from '../utils/httpErrors';

export class NotificationConfigurationRepository extends AbstractRepository<NotificationConfigurationItem> {
  protected readonly partitionKeyName = 'configId';
  protected readonly sortKeyName = '';

  private static readonly CONFIG_PK_NAME = 'CONFIG_CONSTANT';
  private static readonly CONFIG_PK_VALUE = 'CONFIG';
  private static readonly NAME_LOCK_PREFIX = 'NAME_LOCK#';
  private static readonly UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

  protected override readonly GSI_KEY_STRUCTURES: Record<string, string[]> = {
    NameIndex: ['name', 'configId'],
    AllConfigsIndex: [NotificationConfigurationRepository.CONFIG_PK_NAME, 'configId'],
    EnabledTypeIndex: ['enabledType', 'configId'],
  };

  constructor(
    tableName: string,
    dynamoDBClient: DynamoDBDocumentClient,
    private readonly clock: Clock = getClock(),
  ) {
    super('NotificationConfigurationRepository', tableName, dynamoDBClient);
  }

  /** Override findById for partition-key-only table (no sort key). */
  override async findById(configId: string, _: string): Promise<NotificationConfigurationItem | undefined> {
    try {
      const params = {
        TableName: this.tableName,
        Key: {
          [this.partitionKeyName]: configId,
        },
      };

      const response = await this.dynamoDBClient.send(new GetCommand(params));
      return response.Item ? (response.Item as NotificationConfigurationItem) : undefined;
    } catch (error) {
      this.logger.debug('Could not find item by ID', { partitionKey: configId, error });
      return undefined;
    }
  }

  /** Find a configuration by ID. Returns undefined if not found. */
  async findConfigById(configId: string): Promise<NotificationConfigurationItem | undefined> {
    return await this.findById(configId, '');
  }

  async getConfigById(configId: string): Promise<NotificationConfigurationItem> {
    const item = await this.findConfigById(configId);
    if (!item) {
      throw new NotFoundError(`Configuration ${configId} not found`);
    }
    return item;
  }

  /** Find all configurations. Paginates automatically to return the full set. */
  async findAll(): Promise<NotificationConfigurationItem[]> {
    return this.queryAllFromIndex(
      'AllConfigsIndex',
      NotificationConfigurationRepository.CONFIG_PK_NAME,
      NotificationConfigurationRepository.CONFIG_PK_VALUE,
    );
  }

  async findByResourceFilterId(filterId: string): Promise<NotificationConfigurationItem[]> {
    const items: NotificationConfigurationItem[] = [];
    let exclusiveStartKey: Record<string, unknown> | undefined;

    do {
      const result = await this.queryIndexWithFilter({
        indexName: 'AllConfigsIndex',
        partitionKeyName: NotificationConfigurationRepository.CONFIG_PK_NAME,
        partitionKeyValue: NotificationConfigurationRepository.CONFIG_PK_VALUE,
        filterExpression: 'contains(resourceFilterIds, :fid)',
        expressionAttributeValues: { ':fid': filterId },
        exclusiveStartKey,
      });
      items.push(...result.items);
      exclusiveStartKey = result.lastEvaluatedKey;
    } while (exclusiveStartKey);

    return items;
  }

  async findPaginated(options: {
    limit?: number;
    nextToken?: string;
  }): Promise<SearchResult<NotificationConfigurationItem>> {
    const exclusiveStartKey = this.parseNextToken(options.nextToken);

    const result = await this.queryIndexWithFilter({
      indexName: 'AllConfigsIndex',
      partitionKeyName: NotificationConfigurationRepository.CONFIG_PK_NAME,
      partitionKeyValue: NotificationConfigurationRepository.CONFIG_PK_VALUE,
      limit: options.limit,
      exclusiveStartKey,
    });

    const nextToken = result.lastEvaluatedKey
      ? Buffer.from(JSON.stringify(result.lastEvaluatedKey)).toString('base64')
      : undefined;

    return { items: result.items, nextToken };
  }

  private parseNextToken(nextToken?: string): Record<string, unknown> | undefined {
    if (!nextToken) return undefined;

    try {
      const decodedToken = Buffer.from(nextToken, 'base64').toString('utf-8');
      const parsedKey = JSON.parse(decodedToken);

      if (
        parsedKey[NotificationConfigurationRepository.CONFIG_PK_NAME] ===
          NotificationConfigurationRepository.CONFIG_PK_VALUE &&
        typeof parsedKey['configId'] === 'string' &&
        NotificationConfigurationRepository.UUID_REGEX.test(parsedKey['configId'])
      ) {
        return {
          [NotificationConfigurationRepository.CONFIG_PK_NAME]: NotificationConfigurationRepository.CONFIG_PK_VALUE,
          configId: parsedKey['configId'],
        };
      }
      throw new BadRequestError('Invalid pagination token');
    } catch (error) {
      this.logger.error('Invalid nextToken provided, starting from beginning', {
        error: error instanceof Error ? error.message : String(error),
      });
      throw new BadRequestError('Invalid pagination token');
    }
  }

  async findByType(notificationType: NotificationType): Promise<NotificationConfigurationItem[]> {
    return this.queryAllFromIndex('EnabledTypeIndex', 'enabledType', notificationType);
  }

  /** Check if a name is already taken (via GSI) */
  async findByName(name: string): Promise<NotificationConfigurationItem | undefined> {
    const result = await this.queryIndexPK({
      indexName: 'NameIndex',
      partitionKeyName: 'name',
      partitionKeyValue: name,
      limit: 1,
    });
    return result.items[0];
  }

  /**
   * Atomically reserve a name. Throws ConditionalCheckFailedException if already taken.
   * Uses a lock item with configId = "NAME_LOCK#<name>" to enforce uniqueness.
   */
  async reserveName(name: string, lockedConfigId: string): Promise<void> {
    await this.dynamoDBClient.send(
      new PutCommand({
        TableName: this.tableName,
        Item: {
          configId: `${NotificationConfigurationRepository.NAME_LOCK_PREFIX}${name}`,
          lockedConfigId,
        },
        ConditionExpression: 'attribute_not_exists(configId)',
      }),
    );
  }

  /** Release a name lock. */
  async releaseName(name: string): Promise<void> {
    await this.deleteById(`${NotificationConfigurationRepository.NAME_LOCK_PREFIX}${name}`);
  }

  async create(item: NotificationConfigurationItem, createdBy: string): Promise<void> {
    const record = this.buildRecord(item, createdBy);

    try {
      await this.dynamoDBClient.send(
        new PutCommand({
          TableName: this.tableName,
          Item: record,
          ConditionExpression: 'attribute_not_exists(configId)',
        }),
      );
    } catch (error) {
      if (error instanceof ConditionalCheckFailedException) {
        throw new Error(`Configuration with id ${item.configId} already exists`);
      }
      throw error;
    }
  }

  async updateWithVersion(
    item: NotificationConfigurationItem,
    expectedVersion: number,
    updatedBy: string,
  ): Promise<void> {
    const record = this.buildRecord(
      {
        ...item,
        version: expectedVersion + 1,
        updatedAt: this.clock.now().toISOString(),
        updatedBy,
      },
      updatedBy,
    );

    try {
      await this.dynamoDBClient.send(
        new PutCommand({
          TableName: this.tableName,
          Item: record,
          ConditionExpression: 'attribute_exists(configId) AND #v = :expectedVersion',
          ExpressionAttributeNames: { '#v': 'version' },
          ExpressionAttributeValues: { ':expectedVersion': expectedVersion },
          ReturnValuesOnConditionCheckFailure: 'ALL_OLD',
        }),
      );
    } catch (error) {
      if (error instanceof ConditionalCheckFailedException) {
        const rawItem = error.Item;
        let currentVersion: number | undefined;
        if (rawItem) {
          const versionValue = unmarshall(rawItem)['version'];
          currentVersion = typeof versionValue === 'number' ? versionValue : undefined;
        }
        throw new VersionConflictError(undefined, { currentVersion });
      }
      throw error;
    }
  }

  /** Delete a configuration by ID (partition-key-only override). */
  override async deleteById(configId: string): Promise<void> {
    await this.dynamoDBClient.send(
      new DeleteCommand({
        TableName: this.tableName,
        Key: {
          [this.partitionKeyName]: configId,
        },
      }),
    );
  }

  async deleteWithNameRelease(configId: string, expectedName: string): Promise<void> {
    await this.dynamoDBClient.send(
      new TransactWriteCommand({
        TransactItems: [
          {
            Delete: {
              TableName: this.tableName,
              Key: { [this.partitionKeyName]: configId },
              ConditionExpression: '#name = :expectedName',
              ExpressionAttributeNames: { '#name': 'name' },
              ExpressionAttributeValues: { ':expectedName': expectedName },
            },
          },
          {
            Delete: {
              TableName: this.tableName,
              Key: {
                [this.partitionKeyName]: `${NotificationConfigurationRepository.NAME_LOCK_PREFIX}${expectedName}`,
              },
            },
          },
        ],
      }),
    );
  }

  private async queryAllFromIndex(
    indexName: string,
    partitionKeyName: string,
    partitionKeyValue: string,
  ): Promise<NotificationConfigurationItem[]> {
    const allItems: NotificationConfigurationItem[] = [];
    let exclusiveStartKey: Record<string, unknown> | undefined;

    do {
      const result = await this.queryIndexPK({
        indexName,
        partitionKeyName,
        partitionKeyValue,
        exclusiveStartKey,
      });
      allItems.push(...result.items);
      exclusiveStartKey = result.lastEvaluatedKey;
    } while (exclusiveStartKey);

    return allItems;
  }

  private buildRecord(item: NotificationConfigurationItem, modifiedBy: string): Record<string, unknown> {
    const record: Record<string, unknown> = {
      ...item,
      [NotificationConfigurationRepository.CONFIG_PK_NAME]: NotificationConfigurationRepository.CONFIG_PK_VALUE,
      lastUpdatedBy: modifiedBy,
    };

    if (item.enabled) {
      record.enabledType = item.notificationType;
    } else {
      delete record.enabledType;
    }

    return record;
  }
}
