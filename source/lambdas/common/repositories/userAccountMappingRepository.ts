// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { DynamoDBDocumentClient, GetCommand, DeleteCommand } from '@aws-sdk/lib-dynamodb';
import { AbstractRepository } from './abstractRepository';
import { UserAccountMapping, userAccountIds } from '@asr/data-models';
import { ResourceNotFoundException } from '@aws-sdk/client-dynamodb';

export class UserAccountMappingRepository extends AbstractRepository<UserAccountMapping> {
  protected readonly partitionKeyName = 'userId';
  protected readonly sortKeyName = ''; // this table does not have a sort key

  constructor(principal: string, tableName: string, dynamoDBClient: DynamoDBDocumentClient) {
    super(principal, tableName, dynamoDBClient);
  }

  async getUserAccounts(userId: string): Promise<userAccountIds | undefined> {
    const item = await this.findById(userId, '');
    if (!item)
      this.logger.warn(
        `Could not find user account mapping for user ${userId} in table ${this.tableName}. This user should be removed and re-invited if necessary.`,
      );
    return item?.accountIds;
  }

  async create(userAccountMapping: UserAccountMapping): Promise<void> {
    await this.put(userAccountMapping);
  }

  async deleteIfExists(userId: string, _: string): Promise<void> {
    try {
      await this.dynamoDBClient.send(
        new DeleteCommand({
          TableName: this.tableName,
          Key: {
            [this.partitionKeyName]: userId,
          },
        }),
      );
    } catch (error) {
      if (error instanceof ResourceNotFoundException) {
        this.logger.debug(
          `Could not find user account mapping to delete for user ${userId} in table ${this.tableName}.`,
        );
        return;
      }
      throw error;
    }
  }

  override async put(item: UserAccountMapping): Promise<void> {
    const itemWithTimestamp = {
      ...item,
      lastModifiedBy: this.principal,
      lastModifiedTimestamp: new Date().toISOString(),
    };
    return await super.putUntyped(itemWithTimestamp);
  }

  override async findById(userId: string, _: string): Promise<UserAccountMapping | undefined> {
    try {
      const params = {
        TableName: this.tableName,
        Key: {
          [this.partitionKeyName]: userId,
        },
      };

      const response = await this.dynamoDBClient.send(new GetCommand(params));
      const item = response.Item;

      if (!item) {
        return undefined;
      }

      delete (item as any).lastUpdatedBy;
      return item as UserAccountMapping;
    } catch (error) {
      this.logger.debug('Could not find item by ID', { partitionKey: userId });
      return undefined;
    }
  }
}
