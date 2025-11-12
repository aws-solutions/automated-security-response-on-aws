// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import {
  CreateTableCommand,
  DeleteTableCommand,
  DescribeTableCommand,
  ListTablesCommand,
  waitUntilTableExists,
  waitUntilTableNotExists,
} from '@aws-sdk/client-dynamodb';
import { DeleteCommand, DynamoDBDocumentClient, ScanCommand } from '@aws-sdk/lib-dynamodb';
import { createDynamoDBClient } from '../utils/dynamodb';

export class DynamoDBTestSetup {
  private static docClient: DynamoDBDocumentClient;

  static async initialize() {
    this.docClient = createDynamoDBClient({
      endpoint: 'http://127.0.0.1:8000',
      region: 'us-east-1',
      credentials: {
        accessKeyId: 'fakeMyKeyId',
        secretAccessKey: 'fakeSecretAccessKey',
      },
    });
  }

  static getDocClient(): DynamoDBDocumentClient {
    return this.docClient;
  }

  static async createFindingsTable(tableName: string) {
    if (!this.docClient) {
      throw new Error('DynamoDBTestSetup not initialized. Call DynamoDBTestSetup.initialize() first.');
    }
    if (await this.tableExists(tableName)) return;

    await this.docClient.send(
      new CreateTableCommand({
        TableName: tableName,
        KeySchema: [
          { AttributeName: 'findingType', KeyType: 'HASH' },
          { AttributeName: 'findingId', KeyType: 'RANGE' },
        ],
        AttributeDefinitions: [
          { AttributeName: 'findingType', AttributeType: 'S' },
          { AttributeName: 'findingId', AttributeType: 'S' },
          { AttributeName: 'accountId', AttributeType: 'S' },
          { AttributeName: 'resourceId', AttributeType: 'S' },
          { AttributeName: 'severity', AttributeType: 'S' },
          { AttributeName: 'FINDING_CONSTANT', AttributeType: 'S' },
          { AttributeName: 'securityHubUpdatedAtTime#findingId', AttributeType: 'S' },
        ],
        LocalSecondaryIndexes: [
          {
            IndexName: 'securityHubUpdatedAtTime-findingId-LSI',
            KeySchema: [
              { AttributeName: 'findingType', KeyType: 'HASH' },
              { AttributeName: 'securityHubUpdatedAtTime#findingId', KeyType: 'RANGE' },
            ],
            Projection: { ProjectionType: 'ALL' },
          },
        ],
        GlobalSecondaryIndexes: [
          {
            IndexName: 'accountId-securityHubUpdatedAtTime-GSI',
            KeySchema: [
              { AttributeName: 'accountId', KeyType: 'HASH' },
              { AttributeName: 'securityHubUpdatedAtTime#findingId', KeyType: 'RANGE' },
            ],
            Projection: { ProjectionType: 'ALL' },
          },
          {
            IndexName: 'resourceId-securityHubUpdatedAtTime-GSI',
            KeySchema: [
              { AttributeName: 'resourceId', KeyType: 'HASH' },
              { AttributeName: 'securityHubUpdatedAtTime#findingId', KeyType: 'RANGE' },
            ],
            Projection: { ProjectionType: 'ALL' },
          },
          {
            IndexName: 'severity-securityHubUpdatedAtTime-GSI',
            KeySchema: [
              { AttributeName: 'severity', KeyType: 'HASH' },
              { AttributeName: 'securityHubUpdatedAtTime#findingId', KeyType: 'RANGE' },
            ],
            Projection: { ProjectionType: 'ALL' },
          },
          {
            IndexName: 'allFindings-securityHubUpdatedAtTime-GSI',
            KeySchema: [
              { AttributeName: 'FINDING_CONSTANT', KeyType: 'HASH' },
              { AttributeName: 'securityHubUpdatedAtTime#findingId', KeyType: 'RANGE' },
            ],
            Projection: { ProjectionType: 'ALL' },
          },
        ],
        BillingMode: 'PAY_PER_REQUEST',
      }),
    );

    await waitUntilTableExists({ client: this.docClient, maxWaitTime: 30 }, { TableName: tableName });
  }

  static async createConfigTable(tableName: string) {
    if (!this.docClient) {
      throw new Error('DynamoDBTestSetup not initialized. Call DynamoDBTestSetup.initialize() first.');
    }
    if (await this.tableExists(tableName)) return;

    await this.docClient.send(
      new CreateTableCommand({
        TableName: tableName,
        KeySchema: [{ AttributeName: 'controlId', KeyType: 'HASH' }],
        AttributeDefinitions: [{ AttributeName: 'controlId', AttributeType: 'S' }],
        BillingMode: 'PAY_PER_REQUEST',
      }),
    );

    await waitUntilTableExists({ client: this.docClient, maxWaitTime: 30 }, { TableName: tableName });
  }

  static async createUserAccountMappingTable(tableName: string) {
    if (await this.tableExists(tableName)) return;

    await this.docClient.send(
      new CreateTableCommand({
        TableName: tableName,
        KeySchema: [{ AttributeName: 'userId', KeyType: 'HASH' }],
        AttributeDefinitions: [{ AttributeName: 'userId', AttributeType: 'S' }],
        BillingMode: 'PAY_PER_REQUEST',
      }),
    );

    await waitUntilTableExists({ client: this.docClient, maxWaitTime: 30 }, { TableName: tableName });
  }

  static async createRemediationHistoryTable(tableName: string) {
    if (await this.tableExists(tableName)) return;

    await this.docClient.send(
      new CreateTableCommand({
        TableName: tableName,
        KeySchema: [
          { AttributeName: 'findingType', KeyType: 'HASH' },
          { AttributeName: 'findingId#executionId', KeyType: 'RANGE' },
        ],
        AttributeDefinitions: [
          { AttributeName: 'findingType', AttributeType: 'S' },
          { AttributeName: 'findingId#executionId', AttributeType: 'S' },
          { AttributeName: 'findingId', AttributeType: 'S' },
          { AttributeName: 'accountId', AttributeType: 'S' },
          { AttributeName: 'resourceId', AttributeType: 'S' },
          { AttributeName: 'REMEDIATION_CONSTANT', AttributeType: 'S' },
          { AttributeName: 'lastUpdatedTime#findingId', AttributeType: 'S' },
        ],
        GlobalSecondaryIndexes: [
          {
            IndexName: 'lastUpdatedTime-findingIdIndex',
            KeySchema: [
              { AttributeName: 'findingType', KeyType: 'HASH' },
              { AttributeName: 'lastUpdatedTime#findingId', KeyType: 'RANGE' },
            ],
            Projection: { ProjectionType: 'ALL' },
          },
          {
            IndexName: 'allRemediations-lastUpdatedTime-GSI',
            KeySchema: [
              { AttributeName: 'REMEDIATION_CONSTANT', KeyType: 'HASH' },
              { AttributeName: 'lastUpdatedTime#findingId', KeyType: 'RANGE' },
            ],
            Projection: { ProjectionType: 'ALL' },
          },
          {
            IndexName: 'accountId-lastUpdatedTime-GSI',
            KeySchema: [
              { AttributeName: 'accountId', KeyType: 'HASH' },
              { AttributeName: 'lastUpdatedTime#findingId', KeyType: 'RANGE' },
            ],
            Projection: { ProjectionType: 'ALL' },
          },
          {
            IndexName: 'resourceId-lastUpdatedTime-GSI',
            KeySchema: [
              { AttributeName: 'resourceId', KeyType: 'HASH' },
              { AttributeName: 'lastUpdatedTime#findingId', KeyType: 'RANGE' },
            ],
            Projection: { ProjectionType: 'ALL' },
          },
          {
            IndexName: 'findingId-lastUpdatedTime-GSI',
            KeySchema: [
              { AttributeName: 'findingId', KeyType: 'HASH' },
              { AttributeName: 'lastUpdatedTime#findingId', KeyType: 'RANGE' },
            ],
            Projection: { ProjectionType: 'ALL' },
          },
        ],
        BillingMode: 'PAY_PER_REQUEST',
      }),
    );

    await waitUntilTableExists({ client: this.docClient, maxWaitTime: 30 }, { TableName: tableName });
  }

  static async deleteTable(tableName: string) {
    if (!(await this.tableExists(tableName))) return;

    await this.docClient.send(new DeleteTableCommand({ TableName: tableName }));
    await waitUntilTableNotExists({ client: this.docClient, maxWaitTime: 30 }, { TableName: tableName });
  }

  static async cleanup() {
    const response = await this.docClient.send(new ListTablesCommand({}));
    const { TableNames } = response || {};
    if (TableNames && TableNames.length > 0) {
      await Promise.all(TableNames.map((tableName) => this.deleteTable(tableName)));
    }
  }

  static async tableExists(tableName: string): Promise<boolean> {
    if (!this.docClient) {
      throw new Error('DynamoDBTestSetup not initialized. Call DynamoDBTestSetup.initialize() first.');
    }
    try {
      await this.docClient.send(new DescribeTableCommand({ TableName: tableName }));
      return true;
    } catch (error: any) {
      if (error.name === 'ResourceNotFoundException') {
        return false;
      }
      throw error;
    }
  }

  static async clearTable(
    tableName: string,
    tableType: 'findings' | 'config' | 'userAccountMapping' | 'remediationHistory',
  ) {
    if (!(await this.tableExists(tableName))) return;

    const scanResult = await this.docClient.send(new ScanCommand({ TableName: tableName }));
    const { Items } = scanResult || { Items: [] };
    if (Items && Items.length > 0) {
      for (const item of Items) {
        let key;
        if (tableType === 'findings') {
          key = { findingType: item.findingType, findingId: item.findingId };
        } else if (tableType === 'remediationHistory') {
          key = { findingType: item.findingType, 'findingId#executionId': item['findingId#executionId'] };
        } else if (tableType === 'userAccountMapping') {
          key = { userId: item.userId };
        } else {
          key = { controlId: item.controlId };
        }
        await this.docClient.send(new DeleteCommand({ TableName: tableName, Key: key }));
      }
    }
  }
}
