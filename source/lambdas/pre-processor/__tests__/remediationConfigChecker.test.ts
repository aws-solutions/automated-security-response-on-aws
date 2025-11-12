// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { DynamoDBDocumentClient, PutCommand, GetCommand } from '@aws-sdk/lib-dynamodb';
import { RemediationConfigChecker } from '../RemediationConfigChecker';
import { mockClient } from 'aws-sdk-client-mock';
import { DynamoDBTestSetup } from '../../common/__tests__/dynamodbSetup';
import { configTableName } from '../../common/__tests__/envSetup';
import { getLogger } from '../../common/utils/logger';

describe('RemediationConfigChecker', () => {
  const controlId = 'S3.9';
  const mockLogger = getLogger('test');
  let dynamoDBDocumentClient: DynamoDBDocumentClient;
  let checker: RemediationConfigChecker;

  beforeAll(async () => {
    dynamoDBDocumentClient = DynamoDBTestSetup.getDocClient();
    await DynamoDBTestSetup.createConfigTable(configTableName);
  });

  afterAll(async () => {
    await DynamoDBTestSetup.deleteTable(configTableName);
  });

  beforeEach(async () => {
    await DynamoDBTestSetup.clearTable(configTableName, 'config');
    checker = new RemediationConfigChecker(controlId, dynamoDBDocumentClient, configTableName, mockLogger);
  });

  describe('isSupported', () => {
    it('returns true when item exists', async () => {
      await dynamoDBDocumentClient.send(
        new PutCommand({
          TableName: configTableName,
          Item: { controlId, automatedRemediationEnabled: true },
        }),
      );

      const result = await checker.isSupported();
      expect(result).toBe(true);
    });

    it('returns false when item does not exist', async () => {
      checker = new RemediationConfigChecker('EC2.99', dynamoDBDocumentClient, configTableName, mockLogger);

      const result = await checker.isSupported();
      expect(result).toBe(false);
    });
  });

  describe('isAutomatedRemediationEnabled', () => {
    it('returns true when enabled', async () => {
      await dynamoDBDocumentClient.send(
        new PutCommand({
          TableName: configTableName,
          Item: { controlId, automatedRemediationEnabled: true },
        }),
      );

      const result = await checker.isAutomatedRemediationEnabled();
      expect(result).toBe(true);
    });

    it('returns false when disabled', async () => {
      await dynamoDBDocumentClient.send(
        new PutCommand({
          TableName: configTableName,
          Item: { controlId, automatedRemediationEnabled: false },
        }),
      );

      const result = await checker.isAutomatedRemediationEnabled();
      expect(result).toBe(false);
    });

    it('returns false when item does not exist', async () => {
      const result = await checker.isAutomatedRemediationEnabled();
      expect(result).toBe(false);
    });
  });

  describe('caching', () => {
    it('caches results for multiple method calls', async () => {
      await dynamoDBDocumentClient.send(
        new PutCommand({
          TableName: configTableName,
          Item: { controlId, automatedRemediationEnabled: true },
        }),
      );

      const result1 = await checker.isSupported();
      const result2 = await checker.isAutomatedRemediationEnabled();

      expect(result1).toBe(true);
      expect(result2).toBe(true);
    });
  });

  describe('error handling', () => {
    it('throws error when DynamoDB operation fails with non-ResourceNotFoundException', async () => {
      const ddbMock = mockClient(DynamoDBDocumentClient);
      ddbMock.on(GetCommand).rejects(new Error('DynamoDB service error'));

      const errorChecker = new RemediationConfigChecker('TEST.1', ddbMock as any, configTableName, mockLogger);

      await expect(errorChecker.isSupported()).rejects.toThrow('DynamoDB service error');

      ddbMock.restore();
    });
  });
});
