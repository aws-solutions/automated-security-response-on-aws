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

  describe('getControlConfig', () => {
    it('returns full config with filters and filterMode', async () => {
      await dynamoDBDocumentClient.send(
        new PutCommand({
          TableName: configTableName,
          Item: {
            controlId,
            automatedRemediationEnabled: true,
            filters: new Set(['filter-1', 'filter-2']),
            filterMode: 'include',
          },
        }),
      );

      const result = await checker.getControlConfig();
      expect(result).toEqual({
        automatedRemediationEnabled: true,
        filters: expect.arrayContaining(['filter-1', 'filter-2']),
        filterMode: 'include',
      });
      expect(result?.filters).toHaveLength(2);
    });

    it('returns default filterMode when not set', async () => {
      await dynamoDBDocumentClient.send(
        new PutCommand({
          TableName: configTableName,
          Item: { controlId, automatedRemediationEnabled: true },
        }),
      );

      const result = await checker.getControlConfig();
      expect(result).toEqual({
        automatedRemediationEnabled: true,
        filters: [],
        filterMode: 'include',
      });
    });

    it('returns empty filters array when filters not set', async () => {
      await dynamoDBDocumentClient.send(
        new PutCommand({
          TableName: configTableName,
          Item: { controlId, automatedRemediationEnabled: false, filterMode: 'exclude' },
        }),
      );

      const result = await checker.getControlConfig();
      expect(result).toEqual({
        automatedRemediationEnabled: false,
        filters: [],
        filterMode: 'exclude',
      });
    });

    it('returns null when item does not exist', async () => {
      checker = new RemediationConfigChecker('EC2.99', dynamoDBDocumentClient, configTableName, mockLogger);
      const result = await checker.getControlConfig();
      expect(result).toBeNull();
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

    it('treats a blank control id as unsupported without calling DynamoDB', async () => {
      // ARRANGE: a finding that resolved to no control id (e.g. Patch Manager).
      // DynamoDB would reject an empty key with a ValidationException, so the
      // checker must short-circuit before issuing any GetCommand.
      const ddbMock = mockClient(DynamoDBDocumentClient);
      const blankChecker = new RemediationConfigChecker('', ddbMock as any, configTableName, mockLogger);

      // ACT
      const supported = await blankChecker.isSupported();
      const autoEnabled = await blankChecker.isAutomatedRemediationEnabled();
      const config = await blankChecker.getControlConfig();

      // ASSERT: reported unsupported, and no DynamoDB call was made
      expect(supported).toBe(false);
      expect(autoEnabled).toBe(false);
      expect(config).toBeNull();
      expect(ddbMock.commandCalls(GetCommand)).toHaveLength(0);

      ddbMock.restore();
    });

    it('logs warning and returns null when item exists but fails type validation', async () => {
      // ARRANGE: Insert an item missing the required 'automatedRemediationEnabled' field
      await dynamoDBDocumentClient.send(
        new PutCommand({
          TableName: configTableName,
          Item: { controlId, someOtherField: 'value' },
        }),
      );
      const warnSpy = jest.spyOn(mockLogger, 'warn');

      // ACT
      const result = await checker.isSupported();

      // ASSERT
      expect(result).toBe(false);
      expect(warnSpy).toHaveBeenCalledWith(
        expect.stringContaining('failed type validation'),
        expect.objectContaining({ controlId }),
      );
      warnSpy.mockRestore();
    });
  });
});
