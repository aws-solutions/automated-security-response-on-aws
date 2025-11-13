// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import {
  CognitoIdentityProviderClient,
  AdminGetUserCommand,
  AdminListGroupsForUserCommand,
} from '@aws-sdk/client-cognito-identity-provider';
import { DynamoDBDocumentClient, PutCommand } from '@aws-sdk/lib-dynamodb';
import { mockClient } from 'aws-sdk-client-mock';
import { DynamoDBTestSetup } from '../../../common/__tests__/dynamodbSetup';
import { findingsTableName } from '../../../common/__tests__/envSetup';
import { searchRemediations } from '../../handlers/remediations';
import { API_HEADERS } from '../../handlers/apiHandler';
import { createMockContext, createMockEvent, TEST_REQUEST_CONTEXT } from '../utils';

const cognitoMock = mockClient(CognitoIdentityProviderClient);

describe('RemediationsHandler Integration Tests', () => {
  let dynamoDBDocumentClient: DynamoDBDocumentClient;
  const remediationHistoryTableName = 'test-remediation-history-table';
  const userAccountMappingTableName = 'test-user-account-mapping-table';

  beforeAll(async () => {
    await DynamoDBTestSetup.initialize();
    dynamoDBDocumentClient = DynamoDBTestSetup.getDocClient();
    await DynamoDBTestSetup.createFindingsTable(findingsTableName);
    await DynamoDBTestSetup.createRemediationHistoryTable(remediationHistoryTableName);
    await DynamoDBTestSetup.createUserAccountMappingTable(userAccountMappingTableName);
  });

  afterAll(async () => {
    await DynamoDBTestSetup.deleteTable(findingsTableName);
    await DynamoDBTestSetup.deleteTable(remediationHistoryTableName);
    await DynamoDBTestSetup.deleteTable(userAccountMappingTableName);
  });

  afterEach(() => {
    cognitoMock.reset();
    delete process.env.FINDINGS_TABLE_NAME;
    delete process.env.REMEDIATION_HISTORY_TABLE_NAME;
    delete process.env.USER_ACCOUNT_MAPPING_TABLE_NAME;
    delete process.env.USER_POOL_ID;
    delete process.env.ORCHESTRATOR_ARN;
  });

  beforeEach(async () => {
    await DynamoDBTestSetup.clearTable(findingsTableName, 'findings');
    await DynamoDBTestSetup.clearTable(remediationHistoryTableName, 'remediationHistory');
    await DynamoDBTestSetup.clearTable(userAccountMappingTableName, 'userAccountMapping');
    process.env.FINDINGS_TABLE_NAME = findingsTableName;
    process.env.REMEDIATION_HISTORY_TABLE_NAME = remediationHistoryTableName;
    process.env.USER_ACCOUNT_MAPPING_TABLE_NAME = userAccountMappingTableName;
    process.env.USER_POOL_ID = 'test-user-pool-id';
    process.env.ORCHESTRATOR_ARN = 'arn:aws:states:us-east-1:123456789012:stateMachine:test-orchestrator';

    cognitoMock.reset();

    cognitoMock.on(AdminGetUserCommand).resolves({
      Username: 'admin-user@example.com',
      UserAttributes: [
        { Name: 'email', Value: 'admin-user@example.com' },
        { Name: 'custom:invitedBy', Value: 'system@example.com' },
      ],
      UserCreateDate: new Date(),
      UserStatus: 'CONFIRMED',
    });

    cognitoMock.on(AdminListGroupsForUserCommand).resolves({
      Groups: [{ GroupName: 'AdminGroup' }],
    });
  });

  describe('searchRemediations', () => {
    it('should return 200 with empty remediations when no data exists', async () => {
      const requestBody = {
        SortCriteria: [
          {
            Field: 'lastUpdatedTime',
            SortOrder: 'desc',
          },
        ],
      };

      const event = createMockEvent({
        httpMethod: 'POST',
        path: '/remediations',
        headers: {
          'Content-Type': 'application/json',
          authorization: 'Bearer valid-token',
        },
        body: JSON.stringify(requestBody),
        requestContext: {
          ...TEST_REQUEST_CONTEXT,
          authorizer: {
            claims: {
              'cognito:groups': ['AdminGroup'],
              username: 'admin-user@example.com',
            },
          },
        },
      });
      const context = createMockContext();

      const result = await searchRemediations(event, context);

      expect(result.statusCode).toBe(200);
      expect(result.headers).toEqual(API_HEADERS.REMEDIATIONS);

      const body = JSON.parse(result.body);
      expect(body.Remediations).toEqual([]);
      expect(body.NextToken).toBeUndefined();
    });

    it('should return 200 with remediations when data exists', async () => {
      const remediationItem = {
        findingType: 'security-control/Lambda.3',
        findingId: 'arn:aws:securityhub:us-east-1:123456789012:security-control/Lambda.3/finding/test-remediation',
        'findingId#executionId':
          'arn:aws:securityhub:us-east-1:123456789012:security-control/Lambda.3/finding/test-remediation#arn:aws:states:us-east-1:123456789012:execution:TestStateMachine:exec-123',
        accountId: '123456789012',
        resourceId: 'arn:aws:lambda:us-east-1:123456789012:function:test-function',
        resourceType: 'AWS::Lambda::Function',
        severity: 'HIGH',
        region: 'us-east-1',
        remediationStatus: 'SUCCESS',
        lastUpdatedTime: '2023-01-01T00:00:00Z',
        'lastUpdatedTime#findingId':
          '2023-01-01T00:00:00Z#arn:aws:securityhub:us-east-1:123456789012:security-control/Lambda.3/finding/test-remediation',
        REMEDIATION_CONSTANT: 'remediation',
        lastUpdatedBy: 'admin-user@example.com',
        executionId: 'arn:aws:states:us-east-1:123456789012:execution:TestStateMachine:exec-123',
        expireAt: Math.floor(Date.now() / 1000) + 90 * 24 * 60 * 60, // 90 days from now
      };

      await dynamoDBDocumentClient.send(
        new PutCommand({
          TableName: remediationHistoryTableName,
          Item: remediationItem,
        }),
      );

      const requestBody = {
        SortCriteria: [
          {
            Field: 'lastUpdatedTime',
            SortOrder: 'desc',
          },
        ],
      };

      const event = createMockEvent({
        httpMethod: 'POST',
        path: '/remediations',
        headers: {
          'Content-Type': 'application/json',
          authorization: 'Bearer valid-token',
        },
        body: JSON.stringify(requestBody),
        requestContext: {
          ...TEST_REQUEST_CONTEXT,
          authorizer: {
            claims: {
              'cognito:groups': ['AdminGroup'],
              username: 'admin-user@example.com',
            },
          },
        },
      });
      const context = createMockContext();

      const result = await searchRemediations(event, context);

      expect(result.statusCode).toBe(200);
      expect(result.headers).toEqual(API_HEADERS.REMEDIATIONS);

      const body = JSON.parse(result.body);
      expect(body.Remediations).toHaveLength(1);
      expect(body.Remediations[0]).toHaveProperty('findingId');
      expect(body.Remediations[0]).toHaveProperty('accountId', '123456789012');
      expect(body.Remediations[0]).toHaveProperty('remediationStatus', 'SUCCESS');
      expect(body.Remediations[0]).toHaveProperty('severity', 'HIGH');

      expect(body.Remediations[0]).not.toHaveProperty('findingId#executionId');
      expect(body.Remediations[0]).not.toHaveProperty('lastUpdatedTime#findingId');
      expect(body.Remediations[0]).not.toHaveProperty('REMEDIATION_CONSTANT');
      expect(body.Remediations[0]).not.toHaveProperty('expireAt');
    });

    it('should filter remediations by accountId', async () => {
      const remediation1 = {
        findingType: 'security-control/Lambda.3',
        findingId: 'arn:aws:securityhub:us-east-1:123456789012:security-control/Lambda.3/finding/test-1',
        'findingId#executionId':
          'arn:aws:securityhub:us-east-1:123456789012:security-control/Lambda.3/finding/test-1#exec-1',
        accountId: '123456789012',
        resourceId: 'arn:aws:lambda:us-east-1:123456789012:function:test-1',
        resourceType: 'AWS::Lambda::Function',
        severity: 'HIGH',
        region: 'us-east-1',
        remediationStatus: 'SUCCESS',
        lastUpdatedTime: '2023-01-01T00:00:00Z',
        'lastUpdatedTime#findingId':
          '2023-01-01T00:00:00Z#arn:aws:securityhub:us-east-1:123456789012:security-control/Lambda.3/finding/test-1',
        REMEDIATION_CONSTANT: 'remediation',
        lastUpdatedBy: 'admin-user@example.com',
        executionId: 'exec-1',
        expireAt: Math.floor(Date.now() / 1000) + 90 * 24 * 60 * 60,
      };

      const remediation2 = {
        findingType: 'security-control/Lambda.3',
        findingId: 'arn:aws:securityhub:us-east-1:987654321098:security-control/Lambda.3/finding/test-2',
        'findingId#executionId':
          'arn:aws:securityhub:us-east-1:987654321098:security-control/Lambda.3/finding/test-2#exec-2',
        accountId: '987654321098',
        resourceId: 'arn:aws:lambda:us-east-1:987654321098:function:test-2',
        resourceType: 'AWS::Lambda::Function',
        severity: 'MEDIUM',
        region: 'us-east-1',
        remediationStatus: 'FAILED',
        lastUpdatedTime: '2023-01-02T00:00:00Z',
        'lastUpdatedTime#findingId':
          '2023-01-02T00:00:00Z#arn:aws:securityhub:us-east-1:987654321098:security-control/Lambda.3/finding/test-2',
        REMEDIATION_CONSTANT: 'remediation',
        lastUpdatedBy: 'admin-user@example.com',
        executionId: 'exec-2',
        expireAt: Math.floor(Date.now() / 1000) + 90 * 24 * 60 * 60,
      };

      await Promise.all([
        dynamoDBDocumentClient.send(new PutCommand({ TableName: remediationHistoryTableName, Item: remediation1 })),
        dynamoDBDocumentClient.send(new PutCommand({ TableName: remediationHistoryTableName, Item: remediation2 })),
      ]);

      const requestBody = {
        Filters: {
          CompositeFilters: [
            {
              Operator: 'AND',
              StringFilters: [
                {
                  FieldName: 'accountId',
                  Filter: {
                    Value: '123456789012',
                    Comparison: 'EQUALS',
                  },
                },
              ],
            },
          ],
        },
        SortCriteria: [
          {
            Field: 'lastUpdatedTime',
            SortOrder: 'desc',
          },
        ],
      };

      const event = createMockEvent({
        httpMethod: 'POST',
        path: '/remediations',
        headers: {
          'Content-Type': 'application/json',
          authorization: 'Bearer valid-token',
        },
        body: JSON.stringify(requestBody),
        requestContext: {
          ...TEST_REQUEST_CONTEXT,
          authorizer: {
            claims: {
              'cognito:groups': ['AdminGroup'],
              username: 'admin-user@example.com',
            },
          },
        },
      });
      const context = createMockContext();

      const result = await searchRemediations(event, context);

      expect(result.statusCode).toBe(200);
      const body = JSON.parse(result.body);
      expect(body.Remediations).toHaveLength(1);
      expect(body.Remediations[0].accountId).toBe('123456789012');
    });

    it('should throw UnauthorizedError when claims are missing', async () => {
      const event = createMockEvent({
        httpMethod: 'POST',
        path: '/remediations',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({}),
        requestContext: {
          ...TEST_REQUEST_CONTEXT,
          authorizer: {
            claims: null,
          },
        },
      });
      const context = createMockContext();

      await expect(searchRemediations(event, context)).rejects.toThrow(
        "Cannot read properties of null (reading 'cognito:groups')",
      );
    });

    it('should throw BadRequestError when request validation fails', async () => {
      const requestBody = {
        Filters: {
          CompositeFilters: [
            {
              Operator: 'INVALID_OPERATOR', // Invalid operator
              StringFilters: [],
            },
          ],
        },
      };

      const event = createMockEvent({
        httpMethod: 'POST',
        path: '/remediations',
        headers: {
          'Content-Type': 'application/json',
          authorization: 'Bearer valid-token',
        },
        body: JSON.stringify(requestBody),
        requestContext: {
          ...TEST_REQUEST_CONTEXT,
          authorizer: {
            claims: {
              'cognito:groups': ['AdminGroup'],
              username: 'admin-user@example.com',
            },
          },
        },
      });
      const context = createMockContext();

      await expect(searchRemediations(event, context)).rejects.toThrow('Invalid request');
    });
  });
});
