// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import {
  CognitoIdentityProviderClient,
  AdminGetUserCommand,
  AdminListGroupsForUserCommand,
} from '@aws-sdk/client-cognito-identity-provider';
import { DynamoDBDocumentClient, PutCommand, GetCommand } from '@aws-sdk/lib-dynamodb';
import { mockClient } from 'aws-sdk-client-mock';
import { SNSClient, PublishCommand } from '@aws-sdk/client-sns';
import { APIGatewayProxyEvent } from 'aws-lambda';
import { AdminActivityNotification } from '../../services/adminActivityNotifier';
import { SecurityControl } from '@asr/data-models';
import { DynamoDBTestSetup } from '../../../common/__tests__/dynamodbSetup';
import {
  customRunbookTableName,
  remediationConfigTableName,
  userAccountMappingTableName,
} from '../../../common/__tests__/envSetup';
import {
  setupMetricsMocks,
  cleanupMetricsMocks,
  createMetricsTestScope,
} from '../../../common/__tests__/metricsMockSetup';
import { getControls, bulkEditControls } from '../../handlers/controls';
import { createMockContext, createMockEvent, TEST_REQUEST_CONTEXT } from '../utils';

const cognitoMock = mockClient(CognitoIdentityProviderClient);
const snsMock = mockClient(SNSClient);

// The admin activity notifier is the only code path that issues an SNS PublishCommand, so the
// published message can be read back from the SNS boundary to verify what the handler emitted.
function publishedAdminNotifications(): AdminActivityNotification[] {
  return snsMock
    .commandCalls(PublishCommand)
    .map((call) => JSON.parse(call.args[0].input.Message as string) as AdminActivityNotification);
}

describe('ControlsHandler Integration Tests', () => {
  let dynamoDBDocumentClient: DynamoDBDocumentClient;

  beforeAll(async () => {
    await DynamoDBTestSetup.initialize();
    dynamoDBDocumentClient = DynamoDBTestSetup.getDocClient();
    await DynamoDBTestSetup.createConfigTable(remediationConfigTableName);
    await DynamoDBTestSetup.createUserAccountMappingTable(userAccountMappingTableName);
  });

  afterAll(async () => {
    await DynamoDBTestSetup.deleteTable(remediationConfigTableName);
    await DynamoDBTestSetup.deleteTable(userAccountMappingTableName);
    cleanupMetricsMocks();
  });

  beforeEach(async () => {
    await DynamoDBTestSetup.clearTable(remediationConfigTableName, 'config');
    await DynamoDBTestSetup.clearTable(userAccountMappingTableName, 'userAccountMapping');

    snsMock.reset();
    snsMock.on(PublishCommand).resolves({ MessageId: 'admin-notification' });
    cognitoMock.reset();
    setupMetricsMocks();

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

  describe('getControls', () => {
    it('should return 200 with empty controls when no data exists', async () => {
      // ARRANGE
      const event = createMockEvent({
        httpMethod: 'GET',
        path: '/controls',
        headers: {
          'Content-Type': 'application/json',
          authorization: 'Bearer valid-token',
        },
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

      // ACT
      const result = await getControls(event, context);

      // ASSERT
      expect(result.statusCode).toBe(200);
      const body = JSON.parse(result.body);
      expect(body.controls).toEqual([]);
    });

    it('should return 200 with controls when data exists', async () => {
      // ARRANGE
      const controlItem = {
        controlId: 'S3.1',
        description: 'S3 Block Public Access setting should be enabled',
        automatedRemediationEnabled: true,
        filters: new Set(['filter-uuid-123']),
        filterMode: 'include',
        version: 1,
        lastModified: '2024-01-01T00:00:00Z',
        modifiedBy: 'admin-user@example.com',
      };

      await dynamoDBDocumentClient.send(
        new PutCommand({
          TableName: remediationConfigTableName,
          Item: controlItem,
        }),
      );

      const event = createMockEvent({
        httpMethod: 'GET',
        path: '/controls',
        headers: {
          'Content-Type': 'application/json',
          authorization: 'Bearer valid-token',
        },
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

      // ACT
      const result = await getControls(event, context);

      // ASSERT
      expect(result.statusCode).toBe(200);
      const body = JSON.parse(result.body);
      expect(body.controls).toHaveLength(1);
      expect(body.controls[0]).toEqual({
        controlId: 'S3.1',
        description: 'S3 Block Public Access setting should be enabled',
        automatedRemediationEnabled: true,
        filters: ['filter-uuid-123'],
        filterMode: 'include',
        version: 1,
        lastModified: '2024-01-01T00:00:00Z',
        modifiedBy: 'admin-user@example.com',
        rollbackSupported: false,
        source: 'builtin',
      });
    });

    it('should return controls with default values when optional fields are missing', async () => {
      // ARRANGE
      const controlItem = {
        controlId: 'EC2.1',
        description: 'EC2 instances should use IMDSv2',
        automatedRemediationEnabled: false,
        version: 1,
      };

      await dynamoDBDocumentClient.send(
        new PutCommand({
          TableName: remediationConfigTableName,
          Item: controlItem,
        }),
      );

      const event = createMockEvent({
        httpMethod: 'GET',
        path: '/controls',
        headers: {
          'Content-Type': 'application/json',
          authorization: 'Bearer valid-token',
        },
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

      // ACT
      const result = await getControls(event, context);

      // ASSERT
      expect(result.statusCode).toBe(200);
      const body = JSON.parse(result.body);
      expect(body.controls).toHaveLength(1);
      expect(body.controls[0]).toEqual({
        controlId: 'EC2.1',
        description: 'EC2 instances should use IMDSv2',
        automatedRemediationEnabled: false,
        filters: [],
        filterMode: 'include',
        version: 1,
        lastModified: '',
        modifiedBy: '',
        rollbackSupported: false,
        source: 'builtin',
      });
    });

    it('should allow AccountOperator to read controls', async () => {
      // ARRANGE
      const controlItem = {
        controlId: 'Lambda.1',
        description: 'Lambda functions should prohibit public access',
        automatedRemediationEnabled: true,
        version: 1,
      };

      await dynamoDBDocumentClient.send(
        new PutCommand({
          TableName: remediationConfigTableName,
          Item: controlItem,
        }),
      );

      cognitoMock.reset();
      cognitoMock.on(AdminGetUserCommand).resolves({
        Username: 'operator@example.com',
        UserAttributes: [
          { Name: 'email', Value: 'operator@example.com' },
          { Name: 'custom:invitedBy', Value: 'admin@example.com' },
        ],
        UserCreateDate: new Date(),
        UserStatus: 'CONFIRMED',
      });

      cognitoMock.on(AdminListGroupsForUserCommand).resolves({
        Groups: [{ GroupName: 'AccountOperatorGroup' }],
      });

      await dynamoDBDocumentClient.send(
        new PutCommand({
          TableName: userAccountMappingTableName,
          Item: {
            userId: 'operator@example.com',
            accountIds: ['123456789012'],
          },
        }),
      );

      const event = createMockEvent({
        httpMethod: 'GET',
        path: '/controls',
        headers: {
          'Content-Type': 'application/json',
          authorization: 'Bearer valid-token',
        },
        requestContext: {
          ...TEST_REQUEST_CONTEXT,
          authorizer: {
            claims: {
              'cognito:groups': ['AccountOperatorGroup'],
              username: 'operator@example.com',
            },
          },
        },
      });
      const context = createMockContext();

      // ACT
      const result = await getControls(event, context);

      // ASSERT
      expect(result.statusCode).toBe(200);
      const body = JSON.parse(result.body);
      expect(body.controls).toHaveLength(1);
    });

    it('should throw ForbiddenError when user has no valid groups', async () => {
      // ARRANGE
      const event = createMockEvent({
        httpMethod: 'GET',
        path: '/controls',
        headers: {
          'Content-Type': 'application/json',
          authorization: 'Bearer valid-token',
        },
        requestContext: {
          ...TEST_REQUEST_CONTEXT,
          authorizer: {
            claims: {
              'cognito:groups': ['UnknownGroup'],
              username: 'unknown-user@example.com',
            },
          },
        },
      });
      const context = createMockContext();

      // ACT & ASSERT
      await expect(getControls(event, context)).rejects.toThrow('You are not authorized to access this endpoint.');
    });
  });

  describe('bulkEditControls - update operation', () => {
    it('should return 200 and update controls when Admin user submits valid update request', async () => {
      // ARRANGE
      const controlItem = {
        controlId: 'S3.1',
        description: 'S3 Block Public Access setting should be enabled',
        automatedRemediationEnabled: false,
        filterMode: 'include',
        version: 1,
        lastModified: '2024-01-01T00:00:00Z',
        modifiedBy: 'system',
      };

      await dynamoDBDocumentClient.send(
        new PutCommand({
          TableName: remediationConfigTableName,
          Item: controlItem,
        }),
      );

      const updatePayload = {
        operation: 'update',
        data: [
          {
            controlId: 'S3.1',
            description: 'S3 Block Public Access setting should be enabled',
            automatedRemediationEnabled: true,
            filters: ['filter-uuid-123'],
            filterMode: 'include',
            version: 1,
            lastModified: '2024-01-01T00:00:00Z',
            modifiedBy: 'system',
          },
        ],
      };

      const event = createMockEvent({
        httpMethod: 'POST',
        path: '/controls/bulk-edit',
        body: JSON.stringify(updatePayload),
        headers: {
          'Content-Type': 'application/json',
          authorization: 'Bearer valid-token',
        },
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

      // ACT
      const result = await bulkEditControls(event, context);

      // ASSERT
      expect(result.statusCode).toBe(200);
      const body = JSON.parse(result.body);
      expect(body.message).toBe('Controls updated successfully');
      expect(body.updatedCount).toBe(1);

      const updatedItem = await dynamoDBDocumentClient.send(
        new GetCommand({
          TableName: remediationConfigTableName,
          Key: { controlId: 'S3.1' },
        }),
      );
      expect(updatedItem.Item?.automatedRemediationEnabled).toBe(true);
      expect(updatedItem.Item?.version).toBe(2);
      expect(updatedItem.Item?.modifiedBy).toBe('admin-user@example.com');
    });

    it('should return 200 and update multiple controls in a single request', async () => {
      // ARRANGE
      const controls = [
        {
          controlId: 'S3.1',
          description: 'S3 Block Public Access',
          automatedRemediationEnabled: false,
          filterMode: 'include',
          version: 1,
          lastModified: '2024-01-01T00:00:00Z',
          modifiedBy: 'system',
        },
        {
          controlId: 'EC2.1',
          description: 'EC2 IMDSv2',
          automatedRemediationEnabled: false,
          filterMode: 'include',
          version: 1,
          lastModified: '2024-01-01T00:00:00Z',
          modifiedBy: 'system',
        },
      ];

      for (const control of controls) {
        await dynamoDBDocumentClient.send(
          new PutCommand({
            TableName: remediationConfigTableName,
            Item: control,
          }),
        );
      }

      const updatePayload = {
        operation: 'update',
        data: [
          {
            controlId: 'S3.1',
            description: 'S3 Block Public Access',
            automatedRemediationEnabled: true,
            filters: [],
            filterMode: 'include',
            version: 1,
            lastModified: '2024-01-01T00:00:00Z',
            modifiedBy: 'system',
          },
          {
            controlId: 'EC2.1',
            description: 'EC2 IMDSv2',
            automatedRemediationEnabled: true,
            filters: [],
            filterMode: 'exclude',
            version: 1,
            lastModified: '2024-01-01T00:00:00Z',
            modifiedBy: 'system',
          },
        ],
      };

      const event = createMockEvent({
        httpMethod: 'POST',
        path: '/controls/bulk-edit',
        body: JSON.stringify(updatePayload),
        headers: {
          'Content-Type': 'application/json',
          authorization: 'Bearer valid-token',
        },
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

      // ACT
      const result = await bulkEditControls(event, context);

      // ASSERT
      expect(result.statusCode).toBe(200);
      const body = JSON.parse(result.body);
      expect(body.updatedCount).toBe(2);

      const s3Control = await dynamoDBDocumentClient.send(
        new GetCommand({
          TableName: remediationConfigTableName,
          Key: { controlId: 'S3.1' },
        }),
      );
      expect(s3Control.Item?.automatedRemediationEnabled).toBe(true);
      expect(s3Control.Item?.filterMode).toBe('include');

      const ec2Control = await dynamoDBDocumentClient.send(
        new GetCommand({
          TableName: remediationConfigTableName,
          Key: { controlId: 'EC2.1' },
        }),
      );
      expect(ec2Control.Item?.automatedRemediationEnabled).toBe(true);
      expect(ec2Control.Item?.filterMode).toBe('exclude');
    });

    it('should return 207 Multi-Status when version mismatch occurs', async () => {
      // ARRANGE
      const controlItem = {
        controlId: 'S3.1',
        description: 'S3 Block Public Access setting should be enabled',
        automatedRemediationEnabled: false,
        filterMode: 'include',
        version: 2,
        lastModified: '2024-01-01T00:00:00Z',
        modifiedBy: 'system',
      };

      await dynamoDBDocumentClient.send(
        new PutCommand({
          TableName: remediationConfigTableName,
          Item: controlItem,
        }),
      );

      const updatePayload = {
        operation: 'update',
        data: [
          {
            controlId: 'S3.1',
            description: 'S3 Block Public Access setting should be enabled',
            automatedRemediationEnabled: true,
            filters: [],
            filterMode: 'include',
            version: 1,
            lastModified: '2024-01-01T00:00:00Z',
            modifiedBy: 'system',
          },
        ],
      };

      const event = createMockEvent({
        httpMethod: 'POST',
        path: '/controls/bulk-edit',
        body: JSON.stringify(updatePayload),
        headers: {
          'Content-Type': 'application/json',
          authorization: 'Bearer valid-token',
        },
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

      // ACT & ASSERT
      await expect(bulkEditControls(event, context)).rejects.toThrow(
        'Controls failed to update. Data may have been modified or controls may not exist.',
      );
    });

    it('should return 409 Conflict when control does not exist in DynamoDB', async () => {
      // ARRANGE - Don't create the control in DynamoDB
      const updatePayload = {
        operation: 'update',
        data: [
          {
            controlId: 'NONEXISTENT.1',
            description: 'This control does not exist',
            automatedRemediationEnabled: true,
            filters: [],
            filterMode: 'include',
            version: 1,
            lastModified: '2024-01-01T00:00:00Z',
            modifiedBy: 'system',
          },
        ],
      };

      const event = createMockEvent({
        httpMethod: 'POST',
        path: '/controls/bulk-edit',
        body: JSON.stringify(updatePayload),
        headers: {
          'Content-Type': 'application/json',
          authorization: 'Bearer valid-token',
        },
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

      // ACT & ASSERT
      await expect(bulkEditControls(event, context)).rejects.toThrow(
        'Controls failed to update. Data may have been modified or controls may not exist.',
      );
    });

    it('should return 403 Forbidden when AccountOperator attempts to update controls', async () => {
      // ARRANGE
      cognitoMock.reset();
      cognitoMock.on(AdminGetUserCommand).resolves({
        Username: 'operator@example.com',
        UserAttributes: [
          { Name: 'email', Value: 'operator@example.com' },
          { Name: 'custom:invitedBy', Value: 'admin@example.com' },
        ],
        UserCreateDate: new Date(),
        UserStatus: 'CONFIRMED',
      });

      cognitoMock.on(AdminListGroupsForUserCommand).resolves({
        Groups: [{ GroupName: 'AccountOperatorGroup' }],
      });

      await dynamoDBDocumentClient.send(
        new PutCommand({
          TableName: userAccountMappingTableName,
          Item: {
            userId: 'operator@example.com',
            accountIds: ['123456789012'],
          },
        }),
      );

      const updatePayload = {
        operation: 'update',
        data: [
          {
            controlId: 'S3.1',
            description: 'S3 Block Public Access',
            automatedRemediationEnabled: true,
            filters: [],
            filterMode: 'include',
            version: 1,
            lastModified: '2024-01-01T00:00:00Z',
            modifiedBy: 'system',
          },
        ],
      };

      const event = createMockEvent({
        httpMethod: 'POST',
        path: '/controls/bulk-edit',
        body: JSON.stringify(updatePayload),
        headers: {
          'Content-Type': 'application/json',
          authorization: 'Bearer valid-token',
        },
        requestContext: {
          ...TEST_REQUEST_CONTEXT,
          authorizer: {
            claims: {
              'cognito:groups': ['AccountOperatorGroup'],
              username: 'operator@example.com',
            },
          },
        },
      });
      const context = createMockContext();

      // ACT & ASSERT
      await expect(bulkEditControls(event, context)).rejects.toThrow('You are not authorized to access this endpoint.');
    });

    it('should return 400 Bad Request when request body is invalid', async () => {
      // ARRANGE
      const invalidPayload = {
        operation: 'update',
        data: [],
      };

      const event = createMockEvent({
        httpMethod: 'POST',
        path: '/controls/bulk-edit',
        body: JSON.stringify(invalidPayload),
        headers: {
          'Content-Type': 'application/json',
          authorization: 'Bearer valid-token',
        },
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

      // ACT & ASSERT
      await expect(bulkEditControls(event, context)).rejects.toThrow('Invalid bulk edit request');
    });

    it('should return 400 Bad Request when operation is not supported', async () => {
      // ARRANGE
      const unsupportedPayload = {
        operation: 'unsupportedOperation',
        data: 'filter-uuid-123',
      };

      const event = createMockEvent({
        httpMethod: 'POST',
        path: '/controls/bulk-edit',
        body: JSON.stringify(unsupportedPayload),
        headers: {
          'Content-Type': 'application/json',
          authorization: 'Bearer valid-token',
        },
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

      // ACT & ASSERT
      await expect(bulkEditControls(event, context)).rejects.toThrow('Invalid bulk edit request');
    });

    it('should allow DelegatedAdmin to update controls', async () => {
      // ARRANGE
      cognitoMock.reset();
      cognitoMock.on(AdminGetUserCommand).resolves({
        Username: 'delegated-admin@example.com',
        UserAttributes: [
          { Name: 'email', Value: 'delegated-admin@example.com' },
          { Name: 'custom:invitedBy', Value: 'admin@example.com' },
        ],
        UserCreateDate: new Date(),
        UserStatus: 'CONFIRMED',
      });

      cognitoMock.on(AdminListGroupsForUserCommand).resolves({
        Groups: [{ GroupName: 'DelegatedAdminGroup' }],
      });

      const controlItem = {
        controlId: 'S3.1',
        description: 'S3 Block Public Access',
        automatedRemediationEnabled: false,
        filterMode: 'include',
        version: 1,
        lastModified: '2024-01-01T00:00:00Z',
        modifiedBy: 'system',
      };

      await dynamoDBDocumentClient.send(
        new PutCommand({
          TableName: remediationConfigTableName,
          Item: controlItem,
        }),
      );

      const updatePayload = {
        operation: 'update',
        data: [
          {
            controlId: 'S3.1',
            description: 'S3 Block Public Access',
            automatedRemediationEnabled: true,
            filters: [],
            filterMode: 'include',
            version: 1,
            lastModified: '2024-01-01T00:00:00Z',
            modifiedBy: 'system',
          },
        ],
      };

      const event = createMockEvent({
        httpMethod: 'POST',
        path: '/controls/bulk-edit',
        body: JSON.stringify(updatePayload),
        headers: {
          'Content-Type': 'application/json',
          authorization: 'Bearer valid-token',
        },
        requestContext: {
          ...TEST_REQUEST_CONTEXT,
          authorizer: {
            claims: {
              'cognito:groups': ['DelegatedAdminGroup'],
              username: 'delegated-admin@example.com',
            },
          },
        },
      });
      const context = createMockContext();

      // ACT
      const result = await bulkEditControls(event, context);

      // ASSERT
      expect(result.statusCode).toBe(200);
      const body = JSON.parse(result.body);
      expect(body.updatedCount).toBe(1);
    });

    it('should update control with filters as String Set in DynamoDB', async () => {
      // ARRANGE
      const controlItem = {
        controlId: 'S3.1',
        description: 'S3 Block Public Access',
        automatedRemediationEnabled: false,
        filterMode: 'include',
        version: 1,
        lastModified: '2024-01-01T00:00:00Z',
        modifiedBy: 'system',
      };

      await dynamoDBDocumentClient.send(
        new PutCommand({
          TableName: remediationConfigTableName,
          Item: controlItem,
        }),
      );

      const updatePayload = {
        operation: 'update',
        data: [
          {
            controlId: 'S3.1',
            description: 'S3 Block Public Access',
            automatedRemediationEnabled: true,
            filters: ['filter-1', 'filter-2'],
            filterMode: 'exclude',
            version: 1,
            lastModified: '2024-01-01T00:00:00Z',
            modifiedBy: 'system',
          },
        ],
      };

      const event = createMockEvent({
        httpMethod: 'POST',
        path: '/controls/bulk-edit',
        body: JSON.stringify(updatePayload),
        headers: {
          'Content-Type': 'application/json',
          authorization: 'Bearer valid-token',
        },
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

      // ACT
      const result = await bulkEditControls(event, context);

      // ASSERT
      expect(result.statusCode).toBe(200);

      const updatedItem = await dynamoDBDocumentClient.send(
        new GetCommand({
          TableName: remediationConfigTableName,
          Key: { controlId: 'S3.1' },
        }),
      );
      expect(updatedItem.Item?.filterMode).toBe('exclude');
      const filters = updatedItem.Item?.filters;
      expect(filters).toBeInstanceOf(Set);
      expect(Array.from(filters as Set<string>).sort()).toEqual(['filter-1', 'filter-2']);
    });
  });

  describe('bulkEditControls - admin activity notifications', () => {
    const seedControl = async (automatedRemediationEnabled = false): Promise<void> => {
      await dynamoDBDocumentClient.send(
        new PutCommand({
          TableName: remediationConfigTableName,
          Item: {
            controlId: 'S3.1',
            description: 'S3 Block Public Access setting should be enabled',
            automatedRemediationEnabled,
            filterMode: 'include',
            version: 1,
            lastModified: '2024-01-01T00:00:00Z',
            modifiedBy: 'system',
          },
        }),
      );
    };

    const buildUpdateEvent = (
      automatedRemediationEnabled: boolean,
      filterMode: 'include' | 'exclude' = 'include',
    ): APIGatewayProxyEvent =>
      createMockEvent({
        httpMethod: 'POST',
        path: '/controls/bulk-edit',
        body: JSON.stringify({
          operation: 'update',
          data: [
            {
              controlId: 'S3.1',
              description: 'S3 Block Public Access setting should be enabled',
              automatedRemediationEnabled,
              filters: [],
              filterMode,
              version: 1,
              lastModified: '2024-01-01T00:00:00Z',
              modifiedBy: 'system',
            },
          ],
        }),
        headers: { 'Content-Type': 'application/json', authorization: 'Bearer valid-token' },
        requestContext: {
          ...TEST_REQUEST_CONTEXT,
          authorizer: {
            claims: { 'cognito:groups': ['DelegatedAdminGroup'], username: 'admin-user@example.com' },
          },
        },
      });

    it('notifies CONTROL_REMEDIATION_SET when automated remediation is disabled', async () => {
      // ARRANGE
      await seedControl(true);

      // ACT
      await bulkEditControls(buildUpdateEvent(false), createMockContext());

      // ASSERT
      const notifications = publishedAdminNotifications();
      expect(notifications).toHaveLength(1);
      expect(notifications[0]).toMatchObject({
        action: 'CONTROL_REMEDIATION_SET',
        resourceType: 'control',
        affectedControlCount: 1,
        actorGroups: ['DelegatedAdminGroup'],
      });
    });

    it('notifies CONTROL_REMEDIATION_ENABLED when automated remediation is enabled', async () => {
      // ARRANGE
      await seedControl(false);

      // ACT
      await bulkEditControls(buildUpdateEvent(true), createMockContext());

      // ASSERT
      const notifications = publishedAdminNotifications();
      expect(notifications).toHaveLength(1);
      expect(notifications[0]).toMatchObject({ action: 'CONTROL_REMEDIATION_ENABLED', affectedControlCount: 1 });
    });

    it('does not notify a remediation change when only non-remediation fields change', async () => {
      // ARRANGE
      await seedControl(false);

      // ACT
      await bulkEditControls(buildUpdateEvent(false, 'exclude'), createMockContext());

      // ASSERT
      expect(publishedAdminNotifications()).toHaveLength(0);
    });

    it('notifies BULK_FILTER_CHANGE when a filter is applied to all controls', async () => {
      // ARRANGE
      await seedControl();
      const event = createMockEvent({
        httpMethod: 'POST',
        path: '/controls/bulk-edit',
        body: JSON.stringify({ operation: 'applyFilterToAll', data: '550e8400-e29b-41d4-a716-446655440000' }),
        headers: { 'Content-Type': 'application/json', authorization: 'Bearer valid-token' },
        requestContext: {
          ...TEST_REQUEST_CONTEXT,
          authorizer: { claims: { 'cognito:groups': ['AdminGroup'], username: 'admin-user@example.com' } },
        },
      });

      // ACT
      await bulkEditControls(event, createMockContext());

      // ASSERT
      const notifications = publishedAdminNotifications();
      expect(notifications).toHaveLength(1);
      expect(notifications[0]).toMatchObject({
        action: 'BULK_FILTER_CHANGE',
        resourceType: 'control',
        affectedControlCount: 1,
      });
    });
  });

  describe('bulkEditControls - applyFilterToAll operation', () => {
    it('should return 200 and apply filter to all controls when Admin user submits valid request', async () => {
      // ARRANGE
      const controls = [
        {
          controlId: 'S3.1',
          description: 'S3 Block Public Access',
          automatedRemediationEnabled: false,
          filterMode: 'include',
          version: 1,
          lastModified: '2024-01-01T00:00:00Z',
          modifiedBy: 'system',
        },
        {
          controlId: 'EC2.1',
          description: 'EC2 IMDSv2',
          automatedRemediationEnabled: true,
          filterMode: 'include',
          version: 1,
          lastModified: '2024-01-01T00:00:00Z',
          modifiedBy: 'system',
        },
      ];

      for (const control of controls) {
        await dynamoDBDocumentClient.send(
          new PutCommand({
            TableName: remediationConfigTableName,
            Item: control,
          }),
        );
      }

      const applyFilterPayload = {
        operation: 'applyFilterToAll',
        data: '550e8400-e29b-41d4-a716-446655440000',
      };

      const event = createMockEvent({
        httpMethod: 'POST',
        path: '/controls/bulk-edit',
        body: JSON.stringify(applyFilterPayload),
        headers: {
          'Content-Type': 'application/json',
          authorization: 'Bearer valid-token',
        },
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

      // ACT
      const result = await bulkEditControls(event, context);

      // ASSERT
      expect(result.statusCode).toBe(200);
      const body = JSON.parse(result.body);
      expect(body.message).toBe('Filter applied to all controls successfully');
      expect(body.updatedCount).toBe(2);

      const s3Control = await dynamoDBDocumentClient.send(
        new GetCommand({
          TableName: remediationConfigTableName,
          Key: { controlId: 'S3.1' },
        }),
      );
      expect(s3Control.Item?.filters).toBeInstanceOf(Set);
      expect(Array.from(s3Control.Item?.filters as Set<string>)).toContain('550e8400-e29b-41d4-a716-446655440000');
      expect(s3Control.Item?.version).toBe(2);
      expect(s3Control.Item?.modifiedBy).toBe('admin-user@example.com');

      const ec2Control = await dynamoDBDocumentClient.send(
        new GetCommand({
          TableName: remediationConfigTableName,
          Key: { controlId: 'EC2.1' },
        }),
      );
      expect(ec2Control.Item?.filters).toBeInstanceOf(Set);
      expect(Array.from(ec2Control.Item?.filters as Set<string>)).toContain('550e8400-e29b-41d4-a716-446655440000');
      expect(ec2Control.Item?.version).toBe(2);
    });

    it('should add filter to controls that already have existing filters and preserve other attributes', async () => {
      // ARRANGE
      const controlItem = {
        controlId: 'S3.1',
        description: 'S3 Block Public Access',
        automatedRemediationEnabled: true,
        filters: new Set(['existing-filter-uuid']),
        filterMode: 'exclude',
        version: 3,
        lastModified: '2024-01-01T00:00:00Z',
        modifiedBy: 'previous-user@example.com',
      };

      await dynamoDBDocumentClient.send(
        new PutCommand({
          TableName: remediationConfigTableName,
          Item: controlItem,
        }),
      );

      const applyFilterPayload = {
        operation: 'applyFilterToAll',
        data: '550e8400-e29b-41d4-a716-446655440000',
      };

      const event = createMockEvent({
        httpMethod: 'POST',
        path: '/controls/bulk-edit',
        body: JSON.stringify(applyFilterPayload),
        headers: {
          'Content-Type': 'application/json',
          authorization: 'Bearer valid-token',
        },
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

      // ACT
      const result = await bulkEditControls(event, context);

      // ASSERT
      expect(result.statusCode).toBe(200);

      const updatedItem = await dynamoDBDocumentClient.send(
        new GetCommand({
          TableName: remediationConfigTableName,
          Key: { controlId: 'S3.1' },
        }),
      );

      // Verify existing filters are preserved and new filter is added
      const filters = Array.from(updatedItem.Item?.filters as Set<string>).sort();
      expect(filters).toEqual(['550e8400-e29b-41d4-a716-446655440000', 'existing-filter-uuid']);

      // Verify other attributes are preserved
      expect(updatedItem.Item?.description).toBe('S3 Block Public Access');
      expect(updatedItem.Item?.automatedRemediationEnabled).toBe(true);
      expect(updatedItem.Item?.filterMode).toBe('exclude');
      expect(updatedItem.Item?.version).toBe(4);
      expect(updatedItem.Item?.modifiedBy).toBe('admin-user@example.com');
    });

    it('should be idempotent when applying the same filter twice', async () => {
      // ARRANGE
      const controlItem = {
        controlId: 'S3.1',
        description: 'S3 Block Public Access',
        automatedRemediationEnabled: true,
        filters: new Set(['550e8400-e29b-41d4-a716-446655440000']),
        filterMode: 'include',
        version: 1,
        lastModified: '2024-01-01T00:00:00Z',
        modifiedBy: 'system',
      };

      await dynamoDBDocumentClient.send(
        new PutCommand({
          TableName: remediationConfigTableName,
          Item: controlItem,
        }),
      );

      const applyFilterPayload = {
        operation: 'applyFilterToAll',
        data: '550e8400-e29b-41d4-a716-446655440000',
      };

      const event = createMockEvent({
        httpMethod: 'POST',
        path: '/controls/bulk-edit',
        body: JSON.stringify(applyFilterPayload),
        headers: {
          'Content-Type': 'application/json',
          authorization: 'Bearer valid-token',
        },
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

      // ACT
      const result = await bulkEditControls(event, context);

      // ASSERT
      expect(result.statusCode).toBe(200);

      const updatedItem = await dynamoDBDocumentClient.send(
        new GetCommand({
          TableName: remediationConfigTableName,
          Key: { controlId: 'S3.1' },
        }),
      );
      const filters = Array.from(updatedItem.Item?.filters as Set<string>);
      expect(filters).toEqual(['550e8400-e29b-41d4-a716-446655440000']);
      expect(updatedItem.Item?.version).toBe(2);
    });

    it('should apply filter using current version from database scan', async () => {
      // ARRANGE
      // This test verifies that applyFilterToAll correctly handles controls with any version number
      // since it scans for current versions before updating
      const controlItem = {
        controlId: 'S3.1',
        description: 'S3 Block Public Access',
        automatedRemediationEnabled: false,
        filterMode: 'include',
        version: 5,
        lastModified: '2024-01-01T00:00:00Z',
        modifiedBy: 'system',
      };

      await dynamoDBDocumentClient.send(
        new PutCommand({
          TableName: remediationConfigTableName,
          Item: controlItem,
        }),
      );

      const applyFilterPayload = {
        operation: 'applyFilterToAll',
        data: '550e8400-e29b-41d4-a716-446655440000',
      };

      const event = createMockEvent({
        httpMethod: 'POST',
        path: '/controls/bulk-edit',
        body: JSON.stringify(applyFilterPayload),
        headers: {
          'Content-Type': 'application/json',
          authorization: 'Bearer valid-token',
        },
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

      // ACT
      const result = await bulkEditControls(event, context);

      // ASSERT
      expect(result.statusCode).toBe(200);
      const body = JSON.parse(result.body);
      expect(body.updatedCount).toBe(1);

      const updatedItem = await dynamoDBDocumentClient.send(
        new GetCommand({
          TableName: remediationConfigTableName,
          Key: { controlId: 'S3.1' },
        }),
      );
      expect(updatedItem.Item?.version).toBe(6);
    });

    it('should return 403 Forbidden when AccountOperator attempts applyFilterToAll', async () => {
      // ARRANGE
      cognitoMock.reset();
      cognitoMock.on(AdminGetUserCommand).resolves({
        Username: 'operator@example.com',
        UserAttributes: [
          { Name: 'email', Value: 'operator@example.com' },
          { Name: 'custom:invitedBy', Value: 'admin@example.com' },
        ],
        UserCreateDate: new Date(),
        UserStatus: 'CONFIRMED',
      });

      cognitoMock.on(AdminListGroupsForUserCommand).resolves({
        Groups: [{ GroupName: 'AccountOperatorGroup' }],
      });

      await dynamoDBDocumentClient.send(
        new PutCommand({
          TableName: userAccountMappingTableName,
          Item: {
            userId: 'operator@example.com',
            accountIds: ['123456789012'],
          },
        }),
      );

      const applyFilterPayload = {
        operation: 'applyFilterToAll',
        data: '550e8400-e29b-41d4-a716-446655440000',
      };

      const event = createMockEvent({
        httpMethod: 'POST',
        path: '/controls/bulk-edit',
        body: JSON.stringify(applyFilterPayload),
        headers: {
          'Content-Type': 'application/json',
          authorization: 'Bearer valid-token',
        },
        requestContext: {
          ...TEST_REQUEST_CONTEXT,
          authorizer: {
            claims: {
              'cognito:groups': ['AccountOperatorGroup'],
              username: 'operator@example.com',
            },
          },
        },
      });
      const context = createMockContext();

      // ACT & ASSERT
      await expect(bulkEditControls(event, context)).rejects.toThrow('You are not authorized to access this endpoint.');
    });

    it('should return 400 Bad Request when filterId is not a valid UUID', async () => {
      // ARRANGE
      const invalidPayload = {
        operation: 'applyFilterToAll',
        data: 'not-a-valid-uuid',
      };

      const event = createMockEvent({
        httpMethod: 'POST',
        path: '/controls/bulk-edit',
        body: JSON.stringify(invalidPayload),
        headers: {
          'Content-Type': 'application/json',
          authorization: 'Bearer valid-token',
        },
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

      // ACT & ASSERT
      await expect(bulkEditControls(event, context)).rejects.toThrow('Invalid bulk edit request');
    });

    it('should allow DelegatedAdmin to apply filter to all controls', async () => {
      // ARRANGE
      cognitoMock.reset();
      cognitoMock.on(AdminGetUserCommand).resolves({
        Username: 'delegated-admin@example.com',
        UserAttributes: [
          { Name: 'email', Value: 'delegated-admin@example.com' },
          { Name: 'custom:invitedBy', Value: 'admin@example.com' },
        ],
        UserCreateDate: new Date(),
        UserStatus: 'CONFIRMED',
      });

      cognitoMock.on(AdminListGroupsForUserCommand).resolves({
        Groups: [{ GroupName: 'DelegatedAdminGroup' }],
      });

      const controlItem = {
        controlId: 'S3.1',
        description: 'S3 Block Public Access',
        automatedRemediationEnabled: false,
        filterMode: 'include',
        version: 1,
        lastModified: '2024-01-01T00:00:00Z',
        modifiedBy: 'system',
      };

      await dynamoDBDocumentClient.send(
        new PutCommand({
          TableName: remediationConfigTableName,
          Item: controlItem,
        }),
      );

      const applyFilterPayload = {
        operation: 'applyFilterToAll',
        data: '550e8400-e29b-41d4-a716-446655440000',
      };

      const event = createMockEvent({
        httpMethod: 'POST',
        path: '/controls/bulk-edit',
        body: JSON.stringify(applyFilterPayload),
        headers: {
          'Content-Type': 'application/json',
          authorization: 'Bearer valid-token',
        },
        requestContext: {
          ...TEST_REQUEST_CONTEXT,
          authorizer: {
            claims: {
              'cognito:groups': ['DelegatedAdminGroup'],
              username: 'delegated-admin@example.com',
            },
          },
        },
      });
      const context = createMockContext();

      // ACT
      const result = await bulkEditControls(event, context);

      // ASSERT
      expect(result.statusCode).toBe(200);
      const body = JSON.parse(result.body);
      expect(body.updatedCount).toBe(1);
    });

    it('should return 200 with zero updates when no controls exist', async () => {
      // ARRANGE - No controls in the table
      const applyFilterPayload = {
        operation: 'applyFilterToAll',
        data: '550e8400-e29b-41d4-a716-446655440000',
      };

      const event = createMockEvent({
        httpMethod: 'POST',
        path: '/controls/bulk-edit',
        body: JSON.stringify(applyFilterPayload),
        headers: {
          'Content-Type': 'application/json',
          authorization: 'Bearer valid-token',
        },
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

      // ACT
      const result = await bulkEditControls(event, context);

      // ASSERT
      expect(result.statusCode).toBe(200);
      const body = JSON.parse(result.body);
      expect(body.message).toBe('Filter applied to all controls successfully');
      expect(body.updatedCount).toBe(0);
    });

    it('should handle batch splitting when updating more than 100 controls', async () => {
      // ARRANGE
      const controlCount = 150;
      const controls = [];

      for (let i = 1; i <= controlCount; i++) {
        const controlItem = {
          controlId: `CTRL.${i}`,
          description: `Control ${i} description`,
          automatedRemediationEnabled: false,
          filterMode: 'include',
          version: 1,
          lastModified: '2024-01-01T00:00:00Z',
          modifiedBy: 'system',
        };
        controls.push(controlItem);
        await dynamoDBDocumentClient.send(
          new PutCommand({
            TableName: remediationConfigTableName,
            Item: controlItem,
          }),
        );
      }

      const applyFilterPayload = {
        operation: 'applyFilterToAll',
        data: '550e8400-e29b-41d4-a716-446655440000',
      };

      const event = createMockEvent({
        httpMethod: 'POST',
        path: '/controls/bulk-edit',
        body: JSON.stringify(applyFilterPayload),
        headers: {
          'Content-Type': 'application/json',
          authorization: 'Bearer valid-token',
        },
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

      // ACT
      const result = await bulkEditControls(event, context);

      // ASSERT
      expect(result.statusCode).toBe(200);
      const body = JSON.parse(result.body);
      expect(body.updatedCount).toBe(controlCount);

      const firstControl = await dynamoDBDocumentClient.send(
        new GetCommand({
          TableName: remediationConfigTableName,
          Key: { controlId: 'CTRL.1' },
        }),
      );
      expect(firstControl.Item?.filters).toBeInstanceOf(Set);
      expect(Array.from(firstControl.Item?.filters as Set<string>)).toContain('550e8400-e29b-41d4-a716-446655440000');

      const lastControl = await dynamoDBDocumentClient.send(
        new GetCommand({
          TableName: remediationConfigTableName,
          Key: { controlId: `CTRL.${controlCount}` },
        }),
      );
      expect(lastControl.Item?.filters).toBeInstanceOf(Set);
      expect(Array.from(lastControl.Item?.filters as Set<string>)).toContain('550e8400-e29b-41d4-a716-446655440000');
    });
  });

  describe('getControls - DynamoDB scan pagination', () => {
    it('should retrieve all controls when table has many items requiring pagination', async () => {
      // ARRANGE
      const controlCount = 50;

      for (let i = 1; i <= controlCount; i++) {
        const controlItem = {
          controlId: `SCAN.${i}`,
          description: `Scan test control ${i}`,
          automatedRemediationEnabled: i % 2 === 0,
          filterMode: 'include',
          version: 1,
          lastModified: '2024-01-01T00:00:00Z',
          modifiedBy: 'system',
        };
        await dynamoDBDocumentClient.send(
          new PutCommand({
            TableName: remediationConfigTableName,
            Item: controlItem,
          }),
        );
      }

      const event = createMockEvent({
        httpMethod: 'GET',
        path: '/controls',
        headers: {
          'Content-Type': 'application/json',
          authorization: 'Bearer valid-token',
        },
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

      // ACT
      const result = await getControls(event, context);

      // ASSERT
      expect(result.statusCode).toBe(200);
      const body = JSON.parse(result.body);
      expect(body.controls).toHaveLength(controlCount);

      const controlIds = body.controls.map((c: { controlId: string }) => c.controlId);
      expect(controlIds).toContain('SCAN.1');
      expect(controlIds).toContain('SCAN.25');
      expect(controlIds).toContain('SCAN.50');
    });
  });

  // The outer suite runs without a custom-runbook table, which already covers the
  // degrade-to-built-ins path. This block creates the table so the merge itself is
  // exercised against DynamoDB Local, including the status filter the query relies
  // on and the highest-version tie-break.
  describe('getControls with custom runbooks', () => {
    const customRunbookItem = (overrides: Record<string, unknown> = {}) => ({
      runbookId: 'a3f9c1e2-0000-4000-8000-000000000001',
      version: 1,
      controlId: 'Custom.1',
      serviceName: 'Custom',
      description: 'Custom remediation',
      remediationAction: 'Custom remediation',
      status: 'DEPLOYED',
      s3Key: 'runbooks/a3f9c1e2-0000-4000-8000-000000000001/v1/runbook.yaml',
      createdBy: 'author@example.com',
      createdAt: '2026-02-01T00:00:00Z',
      ...overrides,
    });

    async function putCustomRunbook(overrides: Record<string, unknown> = {}): Promise<void> {
      await dynamoDBDocumentClient.send(
        new PutCommand({ TableName: customRunbookTableName, Item: customRunbookItem(overrides) }),
      );
    }

    async function listControls(): Promise<SecurityControl[]> {
      const event = createMockEvent({
        httpMethod: 'GET',
        path: '/controls',
        headers: {
          'Content-Type': 'application/json',
          authorization: 'Bearer valid-token',
        },
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

      const result = await getControls(event, createMockContext());
      expect(result.statusCode).toBe(200);
      return JSON.parse(result.body).controls as SecurityControl[];
    }

    beforeAll(async () => {
      await DynamoDBTestSetup.createCustomRunbookTable(customRunbookTableName);
    });

    afterAll(async () => {
      await DynamoDBTestSetup.deleteTable(customRunbookTableName);
    });

    beforeEach(async () => {
      await DynamoDBTestSetup.clearTable(customRunbookTableName, 'customRunbook');
    });

    it('adds a control served by a deployed custom runbook, tagged as custom', async () => {
      await putCustomRunbook();

      const controls = await listControls();

      expect(controls).toEqual([
        expect.objectContaining({
          controlId: 'Custom.1',
          description: 'Custom remediation',
          source: 'custom',
          automatedRemediationEnabled: false,
          modifiedBy: 'author@example.com',
          lastModified: '2026-02-01T00:00:00Z',
        }),
      ]);
    });

    it('saves an edit to a deployed custom control, whose config row starts at version 0', async () => {
      await putCustomRunbook();
      await dynamoDBDocumentClient.send(
        new PutCommand({
          TableName: remediationConfigTableName,
          Item: {
            controlId: 'Custom.1',
            description: 'Custom remediation',
            automatedRemediationEnabled: false,
            filterMode: 'include',
            version: 0,
            lastModified: '2026-02-01T00:00:00Z',
            modifiedBy: 'author@example.com',
            source: 'custom',
          },
        }),
      );

      expect((await listControls()).find(({ controlId }) => controlId === 'Custom.1')).toEqual(
        expect.objectContaining({
          controlId: 'Custom.1',
          source: 'custom',
          automatedRemediationEnabled: false,
          version: 0,
        }),
      );

      const updateEvent = createMockEvent({
        httpMethod: 'POST',
        path: '/controls/bulk-edit',
        body: JSON.stringify({
          operation: 'update',
          data: [
            {
              controlId: 'Custom.1',
              description: 'Custom remediation',
              automatedRemediationEnabled: false,
              filters: [],
              filterMode: 'exclude',
              version: 0,
              lastModified: '2026-02-01T00:00:00Z',
              modifiedBy: 'author@example.com',
              source: 'custom',
            },
          ],
        }),
        headers: {
          'Content-Type': 'application/json',
          authorization: 'Bearer valid-token',
        },
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

      const updateResult = await bulkEditControls(updateEvent, createMockContext());
      expect(updateResult.statusCode).toBe(200);

      const stored = await dynamoDBDocumentClient.send(
        new GetCommand({
          TableName: remediationConfigTableName,
          Key: { controlId: 'Custom.1' },
        }),
      );
      expect(stored.Item).toMatchObject({
        controlId: 'Custom.1',
        filterMode: 'exclude',
        automatedRemediationEnabled: false,
        source: 'custom',
        version: 1,
        modifiedBy: 'admin-user@example.com',
      });
    });

    it('refuses to enable automated remediation for a deployed custom control', async () => {
      // A custom runbook runs only on a manual trigger: resolve_ssm_doc_for_finding checks
      // the event type before it looks up the custom-runbook table, so an automatically
      // triggered finding never reaches one. Storing the flag would leave the console
      // reporting "Enabled" for a control nothing remediates, so the write is refused here
      // — not only hidden in the Web UI, since the MCP `update_controls` tool posts to this
      // same route.
      await putCustomRunbook();
      await dynamoDBDocumentClient.send(
        new PutCommand({
          TableName: remediationConfigTableName,
          Item: {
            controlId: 'Custom.1',
            description: 'Custom remediation',
            automatedRemediationEnabled: false,
            filterMode: 'include',
            version: 0,
            lastModified: '2026-02-01T00:00:00Z',
            modifiedBy: 'author@example.com',
            source: 'custom',
          },
        }),
      );

      const updateEvent = createMockEvent({
        httpMethod: 'POST',
        path: '/controls/bulk-edit',
        body: JSON.stringify({
          operation: 'update',
          data: [
            {
              controlId: 'Custom.1',
              description: 'Custom remediation',
              automatedRemediationEnabled: true,
              filters: [],
              filterMode: 'include',
              version: 0,
              lastModified: '2026-02-01T00:00:00Z',
              modifiedBy: 'author@example.com',
              source: 'custom',
            },
          ],
        }),
        headers: {
          'Content-Type': 'application/json',
          authorization: 'Bearer valid-token',
        },
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

      await expect(bulkEditControls(updateEvent, createMockContext())).rejects.toThrow(/custom runbook/i);

      // The stored row is untouched: a refusal that still wrote the flag would be the same
      // defect with a different status code.
      const stored = await dynamoDBDocumentClient.send(
        new GetCommand({ TableName: remediationConfigTableName, Key: { controlId: 'Custom.1' } }),
      );
      expect(stored.Item).toMatchObject({ automatedRemediationEnabled: false, version: 0 });
    });

    it('names the refused custom control in a mixed batch, instead of advising a refresh', async () => {
      // A batch with one built-in and one rejected custom control returns 207, not 400 — the
      // built-in did apply. Before, that 207 carried only the generic "data may have been
      // modified, please refresh and try again", which is untrue for the custom control: it
      // will be refused however many times the operator retries. The reason and the ids have
      // to survive into the response body, which is the only thing the console can read.
      await putCustomRunbook();
      for (const [controlId, source] of [
        ['Custom.1', 'custom'],
        ['S3.1', 'builtin'],
      ] as const) {
        await dynamoDBDocumentClient.send(
          new PutCommand({
            TableName: remediationConfigTableName,
            Item: {
              controlId,
              description: `Description for ${controlId}`,
              automatedRemediationEnabled: false,
              filterMode: 'include',
              version: 0,
              lastModified: '2026-02-01T00:00:00Z',
              modifiedBy: 'author@example.com',
              source,
            },
          }),
        );
      }

      const enable = (controlId: string) => ({
        controlId,
        description: `Description for ${controlId}`,
        automatedRemediationEnabled: true,
        filters: [],
        filterMode: 'include' as const,
        version: 0,
        lastModified: '2026-02-01T00:00:00Z',
        modifiedBy: 'author@example.com',
      });

      const result = await bulkEditControls(
        createMockEvent({
          httpMethod: 'POST',
          path: '/controls/bulk-edit',
          body: JSON.stringify({ operation: 'update', data: [enable('Custom.1'), enable('S3.1')] }),
          headers: { 'Content-Type': 'application/json', authorization: 'Bearer valid-token' },
          requestContext: {
            ...TEST_REQUEST_CONTEXT,
            authorizer: {
              claims: { 'cognito:groups': ['AdminGroup'], username: 'admin-user@example.com' },
            },
          },
        }),
        createMockContext(),
      );

      expect(result.statusCode).toBe(207);
      const body = JSON.parse(result.body);
      expect(body.successCount).toBe(1);
      expect(body.failedControlIds).toEqual(['Custom.1']);
      expect(body.rejectedControlIds).toEqual(['Custom.1']);
      expect(body.message).toMatch(/custom runbook/i);
      expect(body.message).toMatch(/Custom\.1/);
      // No refresh advice: every failure in this batch is a rejection, and a retry is
      // refused identically. The console re-derives this split for its own notification,
      // but the MCP `update_controls` tool gets this message verbatim.
      expect(body.message).not.toMatch(/refresh/i);

      // The built-in applied and the custom one did not — a message alone would not prove it.
      const storedBuiltIn = await dynamoDBDocumentClient.send(
        new GetCommand({ TableName: remediationConfigTableName, Key: { controlId: 'S3.1' } }),
      );
      expect(storedBuiltIn.Item).toMatchObject({ automatedRemediationEnabled: true });
      const storedCustom = await dynamoDBDocumentClient.send(
        new GetCommand({ TableName: remediationConfigTableName, Key: { controlId: 'Custom.1' } }),
      );
      expect(storedCustom.Item).toMatchObject({ automatedRemediationEnabled: false });
    });

    it('keeps the rejection reason when everything fails for mixed reasons', async () => {
      // successCount === 0 with one structural rejection and one ordinary failure. The
      // equality check that routes an all-rejected batch to a 400 does not hold here, so
      // this used to fall through to a bare 409 "data may have been modified ... refresh
      // and try again" — advice that is right for the missing control and wrong for the
      // custom one, whose reason was dropped entirely.
      await putCustomRunbook();
      await dynamoDBDocumentClient.send(
        new PutCommand({
          TableName: remediationConfigTableName,
          Item: {
            controlId: 'Custom.1',
            description: 'Custom remediation',
            automatedRemediationEnabled: false,
            filterMode: 'include',
            version: 0,
            lastModified: '2026-02-01T00:00:00Z',
            modifiedBy: 'author@example.com',
            source: 'custom',
          },
        }),
      );

      const enable = (controlId: string, version: number) => ({
        controlId,
        description: `Description for ${controlId}`,
        automatedRemediationEnabled: true,
        filters: [],
        filterMode: 'include' as const,
        version,
        lastModified: '2026-02-01T00:00:00Z',
        modifiedBy: 'author@example.com',
      });

      const event = createMockEvent({
        httpMethod: 'POST',
        path: '/controls/bulk-edit',
        // Custom.1 is refused structurally; NONEXISTENT.1 fails its conditional write.
        body: JSON.stringify({
          operation: 'update',
          data: [enable('Custom.1', 0), enable('NONEXISTENT.1', 1)],
        }),
        headers: { 'Content-Type': 'application/json', authorization: 'Bearer valid-token' },
        requestContext: {
          ...TEST_REQUEST_CONTEXT,
          authorizer: {
            claims: { 'cognito:groups': ['AdminGroup'], username: 'admin-user@example.com' },
          },
        },
      });

      // One invocation, then assert on the captured error: the handler's body parser
      // consumes event.body, so re-invoking the same event fails as malformed JSON.
      const error: unknown = await bulkEditControls(event, createMockContext()).catch((thrown: unknown) => thrown);

      // Still a conflict, because the missing control genuinely is one — but the custom
      // control's reason and id survive alongside it.
      const message = error instanceof Error ? error.message : String(error);
      expect(message).toMatch(/may have been modified/i);
      expect(message).toMatch(/custom runbook/i);
      expect(message).toMatch(/Custom\.1/);
    });

    it('omits a runbook that has only ever been registered as a DRAFT', async () => {
      await putCustomRunbook({ status: 'DRAFT' });

      expect(await listControls()).toEqual([]);
    });

    it('does not duplicate a control the built-in table already covers', async () => {
      await dynamoDBDocumentClient.send(
        new PutCommand({
          TableName: remediationConfigTableName,
          Item: {
            controlId: 'S3.1',
            description: 'Built-in description',
            automatedRemediationEnabled: true,
            filterMode: 'include',
            version: 1,
            lastModified: '2024-01-01T00:00:00Z',
            modifiedBy: 'system',
          },
        }),
      );
      await putCustomRunbook({ controlId: 'S3.1' });

      const controls = await listControls();

      expect(controls).toEqual([
        expect.objectContaining({ controlId: 'S3.1', description: 'Built-in description', source: 'builtin' }),
      ]);
    });

    it('describes the control from its highest deployed version, not whichever the scan returns first', async () => {
      // Deploying v2 does not demote v1, so both versions are DEPLOYED at once.
      await putCustomRunbook({ version: 1, description: 'v1 description', createdBy: 'first@example.com' });
      await putCustomRunbook({ version: 2, description: 'v2 description', createdBy: 'second@example.com' });

      const controls = await listControls();

      expect(controls).toEqual([
        expect.objectContaining({
          controlId: 'Custom.1',
          description: 'v2 description',
          modifiedBy: 'second@example.com',
        }),
      ]);
    });

    it('reports the most recently deployed version as live, so a rollback to v1 wins over a newer v2', async () => {
      // A rollback re-deploys the older version, giving it the later deployedAt. The live
      // version is that one, not the highest number — the rule the Orchestrator applies
      // when it resolves the document for a finding.
      await putCustomRunbook({ version: 1, description: 'v1', deployedAt: '2026-03-10T00:00:00Z' });
      await putCustomRunbook({ version: 2, description: 'v2', deployedAt: '2026-03-01T00:00:00Z' });

      const controls = await listControls();

      expect(controls).toEqual([expect.objectContaining({ controlId: 'Custom.1', runbookVersion: 1 })]);
    });

    it('treats an empty deployedAt as absent, falling back to createdAt like the Orchestrator does', async () => {
      // The Orchestrator ranks by `deployedAt or createdAt`, where Python's `or` skips an
      // empty string. The console must rank identically or the two could name different live
      // versions: with a nullish fallback the empty string would sort lowest and v1 would win.
      await putCustomRunbook({ version: 1, deployedAt: '2026-03-01T00:00:00Z', createdAt: '2026-02-01T00:00:00Z' });
      await putCustomRunbook({ version: 2, deployedAt: '', createdAt: '2026-04-01T00:00:00Z' });

      const controls = await listControls();

      expect(controls).toEqual([expect.objectContaining({ controlId: 'Custom.1', runbookVersion: 2 })]);
    });

    it('breaks a full tie on runbookId, the same way the Orchestrator does, whichever order the scan returns', async () => {
      // Two runbooks for one control, deployed at the same instant with the same version, differ
      // only in runbookId. The Orchestrator's key ends in runbookId under max(), so the higher id
      // wins. Without that tiebreak the console keeps whichever record the scan yields first —
      // non-deterministic, and able to disagree with the resolver. Both orderings are seeded.
      const lowerId = 'a3f9c1e2-0000-4000-8000-00000000000a';
      const higherId = 'a3f9c1e2-0000-4000-8000-00000000000b';
      const tied = { version: 1, deployedAt: '2026-03-01T00:00:00Z' };

      await putCustomRunbook({ ...tied, runbookId: higherId, description: 'higher id' });
      await putCustomRunbook({ ...tied, runbookId: lowerId, description: 'lower id' });
      expect(await listControls()).toEqual([
        expect.objectContaining({ controlId: 'Custom.1', description: 'higher id' }),
      ]);

      await DynamoDBTestSetup.clearTable(customRunbookTableName, 'customRunbook');
      await putCustomRunbook({ ...tied, runbookId: lowerId, description: 'lower id' });
      await putCustomRunbook({ ...tied, runbookId: higherId, description: 'higher id' });
      expect(await listControls()).toEqual([
        expect.objectContaining({ controlId: 'Custom.1', description: 'higher id' }),
      ]);
    });
  });

  describe('bulkEditControls - removeFilterFromAll operation', () => {
    it('should return 200 and remove filter from all controls when Admin user submits valid request', async () => {
      // ARRANGE
      const filterId = '550e8400-e29b-41d4-a716-446655440000';
      const controls = [
        {
          controlId: 'S3.1',
          description: 'S3 Block Public Access',
          automatedRemediationEnabled: false,
          filters: new Set([filterId, 'other-filter-uuid']),
          filterMode: 'include',
          version: 1,
          lastModified: '2024-01-01T00:00:00Z',
          modifiedBy: 'system',
        },
        {
          controlId: 'EC2.1',
          description: 'EC2 IMDSv2',
          automatedRemediationEnabled: true,
          filters: new Set([filterId]),
          filterMode: 'include',
          version: 1,
          lastModified: '2024-01-01T00:00:00Z',
          modifiedBy: 'system',
        },
      ];

      for (const control of controls) {
        await dynamoDBDocumentClient.send(
          new PutCommand({
            TableName: remediationConfigTableName,
            Item: control,
          }),
        );
      }

      const removeFilterPayload = {
        operation: 'removeFilterFromAll',
        data: filterId,
      };

      const event = createMockEvent({
        httpMethod: 'POST',
        path: '/controls/bulk-edit',
        body: JSON.stringify(removeFilterPayload),
        headers: {
          'Content-Type': 'application/json',
          authorization: 'Bearer valid-token',
        },
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

      // ACT
      const result = await bulkEditControls(event, context);

      // ASSERT
      expect(result.statusCode).toBe(200);
      const body = JSON.parse(result.body);
      expect(body.message).toBe('Filter removed from all controls successfully');
      expect(body.updatedCount).toBe(2);

      const s3Control = await dynamoDBDocumentClient.send(
        new GetCommand({
          TableName: remediationConfigTableName,
          Key: { controlId: 'S3.1' },
        }),
      );
      expect(s3Control.Item?.filters).toBeInstanceOf(Set);
      expect(Array.from(s3Control.Item?.filters as Set<string>)).not.toContain(filterId);
      expect(Array.from(s3Control.Item?.filters as Set<string>)).toContain('other-filter-uuid');
      expect(s3Control.Item?.version).toBe(2);
      expect(s3Control.Item?.modifiedBy).toBe('admin-user@example.com');

      const ec2Control = await dynamoDBDocumentClient.send(
        new GetCommand({
          TableName: remediationConfigTableName,
          Key: { controlId: 'EC2.1' },
        }),
      );
      // When all filters are removed, the filters attribute should be empty or not exist
      const ec2Filters = ec2Control.Item?.filters;
      if (ec2Filters) {
        expect(Array.from(ec2Filters as Set<string>)).not.toContain(filterId);
      }
      expect(ec2Control.Item?.version).toBe(2);
    });

    it('should preserve other attributes when removing filter', async () => {
      // ARRANGE
      const filterId = '550e8400-e29b-41d4-a716-446655440000';
      const controlItem = {
        controlId: 'S3.1',
        description: 'S3 Block Public Access',
        automatedRemediationEnabled: true,
        filters: new Set([filterId, 'existing-filter-uuid']),
        filterMode: 'exclude',
        version: 3,
        lastModified: '2024-01-01T00:00:00Z',
        modifiedBy: 'previous-user@example.com',
      };

      await dynamoDBDocumentClient.send(
        new PutCommand({
          TableName: remediationConfigTableName,
          Item: controlItem,
        }),
      );

      const removeFilterPayload = {
        operation: 'removeFilterFromAll',
        data: filterId,
      };

      const event = createMockEvent({
        httpMethod: 'POST',
        path: '/controls/bulk-edit',
        body: JSON.stringify(removeFilterPayload),
        headers: {
          'Content-Type': 'application/json',
          authorization: 'Bearer valid-token',
        },
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

      // ACT
      const result = await bulkEditControls(event, context);

      // ASSERT
      expect(result.statusCode).toBe(200);

      const updatedItem = await dynamoDBDocumentClient.send(
        new GetCommand({
          TableName: remediationConfigTableName,
          Key: { controlId: 'S3.1' },
        }),
      );

      // Verify filter is removed and other filter is preserved
      const filters = Array.from(updatedItem.Item?.filters as Set<string>);
      expect(filters).toEqual(['existing-filter-uuid']);

      // Verify other attributes are preserved
      expect(updatedItem.Item?.description).toBe('S3 Block Public Access');
      expect(updatedItem.Item?.automatedRemediationEnabled).toBe(true);
      expect(updatedItem.Item?.filterMode).toBe('exclude');
      expect(updatedItem.Item?.version).toBe(4);
      expect(updatedItem.Item?.modifiedBy).toBe('admin-user@example.com');
    });

    it('should be idempotent when removing a filter that does not exist on control', async () => {
      // ARRANGE
      const controlItem = {
        controlId: 'S3.1',
        description: 'S3 Block Public Access',
        automatedRemediationEnabled: true,
        filters: new Set(['different-filter-uuid']),
        filterMode: 'include',
        version: 1,
        lastModified: '2024-01-01T00:00:00Z',
        modifiedBy: 'system',
      };

      await dynamoDBDocumentClient.send(
        new PutCommand({
          TableName: remediationConfigTableName,
          Item: controlItem,
        }),
      );

      const removeFilterPayload = {
        operation: 'removeFilterFromAll',
        data: '550e8400-e29b-41d4-a716-446655440000',
      };

      const event = createMockEvent({
        httpMethod: 'POST',
        path: '/controls/bulk-edit',
        body: JSON.stringify(removeFilterPayload),
        headers: {
          'Content-Type': 'application/json',
          authorization: 'Bearer valid-token',
        },
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

      // ACT
      const result = await bulkEditControls(event, context);

      // ASSERT
      expect(result.statusCode).toBe(200);

      const updatedItem = await dynamoDBDocumentClient.send(
        new GetCommand({
          TableName: remediationConfigTableName,
          Key: { controlId: 'S3.1' },
        }),
      );
      const filters = Array.from(updatedItem.Item?.filters as Set<string>);
      expect(filters).toEqual(['different-filter-uuid']);
      expect(updatedItem.Item?.version).toBe(2);
    });

    it('should handle controls with no filters attribute', async () => {
      // ARRANGE
      const controlItem = {
        controlId: 'S3.1',
        description: 'S3 Block Public Access',
        automatedRemediationEnabled: false,
        filterMode: 'include',
        version: 1,
        lastModified: '2024-01-01T00:00:00Z',
        modifiedBy: 'system',
      };

      await dynamoDBDocumentClient.send(
        new PutCommand({
          TableName: remediationConfigTableName,
          Item: controlItem,
        }),
      );

      const removeFilterPayload = {
        operation: 'removeFilterFromAll',
        data: '550e8400-e29b-41d4-a716-446655440000',
      };

      const event = createMockEvent({
        httpMethod: 'POST',
        path: '/controls/bulk-edit',
        body: JSON.stringify(removeFilterPayload),
        headers: {
          'Content-Type': 'application/json',
          authorization: 'Bearer valid-token',
        },
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

      // ACT
      const result = await bulkEditControls(event, context);

      // ASSERT
      expect(result.statusCode).toBe(200);
      const body = JSON.parse(result.body);
      expect(body.updatedCount).toBe(1);

      const updatedItem = await dynamoDBDocumentClient.send(
        new GetCommand({
          TableName: remediationConfigTableName,
          Key: { controlId: 'S3.1' },
        }),
      );
      expect(updatedItem.Item?.version).toBe(2);
    });

    it('should return 403 Forbidden when AccountOperator attempts removeFilterFromAll', async () => {
      // ARRANGE
      cognitoMock.reset();
      cognitoMock.on(AdminGetUserCommand).resolves({
        Username: 'operator@example.com',
        UserAttributes: [
          { Name: 'email', Value: 'operator@example.com' },
          { Name: 'custom:invitedBy', Value: 'admin@example.com' },
        ],
        UserCreateDate: new Date(),
        UserStatus: 'CONFIRMED',
      });

      cognitoMock.on(AdminListGroupsForUserCommand).resolves({
        Groups: [{ GroupName: 'AccountOperatorGroup' }],
      });

      await dynamoDBDocumentClient.send(
        new PutCommand({
          TableName: userAccountMappingTableName,
          Item: {
            userId: 'operator@example.com',
            accountIds: ['123456789012'],
          },
        }),
      );

      const removeFilterPayload = {
        operation: 'removeFilterFromAll',
        data: '550e8400-e29b-41d4-a716-446655440000',
      };

      const event = createMockEvent({
        httpMethod: 'POST',
        path: '/controls/bulk-edit',
        body: JSON.stringify(removeFilterPayload),
        headers: {
          'Content-Type': 'application/json',
          authorization: 'Bearer valid-token',
        },
        requestContext: {
          ...TEST_REQUEST_CONTEXT,
          authorizer: {
            claims: {
              'cognito:groups': ['AccountOperatorGroup'],
              username: 'operator@example.com',
            },
          },
        },
      });
      const context = createMockContext();

      // ACT & ASSERT
      await expect(bulkEditControls(event, context)).rejects.toThrow('You are not authorized to access this endpoint.');
    });

    it('should return 400 Bad Request when filterId is not a valid UUID', async () => {
      // ARRANGE
      const invalidPayload = {
        operation: 'removeFilterFromAll',
        data: 'not-a-valid-uuid',
      };

      const event = createMockEvent({
        httpMethod: 'POST',
        path: '/controls/bulk-edit',
        body: JSON.stringify(invalidPayload),
        headers: {
          'Content-Type': 'application/json',
          authorization: 'Bearer valid-token',
        },
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

      // ACT & ASSERT
      await expect(bulkEditControls(event, context)).rejects.toThrow('Invalid bulk edit request');
    });

    it('should allow DelegatedAdmin to remove filter from all controls', async () => {
      // ARRANGE
      cognitoMock.reset();
      cognitoMock.on(AdminGetUserCommand).resolves({
        Username: 'delegated-admin@example.com',
        UserAttributes: [
          { Name: 'email', Value: 'delegated-admin@example.com' },
          { Name: 'custom:invitedBy', Value: 'admin@example.com' },
        ],
        UserCreateDate: new Date(),
        UserStatus: 'CONFIRMED',
      });

      cognitoMock.on(AdminListGroupsForUserCommand).resolves({
        Groups: [{ GroupName: 'DelegatedAdminGroup' }],
      });

      const filterId = '550e8400-e29b-41d4-a716-446655440000';
      const controlItem = {
        controlId: 'S3.1',
        description: 'S3 Block Public Access',
        automatedRemediationEnabled: false,
        filters: new Set([filterId]),
        filterMode: 'include',
        version: 1,
        lastModified: '2024-01-01T00:00:00Z',
        modifiedBy: 'system',
      };

      await dynamoDBDocumentClient.send(
        new PutCommand({
          TableName: remediationConfigTableName,
          Item: controlItem,
        }),
      );

      const removeFilterPayload = {
        operation: 'removeFilterFromAll',
        data: filterId,
      };

      const event = createMockEvent({
        httpMethod: 'POST',
        path: '/controls/bulk-edit',
        body: JSON.stringify(removeFilterPayload),
        headers: {
          'Content-Type': 'application/json',
          authorization: 'Bearer valid-token',
        },
        requestContext: {
          ...TEST_REQUEST_CONTEXT,
          authorizer: {
            claims: {
              'cognito:groups': ['DelegatedAdminGroup'],
              username: 'delegated-admin@example.com',
            },
          },
        },
      });
      const context = createMockContext();

      // ACT
      const result = await bulkEditControls(event, context);

      // ASSERT
      expect(result.statusCode).toBe(200);
      const body = JSON.parse(result.body);
      expect(body.updatedCount).toBe(1);
    });

    it('should return 200 with zero updates when no controls exist', async () => {
      // ARRANGE - No controls in the table
      const removeFilterPayload = {
        operation: 'removeFilterFromAll',
        data: '550e8400-e29b-41d4-a716-446655440000',
      };

      const event = createMockEvent({
        httpMethod: 'POST',
        path: '/controls/bulk-edit',
        body: JSON.stringify(removeFilterPayload),
        headers: {
          'Content-Type': 'application/json',
          authorization: 'Bearer valid-token',
        },
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

      // ACT
      const result = await bulkEditControls(event, context);

      // ASSERT
      expect(result.statusCode).toBe(200);
      const body = JSON.parse(result.body);
      expect(body.message).toBe('Filter removed from all controls successfully');
      expect(body.updatedCount).toBe(0);
    });

    it('should handle batch splitting when removing filter from more than 100 controls', async () => {
      // ARRANGE
      const controlCount = 150;
      const filterId = '550e8400-e29b-41d4-a716-446655440000';

      for (let i = 1; i <= controlCount; i++) {
        const controlItem = {
          controlId: `CTRL.${i}`,
          description: `Control ${i} description`,
          automatedRemediationEnabled: false,
          filters: new Set([filterId]),
          filterMode: 'include',
          version: 1,
          lastModified: '2024-01-01T00:00:00Z',
          modifiedBy: 'system',
        };
        await dynamoDBDocumentClient.send(
          new PutCommand({
            TableName: remediationConfigTableName,
            Item: controlItem,
          }),
        );
      }

      const removeFilterPayload = {
        operation: 'removeFilterFromAll',
        data: filterId,
      };

      const event = createMockEvent({
        httpMethod: 'POST',
        path: '/controls/bulk-edit',
        body: JSON.stringify(removeFilterPayload),
        headers: {
          'Content-Type': 'application/json',
          authorization: 'Bearer valid-token',
        },
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

      // ACT
      const result = await bulkEditControls(event, context);

      // ASSERT
      expect(result.statusCode).toBe(200);
      const body = JSON.parse(result.body);
      expect(body.updatedCount).toBe(controlCount);

      const firstControl = await dynamoDBDocumentClient.send(
        new GetCommand({
          TableName: remediationConfigTableName,
          Key: { controlId: 'CTRL.1' },
        }),
      );
      const firstFilters = firstControl.Item?.filters;
      if (firstFilters) {
        expect(Array.from(firstFilters as Set<string>)).not.toContain(filterId);
      }

      const lastControl = await dynamoDBDocumentClient.send(
        new GetCommand({
          TableName: remediationConfigTableName,
          Key: { controlId: `CTRL.${controlCount}` },
        }),
      );
      const lastFilters = lastControl.Item?.filters;
      if (lastFilters) {
        expect(Array.from(lastFilters as Set<string>)).not.toContain(filterId);
      }
    });
  });

  describe('bulkEditControls - metrics', () => {
    it('should emit control_configuration_changes metric on successful update', async () => {
      // ARRANGE
      await dynamoDBDocumentClient.send(
        new PutCommand({
          TableName: remediationConfigTableName,
          Item: {
            controlId: 'S3.1',
            description: 'S3 Block Public Access',
            automatedRemediationEnabled: false,
            filterMode: 'include',
            version: 1,
            lastModified: '2024-01-01T00:00:00Z',
            modifiedBy: 'system',
          },
        }),
      );

      const updatePayload = {
        operation: 'update',
        data: [
          {
            controlId: 'S3.1',
            description: 'S3 Block Public Access',
            automatedRemediationEnabled: true,
            filters: ['filter-1', 'filter-2'],
            filterMode: 'include',
            version: 1,
            lastModified: '2024-01-01T00:00:00Z',
            modifiedBy: 'system',
          },
        ],
      };

      const event = createMockEvent({
        httpMethod: 'POST',
        path: '/controls/bulk-edit',
        body: JSON.stringify(updatePayload),
        headers: {
          'Content-Type': 'application/json',
          authorization: 'Bearer valid-token',
        },
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

      const metricsScope = createMetricsTestScope(
        /.*control_configuration_changes.*S3\.1.*control_enabled.*true.*filters_applied.*2.*/,
      );

      // ACT
      const result = await bulkEditControls(event, context);

      // ASSERT
      expect(result.statusCode).toBe(200);
      expect(metricsScope.isDone()).toBe(true);
    });

    it('should not emit metrics when all controls fail to update', async () => {
      // ARRANGE
      const updatePayload = {
        operation: 'update',
        data: [
          {
            controlId: 'NONEXISTENT.1',
            description: 'Does not exist',
            automatedRemediationEnabled: true,
            filters: [],
            filterMode: 'include',
            version: 1,
            lastModified: '2024-01-01T00:00:00Z',
            modifiedBy: 'system',
          },
        ],
      };

      const event = createMockEvent({
        httpMethod: 'POST',
        path: '/controls/bulk-edit',
        body: JSON.stringify(updatePayload),
        headers: {
          'Content-Type': 'application/json',
          authorization: 'Bearer valid-token',
        },
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

      const metricsScope = createMetricsTestScope(/.*control_configuration_changes.*/);

      // ACT & ASSERT
      await expect(bulkEditControls(event, context)).rejects.toThrow();
      expect(metricsScope.isDone()).toBe(false);
    });
  });
});
