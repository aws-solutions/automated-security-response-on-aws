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
import { DynamoDBTestSetup } from '../../../common/__tests__/dynamodbSetup';
import { remediationConfigTableName, userAccountMappingTableName } from '../../../common/__tests__/envSetup';
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
