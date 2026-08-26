// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { mockClient } from 'aws-sdk-client-mock';
import {
  CognitoIdentityProviderClient,
  ListUsersCommand,
  AdminCreateUserCommand,
  AdminAddUserToGroupCommand,
  AdminGetUserCommand,
  AdminListGroupsForUserCommand,
  AdminDeleteUserCommand,
} from '@aws-sdk/client-cognito-identity-provider';
import 'aws-sdk-client-mock-jest';
import { GetCommand, PutCommand } from '@aws-sdk/lib-dynamodb';
import { UserAccountMapping } from '@asr/data-models';
import { DynamoDBTestSetup } from '../../../common/__tests__/dynamodbSetup';
import {
  resourceFiltersTableName,
  userAccountMappingTableName,
  notificationConfigTableName,
} from '../../../common/__tests__/envSetup';
import { createMockEvent, createMockContext, TEST_REQUEST_CONTEXT } from '../utils';
import { handler, createResponse } from '../../handlers/apiHandler';
import { FORBIDDEN_ERROR_MESSAGE } from '../../../common/utils/httpErrors';
import { setupMetricsMocks, cleanupMetricsMocks } from '../../../common/__tests__/metricsMockSetup';

const cognitoMock = mockClient(CognitoIdentityProviderClient);

const TEST_EVENT_ORIGIN = process.env.WEB_UI_URL;

const STANDARD_HEADERS = {
  'Content-Type': 'application/json',
  Origin: TEST_EVENT_ORIGIN,
};

const EXPECTED_CORS_HEADERS = {
  'Access-Control-Allow-Origin': TEST_EVENT_ORIGIN,
  'Access-Control-Allow-Headers': 'Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token',
};

const expectCorsHeaders = (result: any) => {
  expect(result.headers).toEqual(expect.objectContaining(EXPECTED_CORS_HEADERS));
};

const remediationConfigTableName = 'test-remediation-config-table';

describe('Top-level routing', () => {
  beforeAll(async () => {
    await DynamoDBTestSetup.initialize();
    await DynamoDBTestSetup.createUserAccountMappingTable(userAccountMappingTableName);
    await DynamoDBTestSetup.createConfigTable(remediationConfigTableName);
    await DynamoDBTestSetup.createResourceFiltersTable(resourceFiltersTableName);
    await DynamoDBTestSetup.createNotificationConfigTable(notificationConfigTableName);
  });

  afterAll(async () => {
    await DynamoDBTestSetup.deleteTable(userAccountMappingTableName);
    await DynamoDBTestSetup.deleteTable(remediationConfigTableName);
    await DynamoDBTestSetup.deleteTable(resourceFiltersTableName);
    await DynamoDBTestSetup.deleteTable(notificationConfigTableName);
    cleanupMetricsMocks();
  });

  beforeEach(async () => {
    await DynamoDBTestSetup.clearTable(userAccountMappingTableName, 'userAccountMapping');
    await DynamoDBTestSetup.clearTable(remediationConfigTableName, 'config');
    await DynamoDBTestSetup.clearTable(resourceFiltersTableName, 'resourceFilters');
    await DynamoDBTestSetup.clearTable(notificationConfigTableName, 'notificationConfig');
    process.env.USER_POOL_ID = 'test-user-pool-id';
    process.env.USER_ACCOUNT_MAPPING_TABLE_NAME = userAccountMappingTableName;
    process.env.REMEDIATION_CONFIG_TABLE_NAME = remediationConfigTableName;

    cognitoMock.reset();
    setupMetricsMocks();

    cognitoMock.on(AdminGetUserCommand).callsFake((input) => {
      const username = input.Username;
      return Promise.resolve({
        Username: username,
        UserAttributes: [
          { Name: 'email', Value: username },
          { Name: 'custom:invitedBy', Value: 'system@example.com' },
        ],
        UserCreateDate: new Date(),
        UserStatus: 'CONFIRMED',
      });
    });

    cognitoMock.on(AdminListGroupsForUserCommand).callsFake((input) => {
      const username = input.Username;
      let groups = [];

      if (username?.includes('admin-user') || username?.includes('admin@') || username?.includes('super@')) {
        groups = [{ GroupName: 'AdminGroup' }];
      } else if (username?.includes('delegated@')) {
        groups = [{ GroupName: 'DelegatedAdminGroup' }];
      } else if (username?.includes('operator@')) {
        groups = [{ GroupName: 'AccountOperatorGroup' }];
      } else {
        groups = [{ GroupName: 'AdminGroup' }];
      }

      return Promise.resolve({ Groups: groups });
    });
    cognitoMock.on(ListUsersCommand).resolves({ Users: [] });
    cognitoMock.on(AdminCreateUserCommand).resolves({ User: { Username: 'new-user@example.com' } });
    cognitoMock.on(AdminAddUserToGroupCommand).resolves({});
    cognitoMock.on(AdminDeleteUserCommand).resolves({});
  });

  describe('general', () => {
    it('should reject requests with x-amzn-requestid header', async () => {
      // ARRANGE
      const event = createMockEvent({
        httpMethod: 'GET',
        path: '/users',
        headers: {
          ...STANDARD_HEADERS,
          authorization: 'Bearer valid-token',
          'x-amzn-requestid': 'test-request-id',
        },
      });
      const context = createMockContext();

      // ACT
      const result = await handler(event, context);

      // ASSERT
      expect(result.statusCode).toBe(400);
      expectCorsHeaders(result);
      const body = JSON.parse(result.body);
      expect(body.message).toBe('X-Amzn-Requestid header is not allowed');
    });

    it('should reject requests with X-Amzn-Requestid header (case insensitive)', async () => {
      // ARRANGE
      const event = createMockEvent({
        httpMethod: 'GET',
        path: '/users',
        headers: {
          ...STANDARD_HEADERS,
          authorization: 'Bearer valid-token',
          'X-Amzn-Requestid': 'test-request-id',
        },
      });
      const context = createMockContext();

      // ACT
      const result = await handler(event, context);

      // ASSERT
      expect(result.statusCode).toBe(400);
      expectCorsHeaders(result);
      const body = JSON.parse(result.body);
      expect(body.message).toBe('X-Amzn-Requestid header is not allowed');
    });

    it('should reject requests with x-amz-request-id header', async () => {
      // ARRANGE
      const event = createMockEvent({
        httpMethod: 'GET',
        path: '/users',
        headers: {
          ...STANDARD_HEADERS,
          authorization: 'Bearer valid-token',
          'x-amz-request-id': 'test-request-id',
        },
      });
      const context = createMockContext();

      // ACT
      const result = await handler(event, context);

      // ASSERT
      expect(result.statusCode).toBe(400);
      expectCorsHeaders(result);
      const body = JSON.parse(result.body);
      expect(body.message).toBe('X-Amzn-Requestid header is not allowed');
    });

    it('should handle Unauthorized when authorization claims are missing', async () => {
      // ARRANGE
      const event = createMockEvent({
        httpMethod: 'POST',
        path: '/findings/action',
        headers: {
          ...STANDARD_HEADERS,
          authorization: 'Bearer valid-token',
        },
        body: JSON.stringify({ actionType: 'Suppress', findingIds: ['finding-1'] }),
      });
      const context = createMockContext();

      // ACT
      const result = await handler(event, context);

      // ASSERT
      expect(result.statusCode).toBe(401);
      expectCorsHeaders(result);
      const body = JSON.parse(result.body);
      expect(body.message).toMatch(/Could not read claims./);
    });
    it('should create proper API Gateway response', () => {
      // ARRANGE
      const statusCode = 200;
      const body = { message: 'success' };
      const corsHeaders = { 'Access-Control-Allow-Origin': '*' };

      // ACT
      const response = createResponse(statusCode, body, corsHeaders);

      // ASSERT
      expect(response.statusCode).toBe(200);
      expect(response.headers).toEqual(corsHeaders);
      expect(response.body).toBe(JSON.stringify(body));
    });

    it('should handle unsupported route', async () => {
      // ARRANGE
      const event = createMockEvent({
        httpMethod: 'POST',
        path: '/unsupported',
        headers: { ...STANDARD_HEADERS, authorization: 'Bearer valid-token' },
        requestContext: {
          ...TEST_REQUEST_CONTEXT,
          authorizer: {
            claims: {
              'cognito:groups': ['AdminGroup'],
              username: 'myusername',
            },
          },
        },
      });
      const context = createMockContext();

      // ACT
      const result = await handler(event, context);

      // ASSERT
      expect(result.statusCode).toBe(404);
      expectCorsHeaders(result);
      const body = JSON.parse(result.body);
      expect(body.message).toMatch(/Method .+ not found./);
    });
  });

  describe('users routes', () => {
    it('should handle ForbiddenError when claims are missing in GET /users', async () => {
      // ARRANGE
      const event = createMockEvent({
        headers: { ...STANDARD_HEADERS, authorization: 'Bearer valid-token' },
        httpMethod: 'GET',
        path: '/users',
        requestContext: {
          ...TEST_REQUEST_CONTEXT,
          authorizer: {
            claims: {
              'some-claim': 'some-claim-value',
            },
          },
        },
      });
      const context = createMockContext();

      // ACT
      const result = await handler(event, context);

      // ASSERT
      expect(result.statusCode).toBe(401);
      expectCorsHeaders(result);
      const body = JSON.parse(result.body);
      expect(body.message).toMatch(/Could not read claims./);
    });

    it('should handle ForbiddenError when username is missing from claims in GET /users', async () => {
      // ARRANGE
      const event = createMockEvent({
        headers: { authorization: 'Bearer valid-token' },
        httpMethod: 'GET',
        path: '/users',
        requestContext: {
          ...TEST_REQUEST_CONTEXT,
          authorizer: {
            claims: {
              'cognito:groups': ['AdminGroup'],
            },
          },
        },
      });
      const context = createMockContext();

      // ACT
      const result = await handler(event, context);

      // ASSERT
      expect(result.statusCode).toBe(401);
      expectCorsHeaders(result);
      const body = JSON.parse(result.body);
      expect(body.message).toMatch(/Could not read claims./);
    });

    it('should handle ForbiddenError when claims are missing in POST /users', async () => {
      // ARRANGE
      const event = createMockEvent({
        headers: { authorization: 'Bearer valid-token', ...STANDARD_HEADERS },
        httpMethod: 'POST',
        path: '/users',
        requestContext: {
          ...TEST_REQUEST_CONTEXT,
          authorizer: {
            claims: {
              'some-claim': 'some-claim-value',
            },
          },
        },
      });
      const context = createMockContext();

      // ACT
      const result = await handler(event, context);

      // ASSERT
      expect(result.statusCode).toBe(401);
      expectCorsHeaders(result);
      const body = JSON.parse(result.body);
      expect(body.message).toMatch(/Could not read claims./);
    });

    it('should handle ForbiddenError when claims are missing in PUT /users/{id}', async () => {
      // ARRANGE
      const event = createMockEvent({
        headers: { authorization: 'Bearer valid-token', ...STANDARD_HEADERS },
        httpMethod: 'PUT',
        path: '/users/user@example.com',
        pathParameters: { id: 'user@example.com' },
        requestContext: {
          ...TEST_REQUEST_CONTEXT,
          authorizer: {
            claims: {
              'some-claim': 'some-claim-value',
            },
          },
        },
      });
      const context = createMockContext();

      // ACT
      const result = await handler(event, context);

      // ASSERT
      expect(result.statusCode).toBe(401);
      expectCorsHeaders(result);
      const body = JSON.parse(result.body);
      expect(body.message).toMatch(/Could not read claims./);
    });

    it('should handle ForbiddenError when claims are missing in DELETE /users/{id}', async () => {
      // ARRANGE
      const event = createMockEvent({
        headers: { authorization: 'Bearer valid-token' },
        httpMethod: 'DELETE',
        path: '/users/user@example.com',
        pathParameters: { id: 'user@example.com' },
        requestContext: {
          ...TEST_REQUEST_CONTEXT,
          authorizer: {
            claims: {
              'some-claim': 'some-claim-value',
            },
          },
        },
      });
      const context = createMockContext();

      // ACT
      const result = await handler(event, context);

      // ASSERT
      expect(result.statusCode).toBe(401);
      expectCorsHeaders(result);
      const body = JSON.parse(result.body);
      expect(body.message).toMatch(/Could not read claims./);
    });

    it('should route GET /users request successfully', async () => {
      // ARRANGE
      const event = createMockEvent({
        headers: { ...STANDARD_HEADERS, authorization: 'Bearer valid-token' },
        httpMethod: 'GET',
        path: '/users',
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

      cognitoMock.on(ListUsersCommand).resolves({
        Users: [],
      });

      // ACT
      const result = await handler(event, context);

      // ASSERT
      expect(result.statusCode).toBe(200);
      expectCorsHeaders(result);
      expect(result.body).toBeDefined();
    });

    it('should route POST /users request successfully for AdminGroup creating DelegatedAdmin', async () => {
      // ARRANGE
      const event = createMockEvent({
        headers: { ...STANDARD_HEADERS, authorization: 'Bearer valid-token' },
        httpMethod: 'POST',
        path: '/users',
        body: JSON.stringify({
          email: 'delegated@example.com',
          role: 'DelegatedAdmin',
        }),
        requestContext: {
          ...TEST_REQUEST_CONTEXT,
          authorizer: {
            claims: {
              'cognito:groups': ['AdminGroup'],
              username: 'admin@example.com',
            },
          },
        },
      });
      const context = createMockContext();

      cognitoMock.on(AdminCreateUserCommand).resolves({ User: { Username: 'delegated@example.com' } });
      cognitoMock.on(AdminAddUserToGroupCommand).resolves({});

      // ACT
      const result = await handler(event, context);

      // ASSERT
      expect(result.statusCode).toBe(201);
      expectCorsHeaders(result);
      const body = result.body;
      expect(body).toBe(JSON.stringify({ message: 'User invited successfully', email: 'delegated@example.com' }));
    });

    it('should route POST /users request successfully for AdminGroup creating AccountOperator with DynamoDB validation', async () => {
      // ARRANGE
      const event = createMockEvent({
        headers: { ...STANDARD_HEADERS, authorization: 'Bearer valid-token' },
        httpMethod: 'POST',
        path: '/users',
        body: JSON.stringify({
          email: 'operator@example.com',
          role: 'AccountOperator',
          accountIds: ['123456789012'],
        }),
        requestContext: {
          ...TEST_REQUEST_CONTEXT,
          authorizer: {
            claims: {
              'cognito:groups': ['AdminGroup'],
              username: 'admin@example.com',
            },
          },
        },
      });
      const context = createMockContext();

      cognitoMock.on(AdminCreateUserCommand).resolves({ User: { Username: 'operator@example.com' } });
      cognitoMock.on(AdminAddUserToGroupCommand).resolves({});

      // ACT
      const result = await handler(event, context);

      // ASSERT
      expect(result.statusCode).toBe(201);
      expectCorsHeaders(result);
      const body = result.body;
      expect(body).toBe(JSON.stringify({ message: 'User invited successfully', email: 'operator@example.com' }));

      // Verify UserAccountMapping was created in DynamoDB
      const dynamoDBDocumentClient = DynamoDBTestSetup.getDocClient();

      const getResponse = await dynamoDBDocumentClient.send(
        new GetCommand({
          TableName: userAccountMappingTableName,
          Key: { userId: 'operator@example.com' },
        }),
      );
      expect(getResponse.Item).toBeDefined();
      expect(getResponse.Item?.userId).toBe('operator@example.com');
      expect(getResponse.Item?.accountIds).toEqual(['123456789012']);
    });

    it('should handle UnauthorizedError with 401 status', async () => {
      // ARRANGE
      const event = createMockEvent({
        httpMethod: 'GET',
        path: '/users',
      });
      const context = createMockContext();

      // ACT
      const result = await handler(event, context);

      // ASSERT
      expect(result.statusCode).toBe(401);
      expectCorsHeaders(result);
      const body = JSON.parse(result.body);
      expect(body.message).toMatch(/Could not read claims./);
    });

    it('should handle ForbiddenError with 403 status', async () => {
      // ARRANGE
      const event = createMockEvent({
        headers: { authorization: 'Bearer valid-token' },
        httpMethod: 'GET',
        path: '/users',
        requestContext: {
          ...TEST_REQUEST_CONTEXT,
          authorizer: {
            claims: {
              'cognito:groups': ['RegularUserGroup'],
              username: 'testuser@example.com',
            },
          },
        },
      });
      const context = createMockContext();

      // ACT
      const result = await handler(event, context);

      // ASSERT
      expect(result.statusCode).toBe(403);
      expectCorsHeaders(result);
      const body = JSON.parse(result.body);
      expect(body.message).toBe(FORBIDDEN_ERROR_MESSAGE);
    });

    it('should handle generic errors with 400 status', async () => {
      // ARRANGE
      const event = createMockEvent({
        headers: { authorization: 'Bearer valid-token' },
        httpMethod: 'GET',
        path: '/users',
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

      cognitoMock.on(ListUsersCommand).rejects(new Error('Service error'));

      // ACT
      const result = await handler(event, context);

      // ASSERT
      expect(result.statusCode).toBe(400);
      expectCorsHeaders(result);
      const body = JSON.parse(result.body);
      expect(body.message).toBe('An unexpected error occurred.');
    });

    it('should handle DelegatedAdmin access error with proper message', async () => {
      // ARRANGE
      const event = createMockEvent({
        headers: { authorization: 'Bearer valid-token' },
        queryStringParameters: { type: 'admins' },
        requestContext: {
          ...TEST_REQUEST_CONTEXT,
          authorizer: {
            claims: {
              'cognito:groups': ['DelegatedAdminGroup'],
              username: 'testuser@example.com',
            },
          },
        },
      });
      const context = createMockContext();

      // ACT
      const result = await handler(event, context);

      // ASSERT
      expect(result.statusCode).toBe(403);
      expectCorsHeaders(result);
      const body = JSON.parse(result.body);
      expect(body.message).toBe(
        'DelegatedAdminGroup can only fetch Account Operators. You must provide the "type" query parameter with value "accountOperators".',
      );
    });

    it('should handle POST /users validation error for invalid email', async () => {
      // ARRANGE
      const event = createMockEvent({
        headers: { authorization: 'Bearer valid-token', ...STANDARD_HEADERS },
        httpMethod: 'POST',
        path: '/users',
        body: JSON.stringify({
          email: 'invalid-email',
          role: 'DelegatedAdmin',
        }),
        requestContext: {
          ...TEST_REQUEST_CONTEXT,
          authorizer: {
            claims: {
              'cognito:groups': ['AdminGroup'],
              username: 'admin@example.com',
            },
          },
        },
      });
      const context = createMockContext();

      // ACT
      const result = await handler(event, context);

      // ASSERT
      expect(result.statusCode).toBe(400);
      expectCorsHeaders(result);
      const body = JSON.parse(result.body);
      expect(body.message).toMatch(/Invalid request/);
    });

    it('should handle POST /users authorization error for DelegatedAdminGroup creating DelegatedAdmin', async () => {
      // ARRANGE
      const event = createMockEvent({
        headers: { authorization: 'Bearer valid-token', ...STANDARD_HEADERS },
        httpMethod: 'POST',
        path: '/users',
        body: JSON.stringify({
          email: 'delegated@example.com',
          role: 'DelegatedAdmin',
        }),
        requestContext: {
          ...TEST_REQUEST_CONTEXT,
          authorizer: {
            claims: {
              'cognito:groups': ['DelegatedAdminGroup'],
              username: 'delegated@example.com',
            },
          },
        },
      });
      const context = createMockContext();

      // ACT
      const result = await handler(event, context);

      // ASSERT
      expect(result.statusCode).toBe(403);
      expectCorsHeaders(result);
      const body = JSON.parse(result.body);
      expect(body.message).toMatch(/DelegatedAdminGroup can only create AccountOperator users/);
    });

    it('should handle POST /users validation error when invitedBy is included in request body', async () => {
      // ARRANGE
      const event = createMockEvent({
        headers: { authorization: 'Bearer valid-token', ...STANDARD_HEADERS },
        httpMethod: 'POST',
        path: '/users',
        body: JSON.stringify({
          email: 'operator@example.com',
          role: 'AccountOperator',
          accountIds: ['123456789012'],
          invitedBy: 'different@example.com',
        }),
        requestContext: {
          ...TEST_REQUEST_CONTEXT,
          authorizer: {
            claims: {
              'cognito:groups': ['AdminGroup'],
              username: 'admin@example.com',
            },
          },
        },
      });
      const context = createMockContext();

      // ACT
      const result = await handler(event, context);

      // ASSERT
      expect(result.statusCode).toBe(400);
      expectCorsHeaders(result);
      const body = JSON.parse(result.body);
      expect(body.message).toMatch(/Invalid request/);
    });

    it('should successfully create AccountOperator user and verify complete flow', async () => {
      // ARRANGE
      const event = createMockEvent({
        headers: { ...STANDARD_HEADERS, authorization: 'Bearer valid-token' },
        httpMethod: 'POST',
        path: '/users',
        body: JSON.stringify({
          email: 'newoperator@example.com',
          role: 'AccountOperator',
          accountIds: ['111111111111', '222222222222'],
        }),
        requestContext: {
          ...TEST_REQUEST_CONTEXT,
          authorizer: {
            claims: {
              'cognito:groups': ['AdminGroup'],
              username: 'admin@example.com',
            },
          },
        },
      });
      const context = createMockContext();

      cognitoMock.on(AdminCreateUserCommand).resolves({ User: { Username: 'newoperator@example.com' } });
      cognitoMock.on(AdminAddUserToGroupCommand).resolves({});

      // ACT
      const result = await handler(event, context);

      // ASSERT
      expect(result.statusCode).toBe(201);
      expectCorsHeaders(result);
      const body = result.body;
      expect(body).toBe(JSON.stringify({ message: 'User invited successfully', email: 'newoperator@example.com' }));

      // Verify Cognito calls
      expect(cognitoMock).toHaveReceivedCommandWith(AdminCreateUserCommand, {
        UserPoolId: 'us-east-1_testpool',
        Username: 'newoperator@example.com',
        UserAttributes: [
          { Name: 'email', Value: 'newoperator@example.com' },
          { Name: 'email_verified', Value: 'true' },
          { Name: 'custom:invitedBy', Value: 'admin@example.com' },
        ],
      });
      expect(cognitoMock).toHaveReceivedCommandWith(AdminAddUserToGroupCommand, {
        UserPoolId: 'us-east-1_testpool',
        Username: 'newoperator@example.com',
        GroupName: 'AccountOperatorGroup',
      });

      // Verify DynamoDB record creation
      const dynamoDBDocumentClient = DynamoDBTestSetup.getDocClient();
      const getResponse = await dynamoDBDocumentClient.send(
        new GetCommand({
          TableName: userAccountMappingTableName,
          Key: { userId: 'newoperator@example.com' },
        }),
      );
      expect(getResponse.Item).toBeDefined();
      expect(getResponse.Item?.userId).toBe('newoperator@example.com');
      expect(getResponse.Item?.accountIds).toEqual(['111111111111', '222222222222']);
      expect(getResponse.Item?.invitedBy).toBe('admin@example.com');
    });

    it('should successfully create DelegatedAdmin user with complete verification', async () => {
      // ARRANGE
      const event = createMockEvent({
        headers: { ...STANDARD_HEADERS, authorization: 'Bearer valid-token' },
        httpMethod: 'POST',
        path: '/users',
        body: JSON.stringify({
          email: 'newdelegated@example.com',
          role: 'DelegatedAdmin',
        }),
        requestContext: {
          ...TEST_REQUEST_CONTEXT,
          authorizer: {
            claims: {
              'cognito:groups': ['AdminGroup'],
              username: 'admin@example.com',
            },
          },
        },
      });
      const context = createMockContext();

      cognitoMock.on(AdminCreateUserCommand).resolves({ User: { Username: 'newdelegated@example.com' } });
      cognitoMock.on(AdminAddUserToGroupCommand).resolves({});

      // ACT
      const result = await handler(event, context);

      // ASSERT
      expect(result.statusCode).toBe(201);
      expectCorsHeaders(result);
      const body = result.body;
      expect(body).toBe(JSON.stringify({ message: 'User invited successfully', email: 'newdelegated@example.com' }));

      // Verify Cognito calls
      expect(cognitoMock).toHaveReceivedCommandWith(AdminCreateUserCommand, {
        UserPoolId: 'us-east-1_testpool',
        Username: 'newdelegated@example.com',
        UserAttributes: [
          { Name: 'email', Value: 'newdelegated@example.com' },
          { Name: 'email_verified', Value: 'true' },
          { Name: 'custom:invitedBy', Value: 'admin@example.com' },
        ],
      });
      expect(cognitoMock).toHaveReceivedCommandWith(AdminAddUserToGroupCommand, {
        UserPoolId: 'us-east-1_testpool',
        Username: 'newdelegated@example.com',
        GroupName: 'DelegatedAdminGroup',
      });

      // Verify no DynamoDB record created for DelegatedAdmin
      const dynamoDBDocumentClient = DynamoDBTestSetup.getDocClient();
      const getResponse = await dynamoDBDocumentClient.send(
        new GetCommand({
          TableName: userAccountMappingTableName,
          Key: { userId: 'newdelegated@example.com' },
        }),
      );
      expect(getResponse.Item).toBeUndefined();
    });

    it('should route PUT /users/{id} request successfully for AdminGroup updating AccountOperator', async () => {
      // ARRANGE
      const userId = 'operator@example.com';
      const encodedUserId = encodeURIComponent(userId);
      const event = createMockEvent({
        headers: { ...STANDARD_HEADERS, authorization: 'Bearer valid-token' },
        httpMethod: 'PUT',
        path: `/users/${encodedUserId}`,
        pathParameters: { id: encodedUserId },
        body: JSON.stringify({
          type: 'account-operator',
          email: userId,
          status: 'Confirmed',
          accountIds: ['123456789012', '987654321098'],
        }),
        requestContext: {
          ...TEST_REQUEST_CONTEXT,
          authorizer: {
            claims: {
              'cognito:groups': ['AdminGroup'],
              username: 'admin@example.com',
            },
          },
        },
      });
      const context = createMockContext();

      // Mock existing user in Cognito
      cognitoMock.on(AdminGetUserCommand).resolves({
        Username: userId,
        UserAttributes: [
          { Name: 'email', Value: userId },
          { Name: 'custom:invitedBy', Value: 'admin@example.com' },
        ],
        UserCreateDate: new Date('2023-01-01'),
        UserStatus: 'CONFIRMED',
      });
      cognitoMock.on(AdminListGroupsForUserCommand).resolves({
        Groups: [{ GroupName: 'AccountOperatorGroup' }],
      });

      // Create existing user account mapping
      const dynamoDBDocumentClient = DynamoDBTestSetup.getDocClient();
      const existingMapping: UserAccountMapping = {
        userId,
        accountIds: ['111111111111'],
        invitedBy: 'admin@example.com',
        invitationTimestamp: '2023-01-01T00:00:00Z',
      };
      await dynamoDBDocumentClient.send(
        new PutCommand({
          TableName: userAccountMappingTableName,
          Item: existingMapping,
        }),
      );

      // ACT
      const result = await handler(event, context);

      // ASSERT
      expect(result.statusCode).toBe(200);
      expectCorsHeaders(result);
      const body = result.body;
      expect(body).toBe(JSON.stringify({ message: 'User updated successfully' }));

      // Verify DynamoDB was updated
      const getResponse = await dynamoDBDocumentClient.send(
        new GetCommand({
          TableName: userAccountMappingTableName,
          Key: { userId },
        }),
      );
      expect(getResponse.Item?.accountIds).toEqual(['123456789012', '987654321098']);
    });

    it('should handle PUT /users/{id} authorization error for insufficient permissions', async () => {
      // ARRANGE
      const userId = 'operator@example.com';
      const encodedUserId = encodeURIComponent(userId);
      const event = createMockEvent({
        headers: { authorization: 'Bearer valid-token', ...STANDARD_HEADERS },
        httpMethod: 'PUT',
        path: `/users/${encodedUserId}`,
        pathParameters: { id: encodedUserId },
        body: JSON.stringify({
          type: 'account-operator',
          email: userId,
          status: 'Confirmed',
          accountIds: ['123456789012'],
        }),
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
      const result = await handler(event, context);

      // ASSERT
      expect(result.statusCode).toBe(403);
      expectCorsHeaders(result);
      const body = JSON.parse(result.body);
      expect(body.message).toBe(FORBIDDEN_ERROR_MESSAGE);
    });

    it('should handle PUT /users/{id} validation error for invalid user type', async () => {
      // ARRANGE
      const userId = 'user@example.com';
      const encodedUserId = encodeURIComponent(userId);
      const event = createMockEvent({
        headers: { authorization: 'Bearer valid-token', ...STANDARD_HEADERS },
        httpMethod: 'PUT',
        path: `/users/${encodedUserId}`,
        pathParameters: { id: encodedUserId },
        body: JSON.stringify({
          type: 'admin',
          email: userId,
          status: 'Confirmed',
          accountIds: ['123456789012'],
        }),
        requestContext: {
          ...TEST_REQUEST_CONTEXT,
          authorizer: {
            claims: {
              'cognito:groups': ['AdminGroup'],
              username: 'admin@example.com',
            },
          },
        },
      });
      const context = createMockContext();

      // ACT
      const result = await handler(event, context);

      // ASSERT
      expect(result.statusCode).toBe(400);
      expectCorsHeaders(result);
      const body = JSON.parse(result.body);
      expect(body.message).toBe('Only account-operator users can be updated');
    });

    it('should handle PUT /users/{id} validation error for empty accountIds array', async () => {
      // ARRANGE
      const userId = 'operator@example.com';
      const encodedUserId = encodeURIComponent(userId);
      const event = createMockEvent({
        headers: { authorization: 'Bearer valid-token', ...STANDARD_HEADERS },
        httpMethod: 'PUT',
        path: `/users/${encodedUserId}`,
        pathParameters: { id: encodedUserId },
        body: JSON.stringify({
          type: 'account-operator',
          email: userId,
          status: 'Confirmed',
          accountIds: [],
        }),
        requestContext: {
          ...TEST_REQUEST_CONTEXT,
          authorizer: {
            claims: {
              'cognito:groups': ['AdminGroup'],
              username: 'admin@example.com',
            },
          },
        },
      });
      const context = createMockContext();

      // ACT
      const result = await handler(event, context);

      // ASSERT
      expect(result.statusCode).toBe(400);
      expectCorsHeaders(result);
      const body = JSON.parse(result.body);
      expect(body.message).toMatch(/Invalid request/);
    });

    it('should handle PUT /users/{id} validation error when invitedBy is included in request body', async () => {
      // ARRANGE
      const userId = 'operator@example.com';
      const encodedUserId = encodeURIComponent(userId);
      const event = createMockEvent({
        headers: { authorization: 'Bearer valid-token', ...STANDARD_HEADERS },
        httpMethod: 'PUT',
        path: `/users/${encodedUserId}`,
        pathParameters: { id: encodedUserId },
        body: JSON.stringify({
          type: 'account-operator',
          email: userId,
          invitedBy: 'different@example.com',
          status: 'Confirmed',
          accountIds: ['123456789012'],
        }),
        requestContext: {
          ...TEST_REQUEST_CONTEXT,
          authorizer: {
            claims: {
              'cognito:groups': ['AdminGroup'],
              username: 'admin@example.com',
            },
          },
        },
      });
      const context = createMockContext();

      // ACT
      const result = await handler(event, context);

      // ASSERT
      expect(result.statusCode).toBe(400);
      expectCorsHeaders(result);
      const body = JSON.parse(result.body);
      expect(body.message).toMatch(/Invalid request/);
    });

    it('should route DELETE /users/{id} request successfully for AdminGroup deleting AccountOperator', async () => {
      // ARRANGE
      const userId = 'operator@example.com';
      const encodedUserId = encodeURIComponent(userId);
      const event = createMockEvent({
        headers: { ...STANDARD_HEADERS, authorization: 'Bearer valid-token' },
        httpMethod: 'DELETE',
        path: `/users/${encodedUserId}`,
        pathParameters: { id: encodedUserId },
        requestContext: {
          ...TEST_REQUEST_CONTEXT,
          authorizer: {
            claims: {
              'cognito:groups': ['AdminGroup'],
              username: 'admin@example.com',
            },
          },
        },
      });
      const context = createMockContext();

      cognitoMock.on(AdminGetUserCommand).resolves({
        Username: userId,
        UserAttributes: [
          { Name: 'email', Value: userId },
          { Name: 'custom:invitedBy', Value: 'admin@example.com' },
        ],
        UserCreateDate: new Date('2023-01-01'),
        UserStatus: 'CONFIRMED',
      });
      cognitoMock.on(AdminListGroupsForUserCommand).resolves({
        Groups: [{ GroupName: 'AccountOperatorGroup' }],
      });
      cognitoMock.on(AdminDeleteUserCommand).resolves({});

      // ACT
      const result = await handler(event, context);

      // ASSERT
      expect(result.statusCode).toBe(200);
      expectCorsHeaders(result);
      const body = result.body;
      expect(body).toBe(JSON.stringify({ message: 'User deleted successfully' }));
    });

    it('should handle DELETE /users/{id} authorization error for insufficient permissions', async () => {
      // ARRANGE
      const userId = 'operator@example.com';
      const encodedUserId = encodeURIComponent(userId);
      const event = createMockEvent({
        headers: { authorization: 'Bearer valid-token' },
        httpMethod: 'DELETE',
        path: `/users/${encodedUserId}`,
        pathParameters: { id: encodedUserId },
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

      cognitoMock.on(AdminGetUserCommand).resolves({
        Username: userId,
        UserAttributes: [
          { Name: 'email', Value: userId },
          { Name: 'custom:invitedBy', Value: 'admin@example.com' },
        ],
        UserCreateDate: new Date('2023-01-01'),
        UserStatus: 'CONFIRMED',
      });
      cognitoMock.on(AdminListGroupsForUserCommand).resolves({
        Groups: [{ GroupName: 'AccountOperatorGroup' }],
      });

      // ACT
      const result = await handler(event, context);

      // ASSERT
      expect(result.statusCode).toBe(403);
      expectCorsHeaders(result);
      const body = JSON.parse(result.body);
      expect(body.message).toBe(FORBIDDEN_ERROR_MESSAGE);
    });

    it('should handle DELETE /users/{id} validation error for invalid email', async () => {
      // ARRANGE
      const userId = 'invalid-email';
      const encodedUserId = encodeURIComponent(userId);
      const event = createMockEvent({
        headers: { authorization: 'Bearer valid-token' },
        httpMethod: 'DELETE',
        path: `/users/${encodedUserId}`,
        pathParameters: { id: encodedUserId },
        requestContext: {
          ...TEST_REQUEST_CONTEXT,
          authorizer: {
            claims: {
              'cognito:groups': ['AdminGroup'],
              username: 'admin@example.com',
            },
          },
        },
      });
      const context = createMockContext();

      // ACT
      const result = await handler(event, context);

      // ASSERT
      expect(result.statusCode).toBe(400);
      expectCorsHeaders(result);
      const body = JSON.parse(result.body);
      expect(body.message).toMatch(/Valid email address is required for user ID/);
    });

    it('should handle DELETE /users/{id} not found error', async () => {
      // ARRANGE
      const userId = 'notfound@example.com';
      const encodedUserId = encodeURIComponent(userId);
      const event = createMockEvent({
        headers: { authorization: 'Bearer valid-token' },
        httpMethod: 'DELETE',
        path: `/users/${encodedUserId}`,
        pathParameters: { id: encodedUserId },
        requestContext: {
          ...TEST_REQUEST_CONTEXT,
          authorizer: {
            claims: {
              'cognito:groups': ['AdminGroup'],
              username: 'admin@example.com',
            },
          },
        },
      });
      const context = createMockContext();

      cognitoMock.on(AdminGetUserCommand).resolves({});

      // ACT
      const result = await handler(event, context);

      // ASSERT
      expect(result.statusCode).toBe(404);
      expectCorsHeaders(result);
      const body = JSON.parse(result.body);
      expect(body.message).toMatch(/not found/);
    });

    it('should route DELETE /users/{id} request successfully for DelegatedAdminGroup deleting AccountOperator', async () => {
      // ARRANGE
      const userId = 'operator@example.com';
      const encodedUserId = 'operator%40example.com'; // testing without encodeURIComponent
      const event = createMockEvent({
        headers: { ...STANDARD_HEADERS, authorization: 'Bearer valid-token' },
        httpMethod: 'DELETE',
        path: `/users/${encodedUserId}`,
        pathParameters: { id: encodedUserId },
        requestContext: {
          ...TEST_REQUEST_CONTEXT,
          authorizer: {
            claims: {
              'cognito:groups': ['DelegatedAdminGroup'],
              username: 'delegated@example.com',
            },
          },
        },
      });
      const context = createMockContext();

      cognitoMock.on(AdminGetUserCommand).resolves({
        Username: userId,
        UserAttributes: [
          { Name: 'email', Value: userId },
          { Name: 'custom:invitedBy', Value: 'admin@example.com' },
        ],
        UserCreateDate: new Date('2023-01-01'),
        UserStatus: 'CONFIRMED',
      });
      cognitoMock.on(AdminListGroupsForUserCommand).resolves({
        Groups: [{ GroupName: 'AccountOperatorGroup' }],
      });
      cognitoMock.on(AdminDeleteUserCommand).resolves({});

      // ACT
      const result = await handler(event, context);

      // ASSERT
      expect(result.statusCode).toBe(200);
      expectCorsHeaders(result);
      const body = result.body;
      expect(body).toBe(JSON.stringify({ message: 'User deleted successfully' }));
    });
  });

  describe('controls routes', () => {
    it('should route GET /controls request successfully', async () => {
      // ARRANGE
      const event = createMockEvent({
        headers: { ...STANDARD_HEADERS, authorization: 'Bearer valid-token' },
        httpMethod: 'GET',
        path: '/controls',
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
      const result = await handler(event, context);

      // ASSERT
      expect(result.statusCode).toBe(200);
      expectCorsHeaders(result);
      const body = JSON.parse(result.body);
      expect(body.controls).toBeDefined();
      expect(Array.isArray(body.controls)).toBe(true);
    });

    it('should handle ForbiddenError when user has no valid groups for GET /controls', async () => {
      // ARRANGE
      const event = createMockEvent({
        headers: { ...STANDARD_HEADERS, authorization: 'Bearer valid-token' },
        httpMethod: 'GET',
        path: '/controls',
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

      // ACT
      const result = await handler(event, context);

      // ASSERT
      expect(result.statusCode).toBe(403);
      expectCorsHeaders(result);
      const body = JSON.parse(result.body);
      expect(body.message).toBe(FORBIDDEN_ERROR_MESSAGE);
    });

    it('should authorize a machine (client_credentials) token with the full-access scope for GET /controls', async () => {
      // ARRANGE: a client_credentials token carries neither `cognito:groups` nor
      // `username` — only `sub`/`client_id`/`scope`. The full-access scope must be
      // honored even though the human-claims are absent.
      const clientId = 'machine-client-id';
      const event = createMockEvent({
        headers: { ...STANDARD_HEADERS, authorization: 'Bearer valid-machine-token' },
        httpMethod: 'GET',
        path: '/controls',
        requestContext: {
          ...TEST_REQUEST_CONTEXT,
          authorizer: {
            claims: {
              sub: clientId,
              client_id: clientId,
              scope: 'asr-api/api asr-api/full-access',
            },
          },
        },
      });
      const context = createMockContext();

      // ACT
      const result = await handler(event, context);

      // ASSERT
      expect(result.statusCode).toBe(200);
      expectCorsHeaders(result);
      const body = JSON.parse(result.body);
      expect(body.controls).toBeDefined();
      expect(Array.isArray(body.controls)).toBe(true);
    });

    it('should reject a machine token without the full-access scope for GET /controls', async () => {
      // ARRANGE: a machine token granted only the base scope must fail closed.
      const clientId = 'machine-client-id';
      const event = createMockEvent({
        headers: { ...STANDARD_HEADERS, authorization: 'Bearer valid-machine-token' },
        httpMethod: 'GET',
        path: '/controls',
        requestContext: {
          ...TEST_REQUEST_CONTEXT,
          authorizer: {
            claims: {
              sub: clientId,
              client_id: clientId,
              scope: 'asr-api/api',
            },
          },
        },
      });
      const context = createMockContext();

      // ACT
      const result = await handler(event, context);

      // ASSERT
      expect(result.statusCode).toBe(403);
      expectCorsHeaders(result);
      const body = JSON.parse(result.body);
      expect(body.message).toBe(FORBIDDEN_ERROR_MESSAGE);
    });

    it('should route POST /controls/bulk-edit request successfully for AdminGroup', async () => {
      // ARRANGE
      const dynamoDBDocumentClient = DynamoDBTestSetup.getDocClient();

      // Create a test control in the config table
      await dynamoDBDocumentClient.send(
        new PutCommand({
          TableName: remediationConfigTableName,
          Item: {
            controlId: 'S3.1',
            description: 'Test control',
            automatedRemediationEnabled: false,
            filterMode: 'include',
            version: 1,
            lastModified: '2024-01-01T00:00:00Z',
            modifiedBy: 'system',
          },
        }),
      );

      const event = createMockEvent({
        headers: { ...STANDARD_HEADERS, authorization: 'Bearer valid-token' },
        httpMethod: 'POST',
        path: '/controls/bulk-edit',
        body: JSON.stringify({
          operation: 'update',
          data: [
            {
              controlId: 'S3.1',
              description: 'Test control',
              automatedRemediationEnabled: true,
              filters: [],
              filterMode: 'include',
              version: 1,
              lastModified: '2024-01-01T00:00:00Z',
              modifiedBy: 'system',
            },
          ],
        }),
        requestContext: {
          ...TEST_REQUEST_CONTEXT,
          authorizer: {
            claims: {
              'cognito:groups': ['AdminGroup'],
              username: 'admin@example.com',
            },
          },
        },
      });
      const context = createMockContext();

      // ACT
      const result = await handler(event, context);

      // ASSERT
      expect(result.statusCode).toBe(200);
      expectCorsHeaders(result);
      const body = JSON.parse(result.body);
      expect(body.message).toBe('Controls updated successfully');
      expect(body.updatedCount).toBe(1);

      // Verify DynamoDB was updated
      const getResponse = await dynamoDBDocumentClient.send(
        new GetCommand({
          TableName: remediationConfigTableName,
          Key: { controlId: 'S3.1' },
        }),
      );
      expect(getResponse.Item?.automatedRemediationEnabled).toBe(true);
      expect(getResponse.Item?.version).toBe(2);
    });

    it('should handle ForbiddenError when AccountOperator tries POST /controls/bulk-edit', async () => {
      // ARRANGE
      const event = createMockEvent({
        headers: { ...STANDARD_HEADERS, authorization: 'Bearer valid-token' },
        httpMethod: 'POST',
        path: '/controls/bulk-edit',
        body: JSON.stringify({
          operation: 'update',
          data: [
            {
              controlId: 'S3.1',
              description: 'Test control',
              automatedRemediationEnabled: true,
              filters: [],
              filterMode: 'include',
              version: 1,
              lastModified: '2024-01-01T00:00:00Z',
              modifiedBy: 'system',
            },
          ],
        }),
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
      const result = await handler(event, context);

      // ASSERT
      expect(result.statusCode).toBe(403);
      expectCorsHeaders(result);
      const body = JSON.parse(result.body);
      expect(body.message).toBe(FORBIDDEN_ERROR_MESSAGE);
    });

    it('should route POST /controls/bulk-edit applyFilterToAll request successfully for AdminGroup', async () => {
      // ARRANGE
      const dynamoDBDocumentClient = DynamoDBTestSetup.getDocClient();

      await dynamoDBDocumentClient.send(
        new PutCommand({
          TableName: remediationConfigTableName,
          Item: {
            controlId: 'S3.1',
            description: 'Test control',
            automatedRemediationEnabled: false,
            filterMode: 'include',
            version: 1,
            lastModified: '2024-01-01T00:00:00Z',
            modifiedBy: 'system',
          },
        }),
      );

      const filterId = '550e8400-e29b-41d4-a716-446655440000';
      const event = createMockEvent({
        headers: { ...STANDARD_HEADERS, authorization: 'Bearer valid-token' },
        httpMethod: 'POST',
        path: '/controls/bulk-edit',
        body: JSON.stringify({
          operation: 'applyFilterToAll',
          data: filterId,
        }),
        requestContext: {
          ...TEST_REQUEST_CONTEXT,
          authorizer: {
            claims: {
              'cognito:groups': ['AdminGroup'],
              username: 'admin@example.com',
            },
          },
        },
      });
      const context = createMockContext();

      // ACT
      const result = await handler(event, context);

      // ASSERT
      expect(result.statusCode).toBe(200);
      expectCorsHeaders(result);
      const body = JSON.parse(result.body);
      expect(body.message).toBe('Filter applied to all controls successfully');
      expect(body.updatedCount).toBe(1);

      const getResponse = await dynamoDBDocumentClient.send(
        new GetCommand({
          TableName: remediationConfigTableName,
          Key: { controlId: 'S3.1' },
        }),
      );
      expect(getResponse.Item?.version).toBe(2);
      expect(Array.from(getResponse.Item?.filters as Set<string>)).toContain(filterId);
    });

    it('should handle validation error for invalid UUID in applyFilterToAll', async () => {
      // ARRANGE
      const event = createMockEvent({
        headers: { ...STANDARD_HEADERS, authorization: 'Bearer valid-token' },
        httpMethod: 'POST',
        path: '/controls/bulk-edit',
        body: JSON.stringify({
          operation: 'applyFilterToAll',
          data: 'not-a-valid-uuid',
        }),
        requestContext: {
          ...TEST_REQUEST_CONTEXT,
          authorizer: {
            claims: {
              'cognito:groups': ['AdminGroup'],
              username: 'admin@example.com',
            },
          },
        },
      });
      const context = createMockContext();

      // ACT
      const result = await handler(event, context);

      // ASSERT
      expect(result.statusCode).toBe(400);
      expectCorsHeaders(result);
      const body = JSON.parse(result.body);
      expect(body.message).toMatch(/Invalid bulk edit request/);
    });

    it('should handle ForbiddenError when AccountOperator tries applyFilterToAll', async () => {
      // ARRANGE
      const event = createMockEvent({
        headers: { ...STANDARD_HEADERS, authorization: 'Bearer valid-token' },
        httpMethod: 'POST',
        path: '/controls/bulk-edit',
        body: JSON.stringify({
          operation: 'applyFilterToAll',
          data: '550e8400-e29b-41d4-a716-446655440000',
        }),
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
      const result = await handler(event, context);

      // ASSERT
      expect(result.statusCode).toBe(403);
      expectCorsHeaders(result);
      const body = JSON.parse(result.body);
      expect(body.message).toBe(FORBIDDEN_ERROR_MESSAGE);
    });
  });

  describe('filters routes', () => {
    it('should route GET /filters request successfully', async () => {
      // ARRANGE
      const event = createMockEvent({
        headers: { ...STANDARD_HEADERS, authorization: 'Bearer valid-token' },
        httpMethod: 'GET',
        path: '/filters',
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
      const result = await handler(event, context);

      // ASSERT
      expect(result.statusCode).toBe(200);
      expectCorsHeaders(result);
      const body = JSON.parse(result.body);
      expect(body.filters).toBeDefined();
      expect(Array.isArray(body.filters)).toBe(true);
    });

    it('should return filters data when table has items', async () => {
      // ARRANGE
      const dynamoDBDocumentClient = DynamoDBTestSetup.getDocClient();
      await dynamoDBDocumentClient.send(
        new PutCommand({
          TableName: resourceFiltersTableName,
          Item: {
            filterId: '550e8400-e29b-41d4-a716-446655440000',
            name: 'Production Filter',
            accountIds: new Set(['123456789012']),
            version: 1,
            createdAt: '2024-01-01T00:00:00Z',
            createdBy: 'admin@example.com',
            lastModified: '2024-01-01T00:00:00Z',
            modifiedBy: 'admin@example.com',
          },
        }),
      );

      const event = createMockEvent({
        headers: { ...STANDARD_HEADERS, authorization: 'Bearer valid-token' },
        httpMethod: 'GET',
        path: '/filters',
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
      const result = await handler(event, context);

      // ASSERT
      expect(result.statusCode).toBe(200);
      expectCorsHeaders(result);
      const body = JSON.parse(result.body);
      expect(body.filters).toHaveLength(1);
      expect(body.filters[0].filterId).toBe('550e8400-e29b-41d4-a716-446655440000');
      expect(body.filters[0].name).toBe('Production Filter');
    });

    it('should handle ForbiddenError when user has no valid groups for GET /filters', async () => {
      // ARRANGE
      const event = createMockEvent({
        headers: { ...STANDARD_HEADERS, authorization: 'Bearer valid-token' },
        httpMethod: 'GET',
        path: '/filters',
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

      // ACT
      const result = await handler(event, context);

      // ASSERT
      expect(result.statusCode).toBe(403);
      expectCorsHeaders(result);
      const body = JSON.parse(result.body);
      expect(body.message).toBe(FORBIDDEN_ERROR_MESSAGE);
    });

    it('should route PUT /filters/{filterId} request successfully for AdminGroup', async () => {
      // ARRANGE
      const dynamoDBDocumentClient = DynamoDBTestSetup.getDocClient();
      const filterId = '550e8400-e29b-41d4-a716-446655440000';

      await dynamoDBDocumentClient.send(
        new PutCommand({
          TableName: resourceFiltersTableName,
          Item: {
            filterId,
            name: 'Original Name',
            accountIds: new Set(['123456789012']),
            tags: [{ key: 'Env', value: 'Prod' }],
            version: 1,
            createdAt: '2024-01-01T00:00:00Z',
            createdBy: 'admin@example.com',
            lastModified: '2024-01-01T00:00:00Z',
            modifiedBy: 'admin@example.com',
          },
        }),
      );

      const event = createMockEvent({
        headers: { ...STANDARD_HEADERS, authorization: 'Bearer valid-token' },
        httpMethod: 'PUT',
        path: `/filters/${filterId}`,
        pathParameters: { filterId },
        body: JSON.stringify({
          name: 'Updated Name',
          accountIds: ['123456789012', '987654321098'],
          organizationalUnits: [],
          tags: [{ key: 'Env', value: 'Staging' }],
          arnPatterns: [],
          version: 1,
        }),
        requestContext: {
          ...TEST_REQUEST_CONTEXT,
          authorizer: {
            claims: {
              'cognito:groups': ['AdminGroup'],
              username: 'admin@example.com',
            },
          },
        },
      });
      const context = createMockContext();

      // ACT
      const result = await handler(event, context);

      // ASSERT
      expect(result.statusCode).toBe(200);
      expectCorsHeaders(result);
      const body = JSON.parse(result.body);
      expect(body.name).toBe('Updated Name');
      expect(body.version).toBe(2);
      expect(body.modifiedBy).toBe('admin@example.com');
    });

    it('should handle ForbiddenError when AccountOperator tries PUT /filters/{filterId}', async () => {
      // ARRANGE
      const filterId = '550e8400-e29b-41d4-a716-446655440000';
      const event = createMockEvent({
        headers: { ...STANDARD_HEADERS, authorization: 'Bearer valid-token' },
        httpMethod: 'PUT',
        path: `/filters/${filterId}`,
        pathParameters: { filterId },
        body: JSON.stringify({
          name: 'Updated Name',
          accountIds: ['123456789012'],
          organizationalUnits: [],
          tags: [],
          arnPatterns: [],
          version: 1,
        }),
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
      const result = await handler(event, context);

      // ASSERT
      expect(result.statusCode).toBe(403);
      expectCorsHeaders(result);
      const body = JSON.parse(result.body);
      expect(body.message).toBe(FORBIDDEN_ERROR_MESSAGE);
    });

    it('should handle validation error for invalid request body in PUT /filters/{filterId}', async () => {
      // ARRANGE
      const filterId = '550e8400-e29b-41d4-a716-446655440000';
      const event = createMockEvent({
        headers: { ...STANDARD_HEADERS, authorization: 'Bearer valid-token' },
        httpMethod: 'PUT',
        path: `/filters/${filterId}`,
        pathParameters: { filterId },
        body: JSON.stringify({
          name: 'Empty Filter',
          accountIds: [],
          organizationalUnits: [],
          tags: [],
          arnPatterns: [],
          version: 1,
        }),
        requestContext: {
          ...TEST_REQUEST_CONTEXT,
          authorizer: {
            claims: {
              'cognito:groups': ['AdminGroup'],
              username: 'admin@example.com',
            },
          },
        },
      });
      const context = createMockContext();

      // ACT
      const result = await handler(event, context);

      // ASSERT
      expect(result.statusCode).toBe(400);
      expectCorsHeaders(result);
      const body = JSON.parse(result.body);
      expect(body.message).toMatch(/Invalid filter update request/);
    });

    it('should return 409 Conflict when version does not match in PUT /filters/{filterId}', async () => {
      // ARRANGE
      const dynamoDBDocumentClient = DynamoDBTestSetup.getDocClient();
      const filterId = '550e8400-e29b-41d4-a716-446655440000';

      await dynamoDBDocumentClient.send(
        new PutCommand({
          TableName: resourceFiltersTableName,
          Item: {
            filterId,
            name: 'Original Name',
            accountIds: new Set(['123456789012']),
            tags: [{ key: 'Env', value: 'Prod' }],
            version: 5,
            createdAt: '2024-01-01T00:00:00Z',
            createdBy: 'admin@example.com',
            lastModified: '2024-01-01T00:00:00Z',
            modifiedBy: 'admin@example.com',
          },
        }),
      );

      const event = createMockEvent({
        headers: { ...STANDARD_HEADERS, authorization: 'Bearer valid-token' },
        httpMethod: 'PUT',
        path: `/filters/${filterId}`,
        pathParameters: { filterId },
        body: JSON.stringify({
          name: 'Updated Name',
          accountIds: ['123456789012'],
          organizationalUnits: [],
          tags: [{ key: 'Env', value: 'Staging' }],
          arnPatterns: [],
          version: 1,
        }),
        requestContext: {
          ...TEST_REQUEST_CONTEXT,
          authorizer: {
            claims: {
              'cognito:groups': ['AdminGroup'],
              username: 'admin@example.com',
            },
          },
        },
      });
      const context = createMockContext();

      // ACT
      const result = await handler(event, context);

      // ASSERT
      expect(result.statusCode).toBe(409);
      expectCorsHeaders(result);
      const body = JSON.parse(result.body);
      expect(body.message).toMatch(/Data was modified by another user/);
    });

    it('should route POST /filters request successfully for AdminGroup', async () => {
      // ARRANGE
      const event = createMockEvent({
        headers: { ...STANDARD_HEADERS, authorization: 'Bearer valid-token' },
        httpMethod: 'POST',
        path: '/filters',
        body: JSON.stringify({
          name: 'New Filter',
          accountIds: ['123456789012'],
          organizationalUnits: [],
          tags: [{ key: 'Env', value: 'Prod' }],
          arnPatterns: [],
        }),
        requestContext: {
          ...TEST_REQUEST_CONTEXT,
          authorizer: {
            claims: {
              'cognito:groups': ['AdminGroup'],
              username: 'admin@example.com',
            },
          },
        },
      });
      const context = createMockContext();

      // ACT
      const result = await handler(event, context);

      // ASSERT
      expect(result.statusCode).toBe(201);
      expectCorsHeaders(result);
      const body = JSON.parse(result.body);
      expect(body.filterId).toBeDefined();
      expect(body.name).toBe('New Filter');
      expect(body.accountIds).toEqual(['123456789012']);
      expect(body.version).toBe(1);
      expect(body.createdBy).toBe('admin@example.com');
    });

    it('should handle ForbiddenError when AccountOperator tries POST /filters', async () => {
      // ARRANGE
      const event = createMockEvent({
        headers: { ...STANDARD_HEADERS, authorization: 'Bearer valid-token' },
        httpMethod: 'POST',
        path: '/filters',
        body: JSON.stringify({
          name: 'New Filter',
          accountIds: ['123456789012'],
          organizationalUnits: [],
          tags: [],
          arnPatterns: [],
        }),
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
      const result = await handler(event, context);

      // ASSERT
      expect(result.statusCode).toBe(403);
      expectCorsHeaders(result);
      const body = JSON.parse(result.body);
      expect(body.message).toBe(FORBIDDEN_ERROR_MESSAGE);
    });

    it('should handle validation error for invalid request body in POST /filters', async () => {
      // ARRANGE
      const event = createMockEvent({
        headers: { ...STANDARD_HEADERS, authorization: 'Bearer valid-token' },
        httpMethod: 'POST',
        path: '/filters',
        body: JSON.stringify({
          name: 'Empty Filter',
          accountIds: [],
          organizationalUnits: [],
          tags: [],
          arnPatterns: [],
        }),
        requestContext: {
          ...TEST_REQUEST_CONTEXT,
          authorizer: {
            claims: {
              'cognito:groups': ['AdminGroup'],
              username: 'admin@example.com',
            },
          },
        },
      });
      const context = createMockContext();

      // ACT
      const result = await handler(event, context);

      // ASSERT
      expect(result.statusCode).toBe(400);
      expectCorsHeaders(result);
      const body = JSON.parse(result.body);
      expect(body.message).toMatch(/Invalid filter creation request/);
    });

    it('should return 400 when filter name already exists in POST /filters', async () => {
      // ARRANGE
      const dynamoDBDocumentClient = DynamoDBTestSetup.getDocClient();
      await dynamoDBDocumentClient.send(
        new PutCommand({
          TableName: resourceFiltersTableName,
          Item: {
            filterId: '550e8400-e29b-41d4-a716-446655440099',
            name: 'Existing Filter',
            accountIds: new Set(['111111111111']),
            version: 1,
            createdAt: '2024-01-01T00:00:00Z',
            createdBy: 'admin@example.com',
            lastModified: '2024-01-01T00:00:00Z',
            modifiedBy: 'admin@example.com',
          },
        }),
      );

      const event = createMockEvent({
        headers: { ...STANDARD_HEADERS, authorization: 'Bearer valid-token' },
        httpMethod: 'POST',
        path: '/filters',
        body: JSON.stringify({
          name: 'Existing Filter',
          accountIds: ['123456789012'],
          organizationalUnits: [],
          tags: [],
          arnPatterns: [],
        }),
        requestContext: {
          ...TEST_REQUEST_CONTEXT,
          authorizer: {
            claims: {
              'cognito:groups': ['AdminGroup'],
              username: 'admin@example.com',
            },
          },
        },
      });
      const context = createMockContext();

      // ACT
      const result = await handler(event, context);

      // ASSERT
      expect(result.statusCode).toBe(400);
      expectCorsHeaders(result);
      const body = JSON.parse(result.body);
      expect(body.message).toMatch(/A filter with the name "Existing Filter" already exists/);
    });

    it('should route DELETE /filters/{filterId} request successfully for AdminGroup', async () => {
      // ARRANGE
      const dynamoDBDocumentClient = DynamoDBTestSetup.getDocClient();
      const filterId = '550e8400-e29b-41d4-a716-446655440000';

      await dynamoDBDocumentClient.send(
        new PutCommand({
          TableName: resourceFiltersTableName,
          Item: {
            filterId,
            name: 'Filter To Delete',
            accountIds: new Set(['123456789012']),
            version: 1,
            createdAt: '2024-01-01T00:00:00Z',
            createdBy: 'admin@example.com',
            lastModified: '2024-01-01T00:00:00Z',
            modifiedBy: 'admin@example.com',
          },
        }),
      );

      const event = createMockEvent({
        headers: { ...STANDARD_HEADERS, authorization: 'Bearer valid-token' },
        httpMethod: 'DELETE',
        path: `/filters/${filterId}`,
        pathParameters: { filterId },
        requestContext: {
          ...TEST_REQUEST_CONTEXT,
          authorizer: {
            claims: {
              'cognito:groups': ['AdminGroup'],
              username: 'admin@example.com',
            },
          },
        },
      });
      const context = createMockContext();

      // ACT
      const result = await handler(event, context);

      // ASSERT
      expect(result.statusCode).toBe(200);
      expectCorsHeaders(result);
      const body = JSON.parse(result.body);
      expect(body.message).toBe('Filter deleted successfully');
      expect(body.affectedControlIds).toEqual([]);
    });

    it('should handle ForbiddenError when AccountOperator tries DELETE /filters/{filterId}', async () => {
      // ARRANGE
      const filterId = '550e8400-e29b-41d4-a716-446655440000';
      const event = createMockEvent({
        headers: { ...STANDARD_HEADERS, authorization: 'Bearer valid-token' },
        httpMethod: 'DELETE',
        path: `/filters/${filterId}`,
        pathParameters: { filterId },
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
      const result = await handler(event, context);

      // ASSERT
      expect(result.statusCode).toBe(403);
      expectCorsHeaders(result);
      const body = JSON.parse(result.body);
      expect(body.message).toBe(FORBIDDEN_ERROR_MESSAGE);
    });

    it('should return 400 for invalid UUID in DELETE /filters/{filterId}', async () => {
      // ARRANGE
      const event = createMockEvent({
        headers: { ...STANDARD_HEADERS, authorization: 'Bearer valid-token' },
        httpMethod: 'DELETE',
        path: '/filters/not-a-uuid',
        pathParameters: { filterId: 'not-a-uuid' },
        requestContext: {
          ...TEST_REQUEST_CONTEXT,
          authorizer: {
            claims: {
              'cognito:groups': ['AdminGroup'],
              username: 'admin@example.com',
            },
          },
        },
      });
      const context = createMockContext();

      // ACT
      const result = await handler(event, context);

      // ASSERT
      expect(result.statusCode).toBe(400);
      expectCorsHeaders(result);
      const body = JSON.parse(result.body);
      expect(body.message).toMatch(/filterId must be a valid UUID/);
    });

    it('should delete filter and remove it from associated controls via DELETE /filters/{filterId}', async () => {
      // ARRANGE
      const dynamoDBDocumentClient = DynamoDBTestSetup.getDocClient();
      const filterId = '550e8400-e29b-41d4-a716-446655440000';

      await dynamoDBDocumentClient.send(
        new PutCommand({
          TableName: resourceFiltersTableName,
          Item: {
            filterId,
            name: 'Filter With Controls',
            accountIds: new Set(['123456789012']),
            version: 1,
            createdAt: '2024-01-01T00:00:00Z',
            createdBy: 'admin@example.com',
            lastModified: '2024-01-01T00:00:00Z',
            modifiedBy: 'admin@example.com',
          },
        }),
      );
      await dynamoDBDocumentClient.send(
        new PutCommand({
          TableName: remediationConfigTableName,
          Item: {
            controlId: 'S3.1',
            automatedRemediationEnabled: true,
            filters: new Set([filterId]),
            filterMode: 'include',
            version: 1,
          },
        }),
      );

      const event = createMockEvent({
        headers: { ...STANDARD_HEADERS, authorization: 'Bearer valid-token' },
        httpMethod: 'DELETE',
        path: `/filters/${filterId}`,
        pathParameters: { filterId },
        requestContext: {
          ...TEST_REQUEST_CONTEXT,
          authorizer: {
            claims: {
              'cognito:groups': ['AdminGroup'],
              username: 'admin@example.com',
            },
          },
        },
      });
      const context = createMockContext();

      // ACT
      const result = await handler(event, context);

      // ASSERT
      expect(result.statusCode).toBe(200);
      expectCorsHeaders(result);
      const body = JSON.parse(result.body);
      expect(body.message).toBe('Filter deleted successfully');
      expect(body.affectedControlIds).toEqual(['S3.1']);
    });
  });
});
