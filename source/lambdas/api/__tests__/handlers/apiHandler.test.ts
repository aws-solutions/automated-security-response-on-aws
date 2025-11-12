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
import { userAccountMappingTableName } from '../../../common/__tests__/envSetup';
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

describe('Top-level routing', () => {
  beforeAll(async () => {
    await DynamoDBTestSetup.initialize();
    await DynamoDBTestSetup.createUserAccountMappingTable(userAccountMappingTableName);
  });

  afterAll(async () => {
    await DynamoDBTestSetup.deleteTable(userAccountMappingTableName);
    cleanupMetricsMocks();
  });

  beforeEach(async () => {
    await DynamoDBTestSetup.clearTable(userAccountMappingTableName, 'userAccountMapping');
    process.env.USER_POOL_ID = 'test-user-pool-id';
    process.env.USER_ACCOUNT_MAPPING_TABLE_NAME = userAccountMappingTableName;

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
});
