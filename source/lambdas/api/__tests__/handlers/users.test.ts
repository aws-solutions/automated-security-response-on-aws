// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { DynamoDBDocumentClient, PutCommand, GetCommand } from '@aws-sdk/lib-dynamodb';
import { mockClient } from 'aws-sdk-client-mock';
import 'aws-sdk-client-mock-jest';
import {
  AdminAddUserToGroupCommand,
  AdminCreateUserCommand,
  AdminDeleteUserCommand,
  AdminGetUserCommand,
  CognitoIdentityProviderClient,
  ListUsersCommand,
  AdminListGroupsForUserCommand,
} from '@aws-sdk/client-cognito-identity-provider';
import { DynamoDBTestSetup } from '../../../common/__tests__/dynamodbSetup';
import { userAccountMappingTableName } from '../../../common/__tests__/envSetup';
import { UserAccountMapping } from '@asr/data-models';
import { ForbiddenError, NotFoundError, BadRequestError } from '../../../common/utils/httpErrors';
import { createMockEvent, createMockContext, TEST_REQUEST_CONTEXT } from '../utils';
import {
  setupMetricsMocks,
  cleanupMetricsMocks,
  createMetricsTestScope,
} from '../../../common/__tests__/metricsMockSetup';

import { getUsers, inviteUser, putUser, deleteUser } from '../../handlers/users';

const cognitoMock = mockClient(CognitoIdentityProviderClient);

describe('UsersHandler', () => {
  let dynamoDBDocumentClient: DynamoDBDocumentClient;

  beforeAll(async () => {
    await DynamoDBTestSetup.initialize();
    dynamoDBDocumentClient = DynamoDBTestSetup.getDocClient();

    // Create user account mapping table
    await DynamoDBTestSetup.createUserAccountMappingTable(userAccountMappingTableName);
  });

  afterAll(async () => {
    await DynamoDBTestSetup.deleteTable(userAccountMappingTableName);
    cleanupMetricsMocks();
  });

  beforeEach(async () => {
    cognitoMock.reset();
    setupMetricsMocks();
    await DynamoDBTestSetup.clearTable(userAccountMappingTableName, 'userAccountMapping');

    process.env.USER_ACCOUNT_MAPPING_TABLE_NAME = userAccountMappingTableName;

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
        groups = [{ GroupName: 'DelegatedAdminGroup' }];
      }

      return Promise.resolve({ Groups: groups });
    });
  });

  describe('getUsers', () => {
    it('should throw 403 when user lacks required groups', async () => {
      // ARRANGE
      const event = createMockEvent({
        headers: { authorization: 'Bearer valid-token' },
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

      // ACT & ASSERT
      await expect(getUsers(event, context)).rejects.toThrow(ForbiddenError);
    });

    it('should throw error when DelegatedAdmin tries to access without type parameter', async () => {
      // ARRANGE
      const event = createMockEvent({
        headers: { authorization: 'Bearer valid-token' },
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

      // ACT & ASSERT
      await expect(getUsers(event, context)).rejects.toThrow(
        'Only Admins can access GET /users without "type" query parameter',
      );
    });

    it('should throw ForbiddenError when cognito:groups is a string containing AdminGroup', async () => {
      // ARRANGE
      const event = createMockEvent({
        headers: { authorization: 'Bearer valid-token' },
        requestContext: {
          ...TEST_REQUEST_CONTEXT,
          authorizer: {
            claims: {
              'cognito:groups': 'FakeAdminGroup',
              username: 'testuser@example.com',
            },
          },
        },
      });
      const context = createMockContext();

      // ACT & ASSERT
      await expect(getUsers(event, context)).rejects.toThrow(new ForbiddenError());
    });

    it('should throw error when DelegatedAdmin tries to access non-accountOperators type', async () => {
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

      // ACT & ASSERT
      await expect(getUsers(event, context)).rejects.toThrow(
        'DelegatedAdminGroup can only fetch Account Operators. You must provide the "type" query parameter with value "accountOperators".',
      );
    });

    it('should throw error when cognito:groups is DelegatedAdminGroup (string) and tries to access non-accountOperators type', async () => {
      // ARRANGE
      const event = createMockEvent({
        headers: { authorization: 'Bearer valid-token' },
        queryStringParameters: { type: 'admins' },
        requestContext: {
          ...TEST_REQUEST_CONTEXT,
          authorizer: {
            claims: {
              'cognito:groups': 'DelegatedAdminGroup',
              username: 'testuser@example.com',
            },
          },
        },
      });
      const context = createMockContext();

      // ACT & ASSERT
      await expect(getUsers(event, context)).rejects.toThrow(
        'DelegatedAdminGroup can only fetch Account Operators. You must provide the "type" query parameter with value "accountOperators".',
      );
    });

    it('should return all users for Admin without type filter', async () => {
      // ARRANGE
      const event = createMockEvent({
        headers: { authorization: 'Bearer valid-token' },
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
        Users: [
          {
            Username: 'user1',
            Attributes: [
              { Name: 'email', Value: 'user1@example.com' },
              { Name: 'custom:invitedBy', Value: 'admin@example.com' },
            ],
            UserCreateDate: new Date('2023-01-01'),
            UserStatus: 'CONFIRMED',
          },
          {
            Username: 'user2',
            Attributes: [
              { Name: 'email', Value: 'user2@example.com' },
              { Name: 'custom:invitedBy', Value: 'admin@example.com' },
            ],
            UserCreateDate: new Date('2023-01-02'),
            UserStatus: 'FORCE_CHANGE_PASSWORD',
          },
        ],
      });

      cognitoMock.on(AdminListGroupsForUserCommand, { Username: 'user1' }).resolves({
        Groups: [{ GroupName: 'AdminGroup' }],
      });

      cognitoMock.on(AdminListGroupsForUserCommand, { Username: 'user2' }).resolves({
        Groups: [{ GroupName: 'DelegatedAdminGroup' }],
      });

      // ACT
      const result = await getUsers(event, context);

      // ASSERT
      expect(result.statusCode).toBe(200);
      const body = JSON.parse(result.body);
      expect(body).toHaveLength(2);
      expect(body[0].email).toBe('user1@example.com');
      expect(body[0].type).toBe('admin');
      expect(body[0].status).toBe('Confirmed');
      expect(body[1].email).toBe('user2@example.com');
      expect(body[1].type).toBe('delegated-admin');
      expect(body[1].status).toBe('Invited');
    });

    it('should filter users by type when type parameter is provided', async () => {
      // ARRANGE
      const event = createMockEvent({
        headers: { authorization: 'Bearer valid-token' },
        queryStringParameters: { type: 'accountOperators' },
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

      // Add user account mapping for account operator
      const userAccountMapping: UserAccountMapping = {
        userId: 'operator@example.com',
        accountIds: ['123456789012', '987654321098'],
        invitedBy: 'admin@example.com',
        invitationTimestamp: '2023-01-01T00:00:00Z',
      };

      await dynamoDBDocumentClient.send(
        new PutCommand({
          TableName: userAccountMappingTableName,
          Item: userAccountMapping,
        }),
      );

      cognitoMock.on(ListUsersCommand).resolves({
        Users: [
          {
            Username: 'admin-user',
            Attributes: [
              { Name: 'email', Value: 'admin@example.com' },
              { Name: 'custom:invitedBy', Value: 'superadmin@example.com' },
            ],
            UserCreateDate: new Date('2023-01-01'),
            UserStatus: 'CONFIRMED',
          },
          {
            Username: 'operator-user',
            Attributes: [
              { Name: 'email', Value: 'operator@example.com' },
              { Name: 'custom:invitedBy', Value: 'admin@example.com' },
            ],
            UserCreateDate: new Date('2023-01-02'),
            UserStatus: 'CONFIRMED',
          },
        ],
      });

      cognitoMock.on(AdminListGroupsForUserCommand, { Username: 'admin-user' }).resolves({
        Groups: [{ GroupName: 'AdminGroup' }],
      });

      cognitoMock.on(AdminListGroupsForUserCommand, { Username: 'operator-user' }).resolves({
        Groups: [{ GroupName: 'AccountOperatorGroup' }],
      });

      // ACT
      const result = await getUsers(event, context);

      // ASSERT
      expect(result.statusCode).toBe(200);
      const body = JSON.parse(result.body);
      expect(body).toHaveLength(1);
      expect(body[0].email).toBe('operator@example.com');
      expect(body[0].type).toBe('account-operator');
      expect(body[0].accountIds).toEqual(['123456789012', '987654321098']);
    });

    it('should skip users with missing required attributes', async () => {
      // ARRANGE
      const event = createMockEvent({
        headers: { authorization: 'Bearer valid-token' },
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
        Users: [
          {
            Username: 'incomplete-user',
            Attributes: [
              { Name: 'email', Value: 'incomplete@example.com' },
              // Missing custom:invitedBy
            ],
            UserCreateDate: new Date('2023-01-01'),
            UserStatus: 'CONFIRMED',
          },
        ],
      });

      // ACT
      const result = await getUsers(event, context);

      // ASSERT
      expect(result.statusCode).toBe(200);
      const body = JSON.parse(result.body);
      expect(body).toHaveLength(0);
    });

    it('should skip users with no recognized groups', async () => {
      // ARRANGE
      const event = createMockEvent({
        headers: { authorization: 'Bearer valid-token' },
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
        Users: [
          {
            Username: 'unrecognized-user',
            Attributes: [
              { Name: 'email', Value: 'unrecognized@example.com' },
              { Name: 'custom:invitedBy', Value: 'admin@example.com' },
            ],
            UserCreateDate: new Date('2023-01-01'),
            UserStatus: 'CONFIRMED',
          },
        ],
      });

      cognitoMock.on(AdminListGroupsForUserCommand, { Username: 'unrecognized-user' }).resolves({
        Groups: [{ GroupName: 'UnknownGroup' }],
      });

      // ACT
      const result = await getUsers(event, context);

      // ASSERT
      expect(result.statusCode).toBe(200);
      const body = JSON.parse(result.body);
      expect(body).toHaveLength(0);
    });

    it('should throw on Cognito service errors', async () => {
      // ARRANGE
      const event = createMockEvent({
        headers: { authorization: 'Bearer valid-token' },
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

      cognitoMock.on(ListUsersCommand).rejects(new Error('Cognito service error'));

      await expect(getUsers(event, context)).rejects.toThrow();
    });
  });

  describe('inviteUser', () => {
    it('should throw 403 when user lacks required groups', async () => {
      // ARRANGE
      const event = createMockEvent({
        headers: { authorization: 'Bearer valid-token', 'Content-Type': 'application/json' },
        body: JSON.stringify({
          email: 'newuser@example.com',
          role: 'DelegatedAdmin',
        }),
        requestContext: {
          ...TEST_REQUEST_CONTEXT,
          authorizer: {
            claims: {
              'cognito:groups': ['AccountOperatorGroup'],
              username: 'testuser@example.com',
            },
          },
        },
      });
      const context = createMockContext();

      // ACT & ASSERT
      await expect(inviteUser(event, context)).rejects.toThrow(ForbiddenError);
    });

    it('should throw BadRequestError for invalid email format', async () => {
      // ARRANGE
      const event = createMockEvent({
        headers: { authorization: 'Bearer valid-token', 'Content-Type': 'application/json' },
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

      // ACT & ASSERT
      await expect(inviteUser(event, context)).rejects.toThrow(BadRequestError);
    });

    it('should throw BadRequestError for invalid role', async () => {
      // ARRANGE
      const event = createMockEvent({
        headers: { authorization: 'Bearer valid-token', 'Content-Type': 'application/json' },
        body: JSON.stringify({
          email: 'newuser@example.com',
          role: 'InvalidRole',
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

      // ACT & ASSERT
      await expect(inviteUser(event, context)).rejects.toThrow(BadRequestError);
    });

    it('should throw BadRequestError when AccountOperator role lacks accountIds', async () => {
      // ARRANGE
      const event = createMockEvent({
        headers: { authorization: 'Bearer valid-token', 'Content-Type': 'application/json' },
        body: JSON.stringify({
          email: 'newuser@example.com',
          role: 'AccountOperator',
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

      // ACT & ASSERT
      await expect(inviteUser(event, context)).rejects.toThrow(
        new BadRequestError('accountIds is required for AccountOperator role'),
      );
    });

    it('should throw BadRequestError when AccountOperator role has empty accountIds', async () => {
      // ARRANGE
      const event = createMockEvent({
        headers: { authorization: 'Bearer valid-token', 'Content-Type': 'application/json' },
        body: JSON.stringify({
          email: 'newuser@example.com',
          role: 'AccountOperator',
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

      // ACT & ASSERT
      await expect(inviteUser(event, context)).rejects.toThrow(
        new BadRequestError('Invalid request: accountIds: Array must contain at least 1 element(s)'),
      );
    });

    it('should throw ForbiddenError when DelegatedAdmin tries to create DelegatedAdmin user', async () => {
      // ARRANGE
      const event = createMockEvent({
        headers: { authorization: 'Bearer valid-token', 'Content-Type': 'application/json' },
        body: JSON.stringify({
          email: 'newuser@example.com',
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

      // ACT & ASSERT
      await expect(inviteUser(event, context)).rejects.toThrow(
        new ForbiddenError('DelegatedAdminGroup can only create AccountOperator users'),
      );
    });

    it('should successfully create DelegatedAdmin user as Admin', async () => {
      // ARRANGE
      const event = createMockEvent({
        headers: { authorization: 'Bearer valid-token', 'Content-Type': 'application/json' },
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

      const metricsScope = createMetricsTestScope();

      cognitoMock.on(AdminCreateUserCommand).resolves({
        User: { Username: 'newdelegated@example.com' },
      });
      cognitoMock.on(AdminAddUserToGroupCommand).resolves({});

      // ACT
      const result = await inviteUser(event, context);

      // ASSERT
      expect(result.statusCode).toBe(201);
      const body = JSON.parse(result.body);
      expect(body.message).toBe('User invited successfully');
      expect(body.email).toBe('newdelegated@example.com');
      expect(cognitoMock).toHaveReceivedCommandWith(AdminCreateUserCommand, {
        UserPoolId: expect.any(String),
        Username: 'newdelegated@example.com',
        UserAttributes: [
          { Name: 'email', Value: 'newdelegated@example.com' },
          { Name: 'email_verified', Value: 'true' },
          { Name: 'custom:invitedBy', Value: 'admin@example.com' },
        ],
      });
      expect(cognitoMock).toHaveReceivedCommandWith(AdminAddUserToGroupCommand, {
        UserPoolId: expect.any(String),
        Username: 'newdelegated@example.com',
        GroupName: 'DelegatedAdminGroup',
      });

      // Wait for next event loop tick to allow async HTTP request to complete
      await new Promise((resolve) => setTimeout(resolve, 5));
      expect(metricsScope.isDone()).toBe(true);
    });

    it('should successfully create AccountOperator user as Admin with account mappings', async () => {
      // ARRANGE
      const event = createMockEvent({
        headers: { authorization: 'Bearer valid-token', 'Content-Type': 'application/json' },
        body: JSON.stringify({
          email: 'newoperator@example.com',
          role: 'AccountOperator',
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

      cognitoMock.on(AdminCreateUserCommand).resolves({
        User: { Username: 'newoperator@example.com' },
      });
      cognitoMock.on(AdminAddUserToGroupCommand).resolves({});

      // ACT
      const result = await inviteUser(event, context);

      // ASSERT
      expect(result.statusCode).toBe(201);
      const body = JSON.parse(result.body);
      expect(body.message).toBe('User invited successfully');
      expect(body.email).toBe('newoperator@example.com');
      expect(cognitoMock).toHaveReceivedCommandWith(AdminAddUserToGroupCommand, {
        UserPoolId: expect.any(String),
        Username: 'newoperator@example.com',
        GroupName: 'AccountOperatorGroup',
      });

      // Verify UserAccountMapping was created in DynamoDB
      const getResponse = await dynamoDBDocumentClient.send(
        new GetCommand({
          TableName: userAccountMappingTableName,
          Key: { userId: 'newoperator@example.com' },
        }),
      );
      expect(getResponse.Item).toBeDefined();
      expect(getResponse.Item?.userId).toBe('newoperator@example.com');
      expect(getResponse.Item?.accountIds).toEqual(['123456789012', '987654321098']);
      expect(getResponse.Item?.invitedBy).toBe('admin@example.com');
    });

    it('should successfully create AccountOperator user as DelegatedAdmin', async () => {
      // ARRANGE
      const event = createMockEvent({
        headers: { authorization: 'Bearer valid-token', 'Content-Type': 'application/json' },
        body: JSON.stringify({
          email: 'newoperator@example.com',
          role: 'AccountOperator',
          accountIds: ['123456789012'],
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

      cognitoMock.on(AdminCreateUserCommand).resolves({
        User: { Username: 'newoperator@example.com' },
      });
      cognitoMock.on(AdminAddUserToGroupCommand).resolves({});

      // ACT
      const result = await inviteUser(event, context);

      // ASSERT
      expect(result.statusCode).toBe(201);
      const body = JSON.parse(result.body);
      expect(body.message).toBe('User invited successfully');
      expect(body.email).toBe('newoperator@example.com');

      // Verify UserAccountMapping was created in DynamoDB
      const getResponse = await dynamoDBDocumentClient.send(
        new GetCommand({
          TableName: userAccountMappingTableName,
          Key: { userId: 'newoperator@example.com' },
        }),
      );
      expect(getResponse.Item).toBeDefined();
      expect(getResponse.Item?.userId).toBe('newoperator@example.com');
      expect(getResponse.Item?.accountIds).toEqual(['123456789012']);
      expect(getResponse.Item?.invitedBy).toBe('delegated@example.com');
    });

    it('should throw when Cognito service fails', async () => {
      // ARRANGE
      const event = createMockEvent({
        headers: { authorization: 'Bearer valid-token', 'Content-Type': 'application/json' },
        body: JSON.stringify({
          email: 'newuser@example.com',
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

      cognitoMock.on(AdminCreateUserCommand).rejects(new Error('Cognito service error'));

      // ACT & ASSERT
      await expect(inviteUser(event, context)).rejects.toThrow('Cognito service error');
    });

    it('should throw BadRequestError for invalid accountIds format', async () => {
      // ARRANGE
      const event = createMockEvent({
        headers: { authorization: 'Bearer valid-token', 'Content-Type': 'application/json' },
        body: JSON.stringify({
          email: 'newuser@example.com',
          role: 'AccountOperator',
          accountIds: ['invalid-account-id'],
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

      // ACT & ASSERT
      await expect(inviteUser(event, context)).rejects.toThrow(BadRequestError);
    });

    it('should handle string cognito:groups for DelegatedAdmin', async () => {
      // ARRANGE
      const event = createMockEvent({
        headers: { authorization: 'Bearer valid-token', 'Content-Type': 'application/json' },
        body: JSON.stringify({
          email: 'newoperator@example.com',
          role: 'AccountOperator',
          accountIds: ['123456789012'],
        }),
        requestContext: {
          ...TEST_REQUEST_CONTEXT,
          authorizer: {
            claims: {
              'cognito:groups': 'DelegatedAdminGroup',
              username: 'delegated@example.com',
            },
          },
        },
      });
      const context = createMockContext();

      cognitoMock.on(AdminCreateUserCommand).resolves({
        User: { Username: 'newoperator@example.com' },
      });
      cognitoMock.on(AdminAddUserToGroupCommand).resolves({});

      // ACT
      const result = await inviteUser(event, context);

      // ASSERT
      expect(result.statusCode).toBe(201);

      // Verify UserAccountMapping was created in DynamoDB
      const getResponse = await dynamoDBDocumentClient.send(
        new GetCommand({
          TableName: userAccountMappingTableName,
          Key: { userId: 'newoperator@example.com' },
        }),
      );
      expect(getResponse.Item).toBeDefined();
      expect(getResponse.Item?.userId).toBe('newoperator@example.com');
      expect(getResponse.Item?.accountIds).toEqual(['123456789012']);
      expect(getResponse.Item?.invitedBy).toBe('delegated@example.com');
    });
  });

  describe('putUser', () => {
    it('should throw BadRequestError when user ID is missing', async () => {
      // ARRANGE
      const event = createMockEvent({
        httpMethod: 'PUT',
        headers: { authorization: 'Bearer valid-token', 'Content-Type': 'application/json' },
        pathParameters: null,
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

      // ACT & ASSERT
      await expect(putUser(event, context)).rejects.toThrow(new BadRequestError('User ID is required'));
    });

    it('should throw BadRequestError when user type is not account-operator', async () => {
      // ARRANGE
      const event = createMockEvent({
        httpMethod: 'PUT',
        headers: { authorization: 'Bearer valid-token', 'Content-Type': 'application/json' },
        pathParameters: { id: 'user@example.com' },
        body: JSON.stringify({
          type: 'admin',
          email: 'myuser@example.com',
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

      // ACT & ASSERT
      await expect(putUser(event, context)).rejects.toThrow(
        new BadRequestError('Only account-operator users can be updated'),
      );
    });

    it('should throw BadRequestError for invalid account IDs format', async () => {
      // ARRANGE
      const event = createMockEvent({
        httpMethod: 'PUT',
        headers: { authorization: 'Bearer valid-token', 'Content-Type': 'application/json' },
        pathParameters: { id: 'user@example.com' },
        body: JSON.stringify({
          type: 'account-operator',
          accountIds: ['invalid-account-id'],
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

      // ACT & ASSERT
      await expect(putUser(event, context)).rejects.toThrow(BadRequestError);
    });

    it('should throw 403 when user lacks required groups', async () => {
      // ARRANGE
      const event = createMockEvent({
        httpMethod: 'PUT',
        headers: { authorization: 'Bearer valid-token', 'Content-Type': 'application/json' },
        pathParameters: { id: 'user@example.com' },
        body: JSON.stringify({
          type: 'account-operator',
          email: 'user@example.com',
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

      // ACT & ASSERT
      await expect(putUser(event, context)).rejects.toThrow(ForbiddenError);
    });

    it('should successfully update account operator user as Admin', async () => {
      // ARRANGE
      const userId = 'operator@example.com';
      const event = createMockEvent({
        httpMethod: 'PUT',
        headers: { authorization: 'Bearer valid-token', 'Content-Type': 'application/json' },
        pathParameters: { id: userId },
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
      const result = await putUser(event, context);

      // ASSERT
      expect(result.statusCode).toBe(200);
      const body = JSON.parse(result.body);
      expect(body.message).toBe('User updated successfully');

      // Verify DynamoDB was updated
      const getResponse = await dynamoDBDocumentClient.send(
        new GetCommand({
          TableName: userAccountMappingTableName,
          Key: { userId },
        }),
      );
      expect(getResponse.Item).toBeDefined();
      expect(getResponse.Item?.accountIds).toEqual(['123456789012', '987654321098']);
      expect(getResponse.Item?.lastModifiedBy).toBe('UsersAPI');
      expect(getResponse.Item?.lastModifiedTimestamp).toBeDefined();
    });

    it('should successfully update account operator user as DelegatedAdmin', async () => {
      // ARRANGE
      const userId = 'operator@example.com';
      const event = createMockEvent({
        httpMethod: 'PUT',
        headers: { authorization: 'Bearer valid-token', 'Content-Type': 'application/json' },
        pathParameters: { id: userId },
        body: JSON.stringify({
          type: 'account-operator',
          email: userId,
          status: 'Confirmed',
          accountIds: ['555555555555'],
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

      // Mock existing user in Cognito
      cognitoMock.on(AdminGetUserCommand).resolves({
        Username: userId,
        UserAttributes: [
          { Name: 'email', Value: userId },
          { Name: 'custom:invitedBy', Value: 'delegated@example.com' },
        ],
        UserCreateDate: new Date('2023-01-01'),
        UserStatus: 'CONFIRMED',
      });

      cognitoMock.on(AdminListGroupsForUserCommand).resolves({
        Groups: [{ GroupName: 'AccountOperatorGroup' }],
      });

      // ACT
      const result = await putUser(event, context);

      // ASSERT
      expect(result.statusCode).toBe(200);
      const body = JSON.parse(result.body);
      expect(body.message).toBe('User updated successfully');

      // Verify DynamoDB was updated
      const getResponse = await dynamoDBDocumentClient.send(
        new GetCommand({
          TableName: userAccountMappingTableName,
          Key: { userId },
        }),
      );
      expect(getResponse.Item).toBeDefined();
      expect(getResponse.Item?.accountIds).toEqual(['555555555555']);
      expect(getResponse.Item?.invitedBy).toBe('delegated@example.com');
    });

    it('should throw NotFoundError when user does not exist in Cognito', async () => {
      // ARRANGE
      const userId = 'nonexistent@example.com';
      const event = createMockEvent({
        httpMethod: 'PUT',
        headers: { authorization: 'Bearer valid-token', 'Content-Type': 'application/json' },
        pathParameters: { id: userId },
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
              'cognito:groups': ['AdminGroup'],
              username: 'admin@example.com',
            },
          },
        },
      });
      const context = createMockContext();

      cognitoMock.on(AdminGetUserCommand).rejects(new Error('User not found'));

      // ACT & ASSERT
      await expect(putUser(event, context)).rejects.toThrow(NotFoundError);
    });
  });

  describe('deleteUser', () => {
    it('should throw BadRequestError when user ID is missing', async () => {
      // ARRANGE
      const event = createMockEvent({
        httpMethod: 'DELETE',
        headers: { authorization: 'Bearer valid-token' },
        pathParameters: null,
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

      // ACT & ASSERT
      await expect(deleteUser(event, context)).rejects.toThrow(
        new BadRequestError('Valid email address is required for user ID'),
      );
    });

    it('should throw BadRequestError when user ID is not a valid email', async () => {
      // ARRANGE
      const event = createMockEvent({
        httpMethod: 'DELETE',
        headers: { authorization: 'Bearer valid-token' },
        pathParameters: { id: 'invalid-email' },
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

      // ACT & ASSERT
      await expect(deleteUser(event, context)).rejects.toThrow(
        new BadRequestError('Valid email address is required for user ID'),
      );
    });

    it('should throw NotFoundError when user does not exist', async () => {
      // ARRANGE
      const event = createMockEvent({
        httpMethod: 'DELETE',
        headers: { authorization: 'Bearer valid-token' },
        pathParameters: { id: encodeURIComponent('nonexistent@example.com') },
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

      cognitoMock.on(AdminGetUserCommand).rejects(new Error('User not found'));

      // ACT & ASSERT
      await expect(deleteUser(event, context)).rejects.toThrow(
        new NotFoundError('User nonexistent@example.com not found.'),
      );
    });

    it('should throw 403 when user lacks required groups', async () => {
      // ARRANGE
      const event = createMockEvent({
        httpMethod: 'DELETE',
        headers: { authorization: 'Bearer valid-token' },
        pathParameters: { id: encodeURIComponent('user@example.com') },
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
        UserAttributes: [
          { Name: 'email', Value: 'user@example.com' },
          { Name: 'custom:invitedBy', Value: 'admin@example.com' },
        ],
        UserCreateDate: new Date('2023-01-01'),
        UserStatus: 'CONFIRMED',
      });
      cognitoMock.on(AdminListGroupsForUserCommand).resolves({ Groups: [{ GroupName: 'AdminGroup' }] });

      // ACT & ASSERT
      await expect(deleteUser(event, context)).rejects.toThrow(ForbiddenError);
    });

    it('should throw ForbiddenError when DelegatedAdmin tries to delete non-AccountOperator user', async () => {
      // ARRANGE
      const event = createMockEvent({
        httpMethod: 'DELETE',
        headers: { authorization: 'Bearer valid-token' },
        pathParameters: { id: encodeURIComponent('admin@example.com') },
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
        UserAttributes: [
          { Name: 'email', Value: 'admin@example.com' },
          { Name: 'custom:invitedBy', Value: 'super@example.com' },
        ],
        UserCreateDate: new Date('2023-01-01'),
        UserStatus: 'CONFIRMED',
      });
      cognitoMock.on(AdminListGroupsForUserCommand).resolves({ Groups: [{ GroupName: 'AdminGroup' }] });

      // ACT & ASSERT
      await expect(deleteUser(event, context)).rejects.toThrow(
        new ForbiddenError('DelegatedAdminGroup can only delete AccountOperator users'),
      );
    });

    it('should successfully delete admin user as Admin', async () => {
      // ARRANGE
      const event = createMockEvent({
        httpMethod: 'DELETE',
        headers: { authorization: 'Bearer valid-token' },
        pathParameters: { id: encodeURIComponent('admin@example.com') },
        requestContext: {
          ...TEST_REQUEST_CONTEXT,
          authorizer: {
            claims: {
              'cognito:groups': ['AdminGroup'],
              username: 'super@example.com',
            },
          },
        },
      });
      const context = createMockContext();

      cognitoMock.on(AdminGetUserCommand).resolves({
        UserAttributes: [
          { Name: 'email', Value: 'admin@example.com' },
          { Name: 'custom:invitedBy', Value: 'super@example.com' },
        ],
        UserCreateDate: new Date('2023-01-01'),
        UserStatus: 'CONFIRMED',
      });
      cognitoMock.on(AdminListGroupsForUserCommand).resolves({ Groups: [{ GroupName: 'AdminGroup' }] });
      cognitoMock.on(AdminDeleteUserCommand).resolves({});

      // ACT
      const result = await deleteUser(event, context);

      // ASSERT
      expect(result.statusCode).toBe(200);
      const body = JSON.parse(result.body);
      expect(body.message).toBe('User deleted successfully');
      expect(cognitoMock).toHaveReceivedCommandWith(AdminDeleteUserCommand, {
        UserPoolId: expect.any(String),
        Username: 'admin@example.com',
      });
    });

    it('should successfully delete account-operator user and remove DynamoDB mapping as Admin', async () => {
      // ARRANGE
      const userId = 'operator@example.com';
      const event = createMockEvent({
        httpMethod: 'DELETE',
        headers: { authorization: 'Bearer valid-token' },
        pathParameters: { id: encodeURIComponent(userId) },
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

      // Create user account mapping in DynamoDB
      const userAccountMapping: UserAccountMapping = {
        userId,
        accountIds: ['123456789012', '987654321098'],
        invitedBy: 'admin@example.com',
        invitationTimestamp: '2023-01-01T00:00:00Z',
      };

      await dynamoDBDocumentClient.send(
        new PutCommand({
          TableName: userAccountMappingTableName,
          Item: userAccountMapping,
        }),
      );

      cognitoMock.on(AdminGetUserCommand).resolves({
        UserAttributes: [
          { Name: 'email', Value: userId },
          { Name: 'custom:invitedBy', Value: 'admin@example.com' },
        ],
        UserCreateDate: new Date('2023-01-01'),
        UserStatus: 'CONFIRMED',
      });
      cognitoMock.on(AdminListGroupsForUserCommand).resolves({ Groups: [{ GroupName: 'AccountOperatorGroup' }] });
      cognitoMock.on(AdminDeleteUserCommand).resolves({});

      // ACT
      const result = await deleteUser(event, context);

      // ASSERT
      expect(result.statusCode).toBe(200);
      const body = JSON.parse(result.body);
      expect(body.message).toBe('User deleted successfully');
      expect(cognitoMock).toHaveReceivedCommandWith(AdminDeleteUserCommand, {
        UserPoolId: expect.any(String),
        Username: userId,
      });

      // Verify DynamoDB mapping was deleted
      const getResponse = await dynamoDBDocumentClient.send(
        new GetCommand({
          TableName: userAccountMappingTableName,
          Key: { userId },
        }),
      );
      expect(getResponse.Item).toBeUndefined();
    });

    it('should successfully delete account-operator user as DelegatedAdmin', async () => {
      // ARRANGE
      const userId = 'operator@example.com';
      const event = createMockEvent({
        httpMethod: 'DELETE',
        headers: { authorization: 'Bearer valid-token' },
        pathParameters: { id: encodeURIComponent(userId) },
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

      // Create user account mapping in DynamoDB
      const userAccountMapping: UserAccountMapping = {
        userId,
        accountIds: ['123456789012'],
        invitedBy: 'delegated@example.com',
        invitationTimestamp: '2023-01-01T00:00:00Z',
      };

      await dynamoDBDocumentClient.send(
        new PutCommand({
          TableName: userAccountMappingTableName,
          Item: userAccountMapping,
        }),
      );

      cognitoMock.on(AdminGetUserCommand).resolves({
        UserAttributes: [
          { Name: 'email', Value: userId },
          { Name: 'custom:invitedBy', Value: 'delegated@example.com' },
        ],
        UserCreateDate: new Date('2023-01-01'),
        UserStatus: 'CONFIRMED',
      });
      cognitoMock.on(AdminListGroupsForUserCommand).resolves({ Groups: [{ GroupName: 'AccountOperatorGroup' }] });
      cognitoMock.on(AdminDeleteUserCommand).resolves({});

      // ACT
      const result = await deleteUser(event, context);

      // ASSERT
      expect(result.statusCode).toBe(200);
      const body = JSON.parse(result.body);
      expect(body.message).toBe('User deleted successfully');
      expect(cognitoMock).toHaveReceivedCommandWith(AdminDeleteUserCommand, {
        UserPoolId: expect.any(String),
        Username: userId,
      });

      // Verify DynamoDB mapping was deleted
      const getResponse = await dynamoDBDocumentClient.send(
        new GetCommand({
          TableName: userAccountMappingTableName,
          Key: { userId },
        }),
      );
      expect(getResponse.Item).toBeUndefined();
    });

    it('should handle URL encoded email addresses correctly', async () => {
      // ARRANGE
      const userId = 'user+test@example.com';
      const event = createMockEvent({
        httpMethod: 'DELETE',
        headers: { authorization: 'Bearer valid-token' },
        pathParameters: { id: encodeURIComponent(userId) },
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
        UserAttributes: [
          { Name: 'email', Value: userId },
          { Name: 'custom:invitedBy', Value: 'admin@example.com' },
        ],
        UserCreateDate: new Date('2023-01-01'),
        UserStatus: 'CONFIRMED',
      });
      cognitoMock.on(AdminListGroupsForUserCommand).resolves({ Groups: [{ GroupName: 'AdminGroup' }] });
      cognitoMock.on(AdminDeleteUserCommand).resolves({});

      // ACT
      const result = await deleteUser(event, context);

      // ASSERT
      expect(result.statusCode).toBe(200);
      expect(cognitoMock).toHaveReceivedCommandWith(AdminDeleteUserCommand, {
        UserPoolId: expect.any(String),
        Username: userId,
      });
    });

    it('should handle Cognito delete failure', async () => {
      // ARRANGE
      const event = createMockEvent({
        httpMethod: 'DELETE',
        headers: { authorization: 'Bearer valid-token' },
        pathParameters: { id: encodeURIComponent('user@example.com') },
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
        UserAttributes: [
          { Name: 'email', Value: 'user@example.com' },
          { Name: 'custom:invitedBy', Value: 'admin@example.com' },
        ],
        UserCreateDate: new Date('2023-01-01'),
        UserStatus: 'CONFIRMED',
      });
      cognitoMock.on(AdminListGroupsForUserCommand).resolves({ Groups: [{ GroupName: 'AdminGroup' }] });
      cognitoMock.on(AdminDeleteUserCommand).rejects(new Error('Cognito delete failed'));

      // ACT & ASSERT
      await expect(deleteUser(event, context)).rejects.toThrow('Cognito delete failed');
    });

    it('should handle string cognito:groups for DelegatedAdmin', async () => {
      // ARRANGE
      const userId = 'operator@example.com';
      const event = createMockEvent({
        httpMethod: 'DELETE',
        headers: { authorization: 'Bearer valid-token' },
        pathParameters: { id: encodeURIComponent(userId) },
        requestContext: {
          ...TEST_REQUEST_CONTEXT,
          authorizer: {
            claims: {
              'cognito:groups': 'DelegatedAdminGroup',
              username: 'delegated@example.com',
            },
          },
        },
      });
      const context = createMockContext();

      cognitoMock.on(AdminGetUserCommand).resolves({
        UserAttributes: [
          { Name: 'email', Value: userId },
          { Name: 'custom:invitedBy', Value: 'delegated@example.com' },
        ],
        UserCreateDate: new Date('2023-01-01'),
        UserStatus: 'CONFIRMED',
      });
      cognitoMock.on(AdminListGroupsForUserCommand).resolves({ Groups: [{ GroupName: 'AccountOperatorGroup' }] });
      cognitoMock.on(AdminDeleteUserCommand).resolves({});

      // ACT
      const result = await deleteUser(event, context);

      // ASSERT
      expect(result.statusCode).toBe(200);
      const body = JSON.parse(result.body);
      expect(body.message).toBe('User deleted successfully');
    });
  });
});
