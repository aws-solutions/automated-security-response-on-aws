// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { Logger } from '@aws-lambda-powertools/logger';
import { CognitoService } from '../../services/cognito';
import 'aws-sdk-client-mock-jest';
import {
  AdminAddUserToGroupCommand,
  AdminCreateUserCommand,
  AdminDeleteUserCommand,
  CognitoIdentityProviderClient,
  ListUsersCommand,
  AdminGetUserCommand,
  AdminListGroupsForUserCommand,
  DescribeIdentityProviderCommand,
  AdminLinkProviderForUserCommand,
  UsernameExistsException,
} from '@aws-sdk/client-cognito-identity-provider';
import { UserAccountMappingRepository } from '../../../common/repositories/userAccountMappingRepository';
import { DynamoDBTestSetup } from '../../../common/__tests__/dynamodbSetup';
import { userAccountMappingTableName } from '../../../common/__tests__/envSetup';
import { DynamoDBDocumentClient, PutCommand, GetCommand } from '@aws-sdk/lib-dynamodb';
import { UserAccountMapping } from '@asr/data-models';
import { mockClient } from 'aws-sdk-client-mock';
import { createMockUserAccountMapping } from '../../../common/__tests__/userAccountMappingRepository.test';
import { BadRequestError, NotFoundError } from '../../../common/utils/httpErrors';

const mockCognitoClient = mockClient(CognitoIdentityProviderClient);

describe('CognitoService', () => {
  let service: CognitoService;
  let mockLogger: Logger;
  let dynamoDBDocumentClient: DynamoDBDocumentClient;
  let userAccountMappingRepository: UserAccountMappingRepository;

  beforeAll(async () => {
    await DynamoDBTestSetup.initialize();
    dynamoDBDocumentClient = DynamoDBTestSetup.getDocClient();
    await DynamoDBTestSetup.createUserAccountMappingTable(userAccountMappingTableName);
  });

  afterAll(async () => {
    await DynamoDBTestSetup.deleteTable(userAccountMappingTableName);
  });

  beforeEach(async () => {
    mockCognitoClient.reset();
    await DynamoDBTestSetup.clearTable(userAccountMappingTableName, 'userAccountMapping');

    process.env.USER_POOL_ID = 'us-east-1_testpool';
    process.env.USER_ACCOUNT_MAPPING_TABLE_NAME = userAccountMappingTableName;

    mockLogger = new Logger({ serviceName: 'test' });
    userAccountMappingRepository = new UserAccountMappingRepository(
      'UsersAPI',
      userAccountMappingTableName,
      dynamoDBDocumentClient,
    );

    service = new CognitoService(mockLogger);
    (service as any).userAccountMappingRepository = userAccountMappingRepository;
    // Clear cache to ensure clean state between tests
    (service as any).userCache.clear();
  });

  const createUserAccountMapping = (userId: string, accountIds: string[]): UserAccountMapping =>
    createMockUserAccountMapping({ userId, accountIds });

  describe('getAllUsers', () => {
    it('should return all users with complete data', async () => {
      // ARRANGE
      mockCognitoClient.on(ListUsersCommand).resolves({
        Users: [
          {
            Username: 'user1',
            Attributes: [
              { Name: 'email', Value: 'admin@example.com' },
              { Name: 'custom:invitedBy', Value: 'super@example.com' },
            ],
            UserCreateDate: new Date('2023-01-01'),
            UserStatus: 'CONFIRMED',
          },
          {
            Username: 'user2',
            Attributes: [
              { Name: 'email', Value: 'operator@example.com' },
              { Name: 'custom:invitedBy', Value: 'admin@example.com' },
            ],
            UserCreateDate: new Date('2023-01-02'),
            UserStatus: 'FORCE_CHANGE_PASSWORD',
          },
        ],
      });

      mockCognitoClient
        .on(AdminListGroupsForUserCommand, { Username: 'user1' })
        .resolves({ Groups: [{ GroupName: 'AdminGroup' }] });
      mockCognitoClient
        .on(AdminListGroupsForUserCommand, { Username: 'user2' })
        .resolves({ Groups: [{ GroupName: 'AccountOperatorGroup' }] });

      await dynamoDBDocumentClient.send(
        new PutCommand({
          TableName: userAccountMappingTableName,
          Item: createUserAccountMapping('operator@example.com', ['123456789012']),
        }),
      );

      // ACT
      const result = await service.getAllUsers();

      // ASSERT
      expect(result).toHaveLength(2);
      expect(result[0]).toEqual({
        email: 'admin@example.com',
        invitedBy: 'super@example.com',
        invitationTimestamp: '2023-01-01T00:00:00.000Z',
        status: 'Confirmed',
        type: 'admin',
      });
      expect(result[1]).toEqual({
        email: 'operator@example.com',
        invitedBy: 'admin@example.com',
        invitationTimestamp: '2023-01-02T00:00:00.000Z',
        status: 'Invited',
        type: 'account-operator',
        accountIds: ['123456789012'],
      });
    });

    it('should skip users with missing email', async () => {
      // ARRANGE
      mockCognitoClient.on(ListUsersCommand).resolves({
        Users: [
          {
            Username: 'user1',
            Attributes: [{ Name: 'custom:invitedBy', Value: 'admin@example.com' }],
          },
        ],
      });

      // ACT
      const result = await service.getAllUsers();

      // ASSERT
      expect(result).toHaveLength(0);
    });

    it('should skip users with missing invitedBy', async () => {
      // ARRANGE
      mockCognitoClient.on(ListUsersCommand).resolves({
        Users: [
          {
            Username: 'user1',
            Attributes: [{ Name: 'email', Value: 'test@example.com' }],
          },
        ],
      });

      // ACT
      const result = await service.getAllUsers();

      // ASSERT
      expect(result).toHaveLength(0);
    });

    it('should skip users with no recognized groups', async () => {
      // ARRANGE
      mockCognitoClient.on(ListUsersCommand).resolves({
        Users: [
          {
            Username: 'user1',
            Attributes: [
              { Name: 'email', Value: 'test@example.com' },
              { Name: 'custom:invitedBy', Value: 'admin@example.com' },
            ],
          },
        ],
      });
      mockCognitoClient.on(AdminListGroupsForUserCommand).resolves({ Groups: [{ GroupName: 'UnknownGroup' }] });

      // ACT
      const result = await service.getAllUsers();

      // ASSERT
      expect(result).toHaveLength(0);
    });

    it('should handle empty users response', async () => {
      // ARRANGE
      mockCognitoClient.on(ListUsersCommand).resolves({ Users: [] });

      // ACT
      const result = await service.getAllUsers();

      // ASSERT
      expect(result).toHaveLength(0);
    });

    it('should handle undefined users response', async () => {
      // ARRANGE
      mockCognitoClient.on(ListUsersCommand).resolves({});

      // ACT
      const result = await service.getAllUsers();

      // ASSERT
      expect(result).toHaveLength(0);
    });

    it('should handle delegated admin user type', async () => {
      // ARRANGE
      mockCognitoClient.on(ListUsersCommand).resolves({
        Users: [
          {
            Username: 'user1',
            Attributes: [
              { Name: 'email', Value: 'delegated@example.com' },
              { Name: 'custom:invitedBy', Value: 'admin@example.com' },
            ],
            UserCreateDate: new Date('2023-01-01'),
            UserStatus: 'CONFIRMED',
          },
        ],
      });
      mockCognitoClient.on(AdminListGroupsForUserCommand).resolves({ Groups: [{ GroupName: 'DelegatedAdminGroup' }] });

      // ACT
      const result = await service.getAllUsers();

      // ASSERT
      expect(result).toHaveLength(1);
      expect(result[0].type).toBe('delegated-admin');
    });

    it('should handle empty groups response', async () => {
      // ARRANGE
      mockCognitoClient.on(ListUsersCommand).resolves({
        Users: [
          {
            Username: 'user1',
            Attributes: [
              { Name: 'email', Value: 'test@example.com' },
              { Name: 'custom:invitedBy', Value: 'admin@example.com' },
            ],
          },
        ],
      });
      mockCognitoClient.on(AdminListGroupsForUserCommand).resolves({ Groups: [] });

      // ACT
      const result = await service.getAllUsers();

      // ASSERT
      expect(result).toHaveLength(0);
    });

    it('should throw error when Cognito fails', async () => {
      // ARRANGE
      const error = new Error('Cognito error');
      mockCognitoClient.on(ListUsersCommand).rejects(error);

      // ACT & ASSERT
      await expect(service.getAllUsers()).rejects.toThrow('Cognito error');
    });
  });

  describe('getUserById', () => {
    it('should return user when found with complete data', async () => {
      // ARRANGE
      mockCognitoClient.on(AdminGetUserCommand).resolves({
        UserAttributes: [
          { Name: 'email', Value: 'test@example.com' },
          { Name: 'custom:invitedBy', Value: 'admin@example.com' },
        ],
        UserCreateDate: new Date('2023-01-01'),
        UserStatus: 'CONFIRMED',
      });
      mockCognitoClient.on(AdminListGroupsForUserCommand).resolves({ Groups: [{ GroupName: 'AdminGroup' }] });

      // ACT
      const result = await service.getUserById('user1');

      // ASSERT
      expect(result).toEqual({
        email: 'test@example.com',
        invitedBy: 'admin@example.com',
        invitationTimestamp: '2023-01-01T00:00:00.000Z',
        status: 'Confirmed',
        type: 'admin',
      });
    });

    it('should return null when user not found', async () => {
      // ARRANGE
      const error = new Error('User not found');
      mockCognitoClient.on(AdminGetUserCommand).rejects(error);

      // ACT
      const result = await service.getUserById('nonexistent');

      // ASSERT
      expect(result).toBeNull();
    });

    it('should return null when email missing', async () => {
      // ARRANGE
      mockCognitoClient.on(AdminGetUserCommand).resolves({
        UserAttributes: [{ Name: 'custom:invitedBy', Value: 'admin@example.com' }],
      });

      // ACT
      const result = await service.getUserById('user1');

      // ASSERT
      expect(result).toBeNull();
    });

    it('should return null when invitedBy missing', async () => {
      // ARRANGE
      mockCognitoClient.on(AdminGetUserCommand).resolves({
        UserAttributes: [{ Name: 'email', Value: 'test@example.com' }],
      });

      // ACT
      const result = await service.getUserById('user1');

      // ASSERT
      expect(result).toBeNull();
    });

    it('should return null when no recognized groups', async () => {
      // ARRANGE
      mockCognitoClient.on(AdminGetUserCommand).resolves({
        UserAttributes: [
          { Name: 'email', Value: 'test@example.com' },
          { Name: 'custom:invitedBy', Value: 'admin@example.com' },
        ],
      });
      mockCognitoClient.on(AdminListGroupsForUserCommand).resolves({ Groups: [{ GroupName: 'UnknownGroup' }] });

      // ACT
      const result = await service.getUserById('user1');

      // ASSERT
      expect(result).toBeNull();
    });

    it('should handle account operator user type', async () => {
      // ARRANGE
      mockCognitoClient.on(AdminGetUserCommand).resolves({
        UserAttributes: [
          { Name: 'email', Value: 'operator@example.com' },
          { Name: 'custom:invitedBy', Value: 'admin@example.com' },
        ],
        UserCreateDate: new Date('2023-01-01'),
        UserStatus: 'FORCE_CHANGE_PASSWORD',
      });
      mockCognitoClient.on(AdminListGroupsForUserCommand).resolves({ Groups: [{ GroupName: 'AccountOperatorGroup' }] });

      await dynamoDBDocumentClient.send(
        new PutCommand({
          TableName: userAccountMappingTableName,
          Item: createUserAccountMapping('operator@example.com', ['123456789012', '987654321098']),
        }),
      );

      // ACT
      const result = await service.getUserById('user1');

      // ASSERT
      expect(result).toEqual({
        email: 'operator@example.com',
        invitedBy: 'admin@example.com',
        invitationTimestamp: '2023-01-01T00:00:00.000Z',
        status: 'Invited',
        type: 'account-operator',
        accountIds: ['123456789012', '987654321098'],
      });
    });
  });

  describe('createUser', () => {
    it('should successfully create DelegatedAdmin user', async () => {
      // ARRANGE
      mockCognitoClient.on(AdminCreateUserCommand).resolves({
        User: { Username: 'delegated@example.com' },
      });
      mockCognitoClient.on(AdminAddUserToGroupCommand).resolves({});

      // ACT
      await service.createUser('delegated@example.com', 'DelegatedAdmin', 'admin@example.com');

      // ASSERT
      expect(mockCognitoClient).toHaveReceivedCommandWith(AdminCreateUserCommand, {
        UserPoolId: 'us-east-1_testpool',
        Username: 'delegated@example.com',
        UserAttributes: [
          { Name: 'email', Value: 'delegated@example.com' },
          { Name: 'email_verified', Value: 'true' },
          { Name: 'custom:invitedBy', Value: 'admin@example.com' },
        ],
      });
      expect(mockCognitoClient).toHaveReceivedCommandWith(AdminAddUserToGroupCommand, {
        UserPoolId: 'us-east-1_testpool',
        Username: 'delegated@example.com',
        GroupName: 'DelegatedAdminGroup',
      });
    });

    it('should successfully create AccountOperator user with account mappings', async () => {
      // ARRANGE
      mockCognitoClient.on(AdminCreateUserCommand).resolves({
        User: { Username: 'operator@example.com' },
      });
      mockCognitoClient.on(AdminAddUserToGroupCommand).resolves({});

      // ACT
      await service.createUser('operator@example.com', 'AccountOperator', 'admin@example.com', [
        '123456789012',
        '987654321098',
      ]);

      // ASSERT
      expect(mockCognitoClient).toHaveReceivedCommandWith(AdminCreateUserCommand, {
        UserPoolId: 'us-east-1_testpool',
        Username: 'operator@example.com',
        UserAttributes: [
          { Name: 'email', Value: 'operator@example.com' },
          { Name: 'email_verified', Value: 'true' },
          { Name: 'custom:invitedBy', Value: 'admin@example.com' },
        ],
      });
      expect(mockCognitoClient).toHaveReceivedCommandWith(AdminAddUserToGroupCommand, {
        UserPoolId: 'us-east-1_testpool',
        Username: 'operator@example.com',
        GroupName: 'AccountOperatorGroup',
      });

      // Verify UserAccountMapping was created in DynamoDB
      const getResponse = await dynamoDBDocumentClient.send(
        new GetCommand({
          TableName: userAccountMappingTableName,
          Key: { userId: 'operator@example.com' },
        }),
      );
      expect(getResponse.Item).toBeDefined();
      expect(getResponse.Item?.userId).toBe('operator@example.com');
      expect(getResponse.Item?.accountIds).toEqual(['123456789012', '987654321098']);
      expect(getResponse.Item?.invitedBy).toBe('admin@example.com');
      expect(getResponse.Item?.invitationTimestamp).toBeDefined();
    });

    it('should successfully create AccountOperator user without account mappings when accountIds not provided', async () => {
      // ARRANGE
      mockCognitoClient.on(AdminCreateUserCommand).resolves({
        User: { Username: 'operator@example.com' },
      });
      mockCognitoClient.on(AdminAddUserToGroupCommand).resolves({});

      // ACT
      await service.createUser('operator@example.com', 'AccountOperator', 'admin@example.com');

      // ASSERT
      expect(mockCognitoClient).toHaveReceivedCommandWith(AdminAddUserToGroupCommand, {
        UserPoolId: 'us-east-1_testpool',
        Username: 'operator@example.com',
        GroupName: 'AccountOperatorGroup',
      });

      // Verify no UserAccountMapping was created in DynamoDB
      const getResponse = await dynamoDBDocumentClient.send(
        new GetCommand({
          TableName: userAccountMappingTableName,
          Key: { userId: 'operator@example.com' },
        }),
      );
      expect(getResponse.Item).toBeUndefined();
    });

    it('should throw error when AdminCreateUserCommand fails', async () => {
      // ARRANGE
      const error = new Error('Cognito create user failed');
      mockCognitoClient.on(AdminCreateUserCommand).rejects(error);

      // ACT & ASSERT
      await expect(service.createUser('test@example.com', 'DelegatedAdmin', 'admin@example.com')).rejects.toThrow(
        'Cognito create user failed',
      );
    });

    it('should throw error when AdminAddUserToGroupCommand fails', async () => {
      // ARRANGE
      mockCognitoClient.on(AdminCreateUserCommand).resolves({
        User: { Username: 'test@example.com' },
      });
      const error = new Error('Cognito add to group failed');
      mockCognitoClient.on(AdminAddUserToGroupCommand).rejects(error);

      // ACT & ASSERT
      await expect(service.createUser('test@example.com', 'DelegatedAdmin', 'admin@example.com')).rejects.toThrow(
        'Cognito add to group failed',
      );
    });

    it('should throw error when DynamoDB create fails for AccountOperator', async () => {
      // ARRANGE
      mockCognitoClient.on(AdminCreateUserCommand).resolves({
        User: { Username: 'operator@example.com' },
      });
      mockCognitoClient.on(AdminAddUserToGroupCommand).resolves({});

      // Mock DynamoDB failure by overriding the repository method
      const originalCreate = userAccountMappingRepository.create;
      userAccountMappingRepository.create = jest.fn().mockRejectedValue(new Error('DynamoDB error'));

      // ACT & ASSERT
      await expect(
        service.createUser('operator@example.com', 'AccountOperator', 'admin@example.com', ['123456789012']),
      ).rejects.toThrow('DynamoDB error');

      // Restore original method
      userAccountMappingRepository.create = originalCreate;
    });

    it('should handle empty accountIds array for AccountOperator', async () => {
      // ARRANGE
      mockCognitoClient.on(AdminCreateUserCommand).resolves({
        User: { Username: 'operator@example.com' },
      });
      mockCognitoClient.on(AdminAddUserToGroupCommand).resolves({});

      // ACT
      await service.createUser('operator@example.com', 'AccountOperator', 'admin@example.com', []);

      // ASSERT

      // Verify UserAccountMapping was created with empty accountIds
      const getResponse = await dynamoDBDocumentClient.send(
        new GetCommand({
          TableName: userAccountMappingTableName,
          Key: { userId: 'operator@example.com' },
        }),
      );
      expect(getResponse.Item).toBeDefined();
      expect(getResponse.Item?.accountIds).toEqual([]);
    });

    it('should handle case when AdminCreateUserCommand returns no Username', async () => {
      // ARRANGE
      mockCognitoClient.on(AdminCreateUserCommand).resolves({
        User: {},
      });
      mockCognitoClient.on(AdminAddUserToGroupCommand).resolves({});

      // ACT
      await service.createUser('test@example.com', 'DelegatedAdmin', 'admin@example.com');

      // ASSERT
      expect(mockCognitoClient).toHaveReceivedCommandWith(AdminAddUserToGroupCommand, {
        UserPoolId: 'us-east-1_testpool',
        Username: 'test@example.com',
        GroupName: 'DelegatedAdminGroup',
      });
    });

    it('should handle case when AdminCreateUserCommand returns no User', async () => {
      // ARRANGE
      mockCognitoClient.on(AdminCreateUserCommand).resolves({});
      mockCognitoClient.on(AdminAddUserToGroupCommand).resolves({});

      // ACT
      await service.createUser('test@example.com', 'DelegatedAdmin', 'admin@example.com');

      // ASSERT
      expect(mockCognitoClient).toHaveReceivedCommandWith(AdminCreateUserCommand, {
        UserPoolId: 'us-east-1_testpool',
        Username: 'test@example.com',
        UserAttributes: [
          { Name: 'email', Value: 'test@example.com' },
          { Name: 'email_verified', Value: 'true' },
          { Name: 'custom:invitedBy', Value: 'admin@example.com' },
        ],
      });
    });

    it('should create correct group mapping for DelegatedAdmin role', async () => {
      // ARRANGE
      mockCognitoClient.on(AdminCreateUserCommand).resolves({
        User: { Username: 'delegated@example.com' },
      });
      mockCognitoClient.on(AdminAddUserToGroupCommand).resolves({});

      // ACT
      await service.createUser('delegated@example.com', 'DelegatedAdmin', 'admin@example.com');

      // ASSERT
      expect(mockCognitoClient).toHaveReceivedCommandWith(AdminAddUserToGroupCommand, {
        UserPoolId: 'us-east-1_testpool',
        Username: 'delegated@example.com',
        GroupName: 'DelegatedAdminGroup',
      });
    });

    it('should create correct group mapping for AccountOperator role', async () => {
      // ARRANGE
      mockCognitoClient.on(AdminCreateUserCommand).resolves({
        User: { Username: 'operator@example.com' },
      });
      mockCognitoClient.on(AdminAddUserToGroupCommand).resolves({});

      // ACT
      await service.createUser('operator@example.com', 'AccountOperator', 'admin@example.com');

      // ASSERT
      expect(mockCognitoClient).toHaveReceivedCommandWith(AdminAddUserToGroupCommand, {
        UserPoolId: 'us-east-1_testpool',
        Username: 'operator@example.com',
        GroupName: 'AccountOperatorGroup',
      });
    });
  });

  describe('updateAccountOperatorUser', () => {
    it('should throw NotFoundError when user does not exist', async () => {
      // ARRANGE
      mockCognitoClient.on(AdminGetUserCommand).rejects(new Error('User not found'));

      // ACT & ASSERT
      await expect(
        service.updateAccountOperatorUser('nonexistent@example.com', {
          type: 'account-operator',
          accountIds: ['123456789012'],
        }),
      ).rejects.toThrow('not found');
    });

    it('should update account-operator user with new account IDs when mapping exists', async () => {
      // ARRANGE
      mockCognitoClient.on(AdminGetUserCommand).resolves({
        UserAttributes: [
          { Name: 'email', Value: 'operator@example.com' },
          { Name: 'custom:invitedBy', Value: 'admin@example.com' },
        ],
        UserCreateDate: new Date('2023-01-01'),
        UserStatus: 'CONFIRMED',
      });
      mockCognitoClient.on(AdminListGroupsForUserCommand).resolves({ Groups: [{ GroupName: 'AccountOperatorGroup' }] });

      // Create existing mapping
      await dynamoDBDocumentClient.send(
        new PutCommand({
          TableName: userAccountMappingTableName,
          Item: createMockUserAccountMapping({
            userId: 'operator@example.com',
            accountIds: ['123456789012'],
          }),
        }),
      );

      // ACT
      await service.updateAccountOperatorUser('operator@example.com', {
        type: 'account-operator',
        accountIds: ['111111111111', '222222222222'],
      });

      // ASSERT
      const result = await dynamoDBDocumentClient.send(
        new GetCommand({
          TableName: userAccountMappingTableName,
          Key: { userId: 'operator@example.com' },
        }),
      );
      expect(result.Item?.accountIds).toEqual(['111111111111', '222222222222']);
      expect(result.Item?.lastModifiedBy).toBe('UsersAPI');
      expect(result.Item?.lastModifiedTimestamp).toBeDefined();
    });

    it('should create new mapping when updating account-operator user without existing mapping', async () => {
      // ARRANGE
      mockCognitoClient.on(AdminGetUserCommand).resolves({
        UserAttributes: [
          { Name: 'email', Value: 'newoperator@example.com' },
          { Name: 'custom:invitedBy', Value: 'admin@example.com' },
        ],
        UserCreateDate: new Date('2023-01-01'),
        UserStatus: 'CONFIRMED',
      });
      mockCognitoClient.on(AdminListGroupsForUserCommand).resolves({ Groups: [{ GroupName: 'AccountOperatorGroup' }] });

      // ACT
      await service.updateAccountOperatorUser('newoperator@example.com', {
        type: 'account-operator',
        accountIds: ['333333333333'],
      });

      // ASSERT
      const result = await dynamoDBDocumentClient.send(
        new GetCommand({
          TableName: userAccountMappingTableName,
          Key: { userId: 'newoperator@example.com' },
        }),
      );
      expect(result.Item?.userId).toBe('newoperator@example.com');
      expect(result.Item?.accountIds).toEqual(['333333333333']);
      expect(result.Item?.invitedBy).toBe('admin@example.com');
    });

    it('should create mapping with empty array when account-operator user data has no accountIds', async () => {
      // ARRANGE
      mockCognitoClient.on(AdminGetUserCommand).resolves({
        UserAttributes: [
          { Name: 'email', Value: 'operator@example.com' },
          { Name: 'custom:invitedBy', Value: 'admin@example.com' },
        ],
        UserCreateDate: new Date('2023-01-01'),
        UserStatus: 'CONFIRMED',
      });
      mockCognitoClient.on(AdminListGroupsForUserCommand).resolves({ Groups: [{ GroupName: 'AccountOperatorGroup' }] });

      // ACT
      await service.updateAccountOperatorUser('operator@example.com', { type: 'account-operator' });

      // ASSERT
      const result = await dynamoDBDocumentClient.send(
        new GetCommand({
          TableName: userAccountMappingTableName,
          Key: { userId: 'operator@example.com' },
        }),
      );
      expect(result.Item?.accountIds).toEqual([]);
      expect(result.Item?.invitedBy).toBe('admin@example.com');
    });
    it('should handle undefined accountIds by setting empty array', async () => {
      // ARRANGE
      mockCognitoClient.on(AdminGetUserCommand).resolves({
        UserAttributes: [
          { Name: 'email', Value: 'operator@example.com' },
          { Name: 'custom:invitedBy', Value: 'admin@example.com' },
        ],
        UserCreateDate: new Date('2023-01-01'),
        UserStatus: 'CONFIRMED',
      });
      mockCognitoClient.on(AdminListGroupsForUserCommand).resolves({ Groups: [{ GroupName: 'AccountOperatorGroup' }] });

      // ACT
      await service.updateAccountOperatorUser('operator@example.com', {});

      // ASSERT
      const result = await dynamoDBDocumentClient.send(
        new GetCommand({
          TableName: userAccountMappingTableName,
          Key: { userId: 'operator@example.com' },
        }),
      );
      expect(result.Item?.accountIds).toEqual([]);
      expect(result.Item?.invitedBy).toBe('admin@example.com');
    });

    it('should throw BadRequestError when trying to change user type', async () => {
      // ARRANGE
      mockCognitoClient.on(AdminGetUserCommand).resolves({
        UserAttributes: [
          { Name: 'email', Value: 'operator@example.com' },
          { Name: 'custom:invitedBy', Value: 'admin@example.com' },
        ],
        UserCreateDate: new Date('2023-01-01'),
        UserStatus: 'CONFIRMED',
      });
      mockCognitoClient.on(AdminListGroupsForUserCommand).resolves({ Groups: [{ GroupName: 'AccountOperatorGroup' }] });

      // ACT & ASSERT
      await expect(
        service.updateAccountOperatorUser('operator@example.com', {
          // @ts-expect-error - testing
          type: 'admin',
          accountIds: ['123456789012'],
        }),
      ).rejects.toThrow(
        new BadRequestError(
          'Requested user type does not match current type for the user. Modifying the user type is not currently supported.',
        ),
      );
    });

    it('should throw BadRequestError when trying to change user status', async () => {
      // ARRANGE
      mockCognitoClient.on(AdminGetUserCommand).resolves({
        UserAttributes: [
          { Name: 'email', Value: 'operator@example.com' },
          { Name: 'custom:invitedBy', Value: 'admin@example.com' },
        ],
        UserCreateDate: new Date('2023-01-01'),
        UserStatus: 'CONFIRMED',
      });
      mockCognitoClient.on(AdminListGroupsForUserCommand).resolves({ Groups: [{ GroupName: 'AccountOperatorGroup' }] });

      // ACT & ASSERT
      await expect(
        service.updateAccountOperatorUser('operator@example.com', {
          status: 'Invited',
          accountIds: ['123456789012'],
        }),
      ).rejects.toThrow(
        new BadRequestError(
          'Requested user status does not match current status for the user. Modifying the user status is not currently supported.',
        ),
      );
    });
  });

  describe('deleteUser', () => {
    it('should delete existing admin user successfully', async () => {
      // ARRANGE
      mockCognitoClient.on(AdminGetUserCommand).resolves({
        UserAttributes: [
          { Name: 'email', Value: 'admin@example.com' },
          { Name: 'custom:invitedBy', Value: 'super@example.com' },
        ],
        UserCreateDate: new Date('2023-01-01'),
        UserStatus: 'CONFIRMED',
      });
      mockCognitoClient.on(AdminListGroupsForUserCommand).resolves({ Groups: [{ GroupName: 'AdminGroup' }] });
      mockCognitoClient.on(AdminDeleteUserCommand).resolves({});

      // ACT
      await service.deleteUser('admin@example.com');

      // ASSERT
      expect(mockCognitoClient).toHaveReceivedCommandWith(AdminDeleteUserCommand, {
        UserPoolId: 'us-east-1_testpool',
        Username: 'admin@example.com',
      });
    });

    it('should delete account-operator user and remove DynamoDB mapping', async () => {
      // ARRANGE
      mockCognitoClient.on(AdminGetUserCommand).resolves({
        UserAttributes: [
          { Name: 'email', Value: 'operator@example.com' },
          { Name: 'custom:invitedBy', Value: 'admin@example.com' },
        ],
        UserCreateDate: new Date('2023-01-01'),
        UserStatus: 'CONFIRMED',
      });
      mockCognitoClient.on(AdminListGroupsForUserCommand).resolves({ Groups: [{ GroupName: 'AccountOperatorGroup' }] });
      mockCognitoClient.on(AdminDeleteUserCommand).resolves({});

      // Create user account mapping
      await dynamoDBDocumentClient.send(
        new PutCommand({
          TableName: userAccountMappingTableName,
          Item: createUserAccountMapping('operator@example.com', ['123456789012']),
        }),
      );

      // ACT
      await service.deleteUser('operator@example.com');

      // ASSERT
      expect(mockCognitoClient).toHaveReceivedCommandWith(AdminDeleteUserCommand, {
        UserPoolId: 'us-east-1_testpool',
        Username: 'operator@example.com',
      });

      // Verify DynamoDB mapping was deleted
      const result = await dynamoDBDocumentClient.send(
        new GetCommand({
          TableName: userAccountMappingTableName,
          Key: { userId: 'operator@example.com' },
        }),
      );
      expect(result.Item).toBeUndefined();
    });

    it('should throw NotFoundError when user does not exist', async () => {
      // ARRANGE
      mockCognitoClient.on(AdminGetUserCommand).rejects(new Error('User not found'));

      // ACT & ASSERT
      await expect(service.deleteUser('nonexistent@example.com')).rejects.toThrow(NotFoundError);
      expect(mockCognitoClient).not.toHaveReceivedCommand(AdminDeleteUserCommand);
    });

    it('should invalidate cache after successful deletion', async () => {
      // ARRANGE
      const userId = 'cache-test@example.com';
      mockCognitoClient.on(AdminGetUserCommand).resolves({
        UserAttributes: [
          { Name: 'email', Value: userId },
          { Name: 'custom:invitedBy', Value: 'admin@example.com' },
        ],
        UserCreateDate: new Date('2023-01-01'),
        UserStatus: 'CONFIRMED',
      });
      mockCognitoClient.on(AdminListGroupsForUserCommand).resolves({ Groups: [{ GroupName: 'AdminGroup' }] });
      mockCognitoClient.on(AdminDeleteUserCommand).resolves({});

      // Cache the user first
      await service.getUserById(userId);
      expect(mockCognitoClient).toHaveReceivedCommandTimes(AdminGetUserCommand, 1);

      // ACT
      await service.deleteUser(userId);

      // ASSERT - Next call should hit Cognito again (cache invalidated)
      await service.getUserById(userId);
      expect(mockCognitoClient).toHaveReceivedCommandTimes(AdminGetUserCommand, 2);
    });

    it('should handle Cognito delete failure', async () => {
      // ARRANGE
      mockCognitoClient.on(AdminGetUserCommand).resolves({
        UserAttributes: [
          { Name: 'email', Value: 'admin@example.com' },
          { Name: 'custom:invitedBy', Value: 'super@example.com' },
        ],
        UserCreateDate: new Date('2023-01-01'),
        UserStatus: 'CONFIRMED',
      });
      mockCognitoClient.on(AdminListGroupsForUserCommand).resolves({ Groups: [{ GroupName: 'AdminGroup' }] });
      mockCognitoClient.on(AdminDeleteUserCommand).rejects(new Error('Cognito delete failed'));

      // ACT & ASSERT
      await expect(service.deleteUser('admin@example.com')).rejects.toThrow('Cognito delete failed');
    });
  });

  describe('caching', () => {
    it('should return cached user on subsequent calls', async () => {
      // ARRANGE
      const userId = 'cached-user@example.com';
      mockCognitoClient.on(AdminGetUserCommand).resolves({
        UserAttributes: [
          { Name: 'email', Value: userId },
          { Name: 'custom:invitedBy', Value: 'admin@example.com' },
        ],
        UserCreateDate: new Date('2023-01-01'),
        UserStatus: 'CONFIRMED',
      });
      mockCognitoClient.on(AdminListGroupsForUserCommand).resolves({ Groups: [{ GroupName: 'AdminGroup' }] });

      // ACT
      const result1 = await service.getUserById(userId);
      const result2 = await service.getUserById(userId);

      // ASSERT
      expect(result1).toEqual(result2);
      expect(mockCognitoClient).toHaveReceivedCommandTimes(AdminGetUserCommand, 1);
      expect(mockCognitoClient).toHaveReceivedCommandTimes(AdminListGroupsForUserCommand, 1);
    });

    it('should cache null results', async () => {
      // ARRANGE
      const userId = 'nonexistent@example.com';
      mockCognitoClient.on(AdminGetUserCommand).rejects(new Error('User not found'));

      // ACT
      const result1 = await service.getUserById(userId);
      const result2 = await service.getUserById(userId);

      // ASSERT
      expect(result1).toBeNull();
      expect(result2).toBeNull();
      expect(mockCognitoClient).toHaveReceivedCommandTimes(AdminGetUserCommand, 1);
    });

    it('should cache null when email missing', async () => {
      // ARRANGE
      const userId = 'no-email@example.com';
      mockCognitoClient.on(AdminGetUserCommand).resolves({
        UserAttributes: [{ Name: 'custom:invitedBy', Value: 'admin@example.com' }],
      });

      // ACT
      const result1 = await service.getUserById(userId);
      const result2 = await service.getUserById(userId);

      // ASSERT
      expect(result1).toBeNull();
      expect(result2).toBeNull();
      expect(mockCognitoClient).toHaveReceivedCommandTimes(AdminGetUserCommand, 1);
    });

    it('should cache null when no recognized groups', async () => {
      // ARRANGE
      const userId = 'no-groups@example.com';
      mockCognitoClient.on(AdminGetUserCommand).resolves({
        UserAttributes: [
          { Name: 'email', Value: userId },
          { Name: 'custom:invitedBy', Value: 'admin@example.com' },
        ],
      });
      mockCognitoClient.on(AdminListGroupsForUserCommand).resolves({ Groups: [{ GroupName: 'UnknownGroup' }] });

      // ACT
      const result1 = await service.getUserById(userId);
      const result2 = await service.getUserById(userId);

      // ASSERT
      expect(result1).toBeNull();
      expect(result2).toBeNull();
      expect(mockCognitoClient).toHaveReceivedCommandTimes(AdminGetUserCommand, 1);
      expect(mockCognitoClient).toHaveReceivedCommandTimes(AdminListGroupsForUserCommand, 1);
    });
  });

  describe('getProviderEmailAttributeName', () => {
    it('should return email attribute name when provider has attribute mapping', async () => {
      // ARRANGE
      mockCognitoClient.on(DescribeIdentityProviderCommand).resolves({
        IdentityProvider: {
          AttributeMapping: {
            email: 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress',
          },
        },
      });

      // ACT
      const result = await service.getProviderEmailAttributeName('TestProvider');

      // ASSERT
      expect(result).toBe('http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress');
      expect(mockCognitoClient).toHaveReceivedCommandWith(DescribeIdentityProviderCommand, {
        UserPoolId: 'us-east-1_testpool',
        ProviderName: 'TestProvider',
      });
    });

    it('should throw error when provider has no attribute mapping object', async () => {
      // ARRANGE
      mockCognitoClient.on(DescribeIdentityProviderCommand).resolves({
        IdentityProvider: {},
      });

      // ACT & ASSERT
      await expect(service.getProviderEmailAttributeName('TestProvider')).rejects.toThrow(
        'Could not find attribute mapping for provider TestProvider',
      );
    });

    it('should throw error when IdentityProvider is undefined', async () => {
      // ARRANGE
      mockCognitoClient.on(DescribeIdentityProviderCommand).resolves({});

      // ACT & ASSERT
      await expect(service.getProviderEmailAttributeName('TestProvider')).rejects.toThrow(
        'Could not find attribute mapping for provider TestProvider',
      );
    });

    it('should throw error when email attribute mapping is missing', async () => {
      // ARRANGE
      mockCognitoClient.on(DescribeIdentityProviderCommand).resolves({
        IdentityProvider: {
          AttributeMapping: {
            name: 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name',
          },
        },
      });

      // ACT & ASSERT
      await expect(service.getProviderEmailAttributeName('TestProvider')).rejects.toThrow(
        'Could not find email attribute mapping for provider TestProvider. Ensure you have configured an email attribute mapping for this provider.',
      );
    });

    it('should throw error when Cognito command fails', async () => {
      // ARRANGE
      mockCognitoClient.on(DescribeIdentityProviderCommand).rejects(new Error('Provider not found'));

      // ACT & ASSERT
      await expect(service.getProviderEmailAttributeName('NonExistentProvider')).rejects.toThrow('Provider not found');
    });
  });

  describe('linkFederatedUser', () => {
    it('should successfully link federated user', async () => {
      // ARRANGE
      mockCognitoClient.on(DescribeIdentityProviderCommand).resolves({
        IdentityProvider: {
          AttributeMapping: {
            email: 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress',
          },
        },
      });
      mockCognitoClient.on(AdminLinkProviderForUserCommand).resolves({});

      // ACT
      await service.linkFederatedUser('user@example.com', 'SAML');

      // ASSERT
      expect(mockCognitoClient).toHaveReceivedCommandWith(AdminLinkProviderForUserCommand, {
        UserPoolId: 'us-east-1_testpool',
        DestinationUser: {
          ProviderName: 'Cognito',
          ProviderAttributeValue: 'user@example.com',
        },
        SourceUser: {
          ProviderName: 'SAML',
          ProviderAttributeName: 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress',
          ProviderAttributeValue: 'user@example.com',
        },
      });
    });

    it('should throw error when getProviderEmailAttributeName fails', async () => {
      // ARRANGE
      mockCognitoClient.on(DescribeIdentityProviderCommand).rejects(new Error('Provider not found'));

      // ACT & ASSERT
      await expect(service.linkFederatedUser('user@example.com', 'InvalidProvider')).rejects.toThrow(
        'Provider not found',
      );
      expect(mockCognitoClient).not.toHaveReceivedCommand(AdminLinkProviderForUserCommand);
    });

    it('should throw error when AdminLinkProviderForUserCommand fails', async () => {
      // ARRANGE
      mockCognitoClient.on(DescribeIdentityProviderCommand).resolves({
        IdentityProvider: {
          AttributeMapping: {
            email: 'email',
          },
        },
      });
      mockCognitoClient.on(AdminLinkProviderForUserCommand).rejects(new Error('Link failed'));

      // ACT & ASSERT
      await expect(service.linkFederatedUser('user@example.com', 'SAML')).rejects.toThrow('Link failed');
    });
  });

  describe('createUser - UsernameExistsException handling', () => {
    it('should throw BadRequestError when user already exists', async () => {
      // ARRANGE
      const usernameExistsError = new UsernameExistsException({
        message: 'An account with the given email already exists.',
        $metadata: {},
      });
      mockCognitoClient.on(AdminCreateUserCommand).rejects(usernameExistsError);

      // ACT & ASSERT
      await expect(service.createUser('existing@example.com', 'DelegatedAdmin', 'admin@example.com')).rejects.toThrow(
        new BadRequestError('User with username existing@example.com already exists.'),
      );
    });
  });
});
