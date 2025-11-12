// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { Logger } from '@aws-lambda-powertools/logger';
import { AuthorizationService } from '../../services/authorization';
import { ForbiddenError, UnauthorizedError } from '../../../common/utils/httpErrors';
import {
  CognitoIdentityProviderClient,
  AdminGetUserCommand,
  AdminListGroupsForUserCommand,
} from '@aws-sdk/client-cognito-identity-provider';
import { mockClient } from 'aws-sdk-client-mock';
import { DynamoDBTestSetup } from '../../../common/__tests__/dynamodbSetup';

const cognitoMock = mockClient(CognitoIdentityProviderClient);

describe('AuthorizationService', () => {
  let service: AuthorizationService;
  let mockLogger: Logger;
  const userAccountMappingTableName = 'test-user-account-mapping-table';

  beforeAll(async () => {
    await DynamoDBTestSetup.initialize();
    await DynamoDBTestSetup.createUserAccountMappingTable(userAccountMappingTableName);
  });

  afterAll(async () => {
    await DynamoDBTestSetup.deleteTable(userAccountMappingTableName);
  });

  beforeEach(async () => {
    await DynamoDBTestSetup.clearTable(userAccountMappingTableName, 'userAccountMapping');
    process.env.USER_POOL_ID = 'us-east-1_testpool';
    process.env.USER_ACCOUNT_MAPPING_TABLE_NAME = userAccountMappingTableName;
    mockLogger = new Logger({ serviceName: 'test' });
    service = new AuthorizationService(mockLogger);

    cognitoMock.reset();

    // Mock AdminGetUserCommand to return user data based on the username
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

    // Mock AdminListGroupsForUserCommand to return appropriate groups
    cognitoMock.on(AdminListGroupsForUserCommand).callsFake((input) => {
      const username = input.Username;
      let groups = [];

      if (username?.includes('admin')) {
        groups = [{ GroupName: 'AdminGroup' }];
      } else {
        groups = [{ GroupName: 'DelegatedAdminGroup' }];
      }

      return Promise.resolve({ Groups: groups });
    });
  });

  describe('authenticateAndAuthorize', () => {
    it('should return authenticated user when valid claims and groups', async () => {
      // ARRANGE
      const claims = {
        'cognito:groups': ['admin', 'user'],
        username: 'test@example.com',
      };
      const requiredGroups = ['admin'];

      // ACT
      const result = await service.authenticateAndAuthorize(claims, requiredGroups);

      // ASSERT
      expect(result).toEqual({
        username: 'test@example.com',
        groups: ['admin', 'user'],
        email: 'test@example.com',
        authorizedAccounts: undefined,
      });
    });

    it('should throw ForbiddenError when user lacks required group', async () => {
      // ARRANGE
      const claims = {
        'cognito:groups': ['user', 'viewer'],
        username: 'test@example.com',
      };
      const requiredGroups = ['admin'];

      // ACT & ASSERT
      await expect(service.authenticateAndAuthorize(claims, requiredGroups)).rejects.toThrow(new ForbiddenError());
    });

    it('should succeed when user has one of multiple required groups', async () => {
      // ARRANGE
      const claims = {
        'cognito:groups': ['user', 'editor'],
        username: 'test@example.com',
      };
      const requiredGroups = ['admin', 'editor'];

      // ACT
      const result = await service.authenticateAndAuthorize(claims, requiredGroups);

      // ASSERT
      expect(result.username).toBe('test@example.com');
      expect(result.groups).toEqual(['user', 'editor']);
    });

    it('should handle empty groups array', async () => {
      // ARRANGE
      const claims = {
        'cognito:groups': [],
        username: 'test@example.com',
      };
      const requiredGroups = ['admin'];

      // ACT & ASSERT
      await expect(service.authenticateAndAuthorize(claims, requiredGroups)).rejects.toThrow(new ForbiddenError());
    });

    it('should handle empty groups string', async () => {
      // ARRANGE
      const claims = {
        'cognito:groups': '',
        username: 'test@example.com',
      };
      const requiredGroups = ['admin'];

      // ACT & ASSERT
      await expect(service.authenticateAndAuthorize(claims, requiredGroups)).rejects.toThrow(new ForbiddenError());
    });

    it('should convert cognito:groups from string to array', async () => {
      // ARRANGE
      const claims = {
        'cognito:groups': 'admin',
        username: 'test@example.com',
      };
      const requiredGroups = ['admin'];

      // ACT
      const result = await service.authenticateAndAuthorize(claims, requiredGroups);

      // ASSERT
      expect(result.username).toBe('test@example.com');
      expect(result.groups).toEqual(['admin']);
    });

    it('should not permit groups that include a substring of requiredGroups', async () => {
      // ARRANGE
      const claims = {
        'cognito:groups': 'fakeadmin',
        username: 'test@example.com',
      };
      const requiredGroups = ['admin'];

      // ACT & ASSERT
      await expect(service.authenticateAndAuthorize(claims, requiredGroups)).rejects.toThrow(new ForbiddenError());
    });

    it('should handle empty required groups array', async () => {
      // ARRANGE
      const claims = {
        'cognito:groups': ['user'],
        username: 'test@example.com',
      };
      const requiredGroups: string[] = [];

      // ACT & ASSERT
      await expect(service.authenticateAndAuthorize(claims, requiredGroups)).rejects.toThrow(new ForbiddenError());
    });
  });
});
