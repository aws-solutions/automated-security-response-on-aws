// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { Logger } from '@aws-lambda-powertools/logger';
import { AuthorizationService } from '../../services/authorization';
import { ForbiddenError, HttpError } from '../../../common/utils/httpErrors';
import {
  AdminGetUserCommand,
  AdminListGroupsForUserCommand,
  CognitoIdentityProviderClient,
} from '@aws-sdk/client-cognito-identity-provider';
import { mockClient } from 'aws-sdk-client-mock';
import { DynamoDBTestSetup } from '../../../common/__tests__/dynamodbSetup';
import { PutCommand } from '@aws-sdk/lib-dynamodb';
import type { CognitoClaims } from '../../handlers/baseHandler';
import * as cloudWatchMetrics from '../../../common/utils/cloudWatchMetrics';

const cognitoMock = mockClient(CognitoIdentityProviderClient);

const FULL_ACCESS_SCOPE = 'asr-api/full-access';

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

    describe('machine (client_credentials) tokens', () => {
      const machineRequiredGroups = ['AdminGroup', 'DelegatedAdminGroup', 'AccountOperatorGroup'];
      const clientId = 'machine-client-abc123';

      const makeMachineClaims = (scope?: string): CognitoClaims => ({
        client_id: clientId,
        sub: clientId,
        token_use: 'access',
        ...(scope !== undefined ? { scope } : {}),
      });

      let emitMetricSpy: jest.SpyInstance;

      beforeEach(() => {
        emitMetricSpy = jest.spyOn(cloudWatchMetrics, 'emitMetric').mockImplementation(() => undefined);
      });

      afterEach(() => {
        emitMetricSpy.mockRestore();
      });

      it('should grant Full Access (groups include AdminGroup) for a token carrying the full-access scope', async () => {
        const claims = makeMachineClaims(`asr-api/api ${FULL_ACCESS_SCOPE}`);

        const result = await service.authenticateAndAuthorize(claims, machineRequiredGroups);

        expect(result.groups).toContain('AdminGroup');
      });

      it('should throw a typed ForbiddenError (403, never a TypeError/500) for a machine token without the full-access scope', async () => {
        // Carries only asr-api/api (enough to pass API Gateway, not the backend).
        const claims = makeMachineClaims('asr-api/api');

        const promise = service.authenticateAndAuthorize(claims, machineRequiredGroups);
        await expect(promise).rejects.toThrow(ForbiddenError);

        const error = await promise.catch((e: unknown) => e);
        expect(error).toBeInstanceOf(HttpError);
        expect(error).not.toBeInstanceOf(TypeError);
        expect((error as HttpError).statusCode).toBe(403);
      });

      it('should throw ForbiddenError for a machine token with no scope claim at all', async () => {
        const claims = makeMachineClaims(undefined);

        await expect(service.authenticateAndAuthorize(claims, machineRequiredGroups)).rejects.toThrow(ForbiddenError);
      });

      it('should match the full-access scope by exact token, not substring', async () => {
        // A scope that merely contains the full-access string as a prefix must not match.
        const claims = makeMachineClaims('asr-api/full-access-readonly');

        await expect(service.authenticateAndAuthorize(claims, machineRequiredGroups)).rejects.toThrow(ForbiddenError);
      });

      it('should emit the M2MForbiddenAuthorization metric (UserPool dimension) when denying a machine token', async () => {
        const claims = makeMachineClaims('asr-api/api');

        await expect(service.authenticateAndAuthorize(claims, machineRequiredGroups)).rejects.toThrow(ForbiddenError);

        expect(emitMetricSpy).toHaveBeenCalledTimes(1);
        expect(emitMetricSpy).toHaveBeenCalledWith(
          'M2MForbiddenAuthorization',
          1,
          expect.arrayContaining([{ name: 'UserPool', value: 'us-east-1_testpool' }]),
        );
      });

      it('should NOT emit the denial metric on the allow path', async () => {
        const claims = makeMachineClaims(FULL_ACCESS_SCOPE);

        await service.authenticateAndAuthorize(claims, machineRequiredGroups);

        expect(emitMetricSpy).not.toHaveBeenCalled();
      });

      it('should still return a clean 403 (not a 500) if metric emission throws', async () => {
        emitMetricSpy.mockImplementation(() => {
          throw new Error('metrics pipeline broken');
        });
        const claims = makeMachineClaims('asr-api/api');

        const promise = service.authenticateAndAuthorize(claims, machineRequiredGroups);
        await expect(promise).rejects.toThrow(ForbiddenError);

        const error = await promise.catch((e: unknown) => e);
        expect((error as HttpError).statusCode).toBe(403);
      });

      it('should NOT call Cognito AdminGetUser on the machine path', async () => {
        const claims = makeMachineClaims(FULL_ACCESS_SCOPE);

        await service.authenticateAndAuthorize(claims, machineRequiredGroups);

        expect(cognitoMock.commandCalls(AdminGetUserCommand)).toHaveLength(0);
      });

      it('should set the resolved username and email to the raw client_id', async () => {
        const claims = makeMachineClaims(FULL_ACCESS_SCOPE);

        const result = await service.authenticateAndAuthorize(claims, machineRequiredGroups);

        expect(result.username).toBe(clientId);
        expect(result.email).toBe(clientId);
      });

      it('should NOT query the UserAccountMapping table for the machine principal', async () => {
        // Seed a mapping row — if the machine path incorrectly reads it, the
        // result would contain authorizedAccounts, which we assert is absent.
        const docClient = DynamoDBTestSetup.getDocClient();
        await docClient.send(
          new PutCommand({
            TableName: userAccountMappingTableName,
            Item: { userId: clientId, accountIds: ['999999999999'] },
          }),
        );

        const claims = makeMachineClaims(FULL_ACCESS_SCOPE);

        const result = await service.authenticateAndAuthorize(claims, machineRequiredGroups);

        expect(result.authorizedAccounts).toBeUndefined();
      });
    });

    describe('human/UI tokens (regression)', () => {
      it('should parse cognito:groups, call getUserEmail, and load AccountOperatorGroup accounts', async () => {
        const docClient = DynamoDBTestSetup.getDocClient();
        await docClient.send(
          new PutCommand({
            TableName: userAccountMappingTableName,
            Item: { userId: 'operator@example.com', accountIds: ['111122223333'] },
          }),
        );

        const claims = {
          'cognito:groups': ['AccountOperatorGroup'],
          username: 'operator@example.com',
        };
        const requiredGroups = ['AccountOperatorGroup'];

        const result = await service.authenticateAndAuthorize(claims, requiredGroups);

        expect(result.groups).toEqual(['AccountOperatorGroup']);
        expect(result.email).toBe('operator@example.com');
        expect(result.username).toBe('operator@example.com');
        expect(result.authorizedAccounts).toEqual(['111122223333']);
        expect(cognitoMock.commandCalls(AdminGetUserCommand).length).toBeGreaterThan(0);
      });

      it('should ignore a scope claim when cognito:groups is present (scope never grants human access)', async () => {
        // A human token that happens to also carry the full-access scope must still
        // be authorized purely on its groups, never elevated via the scope claim.
        const claims = {
          'cognito:groups': ['user'],
          username: 'test@example.com',
          scope: FULL_ACCESS_SCOPE,
        };
        const requiredGroups = ['admin'];

        await expect(service.authenticateAndAuthorize(claims, requiredGroups)).rejects.toThrow(new ForbiddenError());
      });
    });
  });
});
