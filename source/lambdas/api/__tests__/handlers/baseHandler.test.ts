// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { Logger } from '@aws-lambda-powertools/logger';
import { z } from 'zod';
import { BaseHandler, getClaims } from '../../handlers/baseHandler';
import { AuthenticatedUser } from '../../services/authorization';
import { BadRequestError, ForbiddenError, UnauthorizedError } from '../../../common/utils/httpErrors';

describe('BaseHandler', () => {
  let baseHandler: BaseHandler;
  let mockLogger: Logger;

  beforeEach(() => {
    mockLogger = new Logger({ serviceName: 'test' });
    jest.spyOn(mockLogger, 'error').mockImplementation();
    jest.spyOn(mockLogger, 'info').mockImplementation();
    jest.spyOn(mockLogger, 'debug').mockImplementation();
    jest.spyOn(mockLogger, 'warn').mockImplementation();

    baseHandler = new BaseHandler(mockLogger);
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('getClaims', () => {
    it('should return claims when present', () => {
      const event = {
        requestContext: {
          authorizer: {
            claims: { username: 'user@example.com', 'cognito:groups': ['AdminGroup'] },
          },
        },
      } as any;

      const claims = getClaims(event);
      expect(claims.username).toBe('user@example.com');
    });

    it('should throw UnauthorizedError when claims are missing', () => {
      const event = { requestContext: {} } as any;
      expect(() => getClaims(event)).toThrow(UnauthorizedError);
      expect(() => getClaims(event)).toThrow('Missing authentication claims');
    });

    it('should throw UnauthorizedError when authorizer is undefined', () => {
      const event = { requestContext: { authorizer: undefined } } as any;
      expect(() => getClaims(event)).toThrow(UnauthorizedError);
    });
  });

  describe('extractAccountIdsFromFindings', () => {
    it('returns the unique account ids from finding records', () => {
      const findings = [{ accountId: '111122223333' }, { accountId: '444455556666' }, { accountId: '111122223333' }];
      expect(baseHandler.extractAccountIdsFromFindings(findings)).toEqual(['111122223333', '444455556666']);
    });

    it('returns an empty array when no findings are provided', () => {
      expect(baseHandler.extractAccountIdsFromFindings([])).toEqual([]);
    });

    it('ignores records with an empty account id', () => {
      const findings = [{ accountId: '' }, { accountId: '111122223333' }];
      expect(baseHandler.extractAccountIdsFromFindings(findings)).toEqual(['111122223333']);
    });
  });

  describe('createAdminOnlyAccessRules', () => {
    const userWith = (groups: string[]): AuthenticatedUser => ({
      username: 'u',
      email: 'u@example.com',
      groups,
      authorizedAccounts: ['111122223333'],
    });

    it('requires only Admin/DelegatedAdmin groups', () => {
      expect(baseHandler.createAdminOnlyAccessRules().requiredGroups).toEqual(['AdminGroup', 'DelegatedAdminGroup']);
    });

    it('allows AdminGroup and DelegatedAdminGroup', async () => {
      await expect(
        baseHandler.createAdminOnlyAccessRules().validator!(userWith(['AdminGroup'])),
      ).resolves.toBeUndefined();
      await expect(
        baseHandler.createAdminOnlyAccessRules().validator!(userWith(['DelegatedAdminGroup'])),
      ).resolves.toBeUndefined();
    });

    it('denies AccountOperatorGroup even with authorized accounts (fail closed when scope is unknown)', async () => {
      await expect(
        baseHandler.createAdminOnlyAccessRules().validator!(userWith(['AccountOperatorGroup'])),
      ).rejects.toThrow(ForbiddenError);
    });

    it('denies users without an admin group', async () => {
      await expect(baseHandler.createAdminOnlyAccessRules().validator!(userWith([]))).rejects.toThrow(ForbiddenError);
    });
  });

  describe('validateAccess', () => {
    const claims = { username: 'u@example.com', 'cognito:groups': ['AdminGroup'] } as any;
    const authedUser: AuthenticatedUser = {
      username: 'u',
      email: 'u@example.com',
      groups: ['AdminGroup'],
      authorizedAccounts: ['111122223333'],
    };

    it('returns the authenticated user and runs the optional validator', async () => {
      const authSpy = jest
        .spyOn((baseHandler as any).authorizationService, 'authenticateAndAuthorize')
        .mockResolvedValue(authedUser);
      const validator = jest.fn().mockResolvedValue(undefined);

      const result = await baseHandler.validateAccess(claims, {
        requiredGroups: ['AdminGroup'],
        validator,
      });

      expect(result).toBe(authedUser);
      expect(authSpy).toHaveBeenCalledWith(claims, ['AdminGroup']);
      expect(validator).toHaveBeenCalledWith(authedUser);
    });

    it('returns the authenticated user when no validator is supplied', async () => {
      jest.spyOn((baseHandler as any).authorizationService, 'authenticateAndAuthorize').mockResolvedValue(authedUser);

      const result = await baseHandler.validateAccess(claims, { requiredGroups: ['AdminGroup'] });

      expect(result).toBe(authedUser);
    });
  });

  describe('createAccessRules', () => {
    const userWith = (groups: string[], authorizedAccounts: string[] = []): AuthenticatedUser => ({
      username: 'u',
      email: 'u@example.com',
      groups,
      authorizedAccounts,
    });

    it('exposes the three account-scoped groups', () => {
      expect(baseHandler.createAccessRules([]).requiredGroups).toEqual([
        'AdminGroup',
        'DelegatedAdminGroup',
        'AccountOperatorGroup',
      ]);
    });

    it('allows Admin/DelegatedAdmin regardless of account scope', async () => {
      await expect(
        baseHandler.createAccessRules(['111122223333']).validator!(userWith(['AdminGroup'])),
      ).resolves.toBeUndefined();
      await expect(
        baseHandler.createAccessRules(['111122223333']).validator!(userWith(['DelegatedAdminGroup'])),
      ).resolves.toBeUndefined();
    });

    it('denies an AccountOperator with no authorized accounts', async () => {
      await expect(
        baseHandler.createAccessRules(['111122223333']).validator!(userWith(['AccountOperatorGroup'], [])),
      ).rejects.toThrow(ForbiddenError);
    });

    it('allows an AccountOperator whose authorized accounts cover the request', async () => {
      await expect(
        baseHandler.createAccessRules(['111122223333']).validator!(
          userWith(['AccountOperatorGroup'], ['111122223333']),
        ),
      ).resolves.toBeUndefined();
    });

    it('allows an AccountOperator when no specific accounts are requested', async () => {
      await expect(
        baseHandler.createAccessRules([]).validator!(userWith(['AccountOperatorGroup'], ['111122223333'])),
      ).resolves.toBeUndefined();
    });

    it('denies an AccountOperator requesting an unauthorized account', async () => {
      await expect(
        baseHandler.createAccessRules(['999988887777']).validator!(
          userWith(['AccountOperatorGroup'], ['111122223333']),
        ),
      ).rejects.toThrow(ForbiddenError);
    });

    it('denies a user with no matching group', async () => {
      await expect(baseHandler.createAccessRules([]).validator!(userWith(['SomeOtherGroup']))).rejects.toThrow(
        ForbiddenError,
      );
    });
  });

  describe('extractAccountIdsFromRequest', () => {
    it('returns an empty array when there are no composite filters', () => {
      expect(baseHandler.extractAccountIdsFromRequest({})).toEqual([]);
      expect(baseHandler.extractAccountIdsFromRequest({ Filters: {} })).toEqual([]);
    });

    it('extracts and de-duplicates accountId string filters', () => {
      const request = {
        Filters: {
          CompositeFilters: [
            {
              StringFilters: [
                { FieldName: 'accountId', Filter: { Value: '111122223333' } },
                { FieldName: 'region', Filter: { Value: 'us-east-1' } },
              ],
            },
            {
              StringFilters: [{ FieldName: 'accountId', Filter: { Value: '111122223333' } }],
            },
            {}, // composite filter with no StringFilters
          ],
        },
      };
      expect(baseHandler.extractAccountIdsFromRequest(request)).toEqual(['111122223333']);
    });
  });

  describe('extractValidatedPathId', () => {
    const eventWith = (id?: string) => ({ pathParameters: id === undefined ? undefined : { configId: id } }) as any;

    it('returns a valid UUID path parameter', () => {
      const uuid = '3f2504e0-4f89-41d3-9a0c-0305e82c3301';
      expect(baseHandler.extractValidatedPathId(eventWith(uuid), 'configId')).toBe(uuid);
    });

    it('throws BadRequestError for a missing path parameter', () => {
      expect(() => baseHandler.extractValidatedPathId(eventWith(), 'configId')).toThrow(BadRequestError);
    });

    it('throws BadRequestError for a non-UUID value', () => {
      expect(() => baseHandler.extractValidatedPathId(eventWith('not-a-uuid'), 'configId')).toThrow(
        'configId must be a valid UUID',
      );
    });
  });

  describe('extractValidatedBody', () => {
    const TestSchema = z.object({
      name: z.string(),
      age: z.number(),
      email: z.string().email(),
    });

    it('should successfully extract and validate a valid body', () => {
      const event = {
        body: {
          name: 'John Doe',
          age: 30,
          email: 'john@example.com',
        },
        httpMethod: 'POST',
        path: '/test',
        headers: {},
        requestContext: {} as any,
      } as any;

      const result = baseHandler.extractValidatedBody(event, TestSchema);

      expect(result).toEqual({
        name: 'John Doe',
        age: 30,
        email: 'john@example.com',
      });
    });

    it('should throw BadRequestError for invalid data', () => {
      const event = {
        body: {
          name: 'John Doe',
          age: 'thirty', // Invalid: should be number
          email: 'invalid-email', // Invalid: not a valid email
        },
        httpMethod: 'POST',
        path: '/test',
        headers: {},
        requestContext: {} as any,
      } as any;

      expect(() => {
        baseHandler.extractValidatedBody(event, TestSchema);
      }).toThrow(BadRequestError);
    });

    it('should throw BadRequestError with custom error prefix', () => {
      const event = {
        body: {
          name: 'John Doe',
          age: 'thirty',
          email: 'invalid-email',
        },
        httpMethod: 'POST',
        path: '/test',
        headers: {},
        requestContext: {} as any,
      } as any;

      expect(() => {
        baseHandler.extractValidatedBody(event, TestSchema, 'Custom validation error');
      }).toThrow('Custom validation error');
    });

    it('should handle empty body', () => {
      const event = {
        body: null,
        httpMethod: 'POST',
        path: '/test',
        headers: {},
        requestContext: {} as any,
      } as any;

      expect(() => {
        baseHandler.extractValidatedBody(event, TestSchema);
      }).toThrow(BadRequestError);
    });

    it('falls back to "Validation failed" when the schema reports failure without issue details', () => {
      const event = { body: {}, requestContext: {} as any } as any;
      // Duck-typed schema whose failure carries no `error` — exercises the
      // `|| 'Validation failed'` defensive fallback.
      const schemaWithoutIssues = { safeParse: () => ({ success: false }) };

      expect(() => baseHandler.extractValidatedBody(event, schemaWithoutIssues)).toThrow(
        'Invalid request: Validation failed',
      );
    });

    it('should return correct TypeScript type', () => {
      const event = {
        body: {
          name: 'John Doe',
          age: 30,
          email: 'john@example.com',
        },
        httpMethod: 'POST',
        path: '/test',
        headers: {},
        requestContext: {} as any,
      } as any;

      const result = baseHandler.extractValidatedBody(event, TestSchema);

      expect(typeof result.name).toBe('string');
      expect(typeof result.age).toBe('number');
      expect(typeof result.email).toBe('string');
    });
  });
});
