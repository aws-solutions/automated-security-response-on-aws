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

  describe('createRequestScopedAccessRules', () => {
    const operator = (authorizedAccounts: string[]): AuthenticatedUser => ({
      username: 'op',
      email: 'op@example.com',
      groups: ['AccountOperatorGroup'],
      authorizedAccounts,
    });

    // Mirrors how findings.ts and remediations.ts authorize a search request.
    const rulesForRequest = (request: Parameters<typeof baseHandler.createRequestScopedAccessRules>[0]) =>
      baseHandler.createRequestScopedAccessRules(request);

    const rootLevelAccountFilter = (accountId: string, comparison = 'EQUALS') => ({
      Filters: { StringFilters: [{ FieldName: 'accountId', Filter: { Value: accountId, Comparison: comparison } }] },
    });

    it('denies an operator requesting an unauthorized account via a root-level filter', async () => {
      await expect(
        rulesForRequest(rootLevelAccountFilter('999988887777')).validator!(operator(['111122223333'])),
      ).rejects.toThrow(ForbiddenError);
    });

    it('allows an operator requesting their own account via a root-level filter', async () => {
      await expect(
        rulesForRequest(rootLevelAccountFilter('111122223333')).validator!(operator(['111122223333'])),
      ).resolves.toBeUndefined();
    });

    it('denies an operator negating their own account to read every other account', async () => {
      // The filter value is authorized, so a check that reads only values admits
      // it, while the query it produces excludes that account and returns the
      // rest. The appended ceiling cannot narrow this: filters on one field are
      // combined with OR.
      await expect(
        rulesForRequest(rootLevelAccountFilter('111122223333', 'NOT_EQUALS')).validator!(operator(['111122223333'])),
      ).rejects.toThrow(ForbiddenError);
    });

    it('denies an operator whose accountId filter carries no comparison', async () => {
      const request = {
        Filters: { StringFilters: [{ FieldName: 'accountId', Filter: { Value: '111122223333' } }] },
      };
      await expect(rulesForRequest(request).validator!(operator(['111122223333']))).rejects.toThrow(ForbiddenError);
    });

    it('allows an admin to use a negated accountId filter', async () => {
      const admin: AuthenticatedUser = {
        username: 'admin',
        email: 'admin@example.com',
        groups: ['AdminGroup'],
        authorizedAccounts: [],
      };
      await expect(
        rulesForRequest(rootLevelAccountFilter('111122223333', 'NOT_EQUALS')).validator!(admin),
      ).resolves.toBeUndefined();
    });

    it('denies an operator whose accountId filter carries no value', async () => {
      // Conversion drops a filter with no value, so admitting it would authorize
      // a request that reaches the query with no account scope.
      const request = {
        Filters: { StringFilters: [{ FieldName: 'accountId', Filter: { Comparison: 'EQUALS' } }] },
      };
      await expect(rulesForRequest(request).validator!(operator(['111122223333']))).rejects.toThrow(ForbiddenError);
    });

    it('denies rather than throwing when an accountId filter has no Filter object', async () => {
      const request = { Filters: { StringFilters: [{ FieldName: 'accountId' }] } };
      await expect(rulesForRequest(request).validator!(operator(['111122223333']))).rejects.toThrow(ForbiddenError);
    });

    it('denies an operator requesting an unauthorized account via a composite filter', async () => {
      const request = {
        Filters: {
          CompositeFilters: [
            { StringFilters: [{ FieldName: 'accountId', Filter: { Value: '999988887777', Comparison: 'EQUALS' } }] },
          ],
        },
      };
      await expect(rulesForRequest(request).validator!(operator(['111122223333']))).rejects.toThrow(ForbiddenError);
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

  describe('extractAccountScopeFromRequest', () => {
    const equals = (fieldName: string, value: string) => ({
      FieldName: fieldName,
      Filter: { Value: value, Comparison: 'EQUALS' },
    });

    it('returns an empty scope when there are no filters at all', () => {
      expect(baseHandler.extractAccountScopeFromRequest({})).toEqual({
        accountIds: [],
        hasUnusableAccountFilter: false,
      });
      expect(baseHandler.extractAccountScopeFromRequest({ Filters: {} })).toEqual({
        accountIds: [],
        hasUnusableAccountFilter: false,
      });
    });

    it('extracts an accountId supplied as a root-level string filter', () => {
      // A root-level filter previously returned an empty list, which let the
      // per-account authorization check pass without narrowing the request.
      const request = {
        Filters: { StringFilters: [equals('accountId', '999988887777'), equals('region', 'us-east-1')] },
      };
      expect(baseHandler.extractAccountScopeFromRequest(request)).toEqual({
        accountIds: ['999988887777'],
        hasUnusableAccountFilter: false,
      });
    });

    it('extracts accountIds from both filter shapes and de-duplicates across them', () => {
      const request = {
        Filters: {
          StringFilters: [equals('accountId', '999988887777')],
          CompositeFilters: [
            { StringFilters: [equals('accountId', '111122223333')] },
            { StringFilters: [equals('accountId', '999988887777')] },
          ],
        },
      };
      const scope = baseHandler.extractAccountScopeFromRequest(request);
      expect(scope.accountIds.sort()).toEqual(['111122223333', '999988887777']);
      expect(scope.hasUnusableAccountFilter).toBe(false);
    });

    it('flags a negated accountId filter, which cannot be narrowed to authorized accounts', () => {
      const request = {
        Filters: {
          StringFilters: [{ FieldName: 'accountId', Filter: { Value: '111122223333', Comparison: 'NOT_EQUALS' } }],
        },
      };
      expect(baseHandler.extractAccountScopeFromRequest(request).hasUnusableAccountFilter).toBe(true);
    });

    it('flags an accountId filter with no comparison, which is dropped before it reaches the query', () => {
      const request = {
        Filters: { StringFilters: [{ FieldName: 'accountId', Filter: { Value: '111122223333' } }] },
      };
      expect(baseHandler.extractAccountScopeFromRequest(request).hasUnusableAccountFilter).toBe(true);
    });

    it('extracts and de-duplicates accountId string filters', () => {
      const request = {
        Filters: {
          CompositeFilters: [
            { StringFilters: [equals('accountId', '111122223333'), equals('region', 'us-east-1')] },
            { StringFilters: [equals('accountId', '111122223333')] },
            {}, // composite filter with no StringFilters
          ],
        },
      };
      expect(baseHandler.extractAccountScopeFromRequest(request).accountIds).toEqual(['111122223333']);
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
