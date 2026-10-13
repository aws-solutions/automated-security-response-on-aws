// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { Logger } from '@aws-lambda-powertools/logger';
import { APIGatewayProxyEvent } from 'aws-lambda';
import { z } from 'zod';
import { BadRequestError, ForbiddenError, UnauthorizedError } from '../../common/utils/httpErrors';
import { AuthenticatedUser, AuthorizationService } from '../services/authorization';

/**
 * Claims present on a human user (authorization_code) token from the Cognito
 * authorizer. These tokens always carry `username` and `cognito:groups`.
 */
export interface UserAccessTokenClaims {
  username: string;
  'cognito:groups': string | string[];
  client_id?: string;
  scope?: string;
  email?: string;
  sub?: string;
  aud?: string;
  iss?: string;
  exp?: number;
  iat?: number;
  token_use?: string;
  [key: string]: unknown;
}

/**
 * Claims present on a machine (client_credentials) token. These tokens carry
 * `client_id` and `sub` (both equal to the app-client id) but never carry
 * `cognito:groups` or `username`.
 */
export interface MachineAccessTokenClaims {
  client_id: string;
  sub: string;
  /** Space-delimited OAuth scopes (e.g. "asr-api/api asr-api/full-access"). */
  scope?: string;
  username?: never;
  'cognito:groups'?: never;
  email?: string;
  aud?: string;
  iss?: string;
  exp?: number;
  iat?: number;
  token_use?: string;
  [key: string]: unknown;
}

export type CognitoClaims = UserAccessTokenClaims | MachineAccessTokenClaims;

export interface AccessValidationContext {
  accountIds?: string[];
  resourceIds?: string[];
  [key: string]: unknown; // Allow for additional context data
}

export interface AccessRule {
  requiredGroups: string[];
  validator?: (user: AuthenticatedUser, context?: AccessValidationContext) => void | Promise<void>;
}

export interface RequestedAccountScope {
  accountIds: string[];
  hasUnusableAccountFilter: boolean;
}

export function getClaims(event: APIGatewayProxyEvent): CognitoClaims {
  const claims = event.requestContext?.authorizer?.claims;
  if (!claims) {
    throw new UnauthorizedError('Missing authentication claims');
  }
  return claims as CognitoClaims;
}

export class BaseHandler {
  protected readonly authorizationService: AuthorizationService;

  constructor(protected readonly logger: Logger) {
    this.authorizationService = new AuthorizationService(logger);
  }

  async validateAccess(claims: CognitoClaims, rules: AccessRule): Promise<AuthenticatedUser> {
    const authenticatedUser = await this.authorizationService.authenticateAndAuthorize(claims, rules.requiredGroups);

    if (rules.validator) {
      await rules.validator(authenticatedUser);
    }

    return authenticatedUser;
  }

  createAccessRules(accountIds: string[]): AccessRule {
    return {
      requiredGroups: ['AdminGroup', 'DelegatedAdminGroup', 'AccountOperatorGroup'],
      validator: async (user) => {
        if (user.groups.includes('AdminGroup') || user.groups.includes('DelegatedAdminGroup')) {
          return;
        }

        if (user.groups.includes('AccountOperatorGroup')) {
          if (!user.authorizedAccounts?.length) {
            throw new ForbiddenError('No authorized accounts');
          }

          if (accountIds.length > 0) {
            const unauthorized = accountIds.filter((id) => !user.authorizedAccounts!.includes(id));
            if (unauthorized.length > 0) {
              throw new ForbiddenError('Insufficient permissions');
            }
          }
          return;
        }
        throw new ForbiddenError('Insufficient permissions');
      },
    };
  }

  /**
   * Access rule for operations whose account scope cannot be determined, so
   * per-account authorization can't be applied. Restricts access to
   * Admin/DelegatedAdmin and denies AccountOperators, a fail-closed default.
   *
   * Use this for paths with no account ceiling of their own.
   * `createAccessRules([])` admits an AccountOperator without narrowing the
   * request, so it is safe only where something else supplies the account scope.
   * On the search paths that is `applyAccountFilteringForAccountOperators`,
   * which composes the operator's authorized accounts when the request carries
   * no `accountId` filter of its own, and `createRequestScopedAccessRules`,
   * which authorizes the filter when it does carry one.
   */
  createAdminOnlyAccessRules(): AccessRule {
    return {
      requiredGroups: ['AdminGroup', 'DelegatedAdminGroup'],
      validator: async (user) => {
        if (user.groups.includes('AdminGroup') || user.groups.includes('DelegatedAdminGroup')) {
          return;
        }
        throw new ForbiddenError('Insufficient permissions');
      },
    };
  }

  /**
   * Account scope a search request asks for.
   *
   * `hasUnusableAccountFilter` is set when the request carries an `accountId`
   * filter that cannot serve as a scope: any comparison other than `EQUALS`, or a
   * missing filter, comparison or value.
   *
   * A non-`EQUALS` filter cannot be narrowed to the operator's authorized
   * accounts, because the repository combines filters on one field with OR, so an
   * appended ceiling widens the scope instead of intersecting it and
   * `accountId NOT_EQUALS <own account>` would return every other account. An
   * incomplete filter is dropped when the request is converted to search
   * criteria, so accepting it as a scope would authorize a request that reaches
   * the query with none. Both are denied.
   */
  extractAccountScopeFromRequest(request: {
    Filters?: {
      StringFilters?: Array<{ FieldName: string; Filter?: { Value?: string; Comparison?: string } }>;
      CompositeFilters?: Array<{
        StringFilters?: Array<{ FieldName: string; Filter?: { Value?: string; Comparison?: string } }>;
      }>;
    };
  }): RequestedAccountScope {
    const filters = request.Filters;
    if (!filters) {
      return { accountIds: [], hasUnusableAccountFilter: false };
    }

    // Both filter shapes are read. The service layer accepts an accountId
    // filter at the root or nested in a composite, so validating only the
    // composite shape would let a root-level filter through unauthorized.
    const stringFilters = [
      ...(filters.StringFilters ?? []),
      ...(filters.CompositeFilters ?? []).flatMap((compositeFilter) => compositeFilter.StringFilters ?? []),
    ];

    const accountIdFilters = stringFilters.filter((stringFilter) => stringFilter.FieldName === 'accountId');
    // Fail closed on anything that is not a usable EQUALS filter. A missing
    // Filter, comparison or value is dropped when the request is converted to
    // search criteria, so admitting one here would authorize a request that
    // reaches the query with no account scope.
    const hasUnusableAccountFilter = accountIdFilters.some(
      (stringFilter) => stringFilter.Filter?.Comparison !== 'EQUALS' || !stringFilter.Filter?.Value,
    );
    const accountIds = accountIdFilters
      .map((stringFilter) => stringFilter.Filter?.Value)
      .filter((accountId): accountId is string => accountId !== undefined);

    return {
      accountIds: Array.from(new Set(accountIds)),
      hasUnusableAccountFilter,
    };
  }

  /**
   * Access rule for a search request, scoped to the accounts the request asks
   * for. Prefer this over deriving the scope and calling `createAccessRules`
   * separately: it is the only path that also rejects an account filter whose
   * comparison cannot be narrowed.
   */
  createRequestScopedAccessRules(request: {
    Filters?: {
      StringFilters?: Array<{ FieldName: string; Filter?: { Value?: string; Comparison?: string } }>;
      CompositeFilters?: Array<{
        StringFilters?: Array<{ FieldName: string; Filter?: { Value?: string; Comparison?: string } }>;
      }>;
    };
  }): AccessRule {
    const requestedScope = this.extractAccountScopeFromRequest(request);
    const accountScopedRules = this.createAccessRules(requestedScope.accountIds);

    return {
      ...accountScopedRules,
      validator: async (user) => {
        if (
          requestedScope.hasUnusableAccountFilter &&
          !user.groups.includes('AdminGroup') &&
          !user.groups.includes('DelegatedAdminGroup')
        ) {
          throw new ForbiddenError('Unsupported accountId filter comparison');
        }
        await accountScopedRules.validator?.(user);
      },
    };
  }

  /**
   * Derives the unique set of AWS account ids from already-fetched finding
   * records for account-scoped authorization.
   *
   * The account comes from the authoritative `accountId` persisted on each
   * finding — which resolves IAM Access Analyzer organization-analyzer findings
   * to the resource-owner account — rather than re-parsing the finding-id ARN.
   * Callers fetch the findings once and pass the same records to both this
   * check and the subsequent action, so a finding that cannot be found in
   * DynamoDB contributes no account id and simply cannot be acted upon: there
   * is no account-scope bypass.
   */
  extractAccountIdsFromFindings(findings: ReadonlyArray<{ accountId: string }>): string[] {
    const accountIds = findings.map((finding) => finding.accountId).filter((accountId) => !!accountId);
    return Array.from(new Set(accountIds));
  }

  /**
   * Extracts, validates, and returns the typed body from an API Gateway event
   * Combines body extraction, schema validation, and error handling in one method
   * When using httpJsonBodyParser middleware, the body is already parsed
   * @param event - The API Gateway event
   * @param schema - The Zod schema to validate against
   * @param errorPrefix - Optional prefix for validation error messages
   * @returns The validated and typed body
   * @throws BadRequestError if validation fails
   */
  extractValidatedBody<T>(
    event: APIGatewayProxyEvent,
    schema: {
      safeParse: (data: unknown) => {
        success: boolean;
        data?: T;
        error?: { issues: Array<{ path: PropertyKey[]; message: string }> };
      };
    },
    errorPrefix: string = 'Invalid request',
  ): T {
    const parsedBody = (event.body as unknown) || {};
    const validationResult = schema.safeParse(parsedBody);

    if (!validationResult.success) {
      const errorDetails =
        validationResult.error?.issues
          ?.map((issue) => `${issue.path.map(String).join('.')}: ${issue.message}`)
          ?.join('; ') || 'Validation failed';
      throw new BadRequestError(`${errorPrefix}: ${errorDetails}`);
    }

    return validationResult.data!;
  }

  extractValidatedPathId<T extends string = string>(event: APIGatewayProxyEvent, paramName: string): T {
    const value = event.pathParameters?.[paramName];
    if (!value || !z.uuid().safeParse(value).success) {
      throw new BadRequestError(`${paramName} must be a valid UUID`);
    }
    return value as T;
  }
}
