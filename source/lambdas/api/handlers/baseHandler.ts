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
   * Admin/DelegatedAdmin and denies AccountOperators — a fail-closed default
   * (rather than createAccessRules([]), whose empty-account case is permissive
   * because callers like search rely on the service layer to scope results).
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

  extractAccountIdsFromRequest(request: {
    Filters?: { CompositeFilters?: Array<{ StringFilters?: Array<{ FieldName: string; Filter: { Value: string } }> }> };
  }): string[] {
    if (!request.Filters?.CompositeFilters) {
      return [];
    }

    const accountIds = request.Filters.CompositeFilters.flatMap(
      (compositeFilter) => compositeFilter.StringFilters || [],
    )
      .filter((stringFilter) => stringFilter.FieldName === 'accountId')
      .map((stringFilter) => stringFilter.Filter.Value);

    return Array.from(new Set(accountIds));
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
