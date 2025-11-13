// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { Logger } from '@aws-lambda-powertools/logger';
import { APIGatewayProxyEvent } from 'aws-lambda';
import { BadRequestError, ForbiddenError } from '../../common/utils/httpErrors';
import { AuthenticatedUser, AuthorizationService } from '../services/authorization';

/**
 * AWS API Gateway Cognito Authorizer Claims structure
 */
export interface CognitoClaims {
  username: string;
  'cognito:groups': string | string[];
  email?: string;
  sub?: string;
  aud?: string;
  iss?: string;
  exp?: number;
  iat?: number;
  token_use?: string;
  [key: string]: unknown;
}

export interface AccessValidationContext {
  accountIds?: string[];
  resourceIds?: string[];
  [key: string]: unknown; // Allow for additional context data
}

export interface AccessRule {
  requiredGroups: string[];
  validator?: (user: AuthenticatedUser, context?: AccessValidationContext) => void | Promise<void>;
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

  extractAccountIdsFromArns(arns: string[]): string[] {
    const accountIds: string[] = [];

    for (const arn of arns) {
      const arnMatch = arn.match(/^arn:aws:securityhub:[^:]+:(\d{12}):/);
      if (arnMatch) {
        const accountId = arnMatch[1];
        if (!accountIds.includes(accountId)) {
          accountIds.push(accountId);
        }
      } else {
        this.logger.warn('Could not extract account ID from ARN', { arn });
      }
    }

    return accountIds;
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
        error?: { issues: Array<{ path: (string | number)[]; message: string }> };
      };
    },
    errorPrefix: string = 'Invalid request',
  ): T {
    const parsedBody = (event.body as unknown) || {};
    const validationResult = schema.safeParse(parsedBody);

    if (!validationResult.success) {
      const errorDetails =
        validationResult.error?.issues?.map((issue) => `${issue.path.join('.')}: ${issue.message}`)?.join('; ') ||
        'Validation failed';
      throw new BadRequestError(`${errorPrefix}: ${errorDetails}`);
    }

    return validationResult.data!;
  }
}
