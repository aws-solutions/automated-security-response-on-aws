// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { Logger } from '@aws-lambda-powertools/logger';
import { UserAccountMappingRepository } from '../../common/repositories/userAccountMappingRepository';
import { createDynamoDBClient } from '../../common/utils/dynamodb';
import { ForbiddenError } from '../../common/utils/httpErrors';
import { CognitoService } from './cognito';
import type { CognitoClaims } from '../handlers/baseHandler';

export interface AuthenticatedUser {
  username: string;
  groups: string[];
  authorizedAccounts?: string[];
  email: string;
}

export class AuthorizationService {
  private readonly userAccountMappingRepository: UserAccountMappingRepository;
  private readonly cognitoService: CognitoService;

  constructor(private readonly logger: Logger) {
    this.userAccountMappingRepository = new UserAccountMappingRepository(
      'AuthorizationService',
      process.env.USER_ACCOUNT_MAPPING_TABLE_NAME!,
      createDynamoDBClient({}),
    );
    this.cognitoService = new CognitoService(logger);
  }

  async authenticateAndAuthorize(claims: CognitoClaims, requiredGroups: string[]): Promise<AuthenticatedUser> {
    const rawGroupsClaim = claims['cognito:groups'];
    // groups could be a string, in which case we need to convert it into an array such that includes()
    // does not simply search for substrings matching each group in requiredGroups
    const groups = Array.isArray(rawGroupsClaim) ? rawGroupsClaim : rawGroupsClaim.split(',');
    const username = claims.username;

    this.logger.info('User groups retrieved', { groupCount: groups.length });

    // Check authorization
    const hasRequiredGroup = requiredGroups.some((group) => groups.includes(group));
    if (!hasRequiredGroup) {
      this.logger.warn(`User ${username} lacks required authorization`);
      throw new ForbiddenError();
    }

    // Get user email from Cognito
    const userEmailResult = await this.cognitoService.getUserEmail(username);
    if (!userEmailResult?.email) {
      this.logger.error('Could not retrieve user email from Cognito', { username });
      throw new ForbiddenError('Invalid user');
    }
    const email = userEmailResult.email;

    // Load authorized accounts for Account Operators
    let authorizedAccounts: string[] | undefined;
    const isAccountOperator = groups.includes('AccountOperatorGroup');

    if (isAccountOperator) {
      try {
        authorizedAccounts = await this.userAccountMappingRepository.getUserAccounts(email);
        this.logger.debug('Loaded authorized accounts for Account Operator', {
          username,
          accountCount: authorizedAccounts?.length || 0,
          email,
        });
      } catch (error) {
        this.logger.error('Failed to load authorized accounts for Account Operator', {
          username,
          email,
          error: error instanceof Error ? error.message : String(error),
        });
        throw new ForbiddenError('Unable to verify authorized accounts for the user');
      }
    }

    return { username, groups, authorizedAccounts, email };
  }
}
