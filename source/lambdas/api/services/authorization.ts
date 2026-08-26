// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { Logger } from '@aws-lambda-powertools/logger';
import { UserAccountMappingRepository } from '../../common/repositories/userAccountMappingRepository';
import { createDynamoDBClient } from '../../common/utils/dynamodb';
import { ForbiddenError, UnauthorizedError } from '../../common/utils/httpErrors';
import {
  emitMetric,
  M2M_FORBIDDEN_AUTHORIZATION_METRIC,
  USER_POOL_DIMENSION,
} from '../../common/utils/cloudWatchMetrics';
import { CognitoService } from './cognito';
import type { CognitoClaims, MachineAccessTokenClaims } from '../handlers/baseHandler';
import { apiLambdaEnvironment } from '../apiLambdaEnvironment';

/**
 * OAuth scope that grants a machine (client_credentials) token Full Access. The
 * customer creates an M2M app client granted this scope post-deploy; Cognito
 * only issues it to clients explicitly granted it, so its presence on a token is
 * a trustworthy capability signal.
 */
const FULL_ACCESS_SCOPE = 'asr-api/full-access';

export interface AuthenticatedUser {
  username: string;
  groups: string[];
  authorizedAccounts?: string[];
  email: string;
}

/**
 * Tests whether the token's space-delimited `scope` claim contains the
 * full-access scope, matching an exact scope token (never a substring).
 */
function hasFullAccessScope(claims: CognitoClaims): boolean {
  return (claims.scope ?? '').split(/\s+/).includes(FULL_ACCESS_SCOPE);
}

export class AuthorizationService {
  private readonly userAccountMappingRepository: UserAccountMappingRepository;
  private readonly cognitoService: CognitoService;

  constructor(private readonly logger: Logger) {
    this.userAccountMappingRepository = new UserAccountMappingRepository(
      'AuthorizationService',
      apiLambdaEnvironment().USER_ACCOUNT_MAPPING_TABLE_NAME,
      createDynamoDBClient({}),
    );
    this.cognitoService = new CognitoService(logger);
  }

  async authenticateAndAuthorize(claims: CognitoClaims, requiredGroups: string[]): Promise<AuthenticatedUser> {
    // Machine (client_credentials) tokens carry no `cognito:groups`, so they must be
    // classified and resolved BEFORE the human group-parsing below ever runs — otherwise
    // a groupless token would hit `undefined.split(',')`. A null result means this is
    // not a machine token, so we fall through to the human path.
    const machinePrincipal = this.tryResolveMachinePrincipal(claims);
    if (machinePrincipal) {
      const hasRequiredGroup = requiredGroups.some((group) => machinePrincipal.groups.includes(group));
      if (!hasRequiredGroup) {
        this.logger.warn(`Machine principal ${machinePrincipal.username} lacks required authorization`);
        throw new ForbiddenError();
      }
      return machinePrincipal;
    }

    const rawGroupsClaim = claims['cognito:groups'];
    if (rawGroupsClaim === undefined) {
      // On the human path, `cognito:groups` must be present. If it's undefined here,
      // the token is malformed — surface the problem explicitly rather than silently
      // producing `['']` which would just fail the group check with a misleading 403.
      throw new UnauthorizedError('Token is missing the cognito:groups claim');
    }
    // groups could be a string, in which case we need to convert it into an array such that includes()
    // does not simply search for substrings matching each group in requiredGroups
    const groups = Array.isArray(rawGroupsClaim) ? rawGroupsClaim : rawGroupsClaim.split(',');
    this.logger.info('User groups retrieved', { groupCount: groups.length });

    const hasRequiredGroup = requiredGroups.some((group) => groups.includes(group));
    if (!hasRequiredGroup) {
      this.logger.warn(`User ${claims.username} lacks required authorization`);
      throw new ForbiddenError();
    }

    const userEmailResult = await this.cognitoService.getUserEmail(claims.username);
    if (!userEmailResult?.email) {
      this.logger.error('Could not retrieve user email from Cognito', { username: claims.username });
      throw new ForbiddenError('Invalid user');
    }
    const email = userEmailResult.email;

    let authorizedAccounts: string[] | undefined;
    const isAccountOperator = groups.includes('AccountOperatorGroup');

    if (isAccountOperator) {
      try {
        authorizedAccounts = await this.userAccountMappingRepository.getUserAccounts(email);
        this.logger.debug('Loaded authorized accounts for Account Operator', {
          username: claims.username,
          accountCount: authorizedAccounts?.length || 0,
          email,
        });
      } catch (error) {
        this.logger.error('Failed to load authorized accounts for Account Operator', {
          username: claims.username,
          email,
          error: error instanceof Error ? error.message : String(error),
        });
        throw new ForbiddenError('Unable to verify authorized accounts for the user');
      }
    }

    return { username: claims.username, groups, authorizedAccounts, email };
  }

  /**
   * Type guard: a machine (client_credentials) token has `sub === client_id` and
   * a truthy `client_id`. Narrows `CognitoClaims` to `MachineClaims`.
   */
  private isMachineToken(claims: CognitoClaims): claims is MachineAccessTokenClaims {
    return !!claims.client_id && claims.sub === claims.client_id;
  }

  /**
   * Classifies and resolves a machine (client_credentials) token. Tri-state:
   *
   * - `null` — not a machine token (`sub` differs from `client_id`, or no
   *   `client_id`); the caller falls through to the human authorization path.
   * - `AuthenticatedUser` — a machine token carrying the `asr-api/full-access`
   *   scope. It is granted membership in the existing `AdminGroup`, which yields
   *   Full Access through the existing access rules; `username` and `email` are
   *   set to the raw `client_id` for a stable audit identity, and no
   *   `getUserEmail` lookup or `UserAccountMapping` read is performed.
   * - throws `ForbiddenError` — a machine token without the full-access scope.
   *   Fails closed and emits the `ASR/M2MForbiddenAuthorization` metric that the
   *   opt-in CloudWatch alarm watches.
   *
   * Full-access trust is anchored solely on the OAuth scope (which Cognito only
   * issues to clients granted it), never on a mutable mapping-table row.
   */
  private tryResolveMachinePrincipal(claims: CognitoClaims): AuthenticatedUser | null {
    if (!this.isMachineToken(claims)) {
      return null;
    }
    const clientId = claims.client_id;
    if (hasFullAccessScope(claims)) {
      return { username: clientId, groups: ['AdminGroup'], email: clientId };
    }
    this.logger.warn('Machine token lacks the full-access scope');
    // Publish the metric the opt-in alarm watches before failing closed. emitMetric
    // already swallows its own errors; the extra guard keeps the fail-closed 403 the
    // sole outcome even if metric emission is broken, so observability can never
    // alter the request result.
    try {
      emitMetric(M2M_FORBIDDEN_AUTHORIZATION_METRIC, 1, [
        { name: USER_POOL_DIMENSION, value: apiLambdaEnvironment().USER_POOL_ID },
      ]);
    } catch (error) {
      this.logger.error('Failed to emit M2M denial metric', { error });
    }
    throw new ForbiddenError();
  }
}
