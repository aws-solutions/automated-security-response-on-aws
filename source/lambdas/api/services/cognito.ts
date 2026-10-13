// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { Logger } from '@aws-lambda-powertools/logger';
import {
  AdminAddUserToGroupCommand,
  AdminCreateUserCommand,
  AdminDeleteUserCommand,
  AdminGetUserCommand,
  AdminListGroupsForUserCommand,
  AdminLinkProviderForUserCommand,
  CognitoIdentityProviderClient,
  ListUsersCommand,
  UsernameExistsException,
  DescribeIdentityProviderCommand,
  UserType as CognitoUserType,
} from '@aws-sdk/client-cognito-identity-provider';
import {
  UserAccountMappingRepository,
  UserAuthorizationData,
} from '../../common/repositories/userAccountMappingRepository';
import { createDynamoDBClient } from '../../common/utils/dynamodb';
import { AccountOperatorUser, AdminUser, DelegatedAdminUser, User } from '@asr/data-models';
import { BadRequestError, NotFoundError } from '../../common/utils/httpErrors';
import { apiLambdaEnvironment } from '../apiLambdaEnvironment';

type AsrUserType = 'admin' | 'delegated-admin' | 'account-operator';

interface RecognizedCognitoUser {
  readonly cognitoUser: CognitoUserType;
  readonly email: string;
  readonly invitedBy: string;
  readonly userType: AsrUserType;
}

const COGNITO_GROUP_LOOKUP_CONCURRENCY = 10;

export class CognitoService {
  private readonly cognitoClient: CognitoIdentityProviderClient;
  private readonly userPoolId: string;
  private readonly userAccountMappingRepository: UserAccountMappingRepository;
  private readonly userCache = new Map<string, { user: User | null }>();

  constructor(
    private readonly logger: Logger,
    userPoolId?: string,
  ) {
    const env = apiLambdaEnvironment();
    this.cognitoClient = new CognitoIdentityProviderClient({});
    this.userPoolId = userPoolId ?? env.USER_POOL_ID;
    this.userAccountMappingRepository = new UserAccountMappingRepository(
      'UsersAPI',
      env.USER_ACCOUNT_MAPPING_TABLE_NAME,
      createDynamoDBClient({}),
    );
  }

  async getAllUsers(): Promise<User[]> {
    try {
      const cognitoUsers = await this.listAllCognitoUsers();
      const recognizedUsers = (
        await mapWithConcurrency(cognitoUsers, COGNITO_GROUP_LOOKUP_CONCURRENCY, async (cognitoUser) => {
          const email = cognitoUser.Attributes?.find((attr) => attr.Name === 'email')?.Value;
          const invitedBy = cognitoUser.Attributes?.find((attr) => attr.Name === 'custom:invitedBy')?.Value;
          const username = cognitoUser.Username;

          if (!email || !invitedBy || !username) {
            this.logger.warn('Skipping user with missing required attributes', { username });
            return undefined;
          }

          const groupsResponse = await this.cognitoClient.send(
            new AdminListGroupsForUserCommand({
              UserPoolId: this.userPoolId,
              Username: username,
            }),
          );

          const groups = groupsResponse.Groups?.flatMap((group) => (group.GroupName ? [group.GroupName] : [])) ?? [];
          const userType = this.determineUserType(groups);

          if (!userType) {
            this.logger.warn('Skipping user with no recognized groups', { username, groups });
            return undefined;
          }

          return { cognitoUser, email, invitedBy, userType };
        })
      ).filter((user): user is RecognizedCognitoUser => user !== undefined);

      const authorizationByEmail = await this.userAccountMappingRepository.findUserAuthorizations(
        recognizedUsers.filter((user) => user.userType !== 'admin').map((user) => user.email),
      );

      return recognizedUsers.map(({ cognitoUser, email, invitedBy, userType }) =>
        this.constructUserFromCognitoData(
          email,
          invitedBy,
          userType,
          cognitoUser.UserCreateDate,
          cognitoUser.UserStatus,
          authorizationByEmail.get(email.toLowerCase()),
        ),
      );
    } catch (error) {
      this.logger.error('Failed to retrieve users', {
        error: error instanceof Error ? error.message : String(error),
      });
      throw error;
    }
  }

  /**
   * Resolve whether a user exists in the pool and, if so, their ASR user type — using
   * ONLY Cognito (AdminGetUser + AdminListGroups), with no DynamoDB read.
   *
   * `getUserById` also reads the user's account/MCP-grant mapping from DynamoDB to build a
   * full `User`, which adds a DynamoDB dependency to any caller that only needs existence.
   * The federated pre-sign-up trigger is one such caller: it just needs to know the user
   * exists (and logs the type), so it must not fail sign-in on a transient DynamoDB blip in
   * a mapping read it never uses. Returns undefined when the user does not exist or carries
   * no recognized ASR group; a genuine Cognito failure still propagates.
   */
  async findUserTypeByEmail(userId: string): Promise<AsrUserType | undefined> {
    try {
      const response = await this.cognitoClient.send(
        new AdminGetUserCommand({ UserPoolId: this.userPoolId, Username: userId }),
      );
      const email = response.UserAttributes?.find((attr) => attr.Name === 'email')?.Value;
      const invitedBy = response.UserAttributes?.find((attr) => attr.Name === 'custom:invitedBy')?.Value;
      if (!email || !invitedBy) return undefined;

      const groupsResponse = await this.cognitoClient.send(
        new AdminListGroupsForUserCommand({ UserPoolId: this.userPoolId, Username: userId }),
      );
      const groups = groupsResponse.Groups?.flatMap((group) => (group.GroupName ? [group.GroupName] : [])) ?? [];
      // determineUserType returns null for no recognized group; normalize to undefined
      // to match this method's contract (a single "no ASR user type" sentinel).
      return this.determineUserType(groups) ?? undefined;
    } catch (error) {
      if (isUserNotFound(error)) return undefined;
      throw error;
    }
  }

  async getUserById(userId: string): Promise<User | null> {
    const cached = this.userCache.get(userId);
    if (cached) {
      return cached.user;
    }

    try {
      const response = await this.cognitoClient.send(
        new AdminGetUserCommand({
          UserPoolId: this.userPoolId,
          Username: userId,
        }),
      );

      const email = response.UserAttributes?.find((attr) => attr.Name === 'email')?.Value;
      const invitedBy = response.UserAttributes?.find((attr) => attr.Name === 'custom:invitedBy')?.Value;

      if (!email || !invitedBy) {
        this.userCache.set(userId, { user: null });
        return null;
      }

      const groupsResponse = await this.cognitoClient.send(
        new AdminListGroupsForUserCommand({
          UserPoolId: this.userPoolId,
          Username: userId,
        }),
      );

      const groups = groupsResponse.Groups?.map((group) => group.GroupName!) || [];
      const userType = this.determineUserType(groups);

      if (!userType) {
        this.userCache.set(userId, { user: null });
        return null;
      }

      const authorization =
        userType === 'admin' ? undefined : await this.userAccountMappingRepository.findUserAuthorization(email);
      const user = this.constructUserFromCognitoData(
        email,
        invitedBy,
        userType,
        response.UserCreateDate,
        response.UserStatus,
        authorization,
      );

      this.userCache.set(userId, { user });
      return user;
    } catch (error) {
      // Cache a negative result ONLY for a genuine "no such user". Any other
      // failure — notably a transient DynamoDB error from the findUserAuthorization
      // read above, or a Cognito throttle — must not be frozen into the cache as
      // user:null for the warm Lambda's lifetime, which would make a real, still-
      // existing user look permanently deleted. Rethrow those so the caller
      // surfaces a retryable error instead of a false 404.
      //
      // Not-found is recognized by the real Cognito exception name
      // (UserNotFoundException) or by an error whose message says the user was not
      // found, which is the not-found signal used throughout this service's tests
      // and callers. A transient failure matches neither.
      if (isUserNotFound(error)) {
        this.userCache.set(userId, { user: null });
        return null;
      }
      this.logger.error('Failed to retrieve user by ID', {
        userId,
        error: error instanceof Error ? error.message : String(error),
      });
      throw error;
    }
  }

  async getUserEmail(userId: string): Promise<{ email: string } | null> {
    try {
      const user = await this.getUserById(userId);
      const email = user?.email;

      if (!email) {
        this.logger.warn('User missing email attribute', { userId });
        return null;
      }

      return { email };
    } catch (error) {
      this.logger.error('Failed to retrieve user email by ID', {
        userId,
        userPoolId: this.userPoolId,
        error: error instanceof Error ? error.message : String(error),
      });
      return null;
    }
  }

  private constructUserFromCognitoData(
    email: string,
    invitedBy: string,
    userType: AsrUserType,
    userCreateDate?: Date,
    userStatus?: string,
    authorization?: UserAuthorizationData,
  ): User {
    const allowedMcpTools = userType === 'admin' ? undefined : (authorization?.allowedMcpTools ?? []);
    const baseUser = {
      email,
      invitedBy,
      invitationTimestamp: userCreateDate?.toISOString() || new Date().toISOString(),
      status: userStatus === 'CONFIRMED' ? ('Confirmed' as const) : ('Invited' as const),
      ...(allowedMcpTools ? { allowedMcpTools } : {}),
    };

    switch (userType) {
      case 'admin':
        return { ...baseUser, type: 'admin' } as AdminUser;
      case 'delegated-admin':
        return { ...baseUser, type: 'delegated-admin' } as DelegatedAdminUser;
      case 'account-operator':
        return {
          ...baseUser,
          type: 'account-operator',
          accountIds: authorization?.accountIds ?? [],
        } as AccountOperatorUser;
    }
  }

  private async listAllCognitoUsers(): Promise<CognitoUserType[]> {
    const users: CognitoUserType[] = [];
    let paginationToken: string | undefined;

    do {
      const response = await this.cognitoClient.send(
        new ListUsersCommand({
          UserPoolId: this.userPoolId,
          PaginationToken: paginationToken,
        }),
      );
      users.push(...(response.Users ?? []));
      paginationToken = response.PaginationToken;
    } while (paginationToken);

    return users;
  }

  async createUser(
    email: string,
    role: 'DelegatedAdmin' | 'AccountOperator',
    invitedBy: string,
    accountIds?: string[],
  ): Promise<void> {
    try {
      await this.cognitoClient.send(
        new AdminCreateUserCommand({
          UserPoolId: this.userPoolId,
          Username: email,
          UserAttributes: [
            { Name: 'email', Value: email },
            { Name: 'email_verified', Value: 'true' },
            { Name: 'custom:invitedBy', Value: invitedBy },
          ],
        }),
      );

      const groupName = role === 'DelegatedAdmin' ? 'DelegatedAdminGroup' : 'AccountOperatorGroup';

      await this.cognitoClient.send(
        new AdminAddUserToGroupCommand({
          UserPoolId: this.userPoolId,
          Username: email,
          GroupName: groupName,
        }),
      );

      if (role === 'AccountOperator' && accountIds) {
        await this.userAccountMappingRepository.create({
          userId: email,
          accountIds,
          invitedBy,
          invitationTimestamp: new Date().toISOString(),
        });
      }
    } catch (error) {
      this.logger.error('Failed to create user', {
        email,
        role,
        error: error instanceof Error ? error.message : String(error),
      });
      if (error instanceof UsernameExistsException)
        throw new BadRequestError(`User with username ${email} already exists.`);
      throw error;
    }
  }

  /**
   * Updates an account operator's account assignments and returns the account IDs the operator held
   * *before* the update. Callers use the returned previous assignment to reconcile downstream state
   * (e.g. notification configurations) for any accounts the operator no longer owns.
   */
  async updateAccountOperatorUser(userId: string, userData: Partial<AccountOperatorUser>): Promise<string[]> {
    const existingUser = await this.getUserById(userId);
    if (!existingUser) {
      throw new NotFoundError(`User ${userId} not found.`);
    }

    if (userData.type && existingUser.type !== userData.type) {
      throw new BadRequestError(
        'Requested user type does not match current type for the user. Modifying the user type is not currently supported.',
      );
    }

    if (userData.status && existingUser.status !== userData.status) {
      throw new BadRequestError(
        'Requested user status does not match current status for the user. Modifying the user status is not currently supported.',
      );
    }

    const previousAuthorization = await this.userAccountMappingRepository.findUserAuthorization(userId);
    const previousAccountIds = previousAuthorization?.accountIds ?? [];
    // Route the write through the repository's key-normalizing path rather than a
    // verbatim findById/put. The read-authorization path lowercases and migrates
    // the record, so a raw write on the mixed-case userId would land on a stale
    // duplicate while authorization kept reading the lowercase one — preserving
    // accounts this update was meant to revoke.
    await this.userAccountMappingRepository.setUserAccounts(userId, userData.accountIds ?? [], existingUser.invitedBy);
    this.userCache.delete(userId);
    return previousAccountIds;
  }

  /** Replace a Delegated Admin or Account Operator's MCP tool grant. */
  async updateUserMcpTools(userId: string, allowedTools: readonly string[]): Promise<void> {
    const existingUser = await this.getUserById(userId);
    if (!existingUser) {
      throw new NotFoundError(`User ${userId} not found.`);
    }
    if (existingUser.type === 'admin') {
      throw new BadRequestError('AdminGroup receives all MCP tools automatically and does not accept a tool grant.');
    }
    await this.userAccountMappingRepository.putUserAllowedMcpTools(existingUser.email, allowedTools);
    this.userCache.delete(userId);
  }

  async deleteUser(userId: string): Promise<void> {
    const user = await this.getUserById(userId);
    if (!user) {
      throw new NotFoundError(`User ${userId} not found.`);
    }

    await this.userAccountMappingRepository.deleteIfExists(userId, '');

    await this.cognitoClient.send(
      new AdminDeleteUserCommand({
        UserPoolId: this.userPoolId,
        Username: userId,
      }),
    );

    this.userCache.delete(userId);
  }

  async getProviderEmailAttributeName(providerName: string): Promise<string> {
    const describeProviderResponse = await this.cognitoClient.send(
      new DescribeIdentityProviderCommand({
        UserPoolId: this.userPoolId,
        ProviderName: providerName,
      }),
    );

    if (!describeProviderResponse?.IdentityProvider?.AttributeMapping) {
      this.logger.error(`Could not find attribute mapping object for provider ${providerName}`);
      throw new Error(`Could not find attribute mapping for provider ${providerName}`);
    }

    const emailAttributeName = describeProviderResponse.IdentityProvider.AttributeMapping.email;

    if (!emailAttributeName) {
      this.logger.error(
        `Could not find attribute mapping for email in provider ${providerName}. Ensure this provider is configured with an attribute mapping for the cognito email attribute.`,
      );
      throw new Error(
        `Could not find email attribute mapping for provider ${providerName}. Ensure you have configured an email attribute mapping for this provider.`,
      );
    }

    return emailAttributeName;
  }

  async linkFederatedUser(email: string, providerName: string): Promise<void> {
    const providerEmailAttributeName = await this.getProviderEmailAttributeName(providerName);
    await this.cognitoClient.send(
      new AdminLinkProviderForUserCommand({
        UserPoolId: this.userPoolId,
        DestinationUser: {
          ProviderName: 'Cognito',
          ProviderAttributeValue: email,
        },
        SourceUser: {
          ProviderName: providerName,
          ProviderAttributeName: providerEmailAttributeName,
          ProviderAttributeValue: email,
        },
      }),
    );

    this.logger.info('Linked federated user to existing user profile', { email, providerName });
  }

  private determineUserType(groups: string[]): 'admin' | 'delegated-admin' | 'account-operator' | null {
    if (groups.includes('AdminGroup')) {
      return 'admin';
    }
    if (groups.includes('DelegatedAdminGroup')) {
      return 'delegated-admin';
    }
    if (groups.includes('AccountOperatorGroup')) {
      return 'account-operator';
    }
    return null;
  }
}

async function mapWithConcurrency<T, R>(
  items: readonly T[],
  concurrency: number,
  mapper: (item: T) => Promise<R>,
): Promise<R[]> {
  const results: R[] = [];
  for (let start = 0; start < items.length; start += concurrency) {
    results.push(...(await Promise.all(items.slice(start, start + concurrency).map(mapper))));
  }
  return results;
}

/**
 * Whether an AdminGetUser failure means the user genuinely does not exist, as
 * opposed to a transient or unknown failure. Recognizes both the real Cognito
 * `UserNotFoundException` and an error whose message says the user was not found
 * — the latter is the not-found signal this service's callers and tests rely on.
 * A transient DynamoDB or throttling error matches neither, so it propagates
 * rather than being cached as a missing user.
 */
function isUserNotFound(error: unknown): boolean {
  if (!(error instanceof Error)) return false;
  return error.name === 'UserNotFoundException' || /user not found/i.test(error.message);
}
