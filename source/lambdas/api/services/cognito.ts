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
} from '@aws-sdk/client-cognito-identity-provider';
import { UserAccountMappingRepository } from '../../common/repositories/userAccountMappingRepository';
import { createDynamoDBClient } from '../../common/utils/dynamodb';
import { AccountOperatorUser, AdminUser, DelegatedAdminUser, User } from '@asr/data-models';
import { BadRequestError, NotFoundError } from '../../common/utils/httpErrors';

export class CognitoService {
  private readonly cognitoClient: CognitoIdentityProviderClient;
  private readonly userPoolId: string;
  private readonly userAccountMappingRepository: UserAccountMappingRepository;
  private readonly userCache = new Map<string, { user: User | null }>();

  constructor(
    private readonly logger: Logger,
    userPoolId?: string,
  ) {
    this.cognitoClient = new CognitoIdentityProviderClient({});
    this.userPoolId = userPoolId ?? process.env.USER_POOL_ID!;
    this.userAccountMappingRepository = new UserAccountMappingRepository(
      'UsersAPI',
      process.env.USER_ACCOUNT_MAPPING_TABLE_NAME!,
      createDynamoDBClient({}),
    );
  }

  async getAllUsers(): Promise<User[]> {
    try {
      const response = await this.cognitoClient.send(
        new ListUsersCommand({
          UserPoolId: this.userPoolId,
        }),
      );

      const users: User[] = [];
      for (const cognitoUser of response?.Users || []) {
        const email = cognitoUser.Attributes?.find((attr) => attr.Name === 'email')?.Value;
        const invitedBy = cognitoUser.Attributes?.find((attr) => attr.Name === 'custom:invitedBy')?.Value;
        const username = cognitoUser.Username!;

        if (!email || !invitedBy) {
          this.logger.warn('Skipping user with missing required attributes', { username });
          continue;
        }

        const groupsResponse = await this.cognitoClient.send(
          new AdminListGroupsForUserCommand({
            UserPoolId: this.userPoolId,
            Username: username,
          }),
        );

        const groups = groupsResponse.Groups?.map((group) => group.GroupName!) || [];
        const userType = this.determineUserType(groups);

        if (!userType) {
          this.logger.warn('Skipping user with no recognized groups', { username, groups });
          continue;
        }

        const user = await this.constructUserFromCognitoData(
          email,
          invitedBy,
          userType,
          cognitoUser.UserCreateDate,
          cognitoUser.UserStatus,
        );
        if (user) {
          users.push(user);
        }
      }

      return users;
    } catch (error) {
      this.logger.error('Failed to retrieve users', {
        error: error instanceof Error ? error.message : String(error),
      });
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

      const user = await this.constructUserFromCognitoData(
        email,
        invitedBy,
        userType,
        response.UserCreateDate,
        response.UserStatus,
      );

      this.userCache.set(userId, { user });
      return user;
    } catch (error) {
      this.logger.error('Failed to retrieve user by ID', {
        userId,
        error: error instanceof Error ? error.message : String(error),
      });
      this.userCache.set(userId, { user: null });
      return null;
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

  private async constructUserFromCognitoData(
    email: string,
    invitedBy: string,
    userType: 'admin' | 'delegated-admin' | 'account-operator',
    userCreateDate?: Date,
    userStatus?: string,
  ): Promise<User> {
    const baseUser = {
      email,
      invitedBy,
      invitationTimestamp: userCreateDate?.toISOString() || new Date().toISOString(),
      status: userStatus === 'CONFIRMED' ? ('Confirmed' as const) : ('Invited' as const),
    };

    switch (userType) {
      case 'admin':
        return { ...baseUser, type: 'admin' } as AdminUser;
      case 'delegated-admin':
        return { ...baseUser, type: 'delegated-admin' } as DelegatedAdminUser;
      case 'account-operator': {
        const accountIds = (await this.userAccountMappingRepository.getUserAccounts(email)) ?? [];
        return { ...baseUser, type: 'account-operator', accountIds } as AccountOperatorUser;
      }
    }
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

  async updateAccountOperatorUser(userId: string, userData: Partial<AccountOperatorUser>): Promise<void> {
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

    const existingMapping = await this.userAccountMappingRepository.findById(userId, '');
    if (existingMapping) {
      await this.userAccountMappingRepository.put({
        ...existingMapping,
        accountIds: userData.accountIds ?? [],
      });
    } else {
      await this.userAccountMappingRepository.create({
        userId,
        accountIds: userData.accountIds ?? [],
        invitedBy: existingUser.invitedBy,
        invitationTimestamp: new Date().toISOString(),
      });
    }
    this.userCache.delete(userId);
  }

  async deleteUser(userId: string): Promise<void> {
    const user = await this.getUserById(userId);
    if (!user) {
      throw new NotFoundError(`User ${userId} not found.`);
    }

    if (user.type === 'account-operator') {
      await this.userAccountMappingRepository.deleteIfExists(userId, '');
    }

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
