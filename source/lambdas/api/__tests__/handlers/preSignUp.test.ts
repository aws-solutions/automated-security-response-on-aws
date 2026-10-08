// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { PreSignUpTriggerEvent } from 'aws-lambda';
import { preSignUpHandler } from '../../handlers/preSignUp';
import { mockClient } from 'aws-sdk-client-mock';
import {
  CognitoIdentityProviderClient,
  AdminGetUserCommand,
  AdminListGroupsForUserCommand,
  DescribeIdentityProviderCommand,
  AdminLinkProviderForUserCommand,
} from '@aws-sdk/client-cognito-identity-provider';
import { DynamoDBDocumentClient, GetCommand } from '@aws-sdk/lib-dynamodb';
import { DynamoDBTestSetup } from '../../../common/__tests__/dynamodbSetup';
import { userPoolId } from '../../../common/__tests__/envSetup';
import 'aws-sdk-client-mock-jest';

const mockCognitoClient = mockClient(CognitoIdentityProviderClient);
const mockDynamoClient = mockClient(DynamoDBDocumentClient);

describe('preSignUpHandler', () => {
  beforeEach(async () => {
    mockCognitoClient.reset();
    mockDynamoClient.reset();
    jest.clearAllMocks();
  });

  const createEvent = (
    triggerSource: string,
    userAttributes: Record<string, string> = {},
    userName = 'testuser',
  ): PreSignUpTriggerEvent => ({
    version: '1',
    region: 'us-east-1',
    userPoolId: userPoolId,
    userName,
    callerContext: {
      awsSdkVersion: '1.0.0',
      clientId: 'test-client-id',
    },
    triggerSource: triggerSource as any,
    request: {
      userAttributes,
      validationData: {},
      clientMetadata: {},
    },
    response: {
      autoConfirmUser: false,
      autoVerifyEmail: false,
      autoVerifyPhone: false,
    },
  });

  describe('PreSignUp_ExternalProvider', () => {
    it('should successfully handle external provider sign-up with existing user', async () => {
      // ARRANGE
      const event = createEvent('PreSignUp_ExternalProvider', { email: 'test@example.com' }, 'SAML_testuser');
      mockCognitoClient.on(AdminGetUserCommand).resolves({
        UserAttributes: [
          { Name: 'email', Value: 'test@example.com' },
          { Name: 'custom:invitedBy', Value: 'admin@example.com' },
        ],
        UserCreateDate: new Date('2023-01-01'),
        UserStatus: 'CONFIRMED',
      });
      mockCognitoClient.on(AdminListGroupsForUserCommand).resolves({ Groups: [{ GroupName: 'AdminGroup' }] });
      mockCognitoClient.on(DescribeIdentityProviderCommand).resolves({
        IdentityProvider: {
          AttributeMapping: { email: 'email' },
        },
      });
      mockCognitoClient.on(AdminLinkProviderForUserCommand).resolves({});

      // ACT
      const result = await preSignUpHandler(event);

      // ASSERT
      expect(mockCognitoClient).toHaveReceivedCommandWith(AdminGetUserCommand, {
        UserPoolId: userPoolId,
        Username: 'test@example.com',
      });
      expect(mockCognitoClient).toHaveReceivedCommandWith(AdminLinkProviderForUserCommand, {
        UserPoolId: userPoolId,
        DestinationUser: {
          ProviderName: 'Cognito',
          ProviderAttributeValue: 'test@example.com',
        },
        SourceUser: {
          ProviderName: 'SAML',
          ProviderAttributeName: 'email',
          ProviderAttributeValue: 'test@example.com',
        },
      });
      expect(result).toEqual(event);
    });

    it('links the federated user even when the account-mapping DynamoDB read would fail', async () => {
      // ARRANGE: this path only needs the user's existence and type, both resolved from
      // Cognito. It must NOT depend on the account/MCP-grant mapping in DynamoDB, so a
      // transient DynamoDB failure cannot reject a legitimate federated sign-in. Cognito
      // succeeds for a non-admin (account-operator) user — the tier that getUserById would
      // have followed with a DynamoDB authorization read — while every DynamoDB call fails.
      const event = createEvent('PreSignUp_ExternalProvider', { email: 'operator@example.com' }, 'SAML_testuser');
      mockCognitoClient.on(AdminGetUserCommand).resolves({
        UserAttributes: [
          { Name: 'email', Value: 'operator@example.com' },
          { Name: 'custom:invitedBy', Value: 'admin@example.com' },
        ],
        UserCreateDate: new Date('2023-01-01'),
        UserStatus: 'CONFIRMED',
      });
      mockCognitoClient.on(AdminListGroupsForUserCommand).resolves({ Groups: [{ GroupName: 'AccountOperatorGroup' }] });
      mockCognitoClient.on(DescribeIdentityProviderCommand).resolves({
        IdentityProvider: { AttributeMapping: { email: 'email' } },
      });
      mockCognitoClient.on(AdminLinkProviderForUserCommand).resolves({});
      // Any DynamoDB access would fail — the handler must never make one on this path.
      mockDynamoClient.on(GetCommand).rejects(new Error('DynamoDB unavailable'));

      // ACT
      const result = await preSignUpHandler(event);

      // ASSERT: the sign-in succeeds and the user is linked, unaffected by DynamoDB.
      expect(result).toEqual(event);
      expect(mockCognitoClient).toHaveReceivedCommand(AdminLinkProviderForUserCommand);
      expect(mockDynamoClient).not.toHaveReceivedCommand(GetCommand);
    });

    it('should reject external provider sign-up when user not found', async () => {
      // ARRANGE
      const event = createEvent('PreSignUp_ExternalProvider', { email: 'nonexistent@example.com' }, 'SAML_testuser');
      mockCognitoClient.on(AdminGetUserCommand).rejects(new Error('User not found'));

      // ACT & ASSERT
      await expect(preSignUpHandler(event)).rejects.toThrow('User not found in local user pool');
      expect(mockCognitoClient).toHaveReceivedCommandWith(AdminGetUserCommand, {
        UserPoolId: userPoolId,
        Username: 'nonexistent@example.com',
      });
      expect(mockCognitoClient).not.toHaveReceivedCommand(AdminLinkProviderForUserCommand);
    });

    it('should reject external provider sign-up when provider name cannot be extracted', async () => {
      // ARRANGE
      const event = createEvent('PreSignUp_ExternalProvider', { email: 'test@example.com' }, 'invalidusername');
      mockCognitoClient.on(AdminGetUserCommand).resolves({
        UserAttributes: [
          { Name: 'email', Value: 'test@example.com' },
          { Name: 'custom:invitedBy', Value: 'admin@example.com' },
        ],
        UserCreateDate: new Date('2023-01-01'),
        UserStatus: 'CONFIRMED',
      });
      mockCognitoClient.on(AdminListGroupsForUserCommand).resolves({ Groups: [{ GroupName: 'AdminGroup' }] });

      // ACT & ASSERT
      await expect(preSignUpHandler(event)).rejects.toThrow('No provider name found');
      expect(mockCognitoClient).not.toHaveReceivedCommand(AdminLinkProviderForUserCommand);
    });

    it('should reject external provider sign-up when provider name is empty', async () => {
      // ARRANGE
      const event = createEvent('PreSignUp_ExternalProvider', { email: 'test@example.com' }, '_testuser');
      mockCognitoClient.on(AdminGetUserCommand).resolves({
        UserAttributes: [
          { Name: 'email', Value: 'test@example.com' },
          { Name: 'custom:invitedBy', Value: 'admin@example.com' },
        ],
        UserCreateDate: new Date('2023-01-01'),
        UserStatus: 'CONFIRMED',
      });
      mockCognitoClient.on(AdminListGroupsForUserCommand).resolves({ Groups: [{ GroupName: 'AdminGroup' }] });

      // ACT & ASSERT
      await expect(preSignUpHandler(event)).rejects.toThrow('No provider name found');
      expect(mockCognitoClient).not.toHaveReceivedCommand(AdminLinkProviderForUserCommand);
    });

    it('should handle linkFederatedUser failure', async () => {
      // ARRANGE
      const event = createEvent('PreSignUp_ExternalProvider', { email: 'test1@example.com' }, 'SAML_testuser');
      mockCognitoClient.on(AdminGetUserCommand).resolves({
        UserAttributes: [
          { Name: 'email', Value: 'tes1t@example.com' },
          { Name: 'custom:invitedBy', Value: 'admin@example.com' },
        ],
        UserCreateDate: new Date('2023-01-01'),
        UserStatus: 'CONFIRMED',
      });
      mockCognitoClient.on(AdminListGroupsForUserCommand).resolves({ Groups: [{ GroupName: 'AdminGroup' }] });
      mockCognitoClient.on(DescribeIdentityProviderCommand).resolves({
        IdentityProvider: {
          AttributeMapping: { email: 'email' },
        },
      });
      const linkError = new Error('Link failed');
      mockCognitoClient.on(AdminLinkProviderForUserCommand).rejects(linkError);

      // ACT & ASSERT
      await expect(preSignUpHandler(event)).rejects.toThrow('Link failed');
      expect(mockCognitoClient).toHaveReceivedCommandWith(AdminGetUserCommand, {
        UserPoolId: userPoolId,
        Username: 'test1@example.com',
      });
      expect(mockCognitoClient).toHaveReceivedCommand(AdminLinkProviderForUserCommand);
    });
  });

  describe('PreSignUp_AdminCreateUser', () => {
    it('should allow admin-created user sign-up', async () => {
      // ARRANGE
      const event = createEvent('PreSignUp_AdminCreateUser', { email: 'admin@example.com' });

      // ACT
      const result = await preSignUpHandler(event);

      // ASSERT
      expect(mockCognitoClient).not.toHaveReceivedCommand(AdminGetUserCommand);
      expect(mockCognitoClient).not.toHaveReceivedCommand(AdminLinkProviderForUserCommand);
      expect(result).toEqual(event);
    });
  });

  describe('Email validation', () => {
    it('should reject sign-up with invalid email', async () => {
      // ARRANGE
      const event = createEvent('PreSignUp_ExternalProvider', { email: 'invalid-email' });

      // ACT
      await expect(preSignUpHandler(event)).rejects.toThrow('No valid email address found');
    });

    it('should reject sign-up with missing email attribute', async () => {
      // ARRANGE
      const event = createEvent('PreSignUp_ExternalProvider', {
        someAttribute: 'someAttributeValue',
      });

      // ACT & ASSERT
      await expect(preSignUpHandler(event)).rejects.toThrow(
        '"email" attribute not found in attribute mapping, please ensure you have setup an attribute mapping for "email" in your custom Cognito identity provider',
      );
      expect(mockCognitoClient).not.toHaveReceivedCommand(AdminGetUserCommand);
    });

    it('should reject sign-up with undefined email', async () => {
      // ARRANGE
      const event = createEvent('PreSignUp_ExternalProvider', { email: undefined as any });

      // ACT
      await expect(preSignUpHandler(event)).rejects.toThrow('No valid email address found');
    });

    it('should reject sign-up with empty string email', async () => {
      // ARRANGE
      const event = createEvent('PreSignUp_ExternalProvider', { email: '' });

      // ACT
      await expect(preSignUpHandler(event)).rejects.toThrow('No valid email address found');
    });
  });

  describe('Unsupported trigger sources', () => {
    it('should reject sign-up from unsupported trigger source', async () => {
      // ARRANGE
      const event = createEvent('PreSignUp_SignUp', { email: 'test@example.com' });

      // ACT
      await expect(preSignUpHandler(event)).rejects.toThrow('Sign-up not allowed from this source');
    });
  });

  describe('Error handling', () => {
    it('propagates a transient backend error rather than masking it as "user not found"', async () => {
      // ARRANGE: getUserById now rethrows a genuine backend failure instead of
      // swallowing it as null. A DynamoDB/Cognito blip during a federated sign-in
      // must surface as itself — masking it as "not found" would send an operator
      // chasing a nonexistent provisioning problem, and previously let a blip
      // masquerade as a definite "user not in pool" verdict.
      const event = createEvent('PreSignUp_ExternalProvider', { email: 'test2@example.com' }, 'SAML_testuser');
      const getUserError = new Error('Database error');
      mockCognitoClient.on(AdminGetUserCommand).rejects(getUserError);

      // ACT & ASSERT: sign-up still fails closed, but with the real cause.
      await expect(preSignUpHandler(event)).rejects.toThrow('Database error');
      expect(mockCognitoClient).toHaveReceivedCommandWith(AdminGetUserCommand, {
        UserPoolId: userPoolId,
        Username: 'test2@example.com',
      });
      expect(mockCognitoClient).not.toHaveReceivedCommand(AdminLinkProviderForUserCommand);
    });

    it('propagates a non-Error backend exception rather than masking it as "user not found"', async () => {
      // ARRANGE
      const event = createEvent('PreSignUp_ExternalProvider', { email: 'test3@example.com' }, 'SAML_testuser');
      const stringError = 'String error';
      mockCognitoClient.on(AdminGetUserCommand).rejects(stringError);

      // ACT & ASSERT
      await expect(preSignUpHandler(event)).rejects.toThrow('String error');
      expect(mockCognitoClient).toHaveReceivedCommandWith(AdminGetUserCommand, {
        UserPoolId: userPoolId,
        Username: 'test3@example.com',
      });
    });
  });
});
