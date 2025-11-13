// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { PreSignUpTriggerEvent, Context, Callback } from 'aws-lambda';
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

describe('preSignUpHandler', () => {
  let mockCallback: jest.MockedFunction<Callback>;
  let mockContext: Context;

  beforeEach(async () => {
    mockCognitoClient.reset();
    jest.clearAllMocks();

    mockCallback = jest.fn();
    mockContext = {} as Context;
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
      await preSignUpHandler(event, mockContext, mockCallback);

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
      expect(mockCallback).toHaveBeenCalledWith(null, event);
    });

    it('should reject external provider sign-up when user not found', async () => {
      // ARRANGE
      const event = createEvent('PreSignUp_ExternalProvider', { email: 'nonexistent@example.com' }, 'SAML_testuser');
      mockCognitoClient.on(AdminGetUserCommand).rejects(new Error('User not found'));

      // ACT
      await preSignUpHandler(event, mockContext, mockCallback);

      // ASSERT
      expect(mockCognitoClient).toHaveReceivedCommandWith(AdminGetUserCommand, {
        UserPoolId: userPoolId,
        Username: 'nonexistent@example.com',
      });
      expect(mockCognitoClient).not.toHaveReceivedCommand(AdminLinkProviderForUserCommand);
      expect(mockCallback).toHaveBeenCalledWith(
        expect.objectContaining({ message: 'User not found in local user pool' }),
        event,
      );
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

      // ACT
      await preSignUpHandler(event, mockContext, mockCallback);

      // ASSERT
      expect(mockCognitoClient).not.toHaveReceivedCommand(AdminLinkProviderForUserCommand);
      expect(mockCallback).toHaveBeenCalledWith(expect.objectContaining({ message: 'No provider name found' }), event);
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

      // ACT
      await preSignUpHandler(event, mockContext, mockCallback);

      // ASSERT
      expect(mockCognitoClient).not.toHaveReceivedCommand(AdminLinkProviderForUserCommand);
      expect(mockCallback).toHaveBeenCalledWith(expect.objectContaining({ message: 'No provider name found' }), event);
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

      // ACT
      await preSignUpHandler(event, mockContext, mockCallback);

      // ASSERT
      expect(mockCognitoClient).toHaveReceivedCommandWith(AdminGetUserCommand, {
        UserPoolId: userPoolId,
        Username: 'test1@example.com',
      });
      expect(mockCognitoClient).toHaveReceivedCommand(AdminLinkProviderForUserCommand);
      expect(mockCallback).toHaveBeenCalledWith(linkError, event);
    });
  });

  describe('PreSignUp_AdminCreateUser', () => {
    it('should allow admin-created user sign-up', async () => {
      // ARRANGE
      const event = createEvent('PreSignUp_AdminCreateUser', { email: 'admin@example.com' });

      // ACT
      await preSignUpHandler(event, mockContext, mockCallback);

      // ASSERT
      expect(mockCognitoClient).not.toHaveReceivedCommand(AdminGetUserCommand);
      expect(mockCognitoClient).not.toHaveReceivedCommand(AdminLinkProviderForUserCommand);
      expect(mockCallback).toHaveBeenCalledWith(null, event);
    });
  });

  describe('Email validation', () => {
    it('should reject sign-up with invalid email', async () => {
      // ARRANGE
      const event = createEvent('PreSignUp_ExternalProvider', { email: 'invalid-email' });

      // ACT
      await preSignUpHandler(event, mockContext, mockCallback);

      // ASSERT
      expect(mockCognitoClient).not.toHaveReceivedCommand(AdminGetUserCommand);
      expect(mockCallback).toHaveBeenCalledWith(
        expect.objectContaining({ message: 'No valid email address found' }),
        event,
      );
    });

    it('should reject sign-up with missing email attribute', async () => {
      // ARRANGE
      const event = createEvent('PreSignUp_ExternalProvider', {
        someAttribute: 'someAttributeValue',
      });

      // ACT
      await preSignUpHandler(event, mockContext, mockCallback);

      // ASSERT
      expect(mockCognitoClient).not.toHaveReceivedCommand(AdminGetUserCommand);
      expect(mockCallback).toHaveBeenCalledWith(
        expect.objectContaining({
          message:
            '"email" attribute not found in attribute mapping, please ensure you have setup an attribute mapping for "email" in your custom Cognito identity provider',
        }),
        event,
      );
    });

    it('should reject sign-up with undefined email', async () => {
      // ARRANGE
      const event = createEvent('PreSignUp_ExternalProvider', { email: undefined as any });

      // ACT
      await preSignUpHandler(event, mockContext, mockCallback);

      // ASSERT
      expect(mockCognitoClient).not.toHaveReceivedCommand(AdminGetUserCommand);
      expect(mockCallback).toHaveBeenCalledWith(
        expect.objectContaining({ message: 'No valid email address found' }),
        event,
      );
    });

    it('should reject sign-up with empty string email', async () => {
      // ARRANGE
      const event = createEvent('PreSignUp_ExternalProvider', { email: '' });

      // ACT
      await preSignUpHandler(event, mockContext, mockCallback);

      // ASSERT
      expect(mockCognitoClient).not.toHaveReceivedCommand(AdminGetUserCommand);
      expect(mockCallback).toHaveBeenCalledWith(
        expect.objectContaining({ message: 'No valid email address found' }),
        event,
      );
    });
  });

  describe('Unsupported trigger sources', () => {
    it('should reject sign-up from unsupported trigger source', async () => {
      // ARRANGE
      const event = createEvent('PreSignUp_SignUp', { email: 'test@example.com' });

      // ACT
      await preSignUpHandler(event, mockContext, mockCallback);

      // ASSERT
      expect(mockCognitoClient).not.toHaveReceivedCommand(AdminGetUserCommand);
      expect(mockCallback).toHaveBeenCalledWith(
        expect.objectContaining({ message: 'Sign-up not allowed from this source' }),
        event,
      );
    });
  });

  describe('Error handling', () => {
    it('should handle getUserById error', async () => {
      // ARRANGE
      const event = createEvent('PreSignUp_ExternalProvider', { email: 'test2@example.com' }, 'SAML_testuser');
      const getUserError = new Error('Database error');
      mockCognitoClient.on(AdminGetUserCommand).rejects(getUserError);

      // ACT
      await preSignUpHandler(event, mockContext, mockCallback);

      // ASSERT
      expect(mockCognitoClient).toHaveReceivedCommandWith(AdminGetUserCommand, {
        UserPoolId: userPoolId,
        Username: 'test2@example.com',
      });
      expect(mockCognitoClient).not.toHaveReceivedCommand(AdminLinkProviderForUserCommand);
      expect(mockCallback).toHaveBeenCalledWith(new Error('User not found in local user pool'), event);
    });

    it('should handle non-Error exceptions', async () => {
      // ARRANGE
      const event = createEvent('PreSignUp_ExternalProvider', { email: 'test3@example.com' }, 'SAML_testuser');
      const stringError = 'String error';
      mockCognitoClient.on(AdminGetUserCommand).rejects(stringError);

      // ACT
      await preSignUpHandler(event, mockContext, mockCallback);

      // ASSERT
      expect(mockCognitoClient).toHaveReceivedCommandWith(AdminGetUserCommand, {
        UserPoolId: userPoolId,
        Username: 'test3@example.com',
      });
      expect(mockCallback).toHaveBeenCalledWith(new Error('User not found in local user pool'), event);
    });
  });
});
