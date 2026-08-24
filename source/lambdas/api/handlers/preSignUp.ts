// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { Logger } from '@aws-lambda-powertools/logger';
import { PreSignUpTriggerEvent } from 'aws-lambda';
import { CognitoService } from '../services/cognito';
import { z } from 'zod';

const logger = new Logger({ serviceName: 'PreSignUpHandler' });

const validateEmail = (email: string | undefined): boolean => {
  return !!email && z.string().email().safeParse(email).success;
};

const extractProviderName = (userName: string): string | null => {
  const parts = userName.split('_');
  return parts.length > 1 ? parts[0] : null;
};

const handleExternalProvider = async (
  event: PreSignUpTriggerEvent,
  userEmail: string,
): Promise<PreSignUpTriggerEvent> => {
  const cognitoService = new CognitoService(logger, event.userPoolId);

  const existingUser = await cognitoService.getUserById(userEmail);

  if (!existingUser) {
    logger.error('Rejecting federated sign-up - no matching user found', { email: userEmail });
    throw new Error('User not found in local user pool');
  }

  const providerName = extractProviderName(event.userName);
  if (!providerName) {
    logger.error(`Rejecting federated sign-up - could not extract provider name from user name ${event.userName}`);
    throw new Error('No provider name found');
  }

  await cognitoService.linkFederatedUser(userEmail, providerName);
  logger.info('Federated user linked to existing profile', {
    email: userEmail,
    existingUserType: existingUser.type,
  });
  return event;
};

export const preSignUpHandler = async (event: PreSignUpTriggerEvent): Promise<PreSignUpTriggerEvent> => {
  try {
    logger.info('PreSignUp trigger invoked', {
      triggerSource: event.triggerSource,
      userPoolId: event.userPoolId,
      userName: event.userName,
    });

    const { triggerSource, request } = event;

    if (!('email' in request.userAttributes)) {
      logger.error('Rejecting sign-up - email attribute not found in userAttributes', {
        userAttributes: request.userAttributes,
      });
      throw new Error(
        '"email" attribute not found in attribute mapping, please ensure you have setup an attribute mapping for "email" in your custom Cognito identity provider',
      );
    }

    const userEmail = request.userAttributes.email;

    if (!validateEmail(userEmail)) {
      logger.error('Rejecting sign-up - no valid email found', { userAttributes: request.userAttributes });
      throw new Error('No valid email address found');
    }

    switch (triggerSource) {
      case 'PreSignUp_ExternalProvider':
        return await handleExternalProvider(event, userEmail);

      case 'PreSignUp_AdminCreateUser':
        logger.info('Admin-created user sign-up - passing through', { email: userEmail });
        return event;

      default:
        logger.error('Rejecting sign-up from unsupported trigger source', {
          triggerSource,
          email: userEmail,
        });
        throw new Error('Sign-up not allowed from this source');
    }
  } catch (error) {
    logger.error('Error in PreSignUp handler', {
      error: error instanceof Error ? error.message : String(error),
      triggerSource: event.triggerSource,
    });
    throw error;
  }
};
