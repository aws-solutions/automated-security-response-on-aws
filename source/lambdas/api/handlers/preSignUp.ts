// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { Logger } from '@aws-lambda-powertools/logger';
import { PreSignUpTriggerEvent, Context, Callback } from 'aws-lambda';
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
  callback: Callback,
): Promise<void> => {
  const cognitoService = new CognitoService(logger, event.userPoolId);

  const existingUser = await cognitoService.getUserById(userEmail);

  if (!existingUser) {
    logger.error('Rejecting federated sign-up - no matching user found', { email: userEmail });
    callback(new Error('User not found in local user pool'), event);
    return;
  }

  const providerName = extractProviderName(event.userName);
  if (!providerName) {
    logger.error(`Rejecting federated sign-up - could not extract provider name from user name ${event.userName}`);
    callback(new Error('No provider name found'), event);
    return;
  }

  await cognitoService.linkFederatedUser(userEmail, providerName);
  logger.info('Federated user linked to existing profile', {
    email: userEmail,
    existingUserType: existingUser.type,
  });
  callback(null, event);
};

export const preSignUpHandler = async (event: PreSignUpTriggerEvent, _: Context, callback: Callback): Promise<void> => {
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
      callback(
        new Error(
          '"email" attribute not found in attribute mapping, please ensure you have setup an attribute mapping for "email" in your custom Cognito identity provider',
        ),
        event,
      );
      return;
    }

    const userEmail = request.userAttributes.email;

    if (!validateEmail(userEmail)) {
      logger.error('Rejecting sign-up - no valid email found', { userAttributes: request.userAttributes });
      callback(new Error('No valid email address found'), event);
      return;
    }

    switch (triggerSource) {
      case 'PreSignUp_ExternalProvider':
        await handleExternalProvider(event, userEmail, callback);
        return;

      case 'PreSignUp_AdminCreateUser':
        logger.info('Admin-created user sign-up - passing through', { email: userEmail });
        callback(null, event);
        return;

      default:
        logger.error('Rejecting sign-up from unsupported trigger source', {
          triggerSource,
          email: userEmail,
        });
        callback(new Error('Sign-up not allowed from this source'), event);
    }
  } catch (error) {
    logger.error('Error in PreSignUp handler', {
      error: error instanceof Error ? error.message : String(error),
      triggerSource: event.triggerSource,
    });
    callback(error instanceof Error ? error : new Error(String(error)), event);
  }
};
