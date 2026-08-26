// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { Logger } from '@aws-lambda-powertools/logger';
import { Tracer } from '@aws-lambda-powertools/tracer';
import { APIGatewayProxyEvent, APIGatewayProxyResult, Context } from 'aws-lambda';
import { CognitoService } from '../services/cognito';
import { captureLambdaHandler } from '@aws-lambda-powertools/tracer/middleware';
import { injectLambdaContext } from '@aws-lambda-powertools/logger/middleware';
import { createResponse, API_HEADERS } from './apiHandler';
import { dynamicImport } from 'tsimportlib';
import { AccountOperatorUser, InviteUserRequest, User, PutUserRequest } from '@asr/data-models';
import { BadRequestError, ForbiddenError, NotFoundError } from '../../common/utils/httpErrors';
import { z } from 'zod';
import { sendMetrics } from '../../common/utils/metricsUtils';
import { BaseHandler, CognitoClaims, AccessRule, getClaims } from './baseHandler';
import { AuthenticatedUser } from '../services/authorization';
import { NotificationConfigurationService } from '../services/notificationConfigurationService';

const logger = new Logger({ serviceName: 'UsersAPI' });
const tracer = new Tracer({ serviceName: 'UsersAPI' });
const cognitoService = new CognitoService(logger);
const notificationConfigService = new NotificationConfigurationService(logger);
const baseHandler = new BaseHandler(logger);

async function validateAccess(claims: CognitoClaims, rules: AccessRule) {
  return await baseHandler.validateAccess(claims, rules);
}

function createGetUsersAccessRules(userType?: string): AccessRule {
  return {
    requiredGroups: ['AdminGroup', 'DelegatedAdminGroup'],
    validator: (user, context) => {
      const groups = user.groups;
      const isAdmin = groups.includes('AdminGroup');
      const isDelegatedAdmin = groups.includes('DelegatedAdminGroup');

      if (isAdmin) return;

      if (!userType) {
        throw new ForbiddenError('Only Admins can access GET /users without "type" query parameter');
      }

      if (isDelegatedAdmin && userType !== 'accountOperators') {
        throw new ForbiddenError(
          'DelegatedAdminGroup can only fetch Account Operators. You must provide the "type" query parameter with value "accountOperators".',
        );
      }
    },
  };
}

// Base authorization gate for user management. Checked before any body parsing
// or user lookup so an unauthorized caller gets 403, not 400 or 404.
const USER_MANAGEMENT_GROUPS = ['AdminGroup', 'DelegatedAdminGroup'];

// A DelegatedAdmin may only act on AccountOperator users; an Admin is
// unrestricted. Applied after base authorization, using the already-
// authenticated caller (no re-authentication). Throws ForbiddenError when the
// scope is violated; otherwise returns the validated caller.
function validateDelegatedAdminOperatorScope(
  user: AuthenticatedUser,
  targetIsAccountOperator: boolean,
  verb: 'create' | 'update' | 'delete',
): AuthenticatedUser {
  if (user.groups.includes('AdminGroup')) {
    return user;
  }
  if (user.groups.includes('DelegatedAdminGroup') && !targetIsAccountOperator) {
    throw new ForbiddenError(`DelegatedAdminGroup can only ${verb} AccountOperator users`);
  }
  return user;
}

function filterUsersByType(users: User[], userType?: string): User[] {
  const userTypeToCognitoGroupName = {
    accountOperators: 'account-operator',
    delegatedAdmins: 'delegated-admin',
    admins: 'admin',
  };
  const userTypeAsKey = userType as keyof typeof userTypeToCognitoGroupName;

  if (userType && !userTypeToCognitoGroupName[userTypeAsKey]) {
    throw new BadRequestError(`Invalid user type: ${userType}`);
  }

  return userType ? users.filter((user) => user.type === userTypeToCognitoGroupName[userTypeAsKey]) : users;
}

async function getUsersHandler(event: APIGatewayProxyEvent, _: Context): Promise<APIGatewayProxyResult> {
  const userType = event.queryStringParameters?.type;
  const claims = getClaims(event);

  await validateAccess(claims, createGetUsersAccessRules(userType));
  const allUsers = await cognitoService.getAllUsers();
  const filteredUsers = filterUsersByType(allUsers, userType);

  logger.debug('Successfully retrieved users', { userCount: filteredUsers.length, userType });
  return createResponse(200, filteredUsers, API_HEADERS.USERS);
}

async function inviteUserHandler(event: APIGatewayProxyEvent, _: Context): Promise<APIGatewayProxyResult> {
  const claims = getClaims(event);

  // Authorize before parsing the body so an unauthorized caller gets 403, not 400.
  const authenticatedUser = await validateAccess(claims, { requiredGroups: USER_MANAGEMENT_GROUPS });

  const inviteUsersRequest = baseHandler.extractValidatedBody(event, InviteUserRequest);

  const { email, role, accountIds } = inviteUsersRequest;
  if (role === 'AccountOperator' && (!accountIds || !Array.isArray(accountIds) || accountIds.length === 0)) {
    throw new BadRequestError('accountIds is required for AccountOperator role');
  }

  validateDelegatedAdminOperatorScope(authenticatedUser, role === 'AccountOperator', 'create');

  await cognitoService.createUser(email, role, authenticatedUser.email, accountIds);

  await sendMetrics({ user_invitation: { user_type: role } });

  logger.debug('Successfully invited user', { email, role });
  return createResponse(201, { message: 'User invited successfully', email }, API_HEADERS.USERS);
}

async function putUserHandler(event: APIGatewayProxyEvent, _: Context): Promise<APIGatewayProxyResult> {
  const claims = getClaims(event);

  // Authorize before parsing the body so an unauthorized caller gets 403, not 400.
  const authenticatedUser = await validateAccess(claims, { requiredGroups: USER_MANAGEMENT_GROUPS });

  const userId = event.pathParameters?.id;
  if (!userId) {
    throw new BadRequestError('User ID is required');
  }

  const requestUserData = baseHandler.extractValidatedBody(event, PutUserRequest);

  validateDelegatedAdminOperatorScope(authenticatedUser, requestUserData.type === 'account-operator', 'update');

  if (requestUserData.type !== 'account-operator') {
    throw new BadRequestError('Only account-operator users can be updated');
  }

  if (userId !== requestUserData.email)
    throw new BadRequestError('You may not update the userId (email) of an existing user.');

  const accountOperatorData = requestUserData as Partial<AccountOperatorUser>;
  await cognitoService.updateAccountOperatorUser(userId, accountOperatorData);
  logger.debug('Successfully updated user', { userId });

  // Re-scope the operator's notification configs to their new account set so each config's delivery
  // scope stays in lockstep with the operator's access. The service owns the reconcile logic; the
  // handler only supplies the operator and their new accounts (undefined = accounts untouched).
  await notificationConfigService.reconcileOperatorAccountChange(userId, requestUserData.accountIds);

  return createResponse(200, { message: 'User updated successfully' }, API_HEADERS.USERS);
}

async function deleteUserHandler(event: APIGatewayProxyEvent, _: Context): Promise<APIGatewayProxyResult> {
  const claims = getClaims(event);

  // Authorize before validating the path or looking up the user so an
  // unauthorized caller gets 403, not 400 or 404.
  const authenticatedUser = await validateAccess(claims, { requiredGroups: USER_MANAGEMENT_GROUPS });

  const userId = event.pathParameters?.id;
  if (!userId || !z.string().email().safeParse(userId).success) {
    throw new BadRequestError('Valid email address is required for user ID');
  }
  const targetUser = await cognitoService.getUserById(userId);
  if (!targetUser) {
    throw new NotFoundError(`User ${userId} not found.`);
  }

  validateDelegatedAdminOperatorScope(authenticatedUser, targetUser.type === 'account-operator', 'delete');

  await cognitoService.deleteUser(userId);
  logger.info('Successfully deleted user', { userId });

  // Unsubscribe deleted user from all notification email topics
  await notificationConfigService.unsubscribeEmailFromAllConfigs(userId);

  // A deleted operator owns no accounts, so disable and de-scope every config they created.
  if (targetUser.type === 'account-operator') {
    await notificationConfigService.reconcileAfterOperatorDeletion(userId);
  }

  return createResponse(200, { message: 'User deleted successfully' }, API_HEADERS.USERS);
}

export const getUsers = async (event: APIGatewayProxyEvent, context: Context): Promise<APIGatewayProxyResult> => {
  const { default: middy } = (await dynamicImport('@middy/core', module)) as typeof import('@middy/core');

  const middlewareHandler = middy(getUsersHandler).use(injectLambdaContext(logger)).use(captureLambdaHandler(tracer));
  return middlewareHandler(event, context);
};

export const inviteUser = async (event: APIGatewayProxyEvent, context: Context): Promise<APIGatewayProxyResult> => {
  const { default: middy } = (await dynamicImport('@middy/core', module)) as typeof import('@middy/core');
  const { default: httpJsonBodyParser } = (await dynamicImport(
    '@middy/http-json-body-parser',
    module,
  )) as typeof import('@middy/http-json-body-parser');

  const middlewareHandler = middy(inviteUserHandler)
    .use(injectLambdaContext(logger))
    .use(captureLambdaHandler(tracer))
    .use(httpJsonBodyParser());
  return middlewareHandler(event, context);
};

export const putUser = async (event: APIGatewayProxyEvent, context: Context): Promise<APIGatewayProxyResult> => {
  const { default: middy } = (await dynamicImport('@middy/core', module)) as typeof import('@middy/core');
  const { default: httpJsonBodyParser } = (await dynamicImport(
    '@middy/http-json-body-parser',
    module,
  )) as typeof import('@middy/http-json-body-parser');
  const { default: httpUrlEncodePathParser } = (await dynamicImport(
    '@middy/http-urlencode-path-parser',
    module,
  )) as typeof import('@middy/http-urlencode-path-parser');

  const middlewareHandler = middy(putUserHandler)
    .use(injectLambdaContext(logger))
    .use(captureLambdaHandler(tracer))
    .use(httpJsonBodyParser())
    .use(httpUrlEncodePathParser());
  return middlewareHandler(event, context);
};

export const deleteUser = async (event: APIGatewayProxyEvent, context: Context): Promise<APIGatewayProxyResult> => {
  const { default: middy } = (await dynamicImport('@middy/core', module)) as typeof import('@middy/core');
  const { default: httpUrlEncodePathParser } = (await dynamicImport(
    '@middy/http-urlencode-path-parser',
    module,
  )) as typeof import('@middy/http-urlencode-path-parser');

  const middlewareHandler = middy(deleteUserHandler)
    .use(injectLambdaContext(logger))
    .use(captureLambdaHandler(tracer))
    .use(httpUrlEncodePathParser());
  return middlewareHandler(event, context);
};
