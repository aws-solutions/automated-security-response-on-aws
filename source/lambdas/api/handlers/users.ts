// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { Logger } from '@aws-lambda-powertools/logger';
import { Tracer } from '@aws-lambda-powertools/tracer';
import { APIGatewayProxyEvent, APIGatewayProxyResult, Context } from 'aws-lambda';
import { CognitoService } from '../services/cognito';
import { captureLambdaHandler } from '@aws-lambda-powertools/tracer/middleware';
import { injectLambdaContext } from '@aws-lambda-powertools/logger/middleware';
import { createResponse } from './apiHandler';
import { dynamicImport } from 'tsimportlib';
import { AccountOperatorUser, InviteUserRequest, User, PutUserRequest } from '@asr/data-models';
import { BadRequestError, ForbiddenError, NotFoundError } from '../../common/utils/httpErrors';
import { z } from 'zod';
import { sendMetrics } from '../../common/utils/metricsUtils';
import { BaseHandler, CognitoClaims, AccessRule } from './baseHandler';
import { API_HEADERS } from './apiHandler';

const logger = new Logger({ serviceName: 'UsersAPI' });
const tracer = new Tracer({ serviceName: 'UsersAPI' });
const cognitoService = new CognitoService(logger);
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

function createInviteUserAccessRules(role?: string): AccessRule {
  return {
    requiredGroups: ['AdminGroup', 'DelegatedAdminGroup'],
    validator: (user, context) => {
      const groups = user.groups;
      const isAdmin = groups.includes('AdminGroup');
      const isDelegatedAdmin = groups.includes('DelegatedAdminGroup');

      if (isAdmin) return;

      if (isDelegatedAdmin && role !== 'AccountOperator') {
        throw new ForbiddenError('DelegatedAdminGroup can only create AccountOperator users');
      }
    },
  };
}

function createUpdateUserAccessRules(): AccessRule {
  return {
    requiredGroups: ['AdminGroup', 'DelegatedAdminGroup'],
  };
}

function createDeleteUserAccessRules(targetUserType?: string): AccessRule {
  return {
    requiredGroups: ['AdminGroup', 'DelegatedAdminGroup'],
    validator: (user, context) => {
      const groups = user.groups;
      const isAdmin = groups.includes('AdminGroup');
      const isDelegatedAdmin = groups.includes('DelegatedAdminGroup');

      if (isAdmin) return;

      if (isDelegatedAdmin && targetUserType !== 'account-operator') {
        throw new ForbiddenError('DelegatedAdminGroup can only delete AccountOperator users');
      }
    },
  };
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
  const claims = event.requestContext?.authorizer?.claims as CognitoClaims;

  await validateAccess(claims, createGetUsersAccessRules(userType));
  const allUsers = await cognitoService.getAllUsers();
  const filteredUsers = filterUsersByType(allUsers, userType);

  logger.debug('Successfully retrieved users', { userCount: filteredUsers.length, userType });
  return createResponse(200, filteredUsers, API_HEADERS.USERS);
}

async function inviteUserHandler(event: APIGatewayProxyEvent, _: Context): Promise<APIGatewayProxyResult> {
  const claims = event.requestContext?.authorizer?.claims as CognitoClaims;
  const inviteUsersRequest = baseHandler.extractValidatedBody(event, InviteUserRequest);

  const { email, role, accountIds } = inviteUsersRequest;
  if (role === 'AccountOperator' && (!accountIds || !Array.isArray(accountIds) || accountIds.length === 0)) {
    throw new BadRequestError('accountIds is required for AccountOperator role');
  }

  const authenticatedUser = await validateAccess(claims, createInviteUserAccessRules(role));

  await cognitoService.createUser(email, role, authenticatedUser.email, accountIds);

  await sendMetrics({ user_invitation: { user_type: role } });

  logger.debug('Successfully invited user', { email, role });
  return createResponse(201, { message: 'User invited successfully', email }, API_HEADERS.USERS);
}

async function putUserHandler(event: APIGatewayProxyEvent, _: Context): Promise<APIGatewayProxyResult> {
  const claims = event.requestContext?.authorizer?.claims as CognitoClaims;
  const userId = event.pathParameters?.id;
  if (!userId) {
    throw new BadRequestError('User ID is required');
  }

  const requestUserData = baseHandler.extractValidatedBody(event, PutUserRequest);

  if (requestUserData.type !== 'account-operator') {
    throw new BadRequestError('Only account-operator users can be updated');
  }

  if (userId !== requestUserData.email)
    throw new BadRequestError('You may not update the userId (email) of an existing user.');

  await validateAccess(claims, createUpdateUserAccessRules());

  const accountOperatorData = requestUserData as Partial<AccountOperatorUser>;
  await cognitoService.updateAccountOperatorUser(userId, accountOperatorData);
  logger.debug('Successfully updated user', { userId });
  return createResponse(200, { message: 'User updated successfully' }, API_HEADERS.USERS);
}

async function deleteUserHandler(event: APIGatewayProxyEvent, _: Context): Promise<APIGatewayProxyResult> {
  const claims = event.requestContext?.authorizer?.claims as CognitoClaims;
  const userId = event.pathParameters?.id;
  if (!userId || !z.string().email().safeParse(userId).success) {
    throw new BadRequestError('Valid email address is required for user ID');
  }
  const targetUser = await cognitoService.getUserById(userId);
  if (!targetUser) {
    throw new NotFoundError(`User ${userId} not found.`);
  }

  await validateAccess(claims, createDeleteUserAccessRules(targetUser.type));

  await cognitoService.deleteUser(userId);
  logger.info('Successfully deleted user', { userId });
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
