// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { Logger } from '@aws-lambda-powertools/logger';
import { APIGatewayProxyEvent, APIGatewayProxyResult, Context } from 'aws-lambda';
import { dynamicImport } from 'tsimportlib';
import { BadRequestError, HttpError, NotFoundError, UnauthorizedError } from '../../common/utils/httpErrors';
import { executeFindingAction, exportFindings, searchFindings } from './findings';
import { exportRemediations, searchRemediations } from './remediations';
import { deleteUser, getUsers, inviteUser, putUser } from './users';

const logger = new Logger({ serviceName: 'ApiRouter' });

type ErrorWithStatusCode = Error & { statusCode?: number };
const ALLOWED_ORIGINS = [process.env.WEB_UI_URL!, 'http://localhost:3000'].filter(Boolean);

const BASE_CORS_HEADERS = {
  'Access-Control-Allow-Headers': 'Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token',
} as const;

export const API_HEADERS = {
  FINDINGS: {
    ...BASE_CORS_HEADERS,
    'Access-Control-Allow-Methods': 'GET,POST,OPTIONS',
  },
  REMEDIATIONS: {
    ...BASE_CORS_HEADERS,
    'Access-Control-Allow-Methods': 'GET,POST,OPTIONS',
  },
  USERS: {
    ...BASE_CORS_HEADERS,
    'Access-Control-Allow-Methods': 'GET,POST,PUT,DELETE,OPTIONS',
  },
} as const;

export function createResponse(statusCode: number, body: any, headers: Record<string, string>): APIGatewayProxyResult {
  return {
    statusCode,
    headers,
    body: JSON.stringify(body),
  };
}

function createErrorResponse(error: ErrorWithStatusCode, origin: string) {
  const isHttpError = error instanceof HttpError;
  return createResponse(
    isHttpError ? error.statusCode : 400,
    {
      error: isHttpError ? error.name : 'Error',
      message: isHttpError ? error.message : 'An unexpected error occurred.',
    },
    {
      ...BASE_CORS_HEADERS,
      'Access-Control-Allow-Origin': ALLOWED_ORIGINS.includes(origin) ? origin : ALLOWED_ORIGINS[0],
      'Content-Type': 'application/json',
    },
  );
}

const routes = [
  {
    method: 'GET',
    path: '/users',
    handler: getUsers,
  },
  {
    method: 'POST',
    path: '/users',
    handler: inviteUser,
  },
  {
    method: 'PUT',
    path: '/users/{id}',
    handler: putUser,
  },
  {
    method: 'DELETE',
    path: '/users/{id}',
    handler: deleteUser,
  },
  {
    method: 'POST',
    path: '/findings',
    handler: searchFindings,
  },
  {
    method: 'POST',
    path: '/findings/action',
    handler: executeFindingAction,
  },
  {
    method: 'POST',
    path: '/findings/export',
    handler: exportFindings,
  },
  {
    method: 'POST',
    path: '/remediations',
    handler: searchRemediations,
  },
  {
    method: 'POST',
    path: '/export',
    handler: exportRemediations,
  },
];

export const handler = async (event: APIGatewayProxyEvent, context: Context) => {
  const { default: middy } = (await dynamicImport('@middy/core', module)) as typeof import('@middy/core');
  const { default: httpHeaderNormalizer } = (await dynamicImport(
    '@middy/http-header-normalizer',
    module,
  )) as typeof import('@middy/http-header-normalizer');
  const { default: httpRouterHandler } = (await dynamicImport(
    '@middy/http-router',
    module,
  )) as typeof import('@middy/http-router');
  const { default: cors } = (await dynamicImport('@middy/http-cors', module)) as typeof import('@middy/http-cors');

  /**
   * middy middleware chain:
   * applies custom or prepackaged middlewares to each request and response.
   * - applies all applicable middlewares to the request from top to bottom,
   * - routes to a handler function determined by httpRouterHandler
   * - applies all applicable middlewares to the response from bottom to top
   * each middleware is an object that can have a "before" function applied to the request,
   * an "after" function applied to the response, and an "onError" function applied to the response.
   */
  const middlewareHandler = middy()
    .use(
      cors({
        headers: 'Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token',
        origins: ALLOWED_ORIGINS,
      }),
    )
    .use({
      before: (request) => {
        const { event } = request;

        logger.info('Processing API request', {
          method: event?.httpMethod,
          path: event?.path,
          requestId: request.context?.awsRequestId,
          userAgent: event.headers['user-agent'],
        });

        const headerKeys = Object.keys(event.headers).map((header) => header.toLowerCase());

        if (headerKeys.includes('x-amzn-requestid') || headerKeys.includes('x-amz-request-id'))
          throw new BadRequestError('X-Amzn-Requestid header is not allowed');

        const claims = event.requestContext?.authorizer?.claims;
        if (!claims) throw new UnauthorizedError('No authorization claims found');

        const missingClaims = [];
        if (!('cognito:groups' in claims)) missingClaims.push('cognito:groups');
        if (!('username' in claims)) missingClaims.push('username');

        if (missingClaims.length > 0) {
          logger.warn(`Missing required claims: ${missingClaims.join(', ')}`);
          throw new UnauthorizedError(`Could not read claims.`);
        }
      },
      onError: (request) => {
        const error = request.error as ErrorWithStatusCode;
        const origin = request.event.headers.origin;

        logger.error('API request failed', {
          method: request.event.httpMethod,
          path: request.event.path,
          errorName: error.name,
          errorMessage: error.message,
          statusCode: error.statusCode,
          stack: error.stack,
          requestId: request.context?.awsRequestId,
          userAgent: request.event.headers['user-agent'],
          origin: origin,
        });

        return createErrorResponse(error, origin);
      },
    })
    .use(httpHeaderNormalizer())
    .handler(
      httpRouterHandler({
        // @ts-expect-error - middy httpRouterHandler incorrectly throws a type error for `event`
        routes: routes,
        notFoundResponse: ({ method, path }) => {
          throw new NotFoundError(`Method ${method} with path ${path} not found.`);
        },
      }),
    );

  return middlewareHandler(event, context);
};
