// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { Logger } from '@aws-lambda-powertools/logger';
import { APIGatewayProxyEvent, APIGatewayProxyResult, Context } from 'aws-lambda';
import { dynamicImport } from 'tsimportlib';
import { BadRequestError, HttpError, NotFoundError, UnauthorizedError } from '../../common/utils/httpErrors';
import { bulkEditControls, getControls } from './controls';
import { createFilter, deleteFilter, getFilters, updateFilter } from './filters';
import { executeFindingAction, exportFindings, searchFindings } from './findings';
import { exportRemediations, searchRemediations } from './remediations';
import { deleteUser, getUsers, inviteUser, putUser } from './users';
import {
  createNotificationConfiguration,
  deleteNotificationConfiguration,
  getNotificationConfiguration,
  getNotificationConfigurations,
  toggleNotificationConfigurationStatus,
  updateNotificationConfiguration,
  getEmailSubscriptions,
  resendEmailConfirmation,
  testNotificationConfiguration,
} from './notifications';
import { getIaCTemplateContent } from './iacTemplateContent';
import { apiLambdaEnvironment } from '../apiLambdaEnvironment';
import { recordApiWriteMetrics } from '../rateLimiting/writeMetrics';

const env = apiLambdaEnvironment();
const logger = new Logger({ serviceName: 'ApiRouter' });

type ErrorWithStatusCode = Error & { statusCode?: number };
const ALLOWED_ORIGINS = [env.WEB_UI_URL, 'http://localhost:3000'].filter(Boolean);

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
  CONTROLS: {
    ...BASE_CORS_HEADERS,
    'Access-Control-Allow-Methods': 'GET,POST,OPTIONS',
  },
  FILTERS: {
    ...BASE_CORS_HEADERS,
    'Access-Control-Allow-Methods': 'GET,POST,PUT,DELETE,OPTIONS',
  },
  NOTIFICATIONS: {
    ...BASE_CORS_HEADERS,
    'Access-Control-Allow-Methods': 'GET,POST,PUT,PATCH,DELETE,OPTIONS',
  },
  IAC: {
    ...BASE_CORS_HEADERS,
    'Access-Control-Allow-Methods': 'GET,OPTIONS',
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

// Exported so the rate-limit tier map test (rateLimiting/routeTiers.test.ts)
// can assert every served route has a tier and vice versa. Keep exported.
export const routes = [
  {
    method: 'GET',
    path: '/controls',
    handler: getControls,
  },
  {
    method: 'POST',
    path: '/controls/bulk-edit',
    handler: bulkEditControls,
  },
  {
    method: 'GET',
    path: '/filters',
    handler: getFilters,
  },
  {
    method: 'POST',
    path: '/filters',
    handler: createFilter,
  },
  {
    method: 'PUT',
    path: '/filters/{filterId}',
    handler: updateFilter,
  },
  {
    method: 'DELETE',
    path: '/filters/{filterId}',
    handler: deleteFilter,
  },
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
  {
    method: 'GET',
    path: '/notifications',
    handler: getNotificationConfigurations,
  },
  {
    method: 'GET',
    path: '/notifications/{id}',
    handler: getNotificationConfiguration,
  },
  {
    method: 'POST',
    path: '/notifications',
    handler: createNotificationConfiguration,
  },
  {
    method: 'DELETE',
    path: '/notifications/{id}',
    handler: deleteNotificationConfiguration,
  },
  {
    method: 'PUT',
    path: '/notifications/{id}',
    handler: updateNotificationConfiguration,
  },
  {
    method: 'PATCH',
    path: '/notifications/{id}',
    handler: toggleNotificationConfigurationStatus,
  },
  {
    method: 'GET',
    path: '/notifications/{id}/subscriptions',
    handler: getEmailSubscriptions,
  },
  {
    method: 'POST',
    path: '/notifications/{id}/subscriptions/resend',
    handler: resendEmailConfirmation,
  },
  {
    method: 'POST',
    path: '/notifications/{id}/test',
    handler: testNotificationConfiguration,
  },
  {
    method: 'GET',
    path: '/iac/{findingId}',
    handler: getIaCTemplateContent,
  },
];

/**
 * middy middleware chain:
 * applies custom or prepackaged middlewares to each request and response.
 * - applies all applicable middlewares to the request from top to bottom,
 * - routes to a handler function determined by httpRouterHandler
 * - applies all applicable middlewares to the response from bottom to top
 * each middleware is an object that can have a "before" function applied to the request,
 * an "after" function applied to the response, and an "onError" function applied to the response.
 *
 * Lazily built once per Lambda container on the first request, then memoized.
 * Lazy (not module-load) so that Jest's vm sandbox doesn't trigger dynamicImport at import time.
 */
type MiddyHandler = (event: APIGatewayProxyEvent, context: Context) => Promise<APIGatewayProxyResult>;
let middlewareHandlerPromise: Promise<MiddyHandler> | undefined;

function getMiddlewareHandler(): Promise<MiddyHandler> {
  middlewareHandlerPromise ??= buildMiddyChain().catch((error) => {
    middlewareHandlerPromise = undefined;
    throw error;
  });
  return middlewareHandlerPromise;
}

async function buildMiddyChain(): Promise<MiddyHandler> {
  const [{ default: middy }, { default: httpHeaderNormalizer }, { default: httpRouterHandler }, { default: cors }] =
    await Promise.all([
      dynamicImport('@middy/core', module) as Promise<typeof import('@middy/core')>,
      dynamicImport('@middy/http-header-normalizer', module) as Promise<typeof import('@middy/http-header-normalizer')>,
      dynamicImport('@middy/http-router', module) as Promise<typeof import('@middy/http-router')>,
      dynamicImport('@middy/http-cors', module) as Promise<typeof import('@middy/http-cors')>,
    ]);

  const middyfied = middy()
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

        // Machine (client_credentials) tokens carry neither `cognito:groups` nor
        // `username` — their identity is the `client_id` (equal to `sub`). The
        // human-claims guard below would reject every such token before the route
        // authorizer's `tryResolveMachinePrincipal` ever runs, so skip it for them
        // and let AuthorizationService classify the token (full-access scope → grant,
        // otherwise fail closed). Mirrors the machine-token test in authorization.ts.
        const isMachineToken = !!claims.client_id && claims.sub === claims.client_id;
        if (!isMachineToken) {
          const missingClaims = [];
          if (!('cognito:groups' in claims)) missingClaims.push('cognito:groups');
          if (!('username' in claims)) missingClaims.push('username');

          if (missingClaims.length > 0) {
            logger.warn(`Missing required claims: ${missingClaims.join(', ')}`);
            throw new UnauthorizedError(`Could not read claims.`);
          }
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
    .use({
      // Record write-volume metrics for successful requests (anomaly alarms).
      // Runs only on the success path; failed requests take the onError path
      // and are intentionally not counted here.
      after: (request) => {
        try {
          const { event, response } = request;
          recordApiWriteMetrics(event.httpMethod, event.path, response?.statusCode ?? 0);
        } catch (error) {
          // Metrics must never break the request path, but log at debug so a
          // broken metrics pipeline is still observable to operators.
          logger.debug('Write metrics emission failed', { error });
        }
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

  return (event: APIGatewayProxyEvent, context: Context) => middyfied(event, context);
}

export const handler = async (event: APIGatewayProxyEvent, context: Context) => {
  const middlewareHandler = await getMiddlewareHandler();
  return middlewareHandler(event, context);
};
