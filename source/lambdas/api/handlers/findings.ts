// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { Logger } from '@aws-lambda-powertools/logger';
import { injectLambdaContext } from '@aws-lambda-powertools/logger/middleware';
import { Tracer } from '@aws-lambda-powertools/tracer';
import { captureLambdaHandler } from '@aws-lambda-powertools/tracer/middleware';
import { APIGatewayProxyEvent, APIGatewayProxyResult, Context } from 'aws-lambda';
import { dynamicImport } from 'tsimportlib';
import { FindingsActionRequestSchema, FindingsRequestSchema, ExportRequestSchema } from '@asr/data-models';

import { SCOPE_NAME } from '../../common/constants/apiConstant';
import { FindingsService } from '../services/findingsService';
import { API_HEADERS, createResponse } from './apiHandler';
import { BaseHandler, CognitoClaims } from './baseHandler';

const logger = new Logger({ serviceName: SCOPE_NAME });
const tracer = new Tracer({ serviceName: SCOPE_NAME });
const findingsService = new FindingsService(logger);
const baseHandler = new BaseHandler(logger);

async function searchFindingsHandler(event: APIGatewayProxyEvent): Promise<APIGatewayProxyResult> {
  const claims = event.requestContext?.authorizer?.claims as CognitoClaims;
  const findingsRequest = baseHandler.extractValidatedBody(event, FindingsRequestSchema);

  const requestedAccountIds = baseHandler.extractAccountIdsFromRequest(findingsRequest);
  const authenticatedUser = await baseHandler.validateAccess(
    claims,
    baseHandler.createAccessRules(requestedAccountIds),
  );

  logger.debug('Searching findings', {
    username: authenticatedUser.username,
    groups: authenticatedUser.groups,
    hasAuthorizedAccounts: !!authenticatedUser.authorizedAccounts,
  });

  // Pass authenticated user to service layer for account filtering
  const result = await findingsService.searchFindings(authenticatedUser, findingsRequest);

  return createResponse(200, result, API_HEADERS.FINDINGS);
}

async function executeFindingActionHandler(event: APIGatewayProxyEvent): Promise<APIGatewayProxyResult> {
  const claims = event.requestContext?.authorizer?.claims as CognitoClaims;

  // Validate request body first to get finding IDs
  const actionRequest = baseHandler.extractValidatedBody(event, FindingsActionRequestSchema);

  const accountIds = baseHandler.extractAccountIdsFromArns(actionRequest.findingIds);
  const authenticatedUser = await baseHandler.validateAccess(claims, baseHandler.createAccessRules(accountIds));

  logger.debug('Executing finding action', {
    username: authenticatedUser.username,
    groups: authenticatedUser.groups,
    actionType: actionRequest.actionType,
    findingCount: actionRequest.findingIds.length,
  });

  await findingsService.executeAction(actionRequest, authenticatedUser.email);

  // Determine status code based on action type
  const getStatusCodeForAction = (actionType: string): number => {
    switch (actionType) {
      case 'Suppress':
      case 'Unsuppress':
        return 200;
      case 'Remediate':
      case 'RemediateAndGenerateTicket':
        return 202;
      default:
        return 202;
    }
  };

  const statusCode = getStatusCodeForAction(actionRequest.actionType);
  const responseBody =
    statusCode === 202 &&
    (actionRequest.actionType === 'Remediate' || actionRequest.actionType === 'RemediateAndGenerateTicket')
      ? { status: 'IN_PROGRESS' }
      : '';

  return createResponse(statusCode, responseBody, API_HEADERS.FINDINGS);
}

async function exportFindingsHandler(event: APIGatewayProxyEvent): Promise<APIGatewayProxyResult> {
  logger.debug('Export findings handler started', {
    httpMethod: event.httpMethod,
    path: event.path,
    hasBody: !!event.body,
  });

  const claims = event.requestContext?.authorizer?.claims as CognitoClaims;
  const exportRequest = baseHandler.extractValidatedBody(event, ExportRequestSchema);
  const requestedAccountIds = baseHandler.extractAccountIdsFromRequest(exportRequest);
  const authenticatedUser = await baseHandler.validateAccess(
    claims,
    baseHandler.createAccessRules(requestedAccountIds),
  );

  const result = await findingsService.exportFindings(authenticatedUser, exportRequest);

  logger.debug('Export completed successfully', {
    username: authenticatedUser.username,
    hasDownloadUrl: !!result.downloadUrl,
  });

  return createResponse(200, result, API_HEADERS.FINDINGS);
}

export const searchFindings = async (event: APIGatewayProxyEvent, context: Context): Promise<APIGatewayProxyResult> => {
  const { default: middy } = (await dynamicImport('@middy/core', module)) as typeof import('@middy/core');
  const { default: httpJsonBodyParser } = (await dynamicImport(
    '@middy/http-json-body-parser',
    module,
  )) as typeof import('@middy/http-json-body-parser');

  const middlewareHandler = middy(searchFindingsHandler)
    .use(httpJsonBodyParser())
    .use(injectLambdaContext(logger))
    .use(captureLambdaHandler(tracer));
  return middlewareHandler(event, context);
};

export const executeFindingAction = async (
  event: APIGatewayProxyEvent,
  context: Context,
): Promise<APIGatewayProxyResult> => {
  const { default: middy } = (await dynamicImport('@middy/core', module)) as typeof import('@middy/core');
  const { default: httpJsonBodyParser } = (await dynamicImport(
    '@middy/http-json-body-parser',
    module,
  )) as typeof import('@middy/http-json-body-parser');

  const middlewareHandler = middy(executeFindingActionHandler)
    .use(httpJsonBodyParser())
    .use(injectLambdaContext(logger))
    .use(captureLambdaHandler(tracer));
  return middlewareHandler(event, context);
};

export const exportFindings = async (event: APIGatewayProxyEvent, context: Context): Promise<APIGatewayProxyResult> => {
  const { default: middy } = (await dynamicImport('@middy/core', module)) as typeof import('@middy/core');
  const { default: httpJsonBodyParser } = (await dynamicImport(
    '@middy/http-json-body-parser',
    module,
  )) as typeof import('@middy/http-json-body-parser');

  const middlewareHandler = middy(exportFindingsHandler)
    .use(httpJsonBodyParser())
    .use(injectLambdaContext(logger))
    .use(captureLambdaHandler(tracer));
  return middlewareHandler(event, context);
};
