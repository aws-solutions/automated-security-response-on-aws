// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { Logger } from '@aws-lambda-powertools/logger';
import { injectLambdaContext } from '@aws-lambda-powertools/logger/middleware';
import { Tracer } from '@aws-lambda-powertools/tracer';
import { captureLambdaHandler } from '@aws-lambda-powertools/tracer/middleware';
import { APIGatewayProxyEvent, APIGatewayProxyResult, Context } from 'aws-lambda';
import { dynamicImport } from 'tsimportlib';
import { RemediationsRequestSchema, ExportRequestSchema } from '@asr/data-models';
import { RemediationService } from '../services/remediationService';
import { createResponse, API_HEADERS } from './apiHandler';
import { SCOPE_NAME } from '../../common/constants/apiConstant';
import { BaseHandler, CognitoClaims } from './baseHandler';

const logger = new Logger({ serviceName: SCOPE_NAME });
const tracer = new Tracer({ serviceName: SCOPE_NAME });
const remediationService = new RemediationService(logger);
const baseHandler = new BaseHandler(logger);

async function searchRemediationsHandler(event: APIGatewayProxyEvent): Promise<APIGatewayProxyResult> {
  const claims = event.requestContext?.authorizer?.claims as CognitoClaims;
  const remediationsRequest = baseHandler.extractValidatedBody(event, RemediationsRequestSchema);

  const requestedAccountIds = baseHandler.extractAccountIdsFromRequest(remediationsRequest);
  const authenticatedUser = await baseHandler.validateAccess(
    claims,
    baseHandler.createAccessRules(requestedAccountIds),
  );

  logger.debug('Searching remediations', {
    username: authenticatedUser.username,
    groups: authenticatedUser.groups,
    hasAuthorizedAccounts: !!authenticatedUser.authorizedAccounts,
  });

  const result = await remediationService.searchRemediations(authenticatedUser, remediationsRequest);

  return createResponse(200, result, API_HEADERS.REMEDIATIONS);
}

async function exportRemediationsHandler(event: APIGatewayProxyEvent): Promise<APIGatewayProxyResult> {
  logger.debug('Export remediations handler started', {
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

  const result = await remediationService.exportRemediationHistory(authenticatedUser, exportRequest);

  logger.debug('Export completed successfully', {
    username: authenticatedUser.username,
    hasDownloadUrl: !!result.downloadUrl,
  });

  return createResponse(200, result, API_HEADERS.REMEDIATIONS);
}

export const searchRemediations = async (
  event: APIGatewayProxyEvent,
  context: Context,
): Promise<APIGatewayProxyResult> => {
  const { default: middy } = (await dynamicImport('@middy/core', module)) as typeof import('@middy/core');
  const { default: httpJsonBodyParser } = (await dynamicImport(
    '@middy/http-json-body-parser',
    module,
  )) as typeof import('@middy/http-json-body-parser');

  const middlewareHandler = middy(searchRemediationsHandler)
    .use(httpJsonBodyParser())
    .use(injectLambdaContext(logger))
    .use(captureLambdaHandler(tracer));
  return middlewareHandler(event, context);
};

export const exportRemediations = async (
  event: APIGatewayProxyEvent,
  context: Context,
): Promise<APIGatewayProxyResult> => {
  const { default: middy } = (await dynamicImport('@middy/core', module)) as typeof import('@middy/core');
  const { default: httpJsonBodyParser } = (await dynamicImport(
    '@middy/http-json-body-parser',
    module,
  )) as typeof import('@middy/http-json-body-parser');

  const middlewareHandler = middy(exportRemediationsHandler)
    .use(httpJsonBodyParser())
    .use(injectLambdaContext(logger))
    .use(captureLambdaHandler(tracer));
  return middlewareHandler(event, context);
};
