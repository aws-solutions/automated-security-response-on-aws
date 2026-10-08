// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { Logger } from '@aws-lambda-powertools/logger';
import { injectLambdaContext } from '@aws-lambda-powertools/logger/middleware';
import { Tracer } from '@aws-lambda-powertools/tracer';
import { captureLambdaHandler } from '@aws-lambda-powertools/tracer/middleware';
import { APIGatewayProxyEvent, APIGatewayProxyResult, Context } from 'aws-lambda';
import { dynamicImport } from 'tsimportlib';
import {
  FindingId,
  FindingsActionRequest,
  FindingsActionRequestSchema,
  FindingsRequestSchema,
  ExportRequestSchema,
} from '@asr/data-models';

import { SCOPE_NAME } from '../../common/constants/apiConstant';
import { FindingsService } from '../services/findingsService';
import { API_HEADERS, createResponse } from './apiHandler';
import { BaseHandler, getClaims } from './baseHandler';
import { apiLambdaEnvironment } from '../apiLambdaEnvironment';

const logger = new Logger({ serviceName: SCOPE_NAME });
const tracer = new Tracer({ serviceName: SCOPE_NAME });
const findingsService = new FindingsService(logger);
const baseHandler = new BaseHandler(logger);

async function searchFindingsHandler(event: APIGatewayProxyEvent): Promise<APIGatewayProxyResult> {
  const claims = getClaims(event);
  const findingsRequest = baseHandler.extractValidatedBody(event, FindingsRequestSchema);

  const authenticatedUser = await baseHandler.validateAccess(
    claims,
    baseHandler.createRequestScopedAccessRules(findingsRequest),
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
  const claims = getClaims(event);

  // Validate request body first to get finding IDs
  const actionRequest = baseHandler.extractValidatedBody(event, FindingsActionRequestSchema);

  // Fetch the target findings once (read-only) and authorize against their
  // stored accountId, then act on the same records — no second DynamoDB read.
  const { findings, unresolvedIds } = await findingsService.fetchFindingsForAction(actionRequest);
  const accountIds = baseHandler.extractAccountIdsFromFindings(findings);

  if (actionRequest.actionType === 'Rollback' && apiLambdaEnvironment().ENABLE_ROLLBACK !== 'yes') {
    return createResponse(403, { message: 'Rollback feature is disabled' }, API_HEADERS.FINDINGS);
  }

  // Rollback weakens security posture — restrict to Admin and Delegated Admin only.
  // All other actions use the standard access rules (Admin, DelegatedAdmin, AccountOperator).
  const accessRules =
    actionRequest.actionType === 'Rollback'
      ? baseHandler.createAdminOnlyAccessRules()
      : baseHandler.createAccessRules(accountIds);

  const authenticatedUser = await baseHandler.validateAccess(claims, accessRules);

  logger.debug('Executing finding action', {
    username: authenticatedUser.username,
    groups: authenticatedUser.groups,
    actionType: actionRequest.actionType,
    findingCount: actionRequest.findingIds.length,
  });

  const skippedIds = await findingsService.executeActionOnFindings(actionRequest, findings, authenticatedUser.email);
  const allSkipped = [...unresolvedIds, ...skippedIds];
  const result = { unresolvedIds: allSkipped.length > 0 ? allSkipped : undefined };

  // Determine status code based on action type
  const getStatusCodeForAction = (actionType: string): number => {
    switch (actionType) {
      case 'Suppress':
      case 'Unsuppress':
        return 200;
      case 'Remediate':
      case 'RemediateAndGenerateTicket':
      case 'Rollback':
        return 202;
      default:
        return 202;
    }
  };

  const statusCode = getStatusCodeForAction(actionRequest.actionType);
  const responseBody = buildActionResponseBody(actionRequest.actionType, findings.length, result.unresolvedIds);

  return createResponse(statusCode, responseBody, API_HEADERS.FINDINGS);
}

/** Body of a 202 for an asynchronous action (Remediate / Rollback): the work has been handed off. */
interface AsyncActionResponseBody {
  status: 'IN_PROGRESS';
  /** Requested ids that could not be resolved to a finding; absent when every id resolved. */
  unresolvedIds?: FindingId[];
}

/** Body of a 200 for Suppress / Unsuppress, which complete inline. */
interface InlineActionResponseBody {
  status: 'SUPPRESSED' | 'UNSUPPRESSED';
  /** How many findings the action was applied to. */
  processedCount: number;
  unresolvedIds?: FindingId[];
}

export type FindingsActionResponseBody = AsyncActionResponseBody | InlineActionResponseBody;

/**
 * Shapes the body of a successful `POST /findings/action`.
 *
 * Remediate / Rollback are asynchronous, so they report `IN_PROGRESS`. Suppress / Unsuppress
 * complete inline, so they report a terminal status and the count of findings the action was
 * applied to — an empty body would leave a caller unable to tell how many were flipped and would
 * drop the `unresolvedIds` computed above. `unresolvedIds` is present only when non-empty,
 * matching the async shape; the WebUI reads it opportunistically for these actions.
 */
function buildActionResponseBody(
  actionType: FindingsActionRequest['actionType'],
  fetchedFindingCount: number,
  unresolvedIds: FindingId[] | undefined,
): FindingsActionResponseBody {
  const unresolved = unresolvedIds && unresolvedIds.length > 0 ? { unresolvedIds } : {};
  switch (actionType) {
    case 'Suppress':
    case 'Unsuppress':
      return {
        status: actionType === 'Suppress' ? 'SUPPRESSED' : 'UNSUPPRESSED',
        processedCount: fetchedFindingCount,
        ...unresolved,
      };
    default:
      return { status: 'IN_PROGRESS', ...unresolved };
  }
}

async function exportFindingsHandler(event: APIGatewayProxyEvent): Promise<APIGatewayProxyResult> {
  logger.debug('Export findings handler started', {
    httpMethod: event.httpMethod,
    path: event.path,
    hasBody: !!event.body,
  });

  const claims = getClaims(event);
  const exportRequest = baseHandler.extractValidatedBody(event, ExportRequestSchema);
  const authenticatedUser = await baseHandler.validateAccess(
    claims,
    baseHandler.createRequestScopedAccessRules(exportRequest),
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
