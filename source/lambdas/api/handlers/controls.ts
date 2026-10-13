// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { Logger } from '@aws-lambda-powertools/logger';
import { injectLambdaContext } from '@aws-lambda-powertools/logger/middleware';
import { Tracer } from '@aws-lambda-powertools/tracer';
import { captureLambdaHandler } from '@aws-lambda-powertools/tracer/middleware';
import { APIGatewayProxyEvent, APIGatewayProxyResult, Context } from 'aws-lambda';
import { dynamicImport } from 'tsimportlib';
import {
  BulkEditRequest,
  BulkEditRequestSchema,
  BulkEditSuccessResponse,
  BulkEditPartialSuccessResponse,
} from '@asr/data-models';
import { SCOPE_NAME } from '../../common/constants/apiConstant';
import { BadRequestError, ConflictError } from '../../common/utils/httpErrors';
import { BulkUpdateResult, ControlsService } from '../services/controlsService';
import { API_HEADERS, createResponse } from './apiHandler';
import { BaseHandler, getClaims } from './baseHandler';

const logger = new Logger({ serviceName: SCOPE_NAME });
const tracer = new Tracer({ serviceName: SCOPE_NAME });
const baseHandler = new BaseHandler(logger);
const controlsService = new ControlsService(logger);

const PARTIAL_SUCCESS_MESSAGE = 'Some controls failed to update. Please refresh, review updated state, and try again.';
const CONFLICT_ERROR_MESSAGE =
  'All Controls failed to update. Data may have been modified or controls may not exist. Please refresh and try again.';
const CUSTOM_CONTROL_REJECTION_MESSAGE =
  'Automated remediation cannot be enabled for controls served by a custom runbook: custom runbooks run only on a manual trigger (Security Hub custom action or the API).';

const BULK_EDIT_SUCCESS_MESSAGES: Record<BulkEditRequest['operation'], string> = {
  update: 'Controls updated successfully',
  applyFilterToAll: 'Filter applied to all controls successfully',
  removeFilterFromAll: 'Filter removed from all controls successfully',
};

/**
 * The failure half of a bulk-edit message, composed from the kinds of failure actually
 * present.
 *
 * Two kinds with opposite advice: a version conflict is worth refreshing and retrying, and a
 * custom-runbook rejection is refused identically on every retry. Emitting the refresh advice
 * unconditionally told the caller to retry controls that can never succeed. The console
 * re-derives this split for its own notification, but nothing re-derives it for the MCP
 * `update_controls` tool, which receives this string verbatim — so the split has to be made
 * here.
 */
function bulkEditFailureDetail(retryableFailedIds: string[], rejectedControlIds: string[]): string {
  const parts: string[] = [];
  if (retryableFailedIds.length > 0) parts.push(PARTIAL_SUCCESS_MESSAGE);
  if (rejectedControlIds.length > 0) {
    parts.push(`${CUSTOM_CONTROL_REJECTION_MESSAGE} Controls: ${rejectedControlIds.join(', ')}.`);
  }
  return parts.join(' ');
}

function handleBulkUpdateResult(result: BulkUpdateResult, successMessage: string): APIGatewayProxyResult {
  const rejectedControlIds = result.rejectedControlIds ?? [];
  const retryableFailedIds = result.failedControlIds.filter((id) => !rejectedControlIds.includes(id));

  if (result.failedControlIds.length === 0) {
    const body: BulkEditSuccessResponse = { message: successMessage, updatedCount: result.successCount };
    return createResponse(200, body, API_HEADERS.CONTROLS);
  }

  if (result.successCount === 0) {
    // Nothing applied. When every failure is a structural rejection the request was simply
    // invalid, so it is a 400 naming the reason.
    if (retryableFailedIds.length === 0) {
      throw new BadRequestError(bulkEditFailureDetail(retryableFailedIds, rejectedControlIds));
    }
    // Otherwise at least one control lost a version check, which is a conflict — but a
    // rejection in the same batch still has to be reported, or the operator is told only to
    // refresh and retry a control that will be refused again.
    const conflictDetail = bulkEditFailureDetail([], rejectedControlIds);
    throw new ConflictError(conflictDetail ? `${CONFLICT_ERROR_MESSAGE} ${conflictDetail}` : CONFLICT_ERROR_MESSAGE);
  }

  const body: BulkEditPartialSuccessResponse = {
    message: bulkEditFailureDetail(retryableFailedIds, rejectedControlIds),
    successCount: result.successCount,
    failedControlIds: result.failedControlIds,
    ...(rejectedControlIds.length > 0 ? { rejectedControlIds } : {}),
  };
  return createResponse(207, body, API_HEADERS.CONTROLS);
}

async function getControlsHandler(event: APIGatewayProxyEvent): Promise<APIGatewayProxyResult> {
  const claims = getClaims(event);

  await baseHandler.validateAccess(claims, {
    requiredGroups: ['AdminGroup', 'DelegatedAdminGroup', 'AccountOperatorGroup'],
  });

  const result = await controlsService.getAllControls();

  return createResponse(200, result, API_HEADERS.CONTROLS);
}

async function bulkEditControlsHandler(event: APIGatewayProxyEvent): Promise<APIGatewayProxyResult> {
  const claims = getClaims(event);

  const user = await baseHandler.validateAccess(claims, {
    requiredGroups: ['AdminGroup', 'DelegatedAdminGroup'],
  });

  const body = baseHandler.extractValidatedBody<BulkEditRequest>(
    event,
    BulkEditRequestSchema,
    'Invalid bulk edit request',
  );

  const result = await controlsService.processBulkEdit(body, {
    actorEmail: user.email,
    actorGroups: user.groups,
  });

  return handleBulkUpdateResult(result, BULK_EDIT_SUCCESS_MESSAGES[body.operation]);
}

export const getControls = async (event: APIGatewayProxyEvent, context: Context): Promise<APIGatewayProxyResult> => {
  const { default: middy } = (await dynamicImport('@middy/core', module)) as typeof import('@middy/core');

  const middlewareHandler = middy(getControlsHandler)
    .use(injectLambdaContext(logger))
    .use(captureLambdaHandler(tracer));

  return middlewareHandler(event, context);
};

export const bulkEditControls = async (
  event: APIGatewayProxyEvent,
  context: Context,
): Promise<APIGatewayProxyResult> => {
  const { default: middy } = (await dynamicImport('@middy/core', module)) as typeof import('@middy/core');
  const { default: httpJsonBodyParser } = (await dynamicImport(
    '@middy/http-json-body-parser',
    module,
  )) as typeof import('@middy/http-json-body-parser');

  const middlewareHandler = middy(bulkEditControlsHandler)
    .use(injectLambdaContext(logger))
    .use(captureLambdaHandler(tracer))
    .use(httpJsonBodyParser());

  return middlewareHandler(event, context);
};
