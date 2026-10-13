// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { Logger } from '@aws-lambda-powertools/logger';
import { Tracer } from '@aws-lambda-powertools/tracer';
import { APIGatewayProxyEvent, APIGatewayProxyResult } from 'aws-lambda';
import {
  GenerateRunbookSchema,
  ListRunbooksSchema,
  GetRunbookSchema,
  ValidateRunbookSchema,
  DeployRunbookSchema,
  ExecuteRunbookSchema,
  GetExecutionStatusSchema,
  DriftDetectionSchema,
} from '@asr/data-models';
import { SCOPE_NAME } from '../../common/constants/apiConstant';
import { RunbookGenerationService } from '../services/runbookGenerationService';
import { RunbookValidationService } from '../services/runbookValidationService';
import { RunbookDeploymentService } from '../services/runbookDeploymentService';
import { DriftDetectionService } from '../services/driftDetectionService';
import { CustomRunbookQueryService } from '../services/customRunbookQueryService';
import { CustomRunbookExecutionService } from '../services/customRunbookExecutionService';
import { assertCustomRunbooksConfigured } from '../apiLambdaEnvironment';
import { API_HEADERS, createResponse } from './apiHandler';
import { BaseHandler, getClaims } from './baseHandler';
import { wrapWithMiddy } from './middyWrapper';
import {
  CONTROL_ID_DIMENSION,
  DEPLOY_RUNBOOK_PARTIAL_FAILURE_METRIC,
  emitMetric,
} from '../../common/utils/cloudWatchMetrics';
import type { DeployRunbookResult } from '@asr/data-models';

const logger = new Logger({ serviceName: SCOPE_NAME });
const tracer = new Tracer({ serviceName: SCOPE_NAME });
const baseHandler = new BaseHandler(logger);

const generationService = new RunbookGenerationService();
const validationService = new RunbookValidationService();
const deploymentService = new RunbookDeploymentService(logger);
const driftDetectionService = new DriftDetectionService(logger);
const queryService = new CustomRunbookQueryService(logger);
const executionService = new CustomRunbookExecutionService(logger);

// Use the shared BaseHandler access rules so these handlers inherit the same
// fail-closed validators as the rest of the API rather than re-declaring the
// group lists inline. createAdminOnlyAccessRules() denies Account Operators
// outright, which the runbook write paths need.
//
// The read paths admit Account Operators with no account narrowing because they
// return no per-account data: listRunbooks and getRunbook return
// RunbookMetadataSummary and the runbook's own YAML, and generate/validate work
// on caller-supplied YAML. A runbook is a solution-level object authored in the
// admin account. Its per-member deployment state does live on RunbookMetadata,
// keyed by account id, but no read path here exposes it. Narrowing would have to
// be added alongside any change that starts returning that state.
const ADMIN_ACCESS_RULES = baseHandler.createAdminOnlyAccessRules();
const READ_ACCESS_RULES = baseHandler.createAccessRules([]);

// --- Internal handler functions ---

async function generateRunbookHandler(event: APIGatewayProxyEvent): Promise<APIGatewayProxyResult> {
  await baseHandler.validateAccess(getClaims(event), READ_ACCESS_RULES);
  assertCustomRunbooksConfigured();
  const body = baseHandler.extractValidatedBody(event, GenerateRunbookSchema, 'Invalid generate_runbook input');
  const result = await generationService.getGenerationContext(body);
  return createResponse(200, result, API_HEADERS.RUNBOOKS);
}

async function listRunbooksHandler(event: APIGatewayProxyEvent): Promise<APIGatewayProxyResult> {
  await baseHandler.validateAccess(getClaims(event), READ_ACCESS_RULES);
  // No handler-level assertCustomRunbooksConfigured() here (unlike the
  // custom-only handlers): list_runbooks also serves the built-in ASR-* runbooks,
  // which must work on a deployment without the MCP blueprint. The service gates
  // only the custom-runbook code path — returning built-ins, and 501 only for an
  // explicit type=custom request when unconfigured.
  const body = baseHandler.extractValidatedBody(event, ListRunbooksSchema, 'Invalid list_runbooks input');
  const result = await queryService.listRunbooks(body);
  return createResponse(200, result, API_HEADERS.RUNBOOKS);
}

async function getRunbookHandler(event: APIGatewayProxyEvent): Promise<APIGatewayProxyResult> {
  await baseHandler.validateAccess(getClaims(event), READ_ACCESS_RULES);
  // No handler-level gate for the same reason as list_runbooks: get_runbook
  // resolves built-in ASR-* documents without custom-runbook storage. The service
  // reaches the custom-runbook table (and its 501 gate) only for custom ids.
  const body = baseHandler.extractValidatedBody(event, GetRunbookSchema, 'Invalid get_runbook input');
  const result = await queryService.getRunbook(body.runbook_id);
  return createResponse(200, result, API_HEADERS.RUNBOOKS);
}

async function validateRunbookHandler(event: APIGatewayProxyEvent): Promise<APIGatewayProxyResult> {
  await baseHandler.validateAccess(getClaims(event), READ_ACCESS_RULES);
  assertCustomRunbooksConfigured();
  const body = baseHandler.extractValidatedBody(event, ValidateRunbookSchema, 'Invalid validate_runbook input');
  const instructions = await validationService.getValidationInstructions();
  return createResponse(200, { runbook_yaml: body.runbook_yaml, instructions }, API_HEADERS.RUNBOOKS);
}

async function deployRunbookHandler(event: APIGatewayProxyEvent): Promise<APIGatewayProxyResult> {
  const authenticatedUser = await baseHandler.validateAccess(getClaims(event), ADMIN_ACCESS_RULES);
  assertCustomRunbooksConfigured();
  const body = baseHandler.extractValidatedBody(event, DeployRunbookSchema, 'Invalid deploy_runbook input');
  const result = await deploymentService.execute(body, authenticatedUser.email);

  // A `deploy` can succeed for the version metadata yet leave some member accounts failed —
  // role provisioning or document install threw for them, so the released version is not
  // running fleet-wide (version_consistency.consistent is false). Returning 200 for that made
  // a partial failure read as a clean success in both the REST write metrics and the MCP tool
  // metrics, which key on the status code. Return 207 and emit a failure metric so the partial
  // is observable. A `register` has no member rollout, so it is always 200.
  const failedAccounts = partiallyFailedAccounts(result);
  if (failedAccounts.length > 0) {
    emitMetric(DEPLOY_RUNBOOK_PARTIAL_FAILURE_METRIC, 1, [
      { name: CONTROL_ID_DIMENSION, value: result.control_id ?? 'unknown' },
    ]);
    logger.warn('Custom runbook deploy completed with member-account failures', {
      runbookId: result.runbook_id,
      version: result.version,
      controlId: result.control_id,
      failedAccounts,
    });
    return createResponse(207, result, API_HEADERS.RUNBOOKS);
  }

  return createResponse(200, result, API_HEADERS.RUNBOOKS);
}

/**
 * Member accounts a `deploy` could not fully release the version to — the union of role
 * provisioning and document-install failures. These are the accounts that make
 * `version_consistency.consistent` false; `accounts_pending_release` is deliberately excluded
 * because a staged-but-not-yet-released account is a backlog item, not a failure. Returns an
 * empty list for a `register` (no member rollout) or a clean deploy.
 */
function partiallyFailedAccounts(result: DeployRunbookResult): string[] {
  const failed = new Set<string>();
  for (const entry of result.role_provisioning?.failed ?? []) {
    failed.add(entry.accountId);
  }
  for (const entry of result.document_deployment?.failed ?? []) {
    failed.add(entry.accountId);
  }
  for (const accountId of result.version_consistency?.accounts_failed ?? []) {
    failed.add(accountId);
  }
  return [...failed];
}

async function executeRunbookHandler(event: APIGatewayProxyEvent): Promise<APIGatewayProxyResult> {
  const authenticatedUser = await baseHandler.validateAccess(getClaims(event), ADMIN_ACCESS_RULES);
  assertCustomRunbooksConfigured();
  const body = baseHandler.extractValidatedBody(event, ExecuteRunbookSchema, 'Invalid execute_runbook input');
  const result = await executionService.executeRunbook(
    body.finding_id,
    body.action_type,
    authenticatedUser.authorizedAccounts,
  );
  return createResponse(202, result, API_HEADERS.RUNBOOKS);
}

async function getExecutionStatusHandler(event: APIGatewayProxyEvent): Promise<APIGatewayProxyResult> {
  const authenticatedUser = await baseHandler.validateAccess(getClaims(event), READ_ACCESS_RULES);
  assertCustomRunbooksConfigured();
  const body = baseHandler.extractValidatedBody(event, GetExecutionStatusSchema, 'Invalid get_execution_status input');
  const result = await executionService.getExecutionStatus(body.finding_id, authenticatedUser.authorizedAccounts);
  return createResponse(200, result, API_HEADERS.RUNBOOKS);
}

async function driftDetectionHandler(event: APIGatewayProxyEvent): Promise<APIGatewayProxyResult> {
  const authenticatedUser = await baseHandler.validateAccess(getClaims(event), ADMIN_ACCESS_RULES);
  assertCustomRunbooksConfigured();
  const body = baseHandler.extractValidatedBody(event, DriftDetectionSchema, 'Invalid drift_detection input');

  if (body.action === 'push') {
    const result = await driftDetectionService.push(
      body.control_id,
      body.runbook_yaml,
      body.account_id,
      authenticatedUser.email,
    );
    return createResponse(200, result, API_HEADERS.RUNBOOKS);
  } else if (body.action === 'execute') {
    const result = await driftDetectionService.execute(
      body.control_id,
      body.account_id,
      body.finding_id,
      authenticatedUser.email,
    );
    return createResponse(200, result, API_HEADERS.RUNBOOKS);
  }
  const result = await driftDetectionService.status(body.execution_id, body.account_id);
  return createResponse(200, result, API_HEADERS.RUNBOOKS);
}

// --- Exported Lambda handlers with middy middleware ---

export const generateRunbook = wrapWithMiddy(generateRunbookHandler, logger, tracer);
export const listRunbooks = wrapWithMiddy(listRunbooksHandler, logger, tracer);
export const getRunbook = wrapWithMiddy(getRunbookHandler, logger, tracer);
export const validateRunbook = wrapWithMiddy(validateRunbookHandler, logger, tracer);
export const deployRunbook = wrapWithMiddy(deployRunbookHandler, logger, tracer);
export const executeRunbook = wrapWithMiddy(executeRunbookHandler, logger, tracer);
export const getExecutionStatus = wrapWithMiddy(getExecutionStatusHandler, logger, tracer);
export const driftDetection = wrapWithMiddy(driftDetectionHandler, logger, tracer);
