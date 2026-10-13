// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { z } from 'zod';
import { AdminGetUserCommand, CognitoIdentityProviderClient } from '@aws-sdk/client-cognito-identity-provider';
import { InvokeCommand, LambdaClient } from '@aws-sdk/client-lambda';
import type { APIGatewayProxyEvent } from 'aws-lambda';
import {
  GenerateRunbookSchema,
  ListRunbooksSchema,
  GetRunbookSchema,
  ValidateRunbookSchema,
  DeployRunbookSchema,
  ExecuteRunbookSchema,
  GetExecutionStatusSchema,
  DriftDetectionSchema,
  GetFindingHistorySchema,
  ListFindingsWithoutRunbookSchema,
  CheckDeployReadinessSchema,
  CreateFilterRequestSchema,
  FindingsRequestSchema,
  RemediationsRequestSchema,
  FindingsActionRequestSchema,
  CreateNotificationConfigurationRequestSchema,
  UpdateNotificationConfigurationRequestSchema,
  UpdateFilterRequestSchema,
} from '@asr/data-models';
import {
  TestRemediationScriptSchema,
  TestRunbookYamlSchema,
  CheckRunbookDriftSchema,
  testRemediationScript,
  testRunbookYaml,
  checkRunbookDrift,
  checkDeployReadiness,
  getFindingHistory,
  listFindingsWithoutRunbook,
} from './index';
import { UserAccountMappingRepository } from '../common/repositories/userAccountMappingRepository';
import { createDynamoDBClient } from '../common/utils/dynamodb';
import { readOptionalEnvironmentVariables } from '../common/utils/env-variables';
import { mcpServerEnvironment, mcpServerRuntimeEnvironment } from './mcpServerEnvironment';
import { UpdateControlsToolSchema, tierForGroups, toBulkEditApiBody } from './contract/toolContract';
import {
  assertAuthorized,
  assertRecognizedPrincipal,
  CallerIdentity,
  extractBearerToken,
  extractCallerIdentity,
  ForbiddenError,
} from './cognitoAuthorizer';
import type { ExecutionContext } from './backends/types';
import {
  AccountAuthorizationError,
  MissingParameterError,
  PathContainmentError,
  ValidationError,
} from './backends/common/errors';
import { BadRequestError, HttpError, ServiceUnavailableError } from '../common/utils/httpErrors';
import { getLogger } from '../common/utils/logger';
import { verifyAccessToken } from './tokenVerifier';
import {
  emitMetric,
  MCP_TOOL_ERROR_METRIC,
  MCP_TOOL_INVOCATION_METRIC,
  MCP_TOOL_LATENCY_METRIC,
  MCP_TOOL_NAME_DIMENSION,
} from '../common/utils/cloudWatchMetrics';

// --- AgentCore Gateway types ---

interface AgentCoreEvent {
  [key: string]: unknown;
}

interface AgentCoreContext {
  clientContext: {
    custom: {
      bedrockAgentCoreToolName: string;
      bedrockAgentCoreTargetId: string;
      bedrockAgentCoreGatewayId: string;
      bedrockAgentCoreMcpMessageId: string;
      bedrockAgentCoreAwsRequestId: string;
      bedrockAgentCoreMessageVersion: string;
    };
  };
  awsRequestId: string;
  /** This function's own ARN — the trustworthy source of the account it is running in. */
  invokedFunctionArn: string;
}

interface ToolResponse {
  statusCode: number;
  headers?: Record<string, string>;
  body: string;
}

// --- Tool routing for proxied tools (all routed to the ASR API Lambda) ---

// Tool-input schemas for governance tools whose API route takes no body (GET lists)
// or carries a path id. The proxy strips the id into the URL and forwards the
// remaining arguments as the request body.
const NoArgsSchema = z.object({});

// Delete and test take nothing but the id, so allowing unknown fields costs nothing here.
const FilterIdSchema = z.looseObject({ filterId: z.string().min(1) });
/**
 * The REST route names the path parameter `id`, but every notification record — as returned
 * by `create_notification` and `list_notifications` — carries it as `configId`. Without the
 * description an agent has no way to learn that the two are the same value.
 */
const NOTIFICATION_ID_DESCRIPTION =
  'The notification configuration id: the `configId` value returned by create_notification / list_notifications.';
const NotificationIdSchema = z.looseObject({
  id: z.string().min(1).describe(NOTIFICATION_ID_DESCRIPTION),
});

/**
 * The update tools advertise their full request body rather than relying on
 * passthrough.
 *
 * Passthrough was the original design — keep the API Lambda as the single
 * validator of the body and let anything through here. It does not survive the
 * gateway: Zod renders `.passthrough()` as `additionalProperties: {}` in
 * `toolSchema.json`, and AgentCore drops that keyword when it registers the tool.
 * What clients then receive is a closed schema naming one property, the id. A
 * client that builds arguments from the advertised schema — which is every MCP
 * client — can send nothing else, and both routes replace the whole record and
 * reject a call without it. Both tools were therefore uncallable over MCP.
 *
 * Naming the body here is not duplicated validation: this is what makes the
 * contract self-describing, and the API Lambda still validates what arrives. It
 * also does not depend on how AgentCore treats `additionalProperties`.
 */
const UpdateFilterToolSchema = UpdateFilterRequestSchema.and(z.object({ filterId: z.string().min(1) }));
const UpdateNotificationToolSchema = UpdateNotificationConfigurationRequestSchema.and(
  z.object({ id: z.string().min(1).describe(NOTIFICATION_ID_DESCRIPTION) }),
);

/**
 * A proxied tool forwards to the ASR API Lambda. `method` defaults to POST (the
 * runbook-lifecycle routes). `pathParam` names the single argument that fills a
 * `{param}` token in `path`; the proxy substitutes it into the URL and forwards the
 * remaining arguments as the request body, so the API router matches the concrete
 * route and its handler reads the path id. `toApiBody`, when present, reshapes the
 * validated arguments into the body the API expects — for tools whose MCP-facing input
 * deliberately differs from the API request (see `UpdateControlsToolSchema`).
 */
type ProxiedRoute<TArgs = unknown> = {
  schema: z.ZodSchema<TArgs>;
  path: string;
  method?: 'GET' | 'POST' | 'PUT' | 'DELETE';
  pathParam?: string;
  toApiBody?: (args: TArgs) => unknown;
};

/** Pins `toApiBody`'s parameter to the schema's output type at the definition site. */
function defineProxiedRoute<TArgs>(route: ProxiedRoute<TArgs>): ProxiedRoute {
  return route as ProxiedRoute;
}

const PROXIED_TOOL_ROUTES: Record<string, ProxiedRoute> = {
  generate_runbook: { schema: GenerateRunbookSchema, path: '/runbooks/generate' },
  list_runbooks: { schema: ListRunbooksSchema, path: '/runbooks/list' },
  get_runbook: { schema: GetRunbookSchema, path: '/runbooks/get' },
  validate_runbook: { schema: ValidateRunbookSchema, path: '/runbooks/validate' },
  deploy_runbook: { schema: DeployRunbookSchema, path: '/runbooks/deploy' },
  execute_runbook: { schema: ExecuteRunbookSchema, path: '/runbooks/execute' },
  get_execution_status: { schema: GetExecutionStatusSchema, path: '/runbooks/execution-status' },
  drift_detection: { schema: DriftDetectionSchema, path: '/runbooks/drift-detection' },

  // --- Governance tools (Admin UI parity) — backed by existing API endpoints ---
  // Controls
  list_controls: { schema: NoArgsSchema, path: '/controls', method: 'GET' },
  update_controls: defineProxiedRoute({
    schema: UpdateControlsToolSchema,
    path: '/controls/bulk-edit',
    method: 'POST',
    toApiBody: toBulkEditApiBody,
  }),
  // Filters
  list_filters: { schema: NoArgsSchema, path: '/filters', method: 'GET' },
  create_filter: { schema: CreateFilterRequestSchema, path: '/filters', method: 'POST' },
  update_filter: {
    schema: UpdateFilterToolSchema,
    path: '/filters/{filterId}',
    method: 'PUT',
    pathParam: 'filterId',
  },
  delete_filter: { schema: FilterIdSchema, path: '/filters/{filterId}', method: 'DELETE', pathParam: 'filterId' },
  // Findings & reporting
  findings: { schema: FindingsRequestSchema, path: '/findings', method: 'POST' },
  remediations: { schema: RemediationsRequestSchema, path: '/remediations', method: 'POST' },
  execute_finding_action: { schema: FindingsActionRequestSchema, path: '/findings/action', method: 'POST' },
  // Notifications
  list_notifications: { schema: NoArgsSchema, path: '/notifications', method: 'GET' },
  create_notification: {
    schema: CreateNotificationConfigurationRequestSchema,
    path: '/notifications',
    method: 'POST',
  },
  update_notification: {
    schema: UpdateNotificationToolSchema,
    path: '/notifications/{id}',
    method: 'PUT',
    pathParam: 'id',
  },
  delete_notification: {
    schema: NotificationIdSchema,
    path: '/notifications/{id}',
    method: 'DELETE',
    pathParam: 'id',
  },
  test_notification: {
    schema: NotificationIdSchema,
    path: '/notifications/{id}/test',
    method: 'POST',
    pathParam: 'id',
  },
};

// Direct-execution tools — run AWS SDK calls within this Lambda (no API Gateway proxy).
const logger = getLogger('McpServer');

// The executionContext is the executors' own ExecutionContext (backends/types.ts), referenced directly
// rather than re-declared, so a field the executors rely on — notably authorizedAccountIds,
// which scopes the direct Security Hub tools to a caller's accounts — cannot be dropped from
// this contract without a compile error.
type DirectExecutor = (args: unknown, executionContext: ExecutionContext) => Promise<unknown>;

interface DirectToolRoute {
  readonly schema: z.ZodSchema;
  readonly execute: DirectExecutor;
}

/**
 * Pair a tool's input schema with the executor that consumes it.
 *
 * The generic ties the executor's argument type to the schema's inferred output, so
 * pairing a tool with an executor expecting different params is a compile error.
 * Writing each entry as `execute: someExecutor as DirectExecutor` silenced precisely
 * that check (ADR 0001): the schema and the executor could drift apart and nothing
 * failed until the tool was invoked in production.
 *
 * The one cast inside is the deliberate erasure of that — now verified — relationship.
 * The route table is heterogeneous, so it can only store the widened `unknown`-args
 * signature; the handler parses arguments with this same schema before dispatching, so
 * the value the executor receives really is `z.infer<Schema>`.
 */
function defineDirectRoute<Schema extends z.ZodTypeAny>(
  schema: Schema,
  execute: (args: z.infer<Schema>, executionContext: ExecutionContext) => Promise<unknown>,
): DirectToolRoute {
  return { schema, execute: execute as DirectExecutor };
}

const DIRECT_TOOL_ROUTES: Record<string, DirectToolRoute> = {
  test_remediation_script: defineDirectRoute(TestRemediationScriptSchema, testRemediationScript),
  test_runbook_yaml: defineDirectRoute(TestRunbookYamlSchema, testRunbookYaml),
  check_runbook_drift: defineDirectRoute(CheckRunbookDriftSchema, checkRunbookDrift),
  check_deploy_readiness: defineDirectRoute(CheckDeployReadinessSchema, checkDeployReadiness),
  get_finding_history: defineDirectRoute(GetFindingHistorySchema, getFindingHistory),
  list_findings_without_runbook: defineDirectRoute(ListFindingsWithoutRunbookSchema, listFindingsWithoutRunbook),
};

/**
 * The input schema each tool actually validates, keyed by tool name.
 *
 * Exported so `toolSchema.json` — what the AgentCore Gateway advertises to clients — can be
 * generated from it instead of hand-maintained. They had drifted badly: 9 tools advertised
 * no inputs at all while validating required ones here, which made them impossible to call.
 * `execute_finding_action` was among them, so the Rollback capability could not be invoked
 * over MCP even though it was advertised.
 *
 * This Lambda is the authority: it is what rejects a malformed call, so advertising anything
 * else guarantees either a silently stripped field or an unsatisfiable required one.
 */
export const TOOL_INPUT_SCHEMAS: Readonly<Record<string, z.ZodSchema>> = Object.freeze({
  ...Object.fromEntries(Object.entries(PROXIED_TOOL_ROUTES).map(([name, route]) => [name, route.schema])),
  ...Object.fromEntries(Object.entries(DIRECT_TOOL_ROUTES).map(([name, route]) => [name, route.schema])),
});

const apiLambdaClient = new LambdaClient({});
const cognitoClient = new CognitoIdentityProviderClient({});
const API_LAMBDA_RESPONSE_SCHEMA = z.object({
  statusCode: z.number().int().min(100).max(599),
  body: z.string(),
});
const AUTHORIZATION_ARGUMENT = '__authorizationHeader';

/**
 * Host-set variables that the CDK does not provision. They are read from the host's own
 * environment rather than the typed CDK config because they exist only for local runs:
 * `ASR_WORKSPACE_ROOT` points at a source checkout, which the deployed Lambda never has.
 * Absent in the deployed Lambda, so every consumer must treat it as optional.
 */
interface HandlerHostEnvironment {
  readonly ASR_WORKSPACE_ROOT?: string;
}

const HANDLER_HOST_ENVIRONMENT_KEYS = ['ASR_WORKSPACE_ROOT'] as const;

function getHandlerHostEnvironment(): HandlerHostEnvironment {
  return readOptionalEnvironmentVariables(HANDLER_HOST_ENVIRONMENT_KEYS);
}

// --- Per-client tool allowlist lookup ---

let userAuthorizationRepository: UserAccountMappingRepository | undefined;

function getUserAuthorizationRepository(tableName: string): UserAccountMappingRepository {
  if (!userAuthorizationRepository) {
    userAuthorizationRepository = new UserAccountMappingRepository(
      'McpServerHandler',
      tableName,
      createDynamoDBClient({}),
    );
  }
  return userAuthorizationRepository;
}

/**
 * Read a Delegated Admin or Account Operator's email-keyed MCP grant. AdminGroup
 * does not call this path because it receives every tool automatically.
 * Repository failures surface as a retryable 503 and never widen access.
 */
async function resolveUserAllowedTools(email: string): Promise<readonly string[] | undefined> {
  const tableName = mcpServerEnvironment().USER_ACCOUNT_MAPPING_TABLE_NAME;
  if (!tableName) {
    throw new ServiceUnavailableError('User MCP authorization storage is not configured, so this call is denied.');
  }

  try {
    return await getUserAuthorizationRepository(tableName).findUserAllowedMcpTools(email);
  } catch (err) {
    logger.error('Failed to read user MCP grant — denying access rather than widening to the group tier', {
      email,
      error: err instanceof Error ? err.message : String(err),
    });
    throw new ServiceUnavailableError(
      'Could not read the user MCP tool grant, so this call is denied rather than granted the group tier. ' +
        'This is a transient failure — retry the request.',
    );
  }
}

/**
 * Resolve the access token's Cognito username to the email key used by
 * UserAccountMapping. Access tokens do not contain email in this deployment.
 */
async function resolveHumanUserEmail(username: string): Promise<string> {
  const userPoolId = mcpServerEnvironment().COGNITO_USER_POOL_ID;
  if (!userPoolId) {
    throw new ServiceUnavailableError('Cognito user lookup is not configured, so this call is denied.');
  }

  try {
    const user = await cognitoClient.send(
      new AdminGetUserCommand({
        UserPoolId: userPoolId,
        Username: username,
      }),
    );
    const email = user.UserAttributes?.find((attribute) => attribute.Name === 'email')?.Value;
    if (!email) {
      throw new ForbiddenError('Access denied: the Cognito user has no email attribute.');
    }
    // Trim but do NOT lowercase: the repository normalizes the key itself and, for a record
    // written before that normalization, falls back to the original-case key. Pre-lowercasing
    // here made findUserAuthorization's `normalizedUserId === userId` short-circuit always
    // true, so that mixed-case fallback could never fire for an MCP caller and a legacy
    // mixed-case grant record was unreachable.
    return email.trim();
  } catch (error) {
    if (error instanceof ForbiddenError) throw error;
    if (error instanceof Error && error.name === 'UserNotFoundException') {
      throw new ForbiddenError('Access denied: the Cognito user no longer exists.');
    }
    logger.error('Failed to resolve the MCP caller email from Cognito', {
      username,
      error: error instanceof Error ? error.message : String(error),
    });
    throw new ServiceUnavailableError(
      'Could not resolve the MCP caller in Cognito. This is a transient failure — retry the request.',
    );
  }
}

/**
 * Accounts this caller may see finding data for, or `undefined` for no restriction.
 *
 * The direct-execution tools bypass the REST API, so the per-account rules it enforces
 * through `createAccessRules` never run for them — this is the only place that
 * restriction can be applied for those tools.
 *
 * `undefined` (unrestricted) is returned for Admin and Delegated Admin callers,
 * which the API also lets see every account.
 *
 * Everyone else is restricted to their mapped accounts, and an unmapped user gets an
 * empty list — no finding data, which is the correct answer rather than everything.
 */
async function resolveAuthorizedAccountIds(identity: CallerIdentity): Promise<readonly string[] | undefined> {
  if (tierForGroups(identity.groups) !== 'AccountOperator') return undefined;

  const tableName = mcpServerEnvironment().USER_ACCOUNT_MAPPING_TABLE_NAME;
  if (!tableName || !identity.email) return [];

  try {
    const accounts = await getUserAuthorizationRepository(tableName).getUserAccounts(identity.email);
    return accounts ?? [];
  } catch (error) {
    // Mirror resolveUserAllowedTools: a transient failure reading the same table
    // must surface as a retryable 503, not fall through to the generic handler
    // catch as a non-retryable 500. Failing closed here would also be wrong — an
    // empty list denies every account, turning a blip into a hard authorization
    // failure — so this rethrows retryable instead of returning [].
    logger.error('Failed to read user account assignments — denying access rather than widening scope', {
      email: identity.email,
      error: error instanceof Error ? error.message : String(error),
    });
    throw new ServiceUnavailableError(
      'Could not read the user account assignments, so this call is denied. This is a transient failure — retry the request.',
    );
  }
}

/**
 * Read the partition and account out of this Lambda's own invoked ARN.
 *
 * Indexing `arn.split(':')` directly yields `undefined` for a short or malformed ARN
 * (ADR 0001 — no unguarded index access), and that `undefined` does not stay local: it
 * becomes the account in `createApiGatewayEvent`'s request context, the `accountId`
 * stamped on a recorded custom-runbook test result, and the partition and account of the
 * IAM ARN `customRunbookTestRoleService` builds — where it stringifies to the literal
 * `'undefined'` and produces a role ARN that resolves to nothing. Failing here instead
 * turns a silently wrong attribution into an immediate, named error.
 *
 * The ARN comes from the Lambda runtime, not the caller, so a malformed one is an
 * environment fault rather than bad input — hence a 500 rather than a 400.
 */
function parseInvokedFunctionArn(invokedFunctionArn: string): {
  readonly partition: string;
  readonly accountId: string;
} {
  const segments = invokedFunctionArn.split(':');
  const [prefix, partition, service, , accountId] = segments;
  if (segments.length < 6 || prefix !== 'arn' || !partition || service !== 'lambda' || !/^\d{12}$/.test(accountId)) {
    throw new Error(
      `Could not read the partition and account from this function's ARN ("${invokedFunctionArn}"). ` +
        'Expected arn:<partition>:lambda:<region>:<account>:function:<name>.',
    );
  }
  return { partition, accountId };
}

/**
 * The tool name the caller asked for, stripped of the AgentCore target prefix.
 *
 * The gateway sends `<targetName>___<toolName>`. The prefix is not guaranteed — a
 * direct invocation or a gateway change can deliver a bare name — and the previous
 * `substring(indexOf('___') + 3)` silently removed the first two characters in that
 * case (`indexOf` returns -1, so the offset became 2), turning `list_runbooks` into
 * `st_runbooks`. That resolved to no known tool, so the caller got an authorization
 * failure for a tool they had not named.
 */
function resolveToolName(context: AgentCoreContext): string {
  const delimiter = '___';
  const raw = context.clientContext?.custom?.bedrockAgentCoreToolName;
  if (typeof raw !== 'string' || raw.length === 0) {
    throw new BadRequestError('No tool name found on the invocation context.');
  }
  const separatorIndex = raw.indexOf(delimiter);
  return separatorIndex === -1 ? raw : raw.substring(separatorIndex + delimiter.length);
}

// ToolName dimension sentinels: the default before a name is resolved, and the
// bucket every unrecognized caller-supplied name collapses to (see
// boundedToolName). Both are fixed, so they add exactly two bounded series.
const UNRESOLVED_TOOL_NAME = 'unknown';
const UNRECOGNIZED_TOOL_NAME = 'unrecognized';

/**
 * Bound the ToolName dimension to a low-cardinality set before it is emitted.
 *
 * On the failure path `toolName` is whatever the caller sent: resolveToolName
 * strips the target prefix but does not validate the name, and an unrecognized
 * name is only rejected (400) or denied (403) after it has been resolved. So a
 * caller sending random names would mint a new CloudWatch time series per
 * request through the catch block below — unbounded-cardinality metric
 * injection from untrusted input, billed per series. Only names backed by a
 * real route pass through; the 'unknown' default (no name on the invocation)
 * keeps its own bucket, and any other value collapses to 'unrecognized'.
 */
function boundedToolName(toolName: string): string {
  if (Object.hasOwn(TOOL_INPUT_SCHEMAS, toolName)) return toolName;
  return toolName === UNRESOLVED_TOOL_NAME ? UNRESOLVED_TOOL_NAME : UNRECOGNIZED_TOOL_NAME;
}

/**
 * Emit the per-invocation MCP tool metrics from a handler exit point.
 *
 * Invocation and latency are emitted on every path; the error metric only when
 * the handler status is >= 500, so a caller-fault 4xx (a 404 "finding not
 * found", a 400 bad argument, a 403 denial) does not inflate the error signal
 * the alarm watches. The ToolName dimension is bounded by boundedToolName so an
 * unrecognized caller name cannot inject unbounded metric cardinality. Reuses
 * emitMetric (EMF to stdout), so it adds no API call and, like emitMetric,
 * never throws.
 */
function emitToolMetrics(toolName: string, startTime: number, statusCode: number): void {
  const dimensions = [{ name: MCP_TOOL_NAME_DIMENSION, value: boundedToolName(toolName) }];
  emitMetric(MCP_TOOL_INVOCATION_METRIC, 1, dimensions, 'Count');
  emitMetric(MCP_TOOL_LATENCY_METRIC, Date.now() - startTime, dimensions, 'Milliseconds');
  if (statusCode >= 500) {
    emitMetric(MCP_TOOL_ERROR_METRIC, 1, dimensions, 'Count');
    // Also emit McpToolError with no dimension so the aggregate
    // ASR-Mcp-ToolErrorSpike alarm can evaluate. A CloudWatch alarm cannot roll
    // a per-ToolName metric up across tools (alarms may not use SEARCH), and the
    // per-tool series and the dimensionless total are distinct time series, so
    // the total the alarm watches must be published in its own right. The
    // per-tool series above remains for dashboard breakdowns.
    emitMetric(MCP_TOOL_ERROR_METRIC, 1, [], 'Count');
  }
}

// --- Lambda entry point ---

export const handler = async (event: AgentCoreEvent, context: AgentCoreContext): Promise<ToolResponse> => {
  const startTime = Date.now();
  // Resolved inside the try: `clientContext.custom` is caller-adjacent input, and
  // dereferencing it above the try turned a malformed invocation into an unhandled
  // TypeError with no structured response.
  let toolName = UNRESOLVED_TOOL_NAME;

  try {
    toolName = resolveToolName(context);
    // AdminGroup receives every tool automatically. Delegated Admins and Account
    // Operators require an explicit per-user grant within their role ceiling.
    // The principal check comes first: a caller in no recognized group is refused
    // without spending a DynamoDB read, and its 403 is not masked by a 503 from that
    // read failing.
    // Verify the token's signature BEFORE any claim inside it is trusted. The gateway
    // validates it too, but Lambda admits a same-account caller when either an identity or
    // a resource policy allows the invoke, so a resource policy cannot keep an in-account
    // principal with lambda:InvokeFunction out. Without this, such a caller could forge
    // `cognito:groups: ["AdminGroup"]` and reach every admin-tier tool.
    await verifyAccessToken(extractBearerToken(event), {
      userPoolId: mcpServerEnvironment().COGNITO_USER_POOL_ID,
      expectedClientId: mcpServerEnvironment().MCP_GATEWAY_CLIENT_ID,
    });
    const identity = extractCallerIdentity(event);
    assertRecognizedPrincipal(identity);
    const toolArguments = removeTransportArguments(event);
    const tier = tierForGroups(identity.groups);
    let authorizedIdentity: CallerIdentity = identity;
    let allowedTools: readonly string[] | undefined;
    if (tier !== 'Admin') {
      const email = await resolveHumanUserEmail(identity.username);
      authorizedIdentity = { ...identity, email };
      allowedTools = await resolveUserAllowedTools(email);
    }
    assertAuthorized(toolName, authorizedIdentity, allowedTools);

    // Dispatch: local MD skill → direct execution → proxied tool
    // Direct-execution tools: run AWS SDK calls within this Lambda
    const directRoute = DIRECT_TOOL_ROUTES[toolName];
    if (directRoute) {
      const params = parseOrThrow(directRoute.schema, toolArguments);
      const env = mcpServerEnvironment();
      const executionContext = {
        region: mcpServerRuntimeEnvironment().AWS_REGION,
        requestId: context.awsRequestId,
        workspaceRoot: getHandlerHostEnvironment().ASR_WORKSPACE_ROOT,
        remediationHistoryTableName: env.REMEDIATION_HISTORY_TABLE_NAME,
        customRunbookTableName: env.CUSTOM_RUNBOOK_TABLE_NAME,
        customRunbookTestBoundaryArn: env.CUSTOM_RUNBOOK_TEST_BOUNDARY_ARN,
        authorizedAccountIds: await resolveAuthorizedAccountIds(authorizedIdentity),
        // `accountId` and `partition`, both taken from this Lambda's own ARN rather than
        // from the request, so a test result is attributed to the account the MCP server
        // actually runs in and cannot be influenced by the caller. The partition comes
        // from the same place because it cannot be inferred reliably from a region name —
        // isolated and sovereign partitions would otherwise fall back to `aws` and yield
        // ARNs that resolve to nothing.
        ...parseInvokedFunctionArn(context.invokedFunctionArn),
      };
      const result = await directRoute.execute(params, executionContext);
      logger.info('OK', { toolName, ms: Date.now() - startTime });
      emitToolMetrics(toolName, startTime, 200);
      return { statusCode: 200, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(result) };
    }

    // Proxied tools: invoke the ASR API Lambda under the MCP Lambda's IAM role.
    const route = PROXIED_TOOL_ROUTES[toolName];
    if (!route) throw new BadRequestError(`Unknown tool: ${toolName}`);

    // Validate the tool arguments, then split off any path-param the route needs.
    // A parameterized route fills a {param} token in its path from one argument and
    // forwards the remaining arguments as the request body the API handler reads.
    const validatedArgs = parseOrThrow(route.schema, toolArguments);
    const { concretePath, bodyArgs } = resolveRoutePath(route, validatedArgs);
    const apiBody = route.toApiBody ? route.toApiBody(bodyArgs) : bodyArgs;
    const response = await invokeApiLambda(concretePath, apiBody, authorizedIdentity, context, route.method ?? 'POST');

    if (response.statusCode < 200 || response.statusCode >= 300) {
      throw new ProxiedApiError(
        response.statusCode,
        describeApiFailure(response.body),
        readApiErrorDetail(response.body),
      );
    }

    logger.info('OK', { toolName, ms: Date.now() - startTime });
    emitToolMetrics(toolName, startTime, 200);
    return { statusCode: 200, headers: { 'Content-Type': 'application/json' }, body: response.body };
  } catch (error) {
    const { statusCode, message, detail } = describeToolFailure(error);
    logger.error('FAIL', {
      toolName,
      ms: Date.now() - startTime,
      statusCode,
      message,
      ...(statusCode >= 500 ? describeFailureForLog(error) : {}),
    });
    emitToolMetrics(toolName, startTime, statusCode);

    return {
      statusCode,
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ error: message, ...detail }),
    };
  }
};

/**
 * Remove interceptor-only fields before validating or forwarding tool arguments.
 *
 * AgentCore exposes the caller's bearer token to the target Lambda only through
 * an interceptor-injected argument. It is transport metadata, not a tool input,
 * and passthrough schemas must never copy it into the API Lambda request body.
 */
function removeTransportArguments(event: AgentCoreEvent): AgentCoreEvent {
  const toolArguments = { ...event };
  delete toolArguments[AUTHORIZATION_ARGUMENT];
  return toolArguments;
}

/**
 * Machine-readable detail the ASR API attaches to some errors: a stable `code` (e.g.
 * `VERSION_CONFLICT`) and a `context` (the `currentVersion` to refresh to, the offending ids).
 * The human sentence in `error` is for a person; this is for the agent that has to act.
 */
type ApiErrorDetail = { code?: string; context?: Record<string, unknown> };

/**
 * An ASR API failure forwarded through the proxy, carrying the API's structured detail so the
 * MCP response can pass it on. `describeApiFailure` flattens the body into one sentence for
 * `error`; `detail` preserves the `code` and `context` that sentence cannot carry — for a
 * version conflict, the version the caller has to refresh to.
 */
class ProxiedApiError extends HttpError {
  constructor(
    statusCode: number,
    message: string,
    public readonly detail: ApiErrorDetail,
  ) {
    super(statusCode, message);
    this.name = 'ProxiedApiError';
  }
}

/** Extract the API's `code` / `context`, if the body carries them; an empty object otherwise. */
function readApiErrorDetail(body: string): ApiErrorDetail {
  try {
    const parsed: unknown = JSON.parse(body);
    if (!isPlainRecord(parsed)) return {};
    const detail: ApiErrorDetail = {};
    if (typeof parsed.code === 'string' && parsed.code.length > 0) detail.code = parsed.code;
    if (isPlainRecord(parsed.context)) detail.context = parsed.context;
    return detail;
  } catch {
    return {};
  }
}

/**
 * Reduce an ASR API error body to the single human-readable sentence the MCP
 * client should see.
 *
 * The API returns `{"error":"ConflictError","message":"..."}`. Forwarding that
 * whole JSON string as the `HttpError` message meant the catch block below
 * re-wrapped it, producing a doubly-encoded body — `{"error":"{\"error\":...}"}` —
 * that a client has to `JSON.parse` twice to read. Every other failure path
 * returns `{"error":"<plain sentence>"}`, so an agent that prints `body.error`
 * showed the user an escaped blob for exactly the errors worth reading: the 409
 * version conflicts on `update_controls`/`update_notification` and the 404s on
 * the notification tools.
 *
 * The error name is folded into the sentence rather than dropped — "ConflictError"
 * is the part that tells a caller the retry is a refresh-and-resubmit, not a
 * blind retry. Anything that is not the expected shape is passed through
 * unchanged: a body this function cannot read is still better raw than replaced.
 */
function describeApiFailure(body: string): string {
  try {
    const parsed: unknown = JSON.parse(body);
    if (typeof parsed !== 'object' || parsed === null) return body;
    const { error, message } = parsed as { error?: unknown; message?: unknown };
    // Nested one level deeper when the API's own handler already stringified its
    // error payload into the `error` field.
    if (typeof error === 'string' && error.trimStart().startsWith('{')) {
      return describeApiFailure(error);
    }
    if (typeof message === 'string' && message.length > 0) {
      return typeof error === 'string' && error.length > 0 ? `${error}: ${message}` : message;
    }
    if (typeof error === 'string' && error.length > 0) return error;
    return body;
  } catch {
    return body;
  }
}

/**
 * Map a thrown error to the status and message returned to the MCP client.
 *
 * `MissingParameterError` and `ValidationError` are the caller's fault, and both
 * carry a message written to be acted on ("Pass `automation_assume_role`. The role
 * name must begin with ..."). Letting them fall through to the generic branch turned
 * a fixable 400 into a 500 whose body was only "Internal server error", so the
 * client saw a server fault and never learned which argument to supply — the
 * common case for the optional-but-not-really arguments (`namespace`,
 * `automation_assume_role`) that nothing on the deployed Lambda injects.
 *
 * Anything else stays a 500 with a generic body: an unexpected failure must not
 * leak internals to the caller, and the real error is already in the log line.
 */
function describeToolFailure(error: unknown): { statusCode: number; message: string; detail: ApiErrorDetail } {
  // A proxied API failure keeps the API's structured detail alongside the sentence.
  if (error instanceof ProxiedApiError) {
    return { statusCode: error.statusCode, message: error.message, detail: error.detail };
  }
  // Every status-code error the handler throws now extends the shared HttpError
  // (ForbiddenError/ServiceUnavailableError/BadRequestError and raw HttpError for
  // 502), so one branch reading `statusCode` covers them all.
  if (error instanceof HttpError) {
    return { statusCode: error.statusCode, message: error.message, detail: {} };
  }
  if (error instanceof MissingParameterError || error instanceof ValidationError) {
    return { statusCode: 400, message: error.message, detail: {} };
  }
  // A caller-supplied path that escaped its boundary is the caller's fault, and the
  // message names the boundary. It was collapsing into "Internal server error", which
  // told the caller nothing and read as a server bug.
  if (error instanceof PathContainmentError) {
    return { statusCode: 400, message: error.message, detail: {} };
  }
  // 403, not 400: the request was well-formed and the finding may exist — the caller
  // simply may not see that account. The message names the account so an operator can
  // ask for the mapping they need, without revealing anything about the finding.
  if (error instanceof AccountAuthorizationError) {
    return { statusCode: 403, message: error.message, detail: {} };
  }
  return { statusCode: 500, message: 'Internal server error', detail: {} };
}

/** Preserve unexpected server-side diagnostics in logs without returning them to the caller. */
function describeFailureForLog(error: unknown): Record<string, unknown> {
  if (error instanceof Error) {
    return {
      errorName: error.name,
      errorMessage: error.message,
      errorStack: error.stack,
    };
  }
  return { errorValue: String(error) };
}

async function invokeApiLambda(
  routePath: string,
  params: unknown,
  identity: CallerIdentity,
  context: AgentCoreContext,
  method: 'GET' | 'POST' | 'PUT' | 'DELETE' = 'POST',
): Promise<z.infer<typeof API_LAMBDA_RESPONSE_SCHEMA>> {
  const apiEvent = createApiGatewayEvent(routePath, params, identity.claims, context, method);
  const invocation = await apiLambdaClient.send(
    new InvokeCommand({
      FunctionName: mcpServerEnvironment().API_FUNCTION_NAME,
      InvocationType: 'RequestResponse',
      Payload: Buffer.from(JSON.stringify(apiEvent)),
    }),
  );

  if (invocation.FunctionError) {
    throw new HttpError(502, 'ASR API Lambda invocation failed');
  }

  const responsePayload = invocation.Payload ? Buffer.from(invocation.Payload).toString('utf8') : '';
  const parsedPayload = parseJson(responsePayload);
  const result = API_LAMBDA_RESPONSE_SCHEMA.safeParse(parsedPayload);
  if (!result.success) {
    throw new HttpError(502, 'ASR API Lambda returned an invalid response');
  }
  return result.data;
}

function createApiGatewayEvent(
  routePath: string,
  params: unknown,
  claims: Readonly<Record<string, unknown>>,
  context: AgentCoreContext,
  method: 'GET' | 'POST' | 'PUT' | 'DELETE' = 'POST',
): APIGatewayProxyEvent {
  const { accountId } = parseInvokedFunctionArn(context.invokedFunctionArn);
  return {
    body: JSON.stringify(params),
    headers: {
      'content-type': 'application/json',
      'user-agent': 'asr-mcp-server',
      'x-amzn-trace-id': `Root=${context.awsRequestId}`,
    },
    multiValueHeaders: {},
    httpMethod: method,
    isBase64Encoded: false,
    path: routePath,
    pathParameters: null,
    queryStringParameters: null,
    multiValueQueryStringParameters: null,
    stageVariables: null,
    requestContext: {
      accountId,
      apiId: 'mcp-direct-invocation',
      authorizer: { claims },
      httpMethod: method,
      identity: {
        accessKey: null,
        accountId: null,
        apiKey: null,
        apiKeyId: null,
        caller: null,
        clientCert: null,
        cognitoAuthenticationProvider: null,
        cognitoAuthenticationType: null,
        cognitoIdentityId: null,
        cognitoIdentityPoolId: null,
        principalOrgId: null,
        sourceIp: '127.0.0.1',
        user: null,
        userAgent: 'asr-mcp-server',
        userArn: null,
      },
      path: routePath,
      protocol: 'HTTP/1.1',
      requestId: context.awsRequestId,
      requestTime: '',
      requestTimeEpoch: 0,
      resourceId: 'mcp-direct-invocation',
      resourcePath: routePath,
      stage: 'mcp',
    },
    resource: routePath,
  };
}

function parseJson(value: string): unknown {
  try {
    return JSON.parse(value);
  } catch {
    return undefined;
  }
}

/** Narrows `unknown` to a plain object so its keys can be read without an unchecked cast (ADR 0001). */
function isPlainRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/**
 * Resolve a proxied route's concrete path and request body from the tool arguments.
 * For a parameterized route, the named `pathParam` argument is substituted into the
 * `{param}` token and removed from the body, so the API router matches the concrete
 * route and its handler reads the id from pathParameters. For a non-parameterized
 * route the path is returned unchanged and all arguments form the body.
 */
function resolveRoutePath(route: ProxiedRoute, args: unknown): { concretePath: string; bodyArgs: unknown } {
  if (!route.pathParam) {
    return { concretePath: route.path, bodyArgs: args };
  }

  const record: Record<string, unknown> = isPlainRecord(args) ? { ...args } : {};
  const paramValue = record[route.pathParam];
  if (typeof paramValue !== 'string' || paramValue.length === 0) {
    throw new BadRequestError(`Validation failed: ${route.pathParam} is required`);
  }

  const concretePath = route.path.replace(`{${route.pathParam}}`, encodeURIComponent(paramValue));
  delete record[route.pathParam];
  return { concretePath, bodyArgs: record };
}

function parseOrThrow<T>(schema: z.ZodSchema<T>, input: unknown): T {
  try {
    return schema.parse(input);
  } catch (error) {
    if (error instanceof z.ZodError) {
      const msg = error.issues.map((i) => `${i.path.join('.')}: ${i.message}`).join('; ');
      throw new BadRequestError(`Validation failed: ${msg}`);
    }
    throw error;
  }
}
