// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { Logger } from '@aws-lambda-powertools/logger';
import { injectLambdaContext } from '@aws-lambda-powertools/logger/middleware';
import { Tracer } from '@aws-lambda-powertools/tracer';
import { captureLambdaHandler } from '@aws-lambda-powertools/tracer/middleware';
import { APIGatewayProxyEvent, APIGatewayProxyResult, Context } from 'aws-lambda';
import { dynamicImport } from 'tsimportlib';
import {
  ConfigId,
  CreateNotificationConfigurationRequest,
  CreateNotificationConfigurationRequestSchema,
  DeliveryChannelConfig,
  NotificationConfigurationItem,
  UpdateNotificationConfigurationRequest,
  UpdateNotificationConfigurationRequestSchema,
  ToggleStatusRequest,
  ToggleStatusRequestSchema,
  ResendEmailConfirmationRequest,
  ResendEmailConfirmationRequestSchema,
  createSnsChannelConfigSchema,
  SnsChannelValidationContext,
  TestNotificationRequest,
  TestNotificationRequestSchema,
} from '@asr/data-models';
import { SCOPE_NAME } from '../../common/constants/apiConstant';
import { NotificationConfigurationService } from '../services/notificationConfigurationService';
import { API_HEADERS, createResponse } from './apiHandler';
import { BaseHandler, getClaims } from './baseHandler';
import { apiLambdaEnvironment, apiLambdaRuntimeEnvironment } from '../apiLambdaEnvironment';
import { BadRequestError, ForbiddenError } from '../../common/utils/httpErrors';
import { AuthenticatedUser } from '../services/authorization';
import { sendMetrics } from '../../common/utils/metricsUtils';
import { TestNotificationService } from '../services/testNotificationService';

const logger = new Logger({ serviceName: SCOPE_NAME });
const tracer = new Tracer({ serviceName: SCOPE_NAME });
const baseHandler = new BaseHandler(logger);
const notificationConfigService = new NotificationConfigurationService(logger);
const testNotificationService = new TestNotificationService(logger);

function validateSnsChannels(body: { readonly deliveryChannels: ReadonlyArray<DeliveryChannelConfig> }): void {
  const env = apiLambdaEnvironment();
  const runtime = apiLambdaRuntimeEnvironment();
  const context: SnsChannelValidationContext = {
    accountId: env.AWS_ACCOUNT_ID,
    partition: env.AWS_PARTITION,
    region: runtime.AWS_REGION,
  };
  const snsSchema = createSnsChannelConfigSchema(context);
  body.deliveryChannels.forEach((channel, index) => {
    if (channel.type !== 'sns') return;
    const result = snsSchema.safeParse(channel);
    if (!result.success) {
      const detail = result.error.issues.map((i) => i.message).join('; ');
      throw new BadRequestError(`deliveryChannels[${index}] (sns): ${detail}`);
    }
  });
}

/** Zod-style schema shape accepted by BaseHandler.extractValidatedBody. */
interface ValidatableSchema<T> {
  safeParse: (data: unknown) => {
    success: boolean;
    data?: T;
    error?: { issues: Array<{ path: PropertyKey[]; message: string }> };
  };
}

/**
 * Validates a create/update request body (schema + SNS channel rules) and emits
 * the `configuration_validation_errors` metric when validation fails, so
 * misconfiguration patterns can be tracked via the SolutionsMetrics API.
 */
async function validateConfigurationRequest<
  T extends { readonly deliveryChannels: ReadonlyArray<DeliveryChannelConfig> },
>(event: APIGatewayProxyEvent, schema: ValidatableSchema<T>, errorPrefix: string): Promise<T> {
  try {
    const body = baseHandler.extractValidatedBody<T>(event, schema, errorPrefix);
    validateSnsChannels(body);
    return body;
  } catch (error) {
    if (error instanceof BadRequestError) {
      await sendMetrics({ configuration_validation_errors: 1 });
    }
    throw error;
  }
}

// ─── Account Scope Authorization Helpers ─────────────────────────────────────

/** Returns true if the user is an account operator (not admin or delegated admin). */
function isOperator(user: AuthenticatedUser): boolean {
  return (
    user.groups.includes('AccountOperatorGroup') &&
    !user.groups.includes('AdminGroup') &&
    !user.groups.includes('DelegatedAdminGroup')
  );
}

/** Account IDs the user owns; empty for non-operators or operators with none assigned. */
function ownedAccounts(user: AuthenticatedUser): string[] {
  return user.authorizedAccounts ?? [];
}

/**
 * For an account operator, fetches the target configuration and asserts the operator created it.
 * Returns the fetched configuration so callers can reuse it (avoiding a second read and closing the
 * time-of-check/time-of-use window). Returns undefined for admins and delegated admins, who bypass
 * the creator check and may mutate any configuration.
 */
async function assertOperatorHasCreatorAccess(
  user: AuthenticatedUser,
  configId: ConfigId,
): Promise<NotificationConfigurationItem | undefined> {
  if (!isOperator(user)) return undefined;
  const existing = await notificationConfigService.getConfigurationById(configId);
  NotificationConfigurationService.assertOperatorIsCreator(user.email, existing);
  return existing;
}

/**
 * Resolves the effective request body for a create/update performed by an account operator.
 * Auto-assigns owned accounts when not provided.
 */
function applyOperatorAccountScope<T extends { accountIds?: string[] }>(user: AuthenticatedUser, body: T): T {
  if (isOperator(user) && (!body.accountIds || body.accountIds.length === 0)) {
    const owned = ownedAccounts(user);
    if (owned.length === 0) {
      throw new ForbiddenError(
        'Account operators with no assigned accounts cannot create or modify notification configurations',
      );
    }
    return { ...body, accountIds: owned };
  }
  return body;
}

type HandlerFn = (event: APIGatewayProxyEvent) => Promise<APIGatewayProxyResult>;

// Resolve middy modules once per Lambda container, lazily on first request.
// Lazy (not module-load) so Jest's vm sandbox doesn't trigger dynamicImport at import time.
// http-json-body-parser is loaded on-demand the first time a body-parsing
// route is hit — GET routes never pay its import cost.
let middyCorePromise: Promise<typeof import('@middy/core')> | undefined;
let httpJsonBodyParserPromise: Promise<typeof import('@middy/http-json-body-parser')> | undefined;

function getMiddyCore() {
  middyCorePromise ??= (dynamicImport('@middy/core', module) as Promise<typeof import('@middy/core')>).catch(
    (error) => {
      middyCorePromise = undefined;
      throw error;
    },
  );
  return middyCorePromise;
}

function getHttpJsonBodyParser() {
  httpJsonBodyParserPromise ??= (
    dynamicImport('@middy/http-json-body-parser', module) as Promise<typeof import('@middy/http-json-body-parser')>
  ).catch((error) => {
    httpJsonBodyParserPromise = undefined;
    throw error;
  });
  return httpJsonBodyParserPromise;
}

async function wrapWithMiddleware(
  handler: HandlerFn,
  event: APIGatewayProxyEvent,
  context: Context,
  options?: { shouldParseBody?: boolean },
): Promise<APIGatewayProxyResult> {
  const { default: middy } = await getMiddyCore();
  let middlewareHandler = middy(handler).use(injectLambdaContext(logger)).use(captureLambdaHandler(tracer));
  if (options?.shouldParseBody) {
    const { default: httpJsonBodyParser } = await getHttpJsonBodyParser();
    middlewareHandler = middlewareHandler.use(httpJsonBodyParser());
  }
  return middlewareHandler(event, context);
}

async function getNotificationConfigurationsHandler(event: APIGatewayProxyEvent): Promise<APIGatewayProxyResult> {
  const claims = getClaims(event);

  await baseHandler.validateAccess(claims, {
    requiredGroups: ['AdminGroup', 'DelegatedAdminGroup', 'AccountOperatorGroup'],
  });

  // Every authorized role — including account operators — may list all configurations. Edit
  // authority is creator-based and enforced on the mutation paths; visibility is unrestricted.
  const result = await notificationConfigService.getAllConfigurations();
  return createResponse(200, result, API_HEADERS.NOTIFICATIONS);
}

async function getNotificationConfigurationHandler(event: APIGatewayProxyEvent): Promise<APIGatewayProxyResult> {
  const claims = getClaims(event);

  await baseHandler.validateAccess(claims, {
    requiredGroups: ['AdminGroup', 'DelegatedAdminGroup', 'AccountOperatorGroup'],
  });

  const configId = baseHandler.extractValidatedPathId<ConfigId>(event, 'id');
  const config = await notificationConfigService.getConfigurationById(configId);

  // Operators may *read* any configuration by ID, including configs created by other operators or
  // admins. Edit authority is creator-based and enforced only on the mutation paths
  // (assertOperatorHasCreatorAccess); read access is intentionally unrestricted so operators retain
  // full visibility while acting only on configurations they created.
  return createResponse(200, config, API_HEADERS.NOTIFICATIONS);
}

async function createNotificationConfigurationHandler(event: APIGatewayProxyEvent): Promise<APIGatewayProxyResult> {
  const claims = getClaims(event);

  const user = await baseHandler.validateAccess(claims, {
    requiredGroups: ['AdminGroup', 'DelegatedAdminGroup', 'AccountOperatorGroup'],
  });

  const body = await validateConfigurationRequest<CreateNotificationConfigurationRequest>(
    event,
    CreateNotificationConfigurationRequestSchema,
    'Invalid notification configuration',
  );

  if (isOperator(user)) {
    NotificationConfigurationService.assertOperatorOwnsRequestedAccounts(ownedAccounts(user), body.accountIds);
  }

  const effectiveBody = applyOperatorAccountScope(user, body);

  const created = await notificationConfigService.createConfiguration(effectiveBody, {
    actorEmail: user.email,
    actorGroups: user.groups,
  });

  return createResponse(201, created, API_HEADERS.NOTIFICATIONS);
}

async function deleteNotificationConfigurationHandler(event: APIGatewayProxyEvent): Promise<APIGatewayProxyResult> {
  const claims = getClaims(event);

  const user = await baseHandler.validateAccess(claims, {
    requiredGroups: ['AdminGroup', 'DelegatedAdminGroup', 'AccountOperatorGroup'],
  });

  const configId = baseHandler.extractValidatedPathId<ConfigId>(event, 'id');

  await assertOperatorHasCreatorAccess(user, configId);

  await notificationConfigService.deleteConfiguration(configId, {
    actorEmail: user.email,
    actorGroups: user.groups,
  });

  return createResponse(200, { message: 'Configuration deleted successfully' }, API_HEADERS.NOTIFICATIONS);
}

async function updateNotificationConfigurationHandler(event: APIGatewayProxyEvent): Promise<APIGatewayProxyResult> {
  const claims = getClaims(event);

  const user = await baseHandler.validateAccess(claims, {
    requiredGroups: ['AdminGroup', 'DelegatedAdminGroup', 'AccountOperatorGroup'],
  });

  const configId = baseHandler.extractValidatedPathId<ConfigId>(event, 'id');

  const body = await validateConfigurationRequest<UpdateNotificationConfigurationRequest>(
    event,
    UpdateNotificationConfigurationRequestSchema,
    'Invalid notification configuration update',
  );

  const existingConfig = await assertOperatorHasCreatorAccess(user, configId);
  if (isOperator(user)) {
    NotificationConfigurationService.assertOperatorOwnsRequestedAccounts(ownedAccounts(user), body.accountIds);
  }

  const effectiveBody = applyOperatorAccountScope(user, body);

  const updated = await notificationConfigService.updateConfiguration(
    configId,
    effectiveBody,
    {
      actorEmail: user.email,
      actorGroups: user.groups,
    },
    existingConfig,
  );

  return createResponse(200, updated, API_HEADERS.NOTIFICATIONS);
}

async function toggleNotificationConfigurationStatusHandler(
  event: APIGatewayProxyEvent,
): Promise<APIGatewayProxyResult> {
  const claims = getClaims(event);

  const user = await baseHandler.validateAccess(claims, {
    requiredGroups: ['AdminGroup', 'DelegatedAdminGroup', 'AccountOperatorGroup'],
  });

  const configId = baseHandler.extractValidatedPathId<ConfigId>(event, 'id');

  await assertOperatorHasCreatorAccess(user, configId);

  const body = baseHandler.extractValidatedBody<ToggleStatusRequest>(
    event,
    ToggleStatusRequestSchema,
    'Invalid toggle status request',
  );

  const updated = await notificationConfigService.toggleStatus(configId, body, {
    actorEmail: user.email,
    actorGroups: user.groups,
  });

  return createResponse(200, updated, API_HEADERS.NOTIFICATIONS);
}

async function getEmailSubscriptionsHandler(event: APIGatewayProxyEvent): Promise<APIGatewayProxyResult> {
  const claims = getClaims(event);
  const user = await baseHandler.validateAccess(claims, {
    requiredGroups: ['AdminGroup', 'DelegatedAdminGroup', 'AccountOperatorGroup'],
  });
  const configId = baseHandler.extractValidatedPathId<ConfigId>(event, 'id');
  await assertOperatorHasCreatorAccess(user, configId);
  const { statuses: subscriptions, hasFailure } = await notificationConfigService.listSubscriptionStatuses(configId);
  return createResponse(200, { subscriptions, hasFailure }, API_HEADERS.NOTIFICATIONS);
}

async function resendEmailConfirmationHandler(event: APIGatewayProxyEvent): Promise<APIGatewayProxyResult> {
  const claims = getClaims(event);
  const user = await baseHandler.validateAccess(claims, {
    requiredGroups: ['AdminGroup', 'DelegatedAdminGroup', 'AccountOperatorGroup'],
  });
  const configId = baseHandler.extractValidatedPathId<ConfigId>(event, 'id');
  await assertOperatorHasCreatorAccess(user, configId);
  const body = baseHandler.extractValidatedBody<ResendEmailConfirmationRequest>(
    event,
    ResendEmailConfirmationRequestSchema,
    'Invalid resend email confirmation request',
  );
  await notificationConfigService.resendConfirmation(configId, body.email);
  return createResponse(200, { message: 'Confirmation resent' }, API_HEADERS.NOTIFICATIONS);
}

async function testNotificationConfigurationHandler(event: APIGatewayProxyEvent): Promise<APIGatewayProxyResult> {
  const claims = getClaims(event);

  const user = await baseHandler.validateAccess(claims, {
    requiredGroups: ['AdminGroup', 'DelegatedAdminGroup', 'AccountOperatorGroup'],
  });

  const configId = baseHandler.extractValidatedPathId<ConfigId>(event, 'id');

  await assertOperatorHasCreatorAccess(user, configId);

  const body = event.body
    ? baseHandler.extractValidatedBody<TestNotificationRequest>(
        event,
        TestNotificationRequestSchema,
        'Invalid test notification request',
      )
    : undefined;

  const result = await testNotificationService.sendTestNotification(configId, body, user.email);

  return createResponse(200, result, API_HEADERS.NOTIFICATIONS);
}

export const getNotificationConfigurations = async (
  event: APIGatewayProxyEvent,
  context: Context,
): Promise<APIGatewayProxyResult> => wrapWithMiddleware(getNotificationConfigurationsHandler, event, context);

export const getNotificationConfiguration = async (
  event: APIGatewayProxyEvent,
  context: Context,
): Promise<APIGatewayProxyResult> => wrapWithMiddleware(getNotificationConfigurationHandler, event, context);

export const createNotificationConfiguration = async (
  event: APIGatewayProxyEvent,
  context: Context,
): Promise<APIGatewayProxyResult> =>
  wrapWithMiddleware(createNotificationConfigurationHandler, event, context, { shouldParseBody: true });

export const deleteNotificationConfiguration = async (
  event: APIGatewayProxyEvent,
  context: Context,
): Promise<APIGatewayProxyResult> => wrapWithMiddleware(deleteNotificationConfigurationHandler, event, context);

export const updateNotificationConfiguration = async (
  event: APIGatewayProxyEvent,
  context: Context,
): Promise<APIGatewayProxyResult> =>
  wrapWithMiddleware(updateNotificationConfigurationHandler, event, context, { shouldParseBody: true });

export const toggleNotificationConfigurationStatus = async (
  event: APIGatewayProxyEvent,
  context: Context,
): Promise<APIGatewayProxyResult> =>
  wrapWithMiddleware(toggleNotificationConfigurationStatusHandler, event, context, { shouldParseBody: true });

export const getEmailSubscriptions = async (
  event: APIGatewayProxyEvent,
  context: Context,
): Promise<APIGatewayProxyResult> => wrapWithMiddleware(getEmailSubscriptionsHandler, event, context);

export const resendEmailConfirmation = async (
  event: APIGatewayProxyEvent,
  context: Context,
): Promise<APIGatewayProxyResult> =>
  wrapWithMiddleware(resendEmailConfirmationHandler, event, context, { shouldParseBody: true });

export const testNotificationConfiguration = async (
  event: APIGatewayProxyEvent,
  context: Context,
): Promise<APIGatewayProxyResult> =>
  wrapWithMiddleware(testNotificationConfigurationHandler, event, context, { shouldParseBody: true });
