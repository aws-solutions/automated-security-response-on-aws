// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { ApiLambdaEnvironmentConfig } from '@asr/data-models';
import { NotImplementedError } from '../common/utils/httpErrors';
import { readOptionalEnvironmentVariables, requireEnvironmentVariables } from '../common/utils/env-variables';

let cached: ApiLambdaEnvironmentConfig | undefined;

const REQUIRED_KEYS: readonly (keyof ApiLambdaEnvironmentConfig)[] = [
  'SOLUTION_ID',
  'SOLUTION_VERSION',
  'SOLUTION_TRADEMARKEDNAME',
  'POWERTOOLS_LOG_LEVEL',
  'USER_POOL_ID',
  'USER_ACCOUNT_MAPPING_TABLE_NAME',
  'FINDINGS_TABLE_NAME',
  'REMEDIATION_HISTORY_TABLE_NAME',
  'REMEDIATION_CONFIG_TABLE_NAME',
  'RESOURCE_FILTERS_TABLE_NAME',
  'CSV_EXPORT_BUCKET_NAME',
  'PRESIGNED_URL_TTL_DAYS',
  'ORCHESTRATOR_ARN',
  'AWS_ACCOUNT_ID',
  'AWS_PARTITION',
  'STACK_ID',
  'SECURITY_HUB_V2_ENABLED',
  'EXPORT_MAX_TIME_MS',
  'EXPORT_MAX_RECORDS',
  'NOTIFICATION_CONFIG_TABLE_NAME',
  'RESOURCE_NAME_PREFIX',
  'IAC_TEMPLATES_BUCKET',
  'ADMIN_NOTIFICATION_TOPIC_ARN',
  'ENABLE_ROLLBACK',
  'FINDINGS_TTL_DAYS',
] as const;

/**
 * Keys that are part of the contract but not guaranteed present in every deployment. They are read
 * without validation and may be `undefined` at runtime, so callers must handle their absence
 * gracefully rather than assuming a value is set.
 */
const OPTIONAL_KEYS: readonly (keyof ApiLambdaEnvironmentConfig)[] = [
  // Empty on an MCP-only deployment (ShouldDeployWebUI=no); requiring it there
  // crashes the API Lambda at init and 502s every proxied MCP tool. Consumers
  // omit the link when it is falsy.
  'WEB_UI_URL',
  'NOTIFICATION_BATCHES_TABLE_NAME',
  'CUSTOM_RUNBOOK_BUCKET_NAME',
  'CUSTOM_RUNBOOK_TABLE_NAME',
  'CUSTOM_RUNBOOK_DEV_LOOP_ENABLED',
  'MCP_ENABLED',
] as const;

/**
 * Reads, validates, and caches the environment variables required by the
 * API Lambda. Call once at startup; subsequent calls return the cached result.
 * Throws if any required variables are missing, listing all missing keys.
 */
export function apiLambdaEnvironment(): ApiLambdaEnvironmentConfig {
  if (cached) return cached;
  cached = {
    ...requireEnvironmentVariables(REQUIRED_KEYS),
    ...readOptionalEnvironmentVariables(OPTIONAL_KEYS),
  };
  return cached;
}

export interface CustomRunbookEnvironment {
  readonly bucketName: string;
  readonly tableName: string;
}

/**
 * Whether the drift-detection developer fast-loop (`push`/`execute`) is enabled.
 * Reads `CUSTOM_RUNBOOK_DEV_LOOP_ENABLED`; anything other than the exact string
 * `"true"` — including absent, the production default — is treated as disabled,
 * so the dev-loop writes fail closed.
 */
export function isCustomRunbookDevLoopEnabled(): boolean {
  return apiLambdaEnvironment().CUSTOM_RUNBOOK_DEV_LOOP_ENABLED === 'true';
}

/**
 * Returns the MCP blueprint's storage configuration if both required values
 * are present. Returns `undefined` when the MCP blueprint is not deployed —
 * callers that can degrade gracefully (e.g. controls listing) use this form.
 */
export function optionalCustomRunbookEnvironment(): CustomRunbookEnvironment | undefined {
  const environment = apiLambdaEnvironment();
  const { CUSTOM_RUNBOOK_BUCKET_NAME, CUSTOM_RUNBOOK_TABLE_NAME } = environment;

  if (!CUSTOM_RUNBOOK_BUCKET_NAME || !CUSTOM_RUNBOOK_TABLE_NAME) {
    return undefined;
  }

  return {
    bucketName: CUSTOM_RUNBOOK_BUCKET_NAME,
    tableName: CUSTOM_RUNBOOK_TABLE_NAME,
  };
}

/**
 * Throws NotImplementedError (501) when custom-runbook storage is not configured.
 * Use as a guard at the top of handlers that cannot function without the MCP
 * blueprint — the 501 signals a permanent deployment topology fact, not a
 * transient outage.
 */
export function assertCustomRunbooksConfigured(): CustomRunbookEnvironment {
  const config = optionalCustomRunbookEnvironment();
  if (!config) {
    throw new NotImplementedError(
      'Custom runbooks are not available. Deploy the MCP blueprint to enable this feature.',
    );
  }
  return config;
}

export interface ApiLambdaRuntimeEnvironment {
  readonly AWS_REGION: string;
}

let runtimeCached: ApiLambdaRuntimeEnvironment | undefined;

export function apiLambdaRuntimeEnvironment(): ApiLambdaRuntimeEnvironment {
  if (runtimeCached) return runtimeCached;
  runtimeCached = requireEnvironmentVariables(['AWS_REGION'] as const);
  return runtimeCached;
}

/** Clears the cached config. Useful in tests to re-initialize with different values. */
export function resetApiLambdaEnvironmentCache(): void {
  cached = undefined;
  runtimeCached = undefined;
}
