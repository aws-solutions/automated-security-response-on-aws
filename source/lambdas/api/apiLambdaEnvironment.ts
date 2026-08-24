// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { ApiLambdaEnvironmentConfig } from '@asr/data-models';
import { readOptionalEnvironmentVariables, requireEnvironmentVariables } from '../common/utils/env-variables';

let cached: ApiLambdaEnvironmentConfig | undefined;
let cachedRuntimeEnv: { readonly AWS_REGION: string } | undefined;

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
  'WEB_UI_URL',
  'AWS_ACCOUNT_ID',
  'STACK_ID',
  'SECURITY_HUB_V2_ENABLED',
  'EXPORT_MAX_TIME_MS',
  'EXPORT_MAX_RECORDS',
  'NOTIFICATION_CONFIG_TABLE_NAME',
  'AWS_PARTITION',
  'RESOURCE_NAME_PREFIX',
  'IAC_TEMPLATES_BUCKET',
  'ADMIN_NOTIFICATION_TOPIC_ARN',
] as const;

/**
 * Keys that are part of the contract but not guaranteed present in every deployment. They are read
 * without validation and may be `undefined` at runtime, so callers must handle their absence
 * gracefully rather than assuming a value is set.
 */
const OPTIONAL_KEYS: readonly (keyof ApiLambdaEnvironmentConfig)[] = ['NOTIFICATION_BATCHES_TABLE_NAME'] as const;

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

/** Clears the cached config. Useful in tests to re-initialize with different values. */
export function resetApiLambdaEnvironmentCache(): void {
  cached = undefined;
  cachedRuntimeEnv = undefined;
}

export function apiLambdaRuntimeEnvironment(): { readonly AWS_REGION: string } {
  if (cachedRuntimeEnv) return cachedRuntimeEnv;
  cachedRuntimeEnv = requireEnvironmentVariables(['AWS_REGION'] as const);
  return cachedRuntimeEnv;
}
