// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { PreProcessorEnvironmentConfig } from '@asr/data-models';
import { readOptionalEnvironmentVariables, requireEnvironmentVariables } from '../common/utils/env-variables';

let cached: PreProcessorEnvironmentConfig | undefined;

const REQUIRED_KEYS: readonly (keyof PreProcessorEnvironmentConfig)[] = [
  'SOLUTION_TRADEMARKEDNAME',
  'POWERTOOLS_LOG_LEVEL',
  'FINDINGS_TABLE_NAME',
  'REMEDIATION_HISTORY_TABLE_NAME',
  'REMEDIATION_CONFIG_TABLE_NAME',
  'RESOURCE_FILTERS_TABLE_NAME',
  'NOTIFICATION_CONFIG_TABLE_NAME',
  'ORCHESTRATOR_ARN',
  'FINDINGS_TTL_DAYS',
  'HISTORY_TTL_DAYS',
  'AWS_ACCOUNT_ID',
  'STACK_ID',
  'NOTIFICATION_QUEUE_URL',
] as const;

// Optional tunables (retry cap + cooldown). Absent in deployments that have not
// set them; the pre-processor applies sensible defaults in that case.
const OPTIONAL_KEYS: readonly (keyof PreProcessorEnvironmentConfig)[] = [
  'MAX_REMEDIATION_ATTEMPTS',
  'REMEDIATION_RETRY_COOLDOWN_MINUTES',
] as const;

/**
 * Reads, validates, and caches the environment variables used by the
 * Pre-Processor Lambda. Call once at startup; subsequent calls return the cached result.
 * Throws if any required variables are missing, listing all missing keys. Optional
 * variables that are absent are simply omitted.
 */
export function preProcessorEnvironment(): PreProcessorEnvironmentConfig {
  if (cached) return cached;
  cached = {
    ...requireEnvironmentVariables(REQUIRED_KEYS),
    ...readOptionalEnvironmentVariables(OPTIONAL_KEYS),
  };
  return cached;
}

/** Clears the cached config. Useful in tests to re-initialize with different values. */
export function resetPreProcessorEnvironmentCache(): void {
  cached = undefined;
}
