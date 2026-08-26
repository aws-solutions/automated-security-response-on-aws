// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { SynchronizationFindingsEnvironmentConfig } from '@asr/data-models';
import { requireEnvironmentVariables } from '../common/utils/env-variables';

let cached: SynchronizationFindingsEnvironmentConfig | undefined;

const REQUIRED_KEYS: readonly (keyof SynchronizationFindingsEnvironmentConfig)[] = [
  'SOLUTION_TRADEMARKEDNAME',
  'POWERTOOLS_SERVICE_NAME',
  'POWERTOOLS_LOG_LEVEL',
  'POWERTOOLS_LOGGER_LOG_EVENT',
  'POWERTOOLS_TRACER_CAPTURE_RESPONSE',
  'POWERTOOLS_TRACER_CAPTURE_ERROR',
  'FINDINGS_TABLE_NAME',
  'REMEDIATION_CONFIG_TABLE_NAME',
  'RESOURCE_FILTERS_TABLE_NAME',
  'NOTIFICATION_CONFIG_TABLE_NAME',
  'FINDINGS_TTL_DAYS',
  'AWS_ACCOUNT_ID',
  'STACK_ID',
] as const;

/**
 * Reads, validates, and caches the environment variables required by the
 * SynchronizationFindings Lambda. Call once at module load; subsequent calls
 * return the cached result. Throws if any required variables are missing, listing all missing keys.
 */
export function synchronizationFindingsEnvironment(): SynchronizationFindingsEnvironmentConfig {
  if (cached) return cached;
  cached = requireEnvironmentVariables(REQUIRED_KEYS);
  return cached;
}

/** Clears the cached config. Useful in tests to re-initialize with different values. */
export function resetSynchronizationFindingsEnvironmentCache(): void {
  cached = undefined;
}
