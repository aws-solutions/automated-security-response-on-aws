// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { BatchProcessorEnvironmentConfig } from '@asr/data-models';
import { readOptionalEnvironmentVariables, requireEnvironmentVariables } from '../common/utils/env-variables';

let cached: BatchProcessorEnvironmentConfig | undefined;

const REQUIRED_KEYS: readonly (keyof BatchProcessorEnvironmentConfig)[] = [
  'SOLUTION_TRADEMARKEDNAME',
  'POWERTOOLS_SERVICE_NAME',
  'POWERTOOLS_LOG_LEVEL',
  'NOTIFICATION_CONFIG_TABLE_NAME',
  'NOTIFICATION_BATCHES_TABLE_NAME',
  'RESOURCE_FILTERS_TABLE_NAME',
  'FINDINGS_TABLE_NAME',
  'REMEDIATION_HISTORY_TABLE_NAME',
  'AWS_ACCOUNT_ID',
  'STACK_ID',
  'CHANNEL_FANOUT_TOPIC_ARN',
  'CSV_EXPORT_BUCKET_NAME',
  'ORCHESTRATOR_ARN',
  'LAMBDA_TIMEOUT_SECONDS',
] as const;

const OPTIONAL_KEYS = ['WEB_UI_URL'] as const;

/**
 * Reads, validates, and caches the environment variables required by the
 * BatchProcessor Lambda. Throws on the first missing required variable.
 * WEB_UI_URL is optional and absent when the Web UI is not deployed.
 */
export function batchProcessorEnvironment(): BatchProcessorEnvironmentConfig {
  if (cached) return cached;
  cached = {
    ...requireEnvironmentVariables(REQUIRED_KEYS),
    ...readOptionalEnvironmentVariables(OPTIONAL_KEYS),
  };
  return cached;
}

/** Clears the cached config. Useful in tests to re-initialize with different values. */
export function resetBatchProcessorEnvironmentCache(): void {
  cached = undefined;
}
