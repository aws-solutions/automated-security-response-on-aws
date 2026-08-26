// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { NotificationDispatcherEnvironmentConfig } from '@asr/data-models';
import { requireEnvironmentVariables } from '../common/utils/env-variables';

let cached: NotificationDispatcherEnvironmentConfig | undefined;

const REQUIRED_KEYS: readonly (keyof NotificationDispatcherEnvironmentConfig)[] = [
  'SOLUTION_TRADEMARKEDNAME',
  'POWERTOOLS_SERVICE_NAME',
  'POWERTOOLS_LOG_LEVEL',
  'NOTIFICATION_CONFIG_TABLE_NAME',
  'NOTIFICATION_BATCHES_TABLE_NAME',
  'RESOURCE_FILTERS_TABLE_NAME',
  'AWS_ACCOUNT_ID',
  'STACK_ID',
  'CHANNEL_FANOUT_TOPIC_ARN',
  'LAMBDA_TIMEOUT_SECONDS',
] as const;

/**
 * Reads, validates, and caches the environment variables required by the
 * NotificationDispatcher Lambda. Call once at module load; subsequent calls
 * return the cached result. Throws on the first missing required variable.
 */
export function notificationDispatcherEnvironment(): NotificationDispatcherEnvironmentConfig {
  if (cached) return cached;
  cached = requireEnvironmentVariables(REQUIRED_KEYS);
  return cached;
}

/** Clears the cached config. Useful in tests to re-initialize with different values. */
export function resetNotificationDispatcherEnvironmentCache(): void {
  cached = undefined;
}
