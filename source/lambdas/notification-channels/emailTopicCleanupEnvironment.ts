// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { EmailTopicCleanupEnvironmentConfig } from '@asr/data-models';
import { requireEnvironmentVariables } from '../common/utils/env-variables';

let cached: EmailTopicCleanupEnvironmentConfig | undefined;

const REQUIRED_KEYS: readonly (keyof EmailTopicCleanupEnvironmentConfig)[] = [
  'TOPIC_PREFIX',
  'POWERTOOLS_SERVICE_NAME',
  'POWERTOOLS_LOG_LEVEL',
] as const;

/**
 * Reads, validates, and caches the environment variables required by the
 * EmailTopicCleanup Lambda.
 *
 * Called lazily on first use (via `EmailTopicCleanupHandler.getTopicPrefix()`),
 * NOT at module load. CloudFormation custom resource handlers must always be
 * able to send a response — if a missing env var threw at import time, the
 * Lambda would fail to initialize and CloudFormation would never receive the
 * response, leaving the stack stuck until timeout.
 *
 * Subsequent calls return the cached result. Throws
 * {@link MissingEnvironmentVariableError} listing every missing key.
 */
export function emailTopicCleanupEnvironment(): EmailTopicCleanupEnvironmentConfig {
  if (cached) return cached;
  cached = requireEnvironmentVariables(REQUIRED_KEYS);
  return cached;
}

/** Clears the cached config. Useful in tests to re-initialize with different values. */
export function resetEmailTopicCleanupEnvironmentCache(): void {
  cached = undefined;
}
