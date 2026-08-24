// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { readOptionalEnvironmentVariables } from '../common/utils/env-variables';

/**
 * Environment variables for the SynchronizationTrigger custom-resource Lambda (ADR 0005: typed,
 * validated access — no raw `process.env` reads in handler code).
 *
 * `SYNCHRONIZATION_STATE_MACHINE_ARN` is optional by contract: when it is absent the trigger simply
 * skips starting the initial sweep (the weekly scheduled rule still drives synchronization), so it is
 * read via {@link readOptionalEnvironmentVariables} rather than the throwing accessor. The value is
 * read fresh on each call (not cached) because the handler reads it per invocation.
 */
export interface SynchronizationTriggerEnvironmentConfig {
  readonly SYNCHRONIZATION_STATE_MACHINE_ARN?: string;
}

const OPTIONAL_KEYS = ['SYNCHRONIZATION_STATE_MACHINE_ARN'] as const;

/** Reads and types the SynchronizationTrigger Lambda's environment variables. */
export function synchronizationTriggerEnvironment(): SynchronizationTriggerEnvironmentConfig {
  return readOptionalEnvironmentVariables(OPTIONAL_KEYS);
}
