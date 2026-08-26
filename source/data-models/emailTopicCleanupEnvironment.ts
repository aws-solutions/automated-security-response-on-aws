// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * Shared interface defining the environment variables passed from CDK to the
 * EmailTopicCleanup Lambda. Both the CDK construct and the Lambda accessor
 * reference this type so the compiler catches any drift between the two sides.
 *
 * `POWERTOOLS_*` keys are part of the contract so the CDK `satisfies` check
 * stays exact (no `Record<string, string>` fallback that would let arbitrary
 * env vars slip through) and the runtime accessor validates their presence
 * alongside `TOPIC_PREFIX`.
 */
export interface EmailTopicCleanupEnvironmentConfig {
  readonly TOPIC_PREFIX: string;
  readonly POWERTOOLS_SERVICE_NAME: string;
  readonly POWERTOOLS_LOG_LEVEL: string;
}
