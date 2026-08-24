// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * Shared interface defining the environment variables passed from CDK to the
 * Pre-Processor Lambda. Both the CDK construct and the Lambda accessor reference
 * this type so the compiler catches any drift between the two sides.
 */
export interface PreProcessorEnvironmentConfig {
  readonly SOLUTION_TRADEMARKEDNAME: string;
  readonly POWERTOOLS_LOG_LEVEL: string;
  readonly FINDINGS_TABLE_NAME: string;
  readonly REMEDIATION_HISTORY_TABLE_NAME: string;
  readonly REMEDIATION_CONFIG_TABLE_NAME: string;
  readonly RESOURCE_FILTERS_TABLE_NAME: string;
  readonly NOTIFICATION_CONFIG_TABLE_NAME: string;
  readonly ORCHESTRATOR_ARN: string;
  readonly FINDINGS_TTL_DAYS: string;
  readonly HISTORY_TTL_DAYS: string;
  readonly AWS_ACCOUNT_ID: string;
  readonly STACK_ID: string;
  readonly NOTIFICATION_QUEUE_URL: string;
  // Optional tunables for the auto-remediation retry cap + cooldown. Absent in
  // deployments that have not set them; sensible defaults apply in that case.
  readonly MAX_REMEDIATION_ATTEMPTS?: string;
  readonly REMEDIATION_RETRY_COOLDOWN_MINUTES?: string;
}
