// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * Shared interface defining the environment variables passed from CDK to the
 * SynchronizationFindings Lambda. Both the CDK construct and the Lambda accessor
 * reference this type so the compiler catches any drift between the two sides.
 */
export interface SynchronizationFindingsEnvironmentConfig {
  readonly SOLUTION_TRADEMARKEDNAME: string;
  readonly POWERTOOLS_SERVICE_NAME: string;
  readonly POWERTOOLS_LOG_LEVEL: string;
  readonly POWERTOOLS_LOGGER_LOG_EVENT: string;
  readonly POWERTOOLS_TRACER_CAPTURE_RESPONSE: string;
  readonly POWERTOOLS_TRACER_CAPTURE_ERROR: string;
  readonly FINDINGS_TABLE_NAME: string;
  readonly REMEDIATION_CONFIG_TABLE_NAME: string;
  readonly RESOURCE_FILTERS_TABLE_NAME: string;
  readonly NOTIFICATION_CONFIG_TABLE_NAME: string;
  readonly FINDINGS_TTL_DAYS: string;
  readonly AWS_ACCOUNT_ID: string;
  readonly STACK_ID: string;
}
