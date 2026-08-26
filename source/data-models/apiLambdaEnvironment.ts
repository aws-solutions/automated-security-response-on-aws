// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * Shared interface defining the environment variables passed from CDK to the
 * API Lambda. Both the CDK construct and the Lambda accessor reference this
 * type so the compiler catches any drift between the two sides.
 */
export interface ApiLambdaEnvironmentConfig {
  readonly SOLUTION_ID: string;
  readonly SOLUTION_VERSION: string;
  readonly SOLUTION_TRADEMARKEDNAME: string;
  readonly POWERTOOLS_LOG_LEVEL: string;
  readonly USER_POOL_ID: string;
  readonly USER_ACCOUNT_MAPPING_TABLE_NAME: string;
  readonly FINDINGS_TABLE_NAME: string;
  readonly REMEDIATION_HISTORY_TABLE_NAME: string;
  readonly REMEDIATION_CONFIG_TABLE_NAME: string;
  readonly RESOURCE_FILTERS_TABLE_NAME: string;
  readonly CSV_EXPORT_BUCKET_NAME: string;
  readonly PRESIGNED_URL_TTL_DAYS: string;
  readonly ORCHESTRATOR_ARN: string;
  readonly WEB_UI_URL: string;
  readonly AWS_ACCOUNT_ID: string;
  readonly STACK_ID: string;
  readonly SECURITY_HUB_V2_ENABLED: string;
  readonly EXPORT_MAX_TIME_MS: string;
  readonly EXPORT_MAX_RECORDS: string;
  readonly NOTIFICATION_CONFIG_TABLE_NAME: string;
  readonly AWS_PARTITION: string;
  readonly RESOURCE_NAME_PREFIX: string;
  readonly IAC_TEMPLATES_BUCKET: string;
  readonly ADMIN_NOTIFICATION_TOPIC_ARN: string;
  /**
   * Name of the NotificationBatches table, where reconciliation tasks are written when enforcement
   * settings change. Optional because not every deployment grants the API Lambda access to this
   * table; the service skips reconciliation gracefully when it is absent.
   */
  readonly NOTIFICATION_BATCHES_TABLE_NAME?: string;
}
