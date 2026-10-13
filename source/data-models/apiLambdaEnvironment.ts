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
  /**
   * Base URL of the hosted Web UI, used only to build deep links in
   * notifications and CSV exports. Optional because an MCP-only deployment
   * (ShouldDeployWebUI=no) has no frontend and passes it empty; every consumer
   * omits the link when it is falsy.
   */
  readonly WEB_UI_URL?: string;
  readonly AWS_ACCOUNT_ID: string;
  readonly AWS_PARTITION: string;
  readonly STACK_ID: string;
  readonly SECURITY_HUB_V2_ENABLED: string;
  readonly EXPORT_MAX_TIME_MS: string;
  readonly EXPORT_MAX_RECORDS: string;
  readonly NOTIFICATION_CONFIG_TABLE_NAME: string;
  readonly RESOURCE_NAME_PREFIX: string;
  readonly IAC_TEMPLATES_BUCKET: string;
  readonly ADMIN_NOTIFICATION_TOPIC_ARN: string;
  readonly CUSTOM_RUNBOOK_BUCKET_NAME?: string;
  readonly CUSTOM_RUNBOOK_TABLE_NAME?: string;
  /**
   * Enables the drift-detection developer fast-loop (`push`/`execute`), which
   * writes directly to a member account outside the versioned register/deploy
   * path. Absent/`"false"` (the production default) refuses those writes; a
   * non-production deployment sets it to `"true"` to opt in. A single on/off
   * flag rather than an account list so there is nothing for a customer to keep
   * up to date.
   */
  readonly CUSTOM_RUNBOOK_DEV_LOOP_ENABLED?: string;
  readonly ENABLE_ROLLBACK: string;
  readonly FINDINGS_TTL_DAYS: string;
  /** Exact "true" when the optional MCP stack is deployed. */
  readonly MCP_ENABLED?: string;
  /**
   * Name of the NotificationBatches table, where reconciliation tasks are written when enforcement
   * settings change. Optional because not every deployment grants the API Lambda access to this
   * table; the service skips reconciliation gracefully when it is absent.
   */
  readonly NOTIFICATION_BATCHES_TABLE_NAME?: string;
}
