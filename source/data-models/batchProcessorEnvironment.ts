// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

export interface BatchProcessorEnvironmentConfig {
  readonly SOLUTION_TRADEMARKEDNAME: string;
  readonly POWERTOOLS_SERVICE_NAME: string;
  readonly POWERTOOLS_LOG_LEVEL: string;
  readonly NOTIFICATION_CONFIG_TABLE_NAME: string;
  readonly NOTIFICATION_BATCHES_TABLE_NAME: string;
  readonly RESOURCE_FILTERS_TABLE_NAME: string;
  readonly FINDINGS_TABLE_NAME: string;
  readonly REMEDIATION_HISTORY_TABLE_NAME: string;
  readonly AWS_ACCOUNT_ID: string;
  readonly STACK_ID: string;
  readonly CHANNEL_FANOUT_TOPIC_ARN: string;
  readonly CSV_EXPORT_BUCKET_NAME: string;
  readonly ORCHESTRATOR_ARN: string;
  readonly LAMBDA_TIMEOUT_SECONDS?: string;
  readonly WEB_UI_URL?: string;
  readonly ENFORCEMENT_PER_RUN_CAP?: string;
}
