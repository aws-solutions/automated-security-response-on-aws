// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * Shared interface defining the environment variables passed from CDK to the
 * NotificationDispatcher Lambda. Both the CDK construct and the Lambda accessor
 * reference this type so the compiler catches any drift between the two sides.
 */
export interface NotificationDispatcherEnvironmentConfig {
  readonly SOLUTION_TRADEMARKEDNAME: string;
  readonly POWERTOOLS_SERVICE_NAME: string;
  readonly POWERTOOLS_LOG_LEVEL: string;
  readonly NOTIFICATION_CONFIG_TABLE_NAME: string;
  readonly NOTIFICATION_BATCHES_TABLE_NAME: string;
  readonly RESOURCE_FILTERS_TABLE_NAME?: string;
  readonly AWS_ACCOUNT_ID: string;
  readonly STACK_ID: string;
  readonly CHANNEL_FANOUT_TOPIC_ARN: string;
  readonly LAMBDA_TIMEOUT_SECONDS?: string;
}
