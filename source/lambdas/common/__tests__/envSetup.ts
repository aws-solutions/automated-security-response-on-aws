// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

export const findingsTableName = 'test-findings-table';
export const configTableName = 'test-config-table';
export const remediationConfigTableName = 'test-remediation-config-table';
export const resourceFiltersTableName = 'test-resource-filters-table';
export const userAccountMappingTableName = 'test-user-account-mapping-table';
export const remediationHistoryTableName = 'test-remediation-history-table';
export const notificationBatchesTableName = 'test-notification-batches-table';
export const notificationConfigTableName = 'test-notification-config-table';
export const channelFanoutTopicArn = 'arn:aws:sns:us-east-1:123456789012:channel-fanout';
export const userPoolId = 'us-east-1_testpool';
export const mockAccountId = '123456789012';

// Set environment variables before any imports (jest setupFiles)
process.env.AWS_REGION = 'us-east-1';
process.env.FINDINGS_TABLE_NAME = findingsTableName;
process.env.USER_ACCOUNT_MAPPING_TABLE_NAME = userAccountMappingTableName;
process.env.REMEDIATION_HISTORY_TABLE_NAME = remediationHistoryTableName;
process.env.REMEDIATION_CONFIG_TABLE_NAME = remediationConfigTableName;
process.env.RESOURCE_FILTERS_TABLE_NAME = resourceFiltersTableName;
process.env.ORCHESTRATOR_ARN = 'arn:aws:states:us-east-1:123456789012:stateMachine:orchestrator';
process.env.SOLUTION_TRADEMARKEDNAME = 'ASR-Test';
process.env.DYNAMODB_ENDPOINT = 'http://127.0.0.1:8000';
process.env.USER_POOL_ID = 'us-east-1_testpool';
process.env.LOG_LEVEL = 'debug';
process.env.AWS_REGION = 'us-east-1';
process.env.AWS_ACCESS_KEY_ID = 'fakeMyKeyId';
process.env.AWS_SECRET_ACCESS_KEY = 'fakeSecretAccessKey';
process.env.AWS_SECURITY_TOKEN = 'testing';
process.env.AWS_SESSION_TOKEN = 'testing';
process.env.SOLUTION_VERSION = 'v1.0.0';
process.env.FINDINGS_TTL_DAYS = '8';
process.env.WEB_UI_URL = 'https://d1234abcd.cloudfront.net';
process.env.CSV_EXPORT_BUCKET_NAME = 'test-csv-export-bucket';
process.env.PRESIGNED_URL_TTL_DAYS = '1';
process.env.AWS_ACCOUNT_ID = mockAccountId;
process.env.STACK_ID = 'test-stack-id';
process.env.NOTIFICATION_CONFIG_TABLE_NAME = notificationConfigTableName;
process.env.NOTIFICATION_BATCHES_TABLE_NAME = notificationBatchesTableName;
process.env.CHANNEL_FANOUT_TOPIC_ARN = channelFanoutTopicArn;
process.env.LAMBDA_TIMEOUT_SECONDS = '300';
process.env.POWERTOOLS_SERVICE_NAME = 'notification_dispatcher';
process.env.POWERTOOLS_LOG_LEVEL = 'INFO';
process.env.POWERTOOLS_LOGGER_LOG_EVENT = 'false';
process.env.POWERTOOLS_TRACER_CAPTURE_RESPONSE = 'true';
process.env.POWERTOOLS_TRACER_CAPTURE_ERROR = 'true';
process.env.SOLUTION_ID = 'SO0111';
process.env.SECURITY_HUB_V2_ENABLED = 'false';
process.env.EXPORT_MAX_TIME_MS = '26000';
process.env.EXPORT_MAX_RECORDS = '50000';
process.env.NOTIFICATION_QUEUE_URL = 'https://sqs.us-east-1.amazonaws.com/123456789012/test-notification-queue';
process.env.HISTORY_TTL_DAYS = '90';
process.env.AWS_PARTITION = 'aws';
process.env.RESOURCE_NAME_PREFIX = 'SO0111';
process.env.IAC_TEMPLATES_BUCKET = 'test-iac-templates-bucket';
process.env.ADMIN_NOTIFICATION_TOPIC_ARN = 'arn:aws:sns:us-east-1:123456789012:SO0111-ASR-AdminSecurityNotifications';
