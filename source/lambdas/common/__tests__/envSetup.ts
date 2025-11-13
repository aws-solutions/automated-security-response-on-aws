// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

export const findingsTableName = 'test-findings-table';
export const configTableName = 'test-config-table';
export const userAccountMappingTableName = 'test-user-account-mapping-table';
export const remediationHistoryTableName = 'test-remediation-history-table';
export const userPoolId = 'us-east-1_testpool';
export const mockAccountId = '123456789012';

// Set environment variables before any imports (jest setupFiles)
process.env.AWS_REGION = 'us-east-1';
process.env.FINDINGS_TABLE_NAME = findingsTableName;
process.env.USER_ACCOUNT_MAPPING_TABLE_NAME = userAccountMappingTableName;
process.env.REMEDIATION_HISTORY_TABLE_NAME = remediationHistoryTableName;
process.env.FINDINGS_TABLE_ARN = `arn:aws:dynamodb:us-east-1:123456789012:table/${findingsTableName}`;
process.env.REMEDIATION_CONFIG_TABLE_ARN = `arn:aws:dynamodb:us-east-1:123456789012:table/${configTableName}`;
process.env.REMEDIATION_HISTORY_TABLE_ARN = `arn:aws:dynamodb:us-east-1:123456789012:table/${remediationHistoryTableName}`;
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
