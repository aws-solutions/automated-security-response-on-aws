// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { ApiLambdaEnvironmentConfig } from '@asr/data-models';
import { MissingEnvironmentVariableError } from '../../common/utils/env-variables';
import { apiLambdaEnvironment, resetApiLambdaEnvironmentCache } from '../apiLambdaEnvironment';

const VALID_ENV: ApiLambdaEnvironmentConfig = {
  SOLUTION_ID: 'SO0111',
  SOLUTION_VERSION: 'v1.0.0',
  SOLUTION_TRADEMARKEDNAME: 'ASR-Test',
  POWERTOOLS_LOG_LEVEL: 'INFO',
  USER_POOL_ID: 'us-east-1_testpool',
  USER_ACCOUNT_MAPPING_TABLE_NAME: 'test-user-account-mapping-table',
  FINDINGS_TABLE_NAME: 'test-findings-table',
  REMEDIATION_HISTORY_TABLE_NAME: 'test-remediation-history-table',
  REMEDIATION_CONFIG_TABLE_NAME: 'test-remediation-config-table',
  RESOURCE_FILTERS_TABLE_NAME: 'test-resource-filters-table',
  CSV_EXPORT_BUCKET_NAME: 'test-csv-export-bucket',
  PRESIGNED_URL_TTL_DAYS: '1',
  ORCHESTRATOR_ARN: 'arn:aws:states:us-east-1:123456789012:stateMachine:orchestrator',
  WEB_UI_URL: 'https://d1234abcd.cloudfront.net',
  AWS_ACCOUNT_ID: '123456789012',
  STACK_ID: 'test-stack-id',
  SECURITY_HUB_V2_ENABLED: 'false',
  EXPORT_MAX_TIME_MS: '26000',
  EXPORT_MAX_RECORDS: '50000',
  NOTIFICATION_CONFIG_TABLE_NAME: 'test-notification-config-table',
  AWS_PARTITION: 'aws',
  RESOURCE_NAME_PREFIX: 'SO0111',
  IAC_TEMPLATES_BUCKET: 'test-iac-templates-bucket',
  ADMIN_NOTIFICATION_TOPIC_ARN: 'arn:aws:sns:us-east-1:123456789012:SO0111-ASR-AdminSecurityNotifications',
  NOTIFICATION_BATCHES_TABLE_NAME: 'test-notification-batches-table',
};

describe('apiLambdaEnvironment', () => {
  const originalEnv = process.env;

  beforeEach(() => {
    resetApiLambdaEnvironmentCache();
    process.env = { ...originalEnv };
    for (const [key, value] of Object.entries(VALID_ENV)) {
      process.env[key] = value;
    }
  });

  afterAll(() => {
    process.env = originalEnv;
  });

  it('should return all environment variables when present', () => {
    const env = apiLambdaEnvironment();
    expect(env).toEqual(VALID_ENV);
  });

  it('should omit the optional NOTIFICATION_BATCHES_TABLE_NAME when it is not set', () => {
    delete process.env.NOTIFICATION_BATCHES_TABLE_NAME;
    const env = apiLambdaEnvironment();
    expect(env.NOTIFICATION_BATCHES_TABLE_NAME).toBeUndefined();
    // Required variables remain present, so the accessor does not throw for an absent optional key.
    expect(env.FINDINGS_TABLE_NAME).toBe('test-findings-table');
  });

  it('should cache the result on subsequent calls', () => {
    const first = apiLambdaEnvironment();
    process.env.SOLUTION_ID = 'changed';
    const second = apiLambdaEnvironment();
    expect(second).toBe(first);
  });

  it('should return fresh values after cache reset', () => {
    apiLambdaEnvironment();
    resetApiLambdaEnvironmentCache();
    process.env.WEB_UI_URL = 'https://updated.cloudfront.net';
    const env = apiLambdaEnvironment();
    expect(env.WEB_UI_URL).toBe('https://updated.cloudfront.net');
  });

  it('should throw MissingEnvironmentVariableError when a required variable is missing', () => {
    delete process.env.WEB_UI_URL;
    expect(() => apiLambdaEnvironment()).toThrow(MissingEnvironmentVariableError);
  });

  it('should list all missing variables in the error', () => {
    delete process.env.WEB_UI_URL;
    delete process.env.FINDINGS_TABLE_NAME;
    try {
      apiLambdaEnvironment();
      fail('Expected MissingEnvironmentVariableError');
    } catch (error) {
      expect(error).toBeInstanceOf(MissingEnvironmentVariableError);
      const missing = (error as MissingEnvironmentVariableError).missingVariables;
      expect(missing).toContain('WEB_UI_URL');
      expect(missing).toContain('FINDINGS_TABLE_NAME');
      expect(missing).toHaveLength(2);
    }
  });
});
