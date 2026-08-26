// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { BatchProcessorEnvironmentConfig } from '@asr/data-models';
import { MissingEnvironmentVariableError } from '../../common/utils/env-variables';
import { batchProcessorEnvironment, resetBatchProcessorEnvironmentCache } from '../batchProcessorEnvironment';

const VALID_ENV: BatchProcessorEnvironmentConfig = {
  SOLUTION_TRADEMARKEDNAME: 'ASR-Test',
  POWERTOOLS_SERVICE_NAME: 'batch_processor',
  POWERTOOLS_LOG_LEVEL: 'INFO',
  NOTIFICATION_CONFIG_TABLE_NAME: 'config-table',
  NOTIFICATION_BATCHES_TABLE_NAME: 'batches-table',
  RESOURCE_FILTERS_TABLE_NAME: 'resource-filters-table',
  FINDINGS_TABLE_NAME: 'findings-table',
  REMEDIATION_HISTORY_TABLE_NAME: 'history-table',
  AWS_ACCOUNT_ID: '123456789012',
  STACK_ID: 'test-stack-id',
  CHANNEL_FANOUT_TOPIC_ARN: 'arn:aws:sns:us-east-1:123456789012:fanout',
  CSV_EXPORT_BUCKET_NAME: 'test-csv-export-bucket',
  ORCHESTRATOR_ARN: 'arn:aws:states:us-east-1:123456789012:stateMachine:orchestrator',
  LAMBDA_TIMEOUT_SECONDS: '300',
  WEB_UI_URL: 'https://example.cloudfront.net',
};

describe('batchProcessorEnvironment', () => {
  const originalEnv = process.env;

  beforeEach(() => {
    resetBatchProcessorEnvironmentCache();
    process.env = { ...originalEnv };
    for (const [key, value] of Object.entries(VALID_ENV)) {
      process.env[key] = value;
    }
  });

  afterAll(() => {
    process.env = originalEnv;
  });

  it('should return all environment variables when present', () => {
    const env = batchProcessorEnvironment();
    expect(env).toEqual(VALID_ENV);
  });

  it('should cache the result on subsequent calls', () => {
    const first = batchProcessorEnvironment();
    process.env.SOLUTION_TRADEMARKEDNAME = 'changed-after-first-call';
    const second = batchProcessorEnvironment();
    expect(second).toBe(first);
  });

  it('should return fresh values after cache reset', () => {
    batchProcessorEnvironment();
    resetBatchProcessorEnvironmentCache();
    process.env.SOLUTION_TRADEMARKEDNAME = 'updated-value';
    const env = batchProcessorEnvironment();
    expect(env.SOLUTION_TRADEMARKEDNAME).toBe('updated-value');
  });

  it('should throw MissingEnvironmentVariableError when a required variable is missing', () => {
    delete process.env.ORCHESTRATOR_ARN;
    expect(() => batchProcessorEnvironment()).toThrow(MissingEnvironmentVariableError);
  });

  it('should not throw when optional ENFORCEMENT_PER_RUN_CAP is missing', () => {
    delete process.env.ENFORCEMENT_PER_RUN_CAP;
    expect(() => batchProcessorEnvironment()).not.toThrow();
  });

  it('should not throw when the optional WEB_UI_URL is missing (Web UI not deployed)', () => {
    delete process.env.WEB_UI_URL;
    const env = batchProcessorEnvironment();
    expect(env.WEB_UI_URL).toBeUndefined();
    // Required variables still resolve, so the processor keeps running.
    expect(env.CSV_EXPORT_BUCKET_NAME).toBe('test-csv-export-bucket');
  });

  it('should list all missing variables in the error', () => {
    delete process.env.FINDINGS_TABLE_NAME;
    delete process.env.CSV_EXPORT_BUCKET_NAME;
    try {
      batchProcessorEnvironment();
      fail('Expected MissingEnvironmentVariableError');
    } catch (error) {
      expect(error).toBeInstanceOf(MissingEnvironmentVariableError);
      const missing = (error as MissingEnvironmentVariableError).missingVariables;
      expect(missing).toContain('FINDINGS_TABLE_NAME');
      expect(missing).toContain('CSV_EXPORT_BUCKET_NAME');
      expect(missing).toHaveLength(2);
    }
  });
});
