// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { PreProcessorEnvironmentConfig } from '@asr/data-models';
import { MissingEnvironmentVariableError } from '../../common/utils/env-variables';
import { preProcessorEnvironment, resetPreProcessorEnvironmentCache } from '../preProcessorEnvironment';

const VALID_ENV: PreProcessorEnvironmentConfig = {
  SOLUTION_TRADEMARKEDNAME: 'ASR-Test',
  POWERTOOLS_LOG_LEVEL: 'INFO',
  FINDINGS_TABLE_NAME: 'test-findings-table',
  REMEDIATION_HISTORY_TABLE_NAME: 'test-remediation-history-table',
  REMEDIATION_CONFIG_TABLE_NAME: 'test-remediation-config-table',
  RESOURCE_FILTERS_TABLE_NAME: 'test-resource-filters-table',
  NOTIFICATION_CONFIG_TABLE_NAME: 'test-notification-config-table',
  ORCHESTRATOR_ARN: 'arn:aws:states:us-east-1:123456789012:stateMachine:orchestrator',
  FINDINGS_TTL_DAYS: '8',
  HISTORY_TTL_DAYS: '90',
  AWS_ACCOUNT_ID: '123456789012',
  STACK_ID: 'test-stack-id',
  NOTIFICATION_QUEUE_URL: 'https://sqs.us-east-1.amazonaws.com/123456789012/test-notification-queue',
};

describe('preProcessorEnvironment', () => {
  const originalEnv = process.env;

  beforeEach(() => {
    resetPreProcessorEnvironmentCache();
    process.env = { ...originalEnv };
    for (const [key, value] of Object.entries(VALID_ENV)) {
      process.env[key] = value;
    }
  });

  afterAll(() => {
    process.env = originalEnv;
  });

  it('should return all environment variables when present', () => {
    const env = preProcessorEnvironment();
    expect(env).toEqual(VALID_ENV);
  });

  it('should cache the result on subsequent calls', () => {
    const first = preProcessorEnvironment();
    process.env.SOLUTION_TRADEMARKEDNAME = 'changed';
    const second = preProcessorEnvironment();
    expect(second).toBe(first);
  });

  it('should return fresh values after cache reset', () => {
    preProcessorEnvironment();
    resetPreProcessorEnvironmentCache();
    process.env.FINDINGS_TABLE_NAME = 'updated-findings-table';
    const env = preProcessorEnvironment();
    expect(env.FINDINGS_TABLE_NAME).toBe('updated-findings-table');
  });

  it('should throw MissingEnvironmentVariableError when a required variable is missing', () => {
    delete process.env.NOTIFICATION_QUEUE_URL;
    expect(() => preProcessorEnvironment()).toThrow(MissingEnvironmentVariableError);
  });

  it('should list all missing variables in the error', () => {
    delete process.env.NOTIFICATION_QUEUE_URL;
    delete process.env.FINDINGS_TABLE_NAME;
    try {
      preProcessorEnvironment();
      fail('Expected MissingEnvironmentVariableError');
    } catch (error) {
      expect(error).toBeInstanceOf(MissingEnvironmentVariableError);
      const missing = (error as MissingEnvironmentVariableError).missingVariables;
      expect(missing).toContain('NOTIFICATION_QUEUE_URL');
      expect(missing).toContain('FINDINGS_TABLE_NAME');
      expect(missing).toHaveLength(2);
    }
  });
});
