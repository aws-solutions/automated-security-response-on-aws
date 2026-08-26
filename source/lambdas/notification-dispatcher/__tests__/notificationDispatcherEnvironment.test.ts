// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { NotificationDispatcherEnvironmentConfig } from '@asr/data-models';
import { MissingEnvironmentVariableError } from '../../common/utils/env-variables';
import {
  notificationDispatcherEnvironment,
  resetNotificationDispatcherEnvironmentCache,
} from '../notificationDispatcherEnvironment';

const VALID_ENV: NotificationDispatcherEnvironmentConfig = {
  SOLUTION_TRADEMARKEDNAME: 'ASR-Test',
  POWERTOOLS_SERVICE_NAME: 'notification_dispatcher',
  POWERTOOLS_LOG_LEVEL: 'INFO',
  NOTIFICATION_CONFIG_TABLE_NAME: 'config-table',
  NOTIFICATION_BATCHES_TABLE_NAME: 'batches-table',
  RESOURCE_FILTERS_TABLE_NAME: 'resource-filters-table',
  AWS_ACCOUNT_ID: '123456789012',
  STACK_ID: 'test-stack-id',
  CHANNEL_FANOUT_TOPIC_ARN: 'arn:aws:sns:us-east-1:123456789012:fanout',
  LAMBDA_TIMEOUT_SECONDS: '300',
};

describe('notificationDispatcherEnvironment', () => {
  const originalEnv = process.env;

  beforeEach(() => {
    resetNotificationDispatcherEnvironmentCache();
    process.env = { ...originalEnv };
    for (const [key, value] of Object.entries(VALID_ENV)) {
      process.env[key] = value;
    }
  });

  afterAll(() => {
    process.env = originalEnv;
  });

  it('should return all environment variables when present', () => {
    const env = notificationDispatcherEnvironment();
    expect(env).toEqual(VALID_ENV);
  });

  it('should cache the result on subsequent calls', () => {
    const first = notificationDispatcherEnvironment();
    process.env.SOLUTION_TRADEMARKEDNAME = 'changed-after-first-call';
    const second = notificationDispatcherEnvironment();
    expect(second).toBe(first);
  });

  it('should return fresh values after cache reset', () => {
    notificationDispatcherEnvironment();
    resetNotificationDispatcherEnvironmentCache();
    process.env.SOLUTION_TRADEMARKEDNAME = 'updated-value';
    const env = notificationDispatcherEnvironment();
    expect(env.SOLUTION_TRADEMARKEDNAME).toBe('updated-value');
  });

  it('should throw MissingEnvironmentVariableError when a required variable is missing', () => {
    delete process.env.CHANNEL_FANOUT_TOPIC_ARN;
    expect(() => notificationDispatcherEnvironment()).toThrow(MissingEnvironmentVariableError);
  });

  it('should list all missing variables in the error', () => {
    delete process.env.CHANNEL_FANOUT_TOPIC_ARN;
    delete process.env.NOTIFICATION_CONFIG_TABLE_NAME;
    try {
      notificationDispatcherEnvironment();
      fail('Expected MissingEnvironmentVariableError');
    } catch (error) {
      expect(error).toBeInstanceOf(MissingEnvironmentVariableError);
      const missing = (error as MissingEnvironmentVariableError).missingVariables;
      expect(missing).toContain('CHANNEL_FANOUT_TOPIC_ARN');
      expect(missing).toContain('NOTIFICATION_CONFIG_TABLE_NAME');
      expect(missing).toHaveLength(2);
    }
  });
});
