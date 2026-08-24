// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { SynchronizationFindingsEnvironmentConfig } from '@asr/data-models';
import { MissingEnvironmentVariableError } from '../../common/utils/env-variables';
import {
  synchronizationFindingsEnvironment,
  resetSynchronizationFindingsEnvironmentCache,
} from '../synchronizationFindingsEnvironment';

const VALID_ENV: SynchronizationFindingsEnvironmentConfig = {
  SOLUTION_TRADEMARKEDNAME: 'ASR-Test',
  POWERTOOLS_SERVICE_NAME: 'synchronization_findings',
  POWERTOOLS_LOG_LEVEL: 'INFO',
  POWERTOOLS_LOGGER_LOG_EVENT: 'false',
  POWERTOOLS_TRACER_CAPTURE_RESPONSE: 'true',
  POWERTOOLS_TRACER_CAPTURE_ERROR: 'true',
  FINDINGS_TABLE_NAME: 'findings-table',
  REMEDIATION_CONFIG_TABLE_NAME: 'config-table',
  RESOURCE_FILTERS_TABLE_NAME: 'resource-filters-table',
  NOTIFICATION_CONFIG_TABLE_NAME: 'notification-config-table',
  FINDINGS_TTL_DAYS: '8',
  AWS_ACCOUNT_ID: '123456789012',
  STACK_ID: 'test-stack-id',
};

describe('synchronizationFindingsEnvironment', () => {
  const originalEnv = process.env;

  beforeEach(() => {
    resetSynchronizationFindingsEnvironmentCache();
    process.env = { ...originalEnv };
    for (const [key, value] of Object.entries(VALID_ENV)) {
      process.env[key] = value;
    }
  });

  afterAll(() => {
    process.env = originalEnv;
  });

  it('should return all environment variables when present', () => {
    const env = synchronizationFindingsEnvironment();
    expect(env).toEqual(VALID_ENV);
  });

  it('should cache the result on subsequent calls', () => {
    const first = synchronizationFindingsEnvironment();
    process.env.SOLUTION_TRADEMARKEDNAME = 'changed-after-first-call';
    const second = synchronizationFindingsEnvironment();
    expect(second).toBe(first);
  });

  it('should return fresh values after cache reset', () => {
    synchronizationFindingsEnvironment();
    resetSynchronizationFindingsEnvironmentCache();
    process.env.SOLUTION_TRADEMARKEDNAME = 'updated-value';
    const env = synchronizationFindingsEnvironment();
    expect(env.SOLUTION_TRADEMARKEDNAME).toBe('updated-value');
  });

  it('should throw MissingEnvironmentVariableError when a required variable is missing', () => {
    delete process.env.FINDINGS_TABLE_NAME;
    expect(() => synchronizationFindingsEnvironment()).toThrow(MissingEnvironmentVariableError);
  });

  it('should list all missing variables in the error', () => {
    delete process.env.FINDINGS_TABLE_NAME;
    delete process.env.REMEDIATION_CONFIG_TABLE_NAME;
    try {
      synchronizationFindingsEnvironment();
      fail('Expected MissingEnvironmentVariableError');
    } catch (error) {
      expect(error).toBeInstanceOf(MissingEnvironmentVariableError);
      const missing = (error as MissingEnvironmentVariableError).missingVariables;
      expect(missing).toContain('FINDINGS_TABLE_NAME');
      expect(missing).toContain('REMEDIATION_CONFIG_TABLE_NAME');
      expect(missing).toHaveLength(2);
    }
  });
});
