// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { ChannelLambdaEnvironmentConfig } from '@asr/data-models';
import { MissingEnvironmentVariableError } from '../../common/utils/env-variables';
import {
  channelLambdaEnvironment,
  channelLambdaRuntimeEnvironment,
  resetChannelLambdaEnvironmentCache,
} from '../channelLambdaEnvironment';

const VALID_ENV: ChannelLambdaEnvironmentConfig = {
  SOLUTION_TRADEMARKEDNAME: 'ASR-Test',
  POWERTOOLS_LOG_LEVEL: 'INFO',
  AWS_ACCOUNT_ID: '123456789012',
  AWS_PARTITION: 'aws',
  STACK_ID: 'test-stack-id',
  RESOURCE_NAME_PREFIX: 'SO0111',
  WEB_UI_URL: 'https://d1234abcd.cloudfront.net',
  IAC_TEMPLATES_BUCKET: 'test-iac-templates-bucket',
};

const VALID_RUNTIME_ENV = {
  AWS_REGION: 'us-east-1',
} as const;

describe('channelLambdaEnvironment', () => {
  const originalEnv = process.env;

  beforeEach(() => {
    resetChannelLambdaEnvironmentCache();
    process.env = { ...originalEnv };
    for (const [key, value] of Object.entries(VALID_ENV)) {
      process.env[key] = value;
    }
    process.env.AWS_REGION = VALID_RUNTIME_ENV.AWS_REGION;
  });

  afterAll(() => {
    process.env = originalEnv;
  });

  it('should return all environment variables when present', () => {
    const env = channelLambdaEnvironment();
    expect(env).toEqual(VALID_ENV);
  });

  it('should cache the result on subsequent calls', () => {
    const first = channelLambdaEnvironment();
    process.env.SOLUTION_TRADEMARKEDNAME = 'changed';
    const second = channelLambdaEnvironment();
    expect(second).toBe(first);
  });

  it('should return fresh values after cache reset', () => {
    channelLambdaEnvironment();
    resetChannelLambdaEnvironmentCache();
    process.env.WEB_UI_URL = 'https://updated.cloudfront.net';
    const env = channelLambdaEnvironment();
    expect(env.WEB_UI_URL).toBe('https://updated.cloudfront.net');
  });

  it('should not throw when the optional WEB_UI_URL is missing', () => {
    delete process.env.WEB_UI_URL;
    const env = channelLambdaEnvironment();
    expect(env.WEB_UI_URL).toBeUndefined();
    expect(env.IAC_TEMPLATES_BUCKET).toBe('test-iac-templates-bucket');
  });

  it('should throw MissingEnvironmentVariableError when a required variable is missing', () => {
    delete process.env.IAC_TEMPLATES_BUCKET;
    expect(() => channelLambdaEnvironment()).toThrow(MissingEnvironmentVariableError);
  });

  it('should list all missing variables in the error', () => {
    delete process.env.IAC_TEMPLATES_BUCKET;
    delete process.env.AWS_PARTITION;
    try {
      channelLambdaEnvironment();
      fail('Expected MissingEnvironmentVariableError');
    } catch (error) {
      expect(error).toBeInstanceOf(MissingEnvironmentVariableError);
      const missing = (error as MissingEnvironmentVariableError).missingVariables;
      expect(missing).toContain('IAC_TEMPLATES_BUCKET');
      expect(missing).toContain('AWS_PARTITION');
      expect(missing).toHaveLength(2);
    }
  });
});

describe('channelLambdaRuntimeEnvironment', () => {
  const originalEnv = process.env;

  beforeEach(() => {
    resetChannelLambdaEnvironmentCache();
    process.env = { ...originalEnv };
    process.env.AWS_REGION = VALID_RUNTIME_ENV.AWS_REGION;
  });

  afterAll(() => {
    process.env = originalEnv;
  });

  it('should return AWS_REGION when present', () => {
    const env = channelLambdaRuntimeEnvironment();
    expect(env).toEqual(VALID_RUNTIME_ENV);
  });

  it('should cache the result on subsequent calls', () => {
    const first = channelLambdaRuntimeEnvironment();
    process.env.AWS_REGION = 'eu-west-1';
    const second = channelLambdaRuntimeEnvironment();
    expect(second).toBe(first);
    expect(second.AWS_REGION).toBe(VALID_RUNTIME_ENV.AWS_REGION);
  });

  it('should return fresh values after cache reset', () => {
    channelLambdaRuntimeEnvironment();
    resetChannelLambdaEnvironmentCache();
    process.env.AWS_REGION = 'eu-west-1';
    const env = channelLambdaRuntimeEnvironment();
    expect(env.AWS_REGION).toBe('eu-west-1');
  });

  it('should reset both config and runtime caches together', () => {
    const config = channelLambdaEnvironment();
    const runtime = channelLambdaRuntimeEnvironment();
    resetChannelLambdaEnvironmentCache();
    process.env.WEB_UI_URL = 'https://updated.cloudfront.net';
    process.env.AWS_REGION = 'eu-west-1';
    const newConfig = channelLambdaEnvironment();
    const newRuntime = channelLambdaRuntimeEnvironment();
    expect(newConfig).not.toBe(config);
    expect(newRuntime).not.toBe(runtime);
    expect(newConfig.WEB_UI_URL).toBe('https://updated.cloudfront.net');
    expect(newRuntime.AWS_REGION).toBe('eu-west-1');
  });

  it('should throw MissingEnvironmentVariableError when AWS_REGION is missing', () => {
    delete process.env.AWS_REGION;
    expect(() => channelLambdaRuntimeEnvironment()).toThrow(MissingEnvironmentVariableError);
  });

  it('should list AWS_REGION as the missing variable', () => {
    delete process.env.AWS_REGION;
    try {
      channelLambdaRuntimeEnvironment();
      fail('Expected MissingEnvironmentVariableError');
    } catch (error) {
      expect(error).toBeInstanceOf(MissingEnvironmentVariableError);
      const missing = (error as MissingEnvironmentVariableError).missingVariables;
      expect(missing).toEqual(['AWS_REGION']);
    }
  });
});
