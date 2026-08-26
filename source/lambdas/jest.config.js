// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

const { createDefaultPreset } = require('ts-jest');

const tsJestTransformCfg = createDefaultPreset().transform;

/** @type {import("jest").Config} **/
module.exports = {
  projects: [
    {
      testEnvironment: 'node',
      rootDir: './pre-processor',
      displayName: 'Pre-processor Unit Tests',
      transform: {
        ...tsJestTransformCfg,
      },
      testPathIgnorePatterns: ['<rootDir>/__tests__/jest.config.js', '<rootDir>/__tests__/fixtures/', '.*\\.d\\.ts$', '/__tests__/.*\\.js$'],
      setupFiles: ['<rootDir>/../common/__tests__/envSetup.ts'],
      setupFilesAfterEnv: ['<rootDir>/../common/__tests__/jestAfterEnvSetup.ts'],
    },
    {
      testEnvironment: 'node',
      rootDir: './common',
      displayName: 'Common Unit Tests',
      transform: {
        ...tsJestTransformCfg,
      },
      testPathIgnorePatterns: [
        '<rootDir>/__tests__/jest.dynamodb-local.config.js',
        '<rootDir>/__tests__/jestAfterEnvSetup.ts',
        '<rootDir>/__tests__/envSetup.ts',
        '<rootDir>/__tests__/dynamodbSetup.ts',
        '<rootDir>/__tests__/metricsMockSetup.ts',
        '<rootDir>/__tests__/metricsAutoMock.ts',
        '<rootDir>/__tests__/utils.ts',
        '.*\\.d\\.ts$',
        '/__tests__/.*\\.js$',
      ],
      setupFiles: ['<rootDir>/__tests__/envSetup.ts'],
      setupFilesAfterEnv: ['<rootDir>/__tests__/jestAfterEnvSetup.ts'],
    },
    {
      testEnvironment: 'node',
      displayName: 'API Unit Tests',
      rootDir: './api',
      collectCoverageFrom: [
        '**/*.ts',
        '!**/*.test.ts',
        '!**/*.spec.ts',
        '!**/__tests__/**',
        '!node_modules/**',
        '!jest.config.js',
        '!coverage/**',
      ],
      setupFiles: ['<rootDir>/../common/__tests__/envSetup.ts'],
      setupFilesAfterEnv: ['<rootDir>/../common/__tests__/jestAfterEnvSetup.ts'],
      transform: {
        ...tsJestTransformCfg,
      },
      testPathIgnorePatterns: ['<rootDir>/__tests__/utils.ts', '.*\\.d\\.ts$', '/__tests__/.*\\.js$'],
    },
    {
      testEnvironment: 'node',
      displayName: 'Synchronization Unit Tests',
      rootDir: './synchronization',
      transform: {
        ...tsJestTransformCfg,
      },
      testPathIgnorePatterns: ['.*\\.d\\.ts$', '/__tests__/.*\\.js$'],
      collectCoverageFrom: [
        '**/*.ts',
        '!**/*.test.ts',
        '!**/*.spec.ts',
        '!**/__tests__/**',
        '!node_modules/**',
        '!jest.config.js',
        '!coverage/**',
      ],
      setupFiles: ['<rootDir>/../common/__tests__/envSetup.ts'],
      setupFilesAfterEnv: ['<rootDir>/../common/__tests__/jestAfterEnvSetup.ts'],
    },
    {
      testEnvironment: 'node',
      displayName: 'IaC Template Sync Unit Tests',
      rootDir: './iac-template-sync',
      transform: {
        ...tsJestTransformCfg,
      },
      testPathIgnorePatterns: ['.*\\.d\\.ts$', '/__tests__/.*\\.js$'],
      collectCoverageFrom: [
        '**/*.ts',
        '!**/*.test.ts',
        '!**/*.spec.ts',
        '!**/__tests__/**',
        '!node_modules/**',
        '!coverage/**',
      ],
      setupFiles: ['<rootDir>/../common/__tests__/envSetup.ts'],
    },
    {
      testEnvironment: 'node',
      displayName: 'Notification Dispatcher Unit Tests',
      rootDir: './notification-dispatcher',
      transform: {
        ...tsJestTransformCfg,
      },
      testPathIgnorePatterns: ['.*\\.d\\.ts$', '/__tests__/.*\\.js$'],
      collectCoverageFrom: [
        '**/*.ts',
        '!**/*.test.ts',
        '!**/*.spec.ts',
        '!**/__tests__/**',
        '!node_modules/**',
        '!coverage/**',
      ],
      setupFiles: ['<rootDir>/../common/__tests__/envSetup.ts'],
      setupFilesAfterEnv: [
        '<rootDir>/../common/__tests__/jestAfterEnvSetup.ts',
        '<rootDir>/../common/__tests__/metricsAutoMock.ts',
      ],
    },
    {
      testEnvironment: 'node',
      displayName: 'Batch Processor Unit Tests',
      rootDir: './batch-processor',
      transform: {
        ...tsJestTransformCfg,
      },
      testPathIgnorePatterns: ['.*\\.d\\.ts$', '/__tests__/.*\\.js$'],
      collectCoverageFrom: [
        '**/*.ts',
        '!**/*.test.ts',
        '!**/*.spec.ts',
        '!**/__tests__/**',
        '!node_modules/**',
        '!coverage/**',
      ],
      setupFiles: ['<rootDir>/../common/__tests__/envSetup.ts'],
      setupFilesAfterEnv: [
        '<rootDir>/../common/__tests__/jestAfterEnvSetup.ts',
        '<rootDir>/../common/__tests__/metricsAutoMock.ts',
      ],
    },
    {
      testEnvironment: 'node',
      displayName: 'Baseline Configuration Unit Tests',
      rootDir: './baseline-configuration',
      transform: {
        ...tsJestTransformCfg,
      },
      collectCoverageFrom: [
        '**/*.ts',
        '!**/*.test.ts',
        '!**/*.spec.ts',
        '!**/__tests__/**',
        '!node_modules/**',
        '!coverage/**',
      ],
      setupFiles: ['<rootDir>/../common/__tests__/envSetup.ts'],
    },
    {
      testEnvironment: 'node',
      displayName: 'Notification Channels Unit Tests',
      rootDir: './notification-channels',
      transform: {
        ...tsJestTransformCfg,
      },
      testPathIgnorePatterns: ['<rootDir>/__tests__/test-factories.ts', '.*\\.d\\.ts$', '/__tests__/.*\\.js$'],
      collectCoverageFrom: [
        '**/*.ts',
        '!**/*.test.ts',
        '!**/*.spec.ts',
        '!**/__tests__/**',
        '!node_modules/**',
        '!coverage/**',
      ],
      setupFiles: ['<rootDir>/../common/__tests__/envSetup.ts'],
      setupFilesAfterEnv: ['<rootDir>/../common/__tests__/metricsAutoMock.ts'],
    },
  ],
  testTimeout: 10000,
  coverageReporters: ['text', 'lcov', 'html'],
};
