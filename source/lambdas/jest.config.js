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
      testPathIgnorePatterns: ['<rootDir>/__tests__/jest.config.js'],
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
        '<rootDir>/__tests__/metricsMockSetup.ts'
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
      testPathIgnorePatterns: ['<rootDir>/__tests__/utils.ts'],
    },
    {
      testEnvironment: 'node',
      displayName: 'Synchronization Unit Tests',
      rootDir: './synchronization',
      transform: {
        ...tsJestTransformCfg,
      },
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
  ],
  testTimeout: 10000,
  coverageReporters: ['text', 'lcov', 'html'],
};
