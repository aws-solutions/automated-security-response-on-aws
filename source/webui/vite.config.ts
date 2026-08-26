// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import react from '@vitejs/plugin-react-swc';
import { resolve } from 'path';
import { defineConfig } from 'vite';
import { CoverageOptions } from 'vitest/node';

const coverageConfig: { provider: 'v8' } & CoverageOptions = {
  provider: 'v8',
  enabled: true,
  reportsDirectory: resolve(__dirname, './coverage'),
  reporter: ['text', 'html', 'lcov'],
  exclude: [
    './src/mocks/**',
    './src/main.tsx',
    './src/setupTests.ts',
    './public/mockServiceWorker.js',
    './dist/**',
    './index.html',
    './vite.config.ts',
    './src/utils/constants.ts',
  ],
};

// https://vitejs.dev/config/
const config = {
  test: {
    globals: true, // makes describe, it, expect available without import
    environment: 'jsdom',
    setupFiles: ['./src/setupTests.ts'], // runs this file before all tests
    include: ['./src/__tests__/**/*.test.ts?(x)'],
    coverage: coverageConfig,
    maxConcurrency: 1, // at most one test at a time within a single file
    fileParallelism: false, // run test files serially: the render-heavy findings-table integration tests otherwise starve each other of CPU under coverage and time out
    testTimeout: 60000, // 60s ceiling for the render-heavy findings-table integration tests under coverage
    silent: true, // suppress console output during tests
  },
  plugins: [react()],
  server: {
    port: 3000,
  },
  build: {
    outDir: resolve(__dirname, './dist'),
  },
  resolve: {
    alias: {
      '@data-models': resolve(__dirname, '../data-models/index.ts'),
    },
  },
  define: {
    global: 'globalThis',
  },
};
export default defineConfig(config);
