// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import react from '@vitejs/plugin-react-swc';
import { resolve } from 'path';
import { defineConfig, UserConfig } from 'vite';
import { CoverageV8Options, UserConfig as VitestUserConfig } from 'vitest/node';

const coverageConfig: { provider: 'v8' } & CoverageV8Options = {
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
  ],
};

// https://vitejs.dev/config/
const config: VitestUserConfig & UserConfig = {
  test: {
    globals: true, // makes describe, it, expect available without import
    environment: 'jsdom',
    setupFiles: ['./src/setupTests.ts'], // runs this file before all tests
    include: ['./src/__tests__/**/*.test.ts?(x)'],
    coverage: coverageConfig,
    maxConcurrency: 1, // set to 1 to run tests serially, one file at a time
    testTimeout: 25000, // 25s test timeout unless specified otherwise in the test suite
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
