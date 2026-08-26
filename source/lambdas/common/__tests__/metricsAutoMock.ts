// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Auto-mocks sendMetrics for test suites whose code emits SolutionsMetrics usage
// metrics (notification dispatcher, batch processor, notification channels).
// This keeps unit tests off the network: sendMetrics never reaches SSM or the
// SolutionsMetrics HTTP endpoint. Tests that assert metric emission import
// { sendMetrics } from the metricsUtils module and inspect the jest mock.
jest.mock('../utils/metricsUtils', () => {
  const actual = jest.requireActual('../utils/metricsUtils');
  return {
    __esModule: true,
    ...actual,
    sendMetrics: jest.fn().mockResolvedValue(undefined),
  };
});
