// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { SSMClient, GetParameterCommand } from '@aws-sdk/client-ssm';
import { mockClient } from 'aws-sdk-client-mock';
import nock from 'nock';
import { clearSSMCache } from '../utils/ssmCache';

const ssmMock = mockClient(SSMClient);

export function setupMetricsMocks() {
  ssmMock.reset();
  nock.cleanAll();
  clearSSMCache();

  ssmMock
    .resolves({ Parameter: { Value: 'test-uuid' } })
    .on(GetParameterCommand, { Name: '/Solutions/SO0111/version' })
    .resolves({ Parameter: { Value: '1.0.0' } });

  nock('https://metrics.awssolutionsbuilder.com').post('/generic').reply(200).persist();
}

export function cleanupMetricsMocks() {
  nock.cleanAll();
}

export function createMetricsTestScope(bodyMatchExpression?: RegExp) {
  nock.cleanAll();
  return nock('https://metrics.awssolutionsbuilder.com').post('/generic', bodyMatchExpression).reply(200);
}

/**
 * Registers a persistent catch-all interceptor for the metrics endpoint. Use
 * after `createMetricsTestScope` when the code under test emits additional
 * metrics that are not the one being asserted, so those POSTs are absorbed
 * instead of failing with `Nock: No match`. Register this after the asserted
 * scope so the asserted scope retains first-match priority.
 */
export function allowOtherMetrics() {
  nock('https://metrics.awssolutionsbuilder.com').post('/generic').reply(200).persist();
}

export { ssmMock };
