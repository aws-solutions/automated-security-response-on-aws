// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { emitMetric, ASR_METRIC_NAMESPACE } from '../utils/cloudWatchMetrics';
import { Clock } from '../utils/clock';

interface EmfMetricDirective {
  Namespace: string;
  Dimensions: string[][];
  Metrics: { Name: string; Unit?: string }[];
}

interface EmfDocument {
  _aws: { Timestamp: number; CloudWatchMetrics: EmfMetricDirective[] };
  [key: string]: unknown;
}

// Fixed clock injected for a deterministic EMF timestamp.
const mockNow = new Date('2026-01-01T00:00:00.000Z');
const fixedClock: Clock = { now: () => mockNow };

describe('emitMetric', () => {
  let writeSpy: jest.SpyInstance;

  beforeEach(() => {
    writeSpy = jest.spyOn(process.stdout, 'write').mockImplementation(() => true);
  });

  afterEach(() => {
    writeSpy.mockRestore();
  });

  function lastEmfDocument(): EmfDocument {
    return JSON.parse((writeSpy.mock.calls[writeSpy.mock.calls.length - 1][0] as string).trim());
  }

  it('writes a valid EMF document with the dimension, value, namespace, and timestamp', () => {
    // ARRANGE / ACT
    emitMetric('RateLimitThrottled', 1, [{ name: 'Tier', value: 'critical' }], 'Count', fixedClock);

    // ASSERT
    expect(writeSpy).toHaveBeenCalledTimes(1);
    const doc = lastEmfDocument();
    const directive = doc._aws.CloudWatchMetrics[0];
    expect(doc._aws.Timestamp).toBe(mockNow.getTime());
    expect(directive.Namespace).toBe(ASR_METRIC_NAMESPACE);
    expect(directive.Dimensions).toEqual([['Tier']]);
    expect(directive.Metrics).toEqual([{ Name: 'RateLimitThrottled', Unit: 'Count' }]);
    expect(doc.Tier).toBe('critical');
    expect(doc.RateLimitThrottled).toBe(1);
  });

  it('publishes a dimensionless metric with an empty dimension set', () => {
    // ARRANGE / ACT
    emitMetric('RateLimiterError', 1);

    // ASSERT: [[]] publishes the metric with no dimensions
    const doc = lastEmfDocument();
    expect(doc._aws.CloudWatchMetrics[0].Dimensions).toEqual([[]]);
    expect(doc.RateLimiterError).toBe(1);
  });

  it('never throws and logs to stderr when the underlying write fails', () => {
    // ARRANGE
    const consoleErrorSpy = jest.spyOn(console, 'error').mockImplementation(() => undefined);
    writeSpy.mockImplementation(() => {
      throw new Error('stdout closed');
    });

    // ACT / ASSERT
    expect(() => emitMetric('RateLimiterError', 1)).not.toThrow();
    expect(consoleErrorSpy).toHaveBeenCalledWith('Failed to emit metric RateLimiterError', expect.any(Error));

    consoleErrorSpy.mockRestore();
  });
});
