// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { ProvisionedThroughputExceededException } from '@aws-sdk/client-dynamodb';
import { LimitExceededException, ThrottlingException } from '@aws-sdk/client-securityhub';
import { InvalidArn } from '@aws-sdk/client-sfn';
import { computeThrottleVisibilityDelaySeconds, isThrottle, parseReceiveCount } from '../throttleBackoff';

describe('isThrottle', () => {
  it('is true for Security Hub and DynamoDB throttles, other throttling error names, and HTTP 429', () => {
    // ARRANGE
    const throttles: unknown[] = [
      new LimitExceededException({ message: 'Rate exceeded', $metadata: { httpStatusCode: 429 } }),
      new ThrottlingException({ message: 'Rate exceeded', $metadata: {} }),
      new ProvisionedThroughputExceededException({ message: 'Throughput exceeded', $metadata: {} }),
      Object.assign(new Error('Too many requests'), { name: 'TooManyRequestsException' }),
      Object.assign(new Error('Slow down'), { $metadata: { httpStatusCode: 429 } }),
    ];

    // ACT
    const results = throttles.map(isThrottle);

    // ASSERT
    expect(results).toEqual([true, true, true, true, true]);
  });

  it('is false for a non-throttle error and for values that are not errors', () => {
    // ARRANGE
    const notThrottles: unknown[] = [
      new InvalidArn({ message: 'bad arn', $metadata: { httpStatusCode: 400 } }),
      new Error('boom'),
      null,
      undefined,
      'ThrottlingException',
    ];

    // ACT
    const results = notThrottles.map(isThrottle);

    // ASSERT
    expect(results).toEqual([false, false, false, false, false]);
  });

  it('classifies an error that carries a cause only when the cause is itself an Error', () => {
    // ARRANGE: both are throttles by name; only the cause differs
    const withErrorCause = Object.assign(new Error('Rate exceeded', { cause: new Error('socket') }), {
      name: 'ThrottlingException',
    });
    const withNonErrorCause = Object.assign(new Error('Rate exceeded', { cause: 'socket' }), {
      name: 'ThrottlingException',
    });

    // ACT
    const results = [withErrorCause, withNonErrorCause].map(isThrottle);

    // ASSERT
    expect(results).toEqual([true, false]);
  });
});

describe('computeThrottleVisibilityDelaySeconds', () => {
  it('rounds the jittered delay down to whole seconds', () => {
    // ARRANGE: a random value of 0.46 gives a jitter factor of 0.73, and 30 x 0.73 is 21.9
    const randomValue = 0.46;

    // ACT
    const delay = computeThrottleVisibilityDelaySeconds(1, randomValue);

    // ASSERT
    expect(delay).toBe(21);
  });

  it('doubles the delay with each receive until it reaches the 900-second cap', () => {
    // ARRANGE: a random value of 0 gives the smallest jitter factor, 0.5
    const receiveCounts = [1, 2, 3, 6, 10];

    // ACT
    const delays = receiveCounts.map((receiveCount) => computeThrottleVisibilityDelaySeconds(receiveCount, 0));

    // ASSERT
    expect(delays).toEqual([15, 30, 60, 450, 450]);
  });

  it('keeps the jitter factor below 1.0', () => {
    // ARRANGE: a random value of 0.98 gives a jitter factor of 0.99
    const randomValue = 0.98;

    // ACT
    const delay = computeThrottleVisibilityDelaySeconds(1, randomValue);

    // ASSERT
    expect(delay).toBe(29);
  });
});

describe('parseReceiveCount', () => {
  it('reads a valid receive count and treats a missing or invalid one as the first receive', () => {
    // ARRANGE
    const rawCounts: (string | undefined)[] = ['4', undefined, '', 'abc', '0', '-2', '1.5'];

    // ACT
    const counts = rawCounts.map(parseReceiveCount);

    // ASSERT
    expect(counts).toEqual([4, 1, 1, 1, 1, 1, 1]);
  });
});
