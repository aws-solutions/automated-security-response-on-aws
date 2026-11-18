// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { PRE_PROCESSOR_VISIBILITY_TIMEOUT_SECONDS } from '@asr/data-models';
import { isThrottlingError } from '@smithy/service-error-classification';

const BASE_DELAY_SECONDS = 30;
// Capped at the queue's visibility timeout, so a throttled record never waits longer than any other failed record.
const MAX_DELAY_SECONDS = PRE_PROCESSOR_VISIBILITY_TIMEOUT_SECONDS;
const MIN_JITTER_FACTOR = 0.5;

type ClassifiableSdkError = Parameters<typeof isThrottlingError>[0];

// The SDK's error type narrows `cause` to an Error, which a plain `instanceof Error` check does not.
const isClassifiableSdkError = (error: unknown): error is ClassifiableSdkError =>
  error instanceof Error && (error.cause === undefined || error.cause instanceof Error);

export const isThrottle = (error: unknown): boolean => isClassifiableSdkError(error) && isThrottlingError(error);

/**
 * Seconds a throttled SQS record should stay invisible before its next receive. Jitter spreads out
 * records throttled together so their retries do not hit the API at the same moment.
 *
 * @param randomValue a value from 0 up to, but not including, 1
 */
export const computeThrottleVisibilityDelaySeconds = (receiveCount: number, randomValue: number): number => {
  const uncappedDelaySeconds = BASE_DELAY_SECONDS * 2 ** (receiveCount - 1);
  const cappedDelaySeconds = Math.min(uncappedDelaySeconds, MAX_DELAY_SECONDS);
  const jitterFactor = MIN_JITTER_FACTOR + (1 - MIN_JITTER_FACTOR) * randomValue;
  // SQS visibility timeouts are whole seconds.
  return Math.floor(cappedDelaySeconds * jitterFactor);
};

/** Parses an SQS `ApproximateReceiveCount`, treating a missing or invalid value as the first receive. */
export const parseReceiveCount = (approximateReceiveCount: string | undefined): number => {
  const receiveCount = Number(approximateReceiveCount);
  return Number.isInteger(receiveCount) && receiveCount >= 1 ? receiveCount : 1;
};
