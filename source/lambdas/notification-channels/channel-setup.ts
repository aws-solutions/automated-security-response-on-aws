// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { SecretsManagerClient } from '@aws-sdk/client-secrets-manager';
import { SNSClient } from '@aws-sdk/client-sns';
import { getLogger } from '../common/utils/logger';
import { getTracer } from '../common/utils/tracer';
import { ChannelDependencies } from './types';

const SOLUTION_TRADEMARKEDNAME = process.env.SOLUTION_TRADEMARKEDNAME ?? 'automated-security-response-on-aws';
export const tracer = getTracer(SOLUTION_TRADEMARKEDNAME);
export const logger = getLogger(SOLUTION_TRADEMARKEDNAME);
export const secretsClient = tracer.captureAWSv3Client(new SecretsManagerClient({}));
export const snsClient = tracer.captureAWSv3Client(new SNSClient({}));

const MAX_RETRIES = 2;
const RETRY_BASE_MILLISECONDS = 500;
const RETRYABLE_STATUS = new Set([429, 500, 502, 503, 504]);

/** Default delay function using setTimeout. Can be overridden in tests. */
const defaultDelay = (ms: number): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms));

export async function fetchWithRetry(
  url: string,
  init: RequestInit,
  delay: (ms: number) => Promise<void> = defaultDelay,
): Promise<Response> {
  const parsed = new URL(url);
  if (parsed.protocol !== 'https:') {
    throw new Error(`Endpoint URL must use HTTPS, got: ${parsed.protocol}`);
  }

  let lastResponse: Response | undefined;
  for (let attempt = 0; attempt <= MAX_RETRIES; attempt++) {
    if (attempt > 0) await delay(RETRY_BASE_MILLISECONDS * 2 ** (attempt - 1));
    lastResponse = await fetch(url, init);
    if (!RETRYABLE_STATUS.has(lastResponse.status)) return lastResponse;
  }

  if (!lastResponse) {
    throw new Error(`fetchWithRetry: no response after ${MAX_RETRIES + 1} attempts`);
  }
  return lastResponse;
}

export const channelDependencies: ChannelDependencies = {
  logger,
  secretsClient,
  snsClient,
  fetchWithRetry: (url: string, init: RequestInit) => fetchWithRetry(url, init),
};
