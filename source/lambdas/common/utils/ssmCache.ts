// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { GetParameterCommand, GetParametersByPathCommand, SSMClient } from '@aws-sdk/client-ssm';
import { Logger } from '@aws-lambda-powertools/logger';
import { Clock, getClock } from './clock';

// Shared SSM Client with retry configuration to handle throttling
const ssmClient = new SSMClient({
  maxAttempts: Number.parseInt(process.env.AWS_MAX_ATTEMPTS || '10', 10),
  retryMode: (process.env.AWS_RETRY_MODE as 'adaptive' | 'standard' | 'legacy') || 'adaptive',
});

interface CachedParameter {
  value: string | undefined;
  fetchedAtMilliseconds: number;
}

export interface CachedParameterOptions {
  /** Re-fetch once the cached value is older than this. Omit to cache for the life of the execution environment. */
  maxAgeMilliseconds?: number;
  clock?: Clock;
}

const parameterCache = new Map<string, CachedParameter>();
const parametersByPathCache = new Map<string, Array<{ Name?: string; Value?: string }> | undefined>();

export async function getCachedParameter(
  parameterName: string,
  logger: Logger,
  options: CachedParameterOptions = {},
): Promise<string | undefined> {
  const { maxAgeMilliseconds, clock = getClock() } = options;
  const nowMilliseconds = clock.now().getTime();
  const cached = parameterCache.get(parameterName);
  if (
    cached &&
    (maxAgeMilliseconds === undefined || nowMilliseconds - cached.fetchedAtMilliseconds < maxAgeMilliseconds)
  ) {
    logger.debug('Using cached SSM parameter', { parameterName });
    return cached.value;
  }

  try {
    const command = new GetParameterCommand({ Name: parameterName });
    const response = await ssmClient.send(command);
    const value = response.Parameter?.Value;

    parameterCache.set(parameterName, { value, fetchedAtMilliseconds: nowMilliseconds });

    logger.debug('Retrieved and cached SSM parameter', { parameterName });
    return value;
  } catch (error) {
    logger.error('Error retrieving SSM parameter', { parameterName, error });
    if (!cached) return undefined;
    // An expired value is a better answer than none. Restarting its age stops a throttled SSM being retried on every call.
    parameterCache.set(parameterName, { value: cached.value, fetchedAtMilliseconds: nowMilliseconds });
    return cached.value;
  }
}

export async function getCachedParametersByPath(
  path: string,
  logger: Logger,
  recursive = true,
): Promise<Array<{ Name?: string; Value?: string }> | undefined> {
  const cacheKey = `path:${path}:${recursive}`;

  if (parametersByPathCache.has(cacheKey)) {
    logger.debug('Using cached SSM parameters by path', { path, recursive });
    return parametersByPathCache.get(cacheKey);
  }

  try {
    const command = new GetParametersByPathCommand({
      Path: path,
      Recursive: recursive,
    });
    const response = await ssmClient.send(command);
    const parameters = response.Parameters;

    parametersByPathCache.set(cacheKey, parameters);

    logger.debug('Retrieved and cached SSM parameters by path', { path, recursive, count: parameters?.length });
    return parameters;
  } catch (error) {
    logger.error('Error retrieving SSM parameters by path', { path, error });
    return undefined;
  }
}

export function getSSMClient(): SSMClient {
  return ssmClient;
}

export function clearSSMCache(): void {
  parameterCache.clear();
  parametersByPathCache.clear();
}
