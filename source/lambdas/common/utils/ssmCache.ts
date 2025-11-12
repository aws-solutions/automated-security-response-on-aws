// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { GetParameterCommand, GetParametersByPathCommand, SSMClient } from '@aws-sdk/client-ssm';
import { Logger } from '@aws-lambda-powertools/logger';

// Shared SSM Client with retry configuration to handle throttling
const ssmClient = new SSMClient({
  maxAttempts: parseInt(process.env.AWS_MAX_ATTEMPTS || '10', 10),
  retryMode: (process.env.AWS_RETRY_MODE as 'adaptive' | 'standard' | 'legacy') || 'adaptive',
});

const parameterCache = new Map<string, any>();

export async function getCachedParameter(parameterName: string, logger: Logger): Promise<string | undefined> {
  if (parameterCache.has(parameterName)) {
    logger.debug('Using cached SSM parameter', { parameterName });
    return parameterCache.get(parameterName);
  }

  try {
    const command = new GetParameterCommand({ Name: parameterName });
    const response = await ssmClient.send(command);
    const value = response.Parameter?.Value;

    parameterCache.set(parameterName, value);

    logger.debug('Retrieved and cached SSM parameter', { parameterName });
    return value;
  } catch (error) {
    logger.error('Error retrieving SSM parameter', { parameterName, error });
    return undefined;
  }
}

export async function getCachedParametersByPath(
  path: string,
  logger: Logger,
  recursive = true,
): Promise<Array<{ Name?: string; Value?: string }> | undefined> {
  const cacheKey = `path:${path}:${recursive}`;

  if (parameterCache.has(cacheKey)) {
    logger.debug('Using cached SSM parameters by path', { path, recursive });
    return parameterCache.get(cacheKey);
  }

  try {
    const command = new GetParametersByPathCommand({
      Path: path,
      Recursive: recursive,
    });
    const response = await ssmClient.send(command);
    const parameters = response.Parameters;

    parameterCache.set(cacheKey, parameters);

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
}
