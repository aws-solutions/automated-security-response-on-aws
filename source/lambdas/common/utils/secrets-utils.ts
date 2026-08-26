// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { GetSecretValueCommand, SecretsManagerClient } from '@aws-sdk/client-secrets-manager';
import { Logger } from '@aws-lambda-powertools/logger';
import { SecretRetrievalError } from '../../notification-channels/notification-channel-errors';

// Intentional module-level cache: secrets are cached for the lifetime of the Lambda container.
// This is acceptable because secrets don't change within a single invocation batch, and the
// Lambda runtime recycles containers frequently enough that stale secrets are not a concern.
// clearSecretsCache() is exported for test isolation.
const secretsCache = new Map<string, string>();

export async function getCachedSecretValue(
  client: SecretsManagerClient,
  secretArn: string,
  logger: Logger,
): Promise<string> {
  const cached = secretsCache.get(secretArn);
  if (cached !== undefined) {
    logger.debug('Using cached secret value', { secretArn });
    return cached;
  }

  const response = await client.send(new GetSecretValueCommand({ SecretId: secretArn }));
  if (response.SecretString === undefined) {
    throw new SecretRetrievalError(`Secret ${secretArn} has no SecretString (binary secrets are not supported)`);
  }
  const value = response.SecretString;

  secretsCache.set(secretArn, value);
  logger.debug('Retrieved and cached secret value', { secretArn });
  return value;
}

export function clearSecretsCache(): void {
  secretsCache.clear();
}
