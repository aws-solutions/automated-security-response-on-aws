// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { SecretsManagerClient, GetSecretValueCommand } from '@aws-sdk/client-secrets-manager';
import { mockClient } from 'aws-sdk-client-mock';
import 'aws-sdk-client-mock-jest';
import { Logger } from '@aws-lambda-powertools/logger';
import { getCachedSecretValue, clearSecretsCache } from '../../common/utils/secrets-utils';
import { SecretRetrievalError } from '../../notification-channels/notification-channel-errors';

const secretsManagerMock = mockClient(SecretsManagerClient);
const logger = new Logger({ logLevel: 'SILENT' });
const client = new SecretsManagerClient({});

describe('getCachedSecretValue', () => {
  beforeEach(() => {
    secretsManagerMock.reset();
    clearSecretsCache();
  });

  it('should retrieve secret from Secrets Manager', async () => {
    secretsManagerMock.on(GetSecretValueCommand).resolves({ SecretString: 'my-secret' });

    const result = await getCachedSecretValue(client, 'arn:aws:secretsmanager:us-east-1:123:secret:test', logger);

    expect(result).toBe('my-secret');
    expect(secretsManagerMock.calls()).toHaveLength(1);
  });

  it('should return cached value on second call', async () => {
    secretsManagerMock.on(GetSecretValueCommand).resolves({ SecretString: 'my-secret' });
    const arn = 'arn:aws:secretsmanager:us-east-1:123:secret:test';

    await getCachedSecretValue(client, arn, logger);
    const result = await getCachedSecretValue(client, arn, logger);

    expect(result).toBe('my-secret');
    expect(secretsManagerMock.calls()).toHaveLength(1); // only one API call
  });

  it('should throw SecretRetrievalError when SecretString is undefined', async () => {
    secretsManagerMock.on(GetSecretValueCommand).resolves({});

    await expect(
      getCachedSecretValue(client, 'arn:aws:secretsmanager:us-east-1:123:secret:test', logger),
    ).rejects.toThrow(SecretRetrievalError);
  });

  it('should cache different secrets independently', async () => {
    secretsManagerMock
      .on(GetSecretValueCommand, { SecretId: 'arn:secret:a' })
      .resolves({ SecretString: 'secret-a' })
      .on(GetSecretValueCommand, { SecretId: 'arn:secret:b' })
      .resolves({ SecretString: 'secret-b' });

    const a = await getCachedSecretValue(client, 'arn:secret:a', logger);
    const b = await getCachedSecretValue(client, 'arn:secret:b', logger);

    expect(a).toBe('secret-a');
    expect(b).toBe('secret-b');
    expect(secretsManagerMock.calls()).toHaveLength(2);
  });

  it('should clear cache when clearSecretsCache is called', async () => {
    secretsManagerMock.on(GetSecretValueCommand).resolves({ SecretString: 'my-secret' });
    const arn = 'arn:aws:secretsmanager:us-east-1:123:secret:test';

    await getCachedSecretValue(client, arn, logger);
    clearSecretsCache();
    await getCachedSecretValue(client, arn, logger);

    expect(secretsManagerMock.calls()).toHaveLength(2); // called API again after cache clear
  });
});
