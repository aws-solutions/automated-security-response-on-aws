// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { GetParameterCommand, GetParametersByPathCommand, SSMClient } from '@aws-sdk/client-ssm';
import { mockClient } from 'aws-sdk-client-mock';
import { Logger } from '@aws-lambda-powertools/logger';
import { clearSSMCache, getCachedParameter, getCachedParametersByPath, getSSMClient } from '../ssmCache';

const ssmMock = mockClient(SSMClient);

function makeLogger(): { debug: jest.Mock; error: jest.Mock } {
  return { debug: jest.fn(), error: jest.fn() };
}

describe('ssmCache', () => {
  beforeEach(() => {
    ssmMock.reset();
    clearSSMCache();
  });

  describe('getCachedParameter', () => {
    it('fetches on a cache miss then serves subsequent calls from cache', async () => {
      ssmMock.on(GetParameterCommand).resolves({ Parameter: { Value: 'the-value' } });
      const logger = makeLogger();

      const first = await getCachedParameter('/asr/param', logger as unknown as Logger);
      const second = await getCachedParameter('/asr/param', logger as unknown as Logger);

      expect(first).toBe('the-value');
      expect(second).toBe('the-value');
      // Only one SDK call — the second resolves from cache.
      expect(ssmMock.commandCalls(GetParameterCommand)).toHaveLength(1);
      expect(logger.debug).toHaveBeenCalledWith('Using cached SSM parameter', { parameterName: '/asr/param' });
    });

    it('returns undefined and logs on error', async () => {
      ssmMock.on(GetParameterCommand).rejects(new Error('access denied'));
      const logger = makeLogger();

      const value = await getCachedParameter('/asr/missing', logger as unknown as Logger);

      expect(value).toBeUndefined();
      expect(logger.error).toHaveBeenCalledWith(
        'Error retrieving SSM parameter',
        expect.objectContaining({ parameterName: '/asr/missing' }),
      );
    });
  });

  describe('getCachedParametersByPath', () => {
    it('fetches on a cache miss then serves subsequent calls from cache', async () => {
      const params = [{ Name: '/asr/a', Value: '1' }];
      ssmMock.on(GetParametersByPathCommand).resolves({ Parameters: params });
      const logger = makeLogger();

      const first = await getCachedParametersByPath('/asr', logger as unknown as Logger);
      const second = await getCachedParametersByPath('/asr', logger as unknown as Logger);

      expect(first).toEqual(params);
      expect(second).toEqual(params);
      expect(ssmMock.commandCalls(GetParametersByPathCommand)).toHaveLength(1);
    });

    it('keys the cache on the recursive flag', async () => {
      ssmMock.on(GetParametersByPathCommand).resolves({ Parameters: [] });
      const logger = makeLogger();

      await getCachedParametersByPath('/asr', logger as unknown as Logger, true);
      await getCachedParametersByPath('/asr', logger as unknown as Logger, false);

      // Different recursive values are distinct cache keys => two SDK calls.
      expect(ssmMock.commandCalls(GetParametersByPathCommand)).toHaveLength(2);
    });

    it('returns undefined and logs on error', async () => {
      ssmMock.on(GetParametersByPathCommand).rejects(new Error('boom'));
      const logger = makeLogger();

      const value = await getCachedParametersByPath('/asr/bad', logger as unknown as Logger);

      expect(value).toBeUndefined();
      expect(logger.error).toHaveBeenCalledWith(
        'Error retrieving SSM parameters by path',
        expect.objectContaining({ path: '/asr/bad' }),
      );
    });
  });

  describe('getSSMClient', () => {
    it('returns the shared SSM client instance', () => {
      expect(getSSMClient()).toBeInstanceOf(SSMClient);
    });
  });

  describe('clearSSMCache', () => {
    it('forces a re-fetch after the cache is cleared', async () => {
      ssmMock.on(GetParameterCommand).resolves({ Parameter: { Value: 'v' } });
      const logger = makeLogger();

      await getCachedParameter('/asr/p', logger as unknown as Logger);
      clearSSMCache();
      await getCachedParameter('/asr/p', logger as unknown as Logger);

      // Cleared cache => the second call hits the SDK again.
      expect(ssmMock.commandCalls(GetParameterCommand)).toHaveLength(2);
    });
  });
});
