// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { Clock } from '../clock';
import { LambdaCache, MAX_TTL_MS } from '../lambdaCache';

describe('LambdaCache', () => {
  let currentTime: number;
  let clock: Clock;
  let fetchFn: jest.Mock;

  beforeEach(() => {
    currentTime = 1000000;
    clock = { now: () => new Date(currentTime) };
    fetchFn = jest.fn();
  });

  describe('constructor', () => {
    it.each([0, -1, -100])('should throw when ttlMs is %s (non-positive)', (ttlMs) => {
      expect(() => new LambdaCache({ ttlMs, fetchFn, clock })).toThrow(
        `ttlMs must be between 1 and ${MAX_TTL_MS} (15 minutes - lambda invocation timeout) to minimize stale data`,
      );
    });

    it.each([MAX_TTL_MS + 1, Infinity])('should throw when ttlMs is %s (exceeds max)', (ttlMs) => {
      expect(() => new LambdaCache({ ttlMs, fetchFn, clock })).toThrow(
        `ttlMs must be between 1 and ${MAX_TTL_MS} (15 minutes - lambda invocation timeout) to minimize stale data`,
      );
    });

    it('should accept ttlMs at the upper bound', () => {
      expect(() => new LambdaCache({ ttlMs: MAX_TTL_MS, fetchFn, clock })).not.toThrow();
    });
  });

  describe('get', () => {
    it('should fetch and cache a value on first access', async () => {
      // GIVEN
      fetchFn.mockResolvedValue('value-a');
      const cache = new LambdaCache({ ttlMs: 5000, fetchFn, clock });

      // WHEN
      const result = await cache.get('key-a');

      // THEN
      expect(result).toBe('value-a');
      expect(fetchFn).toHaveBeenCalledTimes(1);
      expect(fetchFn).toHaveBeenCalledWith('key-a');
    });

    it('should return cached value within TTL without re-fetching', async () => {
      // GIVEN
      fetchFn.mockResolvedValue('value-a');
      const cache = new LambdaCache({ ttlMs: 5000, fetchFn, clock });
      await cache.get('key-a');

      // WHEN
      currentTime += 4999;
      const result = await cache.get('key-a');

      // THEN
      expect(result).toBe('value-a');
      expect(fetchFn).toHaveBeenCalledTimes(1);
    });

    it('should re-fetch after TTL expires', async () => {
      // GIVEN
      fetchFn.mockResolvedValueOnce('old-value').mockResolvedValueOnce('new-value');
      const cache = new LambdaCache({ ttlMs: 5000, fetchFn, clock });
      await cache.get('key-a');

      // WHEN
      currentTime += 5000;
      const result = await cache.get('key-a');

      // THEN
      expect(result).toBe('new-value');
      expect(fetchFn).toHaveBeenCalledTimes(2);
    });

    it('should cache null values', async () => {
      // GIVEN
      fetchFn.mockResolvedValue(null);
      const cache = new LambdaCache<string>({ ttlMs: 5000, fetchFn, clock });

      // WHEN
      await cache.get('key-a');
      const result = await cache.get('key-a');

      // THEN
      expect(result).toBeNull();
      expect(fetchFn).toHaveBeenCalledTimes(1);
    });

    it('should cache different keys independently', async () => {
      // GIVEN
      fetchFn.mockImplementation((key: string) => Promise.resolve(`value-for-${key}`));
      const cache = new LambdaCache({ ttlMs: 5000, fetchFn, clock });

      // WHEN
      const resultA = await cache.get('key-a');
      const resultB = await cache.get('key-b');

      // THEN
      expect(resultA).toBe('value-for-key-a');
      expect(resultB).toBe('value-for-key-b');
      expect(fetchFn).toHaveBeenCalledTimes(2);
    });

    it('should propagate fetch errors to the caller', async () => {
      // GIVEN
      fetchFn.mockRejectedValue(new Error('fetch failed'));
      const cache = new LambdaCache({ ttlMs: 5000, fetchFn, clock });

      // WHEN / THEN
      await expect(cache.get('key-a')).rejects.toThrow('fetch failed');
    });

    it('should not cache a failed fetch, allowing retry on next access', async () => {
      // GIVEN
      fetchFn.mockRejectedValueOnce(new Error('transient')).mockResolvedValueOnce('recovered');
      const cache = new LambdaCache({ ttlMs: 5000, fetchFn, clock });

      // WHEN
      await expect(cache.get('key-a')).rejects.toThrow('transient');
      const result = await cache.get('key-a');

      // THEN
      expect(result).toBe('recovered');
      expect(fetchFn).toHaveBeenCalledTimes(2);
    });
  });

  describe('warmKeys', () => {
    it('should pre-fetch values for uncached keys', async () => {
      // GIVEN
      fetchFn.mockImplementation((key: string) => Promise.resolve(`value-for-${key}`));
      const cache = new LambdaCache({ ttlMs: 5000, fetchFn, clock });

      // WHEN
      await cache.warmKeys(['key-a', 'key-b']);

      // THEN
      expect(fetchFn).toHaveBeenCalledTimes(2);
      const resultA = await cache.get('key-a');
      const resultB = await cache.get('key-b');
      expect(resultA).toBe('value-for-key-a');
      expect(resultB).toBe('value-for-key-b');
      expect(fetchFn).toHaveBeenCalledTimes(2);
    });

    it('should skip keys that are already cached and fresh', async () => {
      // GIVEN
      fetchFn.mockImplementation((key: string) => Promise.resolve(`value-for-${key}`));
      const cache = new LambdaCache({ ttlMs: 5000, fetchFn, clock });
      await cache.get('key-a');
      fetchFn.mockClear();

      // WHEN
      await cache.warmKeys(['key-a', 'key-b']);

      // THEN
      expect(fetchFn).toHaveBeenCalledTimes(1);
      expect(fetchFn).toHaveBeenCalledWith('key-b');
    });

    it('should re-warm stale keys', async () => {
      // GIVEN
      fetchFn.mockResolvedValueOnce('old-value').mockResolvedValueOnce('new-value');
      const cache = new LambdaCache({ ttlMs: 5000, fetchFn, clock });
      await cache.get('key-a');

      // WHEN
      currentTime += 5000;
      await cache.warmKeys(['key-a']);

      // THEN
      const result = await cache.get('key-a');
      expect(result).toBe('new-value');
      expect(fetchFn).toHaveBeenCalledTimes(2);
    });

    it('should swallow errors during warm-up and allow get() to retry', async () => {
      // GIVEN
      fetchFn.mockRejectedValueOnce(new Error('warm-up failed')).mockResolvedValueOnce('recovered-value');
      const cache = new LambdaCache({ ttlMs: 5000, fetchFn, clock });

      // WHEN
      await cache.warmKeys(['key-a']);
      const result = await cache.get('key-a');

      // THEN
      expect(result).toBe('recovered-value');
      expect(fetchFn).toHaveBeenCalledTimes(2);
    });

    it('should evict stale entry when warm-up fails, forcing get() to re-fetch', async () => {
      // GIVEN
      fetchFn
        .mockResolvedValueOnce('original-value')
        .mockRejectedValueOnce(new Error('warm-up failed'))
        .mockResolvedValueOnce('fresh-value');
      const cache = new LambdaCache({ ttlMs: 5000, fetchFn, clock });
      await cache.get('key-a');

      // WHEN
      currentTime += 5000;
      await cache.warmKeys(['key-a']);
      const result = await cache.get('key-a');

      // THEN
      expect(result).toBe('fresh-value');
      expect(fetchFn).toHaveBeenCalledTimes(3);
    });

    it('should invoke onWarmUpError callback when warm-up fails', async () => {
      // GIVEN
      const warmUpError = new Error('network timeout');
      fetchFn.mockRejectedValueOnce(warmUpError);
      const onWarmUpError = jest.fn();
      const cache = new LambdaCache({ ttlMs: 5000, fetchFn, clock, onWarmUpError });

      // WHEN
      await cache.warmKeys(['key-a']);

      // THEN
      expect(onWarmUpError).toHaveBeenCalledTimes(1);
      expect(onWarmUpError).toHaveBeenCalledWith('key-a', warmUpError);
    });
  });
});
