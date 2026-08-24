// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { Clock, getClock } from './clock';

interface CachedEntry<T> {
  value: T | null;
  timestamp: number;
}

export interface LambdaCacheOptions<T, K extends string = string> {
  ttlMs: number;
  fetchFn: (key: K) => Promise<T | null>;
  onWarmUpError?: (key: K, error: unknown) => void;
  clock?: Clock;
}

/**
 * Generic in-memory cache with TTL for use in Lambda invocations.
 *
 * Values are lazily fetched via the provided `fetchFn` and cached for `ttlMs` milliseconds.
 * Supports pre-warming multiple keys concurrently via `warmKeys()` to reduce per-item
 * latency during batch processing.
 *
 * The key type `K` is constrained to `string` (or string literal subtypes) because the
 * internal cache uses a `Map<string, ...>`. Narrowing `K` to a union (e.g. a discriminated
 * string literal type) lets callers avoid unsafe `as` casts when passing keys in.
 */
export const MAX_TTL_MS = 15 * 60 * 1000;

export class LambdaCache<T, K extends string = string> {
  private readonly cache = new Map<K, CachedEntry<T>>();
  private readonly ttlMs: number;
  private readonly clock: Clock;
  private readonly fetchFn: (key: K) => Promise<T | null>;
  private readonly onWarmUpError?: (key: K, error: unknown) => void;

  constructor(options: LambdaCacheOptions<T, K>) {
    if (options.ttlMs <= 0 || options.ttlMs > MAX_TTL_MS) {
      throw new Error(
        `ttlMs must be between 1 and ${MAX_TTL_MS} (15 minutes - lambda invocation timeout) to minimize stale data`,
      );
    }
    this.ttlMs = options.ttlMs;
    this.fetchFn = options.fetchFn;
    this.onWarmUpError = options.onWarmUpError;
    this.clock = options.clock ?? getClock();
  }

  /**
   * Retrieves the cached value for `key`, fetching it if absent or stale. Propagates fetch errors to the caller.
   * Stale entries are evicted before fetching so expired data is never served, even if the fetch fails.
   */
  async get(key: K): Promise<T | null> {
    const now = this.clock.now().getTime();
    const cached = this.cache.get(key);

    if (cached && now - cached.timestamp < this.ttlMs) {
      return cached.value;
    }

    if (cached) {
      this.cache.delete(key);
    }

    const value = await this.fetchFn(key);
    this.cache.set(key, { value, timestamp: now });
    return value;
  }

  /**
   * Pre-fetches values for the given keys concurrently, skipping entries that are still fresh.
   * Stale entries are evicted before fetching — if the fetch fails, the entry is removed rather than
   * serving expired data. Errors are swallowed so that `get()` can retry on the next access.
   * If an `onWarmUpError` callback was provided at construction, it is invoked for each failed key.
   */
  async warmKeys(keys: K[]): Promise<void> {
    const now = this.clock.now().getTime();
    const uniqueKeys = [...new Set(keys)];

    const staleOrMissing = uniqueKeys.filter((key) => {
      const cached = this.cache.get(key);
      if (!cached || now - cached.timestamp >= this.ttlMs) {
        if (cached) {
          this.cache.delete(key);
        }
        return true;
      }
      return false;
    });

    await Promise.all(
      staleOrMissing.map(async (key) => {
        try {
          const value = await this.fetchFn(key);
          this.cache.set(key, { value, timestamp: now });
        } catch (error) {
          this.onWarmUpError?.(key, error);
        }
      }),
    );
  }

  clear(): void {
    this.cache.clear();
  }
}
