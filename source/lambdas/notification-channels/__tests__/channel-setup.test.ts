// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { fetchWithRetry } from '../channel-setup';

const noDelay = (): Promise<void> => Promise.resolve();

describe('fetchWithRetry', () => {
  const originalFetch = global.fetch;

  beforeEach(() => {
    jest.restoreAllMocks();
  });

  afterAll(() => {
    global.fetch = originalFetch;
  });

  it('should reject non-HTTPS URLs', async () => {
    await expect(fetchWithRetry('http://example.com', { method: 'POST' })).rejects.toThrow(
      'Endpoint URL must use HTTPS',
    );
  });

  it('should reject invalid URLs', async () => {
    await expect(fetchWithRetry('not-a-url', { method: 'POST' })).rejects.toThrow();
  });

  it('should return response on success', async () => {
    const mockResponse = { ok: true, status: 200 } as Response;
    global.fetch = jest.fn().mockResolvedValue(mockResponse);

    const result = await fetchWithRetry('https://example.com/webhook', { method: 'POST' }, noDelay);

    expect(result).toBe(mockResponse);
    expect(global.fetch).toHaveBeenCalledTimes(1);
  });

  it('should retry on 429 status', async () => {
    const retryResponse = { ok: false, status: 429 } as Response;
    const successResponse = { ok: true, status: 200 } as Response;
    global.fetch = jest.fn().mockResolvedValueOnce(retryResponse).mockResolvedValueOnce(successResponse);

    const result = await fetchWithRetry('https://example.com/webhook', { method: 'POST' }, noDelay);

    expect(result).toBe(successResponse);
    expect(global.fetch).toHaveBeenCalledTimes(2);
  });

  it('should retry on 5xx status', async () => {
    const errorResponse = { ok: false, status: 502 } as Response;
    const successResponse = { ok: true, status: 200 } as Response;
    global.fetch = jest.fn().mockResolvedValueOnce(errorResponse).mockResolvedValueOnce(successResponse);

    const result = await fetchWithRetry('https://example.com/webhook', { method: 'POST' }, noDelay);

    expect(result).toBe(successResponse);
    expect(global.fetch).toHaveBeenCalledTimes(2);
  });

  it('should not retry on 4xx client errors', async () => {
    const clientError = { ok: false, status: 400 } as Response;
    global.fetch = jest.fn().mockResolvedValue(clientError);

    const result = await fetchWithRetry('https://example.com/webhook', { method: 'POST' }, noDelay);

    expect(result).toBe(clientError);
    expect(global.fetch).toHaveBeenCalledTimes(1);
  });

  it('should return last response after max retries exhausted', async () => {
    const errorResponse = { ok: false, status: 503 } as Response;
    global.fetch = jest.fn().mockResolvedValue(errorResponse);

    const result = await fetchWithRetry('https://example.com/webhook', { method: 'POST' }, noDelay);

    expect(result.status).toBe(503);
    expect(global.fetch).toHaveBeenCalledTimes(3); // 1 initial + 2 retries
  });

  it('should call delay function between retries', async () => {
    const errorResponse = { ok: false, status: 500 } as Response;
    global.fetch = jest.fn().mockResolvedValue(errorResponse);
    const mockDelay = jest.fn().mockResolvedValue(undefined);

    await fetchWithRetry('https://example.com/webhook', { method: 'POST' }, mockDelay);

    expect(mockDelay).toHaveBeenCalledTimes(2); // 2 retries = 2 delays
    expect(mockDelay).toHaveBeenNthCalledWith(1, 500);
    expect(mockDelay).toHaveBeenNthCalledWith(2, 1000);
  });
});
