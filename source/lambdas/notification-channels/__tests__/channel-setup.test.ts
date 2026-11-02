// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import * as https from 'node:https';
import { EventEmitter } from 'node:events';
import type { ClientRequest } from 'node:http';

jest.mock('node:https', () => {
  const actual = jest.requireActual<typeof import('node:https')>('node:https');
  return { ...actual, request: jest.fn((...args: Parameters<typeof actual.request>) => actual.request(...args)) };
});
const mockedRequest = jest.mocked(https.request);
import {
  fetchWithRetry,
  httpsTransport,
  IDLE_TIMEOUT_MS,
  MAX_RESPONSE_BYTES,
  ssrfGuardedLookup,
  toHeaderRecord,
  toResponse,
  TOTAL_DEADLINE_MS,
} from '../channel-setup';
import { ChannelTransportError } from '../notification-channel-errors';

const noDelay = (): Promise<void> => Promise.resolve();
const response = (status: number): Response =>
  new Response(status === 204 || status === 304 ? null : 'body', { status });

type TransportMock = jest.Mock<Promise<Response>, [string, RequestInit]>;
const makeTransport = (): TransportMock => jest.fn<Promise<Response>, [string, RequestInit]>();

describe('fetchWithRetry', () => {
  it('rejects non-HTTPS URLs', async () => {
    await expect(fetchWithRetry('http://example.com', { method: 'POST' })).rejects.toThrow(
      'Endpoint URL must use HTTPS',
    );
  });

  it('rejects invalid URLs', async () => {
    await expect(fetchWithRetry('not-a-url', { method: 'POST' })).rejects.toThrow();
  });

  it('rejects an IP-literal host in a private, loopback, or metadata range without sending', async () => {
    const transport = makeTransport();

    for (const url of ['https://169.254.169.254/latest', 'https://127.0.0.1/x', 'https://[::ffff:10.0.0.1]/x']) {
      await expect(fetchWithRetry(url, { method: 'POST' }, noDelay, transport)).rejects.toThrow(/disallowed/);
    }
    expect(transport).not.toHaveBeenCalled();
  });

  it('returns the response on success', async () => {
    const transport = makeTransport().mockResolvedValue(response(200));

    const result = await fetchWithRetry('https://example.com/webhook', { method: 'POST' }, noDelay, transport);

    expect(result.status).toBe(200);
    expect(transport).toHaveBeenCalledTimes(1);
  });

  it('retries on 429 then succeeds', async () => {
    const transport = makeTransport().mockResolvedValueOnce(response(429)).mockResolvedValueOnce(response(200));

    const result = await fetchWithRetry('https://example.com/webhook', { method: 'POST' }, noDelay, transport);

    expect(result.status).toBe(200);
    expect(transport).toHaveBeenCalledTimes(2);
  });

  it('retries on 5xx then succeeds', async () => {
    const transport = makeTransport().mockResolvedValueOnce(response(502)).mockResolvedValueOnce(response(200));

    const result = await fetchWithRetry('https://example.com/webhook', { method: 'POST' }, noDelay, transport);

    expect(result.status).toBe(200);
    expect(transport).toHaveBeenCalledTimes(2);
  });

  it('does not retry on 4xx client errors', async () => {
    const transport = makeTransport().mockResolvedValue(response(400));

    const result = await fetchWithRetry('https://example.com/webhook', { method: 'POST' }, noDelay, transport);

    expect(result.status).toBe(400);
    expect(transport).toHaveBeenCalledTimes(1);
  });

  it('returns the last response after retries are exhausted', async () => {
    const transport = makeTransport().mockResolvedValue(response(503));

    const result = await fetchWithRetry('https://example.com/webhook', { method: 'POST' }, noDelay, transport);

    expect(result.status).toBe(503);
    expect(transport).toHaveBeenCalledTimes(3); // 1 initial + 2 retries
  });

  it('calls the delay function between retries', async () => {
    const transport = makeTransport().mockResolvedValue(response(500));
    const delay = jest.fn<Promise<void>, [number]>().mockResolvedValue(undefined);

    await fetchWithRetry('https://example.com/webhook', { method: 'POST' }, delay, transport);

    expect(delay).toHaveBeenCalledTimes(2);
    expect(delay).toHaveBeenNthCalledWith(1, 500);
    expect(delay).toHaveBeenNthCalledWith(2, 1000);
  });

  it('sends an out-of-range status response once and fails, instead of retrying it', async () => {
    const transport = makeTransport().mockImplementation(() =>
      Promise.reject(new ChannelTransportError('Response from example.com has invalid status 600')),
    );

    await expect(fetchWithRetry('https://example.com/webhook', { method: 'POST' }, noDelay, transport)).rejects.toThrow(
      ChannelTransportError,
    );
    expect(transport).toHaveBeenCalledTimes(1);
  });

  describe('total deadline', () => {
    beforeEach(() => jest.useFakeTimers());
    afterEach(() => jest.useRealTimers());

    const respondAfter = (ms: number, status: number) => (): Promise<Response> =>
      new Promise((resolve) => setTimeout(() => resolve(response(status)), ms));
    const neverRespond = (_url: string, init: RequestInit): Promise<Response> =>
      new Promise((_resolve, reject) => {
        init.signal?.addEventListener('abort', () => reject(init.signal?.reason));
      });

    it('lets a slow but responding request finish instead of cutting it off', async () => {
      const transport = makeTransport().mockImplementation(respondAfter(30_000, 201));

      const pending = fetchWithRetry('https://example.com/webhook', { method: 'POST' }, noDelay, transport);
      await jest.advanceTimersByTimeAsync(30_000);

      expect((await pending).status).toBe(201);
      expect(jest.getTimerCount()).toBe(0);
    });

    it('aborts a request that is still pending when the deadline passes', async () => {
      const transport = makeTransport().mockImplementation(neverRespond);

      const pending = fetchWithRetry('https://example.com/webhook', { method: 'POST' }, noDelay, transport);
      const assertion = expect(pending).rejects.toThrow(ChannelTransportError);
      await jest.advanceTimersByTimeAsync(TOTAL_DEADLINE_MS);

      await assertion;
    });

    it('applies one deadline across all retry attempts', async () => {
      const transport = makeTransport()
        .mockImplementationOnce(respondAfter(20_000, 503))
        .mockImplementationOnce(respondAfter(20_000, 503))
        .mockImplementation(neverRespond);

      const pending = fetchWithRetry('https://example.com/webhook', { method: 'POST' }, noDelay, transport);
      const assertion = expect(pending).rejects.toThrow(`exceeded ${TOTAL_DEADLINE_MS} ms`);
      await jest.advanceTimersByTimeAsync(TOTAL_DEADLINE_MS);

      await assertion;
      expect(transport).toHaveBeenCalledTimes(3);
    });
  });
});

describe('ssrfGuardedLookup', () => {
  function runLookup(
    host: string,
    options: Record<string, unknown> = {},
  ): Promise<{ error: Error | null; address: unknown; family?: number }> {
    return new Promise((resolve) => {
      ssrfGuardedLookup(host, options, (error, address, family) => resolve({ error, address, family }));
    });
  }

  it('fails the connection when the host resolves to a private address', async () => {
    const { error } = await runLookup('10.0.0.5');
    expect(error).toBeInstanceOf(Error);
    expect(error?.message).toMatch(/disallowed/);
  });

  it('fails the connection when the host resolves to loopback (localhost)', async () => {
    const { error } = await runLookup('localhost');
    expect(error?.message).toMatch(/disallowed/);
  });

  it('fails the connection for a metadata address', async () => {
    const { error } = await runLookup('169.254.169.254');
    expect(error?.message).toMatch(/disallowed/);
  });

  it('pins to the validated address for a public target (single-address form)', async () => {
    const { error, address, family } = await runLookup('8.8.8.8');
    expect(error).toBeNull();
    expect(address).toBe('8.8.8.8');
    expect(family).toBe(4);
  });

  it('returns all validated addresses when options.all is set', async () => {
    const { error, address } = await runLookup('8.8.8.8', { all: true });
    expect(error).toBeNull();
    expect(address).toEqual([{ address: '8.8.8.8', family: 4 }]);
  });
});

describe('toResponse', () => {
  it('wraps a body with its status code', async () => {
    const result = toResponse(200, Buffer.from('hello'));
    expect(result.status).toBe(200);
    expect(await result.text()).toBe('hello');
  });

  it('defaults a missing status code to 502', () => {
    expect(toResponse(undefined, Buffer.alloc(0)).status).toBe(502);
  });

  it('rejects a status the Response constructor cannot hold (outside 200-599) as a transport error', () => {
    for (const statusCode of [101, 199, 600, 999]) {
      expect(() => toResponse(statusCode, Buffer.from('body'))).toThrow(ChannelTransportError);
    }
  });

  it('drops the body for null-body statuses so the Response constructor does not throw', () => {
    const result = toResponse(204, Buffer.from('unexpected'));
    expect(result.status).toBe(204);
    expect(result.body).toBeNull();
  });
});

describe('toHeaderRecord', () => {
  it('returns undefined when there are no headers', () => {
    expect(toHeaderRecord(undefined)).toBeUndefined();
  });

  it('passes a plain record through', () => {
    expect(toHeaderRecord({ 'content-type': 'application/json' })).toEqual({ 'content-type': 'application/json' });
  });

  it('omits headers whose value is undefined', () => {
    expect(toHeaderRecord({ Accept: 'application/json', Authorization: undefined })).toEqual({
      Accept: 'application/json',
    });
  });

  it('flattens a Headers instance', () => {
    expect(toHeaderRecord(new Headers({ 'x-token': 'abc' }))).toEqual({ 'x-token': 'abc' });
  });

  it('flattens an entries array', () => {
    expect(toHeaderRecord([['x-token', 'abc']])).toEqual({ 'x-token': 'abc' });
  });
});

describe('httpsTransport', () => {
  afterEach(() => mockedRequest.mockClear());

  function stubRequest(): EventEmitter & {
    write: jest.Mock;
    end: jest.Mock;
    destroy: jest.Mock;
    setTimeout: jest.Mock;
  } {
    const fakeRequest = Object.assign(new EventEmitter(), {
      write: jest.fn(),
      end: jest.fn(),
      destroy: jest.fn(),
      setTimeout: jest.fn(),
    });
    fakeRequest.destroy.mockImplementation((error: Error) => fakeRequest.emit('error', error));
    // Only the event, write, end, destroy, and setTimeout surface of ClientRequest is exercised by httpsTransport.
    mockedRequest.mockReturnValueOnce(fakeRequest as unknown as ClientRequest);
    return fakeRequest;
  }

  it('sets no idle timeout while the server is still processing, so only the total deadline applies', () => {
    const fakeRequest = stubRequest();

    void httpsTransport('https://example.com/x', { method: 'POST', body: '{}' }).catch(() => undefined);

    // Waiting for the first response byte after the body is sent counts as socket inactivity, so an idle
    // timeout here would cut off a slow server that has already created the record.
    expect(mockedRequest.mock.calls[0][1]).not.toHaveProperty('timeout');
    expect(fakeRequest.setTimeout).not.toHaveBeenCalled();
    fakeRequest.emit('error', new Error('settled by test'));
  });

  it('applies the idle timeout once the response starts, and fails a response body that stalls', async () => {
    const fakeRequest = stubRequest();
    const pending = httpsTransport('https://example.com/x', { method: 'GET' });
    const onResponse = mockedRequest.mock.calls[0][2] as (response: EventEmitter & { statusCode?: number }) => void;
    onResponse(Object.assign(new EventEmitter(), { statusCode: 200 }));

    expect(fakeRequest.setTimeout).toHaveBeenCalledWith(IDLE_TIMEOUT_MS);
    fakeRequest.emit('timeout');

    await expect(pending).rejects.toThrow(ChannelTransportError);
  });

  it('cancels the request with the signal reason when the signal aborts', async () => {
    const fakeRequest = stubRequest();
    const controller = new AbortController();
    const reason = new ChannelTransportError('deadline passed');

    const pending = httpsTransport('https://example.com/x', { method: 'GET', signal: controller.signal });
    controller.abort(reason);

    await expect(pending).rejects.toBe(reason);
    expect(fakeRequest.destroy).toHaveBeenCalledWith(reason);
  });

  it('does not send when the signal is already aborted', async () => {
    const controller = new AbortController();
    controller.abort(new ChannelTransportError('deadline passed'));

    await expect(httpsTransport('https://example.com/x', { method: 'GET', signal: controller.signal })).rejects.toThrow(
      'deadline passed',
    );
    expect(mockedRequest).not.toHaveBeenCalled();
  });

  it('writes a string body', async () => {
    const fakeRequest = stubRequest();

    const pending = httpsTransport('https://example.com/x', { method: 'POST', body: '{"a":1}' });

    expect(fakeRequest.write).toHaveBeenCalledWith('{"a":1}');
    expect(fakeRequest.end).toHaveBeenCalled();
    // Settle the request so its deadline timer is cleared and nothing outlives the test.
    fakeRequest.emit('error', new Error('settled by test'));
    await expect(pending).rejects.toThrow('settled by test');
  });

  it('sets Content-Length for a body so it is not sent with chunked encoding', async () => {
    const fakeRequest = stubRequest();

    const pending = httpsTransport('https://example.com/x', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: '{"name":"é"}',
    });

    expect(mockedRequest).toHaveBeenCalledWith(
      'https://example.com/x',
      expect.objectContaining({
        // Byte length, not character length: "é" is two bytes in UTF-8, so 13 bytes for 12 characters.
        headers: { 'Content-Type': 'application/json', 'Content-Length': '13' },
      }),
      expect.any(Function),
    );
    fakeRequest.emit('error', new Error('settled by test'));
    await expect(pending).rejects.toThrow('settled by test');
  });

  it('stops listening for abort once the response stream errors', async () => {
    const fakeRequest = stubRequest();
    const controller = new AbortController();
    const pending = httpsTransport('https://example.com/x', { method: 'GET', signal: controller.signal });
    const onResponse = mockedRequest.mock.calls[0][2] as (response: EventEmitter) => void;
    const response = Object.assign(new EventEmitter(), { statusCode: 200 });
    onResponse(response);

    response.emit('error', new Error('stream broke'));
    await expect(pending).rejects.toThrow('stream broke');

    controller.abort();
    expect(fakeRequest.destroy).not.toHaveBeenCalled();
  });

  it('rejects an unsupported body type instead of sending an empty request', async () => {
    await expect(
      httpsTransport('https://example.com/x', { method: 'POST', body: new URLSearchParams({ a: '1' }) }),
    ).rejects.toThrow(/Unsupported request body type/);
    expect(mockedRequest).not.toHaveBeenCalled();
  });

  it('rejects, rather than throwing inside the response handler, when the status is out of range', async () => {
    stubRequest();
    const pending = httpsTransport('https://example.com/x', { method: 'POST', body: '{}' });
    const onResponse = mockedRequest.mock.calls[0][2] as (response: EventEmitter & { statusCode?: number }) => void;
    const response = Object.assign(new EventEmitter(), { statusCode: 600 });
    onResponse(response);

    response.emit('end');

    await expect(pending).rejects.toThrow(ChannelTransportError);
  });

  it('rejects and destroys the request when the response body exceeds the max size', async () => {
    const fakeRequest = stubRequest();
    const pending = httpsTransport('https://example.com/x', { method: 'GET' });
    const onResponse = mockedRequest.mock.calls[0][2] as (response: EventEmitter & { statusCode?: number }) => void;
    const response = Object.assign(new EventEmitter(), { statusCode: 200 });
    onResponse(response);

    response.emit('data', Buffer.alloc(MAX_RESPONSE_BYTES + 1));

    await expect(pending).rejects.toThrow(ChannelTransportError);
    await expect(pending).rejects.toThrow(/exceeded \d+ bytes/);
    expect(fakeRequest.destroy).toHaveBeenCalled();
  });
});
