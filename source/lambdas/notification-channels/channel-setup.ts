// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { SecretsManagerClient } from '@aws-sdk/client-secrets-manager';
import { SNSClient } from '@aws-sdk/client-sns';
import * as https from 'node:https';
import { lookup as dnsLookup } from 'node:dns/promises';
import type { LookupAddress } from 'node:dns';
import type { LookupFunction } from 'node:net';
import { getLogger } from '../common/utils/logger';
import { getTracer } from '../common/utils/tracer';
import { ChannelDependencies } from './types';
import { isDisallowedAddress } from './disallowed-addresses';
import { ChannelTransportError, InputValidationError } from './notification-channel-errors';

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

export const ssrfGuardedLookup: LookupFunction = (hostname, options, callback) => {
  dnsLookup(hostname, { family: options.family, hints: options.hints, order: options.order, all: true }).then(
    (addresses: LookupAddress[]) => {
      const blockedAddress = addresses.find((entry) => isDisallowedAddress(entry.address));
      if (blockedAddress) {
        return callback(
          new InputValidationError(
            `Endpoint host ${hostname} resolves to a disallowed (private, loopback, or metadata) address`,
          ),
          '',
          0,
        );
      }
      if (options.all) return callback(null, addresses);
      return callback(null, addresses[0].address, addresses[0].family);
    },
    (error: NodeJS.ErrnoException) => callback(error, '', 0),
  );
};

export type HttpTransport = (url: string, init: RequestInit) => Promise<Response>;

const NULL_BODY_STATUSES = new Set([204, 205, 304]);

export function toHeaderRecord(headers: RequestInit['headers']): Record<string, string> | undefined {
  if (!headers) return undefined;
  if (headers instanceof Headers) return Object.fromEntries(headers.entries());
  if (Array.isArray(headers)) return Object.fromEntries(headers);
  return Object.fromEntries(
    Object.entries(headers).filter((entry): entry is [string, string] => typeof entry[1] === 'string'),
  );
}

/** The status range the fetch Response constructor accepts; anything else throws a RangeError. */
const MIN_RESPONSE_STATUS = 200;
const MAX_RESPONSE_STATUS = 599;

/**
 * Wraps a received status and body in a Response. A missing status is reported as 502. A status outside
 * 200-599 (for example 1xx or 600+) throws ChannelTransportError: it is not a retryable HTTP status, so the
 * request fails once instead of being sent again.
 */
export function toResponse(statusCode: number | undefined, body: Buffer): Response {
  const status = statusCode ?? 502;
  if (status < MIN_RESPONSE_STATUS || status > MAX_RESPONSE_STATUS) {
    throw new ChannelTransportError(`Response has invalid HTTP status ${status}`);
  }
  const hasBody = body.length > 0 && !NULL_BODY_STATUSES.has(status);
  return new Response(hasBody ? body : null, { status });
}

/** Idle timeout once a response has started: fails a response that stops sending data partway. */
export const IDLE_TIMEOUT_MS = 10_000;

/**
 * Time budget for one fetchWithRetry call, across every attempt and backoff. It is long enough that a
 * slow server which is still responding is not cut off after it has already created the record (which
 * would make SNS redeliver and create a duplicate), and short enough to fail before the 60-second
 * channel Lambda timeout.
 */
export const TOTAL_DEADLINE_MS = 45_000;

export const MAX_RESPONSE_BYTES = 1_000_000;

function toRequestBody(body: RequestInit['body']): string | Buffer | undefined {
  if (body === undefined || body === null) return undefined;
  if (typeof body === 'string' || Buffer.isBuffer(body)) return body;
  throw new TypeError('Unsupported request body type: only string and Buffer bodies are supported');
}

/**
 * Sends one HTTPS request via node:https (not fetch) so the connection can be pinned to a
 * denylist-validated IP through `ssrfGuardedLookup`. Redirects are not followed, so a 3xx comes back
 * as a non-ok Response the callers already treat as a failure. Aborting `init.signal` cancels the
 * request with the signal's reason.
 */
export const httpsTransport: HttpTransport = (url, init) =>
  new Promise<Response>((resolve, reject) => {
    const { signal } = init;
    signal?.throwIfAborted();
    const body = toRequestBody(init.body);
    const host = new URL(url).host;
    const headers = toHeaderRecord(init.headers) ?? {};
    // Set Content-Length explicitly; otherwise node:https uses chunked transfer encoding, which some
    // endpoints and WAFs reject.
    if (body !== undefined) headers['Content-Length'] = String(Buffer.byteLength(body));
    const request = https.request(
      url,
      {
        method: init.method ?? 'GET',
        headers,
        lookup: ssrfGuardedLookup,
      },
      (response) => {
        // Apply the idle timeout only once the response has started. Before that, the socket is idle while
        // the server processes the request, and cutting it off then could drop a record the server already
        // created; TOTAL_DEADLINE_MS bounds that wait instead.
        request.setTimeout(IDLE_TIMEOUT_MS);
        const chunks: Buffer[] = [];
        let receivedBytes = 0;
        response.on('data', (chunk: Buffer) => {
          receivedBytes += chunk.length;
          if (receivedBytes > MAX_RESPONSE_BYTES) {
            request.destroy(new ChannelTransportError(`Response from ${host} exceeded ${MAX_RESPONSE_BYTES} bytes`));
            return;
          }
          chunks.push(chunk);
        });
        response.on('end', () => {
          stopListeningForAbort();
          try {
            resolve(toResponse(response.statusCode, Buffer.concat(chunks)));
          } catch (error) {
            // Throwing here would escape the event handler uncaught; fail the request instead.
            reject(error);
          }
        });
        response.on('error', (error) => {
          stopListeningForAbort();
          reject(error);
        });
      },
    );
    const onAbort = (): void => {
      request.destroy(
        signal?.reason instanceof Error ? signal.reason : new ChannelTransportError(`Request to ${host} was aborted`),
      );
    };
    const stopListeningForAbort = (): void => signal?.removeEventListener('abort', onAbort);
    signal?.addEventListener('abort', onAbort, { once: true });
    request.on('timeout', () =>
      request.destroy(new ChannelTransportError(`Request to ${host} sent no data for ${IDLE_TIMEOUT_MS} ms`)),
    );
    request.on('error', (error) => {
      stopListeningForAbort();
      reject(error);
    });
    if (body !== undefined) request.write(body);
    request.end();
  });

export async function fetchWithRetry(
  url: string,
  init: RequestInit,
  delay: (ms: number) => Promise<void> = defaultDelay,
  transport: HttpTransport = httpsTransport,
): Promise<Response> {
  const parsed = new URL(url);
  if (parsed.protocol !== 'https:') {
    throw new Error(`Endpoint URL must use HTTPS, got: ${parsed.protocol}`);
  }
  if (isDisallowedAddress(parsed.hostname)) {
    throw new InputValidationError(
      `Endpoint host ${parsed.hostname} is a disallowed (private, loopback, or metadata) address`,
    );
  }

  const controller = new AbortController();
  const deadline = setTimeout(
    () => controller.abort(new ChannelTransportError(`Request to ${parsed.host} exceeded ${TOTAL_DEADLINE_MS} ms`)),
    TOTAL_DEADLINE_MS,
  );
  try {
    let lastResponse: Response | undefined;
    for (let attempt = 0; attempt <= MAX_RETRIES; attempt++) {
      if (attempt > 0) await delay(RETRY_BASE_MILLISECONDS * 2 ** (attempt - 1));
      controller.signal.throwIfAborted();
      lastResponse = await transport(url, { ...init, signal: controller.signal });
      if (!RETRYABLE_STATUS.has(lastResponse.status)) return lastResponse;
    }

    if (!lastResponse) {
      throw new Error(`fetchWithRetry: no response after ${MAX_RETRIES + 1} attempts`);
    }
    return lastResponse;
  } finally {
    clearTimeout(deadline);
  }
}

export const channelDependencies: ChannelDependencies = {
  logger,
  secretsClient,
  snsClient,
  fetchWithRetry: (url: string, init: RequestInit) => fetchWithRetry(url, init),
};
