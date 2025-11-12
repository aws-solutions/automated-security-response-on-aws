// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import '@testing-library/jest-dom';
import { Amplify } from 'aws-amplify';
import { afterAll, afterEach, beforeAll } from 'vitest';
import { MOCK_SERVER_URL, server } from './__tests__/server';

process.env.TZ = 'UTC'; // fix environment timezone for tests to UTC

// Mock IntersectionObserver for tests
globalThis.IntersectionObserver = class IntersectionObserver {
  root: Element | null = null;
  rootMargin: string = '0px';
  thresholds: ReadonlyArray<number> = [0];

  constructor(_callback: IntersectionObserverCallback, options?: IntersectionObserverInit) {
    if (options) {
      this.root = (options.root as Element) || null;
      this.rootMargin = options.rootMargin || '0px';

      if (options.threshold) {
        this.thresholds = Array.isArray(options.threshold) ? options.threshold : [options.threshold];
      } else {
        this.thresholds = [0];
      }
    }
  }

  observe() {
    // Mock implementation - do nothing
  }

  unobserve() {
    // Mock implementation - do nothing
  }

  disconnect() {
    // Mock implementation - do nothing
  }

  takeRecords(): IntersectionObserverEntry[] {
    return [];
  }
} as any;

globalThis.IntersectionObserverEntry = class IntersectionObserverEntry {
  boundingClientRect: DOMRectReadOnly = {} as DOMRectReadOnly;
  intersectionRatio: number = 0;
  intersectionRect: DOMRectReadOnly = {} as DOMRectReadOnly;
  isIntersecting: boolean = false;
  rootBounds: DOMRectReadOnly | null = null;
  target: Element = {} as Element;
  time: number = 0;

  constructor(entry: Partial<IntersectionObserverEntry> = {}) {
    Object.assign(this, entry);
  }
} as any;

beforeAll(() => {
  Amplify.configure({
    Auth: {
      Cognito: {
        userPoolId: '',
        userPoolClientId: '',
      },
    },
    API: {
      REST: {
        'solution-api': {
          endpoint: MOCK_SERVER_URL,
        },
      },
    },
  });
  server.listen({ onUnhandledRequest: 'error' });
});
afterAll(() => server.close());
afterEach(() => server.resetHandlers());
