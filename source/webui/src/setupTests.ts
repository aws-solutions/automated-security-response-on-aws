// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import '@testing-library/jest-dom';
import { Amplify } from 'aws-amplify';
import { afterAll, afterEach, beforeAll } from 'vitest';
import { MOCK_SERVER_URL, server } from './__tests__/server';

process.env.TZ = 'UTC'; // fix environment timezone for tests to UTC

const reportedRenderErrors: unknown[] = [];

// Inert IntersectionObserver stub for tests: it records the options it was given
// and never invokes the callback. Tests that need intersections to fire install
// the recorder from __tests__/intersection-observer-recorder.ts instead.
class InertIntersectionObserver implements IntersectionObserver {
  root: Element | Document | null = null;
  rootMargin: string = '0px';
  thresholds: ReadonlyArray<number> = [0];

  constructor(_callback: IntersectionObserverCallback, options?: IntersectionObserverInit) {
    if (options) {
      this.root = options.root || null;
      this.rootMargin = options.rootMargin || '0px';

      if (options.threshold) {
        this.thresholds = Array.isArray(options.threshold) ? options.threshold : [options.threshold];
      } else {
        this.thresholds = [0];
      }
    }
  }

  observe(_target: Element): void {
    // Inert by design: intersections never fire from this stub.
  }

  unobserve(_target: Element): void {
    // Inert by design: intersections never fire from this stub.
  }

  disconnect(): void {
    // Inert by design: intersections never fire from this stub.
  }

  takeRecords(): IntersectionObserverEntry[] {
    return [];
  }
}

class InertIntersectionObserverEntry implements IntersectionObserverEntry {
  boundingClientRect: DOMRectReadOnly;
  intersectionRatio: number = 0;
  intersectionRect: DOMRectReadOnly;
  isIntersecting: boolean = false;
  rootBounds: DOMRectReadOnly | null = null;
  target: Element;
  time: number = 0;

  constructor(entry: Partial<IntersectionObserverEntry> = {}) {
    this.target = document.createElement('div');
    this.boundingClientRect = this.target.getBoundingClientRect();
    this.intersectionRect = this.target.getBoundingClientRect();
    Object.assign(this, entry);
  }
}

globalThis.IntersectionObserver = InertIntersectionObserver;
globalThis.IntersectionObserverEntry = InertIntersectionObserverEntry;

beforeAll(() => {
  // React 19 diverts an uncaught render error here instead of re-throwing it out of
  // the render call, which would otherwise leave a silent empty tree and a test that
  // fails for the wrong reason — or passes.
  globalThis.reportError = (error: unknown) => {
    reportedRenderErrors.push(error);
  };

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
afterEach(() => {
  server.resetHandlers();

  const errors = reportedRenderErrors.splice(0, reportedRenderErrors.length);
  if (errors.length > 0) {
    throw new Error(
      `React reported ${errors.length} uncaught render error(s):\n` +
        errors.map((error) => (error instanceof Error ? (error.stack ?? error.message) : String(error))).join('\n'),
    );
  }
});
