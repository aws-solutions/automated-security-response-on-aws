// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Shared IntersectionObserver substitute for infinite-scroll tests.
// Substituting globalThis.IntersectionObserver is a platform boundary, the same
// category as fetch, so no internal module is mocked to obtain it.
//
// Registration and teardown counts accumulate across every instance the
// component creates: the observer effect of each scroll-detection table re-runs
// whenever hasMoreData, isLoading, isLoadingMore, or the load-more callback
// changes, so a single mount legitimately produces several observers. The
// assertable invariant is therefore balance between the two counts, not a fixed
// count.

export interface IntersectionObserverRecorder {
  /** Total observe() calls across every instance created while installed. */
  readonly registrationCount: number;
  /** Total registrations released by unobserve() or disconnect() across every instance. */
  readonly teardownCount: number;
  /** Registrations not yet released: registrationCount minus teardownCount. */
  readonly liveRegistrationCount: number;
  /** Fires an intersection change on the most recently created instance. */
  triggerIntersection(isIntersecting: boolean): void;
  /** Reinstates the inert global stub that setupTests.ts installs. */
  restore(): void;
}

class RecordedIntersectionObserverEntry implements IntersectionObserverEntry {
  readonly boundingClientRect: DOMRectReadOnly;
  readonly intersectionRatio: number;
  readonly intersectionRect: DOMRectReadOnly;
  readonly isIntersecting: boolean;
  readonly rootBounds: DOMRectReadOnly | null = null;
  readonly target: Element;
  readonly time: number;

  constructor(target: Element, isIntersecting: boolean) {
    this.target = target;
    this.isIntersecting = isIntersecting;
    this.boundingClientRect = target.getBoundingClientRect();
    this.intersectionRect = target.getBoundingClientRect();
    this.intersectionRatio = isIntersecting ? 1 : 0;
    this.time = 0;
  }
}

export function installIntersectionObserverRecorder(): IntersectionObserverRecorder {
  const previousIntersectionObserver = globalThis.IntersectionObserver;
  let registrationCount = 0;
  let teardownCount = 0;
  let mostRecentObserver: RecordingIntersectionObserver | undefined;
  let mostRecentObservedElement: Element | undefined;

  class RecordingIntersectionObserver implements IntersectionObserver {
    readonly root: Element | Document | null;
    readonly rootMargin: string;
    readonly thresholds: ReadonlyArray<number>;
    private readonly callback: IntersectionObserverCallback;
    private readonly observedElements: Element[] = [];

    constructor(callback: IntersectionObserverCallback, options?: IntersectionObserverInit) {
      this.callback = callback;
      this.root = options?.root ?? null;
      this.rootMargin = options?.rootMargin ?? '0px';
      this.thresholds = normalizeThresholds(options?.threshold);
      mostRecentObserver = this;
    }

    observe(target: Element): void {
      this.observedElements.push(target);
      mostRecentObservedElement = target;
      registrationCount += 1;
    }

    unobserve(target: Element): void {
      const observedIndex = this.observedElements.indexOf(target);
      if (observedIndex === -1) {
        return;
      }
      this.observedElements.splice(observedIndex, 1);
      teardownCount += 1;
    }

    disconnect(): void {
      teardownCount += this.observedElements.length;
      this.observedElements.length = 0;
    }

    takeRecords(): IntersectionObserverEntry[] {
      return [];
    }

    reportIntersection(isIntersecting: boolean): void {
      // Prefer this instance's own element. Once paging ends the load-more
      // trigger unmounts and the replacement observer registers nothing, so the
      // last element observed by any instance keeps a post-teardown trigger
      // meaningful instead of throwing.
      const target = this.observedElements[this.observedElements.length - 1] ?? mostRecentObservedElement;
      if (!target) {
        throw new Error(
          'No element was ever observed, so no intersection can be fired. The load-more trigger only ' +
            'renders while more data is available: check that the response carries a NextToken.',
        );
      }
      this.callback([new RecordedIntersectionObserverEntry(target, isIntersecting)], this);
    }
  }

  globalThis.IntersectionObserver = RecordingIntersectionObserver;

  return {
    get registrationCount(): number {
      return registrationCount;
    },
    get teardownCount(): number {
      return teardownCount;
    },
    get liveRegistrationCount(): number {
      return registrationCount - teardownCount;
    },
    triggerIntersection(isIntersecting: boolean): void {
      if (!mostRecentObserver) {
        throw new Error('No IntersectionObserver was created, so no intersection can be fired.');
      }
      mostRecentObserver.reportIntersection(isIntersecting);
    },
    restore(): void {
      globalThis.IntersectionObserver = previousIntersectionObserver;
    },
  };
}

function normalizeThresholds(threshold: number | number[] | undefined): ReadonlyArray<number> {
  if (threshold === undefined) {
    return [0];
  }
  return Array.isArray(threshold) ? threshold : [threshold];
}
