// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { Sleeper, getSleeper } from '../common/utils/sleeper';
import {
  SecurityHubUtils,
  SuppressionLookupOutcome,
  SuppressionLookupTarget,
  SuppressionVerdict,
} from '../common/utils/securityHub';

/** Measured so that in about 96% of SQS batches, every record has looked up or finished before the window closes. */
export const SUPPRESSION_LOOKUP_WINDOW_MS = 250;
/** Matches the 10-ID chunk of each Security Hub read, so a full window costs one call per view. */
export const MAX_LOOKUPS_PER_WINDOW = 10;

export type SuppressionOutcomeReader = Pick<SecurityHubUtils, 'readSuppressionOutcomes'>;

/** Call `finish` when the record is done, so the batcher stops waiting on a record that will not look up again. */
export interface SuppressionLookupHandle {
  lookUp(target: SuppressionLookupTarget): Promise<SuppressionVerdict>;
  finish(): void;
}

interface PendingLookup {
  target: SuppressionLookupTarget;
  resolve: (verdict: SuppressionVerdict) => void;
  reject: (error: unknown) => void;
}

interface LookupWindow {
  readonly pendingLookups: PendingLookup[];
}

/**
 * Groups the live suppression lookups of one SQS batch into as few Security Hub reads as possible.
 * A window sends when its timer ends, when it is full, or once every record has looked up or finished.
 */
export class SuppressionLookupBatcher {
  private readonly readyRecords = new Set<SuppressionLookupHandle>();
  private openWindow: LookupWindow | undefined;

  constructor(
    private readonly outcomeReader: SuppressionOutcomeReader,
    private readonly recordCount: number,
    private readonly sleeper: Sleeper = getSleeper(),
  ) {}

  createRecordHandle(): SuppressionLookupHandle {
    const handle: SuppressionLookupHandle = {
      lookUp: (target) => this.lookUp(handle, target),
      finish: () => this.markReady(handle),
    };
    return handle;
  }

  private lookUp(handle: SuppressionLookupHandle, target: SuppressionLookupTarget): Promise<SuppressionVerdict> {
    return new Promise((resolve, reject) => {
      const isNewWindow = this.openWindow === undefined;
      const window: LookupWindow = this.openWindow ?? { pendingLookups: [] };
      this.openWindow = window;
      window.pendingLookups.push({ target, resolve, reject });
      this.readyRecords.add(handle);

      if (this.isEveryRecordReady() || window.pendingLookups.length >= MAX_LOOKUPS_PER_WINDOW) {
        this.send(window);
      } else if (isNewWindow) {
        const sendWhenWindowEnds = (): void => this.send(window);
        this.sleeper.sleep(SUPPRESSION_LOOKUP_WINDOW_MS).then(sendWhenWindowEnds, sendWhenWindowEnds);
      }
    });
  }

  private markReady(handle: SuppressionLookupHandle): void {
    this.readyRecords.add(handle);
    if (this.openWindow && this.isEveryRecordReady()) this.send(this.openWindow);
  }

  private isEveryRecordReady(): boolean {
    return this.readyRecords.size >= this.recordCount;
  }

  /** Does nothing for a window already sent, so a timer that outlives its window cannot send a newer one. */
  private send(window: LookupWindow): void {
    if (window !== this.openWindow) return;
    this.openWindow = undefined;
    this.settle(window.pendingLookups);
  }

  private async settle(pendingLookups: PendingLookup[]): Promise<void> {
    try {
      const outcomes = await this.outcomeReader.readSuppressionOutcomes(
        pendingLookups.map((pendingLookup) => pendingLookup.target),
      );
      pendingLookups.forEach((pendingLookup, index) => settleLookup(pendingLookup, outcomes[index]));
    } catch (error) {
      pendingLookups.forEach((pendingLookup) => pendingLookup.reject(error));
    }
  }
}

function settleLookup(pendingLookup: PendingLookup, outcome: SuppressionLookupOutcome): void {
  if (outcome.status === 'FAILED') {
    pendingLookup.reject(outcome.error);
  } else {
    pendingLookup.resolve(outcome.status);
  }
}
