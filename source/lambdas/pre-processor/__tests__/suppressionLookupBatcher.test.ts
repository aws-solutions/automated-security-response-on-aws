// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { GetFindingsCommand, GetFindingsV2Command, SecurityHubClient } from '@aws-sdk/client-securityhub';
import { mockClient } from 'aws-sdk-client-mock';
import { Sleeper } from '../../common/utils/sleeper';
import { SecurityHubUtils, SuppressionLookupTarget } from '../../common/utils/securityHub';
import { SuppressionLookupBatcher } from '../suppressionLookupBatcher';

const securityHubMock = mockClient(SecurityHubClient);

class ControlledSleeper implements Sleeper {
  readonly requestedDurations: number[] = [];
  private readonly wakeUps: Array<() => void> = [];

  sleep(milliseconds: number): Promise<void> {
    this.requestedDurations.push(milliseconds);
    return new Promise((resolve) => this.wakeUps.push(resolve));
  }

  wakeOldest(): void {
    this.wakeUps.shift()?.();
  }
}

const cspmTarget = (suffix: string): SuppressionLookupTarget => ({
  findingId: `arn:aws:securityhub:us-east-1:111111111111:security-control/S3.1/finding/${suffix}`,
  shouldCheckCspm: true,
  shouldCheckSecurityHubV2: false,
});

const letPendingWorkRun = (): Promise<void> => new Promise((resolve) => setImmediate(resolve));

const requestedCspmIds = (callIndex: number): string[] =>
  (securityHubMock.commandCalls(GetFindingsCommand)[callIndex].args[0].input.Filters?.Id ?? []).map(
    (filter) => filter.Value ?? '',
  );

describe('SuppressionLookupBatcher', () => {
  let sleeper: ControlledSleeper;
  const createBatcher = (recordCount: number): SuppressionLookupBatcher =>
    new SuppressionLookupBatcher(new SecurityHubUtils(new SecurityHubClient({ maxAttempts: 1 })), recordCount, sleeper);

  beforeEach(() => {
    securityHubMock.reset();
    securityHubMock.on(GetFindingsCommand).resolves({ Findings: [] });
    securityHubMock.on(GetFindingsV2Command).resolves({ Findings: [] });
    sleeper = new ControlledSleeper();
  });

  it('holds lookups for a 250 ms window and sends the lookups that joined it in one call', async () => {
    // ARRANGE
    const batcher = createBatcher(3);
    const [first, second] = [batcher.createRecordHandle(), batcher.createRecordHandle()];

    // ACT
    const firstLookup = first.lookUp(cspmTarget('first'));
    const secondLookup = second.lookUp(cspmTarget('second'));
    await letPendingWorkRun();
    const callsBeforeTimer = securityHubMock.commandCalls(GetFindingsCommand).length;
    sleeper.wakeOldest();

    // ASSERT
    await expect(Promise.all([firstLookup, secondLookup])).resolves.toEqual(['UNRESOLVED', 'UNRESOLVED']);
    expect(callsBeforeTimer).toBe(0);
    expect(sleeper.requestedDurations).toEqual([250]);
    expect(securityHubMock.commandCalls(GetFindingsCommand)).toHaveLength(1);
    expect(requestedCspmIds(0)).toEqual([cspmTarget('first').findingId, cspmTarget('second').findingId]);
  });

  it('sends without waiting once every record has asked or finished, counting each record once', async () => {
    // ARRANGE
    const batcher = createBatcher(3);
    const [asksThenFinishes, finishesWithoutAsking, asksLast] = [
      batcher.createRecordHandle(),
      batcher.createRecordHandle(),
      batcher.createRecordHandle(),
    ];

    // ACT
    const firstLookup = asksThenFinishes.lookUp(cspmTarget('first'));
    asksThenFinishes.finish();
    const lastLookup = asksLast.lookUp(cspmTarget('last'));
    await letPendingWorkRun();
    const callsBeforeLastRecord = securityHubMock.commandCalls(GetFindingsCommand).length;
    finishesWithoutAsking.finish();

    // ASSERT
    await expect(Promise.all([firstLookup, lastLookup])).resolves.toEqual(['UNRESOLVED', 'UNRESOLVED']);
    expect(callsBeforeLastRecord).toBe(0);
    expect(securityHubMock.commandCalls(GetFindingsCommand)).toHaveLength(1);
    expect(requestedCspmIds(0)).toEqual([cspmTarget('first').findingId, cspmTarget('last').findingId]);
  });

  it('sends the lookup of a batch of one at once, without starting a timer', async () => {
    // ARRANGE
    const handle = createBatcher(1).createRecordHandle();

    // ACT
    const verdict = await handle.lookUp(cspmTarget('alone'));

    // ASSERT
    expect(verdict).toBe('UNRESOLVED');
    expect(sleeper.requestedDurations).toEqual([]);
    expect(securityHubMock.commandCalls(GetFindingsCommand)).toHaveLength(1);
  });

  it('sends a full window of 10 at once, reads a later lookup fresh, and ignores the sent window timer', async () => {
    // ARRANGE
    const batcher = createBatcher(12);
    const handles = Array.from({ length: 11 }, () => batcher.createRecordHandle());
    const fullWindowLookups = handles.slice(0, 10).map((handle, index) => handle.lookUp(cspmTarget(`full-${index}`)));
    await Promise.all(fullWindowLookups);

    // ACT
    const lateLookup = handles[10].lookUp(cspmTarget('full-0'));
    sleeper.wakeOldest();
    await letPendingWorkRun();
    const callsAfterStaleTimer = securityHubMock.commandCalls(GetFindingsCommand).length;
    sleeper.wakeOldest();
    await lateLookup;

    // ASSERT
    expect(requestedCspmIds(0)).toHaveLength(10);
    expect(callsAfterStaleTimer).toBe(1);
    expect(securityHubMock.commandCalls(GetFindingsCommand)).toHaveLength(2);
    expect(requestedCspmIds(1)).toEqual([cspmTarget('full-0').findingId]);
    expect(sleeper.requestedDurations).toEqual([250, 250]);
  });

  it('settles each lookup with its own outcome when one view fails', async () => {
    // ARRANGE
    const batcher = createBatcher(2);
    const securityHubV2Target: SuppressionLookupTarget = { ...cspmTarget('needs-v2'), shouldCheckSecurityHubV2: true };
    securityHubMock.on(GetFindingsV2Command).rejects(new Error('V2 unavailable'));

    // ACT
    const cspmOnlyLookup = batcher.createRecordHandle().lookUp(cspmTarget('cspm-only'));
    const securityHubV2Lookup = batcher.createRecordHandle().lookUp(securityHubV2Target);

    // ASSERT
    await expect(cspmOnlyLookup).resolves.toBe('UNRESOLVED');
    await expect(securityHubV2Lookup).rejects.toThrow('V2 unavailable');
  });

  it('rejects every lookup in the window when the read itself fails', async () => {
    // ARRANGE: SecurityHubUtils settles every view, so no Security Hub error reaches this path; a fake reader stands in
    const failingReader = { readSuppressionOutcomes: () => Promise.reject(new Error('read failed')) };
    const batcher = new SuppressionLookupBatcher(failingReader, 2, sleeper);

    // ACT
    const lookups = [batcher.createRecordHandle(), batcher.createRecordHandle()].map((handle, index) =>
      handle.lookUp(cspmTarget(`failing-${index}`)),
    );

    // ASSERT
    await expect(lookups[0]).rejects.toThrow('read failed');
    await expect(lookups[1]).rejects.toThrow('read failed');
  });
});
