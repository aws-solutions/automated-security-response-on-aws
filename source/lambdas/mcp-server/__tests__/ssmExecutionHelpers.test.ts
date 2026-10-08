// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import {
  DeleteDocumentCommand,
  GetAutomationExecutionCommand,
  SSMClient,
  StopAutomationExecutionCommand,
} from '@aws-sdk/client-ssm';
import { mockClient } from 'aws-sdk-client-mock';
import type { Clock } from '../../common/utils/clock';
import type { Sleeper } from '../../common/utils/sleeper';
import {
  generateDocumentName,
  isSuccessful,
  isTerminal,
  tryDeleteDocument,
  waitForTerminalStatus,
} from '../backends/common/ssmExecutionHelpers';

const ssmMock = mockClient(SSMClient);
const client = new SSMClient({});

function advancingTime(): { readonly clock: Clock; readonly sleeper: Sleeper; readonly sleeps: () => number } {
  let now = 0;
  let sleepCount = 0;
  return {
    clock: { now: () => new Date(now) },
    sleeper: {
      sleep: (milliseconds: number) => {
        now += milliseconds;
        sleepCount++;
        return Promise.resolve();
      },
    },
    sleeps: () => sleepCount,
  };
}

/**
 * A clock/sleeper pair whose single sleep jumps past the poll deadline, so the loop
 * runs exactly one in-loop poll and then exits. This is what isolates the poll that
 * happens *after* the loop — with the shared `advancingTime()` the 3s interval fits
 * inside the 30s budget ten times over, so a terminal status would be picked up
 * in-loop and the closing poll would never be reached.
 */
function timeExhaustedByFirstSleep(): { readonly clock: Clock; readonly sleeper: Sleeper } {
  let now = 0;
  return {
    clock: { now: () => new Date(now) },
    sleeper: {
      sleep: () => {
        now += 60_000;
        return Promise.resolve();
      },
    },
  };
}

beforeEach(() => {
  ssmMock.reset();
});

afterAll(() => {
  ssmMock.restore();
});

describe('SSM execution status helpers', () => {
  test('recognizes every terminal and successful status', () => {
    const terminalStatuses = [
      'Success',
      'Failed',
      'TimedOut',
      'Cancelled',
      'CompletedWithSuccess',
      'CompletedWithFailure',
      'Exited',
      'Rejected',
      'ChangeCalendarOverrideRejected',
    ];

    for (const status of terminalStatuses) {
      expect(isTerminal(status)).toBe(true);
    }
    expect(isTerminal('InProgress')).toBe(false);
    expect(isTerminal(undefined)).toBe(false);
    expect(isSuccessful('Success')).toBe(true);
    expect(isSuccessful('CompletedWithSuccess')).toBe(true);
    expect(isSuccessful('Failed')).toBe(false);
  });

  test('polls until an execution reaches a terminal status', async () => {
    // GIVEN
    const time = advancingTime();
    ssmMock
      .on(GetAutomationExecutionCommand)
      .resolvesOnce({ AutomationExecution: { AutomationExecutionStatus: 'InProgress' } })
      .resolves({ AutomationExecution: { AutomationExecutionStatus: 'Success' } });

    // WHEN
    const execution = await waitForTerminalStatus(client, 'execution-1', 10, time.clock, time.sleeper, 'test_tool');

    // THEN
    expect(execution.AutomationExecutionStatus).toBe('Success');
    expect(time.sleeps()).toBe(1);
    expect(ssmMock.commandCalls(StopAutomationExecutionCommand)).toHaveLength(0);
  });

  test('retries throttling errors within the same poll budget', async () => {
    // GIVEN
    const time = advancingTime();
    ssmMock
      .on(GetAutomationExecutionCommand)
      .rejectsOnce(Object.assign(new Error('slow down'), { name: 'ThrottlingException' }))
      .resolves({ AutomationExecution: { AutomationExecutionStatus: 'CompletedWithSuccess' } });

    // WHEN
    const execution = await waitForTerminalStatus(client, 'execution-2', 10, time.clock, time.sleeper, 'test_tool');

    // THEN
    expect(execution.AutomationExecutionStatus).toBe('CompletedWithSuccess');
    expect(time.sleeps()).toBe(1);
  });

  test('retries transient socket errors that carry a code but no $metadata', async () => {
    // GIVEN a dropped connection: an Error with a Node network `code` and no SDK
    // `$metadata`/`name` match — the shape that the status-code and name branches
    // both miss, so only the transient-network-code check keeps the poll alive.
    const time = advancingTime();
    ssmMock
      .on(GetAutomationExecutionCommand)
      .rejectsOnce(Object.assign(new Error('socket hang up'), { code: 'ECONNRESET' }))
      .resolves({ AutomationExecution: { AutomationExecutionStatus: 'Success' } });

    // WHEN
    const execution = await waitForTerminalStatus(client, 'execution-net', 10, time.clock, time.sleeper, 'test_tool');

    // THEN the poll absorbed the socket error and continued to a terminal status
    // rather than aborting the whole test, and never asked to cancel the run.
    expect(execution.AutomationExecutionStatus).toBe('Success');
    expect(time.sleeps()).toBe(1);
    expect(ssmMock.commandCalls(StopAutomationExecutionCommand)).toHaveLength(0);
  });

  test('requests cancellation before surfacing a non-retryable poll failure', async () => {
    // GIVEN
    const time = advancingTime();
    const pollFailure = new Error('invalid execution');
    ssmMock.on(GetAutomationExecutionCommand).rejects(pollFailure);
    ssmMock.on(StopAutomationExecutionCommand).resolves({});

    // WHEN / THEN
    await expect(waitForTerminalStatus(client, 'execution-3', 10, time.clock, time.sleeper, 'test_tool')).rejects.toBe(
      pollFailure,
    );
    expect(ssmMock.commandCalls(StopAutomationExecutionCommand)).toHaveLength(1);
  });

  test('times out and requests cancellation when the execution never finishes', async () => {
    // GIVEN
    const time = advancingTime();
    ssmMock.on(GetAutomationExecutionCommand).resolves({
      AutomationExecution: { AutomationExecutionStatus: 'InProgress' },
    });
    ssmMock.on(StopAutomationExecutionCommand).resolves({});

    // WHEN / THEN
    await expect(
      waitForTerminalStatus(client, 'execution-4', 0, time.clock, time.sleeper, 'test_tool'),
    ).rejects.toThrow(/stop was requested/i);
    expect(ssmMock.commandCalls(StopAutomationExecutionCommand)).toHaveLength(1);
  });

  test('returns an execution that finished during the final sleep instead of reporting a timeout', async () => {
    // GIVEN a run still InProgress on the in-loop poll that reaches Success during the
    // last sleep. The loop sleeps at the bottom, so without a poll after the loop exits
    // this healthy run was reported as a timeout AND had a cancellation requested
    // against an execution that had already completed.
    const time = timeExhaustedByFirstSleep();
    ssmMock
      .on(GetAutomationExecutionCommand)
      .resolvesOnce({ AutomationExecution: { AutomationExecutionStatus: 'InProgress' } })
      .resolves({
        AutomationExecution: { AutomationExecutionStatus: 'Success', AutomationExecutionId: 'execution-5' },
      });
    ssmMock.on(StopAutomationExecutionCommand).resolves({});

    // WHEN
    const execution = await waitForTerminalStatus(client, 'execution-5', 0, time.clock, time.sleeper, 'test_tool');

    // THEN the terminal status is returned and nothing was cancelled
    expect(execution.AutomationExecutionStatus).toBe('Success');
    expect(ssmMock.commandCalls(StopAutomationExecutionCommand)).toHaveLength(0);
  });

  test('a non-retryable failure on the final poll still cancels and surfaces the error', async () => {
    // GIVEN the loop budget is spent and the closing poll fails for a real reason
    const time = timeExhaustedByFirstSleep();
    const pollFailure = new Error('invalid execution');
    ssmMock
      .on(GetAutomationExecutionCommand)
      .resolvesOnce({ AutomationExecution: { AutomationExecutionStatus: 'InProgress' } })
      .rejects(pollFailure);
    ssmMock.on(StopAutomationExecutionCommand).resolves({});

    // WHEN / THEN the added final poll does not swallow a genuine failure
    await expect(waitForTerminalStatus(client, 'execution-6', 0, time.clock, time.sleeper, 'test_tool')).rejects.toBe(
      pollFailure,
    );
    expect(ssmMock.commandCalls(StopAutomationExecutionCommand)).toHaveLength(1);
  });
});

describe('SSM transient document helpers', () => {
  test('reports document cleanup success and failure without throwing', async () => {
    // GIVEN
    ssmMock.on(DeleteDocumentCommand, { Name: 'ASR-Test-Success' }).resolves({});
    ssmMock.on(DeleteDocumentCommand, { Name: 'ASR-Test-Failure' }).rejects(new Error('delete denied'));

    // WHEN
    const success = await tryDeleteDocument(client, 'ASR-Test-Success');
    const failure = await tryDeleteDocument(client, 'ASR-Test-Failure');

    // THEN
    expect(success).toEqual({ cleanedUp: true, deleteError: undefined });
    expect(failure).toEqual({ cleanedUp: false, deleteError: 'delete denied' });
  });

  test('prefixes, sanitizes, and clamps an explicit document name', () => {
    // GIVEN
    const clock: Clock = { now: () => new Date(0) };
    const explicitName = `${'x'.repeat(140)} bad:name`;

    // WHEN
    const name = generateDocumentName('ASR-Custom-Test-', explicitName, undefined, clock);

    // THEN
    expect(name).toHaveLength(128);
    expect(name).toMatch(/^ASR-Custom-Test-[A-Za-z0-9_.-]+$/);
  });

  test('generates a scoped name whose collision suffix survives long control IDs', () => {
    // GIVEN
    const clock: Clock = { now: () => new Date('2026-09-02T12:00:00.000Z') };

    // WHEN
    const name = generateDocumentName('ASR-Custom-Test-', undefined, `S3.${'9'.repeat(200)}`, clock);

    // THEN
    expect(name).toHaveLength(128);
    expect(name).toMatch(/^ASR-Custom-Test-S3-/);
    expect(name).toMatch(/-[a-z0-9]+-[a-f0-9]{8}$/);
  });

  test('clamps the generated name to 128 chars even when the prefix alone overflows the limit', () => {
    // GIVEN a prefix long enough that prefix + suffix already exceed 128, so `room`
    // goes negative, the slug slice is empty, and only the final clamp keeps the
    // generated name within SSM's CreateDocument limit.
    const clock: Clock = { now: () => new Date('2026-09-02T12:00:00.000Z') };

    // WHEN
    const name = generateDocumentName(`ASR-${'x'.repeat(200)}-`, undefined, 'S3.9', clock);

    // THEN
    expect(name.length).toBeLessThanOrEqual(128);
  });
});
