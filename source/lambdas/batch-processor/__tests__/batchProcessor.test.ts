// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import type { Context, ScheduledEvent } from 'aws-lambda';

const mockProcessBatches = jest.fn();
const mockRemediateOverdueFindings = jest.fn();
const mockRunOutstandingReconciliationTasks = jest.fn();

jest.mock('../batchProcessorService', () => ({
  BatchProcessorService: jest.fn(() => ({ processBatches: mockProcessBatches })),
}));

jest.mock('../overdueRemediationService', () => ({
  OverdueRemediationService: jest.fn(() => ({ remediateOverdueFindings: mockRemediateOverdueFindings })),
}));

jest.mock('../reconciliationService', () => ({
  ReconciliationService: jest.fn(() => ({ processTask: jest.fn() })),
}));

jest.mock('../reconciliationTaskRunner', () => ({
  ReconciliationTaskRunner: jest.fn(() => ({
    runOutstandingReconciliationTasks: mockRunOutstandingReconciliationTasks,
  })),
}));

// Imported after the mocks above so the handler module wires the mocked services at load time.
import { handler, parseEnforcementPerRunCap, BatchProcessorHandler } from '../batchProcessor';
import { OverdueRemediationService } from '../overdueRemediationService';

// Captured at load time before any beforeEach jest.clearAllMocks() wipes the construction call.
const overdueServiceConstructorArgs = (OverdueRemediationService as unknown as jest.Mock).mock.calls[0];

const BATCH_RESULT = { processedCount: 1, sentCount: 1, skippedCount: 0, failedCount: 0 };
const ENFORCEMENT_RESULT = {
  findingsEvaluated: 0,
  remediationsTriggered: 0,
  findingsSkippedSuppressedASR: 0,
  findingsSkippedSuppressedSH: 0,
  findingsSkippedIneligible: 0,
  findingsSkippedError: 0,
  findingsRemaining: 0,
};

describe('parseEnforcementPerRunCap', () => {
  it('returns the parsed value for a valid positive integer', () => {
    // ARRANGE / ACT / ASSERT
    expect(parseEnforcementPerRunCap('25')).toBe(25);
  });

  it('falls back to the default of 50 when the value is missing, non-numeric, zero, or negative', () => {
    // ARRANGE / ACT / ASSERT
    expect(parseEnforcementPerRunCap(undefined)).toBe(50);
    expect(parseEnforcementPerRunCap('not-a-number')).toBe(50);
    expect(parseEnforcementPerRunCap('0')).toBe(50);
    expect(parseEnforcementPerRunCap('-5')).toBe(50);
    expect(parseEnforcementPerRunCap('2.5')).toBe(50);
  });
});

describe('BatchProcessorHandler', () => {
  const scheduledEvent = {} as ScheduledEvent;
  const context = {} as Context;

  beforeEach(() => {
    jest.clearAllMocks();
    mockProcessBatches.mockResolvedValue(BATCH_RESULT);
    mockRemediateOverdueFindings.mockResolvedValue(ENFORCEMENT_RESULT);
    mockRunOutstandingReconciliationTasks.mockResolvedValue(undefined);
  });

  it('constructs the overdue remediation service with the default per-run cap', () => {
    // ARRANGE / ACT
    const perRunCap = overdueServiceConstructorArgs[4];

    // ASSERT - envSetup does not define ENFORCEMENT_PER_RUN_CAP, so the default applies
    expect(perRunCap).toBe(50);
  });

  it('runs batch processing, then reconciliation, then overdue remediation enforcement in order', async () => {
    // ARRANGE / ACT
    await handler(scheduledEvent, context);

    // ASSERT - reconciliation is applied before the overdue scan, and both run after batch processing
    expect(mockProcessBatches).toHaveBeenCalledTimes(1);
    expect(mockRunOutstandingReconciliationTasks).toHaveBeenCalledTimes(1);
    expect(mockRemediateOverdueFindings).toHaveBeenCalledTimes(1);
    expect(mockProcessBatches.mock.invocationCallOrder[0]).toBeLessThan(
      mockRunOutstandingReconciliationTasks.mock.invocationCallOrder[0],
    );
    expect(mockRunOutstandingReconciliationTasks.mock.invocationCallOrder[0]).toBeLessThan(
      mockRemediateOverdueFindings.mock.invocationCallOrder[0],
    );
  });

  it('still runs overdue remediation when reconciliation fails, and does not throw', async () => {
    // ARRANGE
    mockRunOutstandingReconciliationTasks.mockRejectedValue(new Error('reconciliation boom'));

    // ACT / ASSERT - the reconciliation failure is swallowed so enforcement still runs
    await expect(new BatchProcessorHandler().handler(scheduledEvent, context)).resolves.toBeUndefined();
    expect(mockRunOutstandingReconciliationTasks).toHaveBeenCalledTimes(1);
    expect(mockRemediateOverdueFindings).toHaveBeenCalledTimes(1);
  });

  it('does not throw when enforcement fails, after batch processing already completed', async () => {
    // ARRANGE
    mockRemediateOverdueFindings.mockRejectedValue(new Error('enforcement boom'));

    // ACT / ASSERT - enforcement failure is swallowed so the handler still resolves
    await expect(new BatchProcessorHandler().handler(scheduledEvent, context)).resolves.toBeUndefined();
    expect(mockProcessBatches).toHaveBeenCalledTimes(1);
    expect(mockRemediateOverdueFindings).toHaveBeenCalledTimes(1);
  });
});
