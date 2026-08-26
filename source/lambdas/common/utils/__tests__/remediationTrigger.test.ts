// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import type { Logger } from '@aws-lambda-powertools/logger';
import { triggerRemediationForFinding } from '../remediationTrigger';
import { executeOrchestrator } from '../orchestrator';

jest.mock('../orchestrator');

const executeOrchestratorMock = executeOrchestrator as jest.MockedFunction<typeof executeOrchestrator>;

describe('triggerRemediationForFinding', () => {
  let logger: Logger;

  beforeEach(() => {
    jest.clearAllMocks();
    logger = { debug: jest.fn(), info: jest.fn(), warn: jest.fn(), error: jest.fn() } as unknown as Logger;
  });

  it('persists history with the execution id and returns it when the orchestrator starts', async () => {
    // ARRANGE
    executeOrchestratorMock.mockResolvedValueOnce('exec-1');
    const persistHistory = jest.fn().mockResolvedValue(undefined);

    // ACT
    const executionId = await triggerRemediationForFinding({
      orchestratorInput: '{"detail":{}}',
      logger,
      persistHistory,
    });

    // ASSERT — orchestrator started, history persisted with the returned id, id returned to caller
    expect(executeOrchestratorMock).toHaveBeenCalledWith('{"detail":{}}', logger, undefined);
    expect(persistHistory).toHaveBeenCalledWith('exec-1');
    expect(executionId).toBe('exec-1');
  });

  it('does not persist history and returns undefined when the orchestrator returns no execution id', async () => {
    // ARRANGE
    executeOrchestratorMock.mockResolvedValueOnce(undefined);
    const persistHistory = jest.fn().mockResolvedValue(undefined);

    // ACT
    const executionId = await triggerRemediationForFinding({
      orchestratorInput: '{"detail":{}}',
      logger,
      persistHistory,
    });

    // ASSERT — history is never written without an execution id (avoids a malformed composite key)
    expect(persistHistory).not.toHaveBeenCalled();
    expect(executionId).toBeUndefined();
  });

  it('propagates a persistHistory failure so the caller can decide how to handle it', async () => {
    // ARRANGE
    executeOrchestratorMock.mockResolvedValueOnce('exec-1');
    const persistHistory = jest.fn().mockRejectedValue(new Error('write failed'));

    // ACT & ASSERT
    await expect(
      triggerRemediationForFinding({ orchestratorInput: '{"detail":{}}', logger, persistHistory }),
    ).rejects.toThrow('write failed');
  });

  it('forwards an optional SFN client to the orchestrator', async () => {
    // ARRANGE
    executeOrchestratorMock.mockResolvedValueOnce('exec-1');
    const persistHistory = jest.fn().mockResolvedValue(undefined);
    const sfnClient = {} as never;

    // ACT
    await triggerRemediationForFinding({ orchestratorInput: '{"detail":{}}', logger, persistHistory, sfnClient });

    // ASSERT
    expect(executeOrchestratorMock).toHaveBeenCalledWith('{"detail":{}}', logger, sfnClient);
  });
});
