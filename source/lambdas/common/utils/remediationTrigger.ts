// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import type { Logger } from '@aws-lambda-powertools/logger';
import type { SFNClient } from '@aws-sdk/client-sfn';
import { executeOrchestrator } from './orchestrator';

export interface TriggerRemediationForFindingParams {
  /**
   * Pre-built Step Function input. Callers construct this from whichever finding shape they hold
   * (the API and overdue-enforcement paths build it from ASFF, the pre-processor from the native
   * finding payload), so this helper takes the already-serialized input rather than building it.
   */
  orchestratorInput: string;
  logger: Logger;
  /**
   * Persists the remediation-history record once the orchestrator has started. Invoked only when an
   * execution id is returned. The caller owns the persistence method, the fields written, and
   * whether a persistence failure propagates or is swallowed.
   */
  persistHistory: (executionId: string) => Promise<void>;
  sfnClient?: SFNClient;
}

/**
 * Starts the Orchestrator Step Function for a single finding and, on a successful start, persists a
 * remediation-history record via {@link TriggerRemediationForFindingParams.persistHistory}. Returns
 * the execution id, or `undefined` when the Orchestrator did not return one.
 *
 * History is persisted only when an execution id is present: the history composite key
 * `findingId#executionId` would be malformed (`findingId#`) without it, corrupting later lookups.
 * This invariant is the reason every remediation trigger routes through this helper.
 */
export async function triggerRemediationForFinding(
  params: TriggerRemediationForFindingParams,
): Promise<string | undefined> {
  const { orchestratorInput, logger, persistHistory, sfnClient } = params;

  const executionId = await executeOrchestrator(orchestratorInput, logger, sfnClient);

  if (!executionId) {
    return undefined;
  }

  await persistHistory(executionId);

  return executionId;
}
