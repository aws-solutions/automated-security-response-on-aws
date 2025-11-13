// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { SFNClient, StartExecutionCommand } from '@aws-sdk/client-sfn';
import { Logger } from '@aws-lambda-powertools/logger';

const ORCHESTRATOR_ARN = process.env.ORCHESTRATOR_ARN;

export function createSFNClient(): SFNClient {
  return new SFNClient({ maxAttempts: 10 });
}

/**
 * Executes the orchestrator Step Function with the provided input
 * @param input - The JSON string input for the Step Function
 * @param logger - Logger instance for logging
 * @param sfnClient - Optional SFN client instance (will create one if not provided)
 * @returns The execution ID of the started Step Function execution or undefined if extraction fails
 */
export async function executeOrchestrator(
  input: string,
  logger: Logger,
  sfnClient?: SFNClient,
): Promise<string | undefined> {
  if (!ORCHESTRATOR_ARN) {
    throw new Error('ORCHESTRATOR_ARN env is required');
  }

  const client = sfnClient || createSFNClient();

  const response = await client.send(
    new StartExecutionCommand({
      stateMachineArn: ORCHESTRATOR_ARN,
      input,
    }),
  );

  const executionArn = response.executionArn;

  if (!executionArn) {
    logger.warn('Failed to get execution ARN from response', {
      executionArn: response.executionArn,
    });
    return undefined;
  }

  logger.debug(`Orchestrator triggered on input ${input}`, { executionArn });

  return executionArn;
}
