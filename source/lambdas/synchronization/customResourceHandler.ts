// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import type { LambdaInterface } from '@aws-lambda-powertools/commons/types';
import { CloudFormationCustomResourceEvent, Context } from 'aws-lambda';
import { ExecutionAlreadyExists, SFNClient, StartExecutionCommand } from '@aws-sdk/client-sfn';
import { getLogger } from '../common/utils/logger';
import { getTracer } from '../common/utils/tracer';
import { Clock, getClock } from '../common/utils/clock';
import { synchronizationTriggerEnvironment } from './synchronizationTriggerEnvironment';

interface CustomResourceResult {
  status: 'SUCCESS' | 'FAILED';
  data: Record<string, any>;
}

const SOLUTION_TRADEMARKEDNAME = process.env.SOLUTION_TRADEMARKEDNAME ?? 'automated-security-response-on-aws';

const tracer = getTracer(SOLUTION_TRADEMARKEDNAME);
const logger = getLogger(SOLUTION_TRADEMARKEDNAME);

export class SynchronizationTrigger implements LambdaInterface {
  private readonly clock: Clock;

  constructor(clock: Clock = getClock()) {
    this.clock = clock;
  }

  @tracer.captureLambdaHandler()
  @logger.injectLambdaContext()
  async handler(event: CloudFormationCustomResourceEvent, context: Context) {
    logger.info('Synchronization trigger custom resource invoked', {
      requestType: event.RequestType,
      resourceType: event.ResourceType,
      logicalResourceId: event.LogicalResourceId,
    });

    const result = await this.processCustomResourceRequest(event);

    try {
      await this.sendResponse(event, context, result.status, result.data);
    } catch (responseError) {
      logger.error('Failed to send response to CloudFormation', { responseError });
      // Don't re-throw here to prevent Lambda from retrying
    }
  }

  private async processCustomResourceRequest(event: CloudFormationCustomResourceEvent): Promise<CustomResourceResult> {
    try {
      if (event.RequestType === 'Create') {
        return await this.handleCreateRequest(event);
      } else {
        return {
          status: 'SUCCESS',
          data: { Message: `No action required for ${event.RequestType}` },
        };
      }
    } catch (error) {
      logger.error(`Custom resource failed: ${error}`, {
        requestType: event.RequestType,
        error: error instanceof Error ? error.message : 'Unknown error',
      });

      return {
        status: 'FAILED',
        data: { Message: error instanceof Error ? error.message : 'Unknown error occurred' },
      };
    }
  }

  private async handleCreateRequest(event: CloudFormationCustomResourceEvent): Promise<CustomResourceResult> {
    logger.info('Stack deployment completed, triggering initial synchronization');

    const { SYNCHRONIZATION_STATE_MACHINE_ARN: stateMachineArn } = synchronizationTriggerEnvironment();

    if (!stateMachineArn) {
      logger.warn('SYNCHRONIZATION_STATE_MACHINE_ARN not set, skipping synchronization trigger');
      return {
        status: 'SUCCESS',
        data: { Message: 'Custom resource created successfully, synchronization will be handled by scheduled events' },
      };
    }

    try {
      await this.triggerSynchronization(stateMachineArn);
      return {
        status: 'SUCCESS',
        data: { Message: 'Custom resource created successfully, initial synchronization triggered' },
      };
    } catch (syncError) {
      logger.error('Failed to trigger synchronization', { error: syncError });
      return {
        status: 'FAILED',
        data: {
          Message: 'Custom resource created successfully, but synchronization trigger failed.',
          Warning: syncError instanceof Error ? syncError.message : 'State machine start failed',
        },
      };
    }
  }

  /**
   * Starts the synchronization sweep state machine — one end-to-end pass that imports every finding
   * from AWS Security Hub across all member accounts. StartExecution returns as soon as the execution
   * is accepted, so CloudFormation stack creation continues without waiting for the sweep to finish —
   * the state machine drives the fan-out and reports its own success/failure.
   *
   * A deterministic per-UTC-day execution name makes the start idempotent: Step Functions rejects a
   * second execution with the same name, so a stack-create retry (or the weekly schedule firing the
   * same day) cannot launch a second concurrent sweep that would race the first on the account
   * cursors. `ExecutionAlreadyExists` therefore means "already running today" — the desired state, not
   * an error.
   */
  private async triggerSynchronization(stateMachineArn: string): Promise<void> {
    const sfnClient = tracer.captureAWSv3Client(new SFNClient({}));

    const executionName = `initial-sync-${this.clock.now().toISOString().slice(0, 10)}`;
    logger.info('Starting synchronization sweep state machine', { stateMachineArn, executionName });

    try {
      const response = await sfnClient.send(new StartExecutionCommand({ stateMachineArn, name: executionName }));
      logger.info('Synchronization sweep state machine started', { executionArn: response.executionArn });
    } catch (error) {
      if (error instanceof ExecutionAlreadyExists) {
        logger.info('Synchronization sweep is already running for today; skipping duplicate start', {
          executionName,
        });
        return;
      }
      throw error;
    }
  }

  private async sendResponse(
    event: CloudFormationCustomResourceEvent,
    context: Context,
    status: 'SUCCESS' | 'FAILED',
    data: Record<string, any> = {},
  ): Promise<void> {
    const responseBody = JSON.stringify({
      Status: status,
      Reason: `See CloudWatch Log Stream: ${context.logStreamName}`,
      PhysicalResourceId: event.LogicalResourceId,
      StackId: event.StackId,
      RequestId: event.RequestId,
      LogicalResourceId: event.LogicalResourceId,
      Data: data,
    });

    const options = {
      method: 'PUT',
      headers: {
        'Content-Type': '',
        'Content-Length': responseBody.length.toString(),
      },
      body: responseBody,
    };

    try {
      const response = await fetch(event.ResponseURL, options);
      logger.info('CloudFormation response sent', {
        status: response.status,
        statusText: response.statusText,
      });
    } catch (error) {
      logger.error('Failed to send CloudFormation response', { error });
      throw error;
    }
  }
}

const synchronizationTrigger = new SynchronizationTrigger();
export const handler = synchronizationTrigger.handler.bind(synchronizationTrigger);
