// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import type { LambdaInterface } from '@aws-lambda-powertools/commons/types';
import { Context, CloudFormationCustomResourceEvent } from 'aws-lambda';
import { LambdaClient, InvokeCommand } from '@aws-sdk/client-lambda';
import { getLogger } from '../common/utils/logger';
import { getTracer } from '../common/utils/tracer';

interface CustomResourceResult {
  status: 'SUCCESS' | 'FAILED';
  data: Record<string, any>;
}

const SOLUTION_TRADEMARKEDNAME = process.env.SOLUTION_TRADEMARKEDNAME ?? 'automated-security-response-on-aws';

const tracer = getTracer(SOLUTION_TRADEMARKEDNAME);
const logger = getLogger(SOLUTION_TRADEMARKEDNAME);

export class SynchronizationTrigger implements LambdaInterface {
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

    const synchronizationFunctionName = process.env.SYNCHRONIZATION_FUNCTION_NAME;

    if (!synchronizationFunctionName) {
      logger.warn('SYNCHRONIZATION_FUNCTION_NAME not set, skipping synchronization trigger');
      return {
        status: 'SUCCESS',
        data: { Message: 'Custom resource created successfully, synchronization will be handled by scheduled events' },
      };
    }

    try {
      await this.triggerSynchronization(event.ResourceProperties?.TriggerReason || 'WebUI deployment completed');
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
          Warning: syncError instanceof Error ? syncError.message : 'Lambda invocation failed',
        },
      };
    }
  }

  private async triggerSynchronization(triggerReason: string): Promise<void> {
    const synchronizationFunctionName = process.env.SYNCHRONIZATION_FUNCTION_NAME;
    if (!synchronizationFunctionName) {
      throw new Error('SYNCHRONIZATION_FUNCTION_NAME environment variable is not set');
    }

    const lambdaClient = tracer.captureAWSv3Client(new LambdaClient({}));

    const payload = {
      source: 'custom-resource',
      'detail-type': 'Synchronization Trigger',
      detail: {
        triggerReason,
        timestamp: new Date().toISOString(),
      },
    };

    const command = new InvokeCommand({
      FunctionName: synchronizationFunctionName,
      InvocationType: 'Event', // Asynchronous invocation - allows CloudFormation stack creation to continue without waiting for data synchronization to complete. The synchronization Lambda will handle its own success/failure signaling.
      Payload: JSON.stringify(payload),
    });

    logger.info('Triggering synchronization Lambda', {
      functionName: synchronizationFunctionName,
      triggerReason,
    });

    const response = await lambdaClient.send(command);

    if (response.StatusCode !== 202) {
      throw new Error(`Failed to invoke synchronization Lambda. Status: ${response.StatusCode}`);
    }

    logger.info('Synchronization Lambda triggered successfully', {
      statusCode: response.StatusCode,
    });
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
