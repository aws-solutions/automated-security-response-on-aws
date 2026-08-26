// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import type { LambdaInterface } from '@aws-lambda-powertools/commons/types';
import { Context, CloudFormationCustomResourceEvent } from 'aws-lambda';
import { S3Client, PutObjectCommand } from '@aws-sdk/client-s3';
import { getLogger } from '../common/utils/logger';
import { getTracer } from '../common/utils/tracer';

interface CustomResourceResult {
  status: 'SUCCESS' | 'FAILED';
  data: Record<string, string>;
}

const WINDOWS_BASELINE_KEY = 'baseline-overrides/windows-security-baseline.json';

// AWS-RunPatchBaseline's BaselineOverride parameter expects a JSON ARRAY of
// per-operating-system baseline objects (the patching operation selects the
// entry whose OperatingSystem matches the host). A bare object is rejected at
// runtime with "The provided BaselineOverride is invalid json", so this must
// stay wrapped in an array even though it currently holds a single OS entry.
const WINDOWS_SECURITY_BASELINE = JSON.stringify(
  [
    {
      OperatingSystem: 'WINDOWS',
      GlobalFilters: {
        PatchFilters: [
          {
            Key: 'CLASSIFICATION',
            Values: ['SecurityUpdates', 'CriticalUpdates'],
          },
        ],
      },
      ApprovalRules: {
        PatchRules: [
          {
            PatchFilterGroup: {
              PatchFilters: [
                {
                  Key: 'CLASSIFICATION',
                  Values: ['SecurityUpdates', 'CriticalUpdates'],
                },
              ],
            },
            ApproveAfterDays: 0,
            EnableNonSecurity: false,
            ComplianceLevel: 'CRITICAL',
          },
        ],
      },
    },
  ],
  null,
  2,
);

const SOLUTION_TRADEMARKEDNAME = process.env.SOLUTION_TRADEMARKEDNAME ?? 'automated-security-response-on-aws';

const tracer = getTracer(SOLUTION_TRADEMARKEDNAME);
const logger = getLogger(SOLUTION_TRADEMARKEDNAME);

export class BaselineConfigurationHandler implements LambdaInterface {
  @tracer.captureLambdaHandler()
  @logger.injectLambdaContext()
  async handler(event: CloudFormationCustomResourceEvent, context: Context) {
    logger.info('Baseline configuration custom resource invoked', {
      requestType: event.RequestType,
      logicalResourceId: event.LogicalResourceId,
    });

    const result = await this.processRequest(event);

    try {
      await this.sendResponse(event, context, result.status, result.data);
    } catch (responseError) {
      logger.error('Failed to send response to CloudFormation', { responseError });
    }
  }

  private async processRequest(event: CloudFormationCustomResourceEvent): Promise<CustomResourceResult> {
    try {
      if (event.RequestType === 'Delete') {
        return { status: 'SUCCESS', data: { Message: 'No action required for Delete' } };
      }

      return await this.uploadBaseline(event);
    } catch (error) {
      logger.error('Baseline configuration custom resource failed', {
        error: error instanceof Error ? error.message : 'Unknown error',
      });
      return {
        status: 'FAILED',
        data: { Message: error instanceof Error ? error.message : 'Unknown error occurred' },
      };
    }
  }

  private async uploadBaseline(event: CloudFormationCustomResourceEvent): Promise<CustomResourceResult> {
    const bucketName = event.ResourceProperties.BucketName;
    if (!bucketName) {
      throw new Error('BucketName property is required');
    }

    const s3Client = tracer.captureAWSv3Client(new S3Client({}));

    await s3Client.send(
      new PutObjectCommand({
        Bucket: bucketName,
        Key: WINDOWS_BASELINE_KEY,
        Body: WINDOWS_SECURITY_BASELINE,
        ContentType: 'application/json',
      }),
    );

    logger.info('Windows security baseline uploaded', {
      bucket: bucketName,
      key: WINDOWS_BASELINE_KEY,
    });

    return {
      status: 'SUCCESS',
      data: {
        Message: 'Windows security baseline configuration uploaded successfully',
        S3Key: WINDOWS_BASELINE_KEY,
      },
    };
  }

  private async sendResponse(
    event: CloudFormationCustomResourceEvent,
    context: Context,
    status: 'SUCCESS' | 'FAILED',
    data: Record<string, string> = {},
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

    const response = await fetch(event.ResponseURL, {
      method: 'PUT',
      headers: {
        'Content-Type': '',
        'Content-Length': responseBody.length.toString(),
      },
      body: responseBody,
    });

    logger.info('CloudFormation response sent', {
      status: response.status,
      statusText: response.statusText,
    });
  }
}

const baselineConfigurationHandler = new BaselineConfigurationHandler();
export const handler = baselineConfigurationHandler.handler.bind(baselineConfigurationHandler);
