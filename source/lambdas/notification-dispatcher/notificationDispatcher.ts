// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import type { LambdaInterface } from '@aws-lambda-powertools/commons/types';
import { Context, SQSEvent, SQSHandler, SQSRecord } from 'aws-lambda';
import { BatchProcessor, EventType, processPartialResponse } from '@aws-lambda-powertools/batch';
import { NotificationEventSchema } from '@asr/data-models';
import { NotificationDispatcherService } from './notificationDispatcherService';
import { notificationDispatcherEnvironment } from './notificationDispatcherEnvironment';
import { createDynamoDBClient } from '../common/utils/dynamodb';
import { getLogger } from '../common/utils/logger';
import { getTracer } from '../common/utils/tracer';
import { computeStaleProcessingMs } from '../common/repositories/notificationBatchRepository';
import { SNSClient } from '@aws-sdk/client-sns';

const env = notificationDispatcherEnvironment();

const configTableName = env.NOTIFICATION_CONFIG_TABLE_NAME;
const batchesTableName = env.NOTIFICATION_BATCHES_TABLE_NAME;
// RESOURCE_FILTERS_TABLE_NAME: validated by requireEnvironmentVariables(); optional in interface for stacked-CR build compatibility (CR4 adds CDK provider)
const resourceFiltersTableName = env.RESOURCE_FILTERS_TABLE_NAME || '';

const tracer = getTracer(env.SOLUTION_TRADEMARKEDNAME);
const logger = getLogger(env.SOLUTION_TRADEMARKEDNAME);
const processor = new BatchProcessor(EventType.SQS);

const dynamoDBClient = tracer.captureAWSv3Client(createDynamoDBClient({ maxAttempts: 10 }));
const snsClient = tracer.captureAWSv3Client(new SNSClient({}));

const dispatcherService = new NotificationDispatcherService({
  configTableName,
  batchesTableName,
  resourceFiltersTableName,
  dynamoDBClient,
  logger,
  snsClient,
  channelFanoutTopicArn: env.CHANNEL_FANOUT_TOPIC_ARN,
  staleProcessingMs: computeStaleProcessingMs(env.LAMBDA_TIMEOUT_SECONDS || ''),
});

export class NotificationDispatcher implements LambdaInterface {
  @tracer.captureLambdaHandler()
  @logger.injectLambdaContext()
  async handler(event: SQSEvent, context: Context) {
    return processPartialResponse(event, NotificationDispatcher.recordHandler, processor, { context });
  }

  static async recordHandler(record: SQSRecord): Promise<void> {
    let parsed: unknown;
    try {
      parsed = JSON.parse(record.body);
    } catch {
      logger.warn('Malformed JSON in SQS record, skipping', { messageId: record.messageId });
      return;
    }

    const result = NotificationEventSchema.safeParse(parsed);
    if (!result.success) {
      logger.info('Invalid NotificationEvent schema, skipping', {
        messageId: record.messageId,
        errors: result.error.issues,
      });
      return;
    }

    await dispatcherService.dispatch(result.data);
  }
}

const instance = new NotificationDispatcher();
export const handler: SQSHandler = instance.handler.bind(instance);
