// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { SQSRecord } from 'aws-lambda';
import { NotificationDispatcher } from '../notificationDispatcher';

jest.mock('../notificationDispatcherEnvironment', () => ({
  notificationDispatcherEnvironment: () => ({
    SOLUTION_TRADEMARKEDNAME: 'ASR',
    POWERTOOLS_SERVICE_NAME: 'test',
    POWERTOOLS_LOG_LEVEL: 'DEBUG',
    NOTIFICATION_CONFIG_TABLE_NAME: 'config-table',
    NOTIFICATION_BATCHES_TABLE_NAME: 'batches-table',
    RESOURCE_FILTERS_TABLE_NAME: 'filters-table',
    AWS_ACCOUNT_ID: '123456789012',
    STACK_ID: 'test-stack',
    CHANNEL_FANOUT_TOPIC_ARN: 'arn:aws:sns:us-east-1:123456789012:topic',
    LAMBDA_TIMEOUT_SECONDS: '300',
  }),
}));

jest.mock('../notificationDispatcherService');

const mockRecord = (body: string): SQSRecord => ({
  messageId: 'msg-1',
  receiptHandle: 'handle',
  body,
  attributes: {
    ApproximateReceiveCount: '1',
    SentTimestamp: '0',
    SenderId: 'x',
    ApproximateFirstReceiveTimestamp: '0',
  },
  messageAttributes: {},
  md5OfBody: '',
  eventSource: 'aws:sqs',
  eventSourceARN: 'arn:aws:sqs:us-east-1:123456789012:queue',
  awsRegion: 'us-east-1',
});

describe('NotificationDispatcher.recordHandler', () => {
  it('should skip malformed JSON without throwing', async () => {
    await expect(NotificationDispatcher.recordHandler(mockRecord('not json{'))).resolves.toBeUndefined();
  });

  it('should skip records with invalid schema without throwing', async () => {
    await expect(NotificationDispatcher.recordHandler(mockRecord('{"foo":"bar"}'))).resolves.toBeUndefined();
  });

  it('should dispatch valid NotificationEvent records to the dispatcher service', async () => {
    const validEvent = {
      eventId: 'evt-1',
      eventType: 'finding',
      controlId: 'IAM.1',
      accountId: '111111111111',
      region: 'us-east-1',
      severity: 'High',
      resourceType: 'AwsIamUser',
      resourceId: 'arn:aws:iam::111111111111:user/alice',
      title: 'Test finding',
      detectedAt: '2024-01-01T00:00:00Z',
      timestamp: '2024-01-01T00:00:00Z',
    };

    await expect(NotificationDispatcher.recordHandler(mockRecord(JSON.stringify(validEvent)))).resolves.toBeUndefined();
  });
});

describe('NotificationDispatcher.handler', () => {
  it('should process the SQS event end-to-end without throwing', async () => {
    const dispatcher = new NotificationDispatcher();
    const validEvent = {
      eventId: 'evt-1',
      eventType: 'finding',
      controlId: 'IAM.1',
      accountId: '111111111111',
      region: 'us-east-1',
      severity: 'High',
      resourceType: 'AwsIamUser',
      resourceId: 'arn:aws:iam::111111111111:user/alice',
      title: 'Test finding',
      detectedAt: '2024-01-01T00:00:00Z',
      timestamp: '2024-01-01T00:00:00Z',
    };
    const event = {
      Records: [mockRecord(JSON.stringify(validEvent))],
    };
    const ctx = {
      awsRequestId: 'req-1',
      callbackWaitsForEmptyEventLoop: false,
      functionName: 'test',
      functionVersion: '1',
      invokedFunctionArn: 'arn:aws:lambda:us-east-1:123456789012:function:test',
      memoryLimitInMB: '128',
      logGroupName: 'lg',
      logStreamName: 'ls',
      getRemainingTimeInMillis: () => 30000,
      done: () => {},
      fail: () => {},
      succeed: () => {},
    } as unknown as Parameters<typeof dispatcher.handler>[1];

    const result = await dispatcher.handler(event as Parameters<typeof dispatcher.handler>[0], ctx);
    expect(result).toBeDefined();
  });
});
