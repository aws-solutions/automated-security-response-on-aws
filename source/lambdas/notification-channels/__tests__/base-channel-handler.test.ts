// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { Context, SNSEvent } from 'aws-lambda';
import { DeliveryChannelConfig } from '@asr/data-models';
import { createChannelHandler } from '../base-channel-handler';
import { BatchChannelFanoutMessage, BatchEventSummary, ChannelFanoutMessage } from '../types';
import { sendMetrics } from '../../common/utils/metricsUtils';
import { createEvent, createContentOptions, createDependencies } from './test-factories';

const mockDependencies = createDependencies();

const createMockChannel = (): DeliveryChannelConfig => ({
  type: 'email',
  enabled: true,
  recipients: [{ recipientType: 'custom', emailAddresses: ['test@example.com'] }],
});

const createSlackChannel = (): DeliveryChannelConfig => ({
  type: 'slack',
  enabled: true,
  credentialsSecretArn: 'arn:aws:secretsmanager:us-east-1:123456789012:secret:webhook-abc123',
});

const createSnsChannel = (): DeliveryChannelConfig => ({
  type: 'sns',
  enabled: true,
  topicArn: 'arn:aws:sns:us-east-1:123456789012:notifications',
});

const createValidMessage = (overrides: Partial<ChannelFanoutMessage> = {}): ChannelFanoutMessage => ({
  configId: 'config-123',
  configName: 'Test Config',
  contentOptions: createContentOptions(),
  channel: createMockChannel(),
  event: createEvent(),
  ...overrides,
});

/** A successfully remediated event, the only shape eligible for IaC snippets. */
const createRemediatedEvent = () =>
  createEvent({ eventType: 'remediation', remediationStatus: 'SUCCESS', eventId: 'evt-remediated' });

const createBatchMessage = (overrides: Partial<BatchChannelFanoutMessage> = {}): BatchChannelFanoutMessage => ({
  configId: 'config-123',
  configName: 'Test Config',
  notificationType: 'remediation',
  contentOptions: createContentOptions(),
  channel: createMockChannel(),
  isBatch: true,
  findingCount: 0,
  remediationCount: 2,
  startGenerationTime: '2024-01-01T00:00:00Z',
  eventSummaries: [],
  ...overrides,
});

const createBatchEventSummaries = (count: number): BatchEventSummary[] =>
  Array.from({ length: count }, (_, index) => ({
    eventId: `evt-${index + 1}`,
    controlId: `S3.${index + 1}`,
    accountId: '123456789012',
    region: 'us-east-1',
    severity: 'High',
    resourceId: `bucket-${index + 1}`,
    remediationStatus: 'SUCCESS',
  }));

const mockContext: Context = {
  callbackWaitsForEmptyEventLoop: false,
  functionName: 'test-function',
  functionVersion: '$LATEST',
  invokedFunctionArn: 'arn:aws:lambda:us-east-1:123456789012:function:test',
  memoryLimitInMB: '128',
  awsRequestId: 'test-request-id',
  logGroupName: '/aws/lambda/test',
  logStreamName: 'test-stream',
  getRemainingTimeInMillis: () => 30000,
  done: () => {},
  fail: () => {},
  succeed: () => {},
};

function createSnsEvent(message: unknown): SNSEvent {
  return {
    Records: [
      {
        Sns: {
          MessageId: 'msg-123',
          Message: JSON.stringify(message),
        },
      },
    ],
  } as SNSEvent;
}

describe('createChannelHandler', () => {
  beforeEach(() => {
    (sendMetrics as jest.Mock).mockClear();
  });

  it('should parse message and call deliver with dependencies', async () => {
    const deliver = jest.fn().mockResolvedValue(undefined);
    const handler = createChannelHandler(mockDependencies, deliver);

    await handler(createSnsEvent(createValidMessage()), mockContext, () => {});

    expect(deliver).toHaveBeenCalledWith(createValidMessage(), mockDependencies);
  });

  it('should throw on invalid JSON', async () => {
    const deliver = jest.fn();
    const handler = createChannelHandler(mockDependencies, deliver);
    // Intentional partial cast: testing error path with malformed SNS message
    const event = {
      Records: [{ Sns: { MessageId: 'msg-bad', Message: 'not-json' } }],
    } as SNSEvent;

    await expect(handler(event, mockContext, () => {})).rejects.toThrow();
    expect(deliver).not.toHaveBeenCalled();
  });

  it('should throw when parsed JSON does not match ChannelFanoutMessage shape', async () => {
    const deliver = jest.fn();
    const handler = createChannelHandler(mockDependencies, deliver);
    // Intentional partial cast: testing error path with invalid message shape
    const event = {
      Records: [{ Sns: { MessageId: 'msg-bad', Message: JSON.stringify({ unrelated: 'data' }) } }],
    } as SNSEvent;

    await expect(handler(event, mockContext, () => {})).rejects.toThrow(
      'Message does not match ChannelFanoutMessage shape',
    );
    expect(deliver).not.toHaveBeenCalled();
  });

  it('should throw when deliver fails', async () => {
    const deliver = jest.fn().mockRejectedValue(new Error('delivery failed'));
    const handler = createChannelHandler(mockDependencies, deliver);

    await expect(handler(createSnsEvent(createValidMessage()), mockContext, () => {})).rejects.toThrow(
      'delivery failed',
    );
  });

  it('should process multiple records', async () => {
    const deliver = jest.fn().mockResolvedValue(undefined);
    const handler = createChannelHandler(mockDependencies, deliver);
    // Intentional partial cast: only fields relevant to handler logic are populated
    const event = {
      Records: [
        { Sns: { MessageId: 'msg-1', Message: JSON.stringify(createValidMessage()) } },
        { Sns: { MessageId: 'msg-2', Message: JSON.stringify(createValidMessage()) } },
      ],
    } as SNSEvent;

    await handler(event, mockContext, () => {});

    expect(deliver).toHaveBeenCalledTimes(2);
  });

  it('should emit a delivery_succeeded metric on successful delivery', async () => {
    // ARRANGE
    const deliver = jest.fn().mockResolvedValue(undefined);
    const handler = createChannelHandler(mockDependencies, deliver);

    // ACT
    await handler(createSnsEvent(createValidMessage()), mockContext, () => {});

    // ASSERT
    expect(sendMetrics).toHaveBeenCalledWith({
      delivery_attempt: 1,
      delivery_succeeded: 1,
      config_id: 'config-123',
      channel_type: 'email',
      iac_snippet_count: 0,
    });
  });

  it('should emit a delivery_succeeded=0 metric and rethrow when delivery fails', async () => {
    // ARRANGE
    const deliver = jest.fn().mockRejectedValue(new Error('delivery failed'));
    const handler = createChannelHandler(mockDependencies, deliver);

    // ACT & ASSERT
    await expect(handler(createSnsEvent(createValidMessage()), mockContext, () => {})).rejects.toThrow(
      'delivery failed',
    );
    expect(sendMetrics).toHaveBeenCalledWith({
      delivery_attempt: 1,
      delivery_succeeded: 0,
      config_id: 'config-123',
      channel_type: 'email',
      iac_snippet_count: 0,
    });
  });

  describe('iac_snippet_count', () => {
    const getMetricPayload = () => (sendMetrics as jest.Mock).mock.calls[0][0];

    it('should count one snippet per selected format for a successful remediation', async () => {
      // ARRANGE
      const deliver = jest.fn().mockResolvedValue(undefined);
      const handler = createChannelHandler(mockDependencies, deliver);
      const message = createValidMessage({
        contentOptions: createContentOptions({
          includeIaCSnippet: true,
          iacFormats: ['cloudformation-yaml', 'terraform', 'cdk'],
        }),
        event: createRemediatedEvent(),
      });

      // ACT
      await handler(createSnsEvent(message), mockContext, () => {});

      // ASSERT
      expect(getMetricPayload()).toEqual(
        expect.objectContaining({ iac_snippet_count: 3, delivery_succeeded: 1, config_id: 'config-123' }),
      );
    });

    it('should count 0 when snippets are disabled, no formats are selected, or the event is ineligible', async () => {
      // ARRANGE
      const bothFormats = ['cloudformation-yaml', 'terraform'] as const;
      const cases: ChannelFanoutMessage[] = [
        createValidMessage({
          contentOptions: createContentOptions({ includeIaCSnippet: false, iacFormats: [...bothFormats] }),
          event: createRemediatedEvent(),
        }),
        createValidMessage({
          contentOptions: createContentOptions({ includeIaCSnippet: true, iacFormats: [] }),
          event: createRemediatedEvent(),
        }),
        // A finding event and a failed remediation are both IaC-ineligible.
        createValidMessage({
          contentOptions: createContentOptions({ includeIaCSnippet: true, iacFormats: [...bothFormats] }),
          event: createEvent({ eventType: 'finding' }),
        }),
        createValidMessage({
          contentOptions: createContentOptions({ includeIaCSnippet: true, iacFormats: [...bothFormats] }),
          event: createEvent({ eventType: 'remediation', remediationStatus: 'FAILED' }),
        }),
      ];

      for (const message of cases) {
        (sendMetrics as jest.Mock).mockClear();
        const deliver = jest.fn().mockResolvedValue(undefined);
        const handler = createChannelHandler(mockDependencies, deliver);

        // ACT
        await handler(createSnsEvent(message), mockContext, () => {});

        // ASSERT
        expect(getMetricPayload()).toEqual(expect.objectContaining({ iac_snippet_count: 0 }));
      }
    });

    it('should sum snippets across every event summary in a batch notification', async () => {
      // ARRANGE
      const deliver = jest.fn().mockResolvedValue(undefined);
      const deliverBatch = jest.fn().mockResolvedValue(undefined);
      const handler = createChannelHandler(mockDependencies, deliver, deliverBatch);
      const message = createBatchMessage({
        channel: createSlackChannel(),
        contentOptions: createContentOptions({
          includeIaCSnippet: true,
          iacFormats: ['cloudformation-yaml', 'terraform'],
        }),
        eventSummaries: createBatchEventSummaries(3),
      });

      // ACT
      await handler(createSnsEvent(message), mockContext, () => {});

      // ASSERT
      // 3 summaries x 2 formats
      expect(getMetricPayload()).toEqual(
        expect.objectContaining({ iac_snippet_count: 6, delivery_succeeded: 1, channel_type: 'slack' }),
      );
    });

    it('should count batch snippets the same way on every channel', async () => {
      // ARRANGE
      // Every channel now carries IaC links in batch bodies, so the count does
      // not depend on which channel delivered the notification.
      const contentOptions = createContentOptions({
        includeIaCSnippet: true,
        iacFormats: ['cloudformation-yaml', 'terraform'],
      });
      const eventSummaries = createBatchEventSummaries(3);

      for (const channel of [createMockChannel(), createSnsChannel(), createSlackChannel()]) {
        (sendMetrics as jest.Mock).mockClear();
        const deliver = jest.fn().mockResolvedValue(undefined);
        const deliverBatch = jest.fn().mockResolvedValue(undefined);
        const handler = createChannelHandler(mockDependencies, deliver, deliverBatch);
        const message = createBatchMessage({ channel, contentOptions, eventSummaries });

        // ACT
        await handler(createSnsEvent(message), mockContext, () => {});

        // ASSERT
        expect(getMetricPayload()).toEqual(
          expect.objectContaining({ iac_snippet_count: 6, delivery_succeeded: 1, channel_type: channel.type }),
        );
      }
    });

    it('should skip summaries without an eventId when counting a batch notification', async () => {
      // ARRANGE
      const deliver = jest.fn().mockResolvedValue(undefined);
      const deliverBatch = jest.fn().mockResolvedValue(undefined);
      const handler = createChannelHandler(mockDependencies, deliver, deliverBatch);
      const [withEventId, withoutEventId] = createBatchEventSummaries(2);
      const message = createBatchMessage({
        channel: createSlackChannel(),
        contentOptions: createContentOptions({ includeIaCSnippet: true, iacFormats: ['terraform'] }),
        eventSummaries: [withEventId, { ...withoutEventId, eventId: undefined }],
      });

      // ACT
      await handler(createSnsEvent(message), mockContext, () => {});

      // ASSERT
      expect(getMetricPayload()).toEqual(expect.objectContaining({ iac_snippet_count: 1 }));
    });

    it('should report the count on a failed delivery alongside delivery_succeeded=0', async () => {
      // ARRANGE
      const deliver = jest.fn().mockRejectedValue(new Error('delivery failed'));
      const handler = createChannelHandler(mockDependencies, deliver);
      const message = createValidMessage({
        contentOptions: createContentOptions({ includeIaCSnippet: true, iacFormats: ['cdk'] }),
        event: createRemediatedEvent(),
      });

      // ACT & ASSERT
      await expect(handler(createSnsEvent(message), mockContext, () => {})).rejects.toThrow('delivery failed');
      expect(getMetricPayload()).toEqual(
        expect.objectContaining({ iac_snippet_count: 1, delivery_succeeded: 0, delivery_attempt: 1 }),
      );
    });

    it('should report the count on a failed batch delivery alongside delivery_succeeded=0', async () => {
      // ARRANGE
      const deliver = jest.fn().mockResolvedValue(undefined);
      const deliverBatch = jest.fn().mockRejectedValue(new Error('batch delivery failed'));
      const handler = createChannelHandler(mockDependencies, deliver, deliverBatch);
      const message = createBatchMessage({
        channel: createSlackChannel(),
        contentOptions: createContentOptions({ includeIaCSnippet: true, iacFormats: ['terraform'] }),
        eventSummaries: createBatchEventSummaries(2),
      });

      // ACT & ASSERT
      await expect(handler(createSnsEvent(message), mockContext, () => {})).rejects.toThrow('batch delivery failed');
      expect(getMetricPayload()).toEqual(expect.objectContaining({ iac_snippet_count: 2, delivery_succeeded: 0 }));
    });

    it('should report 0 without failing an already-successful delivery when the message is malformed', async () => {
      // ARRANGE
      // iacFormats arrives as a string rather than an array, so link building
      // throws. Counting must absorb that: the notification has already been
      // delivered, so propagating would trigger an SNS retry and a duplicate.
      const deliver = jest.fn().mockResolvedValue(undefined);
      const handler = createChannelHandler(mockDependencies, deliver);
      const message = {
        ...createValidMessage({ event: createRemediatedEvent() }),
        contentOptions: { ...createContentOptions({ includeIaCSnippet: true }), iacFormats: 'cloudformation-yaml' },
      };

      // ACT
      await handler(createSnsEvent(message), mockContext, () => {});

      // ASSERT
      expect(getMetricPayload()).toEqual(
        expect.objectContaining({ iac_snippet_count: 0, delivery_succeeded: 1, delivery_attempt: 1 }),
      );
    });
  });
});
