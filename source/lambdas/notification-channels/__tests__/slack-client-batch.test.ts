// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { SlackClient } from '../slack-client';
import { ChannelApiError } from '../notification-channel-errors';
import { BatchChannelFanoutMessage, BatchEventSummary, SlackWebhookUrl } from '../types';
import { Logger } from '@aws-lambda-powertools/logger';
import { setupIaCTestEnvironment, teardownIaCTestEnvironment } from '../test-helpers/iacTestSetup';

function createBatchMessage(overrides: Partial<BatchChannelFanoutMessage> = {}): BatchChannelFanoutMessage {
  const defaults: BatchChannelFanoutMessage = {
    configId: 'config-1',
    configName: 'Production Alerts',
    notificationType: 'finding',
    contentOptions: {
      includeManualRemediationLink: false,
      includeRemediationDeadline: false,
      enforceDeadline: false,
      includeIaCSnippet: false,
      includeEnableAutomationLink: false,
    },
    channel: {
      type: 'slack',
      enabled: true,
      credentialsSecretArn: 'arn:aws:secretsmanager:us-east-1:123456789012:secret:webhook-abc123',
    },
    isBatch: true,
    findingCount: 5,
    remediationCount: 0,
    startGenerationTime: '2024-06-15T10:30:00Z',
    eventSummaries: [],
  };
  return { ...defaults, ...overrides };
}

function createEventSummaries(count: number): BatchEventSummary[] {
  return Array.from({ length: count }, (_, i) => ({
    eventId: `arn:aws:securityhub:us-east-1:123456789012:security-control/CIS.${i + 1}.1/finding/abc-${i + 1}`,
    controlId: `CIS.${i + 1}.1`,
    accountId: '123456789012',
    region: 'us-east-1',
    severity: 'High',
    resourceId: `arn:aws:iam::123456789012:user/test-user-${i + 1}`,
  }));
}

const WEBHOOK_URL = 'https://hooks.slack.com/services/T0123ABC/B0123DEF/abcXYZ123' as SlackWebhookUrl;

describe('SlackClient.sendBatch', () => {
  let fetchWithRetry: jest.Mock;
  let logger: Logger;
  let client: SlackClient;

  beforeEach(() => {
    fetchWithRetry = jest.fn().mockResolvedValue({ ok: true, status: 200 });
    logger = new Logger({ logLevel: 'SILENT' });
    client = new SlackClient({ fetchWithRetry, logger });
  });

  function getPostedPayload(): Record<string, unknown> {
    return JSON.parse(fetchWithRetry.mock.calls[0][1].body);
  }

  describe('Block Kit payload structure', () => {
    it('should include a header block with notification type, count, and plural noun', async () => {
      // ARRANGE
      const message = createBatchMessage({ findingCount: 5, notificationType: 'finding' });

      // ACT
      await client.sendBatch({ webhookUrl: WEBHOOK_URL, message });

      // ASSERT
      const payload = getPostedPayload();
      const blocks = payload.blocks as Array<Record<string, unknown>>;
      expect(blocks[0]).toEqual({
        type: 'header',
        text: { type: 'plain_text', text: 'Finding Batch — 5 findings' },
      });
    });

    it('should use singular noun when count is 1', async () => {
      // ARRANGE
      const message = createBatchMessage({ findingCount: 1, notificationType: 'finding' });

      // ACT
      await client.sendBatch({ webhookUrl: WEBHOOK_URL, message });

      // ASSERT
      const payload = getPostedPayload();
      const blocks = payload.blocks as Array<Record<string, unknown>>;
      const header = blocks[0] as { text: { text: string } };
      expect(header.text.text).toContain('1 finding');
      expect(header.text.text).not.toContain('findings');
    });

    it('should use "remediations" noun for remediation type', async () => {
      // ARRANGE
      const message = createBatchMessage({
        notificationType: 'remediation',
        findingCount: 0,
        remediationCount: 3,
      });

      // ACT
      await client.sendBatch({ webhookUrl: WEBHOOK_URL, message });

      // ASSERT
      const payload = getPostedPayload();
      const blocks = payload.blocks as Array<Record<string, unknown>>;
      const header = blocks[0] as { text: { text: string } };
      expect(header.text.text).toContain('Remediation Batch — 3 remediations');
    });

    it('should include a section with config name and generation time', async () => {
      // ARRANGE
      const message = createBatchMessage({
        configName: 'My Security Config',
        startGenerationTime: '2024-06-15T10:30:00Z',
      });

      // ACT
      await client.sendBatch({ webhookUrl: WEBHOOK_URL, message });

      // ASSERT
      const payload = getPostedPayload();
      const blocks = payload.blocks as Array<Record<string, unknown>>;
      const configSection = blocks[1] as { fields?: Array<{ text: string }> };
      const fieldTexts = configSection.fields?.map((f) => f.text) ?? [];
      expect(fieldTexts.some((t) => t.includes('My Security Config'))).toBe(true);
      expect(fieldTexts.some((t) => t.includes('2024-06-15T10:30:00Z'))).toBe(true);
    });

    it('should NOT include event summary fields in batch notifications', async () => {
      // ARRANGE
      const summaries = createEventSummaries(3);
      const message = createBatchMessage({ eventSummaries: summaries, findingCount: 3 });

      // ACT
      await client.sendBatch({ webhookUrl: WEBHOOK_URL, message });

      // ASSERT
      const payload = getPostedPayload();
      const blocks = payload.blocks as Array<Record<string, unknown>>;
      const eventSection = blocks.find(
        (b) =>
          b.type === 'section' &&
          Array.isArray(b.fields) &&
          (b.fields as Array<{ text: string }>).some((f) => f.text.includes('CIS.1.1')),
      );
      expect(eventSection).toBeUndefined();
    });

    it('should include export URL section when exportUrl is present', async () => {
      // ARRANGE
      const message = createBatchMessage({
        exportUrl: 'https://s3.amazonaws.com/bucket/export.csv',
      });

      // ACT
      await client.sendBatch({ webhookUrl: WEBHOOK_URL, message });

      // ASSERT
      const payload = getPostedPayload();
      const blocks = payload.blocks as Array<Record<string, unknown>>;
      const exportBlock = blocks.find(
        (b) =>
          b.type === 'section' &&
          (b.text as { text: string } | undefined)?.text?.includes('https://s3.amazonaws.com/bucket/export.csv'),
      );
      expect(exportBlock).toBeDefined();
    });

    it('should display expiration time alongside export URL', async () => {
      // ARRANGE
      const message = createBatchMessage({
        exportUrl: 'https://s3.amazonaws.com/bucket/export.csv',
        linkAccessExpirationTime: '2024-06-16T10:00:00Z',
      });

      // ACT
      await client.sendBatch({ webhookUrl: WEBHOOK_URL, message });

      // ASSERT
      const payload = getPostedPayload();
      const blocks = payload.blocks as Array<Record<string, unknown>>;
      const exportBlock = blocks.find(
        (b) => b.type === 'section' && (b.text as { text: string } | undefined)?.text?.includes('export.csv'),
      );
      expect(exportBlock).toBeDefined();
      const text = (exportBlock as { text: { text: string } }).text.text;
      expect(text).toContain('2024-06-16T10:00:00Z');
    });

    it('should omit export URL section when exportUrl is not present', async () => {
      // ARRANGE
      const message = createBatchMessage({ exportUrl: undefined });

      // ACT
      await client.sendBatch({ webhookUrl: WEBHOOK_URL, message });

      // ASSERT
      const payload = getPostedPayload();
      const blocks = payload.blocks as Array<Record<string, unknown>>;
      const exportBlock = blocks.find(
        (b) => b.type === 'section' && (b.text as { text: string } | undefined)?.text?.includes('Export'),
      );
      expect(exportBlock).toBeUndefined();
    });

    it('should include chunk metadata context block when totalChunks > 0', async () => {
      // ARRANGE
      const message = createBatchMessage({ chunkIndex: 1, totalChunks: 3 });

      // ACT
      await client.sendBatch({ webhookUrl: WEBHOOK_URL, message });

      // ASSERT
      const payload = getPostedPayload();
      const blocks = payload.blocks as Array<Record<string, unknown>>;
      const contextBlock = blocks.find(
        (b) =>
          b.type === 'context' &&
          Array.isArray(b.elements) &&
          (b.elements as Array<{ text: string }>).some((e) => e.text.includes('1') && e.text.includes('3')),
      );
      expect(contextBlock).toBeDefined();
    });

    it('should omit chunk metadata when totalChunks is undefined', async () => {
      // ARRANGE
      const message = createBatchMessage({ chunkIndex: undefined, totalChunks: undefined });

      // ACT
      await client.sendBatch({ webhookUrl: WEBHOOK_URL, message });

      // ASSERT
      const payload = getPostedPayload();
      const blocks = payload.blocks as Array<Record<string, unknown>>;
      const contextBlock = blocks.find((b) => b.type === 'context');
      expect(contextBlock).toBeUndefined();
    });

    it('should omit chunk metadata when totalChunks is 0', async () => {
      // ARRANGE
      const message = createBatchMessage({ chunkIndex: 0, totalChunks: 0 });

      // ACT
      await client.sendBatch({ webhookUrl: WEBHOOK_URL, message });

      // ASSERT
      const payload = getPostedPayload();
      const blocks = payload.blocks as Array<Record<string, unknown>>;
      const contextBlock = blocks.find((b) => b.type === 'context');
      expect(contextBlock).toBeUndefined();
    });
  });

  describe('channel override', () => {
    it('should include channel field in payload when channelId is provided', async () => {
      // ARRANGE
      const message = createBatchMessage();

      // ACT
      await client.sendBatch({ webhookUrl: WEBHOOK_URL, message, channelId: 'C0123456789' });

      // ASSERT
      const payload = getPostedPayload();
      expect(payload.channel).toBe('C0123456789');
    });

    it('should omit channel field when channelId is not provided', async () => {
      // ARRANGE
      const message = createBatchMessage();

      // ACT
      await client.sendBatch({ webhookUrl: WEBHOOK_URL, message });

      // ASSERT
      const payload = getPostedPayload();
      expect(payload.channel).toBeUndefined();
    });
  });

  describe('IaC download links rendering', () => {
    beforeEach(() => setupIaCTestEnvironment());
    afterEach(() => teardownIaCTestEnvironment());

    it('should include IaC link blocks for eligible remediation summaries', async () => {
      const message = createBatchMessage({
        notificationType: 'remediation',
        remediationCount: 2,
        contentOptions: {
          includeManualRemediationLink: false,
          includeRemediationDeadline: false,
          enforceDeadline: false,
          includeIaCSnippet: true,
          iacFormats: ['cloudformation-yaml', 'terraform'],
          includeEnableAutomationLink: false,
        },
        eventSummaries: [
          {
            eventId: 'finding-1',
            controlId: 'S3.1',
            accountId: '111',
            region: 'us-east-1',
            severity: 'High',
            resourceId: 'r1',
            remediationStatus: 'SUCCESS',
          },
          {
            eventId: 'finding-2',
            controlId: 'EC2.1',
            accountId: '111',
            region: 'us-east-1',
            severity: 'Medium',
            resourceId: 'r2',
            remediationStatus: 'FAILED',
          },
        ],
      });

      await client.sendBatch({ webhookUrl: WEBHOOK_URL, message });

      const payload = getPostedPayload();
      const blocks = payload.blocks as Array<{ type: string; text?: { text: string } }>;
      const iacBlocks = blocks.filter((b) => b.text?.text?.includes('S3.1'));
      expect(iacBlocks).toHaveLength(1);
      expect(iacBlocks[0]?.text?.text).toContain('cloudformation-yaml');
      // EC2.1 should NOT appear (FAILED status)
      expect(blocks.filter((b) => b.text?.text?.includes('EC2.1'))).toHaveLength(0);
    });

    it('should not include IaC blocks when includeIaCSnippet is false', async () => {
      const message = createBatchMessage({
        notificationType: 'remediation',
        remediationCount: 1,
        contentOptions: {
          includeManualRemediationLink: false,
          includeRemediationDeadline: false,
          enforceDeadline: false,
          includeIaCSnippet: false,
          includeEnableAutomationLink: false,
        },
        eventSummaries: [
          {
            eventId: 'finding-1',
            controlId: 'S3.1',
            accountId: '111',
            region: 'us-east-1',
            severity: 'High',
            resourceId: 'r1',
            remediationStatus: 'SUCCESS',
          },
        ],
      });

      await client.sendBatch({ webhookUrl: WEBHOOK_URL, message });

      const payload = getPostedPayload();
      const blocks = payload.blocks as Array<{ type: string; text?: { text: string } }>;
      expect(blocks.filter((b) => b.text?.text?.includes('S3.1'))).toHaveLength(0);
    });
  });

  describe('error handling', () => {
    it('should throw ChannelApiError on non-2xx response', async () => {
      fetchWithRetry.mockResolvedValue({
        ok: false,
        status: 403,
        text: () => Promise.resolve('invalid_token'),
      });
      const message = createBatchMessage();

      // ACT & ASSERT
      await expect(client.sendBatch({ webhookUrl: WEBHOOK_URL, message })).rejects.toThrow(ChannelApiError);
    });

    it('should resolve successfully on 2xx response', async () => {
      // ARRANGE
      fetchWithRetry.mockResolvedValue({ ok: true, status: 200 });
      const message = createBatchMessage();

      // ACT & ASSERT
      await expect(client.sendBatch({ webhookUrl: WEBHOOK_URL, message })).resolves.toBeUndefined();
    });
  });
});
