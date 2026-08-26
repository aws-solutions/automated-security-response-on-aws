// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { Logger } from '@aws-lambda-powertools/logger';
import { ConfigId, NotificationConfigurationItem, DeliveryChannelType } from '@asr/data-models';
import { TestNotificationService, ChannelAdapterFactory } from '../../services/testNotificationService';
import { NotificationConfigurationService } from '../../services/notificationConfigurationService';
import { ChannelChecker } from '../../services/channelChecker';
import { ChannelAdapter, TestNotificationEvent } from '../../services/channelAdapters';
import {
  setupMetricsMocks,
  cleanupMetricsMocks,
  createMetricsTestScope,
} from '../../../common/__tests__/metricsMockSetup';

const FIXED_DATE = new Date('2025-06-15T12:00:00.000Z');
const FIXED_UUID = '11111111-2222-4333-a444-000000000001';

const stubClock = { now: () => FIXED_DATE };
const stubIdGenerator = { randomUUID: () => FIXED_UUID };

function asConfigId(id: string): ConfigId {
  return id as unknown as ConfigId;
}

function createMockConfig(overrides: Partial<NotificationConfigurationItem> = {}): NotificationConfigurationItem {
  return {
    configId: asConfigId('aaaaaaaa-bbbb-4ccc-addd-eeeeeeeeeeee'),
    name: 'Test Config',
    enabled: true,
    notificationType: 'finding',
    severityFilter: ['Critical'],
    controlIds: ['S3.1'],
    resourceFilterIds: [],
    deliveryChannels: [
      {
        type: 'email',
        enabled: true,
        recipients: [{ recipientType: 'custom', emailAddresses: ['admin@example.com'] }],
      },
    ],
    batchWindow: { enabled: false },
    contentOptions: {
      includeManualRemediationLink: true,
      includeRemediationDeadline: false,
      includeIaCSnippet: false,
      includeEnableAutomationLink: true,
    },
    version: 1,
    createdAt: '2025-01-01T00:00:00.000Z',
    createdBy: 'admin@example.com',
    ...overrides,
  } as NotificationConfigurationItem;
}

describe('TestNotificationService', () => {
  let service: TestNotificationService;
  let logger: Logger;
  let mockConfigService: jest.Mocked<Pick<NotificationConfigurationService, 'getConfigurationById'>>;
  let mockChecker: jest.Mocked<Pick<ChannelChecker, 'checkChannels'>>;
  let mockAdapter: jest.Mocked<Pick<ChannelAdapter, 'deliver'>>;
  let mockAdapterFactory: jest.Mock;

  beforeEach(() => {
    jest.clearAllMocks();
    setupMetricsMocks();
    logger = new Logger({ logLevel: 'SILENT' });

    mockConfigService = { getConfigurationById: jest.fn() };
    mockChecker = { checkChannels: jest.fn() };
    mockAdapter = { deliver: jest.fn() };
    mockAdapterFactory = jest.fn().mockReturnValue(mockAdapter);

    // ADR-0001 exception: test-only casts, removed when handler integration tests replace these
    service = new TestNotificationService(
      logger,
      mockConfigService as unknown as NotificationConfigurationService,
      mockChecker as unknown as ChannelChecker,
      mockAdapterFactory as ChannelAdapterFactory,
      stubClock,
      stubIdGenerator,
    );
  });

  afterEach(() => {
    cleanupMetricsMocks();
  });

  describe('synthetic event construction', () => {
    it('should construct a synthetic event with isTestEvent flag, [TEST] prefix in title, and correct structure', async () => {
      // ARRANGE
      const configId = asConfigId('aaaaaaaa-bbbb-4ccc-addd-eeeeeeeeeeee');
      const config = createMockConfig({ configId });
      mockConfigService.getConfigurationById.mockResolvedValue(config);
      mockChecker.checkChannels.mockResolvedValue([{ channelType: 'email' as DeliveryChannelType, isValid: true }]);
      mockAdapter.deliver.mockResolvedValue(undefined);

      // ACT
      await service.sendTestNotification(configId);

      // ASSERT
      const deliverCall = mockAdapter.deliver.mock.calls[0];
      const syntheticEvent = deliverCall[0];
      expect(syntheticEvent.isTestEvent).toBe(true);
      expect(syntheticEvent.title).toMatch(/^\[TEST\]/);
      expect(syntheticEvent.eventId).toBe(FIXED_UUID);
      expect(syntheticEvent.timestamp).toBe(FIXED_DATE.toISOString());
    });
  });

  describe('channel validation gates delivery', () => {
    it('should validate all channels before delivery and not deliver to channels that fail validation', async () => {
      // ARRANGE
      const configId = asConfigId('aaaaaaaa-bbbb-4ccc-addd-eeeeeeeeeeee');
      const config = createMockConfig({
        configId,
        deliveryChannels: [
          { type: 'email', enabled: true, recipients: [{ recipientType: 'custom', emailAddresses: ['a@b.com'] }] },
          {
            type: 'slack',
            enabled: true,
            channelId: 'C12345678',
            credentialsSecretArn: 'arn:aws:secretsmanager:us-east-1:123456789012:secret:asr/notifications/slack',
          },
        ],
      });
      mockConfigService.getConfigurationById.mockResolvedValue(config);
      mockChecker.checkChannels.mockResolvedValue([
        { channelType: 'email' as DeliveryChannelType, isValid: true },
        { channelType: 'slack' as DeliveryChannelType, isValid: false, error: 'Credentials secret not found' },
      ]);
      mockAdapter.deliver.mockResolvedValue(undefined);

      // ACT
      const result = await service.sendTestNotification(configId);

      // ASSERT
      expect(mockAdapter.deliver).toHaveBeenCalledTimes(1);
      expect(result.results.slack.status).toBe('failure');
      expect(result.results.slack.error).toBe('Credentials secret not found');
      expect(result.results.email.status).toBe('success');
    });
  });

  describe('independent channel delivery', () => {
    it('should deliver to all channels that pass validation regardless of individual failures', async () => {
      // ARRANGE
      const configId = asConfigId('aaaaaaaa-bbbb-4ccc-addd-eeeeeeeeeeee');
      const config = createMockConfig({
        configId,
        deliveryChannels: [
          { type: 'email', enabled: true, recipients: [{ recipientType: 'custom', emailAddresses: ['a@b.com'] }] },
          {
            type: 'slack',
            enabled: true,
            channelId: 'C12345678',
            credentialsSecretArn: 'arn:aws:secretsmanager:us-east-1:123456789012:secret:asr/notifications/slack',
          },
          {
            type: 'sns',
            enabled: true,
            topicArn: 'arn:aws:sns:us-east-1:123456789012:test-topic',
          },
        ],
      });
      mockConfigService.getConfigurationById.mockResolvedValue(config);
      mockChecker.checkChannels.mockResolvedValue([
        { channelType: 'email' as DeliveryChannelType, isValid: true },
        { channelType: 'slack' as DeliveryChannelType, isValid: true },
        { channelType: 'sns' as DeliveryChannelType, isValid: true },
      ]);
      mockAdapter.deliver
        .mockResolvedValueOnce(undefined)
        .mockRejectedValueOnce(new Error('Webhook returned 403'))
        .mockResolvedValueOnce(undefined);

      // ACT
      const result = await service.sendTestNotification(configId);

      // ASSERT
      expect(mockAdapter.deliver).toHaveBeenCalledTimes(3);
      expect(result.results.email.status).toBe('success');
      expect(result.results.slack.status).toBe('failure');
      expect(result.results.sns.status).toBe('success');
    });
  });

  describe('aggregated per-channel results', () => {
    it('should return aggregated per-channel results with correct status values', async () => {
      // ARRANGE
      const configId = asConfigId('aaaaaaaa-bbbb-4ccc-addd-eeeeeeeeeeee');
      const config = createMockConfig({
        configId,
        name: 'Multi-Channel Config',
        deliveryChannels: [
          { type: 'email', enabled: true, recipients: [{ recipientType: 'custom', emailAddresses: ['a@b.com'] }] },
          {
            type: 'slack',
            enabled: true,
            channelId: 'C12345678',
            credentialsSecretArn: 'arn:aws:secretsmanager:us-east-1:123456789012:secret:asr/notifications/slack',
          },
        ],
      });
      mockConfigService.getConfigurationById.mockResolvedValue(config);
      mockChecker.checkChannels.mockResolvedValue([
        { channelType: 'email' as DeliveryChannelType, isValid: true },
        { channelType: 'slack' as DeliveryChannelType, isValid: true },
      ]);
      mockAdapter.deliver.mockResolvedValueOnce(undefined).mockResolvedValueOnce(undefined);

      // ACT
      const result = await service.sendTestNotification(configId);

      // ASSERT
      expect(result.success).toBe(true);
      expect(result.configId).toBe(configId);
      expect(result.configName).toBe('Multi-Channel Config');
      expect(result.testedAt).toBe(FIXED_DATE.toISOString());
      expect(result.results.email).toEqual(
        expect.objectContaining({
          channelType: 'email',
          enabled: true,
          status: 'success',
        }),
      );
      expect(result.results.slack).toEqual(
        expect.objectContaining({
          channelType: 'slack',
          enabled: true,
          status: 'success',
        }),
      );
    });

    it('should set success to false when any channel fails', async () => {
      // ARRANGE
      const configId = asConfigId('aaaaaaaa-bbbb-4ccc-addd-eeeeeeeeeeee');
      const config = createMockConfig({
        configId,
        deliveryChannels: [
          { type: 'email', enabled: true, recipients: [{ recipientType: 'custom', emailAddresses: ['a@b.com'] }] },
          {
            type: 'slack',
            enabled: true,
            channelId: 'C12345678',
            credentialsSecretArn: 'arn:aws:secretsmanager:us-east-1:123456789012:secret:asr/notifications/slack',
          },
        ],
      });
      mockConfigService.getConfigurationById.mockResolvedValue(config);
      mockChecker.checkChannels.mockResolvedValue([
        { channelType: 'email' as DeliveryChannelType, isValid: true },
        { channelType: 'slack' as DeliveryChannelType, isValid: true },
      ]);
      mockAdapter.deliver.mockResolvedValueOnce(undefined).mockRejectedValueOnce(new Error('Webhook error'));

      // ACT
      const result = await service.sendTestNotification(configId);

      // ASSERT
      expect(result.success).toBe(false);
    });
  });

  describe('channels filter', () => {
    it('should restrict which channels are tested when channels filter is provided', async () => {
      // ARRANGE
      const configId = asConfigId('aaaaaaaa-bbbb-4ccc-addd-eeeeeeeeeeee');
      const config = createMockConfig({
        configId,
        deliveryChannels: [
          { type: 'email', enabled: true, recipients: [{ recipientType: 'custom', emailAddresses: ['a@b.com'] }] },
          {
            type: 'slack',
            enabled: true,
            channelId: 'C12345678',
            credentialsSecretArn: 'arn:aws:secretsmanager:us-east-1:123456789012:secret:asr/notifications/slack',
          },
          {
            type: 'sns',
            enabled: true,
            topicArn: 'arn:aws:sns:us-east-1:123456789012:test-topic',
          },
        ],
      });
      mockConfigService.getConfigurationById.mockResolvedValue(config);
      mockChecker.checkChannels.mockResolvedValue([{ channelType: 'slack' as DeliveryChannelType, isValid: true }]);
      mockAdapter.deliver.mockResolvedValue(undefined);

      // ACT
      const result = await service.sendTestNotification(configId, { channels: ['slack'] });

      // ASSERT
      expect(mockChecker.checkChannels).toHaveBeenCalledWith(
        expect.arrayContaining([expect.objectContaining({ type: 'slack' })]),
      );
      expect(mockAdapter.deliver).toHaveBeenCalledTimes(1);
      expect(result.results.slack).toBeDefined();
      expect(result.results.email).toBeUndefined();
      expect(result.results.sns).toBeUndefined();
    });
  });

  describe('configId validation', () => {
    it('should throw BadRequestError and not load the configuration when configId is not a valid UUID', async () => {
      // ARRANGE
      const invalidConfigId = asConfigId('not-a-uuid');

      // ACT & ASSERT
      await expect(service.sendTestNotification(invalidConfigId)).rejects.toThrow(
        expect.objectContaining({
          name: 'BadRequestError',
          message: 'configId must be a valid UUID',
        }),
      );
      expect(mockConfigService.getConfigurationById).not.toHaveBeenCalled();
    });

    it('should throw BadRequestError when configId is empty', async () => {
      // ARRANGE
      const emptyConfigId = asConfigId('');

      // ACT & ASSERT
      await expect(service.sendTestNotification(emptyConfigId)).rejects.toThrow(
        expect.objectContaining({ name: 'BadRequestError' }),
      );
      expect(mockConfigService.getConfigurationById).not.toHaveBeenCalled();
    });
  });

  describe('no enabled channels', () => {
    it('should throw BadRequestError when no enabled channels exist', async () => {
      // ARRANGE
      const configId = asConfigId('aaaaaaaa-bbbb-4ccc-addd-eeeeeeeeeeee');
      const config = createMockConfig({
        configId,
        deliveryChannels: [
          {
            type: 'email',
            enabled: false,
            recipients: [{ recipientType: 'custom', emailAddresses: ['a@b.com'] }],
          },
        ],
      });
      mockConfigService.getConfigurationById.mockResolvedValue(config);

      // ACT & ASSERT
      await expect(service.sendTestNotification(configId)).rejects.toThrow(
        expect.objectContaining({
          name: 'BadRequestError',
          message: 'No enabled delivery channels available for test',
        }),
      );
    });
  });

  describe('all channels fail validation', () => {
    it('should return success=false with per-channel errors and no delivery attempted', async () => {
      // ARRANGE
      const configId = asConfigId('aaaaaaaa-bbbb-4ccc-addd-eeeeeeeeeeee');
      const config = createMockConfig({
        configId,
        deliveryChannels: [
          { type: 'email', enabled: true, recipients: [{ recipientType: 'custom', emailAddresses: ['a@b.com'] }] },
          {
            type: 'slack',
            enabled: true,
            channelId: 'C12345678',
            credentialsSecretArn: 'arn:aws:secretsmanager:us-east-1:123456789012:secret:asr/notifications/slack',
          },
        ],
      });
      mockConfigService.getConfigurationById.mockResolvedValue(config);
      mockChecker.checkChannels.mockResolvedValue([
        { channelType: 'email' as DeliveryChannelType, isValid: false, error: 'SNS topic not found' },
        { channelType: 'slack' as DeliveryChannelType, isValid: false, error: 'Credentials secret not found' },
      ]);

      // ACT
      const result = await service.sendTestNotification(configId);

      // ASSERT
      expect(result.success).toBe(false);
      expect(result.results.email.status).toBe('failure');
      expect(result.results.email.error).toBe('SNS topic not found');
      expect(result.results.slack.status).toBe('failure');
      expect(result.results.slack.error).toBe('Credentials secret not found');
      expect(mockAdapter.deliver).not.toHaveBeenCalled();
    });
  });

  describe('disabled configuration handling', () => {
    it('should process a disabled configuration identically to an enabled one', async () => {
      // ARRANGE
      const configId = asConfigId('aaaaaaaa-bbbb-4ccc-addd-eeeeeeeeeeee');
      const config = createMockConfig({
        configId,
        enabled: false,
        deliveryChannels: [
          { type: 'email', enabled: true, recipients: [{ recipientType: 'custom', emailAddresses: ['a@b.com'] }] },
        ],
      });
      mockConfigService.getConfigurationById.mockResolvedValue(config);
      mockChecker.checkChannels.mockResolvedValue([{ channelType: 'email' as DeliveryChannelType, isValid: true }]);
      mockAdapter.deliver.mockResolvedValue(undefined);

      // ACT
      const result = await service.sendTestNotification(configId);

      // ASSERT
      expect(result.success).toBe(true);
      expect(result.results.email.status).toBe('success');
      expect(mockChecker.checkChannels).toHaveBeenCalled();
      expect(mockAdapter.deliver).toHaveBeenCalled();
    });
  });

  describe('Solutions Metrics API', () => {
    it('should emit usage metric with config_id and success=true on successful completion', async () => {
      // ARRANGE
      const configId = asConfigId('aaaaaaaa-bbbb-4ccc-addd-eeeeeeeeeeee');
      const config = createMockConfig({ configId });
      mockConfigService.getConfigurationById.mockResolvedValue(config);
      mockChecker.checkChannels.mockResolvedValue([{ channelType: 'email' as DeliveryChannelType, isValid: true }]);
      mockAdapter.deliver.mockResolvedValue(undefined);
      const metricsScope = createMetricsTestScope(
        /.*test_notifications_sent.*1.*config_id.*aaaaaaaa-bbbb-4ccc-addd-eeeeeeeeeeee.*success.*true.*/,
      );

      // ACT
      await service.sendTestNotification(configId);

      // ASSERT
      expect(metricsScope.isDone()).toBe(true);
    });

    it('should emit usage metric with success=false when all channels fail', async () => {
      // ARRANGE
      const configId = asConfigId('aaaaaaaa-bbbb-4ccc-addd-eeeeeeeeeeee');
      const config = createMockConfig({
        configId,
        deliveryChannels: [
          { type: 'email', enabled: true, recipients: [{ recipientType: 'custom', emailAddresses: ['a@b.com'] }] },
          {
            type: 'slack',
            enabled: true,
            channelId: 'C12345678',
            credentialsSecretArn: 'arn:aws:secretsmanager:us-east-1:123456789012:secret:asr/notifications/slack',
          },
        ],
      });
      mockConfigService.getConfigurationById.mockResolvedValue(config);
      mockChecker.checkChannels.mockResolvedValue([
        { channelType: 'email' as DeliveryChannelType, isValid: false, error: 'Topic not found' },
        { channelType: 'slack' as DeliveryChannelType, isValid: false, error: 'Secret not found' },
      ]);
      const metricsScope = createMetricsTestScope(
        /.*test_notifications_sent.*1.*config_id.*aaaaaaaa-bbbb-4ccc-addd-eeeeeeeeeeee.*success.*false.*/,
      );

      // ACT
      await service.sendTestNotification(configId);

      // ASSERT
      expect(metricsScope.isDone()).toBe(true);
    });

    it('should emit usage metric even when delivery channels fail', async () => {
      // ARRANGE
      const configId = asConfigId('aaaaaaaa-bbbb-4ccc-addd-eeeeeeeeeeee');
      const config = createMockConfig({ configId });
      mockConfigService.getConfigurationById.mockResolvedValue(config);
      mockChecker.checkChannels.mockResolvedValue([{ channelType: 'email' as DeliveryChannelType, isValid: true }]);
      mockAdapter.deliver.mockRejectedValue(new Error('Delivery failed'));
      const metricsScope = createMetricsTestScope(
        /.*test_notifications_sent.*1.*config_id.*aaaaaaaa-bbbb-4ccc-addd-eeeeeeeeeeee.*success.*false.*/,
      );

      // ACT
      await service.sendTestNotification(configId);

      // ASSERT
      expect(metricsScope.isDone()).toBe(true);
    });
  });

  describe('error truncation', () => {
    it('should truncate error messages to 500 characters when adapter returns long error', async () => {
      // ARRANGE
      const configId = asConfigId('aaaaaaaa-bbbb-4ccc-addd-eeeeeeeeeeee');
      const config = createMockConfig({
        configId,
        deliveryChannels: [
          {
            type: 'slack',
            enabled: true,
            channelId: 'C12345678',
            credentialsSecretArn: 'arn:aws:secretsmanager:us-east-1:123456789012:secret:asr/notifications/slack',
          },
        ],
      });
      mockConfigService.getConfigurationById.mockResolvedValue(config);
      mockChecker.checkChannels.mockResolvedValue([{ channelType: 'slack' as DeliveryChannelType, isValid: true }]);
      mockAdapter.deliver.mockRejectedValue(new Error('A'.repeat(600)));

      // ACT
      const result = await service.sendTestNotification(configId);

      // ASSERT
      expect(result.results.slack.error).toHaveLength(500);
      expect(result.results.slack.error).toBe('A'.repeat(500));
    });

    it('should truncate non-Error thrown values to 500 characters', async () => {
      // ARRANGE
      const configId = asConfigId('aaaaaaaa-bbbb-4ccc-addd-eeeeeeeeeeee');
      const config = createMockConfig({
        configId,
        deliveryChannels: [
          {
            type: 'jira',
            enabled: true,
            projectKey: 'SEC',
            issueType: 'Bug',
            endpointUrl: 'https://jira.example.com',
            credentialsSecretArn: 'arn:aws:secretsmanager:us-east-1:123456789012:secret:asr/notifications/jira-creds',
            customFieldMappings: [],
          },
        ],
      });
      mockConfigService.getConfigurationById.mockResolvedValue(config);
      mockChecker.checkChannels.mockResolvedValue([{ channelType: 'jira' as DeliveryChannelType, isValid: true }]);
      mockAdapter.deliver.mockRejectedValue('Y'.repeat(600));

      // ACT
      const result = await service.sendTestNotification(configId);

      // ASSERT
      expect(result.results.jira.status).toBe('failure');
      expect(result.results.jira.error).toHaveLength(500);
      expect(result.results.jira.error).toBe('Y'.repeat(500));
    });
  });

  describe('adapter receives channel configuration', () => {
    it('should pass the full channel configuration object to the adapter alongside the synthetic event', async () => {
      // ARRANGE
      const configId = asConfigId('aaaaaaaa-bbbb-4ccc-addd-eeeeeeeeeeee');
      const jiraChannel = {
        type: 'jira' as const,
        enabled: true,
        projectKey: 'SECURITY',
        issueType: 'Task',
        endpointUrl: 'https://jira.corp.example.com',
        credentialsSecretArn: 'arn:aws:secretsmanager:us-east-1:123456789012:secret:asr/notifications/jira',
        customFieldMappings: [{ key: 'customfield_10001', value: 'High Priority' }],
      };
      const config = createMockConfig({
        configId,
        deliveryChannels: [jiraChannel],
      });
      mockConfigService.getConfigurationById.mockResolvedValue(config);
      mockChecker.checkChannels.mockResolvedValue([{ channelType: 'jira' as DeliveryChannelType, isValid: true }]);

      let capturedChannel: unknown;
      mockAdapterFactory.mockReturnValue({
        deliver: jest.fn().mockImplementation(async (_event: TestNotificationEvent, channel: unknown) => {
          capturedChannel = channel;
        }),
      });

      // ACT
      await service.sendTestNotification(configId);

      // ASSERT
      expect(capturedChannel).toEqual(
        expect.objectContaining({
          type: 'jira',
          projectKey: 'SECURITY',
          issueType: 'Task',
          endpointUrl: 'https://jira.corp.example.com',
        }),
      );
    });
  });
});
