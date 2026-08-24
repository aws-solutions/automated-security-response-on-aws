// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { Logger } from '@aws-lambda-powertools/logger';
import {
  ConfigId,
  ConfigIdSchema,
  DeliveryChannelConfig,
  DeliveryChannelType,
  TestNotificationRequest,
  TestNotificationResult,
  ChannelTestResult,
} from '@asr/data-models';
import { Clock, getClock } from '../../common/utils/clock';
import { IdGenerator, getIdGenerator } from '../../common/utils/idGenerator';
import { sendMetrics } from '../../common/utils/metricsUtils';
import { BadRequestError } from '../../common/utils/httpErrors';
import { NotificationConfigurationService } from './notificationConfigurationService';
import { ChannelChecker } from './channelChecker';
import { ChannelAdapter, ChannelAdapterContext, getChannelAdapter, TestNotificationEvent } from './channelAdapters';

export type ChannelAdapterFactory = (
  channelType: DeliveryChannelType,
  context: ChannelAdapterContext,
) => ChannelAdapter;

export class TestNotificationService {
  constructor(
    private readonly logger: Logger,
    private readonly configService: NotificationConfigurationService = new NotificationConfigurationService(logger),
    private readonly channelChecker: ChannelChecker = new ChannelChecker(logger),
    private readonly channelAdapterFactory: ChannelAdapterFactory = getChannelAdapter,
    private readonly clock: Clock = getClock(),
    private readonly idGenerator: IdGenerator = getIdGenerator(),
  ) {}

  async sendTestNotification(
    configId: ConfigId,
    body?: TestNotificationRequest,
    initiatedBy?: string,
  ): Promise<TestNotificationResult> {
    this.logger.info('sendTestNotification called', { configId, body, initiatedBy });

    if (!ConfigIdSchema.safeParse(configId).success) {
      throw new BadRequestError('configId must be a valid UUID');
    }

    const config = await this.configService.getConfigurationById(configId);

    const enabledChannels = config.deliveryChannels.filter((ch) => ch.enabled);
    const targetChannels = this.determineTargetChannels(enabledChannels, body);

    if (targetChannels.length === 0) {
      throw new BadRequestError('No enabled delivery channels available for test');
    }

    const syntheticEvent = this.buildSyntheticEvent();

    const validationResults = await this.channelChecker.checkChannels(targetChannels);
    this.logger.info('Channel validation complete', {
      configId,
      results: validationResults.map((r) => ({ channelType: r.channelType, valid: r.isValid })),
    });

    const channelsByType = new Map(targetChannels.map((ch) => [ch.type, ch]));
    const results: Partial<Record<DeliveryChannelType, ChannelTestResult>> = {};

    for (const validationResult of validationResults) {
      const channel = channelsByType.get(validationResult.channelType);
      if (!channel) continue;

      if (!validationResult.isValid) {
        results[validationResult.channelType] = {
          channelType: validationResult.channelType,
          enabled: true,
          status: 'failure',
          error: validationResult.error,
        };
        continue;
      }

      const adapterContext: ChannelAdapterContext = {
        configId,
        configName: config.name,
        contentOptions: {
          includeManualRemediationLink: false,
          includeRemediationDeadline: false,
          enforceDeadline: false,
          includeIaCSnippet: false,
          includeEnableAutomationLink: false,
        },
      };
      const channelResult = await this.deliverToChannel(syntheticEvent, channel, adapterContext);
      results[validationResult.channelType] = channelResult;
    }

    const isAllSuccess = Object.values(results).every((r) => r.status === 'success');
    this.logger.info('Test notification delivery complete', { configId, isAllSuccess });

    const result: TestNotificationResult = {
      success: isAllSuccess,
      configId,
      configName: config.name,
      eventId: syntheticEvent.eventId,
      testedAt: this.clock.now().toISOString(),
      results,
    };

    await this.emitMetrics(configId, isAllSuccess);

    return result;
  }

  private determineTargetChannels(
    enabledChannels: DeliveryChannelConfig[],
    body?: TestNotificationRequest,
  ): DeliveryChannelConfig[] {
    if (body?.channels && body.channels.length > 0) {
      const requestedTypes = new Set<DeliveryChannelType>(body.channels);
      return enabledChannels.filter((ch) => requestedTypes.has(ch.type));
    }
    return enabledChannels;
  }

  private buildSyntheticEvent(): TestNotificationEvent {
    const now = this.clock.now();

    return {
      isTestEvent: true,
      eventType: 'finding',
      eventId: this.idGenerator.randomUUID(),
      controlId: 'TEST.1',
      accountId: '123456789012',
      region: 'us-east-1',
      severity: 'INFORMATIONAL',
      resourceType: 'AwsTest::Resource',
      resourceId: 'test-resource-id',
      title: '[TEST] Test notification - verify delivery channel configuration',
      description: 'This is a test notification to verify your notification configuration is working correctly.',
      detectedAt: now.toISOString(),
      timestamp: now.toISOString(),
    };
  }

  private async deliverToChannel(
    event: TestNotificationEvent,
    channel: DeliveryChannelConfig,
    context: ChannelAdapterContext,
  ): Promise<ChannelTestResult> {
    try {
      const adapter = this.channelAdapterFactory(channel.type, context);
      await adapter.deliver(event, channel);

      return {
        channelType: channel.type,
        enabled: true,
        status: 'success',
      };
    } catch (error: unknown) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      return {
        channelType: channel.type,
        enabled: true,
        status: 'failure',
        error: errorMessage.slice(0, 500),
      };
    }
  }

  private async emitMetrics(configId: ConfigId, success: boolean): Promise<void> {
    try {
      await sendMetrics({
        test_notifications_sent: 1,
        config_id: configId,
        success,
      });
    } catch (error: unknown) {
      this.logger.warn('Failed to emit test notification metrics', { configId, error });
    }
  }
}
