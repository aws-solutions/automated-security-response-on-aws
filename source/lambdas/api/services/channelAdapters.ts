// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { SecretsManagerClient } from '@aws-sdk/client-secrets-manager';
import { SNSClient } from '@aws-sdk/client-sns';
import {
  ConfigId,
  ContentOptions,
  DeliveryChannelConfig,
  DeliveryChannelType,
  NotificationEvent,
} from '@asr/data-models';
import { getLogger } from '../../common/utils/logger';
import { fetchWithRetry } from '../../notification-channels/channel-setup';
import { deliver as emailDeliver } from '../../notification-channels/email-channel';
import { deliver as slackDeliver } from '../../notification-channels/slack-channel';
import { deliver as jiraDeliver } from '../../notification-channels/jira-channel';
import { deliver as servicenowDeliver } from '../../notification-channels/servicenow-channel';
import { deliver as snsDeliver } from '../../notification-channels/sns-channel';
import { ChannelDependencies, ChannelFanoutMessage } from '../../notification-channels/types';

// Type-level discriminator only. Not checked at runtime today, but available if channels need to differentiate test events in the future.
export type TestNotificationEvent = NotificationEvent & { isTestEvent: true };

/**
 * Adapter for delivering a test notification to a single channel.
 *
 * Contract:
 * - Resolves (void) on success → caller reports status: 'success'.
 * - Throws on failure → caller catches the error and reports status: 'failure'
 *
 */
export interface ChannelAdapter {
  deliver(event: TestNotificationEvent, channel: DeliveryChannelConfig): Promise<void>;
}

export interface ChannelAdapterContext {
  readonly configId: ConfigId;
  readonly configName: string;
  readonly contentOptions: ContentOptions;
}

const logger = getLogger('test-notification-channel-adapter');
const secretsClient = new SecretsManagerClient({});
const snsClient = new SNSClient({});

const dependencies: ChannelDependencies = {
  logger,
  secretsClient,
  snsClient,
  fetchWithRetry: (url: string, init: RequestInit) => fetchWithRetry(url, init),
};

type ChannelDeliverFn = (message: ChannelFanoutMessage, dependencies: ChannelDependencies) => Promise<void>;

const CHANNEL_DELIVER_MAP: Record<DeliveryChannelType, ChannelDeliverFn> = {
  email: emailDeliver,
  slack: slackDeliver,
  jira: jiraDeliver,
  servicenow: servicenowDeliver,
  sns: snsDeliver,
};

export function getChannelAdapter(channelType: DeliveryChannelType, context: ChannelAdapterContext): ChannelAdapter {
  const deliverFn = CHANNEL_DELIVER_MAP[channelType];

  return {
    async deliver(event: TestNotificationEvent, channel: DeliveryChannelConfig): Promise<void> {
      const message: ChannelFanoutMessage = {
        configId: context.configId,
        configName: context.configName,
        contentOptions: context.contentOptions,
        channel,
        event,
      };

      await deliverFn(message, dependencies);
    },
  };
}
