// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { createChannelHandler } from './base-channel-handler';
import { channelDependencies } from './channel-setup';
import { getCachedSecretValue } from '../common/utils/secrets-utils';
import { CredentialParsingError } from './notification-channel-errors';
import {
  BatchChannelFanoutMessage,
  ChannelFanoutMessage,
  ChannelDependencies,
  ChannelType,
  SlackWebhookUrl,
} from './types';
import { SlackClient } from './slack-client';
import { SLACK_CHANNEL_ID_PATTERN } from '@asr/data-models';
import { z } from 'zod';

export type { SlackWebhookUrl } from './types';

const SLACK_WEBHOOK_URL_PATTERN = /^https:\/\/hooks\.slack\.com\/services\/T[a-zA-Z0-9]+\/B[a-zA-Z0-9]+\/[a-zA-Z0-9]+$/;
const MAX_WEBHOOK_URL_LENGTH = 2048;

export function validateSlackWebhookUrl(url: string): SlackWebhookUrl {
  if (url.length > MAX_WEBHOOK_URL_LENGTH) {
    throw new CredentialParsingError(
      `Slack webhook URL exceeds maximum length of ${MAX_WEBHOOK_URL_LENGTH} characters`,
    );
  }
  if (!SLACK_WEBHOOK_URL_PATTERN.test(url)) {
    throw new CredentialParsingError(
      'Slack webhook URL does not match the expected format: https://hooks.slack.com/services/T.../B.../...',
    );
  }
  return url as SlackWebhookUrl;
}

export function validateSlackChannelId(channelId: string): void {
  if (!SLACK_CHANNEL_ID_PATTERN.test(channelId)) {
    throw new CredentialParsingError(
      `Slack channel ID must start with C followed by 8 or more uppercase alphanumeric characters, got: ${channelId}`,
    );
  }
}

const SlackSecretSchema = z.looseObject({
  webhookUrl: z.string().optional(),
  url: z.string().optional(),
});

function extractWebhookUrl(secretValue: string, dependencies: ChannelDependencies): string {
  try {
    const parsed: unknown = JSON.parse(secretValue);
    const result = SlackSecretSchema.safeParse(parsed);
    if (result.success) {
      return result.data.webhookUrl ?? result.data.url ?? secretValue;
    }
    return secretValue;
  } catch {
    dependencies.logger.debug('Secret is not JSON, using raw value as webhook URL');
    return secretValue;
  }
}

interface ResolvedSlackCredentials {
  readonly webhookUrl: SlackWebhookUrl;
  readonly slackClient: SlackClient;
  readonly channelId?: string;
}

async function resolveSlackCredentials(
  channel: ChannelFanoutMessage['channel'],
  dependencies: ChannelDependencies,
): Promise<ResolvedSlackCredentials | null> {
  if (channel.type !== ChannelType.Slack) {
    dependencies.logger.warn('Received non-slack channel message, skipping', {
      channelType: channel.type,
    });
    return null;
  }

  if (channel.channelId) {
    validateSlackChannelId(channel.channelId);
  }

  const { credentialsSecretArn } = channel;
  dependencies.logger.debug('Retrieving webhook credential', { secretArn: credentialsSecretArn });
  const secretValue = await getCachedSecretValue(dependencies.secretsClient, credentialsSecretArn, dependencies.logger);

  const webhookUrl = validateSlackWebhookUrl(extractWebhookUrl(secretValue, dependencies));
  const slackClient = new SlackClient({ fetchWithRetry: dependencies.fetchWithRetry, logger: dependencies.logger });

  return { webhookUrl, slackClient, channelId: channel.channelId };
}

export async function deliver(message: ChannelFanoutMessage, dependencies: ChannelDependencies): Promise<void> {
  const resolved = await resolveSlackCredentials(message.channel, dependencies);
  if (!resolved) return;

  await resolved.slackClient.send({
    webhookUrl: resolved.webhookUrl,
    event: message.event,
    configName: message.configName,
    contentOptions: message.contentOptions,
    channelId: resolved.channelId,
  });
}

export async function deliverBatch(
  message: BatchChannelFanoutMessage,
  dependencies: ChannelDependencies,
): Promise<void> {
  const resolved = await resolveSlackCredentials(message.channel, dependencies);
  if (!resolved) return;

  await resolved.slackClient.sendBatch({
    webhookUrl: resolved.webhookUrl,
    message,
    channelId: resolved.channelId,
  });
}

export const handler = createChannelHandler(channelDependencies, deliver, deliverBatch);
