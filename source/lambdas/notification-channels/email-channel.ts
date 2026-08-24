// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { PublishCommand } from '@aws-sdk/client-sns';
import { createChannelHandler } from './base-channel-handler';
import { channelDependencies } from './channel-setup';
import { channelLambdaEnvironment, channelLambdaRuntimeEnvironment } from './channelLambdaEnvironment';
import { formatSubject } from './format-utils';
import { ChannelFanoutMessage, BatchChannelFanoutMessage, ChannelDependencies, ChannelType } from './types';
import {
  NOTIFICATION_JSON_SCHEMA_VERSION,
  buildBatchNotificationJsonBody,
  buildBatchSubject,
  buildSingleNotificationJsonBody,
} from './json-body';

function perConfigTopicArn(configId: string): string {
  const env = channelLambdaEnvironment();
  const region = channelLambdaRuntimeEnvironment().AWS_REGION;
  return `arn:${env.AWS_PARTITION}:sns:${region}:${env.AWS_ACCOUNT_ID}:asr-notifications-${configId}`;
}

/**
 * Deliver a single-event notification to the per-config email topic.
 * The body is the same JSON payload published to the SNS channel so subscribers
 * see consistent content regardless of channel.
 */
export async function deliver(message: ChannelFanoutMessage, dependencies: ChannelDependencies): Promise<void> {
  if (message.channel.type !== ChannelType.Email) {
    dependencies.logger.warn('Received non-email channel message, skipping', {
      channelType: message.channel.type,
    });
    return;
  }

  const body = await buildSingleNotificationJsonBody(message);

  await dependencies.snsClient.send(
    new PublishCommand({
      TopicArn: perConfigTopicArn(message.configId),
      Subject: formatSubject(message.event, 100),
      Message: body,
      MessageAttributes: {
        schemaVersion: { DataType: 'String', StringValue: NOTIFICATION_JSON_SCHEMA_VERSION },
        configId: { DataType: 'String', StringValue: message.configId },
        severity: { DataType: 'String', StringValue: message.event.severity },
      },
    }),
  );
}

/**
 * Deliver a batched notification to the per-config email topic.
 * The body matches the SNS channel batch JSON so subscribers see consistent
 * content regardless of channel.
 */
export async function deliverBatch(
  message: BatchChannelFanoutMessage,
  dependencies: ChannelDependencies,
): Promise<void> {
  const body = buildBatchNotificationJsonBody(message);

  await dependencies.snsClient.send(
    new PublishCommand({
      TopicArn: perConfigTopicArn(message.configId),
      Subject: buildBatchSubject(message),
      Message: body,
      MessageAttributes: {
        schemaVersion: { DataType: 'String', StringValue: NOTIFICATION_JSON_SCHEMA_VERSION },
        configId: { DataType: 'String', StringValue: message.configId },
        eventType: { DataType: 'String', StringValue: 'batch' },
        notificationType: { DataType: 'String', StringValue: message.notificationType },
      },
    }),
  );
}

export const handler = createChannelHandler(channelDependencies, deliver, deliverBatch);
