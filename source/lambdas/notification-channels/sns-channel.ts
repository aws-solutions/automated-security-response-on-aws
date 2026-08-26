// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { PublishCommand } from '@aws-sdk/client-sns';
import { parseSnsTopicArn } from '@asr/data-models';
import { createChannelHandler } from './base-channel-handler';
import { channelDependencies } from './channel-setup';
import { formatSubject } from './format-utils';
import { channelLambdaEnvironment, channelLambdaRuntimeEnvironment } from './channelLambdaEnvironment';
import { ChannelFanoutMessage, BatchChannelFanoutMessage, ChannelDependencies, ChannelType } from './types';
import {
  NOTIFICATION_JSON_SCHEMA_VERSION,
  buildBatchNotificationJsonBody,
  buildBatchSubject,
  buildSingleNotificationJsonBody,
} from './json-body';

/** @deprecated Use NOTIFICATION_JSON_SCHEMA_VERSION from './json-body' instead. */
export { NOTIFICATION_JSON_SCHEMA_VERSION as SNS_MESSAGE_SCHEMA_VERSION } from './json-body';

/** Validate that the topic ARN is in the same partition, account, and region as this Lambda. */
function validateCustomerTopicArn(topicArn: string): void {
  const env = channelLambdaEnvironment();
  const parsed = parseSnsTopicArn(topicArn);
  if (!parsed) throw new Error(`Topic ARN must be a valid SNS ARN, got: ${topicArn}`);
  if (parsed.partition !== env.AWS_PARTITION) {
    throw new Error(
      `Topic ARN must be in partition "${env.AWS_PARTITION}", got "${parsed.partition}" (topic ARN: ${topicArn})`,
    );
  }
  if (parsed.accountId !== env.AWS_ACCOUNT_ID) {
    throw new Error(
      `Topic ARN must belong to account ${env.AWS_ACCOUNT_ID}, got ${parsed.accountId} (topic ARN: ${topicArn})`,
    );
  }
  const currentRegion = channelLambdaRuntimeEnvironment().AWS_REGION;
  if (parsed.region !== currentRegion) {
    throw new Error(`Topic ARN must be in region "${currentRegion}", got "${parsed.region}" (topic ARN: ${topicArn})`);
  }
}

export async function deliver(message: ChannelFanoutMessage, dependencies: ChannelDependencies): Promise<void> {
  if (message.channel.type !== ChannelType.Sns) {
    dependencies.logger.warn('Received non-sns channel message, skipping', {
      channelType: message.channel.type,
    });
    return;
  }

  const { topicArn } = message.channel;
  validateCustomerTopicArn(topicArn);

  const { event } = message;
  const body = await buildSingleNotificationJsonBody(message);

  await dependencies.snsClient.send(
    new PublishCommand({
      TopicArn: topicArn,
      Subject: formatSubject(event, 100),
      Message: body,
      MessageAttributes: {
        schemaVersion: { DataType: 'String', StringValue: NOTIFICATION_JSON_SCHEMA_VERSION },
        configId: { DataType: 'String', StringValue: message.configId },
        severity: { DataType: 'String', StringValue: event.severity },
        eventType: { DataType: 'String', StringValue: event.eventType },
        controlId: { DataType: 'String', StringValue: event.controlId },
        accountId: { DataType: 'String', StringValue: event.accountId },
      },
    }),
  );
}

export async function deliverBatch(
  message: BatchChannelFanoutMessage,
  dependencies: ChannelDependencies,
): Promise<void> {
  if (message.channel.type !== ChannelType.Sns) return;

  const { topicArn } = message.channel;
  validateCustomerTopicArn(topicArn);

  const body = buildBatchNotificationJsonBody(message);

  await dependencies.snsClient.send(
    new PublishCommand({
      TopicArn: topicArn,
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
