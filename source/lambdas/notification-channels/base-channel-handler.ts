// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { SNSEvent, SNSHandler } from 'aws-lambda';
import { Logger } from '@aws-lambda-powertools/logger';
import {
  ChannelFanoutMessage,
  BatchChannelFanoutMessage,
  ChannelMessage,
  ChannelDependencies,
  isChannelMessage,
} from './types';
import { buildBatchIaCLinkGroups, buildIaCDownloadLinks } from './iac-download-links';
import { sendMetrics } from '../common/utils/metricsUtils';

function parseMessage(raw: string): ChannelMessage {
  const parsed: unknown = JSON.parse(raw);
  if (!isChannelMessage(parsed)) {
    throw new Error('Message does not match ChannelFanoutMessage shape');
  }
  return parsed;
}

/**
 * Counts the IaC snippets present in the notification this channel delivered.
 *
 * Delegates to the builders every channel uses to render the snippets, so the
 * count cannot drift from the eligibility rules that decide whether they appear.
 *
 * Never throws: this runs after a delivery has already succeeded, so an escaping
 * exception would be reported as a delivery failure and trigger an SNS retry of
 * a notification the customer already received.
 */
function countIaCSnippets(message: ChannelMessage, logger: Logger): number {
  try {
    if (isBatchMessage(message)) {
      return buildBatchIaCLinkGroups(message.eventSummaries, message.contentOptions, message.notificationType).reduce(
        (total, group) => total + group.links.length,
        0,
      );
    }
    return buildIaCDownloadLinks(
      message.event.eventId,
      message.contentOptions,
      message.event.eventType,
      message.event.remediationStatus,
    ).length;
  } catch (error) {
    logger.warn('Failed to count IaC snippets for metrics, reporting 0', { error });
    return 0;
  }
}

/**
 * Publishes a per-delivery, per-channel outcome data point to the
 * SolutionsMetrics API so delivery success rate can be derived downstream
 * (successful_deliveries / total_attempts). Best-effort — sendMetrics never
 * rejects, so metrics cannot disrupt delivery or SNS retry/DLQ behavior.
 *
 * `iac_snippet_count` is always present, including as 0, so downstream can
 * derive both the total snippets shipped and the share of notifications that
 * carry IaC. It counts snippets present in the delivered notification, so it is
 * comparable across channels.
 */
async function emitDeliveryMetric(message: ChannelMessage, succeeded: boolean, logger: Logger): Promise<void> {
  await sendMetrics({
    delivery_attempt: 1,
    delivery_succeeded: succeeded ? 1 : 0,
    config_id: message.configId,
    channel_type: message.channel.type,
    iac_snippet_count: countIaCSnippets(message, logger),
  });
}

export function isBatchMessage(message: ChannelMessage): message is BatchChannelFanoutMessage {
  return 'isBatch' in message && message.isBatch === true;
}

export function createChannelHandler(
  dependencies: ChannelDependencies,
  deliver: (message: ChannelFanoutMessage, dependencies: ChannelDependencies) => Promise<void>,
  deliverBatch?: (message: BatchChannelFanoutMessage, dependencies: ChannelDependencies) => Promise<void>,
): SNSHandler {
  const { logger } = dependencies;
  return async (event: SNSEvent): Promise<void> => {
    for (const record of event.Records) {
      const messageId = record.Sns.MessageId;
      const message = parseMessage(record.Sns.Message);

      if (isBatchMessage(message)) {
        if (deliverBatch) {
          logger.info('Processing batch channel notification', {
            messageId,
            configId: message.configId,
            findingCount: message.findingCount,
            remediationCount: message.remediationCount,
            channelType: message.channel.type,
          });
          try {
            await deliverBatch(message, dependencies);
          } catch (error) {
            await emitDeliveryMetric(message, false, logger);
            throw error;
          }
          await emitDeliveryMetric(message, true, logger);
          logger.info('Channel notification delivered', { messageId, configId: message.configId });
        } else {
          logger.info('Batch delivery not implemented for this channel, skipping', {
            messageId,
            configId: message.configId,
            channelType: message.channel.type,
          });
        }
      } else {
        logger.info('Processing channel notification', {
          messageId,
          configId: message.configId,
          eventId: message.event.eventId,
          channelType: message.channel.type,
        });
        try {
          await deliver(message, dependencies);
        } catch (error) {
          await emitDeliveryMetric(message, false, logger);
          throw error;
        }
        await emitDeliveryMetric(message, true, logger);
        logger.info('Channel notification delivered', { messageId, configId: message.configId });
      }
    }
  };
}
