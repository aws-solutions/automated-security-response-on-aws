// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { createChannelHandler } from './base-channel-handler';
import { channelDependencies } from './channel-setup';
import { getCachedSecretValue } from '../common/utils/secrets-utils';
import { InputValidationError } from './notification-channel-errors';
import {
  BatchChannelFanoutMessage,
  ChannelFanoutMessage,
  ChannelDependencies,
  ChannelType,
  ServiceNowCredentials,
  parseServiceNowCredentials,
} from './types';
import {
  checkServiceNowInstanceUrl,
  SERVICENOW_TABLE_NAME_PATTERN,
  ServiceNowCustomFieldMapping,
} from '@asr/data-models';
import { ServiceNowClient } from './servicenow-client';

function validateServiceNowInstanceUrl(url: string): string {
  const error = checkServiceNowInstanceUrl(url);
  if (error) {
    throw new InputValidationError(error);
  }
  return url;
}

function validateServiceNowTableName(tableName: string): string {
  if (!SERVICENOW_TABLE_NAME_PATTERN.test(tableName)) {
    throw new InputValidationError(
      'Invalid ServiceNow table name. Must start with a lowercase letter, followed by lowercase letters, digits, or underscores (1–80 characters total).',
    );
  }
  return tableName;
}

interface ValidatedChannel {
  readonly endpointUrl: string;
  readonly tableName: string;
  readonly credentials: ServiceNowCredentials;
  readonly client: ServiceNowClient;
  readonly customFieldMappings?: ReadonlyArray<ServiceNowCustomFieldMapping>;
}

async function validateAndAuthenticate(
  message: ChannelFanoutMessage | BatchChannelFanoutMessage,
  dependencies: ChannelDependencies,
): Promise<ValidatedChannel | null> {
  if (message.channel.type !== ChannelType.ServiceNow) {
    dependencies.logger.warn('Received non-servicenow channel message, skipping', {
      channelType: message.channel.type,
    });
    return null;
  }

  const { endpointUrl, tableName, credentialsSecretArn, customFieldMappings } = message.channel;

  validateServiceNowInstanceUrl(endpointUrl);
  validateServiceNowTableName(tableName);

  dependencies.logger.debug('Retrieving ServiceNow secret', { credentialsSecretArn });
  const secretValue = await getCachedSecretValue(dependencies.secretsClient, credentialsSecretArn, dependencies.logger);
  const credentials = parseServiceNowCredentials(JSON.parse(secretValue));

  const client = new ServiceNowClient({
    fetchWithRetry: dependencies.fetchWithRetry,
    logger: dependencies.logger,
  });

  return { endpointUrl, tableName, credentials, client, customFieldMappings };
}

export async function deliver(message: ChannelFanoutMessage, dependencies: ChannelDependencies): Promise<void> {
  const channel = await validateAndAuthenticate(message, dependencies);
  if (!channel) return;

  const result = await channel.client.createRecord({
    instanceUrl: channel.endpointUrl,
    tableName: channel.tableName,
    credentials: channel.credentials,
    event: message.event,
    configId: message.configId,
    configName: message.configName,
    contentOptions: message.contentOptions,
    customFields: channel.customFieldMappings,
  });

  dependencies.logger.debug('ServiceNow delivery completed', {
    hasSysId: !!result.sysId,
    configId: message.configId,
  });
}

export async function deliverBatch(
  message: BatchChannelFanoutMessage,
  dependencies: ChannelDependencies,
): Promise<void> {
  const channel = await validateAndAuthenticate(message, dependencies);
  if (!channel) return;

  await channel.client.createBatchRecord({
    instanceUrl: channel.endpointUrl,
    tableName: channel.tableName,
    credentials: channel.credentials,
    message,
    customFields: channel.customFieldMappings,
  });

  dependencies.logger.debug('ServiceNow batch delivery completed', {
    configId: message.configId,
  });
}

export const handler = createChannelHandler(channelDependencies, deliver, deliverBatch);
