// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { createChannelHandler } from './base-channel-handler';
import { channelDependencies } from './channel-setup';
import { getCachedSecretValue } from '../common/utils/secrets-utils';
import { InputValidationError } from './notification-channel-errors';
import { JiraClient } from './jira-client';
import {
  BatchChannelFanoutMessage,
  ChannelFanoutMessage,
  ChannelDependencies,
  ChannelType,
  JiraInstanceUrl,
  JiraProjectKey,
  JiraIssueType,
  parseJiraCredentials,
} from './types';
import { checkJiraInstanceUrl, JIRA_PROJECT_KEY_PATTERN } from '@asr/data-models';

export type { JiraInstanceUrl, JiraProjectKey, JiraIssueType } from './types';

/**
 * Validates a JIRA instance URL using the shared check from data-models.
 * Returns the URL as a branded JiraInstanceUrl type.
 * Throws InputValidationError if the URL is invalid.
 */
function validateJiraInstanceUrl(url: string): JiraInstanceUrl {
  const error = checkJiraInstanceUrl(url);
  if (error) {
    throw new InputValidationError(error);
  }
  return url as JiraInstanceUrl;
}

/**
 * Validates that a JIRA project key matches the expected format.
 * Must start with an uppercase letter, followed by 1-9 uppercase letters, digits, or underscores.
 * Returns the key as a branded JiraProjectKey type.
 * Throws InputValidationError if the key is invalid.
 */
export function validateJiraProjectKey(key: string): JiraProjectKey {
  if (!JIRA_PROJECT_KEY_PATTERN.test(key)) {
    throw new InputValidationError(
      'Invalid JIRA project key. Must match pattern: starts with an uppercase letter, followed by 1-9 uppercase letters, digits, or underscores (2-10 characters total)',
    );
  }
  return key as JiraProjectKey;
}

/**
 * Validates that a JIRA issue type is a non-empty string.
 * Returns the trimmed issue type as a branded JiraIssueType type.
 * Throws InputValidationError if the issue type is empty or whitespace-only.
 */
export function validateJiraIssueType(issueType: string): JiraIssueType {
  const trimmed = issueType.trim();
  if (!trimmed) {
    throw new InputValidationError('JIRA issue type is required and must not be empty');
  }
  return trimmed as JiraIssueType;
}

interface JiraChannelConfig {
  readonly endpointUrl: string;
  readonly projectKey: string;
  readonly issueType: string;
  readonly credentialsSecretArn: string;
  readonly customFieldMappings?: { key: string; value: string }[];
}

async function resolveJiraContext(channel: JiraChannelConfig, dependencies: ChannelDependencies) {
  const validatedInstanceUrl = validateJiraInstanceUrl(channel.endpointUrl);
  const validatedProjectKey = validateJiraProjectKey(channel.projectKey);
  const validatedIssueType = validateJiraIssueType(channel.issueType);

  dependencies.logger.debug('Retrieving JIRA credential', { secretArn: channel.credentialsSecretArn });
  const secretValue = await getCachedSecretValue(
    dependencies.secretsClient,
    channel.credentialsSecretArn,
    dependencies.logger,
  );
  const credentials = parseJiraCredentials(JSON.parse(secretValue));

  return { validatedInstanceUrl, validatedProjectKey, validatedIssueType, credentials };
}

export async function deliver(message: ChannelFanoutMessage, dependencies: ChannelDependencies): Promise<void> {
  if (message.channel.type !== ChannelType.Jira) {
    dependencies.logger.warn('Received non-jira channel message, skipping', {
      channelType: message.channel.type,
    });
    return;
  }

  const { validatedInstanceUrl, validatedProjectKey, validatedIssueType, credentials } = await resolveJiraContext(
    message.channel,
    dependencies,
  );

  const jiraClient = new JiraClient({ fetchWithRetry: dependencies.fetchWithRetry, logger: dependencies.logger });
  const result = await jiraClient.createIssue({
    instanceUrl: validatedInstanceUrl,
    projectKey: validatedProjectKey,
    issueType: validatedIssueType,
    credentials,
    event: message.event,
    configName: message.configName,
    contentOptions: message.contentOptions,
    customFields: message.channel.customFieldMappings,
  });

  dependencies.logger.info('JIRA issue created', { issueKey: result.key, configId: message.configId });
}

export async function deliverBatch(
  message: BatchChannelFanoutMessage,
  dependencies: ChannelDependencies,
): Promise<void> {
  if (message.channel.type !== ChannelType.Jira) {
    dependencies.logger.warn('Received non-jira channel message, skipping', {
      channelType: message.channel.type,
    });
    return;
  }

  const { validatedInstanceUrl, validatedProjectKey, validatedIssueType, credentials } = await resolveJiraContext(
    message.channel,
    dependencies,
  );

  const jiraClient = new JiraClient({ fetchWithRetry: dependencies.fetchWithRetry, logger: dependencies.logger });
  const result = await jiraClient.createBatchIssue({
    instanceUrl: validatedInstanceUrl,
    projectKey: validatedProjectKey,
    issueType: validatedIssueType,
    credentials,
    message,
    customFields: message.channel.customFieldMappings,
  });

  dependencies.logger.info('JIRA batch issue created', { issueKey: result.key, configId: message.configId });
}

export const handler = createChannelHandler(channelDependencies, deliver, deliverBatch);
