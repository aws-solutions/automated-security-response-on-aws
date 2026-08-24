// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { Logger } from '@aws-lambda-powertools/logger';
import { SecretsManagerClient } from '@aws-sdk/client-secrets-manager';
import { SNSClient } from '@aws-sdk/client-sns';
import { NotificationEvent, ContentOptions, DeliveryChannelConfig } from '@asr/data-models';
import { ChannelFanoutMessage, ChannelDependencies } from '../types';

export const createEvent = (overrides: Partial<NotificationEvent> = {}): NotificationEvent => ({
  eventType: 'finding',
  eventId: 'evt-1',
  severity: 'High',
  controlId: 'CIS.1.1',
  accountId: '123456789012',
  region: 'us-east-1',
  resourceType: 'AWS::IAM::User',
  resourceId: 'test-user',
  title: 'Test finding',
  detectedAt: '2024-01-01T00:00:00Z',
  timestamp: '2024-01-01T00:00:00Z',
  ...overrides,
});

export const createContentOptions = (overrides: Partial<ContentOptions> = {}): ContentOptions => ({
  includeManualRemediationLink: false,
  includeRemediationDeadline: false,
  enforceDeadline: false,
  includeIaCSnippet: false,
  includeEnableAutomationLink: false,
  ...overrides,
});

export function createDependencies(fetchMock?: jest.Mock): ChannelDependencies {
  return {
    logger: new Logger({ logLevel: 'SILENT' }),
    secretsClient: new SecretsManagerClient({}),
    snsClient: new SNSClient({}),
    fetchWithRetry: fetchMock ?? jest.fn(),
  };
}

export function createMessage(
  channelOverrides: Partial<DeliveryChannelConfig>,
  overrides: Partial<ChannelFanoutMessage> = {},
): ChannelFanoutMessage {
  return {
    configId: 'config-1',
    configName: 'Test Config',
    contentOptions: createContentOptions(),
    channel: { enabled: true, ...channelOverrides } as DeliveryChannelConfig,
    event: createEvent(),
    ...overrides,
  };
}
