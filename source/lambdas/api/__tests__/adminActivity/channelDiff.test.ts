// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { DeliveryChannelConfig, NotificationConfigurationItem } from '@asr/data-models';
import { computeChannelChange } from '../../adminActivity/channelDiff';

function configWithChannels(
  deliveryChannels: DeliveryChannelConfig[],
): Pick<NotificationConfigurationItem, 'deliveryChannels'> {
  return { deliveryChannels };
}

describe('computeChannelChange', () => {
  it('flags a destination change when a destination field changes', () => {
    // ARRANGE
    const oldConfig = configWithChannels([
      { type: 'slack', enabled: true, channelId: 'C0000000001', credentialsSecretArn: 'arn:a' },
    ]);
    const newConfig = configWithChannels([
      { type: 'slack', enabled: true, channelId: 'C9999999999', credentialsSecretArn: 'arn:a' },
    ]);

    // ACT
    const result = computeChannelChange(oldConfig, newConfig);

    // ASSERT
    expect(result.action).toBe('CHANNEL_DESTINATION_CHANGED');
    expect(result.changedFields).toContain('slack.channelId');
  });

  it('flags a destination change when a channel type is added', () => {
    // ARRANGE
    const oldConfig = configWithChannels([
      { type: 'slack', enabled: true, channelId: 'C1', credentialsSecretArn: 'arn:a' },
    ]);
    const newConfig = configWithChannels([
      { type: 'slack', enabled: true, channelId: 'C1', credentialsSecretArn: 'arn:a' },
      { type: 'sns', enabled: true, topicArn: 'arn:aws:sns:us-east-1:111122223333:t' },
    ]);

    // ACT
    const result = computeChannelChange(oldConfig, newConfig);

    // ASSERT
    expect(result.action).toBe('CHANNEL_DESTINATION_CHANGED');
    expect(result.changedFields).toContain('sns');
  });

  it('reports a benign update when no destination field changed', () => {
    // ARRANGE
    const channel: DeliveryChannelConfig = {
      type: 'jira',
      enabled: true,
      endpointUrl: 'https://x.atlassian.net',
      projectKey: 'SEC',
      issueType: 'Bug',
      credentialsSecretArn: 'arn:a',
    };
    const oldConfig = configWithChannels([{ ...channel }]);
    const newConfig = configWithChannels([{ ...channel }]);

    // ACT
    const result = computeChannelChange(oldConfig, newConfig);

    // ASSERT
    expect(result.action).toBe('CHANNEL_UPDATED');
    expect(result.changedFields).toEqual([]);
  });
});
