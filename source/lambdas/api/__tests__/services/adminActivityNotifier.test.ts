// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { Logger } from '@aws-lambda-powertools/logger';
import { SNSClient, PublishCommand } from '@aws-sdk/client-sns';
import { mockClient } from 'aws-sdk-client-mock';
import {
  AdminActivityNotifier,
  AdminActivityInput,
  AdminActivityNotification,
} from '../../services/adminActivityNotifier';
import { Clock } from '../../../common/utils/clock';

const snsMock = mockClient(SNSClient);

describe('AdminActivityNotifier', () => {
  const fixedNow = new Date('2026-06-22T12:00:00.000Z');
  const clock: Clock = { now: () => fixedNow };
  let logger: Logger;
  let notifier: AdminActivityNotifier;

  beforeEach(() => {
    snsMock.reset();
    snsMock.on(PublishCommand).resolves({ MessageId: 'mid' });
    logger = new Logger();
    notifier = new AdminActivityNotifier(logger, clock);
  });

  it('publishes an enriched notification for a delegated-admin destination change', async () => {
    // ARRANGE
    const input: AdminActivityInput = {
      action: 'CHANNEL_DESTINATION_CHANGED',
      actorEmail: 'delegate@example.com',
      actorGroups: ['DelegatedAdminGroup'],
      resourceType: 'notification-channel',
      resourceId: 'config-123',
      resourceName: 'Prod Slack',
      channelType: 'slack',
      changedFields: ['channelId'],
    };

    // ACT
    await notifier.notify(input);

    // ASSERT
    const calls = snsMock.commandCalls(PublishCommand);
    expect(calls).toHaveLength(1);
    const publishInput = calls[0].args[0].input;
    expect(publishInput.TopicArn).toBe('arn:aws:sns:us-east-1:123456789012:SO0111-ASR-AdminSecurityNotifications');
    expect(publishInput.Subject).toBe('[ASR] high admin action: CHANNEL_DESTINATION_CHANGED');

    const message = JSON.parse(publishInput.Message as string) as AdminActivityNotification;
    expect(message.severity).toBe('high');
    expect(message.isDelegatedAdmin).toBe(true);
    expect(message.changedFields).toEqual(['channelId']);
    expect(message.channelType).toBe('slack');
    expect(message.timestamp).toBe('2026-06-22T12:00:00.000Z');
    expect(message.region).toBe('us-east-1');
    expect(message.accountId).toBe('123456789012');
  });

  it('marks primary-admin actions as not delegated and summarizes the control count', async () => {
    // ARRANGE
    const input: AdminActivityInput = {
      action: 'CONTROL_REMEDIATION_SET',
      actorEmail: 'admin@example.com',
      actorGroups: ['AdminGroup', 'DelegatedAdminGroup'],
      resourceType: 'control',
      affectedControlCount: 12,
    };

    // ACT
    await notifier.notify(input);

    // ASSERT
    const message = JSON.parse(
      snsMock.commandCalls(PublishCommand)[0].args[0].input.Message as string,
    ) as AdminActivityNotification;
    expect(message.isDelegatedAdmin).toBe(false);
    expect(message.severity).toBe('high');
    expect(message.affectedControlCount).toBe(12);
    expect(message.summary).toContain('12 control');
  });

  it('is fail-open: logs and does not throw when publish fails', async () => {
    // ARRANGE
    snsMock.on(PublishCommand).rejects(new Error('SNS down'));
    const errorSpy = jest.spyOn(logger, 'error').mockImplementation(() => undefined);

    // ACT / ASSERT
    await expect(
      notifier.notify({
        action: 'CHANNEL_DELETED',
        actorEmail: 'a@example.com',
        actorGroups: ['AdminGroup'],
        resourceType: 'notification-channel',
        resourceId: 'c1',
      }),
    ).resolves.toBeUndefined();
    expect(errorSpy).toHaveBeenCalled();
  });
});
