// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import {
  SNSClient,
  CreateTopicCommand,
  DeleteTopicCommand,
  SubscribeCommand,
  UnsubscribeCommand,
  ListSubscriptionsByTopicCommand,
} from '@aws-sdk/client-sns';
import { mockClient } from 'aws-sdk-client-mock';
import { Logger } from '@aws-lambda-powertools/logger';
import { EmailTopicLifecycleService } from '../email-topic-lifecycle';

const snsMock = mockClient(SNSClient);

const ACCOUNT = '123456789012';
const REGION = 'us-east-1';
const PARTITION = 'aws';
const CONFIG_ID = 'config-1';
const TOPIC_ARN = `arn:${PARTITION}:sns:${REGION}:${ACCOUNT}:asr-notifications-${CONFIG_ID}`;

function makeService(): {
  service: EmailTopicLifecycleService;
  logger: { info: jest.Mock; error: jest.Mock };
} {
  const logger = { info: jest.fn(), error: jest.fn() };
  const service = new EmailTopicLifecycleService(
    new SNSClient({}),
    logger as unknown as Logger,
    ACCOUNT,
    REGION,
    PARTITION,
  );
  return { service, logger };
}

describe('EmailTopicLifecycleService', () => {
  beforeEach(() => {
    snsMock.reset();
  });

  describe('topicArn', () => {
    it('builds the expected ARN for a config id', () => {
      const { service } = makeService();
      expect(service.topicArn(CONFIG_ID)).toBe(TOPIC_ARN);
    });
  });

  describe('createTopic', () => {
    it('creates a topic with the config tag and returns the ARN', async () => {
      snsMock.on(CreateTopicCommand).resolves({ TopicArn: TOPIC_ARN });
      const { service, logger } = makeService();

      const arn = await service.createTopic(CONFIG_ID);

      expect(arn).toBe(TOPIC_ARN);
      const calls = snsMock.commandCalls(CreateTopicCommand);
      expect(calls).toHaveLength(1);
      expect(calls[0].args[0].input).toEqual({
        Name: `asr-notifications-${CONFIG_ID}`,
        Tags: [{ Key: 'asr:configId', Value: CONFIG_ID }],
      });
      expect(logger.info).toHaveBeenCalledWith('Created SNS topic', {
        configId: CONFIG_ID,
        topicArn: TOPIC_ARN,
      });
    });

    it('throws when CreateTopic returns no ARN', async () => {
      snsMock.on(CreateTopicCommand).resolves({});
      const { service } = makeService();

      await expect(service.createTopic(CONFIG_ID)).rejects.toThrow(
        `CreateTopic did not return a TopicArn for configId ${CONFIG_ID}`,
      );
    });
  });

  describe('deleteTopic', () => {
    it('deletes the topic for the config id', async () => {
      snsMock.on(DeleteTopicCommand).resolves({});
      const { service } = makeService();

      await service.deleteTopic(CONFIG_ID);

      const calls = snsMock.commandCalls(DeleteTopicCommand);
      expect(calls).toHaveLength(1);
      expect(calls[0].args[0].input.TopicArn).toBe(TOPIC_ARN);
    });
  });

  describe('subscribe', () => {
    it('subscribes an email to the topic', async () => {
      snsMock.on(SubscribeCommand).resolves({});
      const { service } = makeService();

      await service.subscribe(CONFIG_ID, 'a@example.com');

      const calls = snsMock.commandCalls(SubscribeCommand);
      expect(calls).toHaveLength(1);
      expect(calls[0].args[0].input).toEqual({
        TopicArn: TOPIC_ARN,
        Protocol: 'email',
        Endpoint: 'a@example.com',
      });
    });
  });

  describe('unsubscribe', () => {
    it('unsubscribes by subscription ARN', async () => {
      snsMock.on(UnsubscribeCommand).resolves({});
      const { service } = makeService();

      await service.unsubscribe('sub-arn-1');

      const calls = snsMock.commandCalls(UnsubscribeCommand);
      expect(calls).toHaveLength(1);
      expect(calls[0].args[0].input.SubscriptionArn).toBe('sub-arn-1');
    });
  });

  describe('resendConfirmation', () => {
    it('re-subscribes the email to trigger a fresh confirmation', async () => {
      snsMock.on(SubscribeCommand).resolves({});
      const { service, logger } = makeService();

      await service.resendConfirmation(CONFIG_ID, 'a@example.com');

      expect(snsMock.commandCalls(SubscribeCommand)).toHaveLength(1);
      expect(logger.info).toHaveBeenCalledWith('Resent confirmation', {
        configId: CONFIG_ID,
        email: 'a@example.com',
      });
    });
  });

  describe('listSubscriptionStatuses', () => {
    it('returns only email subscriptions, mapping pending vs confirmed and dropping deleted', async () => {
      snsMock.on(ListSubscriptionsByTopicCommand).resolves({
        Subscriptions: [
          { Protocol: 'email', Endpoint: 'confirmed@example.com', SubscriptionArn: 'arn-confirmed' },
          { Protocol: 'email', Endpoint: 'pending@example.com', SubscriptionArn: 'PendingConfirmation' },
          { Protocol: 'email', Endpoint: 'deleted@example.com', SubscriptionArn: 'Deleted' },
          { Protocol: 'sms', Endpoint: '+15555555555', SubscriptionArn: 'arn-sms' },
          { Protocol: 'email', SubscriptionArn: 'arn-no-endpoint' },
        ],
      });
      const { service } = makeService();

      const statuses = await service.listSubscriptionStatuses(CONFIG_ID);

      expect(statuses).toEqual([
        { email: 'confirmed@example.com', subscriptionArn: 'arn-confirmed', status: 'Confirmed' },
        { email: 'pending@example.com', subscriptionArn: 'PendingConfirmation', status: 'PendingConfirmation' },
      ]);
    });

    it('coerces a missing subscription ARN to an empty string', async () => {
      snsMock.on(ListSubscriptionsByTopicCommand).resolves({
        Subscriptions: [{ Protocol: 'email', Endpoint: 'x@example.com' }],
      });
      const { service } = makeService();

      const statuses = await service.listSubscriptionStatuses(CONFIG_ID);

      expect(statuses).toEqual([{ email: 'x@example.com', subscriptionArn: '', status: 'Confirmed' }]);
    });

    it('paginates through NextToken pages', async () => {
      snsMock
        .on(ListSubscriptionsByTopicCommand)
        .resolvesOnce({
          Subscriptions: [{ Protocol: 'email', Endpoint: 'page1@example.com', SubscriptionArn: 'arn-1' }],
          NextToken: 'token-2',
        })
        .resolvesOnce({
          Subscriptions: [{ Protocol: 'email', Endpoint: 'page2@example.com', SubscriptionArn: 'arn-2' }],
        });
      const { service } = makeService();

      const statuses = await service.listSubscriptionStatuses(CONFIG_ID);

      expect(statuses.map((s) => s.email)).toEqual(['page1@example.com', 'page2@example.com']);
      const calls = snsMock.commandCalls(ListSubscriptionsByTopicCommand);
      expect(calls).toHaveLength(2);
      expect(calls[1].args[0].input.NextToken).toBe('token-2');
    });

    it('handles a response with no Subscriptions field', async () => {
      snsMock.on(ListSubscriptionsByTopicCommand).resolves({});
      const { service } = makeService();

      expect(await service.listSubscriptionStatuses(CONFIG_ID)).toEqual([]);
    });
  });

  describe('syncSubscriptions', () => {
    it('adds missing emails and removes stale confirmed ones', async () => {
      // a@ stays, b@ is stale (confirmed, not desired), pending@ is skipped for removal,
      // d@ is missing and must be added.
      snsMock.on(ListSubscriptionsByTopicCommand).resolves({
        Subscriptions: [
          { Protocol: 'email', Endpoint: 'a@example.com', SubscriptionArn: 'arn-a' },
          { Protocol: 'email', Endpoint: 'b@example.com', SubscriptionArn: 'arn-b' },
          { Protocol: 'email', Endpoint: 'pending@example.com', SubscriptionArn: 'PendingConfirmation' },
          // No Endpoint — must be skipped when indexing current subscriptions by email.
          { Protocol: 'email', SubscriptionArn: 'arn-no-endpoint' },
        ],
      });
      snsMock.on(UnsubscribeCommand).resolves({});
      snsMock.on(SubscribeCommand).resolves({});
      const { service } = makeService();

      await service.syncSubscriptions(CONFIG_ID, ['a@example.com', 'd@example.com']);

      const unsub = snsMock.commandCalls(UnsubscribeCommand);
      expect(unsub).toHaveLength(1);
      expect(unsub[0].args[0].input.SubscriptionArn).toBe('arn-b');

      const sub = snsMock.commandCalls(SubscribeCommand);
      expect(sub).toHaveLength(1);
      expect(sub[0].args[0].input.Endpoint).toBe('d@example.com');
    });

    it('preserves stale subscriptions when the desired set is incomplete', async () => {
      snsMock.on(ListSubscriptionsByTopicCommand).resolves({
        Subscriptions: [{ Protocol: 'email', Endpoint: 'b@example.com', SubscriptionArn: 'arn-b' }],
      });
      snsMock.on(UnsubscribeCommand).resolves({});
      snsMock.on(SubscribeCommand).resolves({});
      const { service } = makeService();

      await service.syncSubscriptions(CONFIG_ID, ['d@example.com'], true);

      // b@ would normally be removed, but incomplete set skips stale removal.
      expect(snsMock.commandCalls(UnsubscribeCommand)).toHaveLength(0);
      expect(snsMock.commandCalls(SubscribeCommand)).toHaveLength(1);
    });

    it('skips stale removal for a subscription that has no ARN', async () => {
      snsMock.on(ListSubscriptionsByTopicCommand).resolves({
        Subscriptions: [{ Protocol: 'email', Endpoint: 'noarn@example.com' }],
      });
      snsMock.on(UnsubscribeCommand).resolves({});
      const { service } = makeService();

      // noarn@ is not desired, but with no SubscriptionArn it can't be unsubscribed.
      await service.syncSubscriptions(CONFIG_ID, []);

      expect(snsMock.commandCalls(UnsubscribeCommand)).toHaveLength(0);
    });

    it('does not re-subscribe an email that is already present', async () => {
      snsMock.on(ListSubscriptionsByTopicCommand).resolves({
        Subscriptions: [{ Protocol: 'email', Endpoint: 'a@example.com', SubscriptionArn: 'arn-a' }],
      });
      const { service } = makeService();

      await service.syncSubscriptions(CONFIG_ID, ['a@example.com']);

      expect(snsMock.commandCalls(SubscribeCommand)).toHaveLength(0);
      expect(snsMock.commandCalls(UnsubscribeCommand)).toHaveLength(0);
    });

    it('continues and logs when unsubscribing a stale email fails', async () => {
      snsMock.on(ListSubscriptionsByTopicCommand).resolves({
        Subscriptions: [{ Protocol: 'email', Endpoint: 'b@example.com', SubscriptionArn: 'arn-b' }],
      });
      snsMock.on(UnsubscribeCommand).rejects(new Error('unsub boom'));
      const { service, logger } = makeService();

      await expect(service.syncSubscriptions(CONFIG_ID, [])).resolves.toBeDefined();

      expect(logger.error).toHaveBeenCalledWith(
        'Failed to unsubscribe stale email, continuing',
        expect.objectContaining({ email: 'b@example.com' }),
      );
    });

    it('continues and logs when subscribing a missing email fails', async () => {
      snsMock.on(ListSubscriptionsByTopicCommand).resolves({ Subscriptions: [] });
      snsMock.on(SubscribeCommand).rejects(new Error('sub boom'));
      const { service, logger } = makeService();

      await expect(service.syncSubscriptions(CONFIG_ID, ['d@example.com'])).resolves.toBeDefined();

      expect(logger.error).toHaveBeenCalledWith(
        'Failed to subscribe email, continuing',
        expect.objectContaining({ configId: CONFIG_ID, email: 'd@example.com' }),
      );
    });
  });
});
