// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import {
  SNSClient,
  CreateTopicCommand,
  DeleteTopicCommand,
  SubscribeCommand,
  UnsubscribeCommand,
  ListSubscriptionsByTopicCommand,
  Subscription,
} from '@aws-sdk/client-sns';
import { Logger } from '@aws-lambda-powertools/logger';
import { EmailSubscriptionStatus } from '@asr/data-models';

const TOPIC_PREFIX = 'asr-notifications-';

export type { EmailSubscriptionStatus };

export class EmailTopicLifecycleService {
  constructor(
    private readonly snsClient: SNSClient,
    private readonly logger: Logger,
    private readonly accountId: string,
    private readonly region: string,
    private readonly partition: string,
  ) {}

  /** Build the topic name for a given config ID. */
  private topicName(configId: string): string {
    return `${TOPIC_PREFIX}${configId}`;
  }

  /** Build the expected topic ARN for a given config ID. */
  topicArn(configId: string): string {
    return `arn:${this.partition}:sns:${this.region}:${this.accountId}:${this.topicName(configId)}`;
  }

  /** Create an SNS topic for a notification configuration. */
  async createTopic(configId: string): Promise<string> {
    const result = await this.snsClient.send(
      new CreateTopicCommand({
        Name: this.topicName(configId),
        Tags: [{ Key: 'asr:configId', Value: configId }],
      }),
    );
    if (!result.TopicArn) {
      throw new Error(`CreateTopic did not return a TopicArn for configId ${configId}`);
    }
    this.logger.info('Created SNS topic', { configId, topicArn: result.TopicArn });
    return result.TopicArn;
  }

  /** Delete the SNS topic for a notification configuration. */
  async deleteTopic(configId: string): Promise<void> {
    await this.snsClient.send(new DeleteTopicCommand({ TopicArn: this.topicArn(configId) }));
    this.logger.info('Deleted SNS topic', { configId });
  }

  /** Subscribe an email address to the config's topic. */
  async subscribe(configId: string, email: string): Promise<void> {
    await this.snsClient.send(
      new SubscribeCommand({
        TopicArn: this.topicArn(configId),
        Protocol: 'email',
        Endpoint: email,
      }),
    );
    this.logger.info('Subscribed email', { configId, email });
  }

  /** Unsubscribe by subscription ARN. */
  async unsubscribe(subscriptionArn: string): Promise<void> {
    await this.snsClient.send(new UnsubscribeCommand({ SubscriptionArn: subscriptionArn }));
    this.logger.info('Unsubscribed', { subscriptionArn });
  }

  /**
   * Sync subscriptions: add missing emails, remove stale ones.
   * When isDesiredSetIncomplete is true, existing subscriptions not in desiredEmails are
   * preserved (used when recipient resolution failed and we can't determine the full desired set).
   */
  async syncSubscriptions(
    configId: string,
    desiredEmails: string[],
    isDesiredSetIncomplete = false,
  ): Promise<EmailSubscriptionStatus[]> {
    const topicArn = this.topicArn(configId);
    const current = await this.listRawSubscriptions(topicArn);

    const currentByEmail = new Map<string, Subscription>();
    for (const sub of current) {
      if (sub.Endpoint) currentByEmail.set(sub.Endpoint, sub);
    }

    const desired = new Set(desiredEmails);

    // Skip stale removal when resolution was incomplete: we can't tell a truly
    // stale subscription from one whose desired email we simply failed to resolve.
    if (!isDesiredSetIncomplete) {
      await this.removeStaleSubscriptions(currentByEmail, desired);
    }
    await this.addMissingSubscriptions(configId, currentByEmail, desired);

    return this.listSubscriptionStatuses(configId);
  }

  /** Unsubscribe confirmed subscriptions whose email is no longer desired. Best-effort per email. */
  private async removeStaleSubscriptions(
    currentByEmail: Map<string, Subscription>,
    desired: Set<string>,
  ): Promise<void> {
    for (const [email, sub] of currentByEmail) {
      if (desired.has(email) || !sub.SubscriptionArn || sub.SubscriptionArn === 'PendingConfirmation') {
        continue;
      }
      try {
        await this.unsubscribe(sub.SubscriptionArn);
      } catch (err) {
        this.logger.error('Failed to unsubscribe stale email, continuing', { email, error: err });
      }
    }
  }

  /** Subscribe every desired email that has no current subscription. Best-effort per email. */
  private async addMissingSubscriptions(
    configId: string,
    currentByEmail: Map<string, Subscription>,
    desired: Set<string>,
  ): Promise<void> {
    for (const email of desired) {
      if (currentByEmail.has(email)) continue;
      try {
        await this.subscribe(configId, email);
      } catch (err) {
        this.logger.error('Failed to subscribe email, continuing', { configId, email, error: err });
      }
    }
  }

  /** List subscription statuses for the UI — mirrors SNS console view. */
  async listSubscriptionStatuses(configId: string): Promise<EmailSubscriptionStatus[]> {
    const topicArn = this.topicArn(configId);
    const subs = await this.listRawSubscriptions(topicArn);

    return subs
      .filter((s): s is Subscription & { Endpoint: string } => s.Protocol === 'email' && !!s.Endpoint)
      .filter((s) => s.SubscriptionArn !== 'Deleted')
      .map((s) => ({
        email: s.Endpoint,
        subscriptionArn: s.SubscriptionArn ?? '',
        status: s.SubscriptionArn === 'PendingConfirmation' ? ('PendingConfirmation' as const) : ('Confirmed' as const),
      }));
  }

  /** Resend confirmation by re-subscribing (SNS re-sends the confirmation email). */
  async resendConfirmation(configId: string, email: string): Promise<void> {
    await this.subscribe(configId, email);
    this.logger.info('Resent confirmation', { configId, email });
  }

  private async listRawSubscriptions(topicArn: string): Promise<Subscription[]> {
    const subs: Subscription[] = [];
    let nextToken: string | undefined;
    do {
      const result = await this.snsClient.send(
        new ListSubscriptionsByTopicCommand({ TopicArn: topicArn, NextToken: nextToken }),
      );
      subs.push(...(result.Subscriptions ?? []));
      nextToken = result.NextToken;
    } while (nextToken);
    return subs;
  }
}
