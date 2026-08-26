// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { Logger } from '@aws-lambda-powertools/logger';
import { SNSClient, PublishCommand } from '@aws-sdk/client-sns';
import { DeliveryChannelType } from '@asr/data-models';
import { Clock, getClock } from '../../common/utils/clock';
import { apiLambdaEnvironment, apiLambdaRuntimeEnvironment } from '../apiLambdaEnvironment';
import { ACTION_SEVERITY } from '../adminActivity/notifiableActions';

const ADMIN_GROUP = 'AdminGroup';
const DELEGATED_ADMIN_GROUP = 'DelegatedAdminGroup';
const MAX_SNS_SUBJECT_LENGTH = 100;

/** Channel-lifecycle actions that target a notification channel. */
export type ChannelActivityAction =
  | 'CHANNEL_CREATED'
  | 'CHANNEL_DESTINATION_CHANGED'
  | 'CHANNEL_UPDATED'
  | 'CHANNEL_DELETED'
  | 'CHANNEL_TOGGLED';

/** Control-configuration actions that target one or more controls. */
export type ControlActivityAction = 'CONTROL_REMEDIATION_SET' | 'CONTROL_REMEDIATION_ENABLED' | 'BULK_FILTER_CHANGE';

/** Security-critical configuration changes that trigger an admin-activity notification. */
export type AdminActivityAction = ChannelActivityAction | ControlActivityAction;

/** Severity grade applied to a notifiable admin action. */
export type AdminActivitySeverity = 'high' | 'medium';

/** Kind of resource an admin action targets. */
export type AdminActivityResourceType = 'notification-channel' | 'control';

/**
 * Payload published to the admin security notifications topic when a Delegated
 * Admin (or primary Admin) performs a security-critical configuration change.
 * Carries only references (resource ids, changed field names, channel type) — never
 * a resolved Secrets Manager value or raw finding data.
 */
export interface AdminActivityNotification {
  readonly actorEmail: string;
  readonly actorGroups: string[];
  readonly isDelegatedAdmin: boolean;
  readonly action: AdminActivityAction;
  readonly severity: AdminActivitySeverity;
  readonly resourceType: AdminActivityResourceType;
  readonly resourceId?: string;
  readonly resourceName?: string;
  readonly channelType?: DeliveryChannelType;
  readonly changedFields?: string[];
  readonly affectedControlCount?: number;
  readonly timestamp: string;
  readonly region: string;
  readonly accountId: string;
  readonly webUiUrl?: string;
  readonly summary: string;
}

/** Identity of the admin performing a notifiable action, common to every activity type. */
export interface AdminActorContext {
  readonly actorEmail: string;
  readonly actorGroups: string[];
}

/** A notifiable change to a notification channel. */
interface ChannelActivityInput extends AdminActorContext {
  readonly resourceType: 'notification-channel';
  readonly action: ChannelActivityAction;
  readonly resourceId?: string;
  readonly resourceName?: string;
  readonly channelType?: DeliveryChannelType;
  readonly changedFields?: string[];
}

/** A notifiable change to one or more controls. */
interface ControlActivityInput extends AdminActorContext {
  readonly resourceType: 'control';
  readonly action: ControlActivityAction;
  readonly affectedControlCount: number;
}

/**
 * Caller-supplied details of a notifiable admin action. Modeled as a discriminated union on
 * `resourceType` so channel-only fields (e.g. `channelType`, `changedFields`) and control-only
 * fields (`affectedControlCount`) cannot be combined, and the `action` is constrained to those
 * valid for the resource type.
 */
export type AdminActivityInput = ChannelActivityInput | ControlActivityInput;

/**
 * Publishes admin-activity notifications to the dedicated, infrastructure-defined admin
 * security topic. Best-effort and fail-open: a delivery failure is logged but never thrown,
 * so it cannot fail the admin operation that triggered it.
 */
export class AdminActivityNotifier {
  private snsClient: SNSClient | undefined;

  constructor(
    private readonly logger: Logger,
    private readonly clock: Clock = getClock(),
  ) {}

  private getSnsClient(): SNSClient {
    this.snsClient ??= new SNSClient({});
    return this.snsClient;
  }

  async notify(input: AdminActivityInput): Promise<void> {
    try {
      const notification = this.buildNotification(input);

      await this.getSnsClient().send(
        new PublishCommand({
          TopicArn: apiLambdaEnvironment().ADMIN_NOTIFICATION_TOPIC_ARN,
          Subject: this.buildSubject(notification.severity, notification.action),
          Message: JSON.stringify(notification, null, 2),
        }),
      );
    } catch (error) {
      // Fail-open: never let a notification failure break the admin operation.
      this.logger.error('Failed to publish admin activity notification', {
        action: input.action,
        error: error instanceof Error ? error.message : String(error),
      });
    }
  }

  private buildNotification(input: AdminActivityInput): AdminActivityNotification {
    const env = apiLambdaEnvironment();
    const isDelegatedAdmin =
      input.actorGroups.includes(DELEGATED_ADMIN_GROUP) && !input.actorGroups.includes(ADMIN_GROUP);

    const resourceDetails =
      input.resourceType === 'control'
        ? { affectedControlCount: input.affectedControlCount }
        : {
            resourceId: input.resourceId,
            resourceName: input.resourceName,
            channelType: input.channelType,
            changedFields: input.changedFields,
          };

    return {
      actorEmail: input.actorEmail,
      actorGroups: input.actorGroups,
      isDelegatedAdmin,
      action: input.action,
      severity: ACTION_SEVERITY[input.action],
      resourceType: input.resourceType,
      ...resourceDetails,
      timestamp: this.clock.now().toISOString(),
      region: apiLambdaRuntimeEnvironment().AWS_REGION,
      accountId: env.AWS_ACCOUNT_ID,
      webUiUrl: env.WEB_UI_URL,
      summary: this.buildSummary(input, isDelegatedAdmin),
    };
  }

  private buildSubject(severity: string, action: string): string {
    const subject = `[ASR] ${severity} admin action: ${action}`;
    return subject.length > MAX_SNS_SUBJECT_LENGTH ? subject.slice(0, MAX_SNS_SUBJECT_LENGTH) : subject;
  }

  private buildSummary(input: AdminActivityInput, isDelegatedAdmin: boolean): string {
    const actor = `${input.actorEmail}${isDelegatedAdmin ? ' (Delegated Admin)' : ''}`;

    if (input.resourceType === 'control') {
      return `${actor} performed ${input.action} affecting ${input.affectedControlCount} control(s).`;
    }

    const target = input.resourceName ?? input.resourceId ?? input.channelType ?? input.resourceType;
    return `${actor} performed ${input.action} on ${target}.`;
  }
}
