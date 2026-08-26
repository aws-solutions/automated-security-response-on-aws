// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * Re-exports canonical API types from @data-models for the notification UI.
 * UI-specific helper types and display utilities live here.
 */

export type {
  NotificationConfigurationItem,
  CreateNotificationConfigurationRequest,
  UpdateNotificationConfigurationRequest,
  ToggleStatusRequest,
  DeliveryChannelType,
  DeliveryChannelConfig,
  SeverityFilter,
  RemediationStatusFilter,
  BatchWindowUnit,
  RecipientType,
  NotificationType,
  ContentOptions,
  BatchWindow,
  IaCFormat,
} from '@data-models';

/** Ordered list of all supported delivery channel types. Single source of truth for the UI. */
export const CHANNEL_TYPES = ['email', 'slack', 'jira', 'servicenow', 'sns'] as const;

/** Display label for a delivery channel type. */
export const channelLabel = (type: string): string => {
  const labels: Record<string, string> = {
    email: 'Email',
    slack: 'Slack',
    jira: 'JIRA',
    servicenow: 'ServiceNow',
    sns: 'SNS',
  };
  return labels[type] ?? type;
};

/** Display label for a severity filter value. */
export const severityLabel = (s: string): string => (s === 'All' ? 'All' : s);

/** Badge color for a severity filter value. */
export const severityBadgeColor = (s: string): 'red' | 'blue' | 'green' | 'grey' => {
  if (s === 'Critical' || s === 'High') return 'red';
  if (s === 'Medium') return 'blue';
  if (s === 'Low' || s === 'Informational') return 'green';
  return 'grey';
};
