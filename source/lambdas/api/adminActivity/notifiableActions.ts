// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { DeliveryChannelType } from '@asr/data-models';
import type { AdminActivityAction, AdminActivitySeverity } from '../services/adminActivityNotifier';

/**
 * Severity grade for each notifiable admin action. `high` covers actions that materially
 * change the solution's security posture: establishing a new external destination for
 * finding data (`CHANNEL_CREATED`), redirecting an existing destination
 * (`CHANNEL_DESTINATION_CHANGED`), disabling automated remediation
 * (`CONTROL_REMEDIATION_SET`), or changing filters across all controls
 * (`BULK_FILTER_CHANGE`). `medium` covers lower-impact lifecycle changes that do not open a
 * new data path or weaken remediation: benign channel edits, enable/disable toggles,
 * deletes, and re-enabling automated remediation.
 */
export const ACTION_SEVERITY: Record<AdminActivityAction, AdminActivitySeverity> = {
  CHANNEL_CREATED: 'high',
  CHANNEL_DESTINATION_CHANGED: 'high',
  CHANNEL_UPDATED: 'medium',
  CHANNEL_DELETED: 'medium',
  CHANNEL_TOGGLED: 'medium',
  CONTROL_REMEDIATION_SET: 'high',
  CONTROL_REMEDIATION_ENABLED: 'medium',
  BULK_FILTER_CHANGE: 'high',
};

/**
 * Per-channel-type set of configuration fields that determine where finding data is
 * delivered. A change to any of these between the old and new config is treated as a
 * destination change (`CHANNEL_DESTINATION_CHANGED`); a change to other fields is a
 * `CHANNEL_UPDATED`.
 *
 * `credentialsSecretArn` is an ARN reference, not the secret value, so it is safe to
 * surface as a changed field name. Raw webhook URLs/tokens live in Secrets Manager and
 * are never part of the stored config.
 */
export const DESTINATION_FIELDS_BY_CHANNEL_TYPE: Record<DeliveryChannelType, readonly string[]> = {
  email: ['recipients'],
  slack: ['channelId', 'credentialsSecretArn'],
  jira: ['endpointUrl', 'projectKey', 'issueType', 'credentialsSecretArn'],
  servicenow: ['endpointUrl', 'tableName', 'credentialsSecretArn'],
  sns: ['topicArn'],
};
