// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { buildBatchIaCLinkGroups, buildIaCDownloadLinks } from './iac-download-links';
import { buildEnableAutomationLink, buildManualRemediationLink, calculateDeadline, getWebUiUrl } from './format-utils';
import { BatchChannelFanoutMessage, ChannelFanoutMessage } from './types';

/**
 * Schema version of the JSON body shared by SNS and email channels.
 * Bump this whenever the body shape changes in a backwards-incompatible way.
 */
export const NOTIFICATION_JSON_SCHEMA_VERSION = '1.0';

/** Optional content-driven extras included alongside the event in the JSON body. */
interface NotificationExtras {
  manualRemediationUrl?: string;
  controlSettingsUrl?: string;
  remediationDeadline?: { deadlineDate: string; daysRemaining: number };
}

/** IaC download link entry in JSON bodies when the customer opts in. */
interface IaCDownloadLinkEntry {
  format: string;
  url: string;
}

/**
 * IaC download links for one control in a batched notification. Batches cover
 * many events, so links are grouped per control rather than flat as in the
 * single-event body, matching how the Slack, Jira and ServiceNow batch bodies
 * present them.
 */
interface BatchIaCDownloadLinkGroup {
  controlId: string;
  links: IaCDownloadLinkEntry[];
}

/** Public schema of the JSON body sent for a single-event notification. */
export interface SingleNotificationJsonBody extends NotificationExtras {
  schemaVersion: typeof NOTIFICATION_JSON_SCHEMA_VERSION;
  configId: string;
  configName: string;
  event: ChannelFanoutMessage['event'];
  iacDownloadLinks?: IaCDownloadLinkEntry[];
}

/** Public schema of the JSON body sent for a batched notification. */
export interface BatchNotificationJsonBody {
  schemaVersion: typeof NOTIFICATION_JSON_SCHEMA_VERSION;
  configId: string;
  configName: string;
  notificationType: BatchChannelFanoutMessage['notificationType'];
  startGenerationTime: string;
  findingCount?: number;
  remediationCount?: number;
  exportUrl?: string;
  linkAccessExpirationTime?: string;
  chunkIndex?: number;
  totalChunks?: number;
  iacDownloadLinkGroups?: BatchIaCDownloadLinkGroup[];
}

/** Build the optional content-driven extras included alongside the event in the JSON body. */
function buildExtras(
  event: ChannelFanoutMessage['event'],
  contentOptions: ChannelFanoutMessage['contentOptions'],
): NotificationExtras {
  const extras: NotificationExtras = {};
  const webUiUrl = getWebUiUrl();

  if (contentOptions.includeManualRemediationLink && webUiUrl) {
    extras.manualRemediationUrl = buildManualRemediationLink(event.eventId, event.eventType);
  }
  if (contentOptions.includeEnableAutomationLink && webUiUrl) {
    extras.controlSettingsUrl = buildEnableAutomationLink(event.controlId);
  }
  if (contentOptions.includeRemediationDeadline && contentOptions.remediationDeadlineDays && event.detectedAt) {
    const result = calculateDeadline(event.detectedAt, contentOptions.remediationDeadlineDays);
    if (result) {
      extras.remediationDeadline = { deadlineDate: result.deadlineDate, daysRemaining: result.daysRemaining };
    }
  }
  return extras;
}

/**
 * Build the pretty-printed JSON body used by both the SNS and email channels for a
 * single-event notification. IaC download links are included when configured.
 */
export async function buildSingleNotificationJsonBody(message: ChannelFanoutMessage): Promise<string> {
  const { event, configName, contentOptions } = message;
  const downloadLinks = buildIaCDownloadLinks(event.eventId, contentOptions, event.eventType, event.remediationStatus);

  const body: SingleNotificationJsonBody = {
    schemaVersion: NOTIFICATION_JSON_SCHEMA_VERSION,
    configId: message.configId,
    configName,
    event,
    ...buildExtras(event, contentOptions),
    ...(downloadLinks.length > 0 && {
      iacDownloadLinks: downloadLinks.map((l) => ({ format: l.format, url: l.url })),
    }),
  };

  return JSON.stringify(body, null, 2);
}

/**
 * Build the pretty-printed JSON body used by both the SNS and email channels for a
 * batched notification. The body summarizes the batch (counts, generation time)
 * and includes a CSV export link plus chunk markers when applicable, along with
 * per-control IaC download links so batches carry the same IaC content the
 * single-event body and the other channels already provide.
 */
export function buildBatchNotificationJsonBody(message: BatchChannelFanoutMessage): string {
  const isRemediation = message.notificationType === 'remediation';
  const count = isRemediation ? message.remediationCount : message.findingCount;
  const iacLinkGroups = buildBatchIaCLinkGroups(
    message.eventSummaries,
    message.contentOptions,
    message.notificationType,
  );

  const body: BatchNotificationJsonBody = {
    schemaVersion: NOTIFICATION_JSON_SCHEMA_VERSION,
    configId: message.configId,
    configName: message.configName,
    notificationType: message.notificationType,
    startGenerationTime: message.startGenerationTime,
    ...(isRemediation ? { remediationCount: count } : { findingCount: count }),
    ...(message.exportUrl && { exportUrl: message.exportUrl }),
    ...(message.linkAccessExpirationTime && { linkAccessExpirationTime: message.linkAccessExpirationTime }),
    ...(message.totalChunks !== undefined &&
      message.totalChunks > 0 &&
      message.chunkIndex !== undefined && {
        chunkIndex: message.chunkIndex,
        totalChunks: message.totalChunks,
      }),
    ...(iacLinkGroups.length > 0 && {
      iacDownloadLinkGroups: iacLinkGroups.map((group) => ({
        controlId: group.controlId,
        links: group.links.map((link) => ({ format: link.format, url: link.url })),
      })),
    }),
  };

  return JSON.stringify(body, null, 2);
}

/**
 * Build the subject line for a batched notification. Shared by SNS and email so both
 * channels stay in sync on the user-facing format.
 */
export function buildBatchSubject(message: BatchChannelFanoutMessage, maxLength = 100): string {
  const isRemediation = message.notificationType === 'remediation';
  const count = isRemediation ? message.remediationCount : message.findingCount;
  const noun = isRemediation ? 'remediation' : 'finding';
  const countLabel = `${count} ${noun}${count === 1 ? '' : 's'}`;
  return `${message.configName} - ${countLabel}`.slice(0, maxLength);
}

export function getBatchEventCount(message: BatchChannelFanoutMessage): number {
  return message.notificationType === 'remediation' ? message.remediationCount : message.findingCount;
}
