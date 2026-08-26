// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { NotificationEvent, NotificationType, ContentOptions } from '@asr/data-models';
import { Clock, getClock } from '../common/utils/clock';
import { getDisplayRemediationStatus } from '../common/utils/remediationStatusDisplay';
import { channelLambdaEnvironment } from './channelLambdaEnvironment';

const NOTIFICATION_TYPE_DISPLAY: Record<NotificationType, string> = {
  finding: 'New Finding',
  remediation: 'Remediation Result',
};

export function getWebUiUrl(): string {
  return channelLambdaEnvironment().WEB_UI_URL ?? '';
}

const MS_PER_DAY = 86_400_000;

/** Calculate the remediation deadline date and days remaining. */
export function calculateDeadline(
  detectedAt: string,
  deadlineDays: number,
  clock: Clock = getClock(),
): { deadlineDate: string; daysRemaining: number } | undefined {
  const detected = new Date(detectedAt);
  if (Number.isNaN(detected.getTime())) {
    return undefined;
  }
  const deadline = new Date(detected.getTime() + deadlineDays * MS_PER_DAY);
  const daysRemaining = Math.floor((deadline.getTime() - clock.now().getTime()) / MS_PER_DAY);
  return { deadlineDate: deadline.toISOString(), daysRemaining };
}

/** Format the deadline as a human-readable string. */
export function formatDeadline(
  detectedAt: string,
  deadlineDays: number,
  clock: Clock = getClock(),
): string | undefined {
  const result = calculateDeadline(detectedAt, deadlineDays, clock);
  if (!result) return undefined;
  const { deadlineDate, daysRemaining } = result;
  const dateStr = new Date(deadlineDate).toUTCString();
  if (daysRemaining < 0) return `OVERDUE by ${Math.abs(daysRemaining)} day(s) — was due ${dateStr}`;
  return `${dateStr} (${daysRemaining} day(s) remaining)`;
}

/** Formats a notification subject line from event fields, truncated to the given max length. */
export function formatSubject(event: NotificationEvent, maxLength: number): string {
  const title = event.title.startsWith(event.controlId)
    ? event.title.slice(event.controlId.length).trimStart()
    : event.title;
  return `[ASR] ${event.controlId} ${event.severity} ${event.eventType}: ${title}`.substring(0, maxLength);
}

/**
 * Build the deep link customers follow to act on the event.
 *
 * For findings, we link to the Findings page so the customer can remediate
 * the finding manually. For remediations, we link to the Remediation History
 * page so the customer can inspect what happened.
 */
export function buildManualRemediationLink(findingId: string, eventType: NotificationType = 'finding'): string {
  const path = eventType === 'remediation' ? '/history' : '/findings';
  return `${getWebUiUrl()}${path}?findingId=${encodeURIComponent(findingId)}`;
}

/** Human-facing label for the deep link in notifications — adapts to the event type. */
export function getManualRemediationLinkLabel(eventType: NotificationType): string {
  return eventType === 'remediation' ? 'History link' : 'Remediation link';
}

/** Build the enable-automation deep link — filters the controls page to the specific control. */
export function buildEnableAutomationLink(controlId: string): string {
  return `${getWebUiUrl()}/controls?controlId=${encodeURIComponent(controlId)}`;
}

/**
 * Builds a plain-text description body from event fields, config name, and content options.
 *
 * `encodeValue` is applied to dynamic field values only (not labels or the
 * caller's line structure), letting a channel sanitize finding-sourced values
 * for its target syntax. Defaults to identity so channels that need no encoding
 * (e.g. ServiceNow plain text) are unaffected.
 */
export function formatEventDescription(
  event: NotificationEvent,
  configName: string,
  contentOptions?: ContentOptions,
  formatLine: (label: string, value: string) => string = (label, value) => `${label}: ${value}`,
  encodeValue: (value: string) => string = (value) => value,
): string {
  const line = (label: string, value: string): string => formatLine(label, encodeValue(value));
  const lines = [
    line('Notification Type', NOTIFICATION_TYPE_DISPLAY[event.eventType]),
    line('Configuration', configName),
    line('Severity', event.severity),
    line('Control', event.controlId),
    line('Account', event.accountId),
    line('Region', event.region),
    line('Resource', `${event.resourceType} — ${event.resourceId}`),
    line('Detected', event.detectedAt),
    event.description ? encodeValue(event.description) : '',
    event.findingDescription ? line('Finding Description', event.findingDescription) : '',
    event.remediationStatus ? line('Remediation Status', getDisplayRemediationStatus(event)) : '',
    event.remediationMessage ? line('Remediation Message', event.remediationMessage) : '',
  ];

  if (contentOptions?.includeManualRemediationLink && getWebUiUrl()) {
    const linkLabel = getManualRemediationLinkLabel(event.eventType);
    const linkUrl = buildManualRemediationLink(event.eventId, event.eventType);
    lines.push(line(linkLabel, linkUrl));
  }

  if (contentOptions?.includeEnableAutomationLink && getWebUiUrl()) {
    lines.push(line('Control Settings', buildEnableAutomationLink(event.controlId)));
  }

  if (contentOptions?.includeRemediationDeadline && contentOptions.remediationDeadlineDays && event.detectedAt) {
    const deadlineText = formatDeadline(event.detectedAt, contentOptions.remediationDeadlineDays);
    if (deadlineText) {
      lines.push(line('Remediation Deadline', deadlineText));
    }
  }

  lines.push('Sent by Automated Security Response on AWS');

  return lines.filter(Boolean).join('\n');
}

function formatExportLine(exportUrl: string, linkAccessExpirationTime?: string, clock: Clock = getClock()): string {
  if (!linkAccessExpirationTime) return `Export: ${exportUrl}`;
  const isExpired = new Date(linkAccessExpirationTime).getTime() < clock.now().getTime();
  const suffix = isExpired ? ' (expired)' : '';
  return `Export: ${exportUrl} (expires: ${linkAccessExpirationTime})${suffix}`;
}

/** Builds a plain-text batch description with labeled lines. */
export function formatBatchDescription(params: {
  notificationType: NotificationType;
  eventCount: number;
  generationTime: string;
  exportUrl?: string;
  linkAccessExpirationTime?: string;
  clock?: Clock;
}): string {
  const {
    notificationType,
    eventCount,
    generationTime,
    exportUrl,
    linkAccessExpirationTime,
    clock = getClock(),
  } = params;
  const noun = notificationType === 'remediation' ? 'remediation' : 'finding';
  const pluralNoun = eventCount === 1 ? noun : `${noun}s`;

  const lines: string[] = [`Notification Type: Batch — ${eventCount} ${pluralNoun}`, `Generated: ${generationTime}`];

  if (exportUrl) {
    lines.push(formatExportLine(exportUrl, linkAccessExpirationTime, clock));
  }

  return lines.join('\n');
}
