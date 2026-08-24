// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import {
  ContentOptions,
  ContentOptionsSchema,
  DeliveryChannelConfig,
  DeliveryChannelConfigSchema,
  NotificationEvent,
  NotificationTypeSchema,
} from '@asr/data-models';
import { z } from 'zod';
import { SecretsManagerClient } from '@aws-sdk/client-secrets-manager';
import { SNSClient } from '@aws-sdk/client-sns';
import { Logger } from '@aws-lambda-powertools/logger';
import { CredentialParsingError } from './notification-channel-errors';

/** Canonical severity levels used across all notification channels. */
export type SeverityLevel = 'Critical' | 'High' | 'Medium' | 'Low' | 'Informational';

/** OCSF severity_id values mapped to canonical SeverityLevel. */
export type OcsfSeverityId = 0 | 1 | 2 | 3 | 4 | 5;

const SEVERITY_LEVELS = new Set<string>(['Critical', 'High', 'Medium', 'Low', 'Informational']);

/** Type guard to check if a string is a valid SeverityLevel. */
export function isSeverityLevel(value: string): value is SeverityLevel {
  return SEVERITY_LEVELS.has(value);
}

/**
 * Normalizes a severity string to title-case and returns the corresponding SeverityMeta,
 * or undefined if the value doesn't match any known severity level.
 * Handles case-insensitive input (e.g. 'LOW', 'low', 'Low' all map to 'Low').
 */
export function getChannelSeverity(value: string): SeverityMeta | undefined {
  const normalized = value.charAt(0).toUpperCase() + value.slice(1).toLowerCase();
  return isSeverityLevel(normalized) ? SEVERITY_MAP[normalized] : undefined;
}

/** Maps OCSF severity_id (0–5) to canonical SeverityLevel. */
export const OCSF_SEVERITY_MAP: Record<OcsfSeverityId, SeverityLevel> = {
  0: 'Informational', // Unknown
  1: 'Informational', // Informational
  2: 'Low', // Low
  3: 'Medium', // Medium
  4: 'High', // High
  5: 'Critical', // Critical / Fatal
};

/**
 * Supported notification channel types.
 * These values intentionally mirror DeliveryChannelType from @asr/data-models.
 * An enum is used here for exhaustive switch-case checking in channel routing.
 */
export enum ChannelType {
  Email = 'email',
  Slack = 'slack',
  Jira = 'jira',
  ServiceNow = 'servicenow',
  Sns = 'sns',
}

/** Channel-specific metadata for each severity level. */
export interface SeverityMeta {
  readonly urgency: number;
  readonly jiraPriority: string;
}

/** Single source of truth for severity-to-channel mappings. */
export const SEVERITY_MAP: Record<SeverityLevel, SeverityMeta> = {
  Critical: { urgency: 1, jiraPriority: 'Highest' },
  High: { urgency: 2, jiraPriority: 'High' },
  Medium: { urgency: 3, jiraPriority: 'Medium' },
  Low: { urgency: 4, jiraPriority: 'Low' },
  Informational: { urgency: 4, jiraPriority: 'Lowest' },
};

/**
 * Payload published by the NotificationDispatcher to the ChannelFanout SNS topic.
 * Each channel adapter Lambda receives this as the SNS message body.
 */
export interface ChannelFanoutMessage {
  readonly configId: string;
  readonly configName: string;
  readonly contentOptions: ContentOptions;
  readonly channel: DeliveryChannelConfig;
  readonly event: NotificationEvent;
}

/** Summary of a single event included in batch notifications for inline display. */
export const BatchEventSummarySchema = z.object({
  // Optional for backward compatibility: messages produced by an older batch
  // processor (in flight in SQS/SNS during a rolling deployment) won't carry
  // eventId. Keeping it optional lets the new channel Lambda accept them rather
  // than rejecting them at Zod validation. IaC download links are skipped for
  // summaries without an eventId (see buildBatchIaCLinkGroups).
  eventId: z.string().optional(),
  controlId: z.string(),
  accountId: z.string(),
  region: z.string(),
  severity: z.string(),
  resourceId: z.string(),
  remediationStatus: z.string().optional(),
  remediationMessage: z.string().optional(),
});

export type BatchEventSummary = z.infer<typeof BatchEventSummarySchema>;

/**
 * Payload published by the BatchProcessor to the ChannelFanout SNS topic.
 * Contains aggregated finding/remediation IDs for a batch window.
 *
 * Invariant: exactly one of `findingCount` / `remediationCount` is > 0, decided
 * by the config's `notificationType`. Channels render only the relevant count.
 *
 * `startGenerationTime` is the ISO timestamp of when the batch processor began
 * dispatching this batch — useful for support and audit trails.
 *
 * `linkAccessExpirationTime` is the ISO timestamp when the pre-signed
 * `exportUrl` expires; undefined when no CSV is attached.
 */
export const BatchChannelFanoutMessageSchema = z.object({
  configId: z.string(),
  configName: z.string(),
  notificationType: NotificationTypeSchema,
  contentOptions: ContentOptionsSchema,
  channel: DeliveryChannelConfigSchema,
  isBatch: z.literal(true),
  findingCount: z.number(),
  remediationCount: z.number(),
  startGenerationTime: z.string(),
  linkAccessExpirationTime: z.iso.datetime().optional(),
  exportUrl: z.string().optional(),
  eventSummaries: z.array(BatchEventSummarySchema).optional(),
  chunkIndex: z.number().optional(),
  totalChunks: z.number().optional(),
});

export type BatchChannelFanoutMessage = z.infer<typeof BatchChannelFanoutMessageSchema>;

export type ChannelMessage = ChannelFanoutMessage | BatchChannelFanoutMessage;

/** Injectable dependencies for channel deliver functions. */
export interface ChannelDependencies {
  readonly logger: Logger;
  readonly secretsClient: SecretsManagerClient;
  readonly snsClient: SNSClient;
  readonly fetchWithRetry: (url: string, init: RequestInit) => Promise<Response>;
}

/** Response from ServiceNow Table API when creating a record. */
export interface ServiceNowCreateResponse {
  result?: {
    sys_id?: string;
    number?: string;
  };
}

/** Response from JIRA REST API when creating an issue. */
export interface JiraCreateIssueResponse {
  key: string;
  id: string;
  self: string;
}

/** Credentials for JIRA API authentication. */
export interface JiraCredentials {
  readonly username: string;
  readonly apiToken: string;
}

/**
 * Looks up a property value by key, ignoring case. Returns the match found.
 * Throws if multiple case-variant keys exist (e.g. "username" and "Username")
 * to prevent silently masking credential misconfigurations.
 */
function getFieldCaseInsensitive(obj: object, key: string): unknown {
  const lower = key.toLowerCase();
  const entries = Object.entries(obj);
  const matches = entries.filter(([k]) => k.toLowerCase() === lower);
  if (matches.length > 1) {
    throw new CredentialParsingError(`Ambiguous credential field: multiple case variants found for "${key}"`);
  }
  return matches.length === 1 ? matches[0][1] : undefined;
}

/** Extracts validated JiraCredentials from parsed JSON. */
export function parseJiraCredentials(value: unknown): JiraCredentials {
  if (typeof value !== 'object' || value === null) {
    throw new CredentialParsingError('JIRA credentials secret must be a JSON object with username and apiToken fields');
  }
  const username = getFieldCaseInsensitive(value, 'username');
  if (typeof username !== 'string' || !username) {
    throw new CredentialParsingError('JIRA credentials secret missing username');
  }
  const token = getFieldCaseInsensitive(value, 'apiToken') ?? getFieldCaseInsensitive(value, 'password');
  if (typeof token !== 'string' || !token) {
    throw new CredentialParsingError('JIRA credentials secret missing apiToken or password');
  }
  return { username, apiToken: token };
}

/** Credentials for ServiceNow API authentication. */
export interface ServiceNowCredentials {
  readonly username: string;
  readonly password: string;
}

/** Extracts validated ServiceNowCredentials from parsed JSON. */
export function parseServiceNowCredentials(value: unknown): ServiceNowCredentials {
  if (typeof value !== 'object' || value === null) {
    throw new CredentialParsingError(
      'ServiceNow credentials secret must be a JSON object with username and password fields',
    );
  }
  const username = getFieldCaseInsensitive(value, 'username');
  if (typeof username !== 'string' || !username) {
    throw new CredentialParsingError('ServiceNow credentials secret missing username');
  }
  const password = getFieldCaseInsensitive(value, 'password');
  if (typeof password !== 'string' || !password) {
    throw new CredentialParsingError('ServiceNow credentials secret missing password');
  }
  return { username, password };
}

/** Type guard to validate a JIRA API create-issue response. */
export function isJiraCreateIssueResponse(value: unknown): value is JiraCreateIssueResponse {
  return typeof value === 'object' && value !== null && 'key' in value && typeof value.key === 'string';
}

/** Type guard to validate a ServiceNow Table API create response. */
export function isServiceNowCreateResponse(value: unknown): value is ServiceNowCreateResponse {
  if (typeof value !== 'object' || value === null) return false;
  if (!('result' in value)) return true; // result is optional
  return typeof value.result === 'object' || value.result === undefined;
}

/** Type guard to validate a ChannelFanoutMessage from parsed JSON. */
export function isChannelFanoutMessage(value: unknown): value is ChannelFanoutMessage {
  if (typeof value !== 'object' || value === null) return false;
  return (
    'configId' in value &&
    typeof value.configId === 'string' &&
    'configName' in value &&
    typeof value.configName === 'string' &&
    'channel' in value &&
    typeof value.channel === 'object' &&
    value.channel !== null &&
    'event' in value &&
    typeof value.event === 'object' &&
    value.event !== null &&
    'contentOptions' in value &&
    typeof value.contentOptions === 'object' &&
    value.contentOptions !== null
  );
}

/** Validates a BatchChannelFanoutMessage from parsed JSON using Zod. */
export function isBatchChannelFanoutMessage(value: unknown): value is BatchChannelFanoutMessage {
  return BatchChannelFanoutMessageSchema.safeParse(value).success;
}

/** Type guard for either message shape. */
export function isChannelMessage(value: unknown): value is ChannelMessage {
  return isChannelFanoutMessage(value) || isBatchChannelFanoutMessage(value);
}

/** Slack Block Kit text element. */
export interface SlackTextObject {
  readonly type: 'plain_text' | 'mrkdwn';
  readonly text: string;
}

/** Slack Block Kit block element. */
export interface SlackBlock {
  readonly type: 'header' | 'section' | 'divider' | 'context';
  readonly text?: SlackTextObject;
  readonly fields?: SlackTextObject[];
  readonly elements?: SlackTextObject[];
}

/** Slack Block Kit message payload. */
export interface SlackPayload {
  readonly blocks: SlackBlock[];
  readonly channel?: string;
}

export type SlackWebhookUrl = string & { readonly __brand: 'SlackWebhookUrl' };

export type JiraInstanceUrl = string & { readonly __brand: 'JiraInstanceUrl' };

export type JiraProjectKey = string & { readonly __brand: 'JiraProjectKey' };

export type JiraIssueType = string & { readonly __brand: 'JiraIssueType' };

/** JIRA REST API v2 create-issue endpoint suffix. */
export const JIRA_CREATE_ISSUE_PATH = '/rest/api/2/issue';
