// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import {
  NotificationEvent,
  ContentOptions,
  ServiceNowCustomFieldMapping,
  RESERVED_SERVICENOW_FIELD_KEYS,
  MAX_SERVICENOW_CUSTOM_FIELDS,
  MAX_SERVICENOW_CUSTOM_FIELD_KEY_LENGTH,
  MAX_SERVICENOW_CUSTOM_FIELD_VALUE_LENGTH,
} from '@asr/data-models';
import { Logger } from '@aws-lambda-powertools/logger';
import {
  BatchChannelFanoutMessage,
  ServiceNowCredentials,
  getChannelSeverity,
  isServiceNowCreateResponse,
} from './types';
import { ChannelApiError, InputValidationError } from './notification-channel-errors';
import {
  formatEventDescription,
  formatSubject,
  formatBatchDescription,
  buildManualRemediationLink,
  getWebUiUrl,
} from './format-utils';
import { buildBatchIaCLinkGroups, buildIaCDownloadLinks, IaCDownloadLink } from './iac-download-links';
import { formatLinksPlainText } from './iac-link-formatters';
import { buildBatchSubject, getBatchEventCount } from './json-body';
import {
  TemplateVariableContext,
  resolveTemplateVariables,
  BatchTemplateVariableContext,
  resolveBatchTemplateVariables,
} from './template-variables';

const MAX_SHORT_DESCRIPTION_LENGTH = 160;

interface ServiceNowBaseParams {
  readonly instanceUrl: string;
  readonly tableName: string;
  readonly credentials: ServiceNowCredentials;
  readonly customFields?: ReadonlyArray<ServiceNowCustomFieldMapping>;
}

export interface ServiceNowSendParams extends ServiceNowBaseParams {
  readonly event: NotificationEvent;
  readonly configId: string;
  readonly configName: string;
  readonly contentOptions: ContentOptions;
}

export interface ServiceNowBatchSendParams extends ServiceNowBaseParams {
  readonly message: BatchChannelFanoutMessage;
}

export interface ServiceNowClientDependencies {
  readonly fetchWithRetry: (url: string, init: RequestInit) => Promise<Response>;
  readonly logger: Logger;
}

export interface ServiceNowCreateRecordResult {
  readonly sysId?: string;
  readonly number?: string;
}

const formatAsPlainTextLine = (label: string, value: string): string => `${label}: ${value}`;

type CustomFieldContext = TemplateVariableContext | BatchTemplateVariableContext;

function resolveCustomFields<TContext extends CustomFieldContext>(
  customFields: ReadonlyArray<ServiceNowCustomFieldMapping>,
  context: TContext,
  resolver: (template: string, context: TContext) => string,
): Record<string, string> {
  if (customFields.length > MAX_SERVICENOW_CUSTOM_FIELDS) {
    throw new InputValidationError(`Custom field mappings must not exceed ${MAX_SERVICENOW_CUSTOM_FIELDS} entries.`);
  }

  const resolved: Record<string, string> = {};
  for (const field of customFields) {
    if (field.key.length > MAX_SERVICENOW_CUSTOM_FIELD_KEY_LENGTH) {
      throw new InputValidationError(
        `Custom field key must not exceed ${MAX_SERVICENOW_CUSTOM_FIELD_KEY_LENGTH} characters.`,
      );
    }
    const resolvedValue = resolver(field.value, context);
    if (resolvedValue.length > MAX_SERVICENOW_CUSTOM_FIELD_VALUE_LENGTH) {
      throw new InputValidationError(
        `Resolved custom field value for key "${field.key}" must not exceed ${MAX_SERVICENOW_CUSTOM_FIELD_VALUE_LENGTH} characters.`,
      );
    }
    resolved[field.key] = resolvedValue;
  }
  return resolved;
}

function validateNoReservedKeyConflicts(resolvedFields: Record<string, string>): void {
  for (const key of Object.keys(resolvedFields)) {
    if (RESERVED_SERVICENOW_FIELD_KEYS.has(key)) {
      throw new InputValidationError(`Custom field key "${key}" conflicts with a reserved ServiceNow record field.`);
    }
  }
}

// ServiceNow custom-field values are passed through verbatim — unlike the JIRA path, no
// markup stripping is applied. ServiceNow has no wiki-markup analog; whether a stored value
// could render as HTML/script depends on the target field type (plain String fields display
// as text; HTML and journal fields can render markup) and the instance's security hardening
// (HTML escaping/sanitizer settings), which the ServiceNow customer owns. Custom fields
// should map to standard data fields; conflicts with reserved record fields are rejected
// separately.
export function resolveServiceNowCustomFields(
  customFields: ReadonlyArray<ServiceNowCustomFieldMapping>,
  context: TemplateVariableContext,
): Record<string, string> {
  return resolveCustomFields(customFields, context, resolveTemplateVariables);
}

export function resolveBatchServiceNowCustomFields(
  customFields: ReadonlyArray<ServiceNowCustomFieldMapping>,
  context: BatchTemplateVariableContext,
): Record<string, string> {
  return resolveCustomFields(customFields, context, resolveBatchTemplateVariables);
}

interface PostRecordParams {
  readonly instanceUrl: string;
  readonly tableName: string;
  readonly credentials: ServiceNowCredentials;
  readonly payload: Record<string, unknown>;
  readonly configId: string;
}

export class ServiceNowClient {
  private readonly fetchWithRetry: (url: string, init: RequestInit) => Promise<Response>;
  private readonly logger: Logger;

  constructor(dependencies: ServiceNowClientDependencies) {
    this.fetchWithRetry = dependencies.fetchWithRetry;
    this.logger = dependencies.logger;
  }

  async createRecord(params: ServiceNowSendParams): Promise<ServiceNowCreateRecordResult> {
    const { instanceUrl, tableName, credentials, event, configId, configName, contentOptions, customFields } = params;

    const description = formatEventDescription(event, configName, contentOptions, formatAsPlainTextLine);

    const iacLinks = buildIaCDownloadLinks(event.eventId, contentOptions, event.eventType, event.remediationStatus);
    const fullDescription = description + this.buildIaCLinksSection(iacLinks);

    const shortDescription = formatSubject(event, MAX_SHORT_DESCRIPTION_LENGTH);

    const severityMeta = getChannelSeverity(event.severity);
    // ServiceNow OOB urgency/impact use a 1–3 scale (1=High, 2=Medium, 3=Low); clamp to avoid invalid values.
    const urgency = severityMeta ? Math.min(severityMeta.urgency, 3) : 3;
    const impact = urgency;

    const workNotes = this.buildWorkNotes(event, configId, configName);

    const resolvedFields =
      customFields && customFields.length > 0
        ? resolveServiceNowCustomFields(customFields, {
            findingId: event.eventId,
            controlId: event.controlId,
            severity: event.severity,
            accountId: event.accountId,
            region: event.region,
            resourceArn: event.resourceId,
            configName,
          })
        : {};

    const basePayload = {
      short_description: shortDescription,
      description: fullDescription,
      urgency,
      impact,
      work_notes: workNotes,
    };

    validateNoReservedKeyConflicts(resolvedFields);

    const recordPayload = { ...resolvedFields, ...basePayload };

    return this.postRecord({ instanceUrl, tableName, credentials, payload: recordPayload, configId });
  }

  async createBatchRecord(params: ServiceNowBatchSendParams): Promise<ServiceNowCreateRecordResult> {
    const { instanceUrl, tableName, credentials, message, customFields } = params;

    const shortDescription = buildBatchSubject(message, MAX_SHORT_DESCRIPTION_LENGTH);
    const description = this.buildBatchDescription(message);
    const resolvedFields = this.resolveBatchCustomFields(message, customFields);

    validateNoReservedKeyConflicts(resolvedFields);

    const recordPayload = {
      ...resolvedFields,
      short_description: shortDescription,
      description,
      // Batch aggregates multiple severities; a single urgency/impact cannot represent the range.
      // Default to 2 (Medium) since individual severity cannot be derived from the batch payload.
      urgency: 2,
      impact: 2,
    };

    return this.postRecord({ instanceUrl, tableName, credentials, payload: recordPayload, configId: message.configId });
  }

  private buildBatchDescription(message: BatchChannelFanoutMessage): string {
    const eventCount = getBatchEventCount(message);
    const chunkSuffix =
      message.totalChunks !== undefined && message.totalChunks > 0 && message.chunkIndex !== undefined
        ? `\nPart ${message.chunkIndex} of ${message.totalChunks}`
        : '';
    const iacSection = this.buildBatchIaCLinksText(message);
    return (
      formatBatchDescription({
        notificationType: message.notificationType,
        eventCount,
        generationTime: message.startGenerationTime,
        exportUrl: message.exportUrl,
        linkAccessExpirationTime: message.linkAccessExpirationTime,
      }) +
      chunkSuffix +
      iacSection
    );
  }

  /**
   * Render a single-event IaC download-links section as plain text.
   *
   * Mirrors the batch path and email/SNS: one download link per selected
   * format instead of an inlined template. Returns '' when there are no links
   * (ineligible event or WEB_UI_URL unset).
   */
  private buildIaCLinksSection(links: IaCDownloadLink[]): string {
    if (links.length === 0) return '';
    return `\n\nIaC Templates:\n${formatLinksPlainText(links)}`;
  }

  private buildBatchIaCLinksText(message: BatchChannelFanoutMessage): string {
    const groups = buildBatchIaCLinkGroups(message.eventSummaries, message.contentOptions, message.notificationType);
    const sections = groups.map((group) => `\n${group.controlId}:\n${formatLinksPlainText(group.links)}`);
    return sections.length > 0 ? `\n\nIaC Templates:${sections.join('')}` : '';
  }

  private resolveBatchCustomFields(
    message: BatchChannelFanoutMessage,
    customFields?: ReadonlyArray<ServiceNowCustomFieldMapping>,
  ): Record<string, string> {
    if (!customFields || customFields.length === 0) return {};
    return resolveBatchServiceNowCustomFields(customFields, {
      configName: message.configName,
      notificationType: message.notificationType,
      findingCount: String(message.findingCount),
      remediationCount: String(message.remediationCount),
    });
  }

  private async postRecord(params: PostRecordParams): Promise<ServiceNowCreateRecordResult> {
    const { instanceUrl, tableName, credentials, payload, configId } = params;

    const normalizedUrl = instanceUrl.replace(/\/$/, '');
    const apiUrl = `${normalizedUrl}/api/now/table/${encodeURIComponent(tableName)}`;
    const authHeader = `Basic ${Buffer.from(credentials.username + ':' + credentials.password).toString('base64')}`;

    const response = await this.fetchWithRetry(apiUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Accept: 'application/json',
        Authorization: authHeader,
      },
      body: JSON.stringify(payload),
    });

    if (!response.ok) {
      const body = await response.text();
      throw new ChannelApiError('ServiceNow', response.status, body);
    }

    let result: unknown;
    try {
      result = await response.json();
    } catch {
      this.logger.warn('ServiceNow returned non-JSON response body', { configId });
      return {};
    }

    if (isServiceNowCreateResponse(result) && result.result?.sys_id) {
      this.logger.info('ServiceNow record created', {
        sysId: result.result.sys_id,
        number: result.result.number,
        configId,
      });
      return { sysId: result.result.sys_id, number: result.result.number };
    }

    this.logger.info('ServiceNow record created successfully', { configId });
    return {};
  }

  private buildWorkNotes(event: NotificationEvent, configId: string, configName: string): string {
    const webUiUrl = getWebUiUrl();
    const lines = [
      `Finding ID: ${event.eventId}`,
      `Control ID: ${event.controlId}`,
      `Severity: ${event.severity}`,
      `Resource ARN: ${event.resourceId}`,
      `Account: ${event.accountId}`,
      `Region: ${event.region}`,
      ...(webUiUrl ? [`ASR Console: ${buildManualRemediationLink(event.eventId)}`] : []),
      `Configuration: ${configName} (${configId})`,
    ];
    return lines.join('\n');
  }
}
