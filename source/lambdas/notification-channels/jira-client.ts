// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import {
  NotificationEvent,
  ContentOptions,
  JiraCustomFieldMapping,
  MAX_JIRA_CUSTOM_FIELDS,
  MAX_JIRA_CUSTOM_FIELD_KEY_LENGTH,
  MAX_JIRA_CUSTOM_FIELD_VALUE_LENGTH,
  JIRA_CUSTOM_FIELD_KEY_PATTERN,
} from '@asr/data-models';
import { Logger } from '@aws-lambda-powertools/logger';
import { ChannelApiError, InputValidationError } from './notification-channel-errors';
import { formatSubject, formatEventDescription, formatBatchDescription } from './format-utils';
import { buildBatchIaCLinkGroups, buildIaCDownloadLinks, IaCDownloadLink } from './iac-download-links';
import { formatLinksJiraWiki, stripJiraWikiMarkup } from './iac-link-formatters';
import { buildBatchSubject, getBatchEventCount } from './json-body';
import {
  TemplateVariableContext,
  resolveTemplateVariables,
  BatchTemplateVariableContext,
  resolveBatchTemplateVariables,
} from './template-variables';
import {
  BatchChannelFanoutMessage,
  JiraCredentials,
  JiraCreateIssueResponse,
  getChannelSeverity,
  isJiraCreateIssueResponse,
  JIRA_CREATE_ISSUE_PATH,
} from './types';

const MAX_SNIPPET_LENGTH = 10_000;
const MAX_DESCRIPTION_LENGTH = 32_767;

interface JiraErrorBody {
  readonly errors?: Record<string, unknown>;
}

function isJiraErrorBody(value: unknown): value is JiraErrorBody {
  return typeof value === 'object' && value !== null && 'errors' in value;
}

/**
 * Detects whether a JIRA error response body is rejecting the `priority` field.
 *
 * Some JIRA projects (notably Jira Service Management projects) resolve the
 * priority field against the project's own priority scheme. When the supplied
 * priority name is not part of that scheme, JIRA responds with a 400 carrying
 * an `errors.priority` entry (e.g. "Specify the Priority (name) in the string
 * format"). Detecting this lets the client retry without the priority field so
 * JIRA applies the project default instead of dropping the notification.
 */
export function isPriorityFieldError(body: string): boolean {
  try {
    const parsed: unknown = JSON.parse(body);
    if (isJiraErrorBody(parsed)) {
      const errors = parsed.errors;
      return typeof errors === 'object' && errors !== null && 'priority' in errors;
    }
  } catch {
    // Body was not JSON; treat it as unrelated to the priority field.
  }
  return false;
}

interface JiraBaseParams {
  readonly instanceUrl: string;
  readonly projectKey: string;
  readonly issueType: string;
  readonly credentials: JiraCredentials;
  readonly customFields?: ReadonlyArray<JiraCustomFieldMapping>;
}

export interface JiraSendParams extends JiraBaseParams {
  readonly event: NotificationEvent;
  readonly configName: string;
  readonly contentOptions: ContentOptions;
}

export interface JiraBatchSendParams extends JiraBaseParams {
  readonly message: BatchChannelFanoutMessage;
}

export interface JiraClientDependencies {
  readonly fetchWithRetry: (url: string, init: RequestInit) => Promise<Response>;
  readonly logger: Logger;
}

type JiraCustomFieldContext = TemplateVariableContext | BatchTemplateVariableContext;

function validateJiraCustomFields(
  customFields: ReadonlyArray<JiraCustomFieldMapping>,
): ReadonlyArray<JiraCustomFieldMapping> {
  if (customFields.length > MAX_JIRA_CUSTOM_FIELDS) {
    throw new InputValidationError(`Custom field mappings must not exceed ${MAX_JIRA_CUSTOM_FIELDS} entries.`);
  }
  for (const field of customFields) {
    if (field.key.length > MAX_JIRA_CUSTOM_FIELD_KEY_LENGTH) {
      throw new InputValidationError(
        `Custom field key must not exceed ${MAX_JIRA_CUSTOM_FIELD_KEY_LENGTH} characters.`,
      );
    }
    if (!JIRA_CUSTOM_FIELD_KEY_PATTERN.test(field.key)) {
      throw new InputValidationError(
        `Custom field key "${field.key}" must match pattern customfield_<number> (e.g. customfield_10001).`,
      );
    }
    if (field.value.length > MAX_JIRA_CUSTOM_FIELD_VALUE_LENGTH) {
      throw new InputValidationError(
        `Custom field value for key "${field.key}" must not exceed ${MAX_JIRA_CUSTOM_FIELD_VALUE_LENGTH} characters.`,
      );
    }
  }
  return customFields;
}

function resolveJiraCustomFields<TContext extends JiraCustomFieldContext>(
  customFields: ReadonlyArray<JiraCustomFieldMapping>,
  context: TContext,
  resolver: (template: string, context: TContext) => string,
): Record<string, string> {
  const validatedFields = validateJiraCustomFields(customFields);
  const resolved: Record<string, string> = {};
  for (const field of validatedFields) {
    resolved[field.key] = resolver(field.value, context);
  }
  return resolved;
}

export function resolveCustomFields(
  customFields: ReadonlyArray<JiraCustomFieldMapping>,
  context: TemplateVariableContext,
): Record<string, string> {
  return resolveJiraCustomFields(customFields, context, (template, fieldContext) =>
    resolveTemplateVariables(template, fieldContext, stripJiraWikiMarkup),
  );
}

export function resolveBatchCustomFields(
  customFields: ReadonlyArray<JiraCustomFieldMapping>,
  context: BatchTemplateVariableContext,
): Record<string, string> {
  return resolveJiraCustomFields(customFields, context, (template, fieldContext) =>
    resolveBatchTemplateVariables(template, fieldContext, stripJiraWikiMarkup),
  );
}

export class JiraClient {
  private readonly fetchWithRetry: (url: string, init: RequestInit) => Promise<Response>;
  private readonly logger: Logger;

  constructor(dependencies: JiraClientDependencies) {
    this.fetchWithRetry = dependencies.fetchWithRetry;
    this.logger = dependencies.logger;
  }

  async createIssue(params: JiraSendParams): Promise<JiraCreateIssueResponse> {
    const { instanceUrl, projectKey, issueType, credentials, event, configName, contentOptions, customFields } = params;

    const jiraLine = (label: string, value: string): string => `*${label}:* ${value}`;
    const description = formatEventDescription(event, configName, contentOptions, jiraLine, stripJiraWikiMarkup);

    const iacLinks = buildIaCDownloadLinks(event.eventId, contentOptions, event.eventType, event.remediationStatus);
    const fullDescription = description + this.buildIaCLinksSection(iacLinks);

    const finalDescription =
      fullDescription.length > MAX_DESCRIPTION_LENGTH
        ? fullDescription.substring(0, MAX_DESCRIPTION_LENGTH - '…(truncated — JIRA limit)'.length) +
          '…(truncated — JIRA limit)'
        : fullDescription;

    const resolvedFields =
      customFields && customFields.length > 0
        ? resolveCustomFields(customFields, {
            findingId: event.eventId,
            controlId: event.controlId,
            severity: event.severity,
            accountId: event.accountId,
            region: event.region,
            resourceArn: event.resourceId,
            configName,
          })
        : {};

    const fields = {
      ...resolvedFields,
      project: { key: projectKey },
      summary: formatSubject(event, 255),
      description: finalDescription,
      issuetype: { name: issueType },
      priority: { name: getChannelSeverity(event.severity)?.jiraPriority ?? 'Medium' },
    };

    return this.postIssue(instanceUrl, credentials, fields);
  }

  async createBatchIssue(params: JiraBatchSendParams): Promise<JiraCreateIssueResponse> {
    const { instanceUrl, projectKey, issueType, credentials, message, customFields } = params;

    const summary = buildBatchSubject(message, 255);

    const eventCount = getBatchEventCount(message);
    const chunkSuffix =
      message.totalChunks !== undefined && message.totalChunks > 0 && message.chunkIndex !== undefined
        ? `\nPart ${message.chunkIndex} of ${message.totalChunks}`
        : '';
    const description =
      formatBatchDescription({
        notificationType: message.notificationType,
        eventCount,
        generationTime: message.startGenerationTime,
        exportUrl: message.exportUrl,
        linkAccessExpirationTime: message.linkAccessExpirationTime,
      }) +
      chunkSuffix +
      this.buildBatchIaCLinksSection(message);

    const resolvedFields =
      customFields && customFields.length > 0
        ? resolveBatchCustomFields(customFields, {
            configName: message.configName,
            notificationType: message.notificationType,
            findingCount: String(message.findingCount),
            remediationCount: String(message.remediationCount),
          })
        : {};

    const fields = {
      ...resolvedFields,
      project: { key: projectKey },
      summary,
      description,
      issuetype: { name: issueType },
      priority: { name: 'Medium' },
    };

    return this.postIssue(instanceUrl, credentials, fields);
  }

  /**
   * Render a single-event IaC download-links section in JIRA wiki markup.
   *
   * Mirrors the batch path and email/SNS: one download link per selected
   * format instead of an inlined template. Returns '' when there are no links
   * (ineligible event or WEB_UI_URL unset).
   */
  private buildIaCLinksSection(links: IaCDownloadLink[]): string {
    if (links.length === 0) return '';
    return `\n\n*IaC Templates:*\n${formatLinksJiraWiki(links)}`;
  }

  private buildBatchIaCLinksSection(message: JiraBatchSendParams['message']): string {
    const groups = buildBatchIaCLinkGroups(message.eventSummaries, message.contentOptions, message.notificationType);
    const sections = groups.map(
      (group) => `\n*${stripJiraWikiMarkup(group.controlId)}:*\n${formatLinksJiraWiki(group.links)}`,
    );
    return sections.length > 0 ? `\n\n*IaC Templates:*${sections.join('')}` : '';
  }

  private async postIssue(
    instanceUrl: string,
    credentials: JiraCredentials,
    fields: Record<string, unknown>,
  ): Promise<JiraCreateIssueResponse> {
    const apiUrl = `${instanceUrl}${JIRA_CREATE_ISSUE_PATH}`;
    const encodedCredentials = Buffer.from(`${credentials.username}:${credentials.apiToken}`).toString('base64');
    const authHeader = `Basic ${encodedCredentials}`;

    const sendRequest = (requestFields: Record<string, unknown>): Promise<Response> =>
      this.fetchWithRetry(apiUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: authHeader,
        },
        body: JSON.stringify({ fields: requestFields }),
      });

    const response = await this.sendWithPriorityFallback(sendRequest, fields);

    const result: unknown = await response.json();
    if (!isJiraCreateIssueResponse(result)) {
      throw new ChannelApiError('JIRA', 200, 'Response missing issue key');
    }

    return result;
  }

  /**
   * Sends the create-issue request and, when JIRA rejects the priority field on
   * a 400, retries once without the priority field so the project default
   * applies. Returns the successful {@link Response}; throws {@link ChannelApiError}
   * for any non-recoverable failure.
   */
  private async sendWithPriorityFallback(
    sendRequest: (requestFields: Record<string, unknown>) => Promise<Response>,
    fields: Record<string, unknown>,
  ): Promise<Response> {
    const response = await sendRequest(fields);
    if (response.ok) {
      return response;
    }

    const body = await response.text();
    if (response.status === 400 && 'priority' in fields && isPriorityFieldError(body)) {
      this.logger.warn('JIRA rejected the priority field; retrying without priority so the project default applies', {
        priority: fields.priority,
      });
      const { priority: _priority, ...fieldsWithoutPriority } = fields;

      const retryResponse = await sendRequest(fieldsWithoutPriority);
      if (!retryResponse.ok) {
        throw new ChannelApiError('JIRA', retryResponse.status, await retryResponse.text());
      }
      return retryResponse;
    }

    throw new ChannelApiError('JIRA', response.status, body);
  }
}
