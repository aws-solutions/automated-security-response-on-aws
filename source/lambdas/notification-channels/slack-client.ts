// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { NotificationEvent, ContentOptions } from '@asr/data-models';
import { Logger } from '@aws-lambda-powertools/logger';
import { ChannelApiError } from './notification-channel-errors';
import { buildBatchIaCLinkGroups, buildIaCDownloadLinks } from './iac-download-links';
import { formatLinksSlackMarkdown } from './iac-link-formatters';
import {
  buildManualRemediationLink,
  buildEnableAutomationLink,
  formatDeadline,
  getManualRemediationLinkLabel,
  getWebUiUrl,
} from './format-utils';
import { SlackBlock, SlackPayload, SlackWebhookUrl, BatchChannelFanoutMessage } from './types';
import { getBatchEventCount } from './json-body';

const MAX_BLOCKS_PER_MESSAGE = 50;

// Matches Slack emoji shortcode patterns like :emoji_name: or :custom-emoji:
// Matches :shortcode: patterns containing at least one letter.
// Requires at least one letter to avoid false positives on timestamps (e.g. :30:).
// The lookahead `(?=[^:]*[a-zA-Z])` uses `[^:]` (any non-colon) which cannot overlap
// with the `:` delimiter, preventing catastrophic backtracking.
const EMOJI_SHORTCODE_PATTERN = /:(?=[^:]*[a-zA-Z])([a-zA-Z0-9_+-]+):/g;
const ZERO_WIDTH_SPACE = '\u200B';

/**
 * Escapes text for safe inclusion in Slack mrkdwn blocks.
 *
 * Slack requires `&`, `<`, `>` to be HTML-entity encoded when they are not
 * used as control characters. Additionally, `:word:` patterns are rendered as
 * emoji — a zero-width space is inserted after the leading colon to suppress
 * unintended emoji rendering.
 *
 * @see https://api.slack.com/reference/surfaces/formatting#escaping
 */
export function escapeSlackText(text: string): string {
  return text
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll(EMOJI_SHORTCODE_PATTERN, `:${ZERO_WIDTH_SPACE}$1:`);
}

/**
 * Escapes content for inclusion inside triple-backtick code blocks.
 *
 * Slack does not render emoji shortcodes inside code blocks, so only the
 * standard `&`, `<`, `>` entity encoding is needed. Applying emoji escaping
 * here would inject zero-width spaces that corrupt displayed content (e.g.
 * ARNs containing `:aws:`, `:iam:`, `:s3:`).
 */
export function escapeSlackCodeContent(text: string): string {
  return text.replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;');
}

/**
 * Escapes a URL for use inside Slack's `<url|label>` link syntax.
 *
 * Only `&` needs encoding per Slack docs. Applying `<`/`>` or emoji escaping
 * would corrupt the URL.
 */
export function escapeSlackUrl(url: string): string {
  return url.replaceAll('&', '&amp;');
}

export interface SlackSendParams {
  readonly webhookUrl: SlackWebhookUrl;
  readonly event: NotificationEvent;
  readonly configName: string;
  readonly contentOptions: ContentOptions;
  readonly channelId?: string;
}

export interface SlackSendBatchParams {
  readonly webhookUrl: SlackWebhookUrl;
  readonly message: BatchChannelFanoutMessage;
  readonly channelId?: string;
}

export interface SlackClientDependencies {
  readonly fetchWithRetry: (url: string, init: RequestInit) => Promise<Response>;
  readonly logger: Logger;
}

export class SlackClient {
  private readonly fetchWithRetry: (url: string, init: RequestInit) => Promise<Response>;
  private readonly logger: Logger;

  constructor(dependencies: SlackClientDependencies) {
    this.fetchWithRetry = dependencies.fetchWithRetry;
    this.logger = dependencies.logger;
  }

  async send(params: SlackSendParams): Promise<void> {
    const { webhookUrl, event, configName, contentOptions, channelId } = params;

    const blocks: SlackBlock[] = [
      {
        type: 'header',
        text: {
          type: 'plain_text',
          text: `${event.severity} ${event.eventType} Alert`,
        },
      },
      {
        type: 'section',
        fields: [
          { type: 'mrkdwn', text: `*Config:*\n${escapeSlackText(configName)}` },
          { type: 'mrkdwn', text: `*Severity:*\n${escapeSlackText(event.severity)}` },
          { type: 'mrkdwn', text: `*Control:*\n${escapeSlackText(event.controlId)}` },
          { type: 'mrkdwn', text: `*Account:*\n${escapeSlackText(event.accountId)}` },
          { type: 'mrkdwn', text: `*Region:*\n${escapeSlackText(event.region)}` },
          {
            type: 'mrkdwn',
            text: `*Resource:*\n${escapeSlackText(event.resourceType)} — ${escapeSlackText(event.resourceId)}`,
          },
        ],
      },
      {
        type: 'section',
        text: { type: 'mrkdwn', text: `*Title:* ${escapeSlackText(event.title)}` },
      },
    ];

    if (event.findingDescription) {
      blocks.push({
        type: 'section',
        text: { type: 'mrkdwn', text: `*Description:* ${escapeSlackText(event.findingDescription)}` },
      });
    }

    this.appendLinkBlocks(blocks, event, contentOptions);
    this.appendDeadlineBlock(blocks, event, contentOptions);
    this.appendIaCLinks(blocks, event, contentOptions);

    const payload: SlackPayload = {
      blocks,
      ...(channelId ? { channel: channelId } : {}),
    };

    const response = await this.fetchWithRetry(webhookUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });

    if (!response.ok) {
      const body = await response.text();
      throw new ChannelApiError('Slack', response.status, body);
    }
  }

  private appendLinkBlocks(
    blocks: SlackBlock[],
    event: SlackSendParams['event'],
    contentOptions: SlackSendParams['contentOptions'],
  ): void {
    if (!getWebUiUrl()) return;

    const links: string[] = [];
    if (contentOptions?.includeManualRemediationLink) {
      const label = getManualRemediationLinkLabel(event.eventType);
      links.push(`<${buildManualRemediationLink(event.eventId, event.eventType)}|${label}>`);
    }
    if (contentOptions?.includeEnableAutomationLink) {
      links.push(`<${buildEnableAutomationLink(event.controlId)}|Control Settings>`);
    }
    if (links.length > 0) {
      blocks.push({ type: 'section', text: { type: 'mrkdwn', text: links.join(' | ') } });
    }
  }

  private appendDeadlineBlock(
    blocks: SlackBlock[],
    event: SlackSendParams['event'],
    contentOptions: SlackSendParams['contentOptions'],
  ): void {
    if (contentOptions?.includeRemediationDeadline && contentOptions.remediationDeadlineDays && event.detectedAt) {
      const deadlineText = formatDeadline(event.detectedAt, contentOptions.remediationDeadlineDays);
      if (deadlineText) {
        blocks.push({
          type: 'context',
          elements: [{ type: 'mrkdwn', text: `⏰ ${deadlineText}` }],
        });
      }
    }
  }

  async sendBatch(params: SlackSendBatchParams): Promise<void> {
    const { webhookUrl, message, channelId } = params;
    const { notificationType, configName, startGenerationTime, exportUrl, linkAccessExpirationTime } = message;

    const count = getBatchEventCount(message);
    const noun = count === 1 ? notificationType : `${notificationType}s`;

    const capitalizedType = notificationType.charAt(0).toUpperCase() + notificationType.slice(1);
    const blocks: SlackBlock[] = [
      {
        type: 'header',
        text: { type: 'plain_text', text: `${capitalizedType} Batch — ${count} ${noun}` },
      },
      {
        type: 'section',
        fields: [
          { type: 'mrkdwn', text: `*Config:*\n${escapeSlackText(configName)}` },
          { type: 'mrkdwn', text: `*Generated:*\n${escapeSlackText(startGenerationTime)}` },
        ],
      },
    ];

    if (exportUrl) {
      const escapedUrl = escapeSlackUrl(exportUrl);
      const exportText = linkAccessExpirationTime
        ? `*Export:* <${escapedUrl}|Download CSV>\nExpires: ${escapeSlackText(linkAccessExpirationTime)}`
        : `*Export:* <${escapedUrl}|Download CSV>`;
      blocks.push({ type: 'section', text: { type: 'mrkdwn', text: exportText } });
    }

    if (message.totalChunks !== undefined && message.totalChunks > 0 && message.chunkIndex !== undefined) {
      blocks.push({
        type: 'context',
        elements: [{ type: 'mrkdwn', text: `Part ${message.chunkIndex} of ${message.totalChunks}` }],
      });
    }

    if (message.eventSummaries?.length) {
      const groups = buildBatchIaCLinkGroups(message.eventSummaries, message.contentOptions, message.notificationType);
      for (const group of groups) {
        if (blocks.length >= MAX_BLOCKS_PER_MESSAGE) break;
        const linksText = formatLinksSlackMarkdown(group.links);
        blocks.push({
          type: 'section',
          text: { type: 'mrkdwn', text: `*${escapeSlackText(group.controlId)}:* ${linksText}` },
        });
      }
    }

    const payload: SlackPayload = {
      blocks,
      ...(channelId ? { channel: channelId } : {}),
    };

    const response = await this.fetchWithRetry(webhookUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });

    if (!response.ok) {
      const body = await response.text();
      throw new ChannelApiError('Slack', response.status, body);
    }
  }

  /**
   * Append IaC download links for a single successfully-remediated finding.
   *
   * Mirrors the batch path and the email/SNS channels: instead of inlining the
   * template content, we render one download link per selected format. Returns
   * silently (emitting no block) when the finding is ineligible or no links can
   * be built (e.g. WEB_UI_URL unset).
   */
  private appendIaCLinks(
    blocks: SlackBlock[],
    event: SlackSendParams['event'],
    contentOptions: SlackSendParams['contentOptions'],
  ): void {
    const links = buildIaCDownloadLinks(event.eventId, contentOptions, event.eventType, event.remediationStatus);
    if (links.length === 0) return;
    if (blocks.length >= MAX_BLOCKS_PER_MESSAGE) {
      this.logger.warn('Reached Slack block limit, omitting IaC download links', { includedBlocks: blocks.length });
      return;
    }
    blocks.push({
      type: 'section',
      text: { type: 'mrkdwn', text: `*IaC Templates:*\n${formatLinksSlackMarkdown(links)}` },
    });
  }
}
