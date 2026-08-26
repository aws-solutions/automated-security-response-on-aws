// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { IaCFormat, ContentOptions, NotificationType, normalizeRemediationStatus } from '@asr/data-models';
import { channelLambdaEnvironment } from './channelLambdaEnvironment';
import { getLogger } from '../common/utils/logger';

const logger = getLogger('iac-download-links');

/**
 * Represents a download link for an IaC template in a specific format.
 */
export interface IaCDownloadLink {
  readonly format: IaCFormat;
  readonly url: string;
}

/**
 * IaC remediation code only makes sense for findings that were successfully
 * remediated — it shows the customer how to codify the fix that already
 * happened. We therefore only surface IaC (download links and inline snippets)
 * for remediation events whose status normalizes to 'Success'.
 *
 * Finding events, in-progress/failed/rolled-back remediations, and events with a
 * missing status are all treated as ineligible (normalizeRemediationStatus maps
 * an absent status to 'Failed', so the default is safe).
 */
export function isIaCEligible(eventType: NotificationType | undefined, remediationStatus?: string): boolean {
  if (eventType !== 'remediation') return false;
  return normalizeRemediationStatus(remediationStatus) === 'Success';
}

/**
 * Canonical builder for the IaC download URL. This is the single source of
 * truth for the `/iac/{findingId}?format=...` URL shape, used by both the
 * notification-channel download links and the batch CSV exports.
 */
export function buildIaCDownloadUrl(baseUrl: string, findingId: string, format: IaCFormat): string {
  return `${baseUrl}/iac/${encodeURIComponent(findingId)}?format=${encodeURIComponent(format)}`;
}

/** The four IaC download URLs emitted as columns in the batch CSV export. */
export interface IaCCsvUrls {
  readonly iacCloudformationYaml: string;
  readonly iacCloudformationJson: string;
  readonly iacTerraform: string;
  readonly iacCdk: string;
}

/**
 * Build the IaC download URLs for the batch CSV export. Unlike
 * buildIaCDownloadLinks (which filters by the user's selected iacFormats), the
 * CSV export always emits all four formats as dedicated columns. Delegates to
 * buildIaCDownloadUrl so the URL format stays defined in one place.
 */
export function buildIaCCsvUrls(baseUrl: string, findingId: string): IaCCsvUrls {
  return {
    iacCloudformationYaml: buildIaCDownloadUrl(baseUrl, findingId, 'cloudformation-yaml'),
    iacCloudformationJson: buildIaCDownloadUrl(baseUrl, findingId, 'cloudformation-json'),
    iacTerraform: buildIaCDownloadUrl(baseUrl, findingId, 'terraform'),
    iacCdk: buildIaCDownloadUrl(baseUrl, findingId, 'cdk'),
  };
}

/** Returns a human-readable label for a given IaC format. */
export function getFormatLabel(format: IaCFormat): string {
  switch (format) {
    case 'cloudformation-yaml':
      return 'CloudFormation (YAML)';
    case 'cloudformation-json':
      return 'CloudFormation (JSON)';
    case 'terraform':
      return 'Terraform';
    case 'cdk':
      return 'CDK (TypeScript)';
  }
}

/**
 * Reads WEB_UI_URL from the channel Lambda environment, returning undefined
 * rather than throwing when it is unset/empty or the environment cannot be
 * resolved. Lets callers keep `baseUrl` as a `const`.
 */
function getWebUiBaseUrlOrUndefined(): string | undefined {
  try {
    return channelLambdaEnvironment().WEB_UI_URL || undefined;
  } catch {
    return undefined;
  }
}

/**
 * Builds download link URLs for each selected IaC format.
 * Only included for remediation notifications that succeeded — see isIaCEligible.
 * If a control doesn't have a template, the download page shows a friendly message.
 *
 * Returns [] (and logs a warning) when WEB_UI_URL is unset, to avoid shipping
 * relative `/iac/...` URLs to customers in Slack/Jira/email.
 */
export function buildIaCDownloadLinks(
  findingId: string,
  contentOptions: ContentOptions,
  eventType?: NotificationType,
  remediationStatus?: string,
): IaCDownloadLink[] {
  if (!isIaCEligible(eventType, remediationStatus)) return [];
  if (!contentOptions.includeIaCSnippet || !contentOptions.iacFormats?.length) return [];

  // WEB_UI_URL is a required env var, but treat an unset/empty value as a soft
  // failure here: without it we can only build relative `/iac/...` URLs, which
  // are useless in an external notification. Warn and skip rather than throw so
  // the rest of the notification still delivers.
  const baseUrl = getWebUiBaseUrlOrUndefined();
  if (!baseUrl) {
    logger.warn('Skipping IaC download links: WEB_UI_URL is not configured');
    return [];
  }

  return contentOptions.iacFormats.map((format) => ({
    format,
    url: buildIaCDownloadUrl(baseUrl, findingId, format),
  }));
}

/** A batch event summary paired with its (non-empty) IaC download links. */
export interface BatchIaCLinkGroup {
  readonly controlId: string;
  readonly links: IaCDownloadLink[];
}

/**
 * Build IaC download links for each event summary in a batch, returning only
 * the summaries that have eligible links. Shared by the Jira, ServiceNow, and
 * Slack batch adapters so the iterate-and-filter logic lives in one place;
 * each adapter handles only channel-specific rendering of the returned groups.
 */
export function buildBatchIaCLinkGroups(
  eventSummaries: ReadonlyArray<{ eventId?: string; controlId: string; remediationStatus?: string }> | undefined,
  contentOptions: ContentOptions,
  notificationType: NotificationType,
): BatchIaCLinkGroup[] {
  if (!eventSummaries?.length) return [];
  return eventSummaries
    .map((summary) => ({
      controlId: summary.controlId,
      // Older messages may lack eventId; without it we can't build a link, so
      // emit no links for that summary and let the filter below drop it.
      links: summary.eventId
        ? buildIaCDownloadLinks(summary.eventId, contentOptions, notificationType, summary.remediationStatus)
        : [],
    }))
    .filter((group) => group.links.length > 0);
}
