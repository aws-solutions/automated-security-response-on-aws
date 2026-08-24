// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { IaCDownloadLink, getFormatLabel } from './iac-download-links';

/** A function that renders a single link as a string for a specific channel. */
type LinkRenderer = (label: string, url: string) => string;

/** Strip characters that would break or smuggle markup in link syntax. */
function stripLinkDelimiters(value: string, chars: RegExp): string {
  return value.replace(chars, '');
}

/**
 * Strip JIRA wiki-markup structural characters from a value so it cannot alter
 * rendering or smuggle content when interpolated into a wiki-markup string.
 * Removes macro/brace (`{`,`}`), link/table (`[`,`]`,`|`) and image-embed (`!`)
 * characters; stripping `{`/`}` also neutralizes `{code}`/`{noformat}` macros.
 * Inline-emphasis characters (`*`,`_`,`-`,`+`,`^`,`~`) are intentionally kept —
 * they only cause cosmetic styling and appear in legitimate identifiers. Pure
 * and idempotent. Follows the strip-not-escape convention of stripLinkDelimiters.
 */
export function stripJiraWikiMarkup(value: string): string {
  return value.replace(/[{}[\]|!]/g, '');
}

/**
 * Generic formatter — maps links through a renderer and joins with a separator.
 * All channel-specific formatters delegate to this.
 */
function formatLinks(links: IaCDownloadLink[], render: LinkRenderer, separator: string): string {
  if (links.length === 0) return '';
  return links.map((link) => render(`${getFormatLabel(link.format)} Template`, link.url)).join(separator);
}

/** Slack mrkdwn link syntax. */
export const formatLinksSlackMarkdown = (links: IaCDownloadLink[]): string =>
  formatLinks(
    links,
    (label, url) => `<${stripLinkDelimiters(url, /[|>]/g)}|${stripLinkDelimiters(label, /[|>]/g)}>`,
    '\n',
  );

/** Plain-text URLs prefixed with format name (SNS, ServiceNow). */
export const formatLinksPlainText = (links: IaCDownloadLink[]): string =>
  formatLinks(links, (label, url) => `${label}: ${url}`, '\n');

/** JIRA wiki markup link syntax. */
export const formatLinksJiraWiki = (links: IaCDownloadLink[]): string =>
  formatLinks(
    links,
    (label, url) => `[${stripLinkDelimiters(label, /[|\]]/g)}|${stripLinkDelimiters(url, /[|\]]/g)}]`,
    '\n',
  );
