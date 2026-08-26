// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { IaCDownloadLink } from '../iac-download-links';
import {
  formatLinksSlackMarkdown,
  formatLinksPlainText,
  formatLinksJiraWiki,
  stripJiraWikiMarkup,
} from '../iac-link-formatters';

const sampleLinks: IaCDownloadLink[] = [
  { format: 'cloudformation-yaml', url: 'https://example.com/iac/f1?format=cloudformation-yaml' },
  { format: 'terraform', url: 'https://example.com/iac/f1?format=terraform' },
];

describe('formatLinksSlackMarkdown', () => {
  it('returns empty string for empty links', () => {
    expect(formatLinksSlackMarkdown([])).toBe('');
  });

  it('renders Slack mrkdwn links joined by newlines', () => {
    const result = formatLinksSlackMarkdown(sampleLinks);
    expect(result).toBe(
      '<https://example.com/iac/f1?format=cloudformation-yaml|CloudFormation (YAML) Template>\n' +
        '<https://example.com/iac/f1?format=terraform|Terraform Template>',
    );
  });

  it('strips pipe and closing angle bracket from URLs', () => {
    const links: IaCDownloadLink[] = [{ format: 'terraform', url: 'https://x.com/a|b>c' }];
    const result = formatLinksSlackMarkdown(links);
    expect(result).toBe('<https://x.com/abc|Terraform Template>');
  });
});

describe('formatLinksPlainText', () => {
  it('returns empty string for empty links', () => {
    expect(formatLinksPlainText([])).toBe('');
  });

  it('renders label: url pairs joined by newlines', () => {
    const result = formatLinksPlainText(sampleLinks);
    expect(result).toBe(
      'CloudFormation (YAML) Template: https://example.com/iac/f1?format=cloudformation-yaml\n' +
        'Terraform Template: https://example.com/iac/f1?format=terraform',
    );
  });
});

describe('formatLinksJiraWiki', () => {
  it('returns empty string for empty links', () => {
    expect(formatLinksJiraWiki([])).toBe('');
  });

  it('renders Jira wiki markup links joined by newlines', () => {
    const result = formatLinksJiraWiki(sampleLinks);
    expect(result).toBe(
      '[CloudFormation (YAML) Template|https://example.com/iac/f1?format=cloudformation-yaml]\n' +
        '[Terraform Template|https://example.com/iac/f1?format=terraform]',
    );
  });

  it('strips pipe and bracket characters from URLs', () => {
    const links: IaCDownloadLink[] = [{ format: 'cdk', url: 'https://x.com/a|b]c' }];
    const result = formatLinksJiraWiki(links);
    expect(result).toBe('[CDK (TypeScript) Template|https://x.com/abc]');
  });
});

describe('stripJiraWikiMarkup', () => {
  it('strips macro/brace, link/table, and image-embed characters', () => {
    // ARRANGE / ACT / ASSERT — neutralizes [link|url], {code}/{noformat} macros, and !image! embeds.
    expect(stripJiraWikiMarkup('[evil|http://x]')).toBe('evilhttp://x');
    expect(stripJiraWikiMarkup('{code}rm -rf{code}')).toBe('coderm -rfcode');
    expect(stripJiraWikiMarkup('!http://x/p.png!')).toBe('http://x/p.png');
  });

  it('preserves inline-emphasis characters common in identifiers', () => {
    // ARRANGE / ACT / ASSERT — *,_,-,+,^,~ only cause cosmetic styling and appear in real values.
    expect(stripJiraWikiMarkup('S3.1')).toBe('S3.1');
    expect(stripJiraWikiMarkup('us-east-1')).toBe('us-east-1');
    expect(stripJiraWikiMarkup('a_b*c-d+e^f~g')).toBe('a_b*c-d+e^f~g');
  });

  it('is idempotent', () => {
    // ARRANGE
    const input = '[x]{y}|z!';
    // ACT
    const once = stripJiraWikiMarkup(input);
    // ASSERT
    expect(stripJiraWikiMarkup(once)).toBe(once);
  });
});
