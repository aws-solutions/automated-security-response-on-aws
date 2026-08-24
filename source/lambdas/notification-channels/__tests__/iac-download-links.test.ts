// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { ContentOptions } from '@asr/data-models';
import { buildIaCDownloadLinks, isIaCEligible } from '../iac-download-links';
import { resetChannelLambdaEnvironmentCache } from '../channelLambdaEnvironment';

const WEB_UI_URL = 'https://d1234abcd.cloudfront.net';

function setEnv(): void {
  resetChannelLambdaEnvironmentCache();
  process.env.SOLUTION_VERSION = 'v1.0.0';
  process.env.SOLUTION_TRADEMARKEDNAME = 'ASR-Test';
  process.env.POWERTOOLS_LOG_LEVEL = 'INFO';
  process.env.AWS_PARTITION = 'aws';
  process.env.STACK_ID = 'test-stack-id';
  process.env.RESOURCE_NAME_PREFIX = 'SO0111';
  process.env.WEB_UI_URL = WEB_UI_URL;
  process.env.IAC_TEMPLATES_BUCKET = 'test-iac-templates-bucket';
}

function makeContentOptions(
  overrides: Partial<Pick<ContentOptions, 'includeIaCSnippet' | 'iacFormats'>> = {},
): ContentOptions {
  return {
    includeManualRemediationLink: false,
    includeRemediationDeadline: false,
    enforceDeadline: false,
    includeIaCSnippet: true,
    iacFormats: ['cloudformation-yaml', 'terraform'],
    includeEnableAutomationLink: false,
    ...overrides,
  };
}

describe('isIaCEligible', () => {
  it('returns true only for successful remediation events', () => {
    expect(isIaCEligible('remediation', 'SUCCESS')).toBe(true);
    expect(isIaCEligible('remediation', 'Success')).toBe(true);
  });

  it('returns false for non-success remediation statuses', () => {
    expect(isIaCEligible('remediation', 'FAILED')).toBe(false);
    expect(isIaCEligible('remediation', 'IN_PROGRESS')).toBe(false);
    expect(isIaCEligible('remediation', 'QUEUED')).toBe(false);
    expect(isIaCEligible('remediation', 'ROLLBACK_SUCCESS')).toBe(false);
  });

  it('returns false for a missing status (treated as failure)', () => {
    expect(isIaCEligible('remediation', undefined)).toBe(false);
  });

  it('returns false for finding events regardless of status', () => {
    expect(isIaCEligible('finding', 'SUCCESS')).toBe(false);
    expect(isIaCEligible('finding', undefined)).toBe(false);
  });

  it('returns false when eventType is undefined', () => {
    expect(isIaCEligible(undefined, 'SUCCESS')).toBe(false);
  });
});

describe('buildIaCDownloadLinks', () => {
  beforeEach(() => {
    setEnv();
  });

  it('builds one link per selected format for a successful remediation', () => {
    const links = buildIaCDownloadLinks('finding-1', makeContentOptions(), 'remediation', 'SUCCESS');

    expect(links).toEqual([
      { format: 'cloudformation-yaml', url: `${WEB_UI_URL}/iac/finding-1?format=cloudformation-yaml` },
      { format: 'terraform', url: `${WEB_UI_URL}/iac/finding-1?format=terraform` },
    ]);
  });

  it('returns [] for a non-success remediation status', () => {
    expect(buildIaCDownloadLinks('finding-1', makeContentOptions(), 'remediation', 'FAILED')).toEqual([]);
    expect(buildIaCDownloadLinks('finding-1', makeContentOptions(), 'remediation', 'IN_PROGRESS')).toEqual([]);
  });

  it('returns [] when the remediation status is missing', () => {
    expect(buildIaCDownloadLinks('finding-1', makeContentOptions(), 'remediation', undefined)).toEqual([]);
  });

  it('returns [] for finding events', () => {
    expect(buildIaCDownloadLinks('finding-1', makeContentOptions(), 'finding', 'SUCCESS')).toEqual([]);
  });

  it('returns [] when IaC snippets are not enabled even for a successful remediation', () => {
    const links = buildIaCDownloadLinks(
      'finding-1',
      makeContentOptions({ includeIaCSnippet: false }),
      'remediation',
      'SUCCESS',
    );
    expect(links).toEqual([]);
  });

  it('returns [] when no formats are selected', () => {
    const links = buildIaCDownloadLinks('finding-1', makeContentOptions({ iacFormats: [] }), 'remediation', 'SUCCESS');
    expect(links).toEqual([]);
  });

  it('URL-encodes the finding ID', () => {
    const findingId = 'arn:aws:securityhub:us-east-1:123:finding/abc';
    const links = buildIaCDownloadLinks(
      findingId,
      makeContentOptions({ iacFormats: ['cdk'] }),
      'remediation',
      'SUCCESS',
    );
    expect(links[0].url).toBe(`${WEB_UI_URL}/iac/${encodeURIComponent(findingId)}?format=cdk`);
  });

  it('URL-encodes the format query parameter', () => {
    // Future-proofing: today's IaCFormat values are URL-safe slugs, but the helper
    // should still encode in case a new format introduces special characters.
    const findingId = 'finding-1';
    const links = buildIaCDownloadLinks(findingId, makeContentOptions(), 'remediation', 'SUCCESS');
    expect(links[0].url).toContain(`?format=${encodeURIComponent('cloudformation-yaml')}`);
  });

  it('returns [] when WEB_UI_URL is empty', () => {
    setEnv();
    process.env.WEB_UI_URL = '';
    resetChannelLambdaEnvironmentCache();

    const links = buildIaCDownloadLinks('finding-1', makeContentOptions(), 'remediation', 'SUCCESS');

    expect(links).toEqual([]);
  });
});
