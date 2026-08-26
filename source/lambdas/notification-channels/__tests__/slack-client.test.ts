// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { SlackClient, SlackSendParams, escapeSlackText, escapeSlackCodeContent, escapeSlackUrl } from '../slack-client';
import { ChannelApiError } from '../notification-channel-errors';
import { createEvent, createContentOptions } from './test-factories';
import { Logger } from '@aws-lambda-powertools/logger';
import { SlackWebhookUrl } from '../types';
import { setupIaCTestEnvironment, teardownIaCTestEnvironment } from '../test-helpers/iacTestSetup';

function createSendParams(overrides: Partial<SlackSendParams> = {}): SlackSendParams {
  return {
    webhookUrl: 'https://hooks.slack.com/services/T0123ABC/B0123DEF/abcXYZ123' as SlackWebhookUrl,
    event: createEvent(),
    configName: 'Test Config',
    contentOptions: createContentOptions(),
    ...overrides,
  };
}

describe('SlackClient', () => {
  let fetchWithRetry: jest.Mock;
  let logger: Logger;
  let client: SlackClient;

  beforeEach(() => {
    setupIaCTestEnvironment();
    fetchWithRetry = jest.fn().mockResolvedValue({ ok: true, status: 200 });
    logger = new Logger({ logLevel: 'SILENT' });
    client = new SlackClient({ fetchWithRetry, logger });
  });

  afterEach(() => teardownIaCTestEnvironment());

  it('should build correct Block Kit structure with header, fields, and title blocks', async () => {
    // ARRANGE
    const params = createSendParams();

    // ACT
    await client.send(params);

    // ASSERT
    const body = JSON.parse(fetchWithRetry.mock.calls[0][1].body);
    expect(body.blocks[0]).toEqual({
      type: 'header',
      text: { type: 'plain_text', text: 'High finding Alert' },
    });
    expect(body.blocks[1].type).toBe('section');
    expect(body.blocks[1].fields).toHaveLength(6);
    expect(body.blocks[1].fields[0]).toEqual({ type: 'mrkdwn', text: '*Config:*\nTest Config' });
    expect(body.blocks[2]).toEqual({
      type: 'section',
      text: { type: 'mrkdwn', text: '*Title:* Test finding' },
    });
  });

  it('should include links block when includeManualRemediationLink or includeEnableAutomationLink is enabled', async () => {
    // ARRANGE
    const params = createSendParams({
      contentOptions: { ...createContentOptions(), includeManualRemediationLink: true },
    });

    // ACT
    await client.send(params);

    // ASSERT
    const body = JSON.parse(fetchWithRetry.mock.calls[0][1].body);
    const linkBlock = body.blocks.find(
      (b: { type: string; text?: { text: string } }) =>
        b.type === 'section' && b.text?.text?.includes('Remediation link'),
    );
    expect(linkBlock).toBeDefined();
    expect(linkBlock.text.text).toContain('/findings?findingId=');
  });

  it('should use pipe separator when both link types are enabled', async () => {
    // ARRANGE
    const params = createSendParams({
      contentOptions: {
        ...createContentOptions(),
        includeManualRemediationLink: true,
        includeEnableAutomationLink: true,
      },
    });

    // ACT
    await client.send(params);

    // ASSERT
    const body = JSON.parse(fetchWithRetry.mock.calls[0][1].body);
    const linkBlock = body.blocks.find(
      (b: { type: string; text?: { text: string } }) =>
        b.type === 'section' && b.text?.text?.includes('Remediation link'),
    );
    expect(linkBlock.text.text).toContain(' | ');
    expect(linkBlock.text.text).toContain('Control Settings');
  });

  it('should omit links block when both link options are disabled', async () => {
    // ARRANGE
    const params = createSendParams();

    // ACT
    await client.send(params);

    // ASSERT
    const body = JSON.parse(fetchWithRetry.mock.calls[0][1].body);
    const linkBlock = body.blocks.find(
      (b: { type: string; text?: { text: string } }) =>
        b.type === 'section' && b.text?.text?.includes('Remediation link'),
    );
    expect(linkBlock).toBeUndefined();
  });

  it('should include deadline context block when includeRemediationDeadline is enabled with remediationDeadlineDays', async () => {
    // ARRANGE
    const params = createSendParams({
      contentOptions: {
        ...createContentOptions(),
        includeRemediationDeadline: true,
        remediationDeadlineDays: 30,
      },
    });

    // ACT
    await client.send(params);

    // ASSERT
    const body = JSON.parse(fetchWithRetry.mock.calls[0][1].body);
    const contextBlock = body.blocks.find((b: { type: string }) => b.type === 'context');
    expect(contextBlock).toBeDefined();
    expect(contextBlock.elements[0].text).toContain('⏰');
  });

  it('should omit deadline block when includeRemediationDeadline is disabled', async () => {
    // ARRANGE
    const params = createSendParams();

    // ACT
    await client.send(params);

    // ASSERT
    const body = JSON.parse(fetchWithRetry.mock.calls[0][1].body);
    const contextBlock = body.blocks.find((b: { type: string }) => b.type === 'context');
    expect(contextBlock).toBeUndefined();
  });

  it('should render IaC download links for eligible remediation events', async () => {
    // ARRANGE
    const params = createSendParams({
      event: createEvent({ eventType: 'remediation', remediationStatus: 'SUCCESS' }),
      contentOptions: {
        ...createContentOptions(),
        includeIaCSnippet: true,
        iacFormats: ['cloudformation-yaml', 'terraform'],
      },
    });

    // ACT
    await client.send(params);

    // ASSERT
    const body = JSON.parse(fetchWithRetry.mock.calls[0][1].body);
    const iacBlock = body.blocks.find(
      (b: { type: string; text?: { text: string } }) => b.type === 'section' && b.text?.text?.includes('IaC Templates'),
    );
    expect(iacBlock).toBeDefined();
    expect(iacBlock.text.text).toContain('/iac/');
    expect(iacBlock.text.text).toContain('format=cloudformation-yaml');
    expect(iacBlock.text.text).toContain('format=terraform');
  });

  it('should omit IaC links for non-remediation (finding) events', async () => {
    // ARRANGE
    const params = createSendParams({
      event: createEvent({ eventType: 'finding' }),
      contentOptions: { ...createContentOptions(), includeIaCSnippet: true, iacFormats: ['cloudformation-yaml'] },
    });

    // ACT
    await client.send(params);

    // ASSERT
    const body = JSON.parse(fetchWithRetry.mock.calls[0][1].body);
    const iacBlock = body.blocks.find(
      (b: { type: string; text?: { text: string } }) => b.type === 'section' && b.text?.text?.includes('IaC Templates'),
    );
    expect(iacBlock).toBeUndefined();
  });

  it('should include channel field in payload when channelId is provided', async () => {
    // ARRANGE
    const params = createSendParams({ channelId: 'C0123456789' });

    // ACT
    await client.send(params);

    // ASSERT
    const body = JSON.parse(fetchWithRetry.mock.calls[0][1].body);
    expect(body.channel).toBe('C0123456789');
  });

  it('should omit channel field when channelId is undefined', async () => {
    // ARRANGE
    const params = createSendParams({ channelId: undefined });

    // ACT
    await client.send(params);

    // ASSERT
    const body = JSON.parse(fetchWithRetry.mock.calls[0][1].body);
    expect(body.channel).toBeUndefined();
  });

  it('should include Description section when findingDescription is present', async () => {
    // ARRANGE
    const params = createSendParams({
      event: createEvent({ findingDescription: 'S3 bucket allows public access' }),
    });

    // ACT
    await client.send(params);

    // ASSERT
    const body = JSON.parse(fetchWithRetry.mock.calls[0][1].body);
    const findingDescBlock = body.blocks.find(
      (b: { type: string; text?: { text: string } }) => b.type === 'section' && b.text?.text?.includes('Description'),
    );
    expect(findingDescBlock).toBeDefined();
    expect(findingDescBlock.text.text).toContain('S3 bucket allows public access');
  });

  it('should omit Finding Description section when findingDescription is absent', async () => {
    // ARRANGE
    const params = createSendParams();

    // ACT
    await client.send(params);

    // ASSERT
    const body = JSON.parse(fetchWithRetry.mock.calls[0][1].body);
    const findingDescBlock = body.blocks.find(
      (b: { type: string; text?: { text: string } }) => b.type === 'section' && b.text?.text?.includes('Description'),
    );
    expect(findingDescBlock).toBeUndefined();
  });

  it('should throw ChannelApiError on non-2xx response', async () => {
    // ARRANGE
    fetchWithRetry.mockResolvedValue({
      ok: false,
      status: 403,
      text: () => Promise.resolve('invalid_token'),
    });
    const params = createSendParams();

    // ACT & ASSERT
    await expect(client.send(params)).rejects.toThrow(ChannelApiError);
  });

  it('should resolve successfully on 2xx response', async () => {
    // ARRANGE
    fetchWithRetry.mockResolvedValue({ ok: true, status: 200 });
    const params = createSendParams();

    // ACT & ASSERT
    await expect(client.send(params)).resolves.toBeUndefined();
  });
});

describe('escapeSlackText', () => {
  it('encodes &, <, > as HTML entities and suppresses emoji shortcodes', () => {
    // Arrange
    const input = 'a & b < c > d :wave: hello :thumbsup:';

    // Act
    const result = escapeSlackText(input);

    // Assert
    expect(result).toBe('a &amp; b &lt; c &gt; d :\u200Bwave: hello :\u200Bthumbsup:');
  });

  it('does not escape timestamp-like patterns without letters', () => {
    // Arrange
    const input = 'Time is 12:30:00';

    // Act
    const result = escapeSlackText(input);

    // Assert
    expect(result).toBe('Time is 12:30:00');
  });
});

describe('escapeSlackCodeContent', () => {
  it('encodes &, <, > but does NOT inject zero-width spaces into ARN patterns', () => {
    // Arrange
    const arnWithHtml = 'arn:aws:iam::123456789012:role/MyRole & <tag>';

    // Act
    const result = escapeSlackCodeContent(arnWithHtml);

    // Assert
    expect(result).toBe('arn:aws:iam::123456789012:role/MyRole &amp; &lt;tag&gt;');
    expect(result).not.toContain('\u200B');
  });

  it('preserves ARNs with multiple emoji-like segments unchanged', () => {
    // Arrange
    const arn = 'arn:aws:lambda:us-east-1:123456789012:function:my-function';

    // Act
    const result = escapeSlackCodeContent(arn);

    // Assert
    expect(result).toBe(arn);
    expect(result).not.toContain('\u200B');
  });

  it('preserves S3 ARN and CloudFormation intrinsics', () => {
    // Arrange
    const cfnSnippet = '!Sub "arn:aws:s3:::${BucketName}/*"';

    // Act
    const result = escapeSlackCodeContent(cfnSnippet);

    // Assert
    expect(result).not.toContain('\u200B');
  });
});

describe('escapeSlackUrl', () => {
  it('encodes only & and does not corrupt URL paths matching emoji patterns', () => {
    // Arrange
    const url = 'https://bucket.s3.amazonaws.com/path:aws:segment/file.csv?a=1&b=2';

    // Act
    const result = escapeSlackUrl(url);

    // Assert
    expect(result).toBe('https://bucket.s3.amazonaws.com/path:aws:segment/file.csv?a=1&amp;b=2');
    expect(result).not.toContain('\u200B');
    expect(result).not.toContain('&lt;');
    expect(result).not.toContain('&gt;');
  });

  it('returns URL unchanged when no & is present', () => {
    // Arrange
    const url = 'https://example.com/simple/path.csv';

    // Act
    const result = escapeSlackUrl(url);

    // Assert
    expect(result).toBe(url);
  });
});
