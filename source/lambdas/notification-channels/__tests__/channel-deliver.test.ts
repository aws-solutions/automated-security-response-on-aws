// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

process.env.EMAIL_NOTIFICATIONS_TOPIC_ARN = 'arn:aws:sns:us-east-1:123456789012:email-topic';
process.env.AWS_ACCOUNT_ID = '123456789012';
process.env.AWS_REGION = 'us-east-1';
process.env.RESOURCE_NAME_PREFIX = 'SO0111';
process.env.WEB_UI_URL = 'https://ui.example.com';

import { SNSClient, PublishCommand } from '@aws-sdk/client-sns';
import { SecretsManagerClient, GetSecretValueCommand } from '@aws-sdk/client-secrets-manager';
import { mockClient } from 'aws-sdk-client-mock';
import 'aws-sdk-client-mock-jest';
import { ChannelApiError, CredentialParsingError, InputValidationError } from '../notification-channel-errors';
import { clearSecretsCache } from '../../common/utils/secrets-utils';
import { deliver as emailDeliver, deliverBatch as emailDeliverBatch } from '../email-channel';
import { deliver as snsDeliver } from '../sns-channel';
import { deliver as jiraDeliver, deliverBatch as jiraDeliverBatch } from '../jira-channel';
import { deliver as slackDeliver, deliverBatch as slackDeliverBatch } from '../slack-channel';
import { deliver as servicenowDeliver, deliverBatch as servicenowDeliverBatch } from '../servicenow-channel';
import { createDependencies, createMessage, createContentOptions, createEvent } from './test-factories';

const snsMock = mockClient(SNSClient);
const secretsMock = mockClient(SecretsManagerClient);

/**
 * Asserts the SNS Publish payload has a Message body and returns the parsed JSON.
 *
 * Centralizes the null-guard so individual tests stay focused on behavior assertions
 * and don't need the `!` non-null assertion (forbidden by ADR 0001 — Type Safety).
 *
 * Returns `Record<string, unknown>` by default so callers must access fields
 * deliberately. Tests that drill into nested structures pass an explicit shape via
 * the generic parameter (e.g. `parsePublishedMessage<{ event: { severity: string } }>()`).
 * This keeps test bodies type-checked without forcing per-test casts.
 */
function parsePublishedMessage<T extends Record<string, unknown> = Record<string, unknown>>(callIndex = 0): T {
  const message = snsMock.commandCalls(PublishCommand)[callIndex].args[0].input.Message;
  // Throw rather than `?? ''` so a missing Message surfaces as a clear assertion
  // failure instead of a misleading JSON syntax error from parsing the empty
  // string. This also narrows `message` to `string` for the JSON.parse call,
  // avoiding the non-null-assertion pattern banned by ADR 0001 (Type Safety).
  if (message === undefined) {
    throw new Error(`Expected SNS Publish call ${callIndex} to have a Message body, but it was undefined`);
  }
  return JSON.parse(message) as T;
}

beforeEach(() => {
  snsMock.reset();
  secretsMock.reset();
  clearSecretsCache();
});

describe('email-channel deliver', () => {
  it('should publish JSON body to per-config SNS topic with formatted subject', async () => {
    snsMock.on(PublishCommand).resolves({ MessageId: 'msg-1' });
    const deps = createDependencies();
    const message = createMessage({
      type: 'email',
      recipients: [{ recipientType: 'custom', emailAddresses: ['a@b.com'] }],
    });

    await emailDeliver(message, deps);

    expect(snsMock).toHaveReceivedCommandTimes(PublishCommand, 1);
    const call = snsMock.commandCalls(PublishCommand)[0].args[0].input;
    expect(call.TopicArn).toBe('arn:aws:sns:us-east-1:123456789012:asr-notifications-config-1');
    expect(call.Subject).toContain('[ASR] CIS.1.1 High finding: Test finding');
    const body = parsePublishedMessage<{
      schemaVersion: string;
      configId: string;
      configName: string;
      event: { controlId: string; severity: string };
    }>();
    expect(body.schemaVersion).toBe('1.0');
    expect(body.configId).toBe('config-1');
    expect(body.configName).toBe('Test Config');
    expect(body.event.controlId).toBe('CIS.1.1');
    expect(body.event.severity).toBe('High');
    expect(call.MessageAttributes?.schemaVersion?.StringValue).toBe('1.0');
  });

  it('should produce the same JSON body as the SNS channel for the same message', async () => {
    snsMock.on(PublishCommand).resolves({ MessageId: 'parity-1' });
    const deps = createDependencies();
    const emailMessage = createMessage(
      { type: 'email', recipients: [{ recipientType: 'custom', emailAddresses: ['a@b.com'] }] },
      { contentOptions: { ...createContentOptions(), includeManualRemediationLink: true } },
    );

    await emailDeliver(emailMessage, deps);
    const emailBody = parsePublishedMessage();

    snsMock.reset();
    snsMock.on(PublishCommand).resolves({ MessageId: 'parity-2' });
    const snsMessage = createMessage(
      { type: 'sns', topicArn: 'arn:aws:sns:us-east-1:123456789012:any-topic' },
      { contentOptions: { ...createContentOptions(), includeManualRemediationLink: true } },
    );

    await snsDeliver(snsMessage, deps);
    const snsBody = parsePublishedMessage();

    // Bodies are channel-agnostic — same schema, configId, event, and extras.
    expect(emailBody).toEqual(snsBody);
    // Lock the schema shape so a regression in one channel can't drift both in lockstep.
    expect(emailBody).toMatchObject({
      schemaVersion: '1.0',
      configId: 'config-1',
      configName: 'Test Config',
      event: { controlId: 'CIS.1.1', severity: 'High', eventType: 'finding' },
    });
  });

  it('should include IaC download links for a successfully remediated event', async () => {
    // ARRANGE
    snsMock.on(PublishCommand).resolves({ MessageId: 'single-iac' });
    const deps = createDependencies();
    const message = createMessage(
      { type: 'email', recipients: [{ recipientType: 'custom', emailAddresses: ['a@b.com'] }] },
      {
        contentOptions: {
          ...createContentOptions(),
          includeIaCSnippet: true,
          iacFormats: ['cloudformation-yaml', 'cdk'],
        },
        event: createEvent({ eventType: 'remediation', remediationStatus: 'SUCCESS', eventId: 'evt-single-1' }),
      },
    );

    // ACT
    await emailDeliver(message, deps);

    // ASSERT
    const body = parsePublishedMessage<{ iacDownloadLinks?: { format: string; url: string }[] }>();
    expect(body.iacDownloadLinks?.map((link) => link.format)).toEqual(['cloudformation-yaml', 'cdk']);
    expect(body.iacDownloadLinks?.[0].url).toContain('/iac/evt-single-1?format=cloudformation-yaml');
  });

  it('should skip non-email channel messages', async () => {
    const deps = createDependencies();
    const message = createMessage({ type: 'slack', credentialsSecretArn: 'arn:secret' });

    await emailDeliver(message, deps);

    expect(snsMock).not.toHaveReceivedCommand(PublishCommand);
  });
});

describe('email-channel deliverBatch', () => {
  const baseBatchMessage = {
    configId: 'config-1',
    configName: 'Test Config',
    contentOptions: createContentOptions(),
    channel: { type: 'email' as const, enabled: true, recipients: [] },
    isBatch: true as const,
    startGenerationTime: '2024-01-01T00:05:30Z',
  };

  it('should publish JSON body to per-config SNS topic for finding-type batches', async () => {
    snsMock.on(PublishCommand).resolves({ MessageId: 'batch-1' });
    const deps = createDependencies();

    await emailDeliverBatch(
      { ...baseBatchMessage, notificationType: 'finding', findingCount: 3, remediationCount: 0 },
      deps,
    );

    expect(snsMock).toHaveReceivedCommandTimes(PublishCommand, 1);
    const call = snsMock.commandCalls(PublishCommand)[0].args[0].input;
    expect(call.TopicArn).toBe('arn:aws:sns:us-east-1:123456789012:asr-notifications-config-1');
    expect(call.Subject).toBe('Test Config - 3 findings');
    const body = parsePublishedMessage();
    expect(body.schemaVersion).toBe('1.0');
    expect(body.notificationType).toBe('finding');
    expect(body.findingCount).toBe(3);
    expect(body.remediationCount).toBeUndefined();
    expect(body.startGenerationTime).toBe('2024-01-01T00:05:30Z');
  });

  it('should include only the remediationCount field for remediation-type batches', async () => {
    snsMock.on(PublishCommand).resolves({ MessageId: 'batch-2' });
    const deps = createDependencies();

    await emailDeliverBatch(
      { ...baseBatchMessage, notificationType: 'remediation', findingCount: 0, remediationCount: 1 },
      deps,
    );

    const call = snsMock.commandCalls(PublishCommand)[0].args[0].input;
    expect(call.Subject).toBe('Test Config - 1 remediation');
    const body = parsePublishedMessage();
    expect(body.notificationType).toBe('remediation');
    expect(body.remediationCount).toBe(1);
    expect(body.findingCount).toBeUndefined();
  });

  it('should include exportUrl and linkAccessExpirationTime when provided', async () => {
    snsMock.on(PublishCommand).resolves({ MessageId: 'batch-4' });
    const deps = createDependencies();

    await emailDeliverBatch(
      {
        ...baseBatchMessage,
        notificationType: 'finding',
        findingCount: 1,
        remediationCount: 0,
        exportUrl: 'https://example.com/report.csv',
        linkAccessExpirationTime: '2024-01-01T01:05:30Z',
      },
      deps,
    );

    const body = parsePublishedMessage();
    expect(body.exportUrl).toBe('https://example.com/report.csv');
    expect(body.linkAccessExpirationTime).toBe('2024-01-01T01:05:30Z');
  });

  it('should include chunkIndex and totalChunks when message is part of a multi-chunk batch', async () => {
    snsMock.on(PublishCommand).resolves({ MessageId: 'batch-5' });
    const deps = createDependencies();

    await emailDeliverBatch(
      {
        ...baseBatchMessage,
        notificationType: 'finding',
        findingCount: 1,
        remediationCount: 0,
        chunkIndex: 1,
        totalChunks: 3,
      },
      deps,
    );

    const body = parsePublishedMessage();
    expect(body.chunkIndex).toBe(1);
    expect(body.totalChunks).toBe(3);
  });

  it('should include chunkIndex and totalChunks for single-chunk batches (totalChunks === 1)', async () => {
    // Locks the pre-refactor behavior: SNS subscribers used to receive chunk metadata
    // whenever totalChunks was set, including the single-chunk case. Removing it for
    // totalChunks === 1 would be a silent breaking change for any downstream consumer
    // that relies on the chunk fields existing in every batch payload.
    snsMock.on(PublishCommand).resolves({ MessageId: 'batch-single-chunk' });
    const deps = createDependencies();

    await emailDeliverBatch(
      {
        ...baseBatchMessage,
        notificationType: 'finding',
        findingCount: 1,
        remediationCount: 0,
        chunkIndex: 0,
        totalChunks: 1,
      },
      deps,
    );

    const body = parsePublishedMessage();
    expect(body.chunkIndex).toBe(0);
    expect(body.totalChunks).toBe(1);
  });

  it('should include per-control IaC download links for successfully remediated events', async () => {
    // ARRANGE
    // Batch bodies previously omitted IaC links entirely, so email and SNS
    // subscribers received none even with snippets enabled, while the Slack,
    // Jira and ServiceNow batch bodies included them.
    snsMock.on(PublishCommand).resolves({ MessageId: 'batch-iac' });
    const deps = createDependencies();

    // ACT
    await emailDeliverBatch(
      {
        ...baseBatchMessage,
        notificationType: 'remediation',
        findingCount: 0,
        remediationCount: 2,
        contentOptions: {
          ...createContentOptions(),
          includeIaCSnippet: true,
          iacFormats: ['cloudformation-yaml', 'terraform'],
        },
        eventSummaries: [
          {
            eventId: 'evt-1',
            controlId: 'S3.2',
            accountId: '123456789012',
            region: 'us-east-1',
            severity: 'High',
            resourceId: 'bucket-1',
            remediationStatus: 'SUCCESS',
          },
          {
            eventId: 'evt-2',
            controlId: 'S3.5',
            accountId: '123456789012',
            region: 'us-east-1',
            severity: 'High',
            resourceId: 'bucket-2',
            remediationStatus: 'FAILED',
          },
        ],
      },
      deps,
    );

    // ASSERT
    // Only the successful remediation is IaC-eligible, with one link per format.
    const body = parsePublishedMessage<{
      iacDownloadLinkGroups?: { controlId: string; links: { format: string; url: string }[] }[];
    }>();
    expect(body.iacDownloadLinkGroups).toHaveLength(1);
    expect(body.iacDownloadLinkGroups?.[0].controlId).toBe('S3.2');
    expect(body.iacDownloadLinkGroups?.[0].links.map((link) => link.format)).toEqual([
      'cloudformation-yaml',
      'terraform',
    ]);
    expect(body.iacDownloadLinkGroups?.[0].links[0].url).toContain('/iac/evt-1?format=cloudformation-yaml');
  });

  it('should omit iacDownloadLinkGroups when IaC snippets are not enabled', async () => {
    // ARRANGE
    snsMock.on(PublishCommand).resolves({ MessageId: 'batch-no-iac' });
    const deps = createDependencies();

    // ACT
    await emailDeliverBatch(
      {
        ...baseBatchMessage,
        notificationType: 'remediation',
        findingCount: 0,
        remediationCount: 1,
        eventSummaries: [
          {
            eventId: 'evt-1',
            controlId: 'S3.2',
            accountId: '123456789012',
            region: 'us-east-1',
            severity: 'High',
            resourceId: 'bucket-1',
            remediationStatus: 'SUCCESS',
          },
        ],
      },
      deps,
    );

    // ASSERT
    expect(parsePublishedMessage<{ iacDownloadLinkGroups?: unknown }>().iacDownloadLinkGroups).toBeUndefined();
  });

  it('should render a "0 findings" subject for empty finding batches', async () => {
    snsMock.on(PublishCommand).resolves({ MessageId: 'batch-6' });
    const deps = createDependencies();

    await emailDeliverBatch(
      { ...baseBatchMessage, notificationType: 'finding', findingCount: 0, remediationCount: 0 },
      deps,
    );

    expect(snsMock.commandCalls(PublishCommand)[0].args[0].input.Subject).toBe('Test Config - 0 findings');
  });

  it('should NOT include eventSummaries in the JSON body for email batch notifications', async () => {
    snsMock.on(PublishCommand).resolves({ MessageId: 'batch-summaries-1' });
    const deps = createDependencies();

    const summaries = [
      {
        eventId: 'arn:aws:securityhub:us-east-1:111111111111:security-control/IAM.1/finding/abc-111',
        controlId: 'IAM.1',
        accountId: '111111111111',
        region: 'us-east-1',
        severity: 'High',
        resourceId: 'arn:aws:iam::111111111111:user/alice',
      },
      {
        eventId: 'arn:aws:securityhub:eu-west-1:222222222222:security-control/S3.5/finding/abc-222',
        controlId: 'S3.5',
        accountId: '222222222222',
        region: 'eu-west-1',
        severity: 'Critical',
        resourceId: 'arn:aws:s3:::bucket-2',
        remediationStatus: 'FAILED',
        remediationMessage: 'Permission denied',
      },
    ];

    await emailDeliverBatch(
      {
        ...baseBatchMessage,
        notificationType: 'finding',
        findingCount: 2,
        remediationCount: 0,
        eventSummaries: summaries,
        exportUrl: 'https://example.com/report.csv',
      },
      deps,
    );

    const body = parsePublishedMessage();
    expect(body.eventSummaries).toBeUndefined();
    expect(body.exportUrl).toBe('https://example.com/report.csv');
  });

  it('should produce the same JSON body as the SNS channel for batches without inline summaries', async () => {
    snsMock.on(PublishCommand).resolves({ MessageId: 'batch-parity' });
    const deps = createDependencies();

    // No eventSummaries: email omits them by design, SNS includes them when present.
    // For a fair channel-parity check, exercise a batch without any summaries to
    // verify counts, exportUrl, and metadata stay aligned across channels.
    const sharedBatchFields = {
      ...baseBatchMessage,
      notificationType: 'finding' as const,
      findingCount: 2,
      remediationCount: 0,
      exportUrl: 'https://example.com/report.csv',
    };

    await emailDeliverBatch(sharedBatchFields, deps);
    const emailBody = parsePublishedMessage();

    snsMock.reset();
    snsMock.on(PublishCommand).resolves({ MessageId: 'batch-parity-2' });

    const { deliverBatch: snsDeliverBatch } = await import('../sns-channel');
    await snsDeliverBatch(
      {
        ...sharedBatchFields,
        channel: { type: 'sns', enabled: true, topicArn: 'arn:aws:sns:us-east-1:123456789012:topic' },
      },
      deps,
    );
    const snsBody = parsePublishedMessage();

    expect(emailBody).toEqual(snsBody);
  });
});

describe('sns-channel deliver', () => {
  it('should publish event JSON to the configured topic', async () => {
    snsMock.on(PublishCommand).resolves({ MessageId: 'msg-1' });
    const deps = createDependencies();
    const message = createMessage({
      type: 'sns',
      topicArn: 'arn:aws:sns:us-east-1:123456789012:any-customer-topic',
    });

    await snsDeliver(message, deps);

    expect(snsMock).toHaveReceivedCommandWith(PublishCommand, {
      TopicArn: 'arn:aws:sns:us-east-1:123456789012:any-customer-topic',
      Subject: expect.stringContaining('[ASR] CIS.1.1 High finding: Test finding'),
    });
    const call = snsMock.commandCalls(PublishCommand)[0];
    const body = parsePublishedMessage();
    expect(body.configId).toBe('config-1');
    expect(body.schemaVersion).toBe('1.0');
    expect(call.args[0].input.MessageAttributes?.schemaVersion?.StringValue).toBe('1.0');
  });

  it('should reject topic ARN from a different account', async () => {
    const deps = createDependencies();
    const message = createMessage({ type: 'sns', topicArn: 'arn:aws:sns:us-east-1:999999999999:any-topic' });

    await expect(snsDeliver(message, deps)).rejects.toThrow('belong to account 123456789012');
  });

  it('should reject a topic in a different region', async () => {
    const deps = createDependencies();
    const message = createMessage({
      type: 'sns',
      topicArn: 'arn:aws:sns:eu-west-2:123456789012:cross-region-topic',
    });

    await expect(snsDeliver(message, deps)).rejects.toThrow('must be in region');
  });

  it('should reject topic ARN from a different partition', async () => {
    const deps = createDependencies();
    const message = createMessage({
      type: 'sns',
      topicArn: 'arn:aws-us-gov:sns:us-gov-west-1:123456789012:any-topic',
    });

    await expect(snsDeliver(message, deps)).rejects.toThrow('partition');
  });

  it('should reject invalid topic ARN', async () => {
    const deps = createDependencies();
    const message = createMessage({ type: 'sns', topicArn: 'not-an-arn' });

    await expect(snsDeliver(message, deps)).rejects.toThrow('must be a valid SNS ARN');
  });

  it('should accept any topic name in the same account and partition', async () => {
    snsMock.on(PublishCommand).resolves({ MessageId: 'msg-3' });
    const deps = createDependencies();
    const message = createMessage({
      type: 'sns',
      topicArn: 'arn:aws:sns:us-east-1:123456789012:customer-owned-topic',
    });

    await snsDeliver(message, deps);

    expect(snsMock).toHaveReceivedCommandWith(PublishCommand, {
      TopicArn: 'arn:aws:sns:us-east-1:123456789012:customer-owned-topic',
    });
  });

  it('should skip non-sns channel messages', async () => {
    const deps = createDependencies();
    const message = createMessage({ type: 'email', recipients: [] });

    await snsDeliver(message, deps);

    expect(snsMock).not.toHaveReceivedCommand(PublishCommand);
  });

  it('should include manualRemediationUrl when content option is enabled', async () => {
    snsMock.on(PublishCommand).resolves({ MessageId: 'msg-extras' });
    const deps = createDependencies();
    const message = createMessage(
      { type: 'sns', topicArn: 'arn:aws:sns:us-east-1:123456789012:topic' },
      { contentOptions: { ...createContentOptions(), includeManualRemediationLink: true } },
    );

    await snsDeliver(message, deps);

    const body = parsePublishedMessage();
    expect(body.manualRemediationUrl).toContain('/findings?findingId=');
  });

  it('should route the link to /history for remediation events', async () => {
    snsMock.on(PublishCommand).resolves({ MessageId: 'msg-remediation' });
    const deps = createDependencies();
    const message = createMessage(
      { type: 'sns', topicArn: 'arn:aws:sns:us-east-1:123456789012:topic' },
      {
        event: createEvent({ eventType: 'remediation' }),
        contentOptions: { ...createContentOptions(), includeManualRemediationLink: true },
      },
    );

    await snsDeliver(message, deps);

    const body = parsePublishedMessage();
    expect(body.manualRemediationUrl).toContain('/history?findingId=');
    expect(body.manualRemediationUrl).not.toContain('/findings?findingId=');
  });

  it('should include controlSettingsUrl when content option is enabled', async () => {
    snsMock.on(PublishCommand).resolves({ MessageId: 'msg-extras' });
    const deps = createDependencies();
    const message = createMessage(
      { type: 'sns', topicArn: 'arn:aws:sns:us-east-1:123456789012:topic' },
      { contentOptions: { ...createContentOptions(), includeEnableAutomationLink: true } },
    );

    await snsDeliver(message, deps);

    const body = parsePublishedMessage();
    expect(body.controlSettingsUrl).toContain('/controls?controlId=');
  });

  it('should include remediationDeadline when content option is enabled', async () => {
    snsMock.on(PublishCommand).resolves({ MessageId: 'msg-extras' });
    const deps = createDependencies();
    const message = createMessage(
      { type: 'sns', topicArn: 'arn:aws:sns:us-east-1:123456789012:topic' },
      {
        contentOptions: {
          ...createContentOptions(),
          includeRemediationDeadline: true,
          remediationDeadlineDays: 30,
        },
      },
    );

    await snsDeliver(message, deps);

    const body = parsePublishedMessage<{
      remediationDeadline: { deadlineDate: string; daysRemaining: number };
    }>();
    expect(body.remediationDeadline).toBeDefined();
    expect(body.remediationDeadline.deadlineDate).toBeDefined();
    expect(typeof body.remediationDeadline.daysRemaining).toBe('number');
  });

  it('should not include extras when content options are disabled', async () => {
    snsMock.on(PublishCommand).resolves({ MessageId: 'msg-no-extras' });
    const deps = createDependencies();
    const message = createMessage(
      { type: 'sns', topicArn: 'arn:aws:sns:us-east-1:123456789012:topic' },
      { contentOptions: createContentOptions() },
    );

    await snsDeliver(message, deps);

    const body = parsePublishedMessage();
    expect(body.manualRemediationUrl).toBeUndefined();
    expect(body.controlSettingsUrl).toBeUndefined();
    expect(body.remediationDeadline).toBeUndefined();
  });
});

describe('jira-channel deliver', () => {
  const jiraChannel = {
    type: 'jira' as const,
    endpointUrl: 'https://jira.example.com',
    projectKey: 'PROJ',
    issueType: 'Bug',
    credentialsSecretArn: 'arn:aws:secretsmanager:us-east-1:123:secret:jira',
  };

  it('should create a JIRA issue with correct payload', async () => {
    secretsMock.on(GetSecretValueCommand).resolves({
      SecretString: JSON.stringify({ username: 'user', apiToken: 'token' }),
    });
    const fetchMock = jest.fn().mockResolvedValue({
      ok: true,
      status: 201,
      json: () => Promise.resolve({ key: 'PROJ-1', id: '1', self: 'url' }),
    });
    const deps = createDependencies(fetchMock);
    const message = createMessage(jiraChannel);

    await jiraDeliver(message, deps);

    expect(fetchMock).toHaveBeenCalledWith(
      'https://jira.example.com/rest/api/2/issue',
      expect.objectContaining({ method: 'POST' }),
    );
    const body = JSON.parse(fetchMock.mock.calls[0][1].body);
    expect(body.fields.project.key).toBe('PROJ');
    expect(body.fields.summary).toContain('[ASR] CIS.1.1 High finding: Test finding');
    expect(body.fields.description).toContain('*Configuration:* Test Config');
  });

  it('should throw ChannelApiError on non-ok response', async () => {
    secretsMock.on(GetSecretValueCommand).resolves({
      SecretString: JSON.stringify({ username: 'user', apiToken: 'token' }),
    });
    const fetchMock = jest.fn().mockResolvedValue({
      ok: false,
      status: 401,
      text: () => Promise.resolve('Unauthorized'),
    });
    const deps = createDependencies(fetchMock);

    await expect(jiraDeliver(createMessage(jiraChannel), deps)).rejects.toThrow(ChannelApiError);
  });

  it('should throw when response is missing issue key', async () => {
    secretsMock.on(GetSecretValueCommand).resolves({
      SecretString: JSON.stringify({ username: 'user', apiToken: 'token' }),
    });
    const fetchMock = jest.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: () => Promise.resolve({ noKey: true }),
    });
    const deps = createDependencies(fetchMock);

    await expect(jiraDeliver(createMessage(jiraChannel), deps)).rejects.toThrow(ChannelApiError);
  });

  it('should skip non-jira channel messages', async () => {
    const fetchMock = jest.fn();
    const deps = createDependencies(fetchMock);
    const message = createMessage({ type: 'email', recipients: [] });

    await jiraDeliver(message, deps);

    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('should throw InputValidationError when instance URL is not HTTPS', async () => {
    // ARRANGE
    const deps = createDependencies();
    const message = createMessage({ ...jiraChannel, endpointUrl: 'http://insecure.com' });

    // ACT & ASSERT
    await expect(jiraDeliver(message, deps)).rejects.toThrow(InputValidationError);
  });

  it('should throw InputValidationError when project key is invalid', async () => {
    // ARRANGE
    const deps = createDependencies();
    const message = createMessage({ ...jiraChannel, projectKey: 'bad-key' });

    // ACT & ASSERT
    await expect(jiraDeliver(message, deps)).rejects.toThrow(InputValidationError);
  });

  it('should throw InputValidationError when issue type is empty', async () => {
    // ARRANGE
    const deps = createDependencies();
    const message = createMessage({ ...jiraChannel, issueType: '' });

    // ACT & ASSERT
    await expect(jiraDeliver(message, deps)).rejects.toThrow(InputValidationError);
  });

  it('should render IaC download links in the Jira description for eligible remediations', async () => {
    secretsMock.on(GetSecretValueCommand).resolves({
      SecretString: JSON.stringify({ username: 'user', apiToken: 'token' }),
    });
    const fetchMock = jest.fn().mockResolvedValue({
      ok: true,
      status: 201,
      json: () => Promise.resolve({ key: 'PROJ-2', id: '2', self: 'url' }),
    });
    const deps = createDependencies(fetchMock);
    const message = createMessage(jiraChannel, {
      event: createEvent({ eventType: 'remediation', remediationStatus: 'SUCCESS' }),
      contentOptions: {
        ...createContentOptions(),
        includeIaCSnippet: true,
        iacFormats: ['cloudformation-yaml'],
      },
    });

    await jiraDeliver(message, deps);

    const body = JSON.parse(fetchMock.mock.calls[0][1].body);
    expect(body.fields.description).toContain('*IaC Templates:*');
    expect(body.fields.description).toContain('/iac/');
    expect(body.fields.description).toContain('format=cloudformation-yaml');
  });
});

describe('slack-channel deliver', () => {
  const slackChannel = {
    type: 'slack' as const,
    credentialsSecretArn: 'arn:aws:secretsmanager:us-east-1:123:secret:slack',
  };

  it('should post Block Kit payload to webhook URL', async () => {
    secretsMock.on(GetSecretValueCommand).resolves({
      SecretString: 'https://hooks.slack.com/services/T00/B00/xxx',
    });
    const fetchMock = jest.fn().mockResolvedValue({ ok: true, status: 200 });
    const deps = createDependencies(fetchMock);
    const message = createMessage(slackChannel);

    await slackDeliver(message, deps);

    expect(fetchMock).toHaveBeenCalledWith(
      'https://hooks.slack.com/services/T00/B00/xxx',
      expect.objectContaining({ method: 'POST' }),
    );
    const body = JSON.parse(fetchMock.mock.calls[0][1].body);
    expect(body.blocks).toBeDefined();
    expect(body.blocks[0].type).toBe('header');
  });

  it('should extract webhookUrl from JSON secret', async () => {
    secretsMock.on(GetSecretValueCommand).resolves({
      SecretString: JSON.stringify({ webhookUrl: 'https://hooks.slack.com/services/T0123ABC/B0123DEF/abcXYZ123' }),
    });
    const fetchMock = jest.fn().mockResolvedValue({ ok: true, status: 200 });
    const deps = createDependencies(fetchMock);

    await slackDeliver(createMessage(slackChannel), deps);

    expect(fetchMock).toHaveBeenCalledWith(
      'https://hooks.slack.com/services/T0123ABC/B0123DEF/abcXYZ123',
      expect.anything(),
    );
  });

  it('should include channel field when channelId is set', async () => {
    secretsMock.on(GetSecretValueCommand).resolves({
      SecretString: 'https://hooks.slack.com/services/T0123ABC/B0123DEF/abcXYZ123',
    });
    const fetchMock = jest.fn().mockResolvedValue({ ok: true, status: 200 });
    const deps = createDependencies(fetchMock);
    const message = createMessage({ ...slackChannel, channelId: 'C0123456789' });

    await slackDeliver(message, deps);

    const body = JSON.parse(fetchMock.mock.calls[0][1].body);
    expect(body.channel).toBe('C0123456789');
  });

  it('should not include channel field when channelId is absent', async () => {
    secretsMock.on(GetSecretValueCommand).resolves({
      SecretString: 'https://hooks.slack.com/services/T00/B00/xxx',
    });
    const fetchMock = jest.fn().mockResolvedValue({ ok: true, status: 200 });
    const deps = createDependencies(fetchMock);

    await slackDeliver(createMessage(slackChannel), deps);

    const body = JSON.parse(fetchMock.mock.calls[0][1].body);
    expect(body.channel).toBeUndefined();
  });

  it('should throw ChannelApiError on non-ok response', async () => {
    secretsMock.on(GetSecretValueCommand).resolves({
      SecretString: 'https://hooks.slack.com/services/T00/B00/xxx',
    });
    const fetchMock = jest.fn().mockResolvedValue({
      ok: false,
      status: 403,
      text: () => Promise.resolve('invalid_token'),
    });
    const deps = createDependencies(fetchMock);

    await expect(slackDeliver(createMessage(slackChannel), deps)).rejects.toThrow(ChannelApiError);
  });

  it('should skip non-slack channel messages', async () => {
    const fetchMock = jest.fn();
    const deps = createDependencies(fetchMock);
    const message = createMessage({ type: 'email', recipients: [] });

    await slackDeliver(message, deps);

    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('should include action links when content options are enabled', async () => {
    secretsMock.on(GetSecretValueCommand).resolves({
      SecretString: 'https://hooks.slack.com/services/T00/B00/xxx',
    });
    const fetchMock = jest.fn().mockResolvedValue({ ok: true, status: 200 });
    const deps = createDependencies(fetchMock);
    const message = createMessage(
      { type: 'slack', credentialsSecretArn: 'arn:aws:secretsmanager:us-east-1:123:secret:slack' },
      {
        contentOptions: {
          ...createContentOptions(),
          includeManualRemediationLink: true,
          includeEnableAutomationLink: true,
        },
      },
    );

    await slackDeliver(message, deps);

    const body = JSON.parse(fetchMock.mock.calls[0][1].body);
    const linkBlock = body.blocks.find(
      (b: { type: string; text?: { text: string } }) =>
        b.type === 'section' && b.text?.text?.includes('Remediation link'),
    );
    expect(linkBlock).toBeDefined();
    expect(linkBlock.text.text).toContain('Control Settings');
    expect(linkBlock.text.text).toContain('/findings?findingId=');
  });

  it('should label the deep link as "History link" and point to /history for remediation events', async () => {
    secretsMock.on(GetSecretValueCommand).resolves({
      SecretString: 'https://hooks.slack.com/services/T00/B00/xxx',
    });
    const fetchMock = jest.fn().mockResolvedValue({ ok: true, status: 200 });
    const deps = createDependencies(fetchMock);
    const message = createMessage(
      { type: 'slack', credentialsSecretArn: 'arn:aws:secretsmanager:us-east-1:123:secret:slack' },
      {
        event: createEvent({ eventType: 'remediation' }),
        contentOptions: {
          ...createContentOptions(),
          includeManualRemediationLink: true,
        },
      },
    );

    await slackDeliver(message, deps);

    const body = JSON.parse(fetchMock.mock.calls[0][1].body);
    const linkBlock = body.blocks.find(
      (b: { type: string; text?: { text: string } }) => b.type === 'section' && b.text?.text?.includes('History link'),
    );
    expect(linkBlock).toBeDefined();
    expect(linkBlock.text.text).toContain('/history?findingId=');
    expect(linkBlock.text.text).not.toContain('/findings?findingId=');
  });

  it('should include deadline context block when content option is enabled', async () => {
    secretsMock.on(GetSecretValueCommand).resolves({
      SecretString: 'https://hooks.slack.com/services/T00/B00/xxx',
    });
    const fetchMock = jest.fn().mockResolvedValue({ ok: true, status: 200 });
    const deps = createDependencies(fetchMock);
    const message = createMessage(
      { type: 'slack', credentialsSecretArn: 'arn:aws:secretsmanager:us-east-1:123:secret:slack' },
      {
        contentOptions: {
          ...createContentOptions(),
          includeRemediationDeadline: true,
          remediationDeadlineDays: 30,
        },
      },
    );

    await slackDeliver(message, deps);

    const body = JSON.parse(fetchMock.mock.calls[0][1].body);
    const contextBlock = body.blocks.find((b: { type: string }) => b.type === 'context');
    expect(contextBlock).toBeDefined();
    expect(contextBlock.elements[0].text).toContain('⏰');
  });

  it('should extract url property from JSON secret when webhookUrl is absent', async () => {
    secretsMock.on(GetSecretValueCommand).resolves({
      SecretString: JSON.stringify({ url: 'https://hooks.slack.com/services/T0123ABC/B0123DEF/abcXYZ123' }),
    });
    const fetchMock = jest.fn().mockResolvedValue({ ok: true, status: 200 });
    const deps = createDependencies(fetchMock);

    await slackDeliver(
      createMessage({ type: 'slack', credentialsSecretArn: 'arn:aws:secretsmanager:us-east-1:123:secret:slack' }),
      deps,
    );

    expect(fetchMock).toHaveBeenCalledWith(
      'https://hooks.slack.com/services/T0123ABC/B0123DEF/abcXYZ123',
      expect.anything(),
    );
  });

  it('should throw CredentialParsingError when JSON has no recognized URL key', async () => {
    secretsMock.on(GetSecretValueCommand).resolves({
      SecretString: JSON.stringify({ token: 'some-token' }),
    });
    const fetchMock = jest.fn().mockResolvedValue({ ok: true, status: 200 });
    const deps = createDependencies(fetchMock);

    await expect(
      slackDeliver(
        createMessage({ type: 'slack', credentialsSecretArn: 'arn:aws:secretsmanager:us-east-1:123:secret:slack' }),
        deps,
      ),
    ).rejects.toThrow(CredentialParsingError);
  });

  it('should throw CredentialParsingError when webhook URL is invalid', async () => {
    // ARRANGE
    secretsMock.on(GetSecretValueCommand).resolves({
      SecretString: 'https://evil.com/hook',
    });
    const fetchMock = jest.fn().mockResolvedValue({ ok: true, status: 200 });
    const deps = createDependencies(fetchMock);
    const message = createMessage(slackChannel);

    // ACT & ASSERT
    await expect(slackDeliver(message, deps)).rejects.toThrow(CredentialParsingError);
  });

  it('should throw CredentialParsingError when channel ID is invalid', async () => {
    // ARRANGE
    secretsMock.on(GetSecretValueCommand).resolves({
      SecretString: 'https://hooks.slack.com/services/T0123ABC/B0123DEF/abcXYZ123',
    });
    const fetchMock = jest.fn().mockResolvedValue({ ok: true, status: 200 });
    const deps = createDependencies(fetchMock);
    const message = createMessage({ ...slackChannel, channelId: 'invalid-id' });

    // ACT & ASSERT
    await expect(slackDeliver(message, deps)).rejects.toThrow(CredentialParsingError);
  });
});

describe('slack-channel deliverBatch', () => {
  const slackChannel = {
    type: 'slack' as const,
    credentialsSecretArn: 'arn:aws:secretsmanager:us-east-1:123:secret:slack',
  };

  const baseBatchMessage = {
    configId: 'config-1',
    configName: 'Test Config',
    contentOptions: createContentOptions(),
    channel: { enabled: true, ...slackChannel },
    isBatch: true as const,
    notificationType: 'finding' as const,
    findingCount: 3,
    remediationCount: 0,
    startGenerationTime: '2024-01-01T00:05:30Z',
  };

  it('should post batch payload to webhook URL via SlackClient.sendBatch', async () => {
    // ARRANGE
    secretsMock.on(GetSecretValueCommand).resolves({
      SecretString: 'https://hooks.slack.com/services/T0123ABC/B0123DEF/abcXYZ123',
    });
    const fetchMock = jest.fn().mockResolvedValue({ ok: true, status: 200 });
    const deps = createDependencies(fetchMock);

    // ACT
    await slackDeliverBatch(baseBatchMessage, deps);

    // ASSERT
    expect(fetchMock).toHaveBeenCalledWith(
      'https://hooks.slack.com/services/T0123ABC/B0123DEF/abcXYZ123',
      expect.objectContaining({ method: 'POST' }),
    );
    const body = JSON.parse(fetchMock.mock.calls[0][1].body);
    expect(body.blocks).toBeDefined();
    expect(body.blocks[0]).toEqual({
      type: 'header',
      text: { type: 'plain_text', text: expect.stringContaining('3') },
    });
  });

  it('should skip non-slack channel type without error', async () => {
    // ARRANGE
    const fetchMock = jest.fn();
    const deps = createDependencies(fetchMock);
    const message = {
      ...baseBatchMessage,
      channel: { enabled: true, type: 'email' as const, recipients: [] },
    };

    // ACT
    await slackDeliverBatch(message, deps);

    // ASSERT
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('should reject an invalid channel ID with CredentialParsingError', async () => {
    // ARRANGE
    secretsMock.on(GetSecretValueCommand).resolves({
      SecretString: 'https://hooks.slack.com/services/T0123ABC/B0123DEF/abcXYZ123',
    });
    const fetchMock = jest.fn().mockResolvedValue({ ok: true, status: 200 });
    const deps = createDependencies(fetchMock);
    const message = {
      ...baseBatchMessage,
      channel: { enabled: true, ...slackChannel, channelId: 'invalid-id' },
    };

    // ACT & ASSERT
    await expect(slackDeliverBatch(message, deps)).rejects.toThrow(CredentialParsingError);
  });

  it('should throw on invalid webhook URL', async () => {
    // ARRANGE
    secretsMock.on(GetSecretValueCommand).resolves({
      SecretString: 'https://evil.com/hook',
    });
    const fetchMock = jest.fn().mockResolvedValue({ ok: true, status: 200 });
    const deps = createDependencies(fetchMock);

    // ACT & ASSERT
    await expect(slackDeliverBatch(baseBatchMessage, deps)).rejects.toThrow(CredentialParsingError);
  });

  it('should throw ChannelApiError on non-2xx response', async () => {
    // ARRANGE
    secretsMock.on(GetSecretValueCommand).resolves({
      SecretString: 'https://hooks.slack.com/services/T0123ABC/B0123DEF/abcXYZ123',
    });
    const fetchMock = jest.fn().mockResolvedValue({
      ok: false,
      status: 403,
      text: () => Promise.resolve('invalid_token'),
    });
    const deps = createDependencies(fetchMock);

    // ACT & ASSERT
    await expect(slackDeliverBatch(baseBatchMessage, deps)).rejects.toThrow(ChannelApiError);
  });
});

describe('servicenow-channel deliver', () => {
  const snowChannel = {
    type: 'servicenow' as const,
    endpointUrl: 'https://instance.service-now.com',
    tableName: 'incident',
    credentialsSecretArn: 'arn:aws:secretsmanager:us-east-1:123:secret:snow',
  };

  it('should throw InputValidationError when instance URL is not HTTPS', async () => {
    // ARRANGE
    const deps = createDependencies();
    const message = createMessage({ ...snowChannel, endpointUrl: 'http://insecure.com' });

    // ACT & ASSERT
    await expect(servicenowDeliver(message, deps)).rejects.toThrow(InputValidationError);
    await expect(servicenowDeliver(message, deps)).rejects.toThrow(/HTTPS/);
  });

  it('should throw InputValidationError when instance URL has trailing slash', async () => {
    // ARRANGE
    const deps = createDependencies();
    const message = createMessage({ ...snowChannel, endpointUrl: 'https://instance.service-now.com/' });

    // ACT & ASSERT
    await expect(servicenowDeliver(message, deps)).rejects.toThrow(InputValidationError);
    await expect(servicenowDeliver(message, deps)).rejects.toThrow(/trailing/);
  });

  it('should throw InputValidationError when table name is uppercase', async () => {
    // ARRANGE
    const deps = createDependencies();
    const message = createMessage({ ...snowChannel, tableName: 'INVALID' });

    // ACT & ASSERT
    await expect(servicenowDeliver(message, deps)).rejects.toThrow(InputValidationError);
    await expect(servicenowDeliver(message, deps)).rejects.toThrow(/table name/);
  });

  it('should throw InputValidationError when table name starts with a digit', async () => {
    // ARRANGE
    const deps = createDependencies();
    const message = createMessage({ ...snowChannel, tableName: '1starts_with_digit' });

    // ACT & ASSERT
    await expect(servicenowDeliver(message, deps)).rejects.toThrow(InputValidationError);
    await expect(servicenowDeliver(message, deps)).rejects.toThrow(/table name/);
  });

  it('should create a ServiceNow record with correct payload', async () => {
    secretsMock.on(GetSecretValueCommand).resolves({
      SecretString: JSON.stringify({ username: 'admin', password: 'pass' }),
    });
    const fetchMock = jest.fn().mockResolvedValue({
      ok: true,
      status: 201,
      json: () => Promise.resolve({ result: { sys_id: 'abc', number: 'INC001' } }),
    });
    const deps = createDependencies(fetchMock);
    const message = createMessage(snowChannel);

    await servicenowDeliver(message, deps);

    expect(fetchMock).toHaveBeenCalledWith(
      'https://instance.service-now.com/api/now/table/incident',
      expect.objectContaining({ method: 'POST' }),
    );
    const body = JSON.parse(fetchMock.mock.calls[0][1].body);
    expect(body.short_description).toContain('[ASR] CIS.1.1 High finding: Test finding');
    expect(body.description).toContain('Configuration: Test Config');
    expect(body.urgency).toBe(2); // High severity maps to urgency 2
  });

  it('should throw ChannelApiError on non-ok response', async () => {
    secretsMock.on(GetSecretValueCommand).resolves({
      SecretString: JSON.stringify({ username: 'admin', password: 'pass' }),
    });
    const fetchMock = jest.fn().mockResolvedValue({
      ok: false,
      status: 500,
      text: () => Promise.resolve('Internal Server Error'),
    });
    const deps = createDependencies(fetchMock);

    await expect(servicenowDeliver(createMessage(snowChannel), deps)).rejects.toThrow(ChannelApiError);
  });

  it('should handle response without standard result shape', async () => {
    secretsMock.on(GetSecretValueCommand).resolves({
      SecretString: JSON.stringify({ username: 'admin', password: 'pass' }),
    });
    const fetchMock = jest.fn().mockResolvedValue({
      ok: true,
      status: 201,
      json: () => Promise.resolve('not-an-object'),
    });
    const deps = createDependencies(fetchMock);

    // Should not throw — logs a generic success message instead. Assert the
    // ServiceNow POST was still attempted so the "no standard result shape"
    // branch is exercised end-to-end rather than short-circuiting earlier.
    await expect(servicenowDeliver(createMessage(snowChannel), deps)).resolves.toBeUndefined();
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it('should skip non-servicenow channel messages', async () => {
    const fetchMock = jest.fn();
    const deps = createDependencies(fetchMock);
    const message = createMessage({ type: 'email', recipients: [] });

    await servicenowDeliver(message, deps);

    expect(fetchMock).not.toHaveBeenCalled();
  });
});

describe('jira-channel deliverBatch', () => {
  const jiraChannel = {
    type: 'jira' as const,
    endpointUrl: 'https://jira.example.com',
    projectKey: 'PROJ',
    issueType: 'Bug',
    credentialsSecretArn: 'arn:aws:secretsmanager:us-east-1:123:secret:jira',
  };

  const baseBatchMessage = {
    configId: 'config-1',
    configName: 'Test Config',
    contentOptions: createContentOptions(),
    channel: { enabled: true, ...jiraChannel },
    isBatch: true as const,
    notificationType: 'finding' as const,
    findingCount: 3,
    remediationCount: 0,
    startGenerationTime: '2024-01-01T00:05:30Z',
  };

  it('should create a batch issue via JiraClient.createBatchIssue', async () => {
    // ARRANGE
    secretsMock.on(GetSecretValueCommand).resolves({
      SecretString: JSON.stringify({ username: 'user', apiToken: 'token' }),
    });
    const fetchMock = jest.fn().mockResolvedValue({
      ok: true,
      status: 201,
      json: () => Promise.resolve({ key: 'PROJ-10', id: '10', self: 'url' }),
    });
    const deps = createDependencies(fetchMock);

    // ACT
    await jiraDeliverBatch(baseBatchMessage, deps);

    // ASSERT
    expect(fetchMock).toHaveBeenCalledWith(
      'https://jira.example.com/rest/api/2/issue',
      expect.objectContaining({ method: 'POST' }),
    );
    const body = JSON.parse(fetchMock.mock.calls[0][1].body);
    expect(body.fields.project.key).toBe('PROJ');
    expect(body.fields.summary).toContain('Test Config');
    expect(body.fields.summary).toMatch(/3 finding/);
    expect(body.fields.priority).toEqual({ name: 'Medium' });
  });

  it('should skip non-jira channel type without error', async () => {
    // ARRANGE
    const fetchMock = jest.fn();
    const deps = createDependencies(fetchMock);
    const message = {
      ...baseBatchMessage,
      channel: { enabled: true, type: 'email' as const, recipients: [] },
    };

    // ACT
    await jiraDeliverBatch(message, deps);

    // ASSERT
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('should throw InputValidationError when instance URL is not HTTPS', async () => {
    // ARRANGE
    const fetchMock = jest.fn();
    const deps = createDependencies(fetchMock);
    const message = {
      ...baseBatchMessage,
      channel: { enabled: true, ...jiraChannel, endpointUrl: 'http://insecure.com' },
    };

    // ACT & ASSERT
    await expect(jiraDeliverBatch(message, deps)).rejects.toThrow(InputValidationError);
  });

  it('should throw InputValidationError when project key is invalid', async () => {
    // ARRANGE
    const fetchMock = jest.fn();
    const deps = createDependencies(fetchMock);
    const message = {
      ...baseBatchMessage,
      channel: { enabled: true, ...jiraChannel, projectKey: 'bad-key' },
    };

    // ACT & ASSERT
    await expect(jiraDeliverBatch(message, deps)).rejects.toThrow(InputValidationError);
  });

  it('should throw InputValidationError when issue type is empty', async () => {
    // ARRANGE
    const fetchMock = jest.fn();
    const deps = createDependencies(fetchMock);
    const message = {
      ...baseBatchMessage,
      channel: { enabled: true, ...jiraChannel, issueType: '' },
    };

    // ACT & ASSERT
    await expect(jiraDeliverBatch(message, deps)).rejects.toThrow(InputValidationError);
  });

  it('should throw CredentialParsingError on credential retrieval failure', async () => {
    // ARRANGE
    secretsMock.on(GetSecretValueCommand).resolves({
      SecretString: JSON.stringify({ invalid: 'shape' }),
    });
    const fetchMock = jest.fn();
    const deps = createDependencies(fetchMock);

    // ACT & ASSERT
    await expect(jiraDeliverBatch(baseBatchMessage, deps)).rejects.toThrow(CredentialParsingError);
  });

  it('should throw ChannelApiError on non-2xx response', async () => {
    // ARRANGE
    secretsMock.on(GetSecretValueCommand).resolves({
      SecretString: JSON.stringify({ username: 'user', apiToken: 'token' }),
    });
    const fetchMock = jest.fn().mockResolvedValue({
      ok: false,
      status: 401,
      text: () => Promise.resolve('Unauthorized'),
    });
    const deps = createDependencies(fetchMock);

    // ACT & ASSERT
    await expect(jiraDeliverBatch(baseBatchMessage, deps)).rejects.toThrow(ChannelApiError);
  });
});

describe('servicenow-channel deliverBatch', () => {
  const snowChannel = {
    type: 'servicenow' as const,
    endpointUrl: 'https://instance.service-now.com',
    tableName: 'incident',
    credentialsSecretArn: 'arn:aws:secretsmanager:us-east-1:123:secret:snow',
  };

  const baseBatchMessage = {
    configId: 'config-1',
    configName: 'Test Config',
    contentOptions: createContentOptions(),
    channel: { enabled: true, ...snowChannel },
    isBatch: true as const,
    notificationType: 'finding' as const,
    findingCount: 3,
    remediationCount: 0,
    startGenerationTime: '2024-01-01T00:05:30Z',
  };

  it('should create a batch record via ServiceNowClient.createBatchRecord', async () => {
    // ARRANGE
    secretsMock.on(GetSecretValueCommand).resolves({
      SecretString: JSON.stringify({ username: 'admin', password: 'pass' }),
    });
    const fetchMock = jest.fn().mockResolvedValue({
      ok: true,
      status: 201,
      json: () => Promise.resolve({ result: { sys_id: 'batch-abc', number: 'INC100' } }),
    });
    const deps = createDependencies(fetchMock);

    // ACT
    await servicenowDeliverBatch(baseBatchMessage, deps);

    // ASSERT
    expect(fetchMock).toHaveBeenCalledWith(
      'https://instance.service-now.com/api/now/table/incident',
      expect.objectContaining({ method: 'POST' }),
    );
    expect(JSON.parse(fetchMock.mock.calls[0][1].body).short_description).toBe('Test Config - 3 findings');
  });

  it('should skip non-servicenow channel type without error', async () => {
    // ARRANGE
    const fetchMock = jest.fn();
    const deps = createDependencies(fetchMock);
    const message = {
      ...baseBatchMessage,
      channel: { enabled: true, type: 'email' as const, recipients: [] },
    };

    // ACT
    await servicenowDeliverBatch(message, deps);

    // ASSERT
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('should throw InputValidationError when instance URL is not HTTPS', async () => {
    // ARRANGE
    const fetchMock = jest.fn();
    const deps = createDependencies(fetchMock);
    const message = {
      ...baseBatchMessage,
      channel: { enabled: true, ...snowChannel, endpointUrl: 'http://insecure.com' },
    };

    // ACT & ASSERT
    await expect(servicenowDeliverBatch(message, deps)).rejects.toThrow(InputValidationError);
  });

  it('should throw InputValidationError when table name is invalid', async () => {
    // ARRANGE
    const fetchMock = jest.fn();
    const deps = createDependencies(fetchMock);
    const message = {
      ...baseBatchMessage,
      channel: { enabled: true, ...snowChannel, tableName: 'INVALID' },
    };

    // ACT & ASSERT
    await expect(servicenowDeliverBatch(message, deps)).rejects.toThrow(InputValidationError);
  });

  it('should throw CredentialParsingError on credential retrieval failure', async () => {
    // ARRANGE
    secretsMock.on(GetSecretValueCommand).resolves({
      SecretString: JSON.stringify({ invalid: 'shape' }),
    });
    const fetchMock = jest.fn();
    const deps = createDependencies(fetchMock);

    // ACT & ASSERT
    await expect(servicenowDeliverBatch(baseBatchMessage, deps)).rejects.toThrow(CredentialParsingError);
  });

  it('should throw ChannelApiError on non-2xx response', async () => {
    // ARRANGE
    secretsMock.on(GetSecretValueCommand).resolves({
      SecretString: JSON.stringify({ username: 'admin', password: 'pass' }),
    });
    const fetchMock = jest.fn().mockResolvedValue({
      ok: false,
      status: 500,
      text: () => Promise.resolve('Internal Server Error'),
    });
    const deps = createDependencies(fetchMock);

    // ACT & ASSERT
    await expect(servicenowDeliverBatch(baseBatchMessage, deps)).rejects.toThrow(ChannelApiError);
  });
});
