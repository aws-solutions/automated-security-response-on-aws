// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { JiraClient } from '../jira-client';
import { ChannelApiError } from '../notification-channel-errors';
import { BatchChannelFanoutMessage, BatchEventSummary, JiraCredentials } from '../types';
import { Logger } from '@aws-lambda-powertools/logger';
import { setupIaCTestEnvironment, teardownIaCTestEnvironment } from '../test-helpers/iacTestSetup';

function createBatchMessage(overrides: Partial<BatchChannelFanoutMessage> = {}): BatchChannelFanoutMessage {
  const defaults: BatchChannelFanoutMessage = {
    configId: 'config-1',
    configName: 'Production Alerts',
    notificationType: 'finding',
    contentOptions: {
      includeManualRemediationLink: false,
      includeRemediationDeadline: false,
      enforceDeadline: false,
      includeIaCSnippet: false,
      includeEnableAutomationLink: false,
    },
    channel: {
      type: 'jira',
      enabled: true,
      credentialsSecretArn: 'arn:aws:secretsmanager:us-east-1:123456789012:secret:jira-creds',
      endpointUrl: 'https://company.atlassian.net',
      projectKey: 'SEC',
      issueType: 'Task',
    },
    isBatch: true,
    findingCount: 5,
    remediationCount: 0,
    startGenerationTime: '2024-06-15T10:30:00Z',
    eventSummaries: [],
  };
  return { ...defaults, ...overrides };
}

const defaultCredentials: JiraCredentials = { username: 'user@company.com', apiToken: 'test-token-123' };

describe('JiraClient.createBatchIssue', () => {
  let fetchWithRetry: jest.Mock;
  let logger: Logger;
  let client: JiraClient;

  beforeEach(() => {
    fetchWithRetry = jest.fn().mockResolvedValue({
      ok: true,
      status: 201,
      json: () =>
        Promise.resolve({ key: 'SEC-100', id: '10100', self: 'https://company.atlassian.net/rest/api/2/issue/10100' }),
    });
    logger = new Logger({ logLevel: 'SILENT' });
    client = new JiraClient({ fetchWithRetry, logger });
  });

  function getPostedBody(): Record<string, unknown> {
    return JSON.parse(fetchWithRetry.mock.calls[0][1].body);
  }

  async function callCreateBatchIssue(
    message: BatchChannelFanoutMessage,
    overrides: Partial<Omit<Parameters<typeof client.createBatchIssue>[0], 'message'>> = {},
  ) {
    return client.createBatchIssue({
      instanceUrl: 'https://company.atlassian.net',
      projectKey: 'SEC',
      issueType: 'Task',
      credentials: defaultCredentials,
      message,
      ...overrides,
    });
  }

  describe('summary format', () => {
    it('should set summary using buildBatchSubject pattern "{configName} - {count} {noun(s)}"', async () => {
      // ARRANGE
      const message = createBatchMessage({ configName: 'MyConfig', findingCount: 5, notificationType: 'finding' });

      // ACT
      await callCreateBatchIssue(message);

      // ASSERT
      const body = getPostedBody();
      const fields = body.fields as Record<string, unknown>;
      expect(fields.summary).toBe('MyConfig - 5 findings');
    });

    it('should use singular noun when count is 1', async () => {
      // ARRANGE
      const message = createBatchMessage({ configName: 'MyConfig', findingCount: 1, notificationType: 'finding' });

      // ACT
      await callCreateBatchIssue(message);

      // ASSERT
      const body = getPostedBody();
      const fields = body.fields as Record<string, unknown>;
      expect(fields.summary).toBe('MyConfig - 1 finding');
    });

    it('should truncate summary to max 255 characters', async () => {
      // ARRANGE
      const longConfigName = 'A'.repeat(300);
      const message = createBatchMessage({ configName: longConfigName, findingCount: 3 });

      // ACT
      await callCreateBatchIssue(message);

      // ASSERT
      const body = getPostedBody();
      const fields = body.fields as Record<string, unknown>;
      expect((fields.summary as string).length).toBeLessThanOrEqual(255);
    });
  });

  describe('description content', () => {
    it('should include batch metadata (notification type, count, generation time) in description', async () => {
      // ARRANGE
      const message = createBatchMessage({
        notificationType: 'finding',
        findingCount: 7,
        startGenerationTime: '2024-06-15T10:30:00Z',
      });

      // ACT
      await callCreateBatchIssue(message);

      // ASSERT
      const body = getPostedBody();
      const fields = body.fields as Record<string, unknown>;
      const description = fields.description as string;
      expect(description).toContain('7 findings');
      expect(description).toContain('2024-06-15T10:30:00Z');
    });

    it('should use remediationCount for remediation type messages', async () => {
      // ARRANGE
      const message = createBatchMessage({
        notificationType: 'remediation',
        findingCount: 0,
        remediationCount: 4,
        startGenerationTime: '2024-06-15T10:30:00Z',
      });

      // ACT
      await callCreateBatchIssue(message);

      // ASSERT
      const body = getPostedBody();
      const fields = body.fields as Record<string, unknown>;
      const description = fields.description as string;
      expect(description).toContain('4 remediations');
    });

    it('should include export URL in description when present', async () => {
      // ARRANGE
      const message = createBatchMessage({
        exportUrl: 'https://s3.amazonaws.com/bucket/export.csv',
      });

      // ACT
      await callCreateBatchIssue(message);

      // ASSERT
      const body = getPostedBody();
      const fields = body.fields as Record<string, unknown>;
      const description = fields.description as string;
      expect(description).toContain('https://s3.amazonaws.com/bucket/export.csv');
    });

    it('should NOT include event summaries in description', async () => {
      // ARRANGE
      const summaries: BatchEventSummary[] = [
        {
          eventId: 'arn:aws:securityhub:us-east-1:123456789012:security-control/CIS.1.1/finding/abc-1',
          controlId: 'CIS.1.1',
          accountId: '123456789012',
          region: 'us-east-1',
          severity: 'High',
          resourceId: 'arn:aws:iam::123456789012:user/test-user',
        },
        {
          eventId: 'arn:aws:securityhub:us-west-2:123456789012:security-control/CIS.2.1/finding/abc-2',
          controlId: 'CIS.2.1',
          accountId: '123456789012',
          region: 'us-west-2',
          severity: 'Critical',
          resourceId: 'arn:aws:s3:::my-bucket',
        },
      ];
      const message = createBatchMessage({ eventSummaries: summaries, findingCount: 2 });

      // ACT
      await callCreateBatchIssue(message);

      // ASSERT
      const body = getPostedBody();
      const fields = body.fields as Record<string, unknown>;
      const description = fields.description as string;
      expect(description).not.toContain('CIS.1.1');
      expect(description).not.toContain('CIS.2.1');
      expect(description).not.toContain('test-user');
      expect(description).not.toContain('my-bucket');
    });

    it('should include chunk metadata in description when totalChunks > 0', async () => {
      // ARRANGE
      const message = createBatchMessage({ chunkIndex: 2, totalChunks: 5 });

      // ACT
      await callCreateBatchIssue(message);

      // ASSERT
      const body = getPostedBody();
      const fields = body.fields as Record<string, unknown>;
      const description = fields.description as string;
      expect(description).toMatch(/Part 2 of 5/);
    });

    it('should omit chunk metadata from description when totalChunks is undefined', async () => {
      // ARRANGE
      const message = createBatchMessage({ chunkIndex: undefined, totalChunks: undefined });

      // ACT
      await callCreateBatchIssue(message);

      // ASSERT
      const body = getPostedBody();
      const fields = body.fields as Record<string, unknown>;
      const description = fields.description as string;
      expect(description).not.toMatch(/Part \d+ of \d+/);
    });
  });

  describe('priority', () => {
    it('should set priority to Medium for all batch issues', async () => {
      // ARRANGE
      const message = createBatchMessage();

      // ACT
      await callCreateBatchIssue(message);

      // ASSERT
      const body = getPostedBody();
      const fields = body.fields as Record<string, unknown>;
      expect(fields.priority).toEqual({ name: 'Medium' });
    });
  });

  describe('custom fields with batch template variable resolution', () => {
    it('should resolve batch-level template variables in custom fields', async () => {
      // ARRANGE
      const message = createBatchMessage({
        configName: 'Security Alerts',
        notificationType: 'finding',
        findingCount: 10,
        remediationCount: 0,
      });

      // ACT
      await callCreateBatchIssue(message, {
        customFields: [
          { key: 'customfield_10001', value: 'Config: ${CONFIG_NAME}' },
          { key: 'customfield_10002', value: 'Type: ${NOTIFICATION_TYPE}' },
          { key: 'customfield_10003', value: 'Findings: ${FINDING_COUNT}' },
          { key: 'customfield_10004', value: 'Remediations: ${REMEDIATION_COUNT}' },
        ],
      });

      // ASSERT
      const body = getPostedBody();
      const fields = body.fields as Record<string, unknown>;
      expect(fields.customfield_10001).toBe('Config: Security Alerts');
      expect(fields.customfield_10002).toBe('Type: finding');
      expect(fields.customfield_10003).toBe('Findings: 10');
      expect(fields.customfield_10004).toBe('Remediations: 0');
    });

    it('should preserve single-event variable placeholders as literal syntax', async () => {
      // ARRANGE
      const message = createBatchMessage();

      // ACT
      await callCreateBatchIssue(message, {
        customFields: [
          { key: 'customfield_10001', value: 'Finding: ${FINDING_ID}' },
          { key: 'customfield_10002', value: 'Control: ${CONTROL_ID}' },
          { key: 'customfield_10003', value: 'Severity: ${SEVERITY}' },
        ],
      });

      // ASSERT
      const body = getPostedBody();
      const fields = body.fields as Record<string, unknown>;
      expect(fields.customfield_10001).toBe('Finding: ${FINDING_ID}');
      expect(fields.customfield_10002).toBe('Control: ${CONTROL_ID}');
      expect(fields.customfield_10003).toBe('Severity: ${SEVERITY}');
    });
  });

  describe('API request', () => {
    it('should POST to {instanceUrl}/rest/api/2/issue', async () => {
      // ARRANGE
      const message = createBatchMessage();

      // ACT
      await callCreateBatchIssue(message, { instanceUrl: 'https://jira.example.com' });

      // ASSERT
      expect(fetchWithRetry.mock.calls[0][0]).toBe('https://jira.example.com/rest/api/2/issue');
      expect(fetchWithRetry.mock.calls[0][1].method).toBe('POST');
      expect(fetchWithRetry.mock.calls[0][1].headers['Content-Type']).toBe('application/json');
    });

    it('should use Basic Auth header with base64-encoded credentials', async () => {
      // ARRANGE
      const message = createBatchMessage();
      const credentials: JiraCredentials = { username: 'admin@corp.com', apiToken: 'secret-token' };

      // ACT
      await callCreateBatchIssue(message, { credentials });

      // ASSERT
      const expectedAuth = `Basic ${Buffer.from('admin@corp.com:secret-token').toString('base64')}`;
      expect(fetchWithRetry.mock.calls[0][1].headers.Authorization).toBe(expectedAuth);
    });
  });

  describe('IaC download links rendering', () => {
    beforeEach(() => setupIaCTestEnvironment());
    afterEach(() => teardownIaCTestEnvironment());

    it('should include IaC links in description for eligible remediation summaries', async () => {
      const message = createBatchMessage({
        notificationType: 'remediation',
        remediationCount: 2,
        contentOptions: {
          includeManualRemediationLink: false,
          includeRemediationDeadline: false,
          enforceDeadline: false,
          includeIaCSnippet: true,
          iacFormats: ['terraform'],
          includeEnableAutomationLink: false,
        },
        eventSummaries: [
          {
            eventId: 'finding-1',
            controlId: 'S3.1',
            accountId: '111',
            region: 'us-east-1',
            severity: 'High',
            resourceId: 'r1',
            remediationStatus: 'SUCCESS',
          },
          {
            eventId: 'finding-2',
            controlId: 'EC2.1',
            accountId: '111',
            region: 'us-east-1',
            severity: 'Medium',
            resourceId: 'r2',
            remediationStatus: 'FAILED',
          },
        ],
      });

      await callCreateBatchIssue(message);

      const body = getPostedBody();
      const description = (body.fields as Record<string, unknown>).description as string;
      expect(description).toContain('S3.1');
      expect(description).toContain('terraform');
      // EC2.1 failed — should not have IaC links
      expect(description).not.toMatch(/EC2\.1.*terraform/);
    });

    it('strips JIRA wiki-markup characters from controlId in the IaC section', async () => {
      // ARRANGE — a crafted controlId carrying link/macro/image markup.
      const message = createBatchMessage({
        notificationType: 'remediation',
        remediationCount: 1,
        contentOptions: {
          includeManualRemediationLink: false,
          includeRemediationDeadline: false,
          enforceDeadline: false,
          includeIaCSnippet: true,
          iacFormats: ['terraform'],
          includeEnableAutomationLink: false,
        },
        eventSummaries: [
          {
            eventId: 'finding-1',
            controlId: 'S3.1[x|http://evil]{code}!img!',
            accountId: '111',
            region: 'us-east-1',
            severity: 'High',
            resourceId: 'r1',
            remediationStatus: 'SUCCESS',
          },
        ],
      });

      // ACT
      await callCreateBatchIssue(message);

      // ASSERT — structural markup characters are stripped from the controlId label.
      const body = getPostedBody();
      const description = (body.fields as Record<string, unknown>).description as string;
      expect(description).toContain('S3.1xhttp://evilcodeimg');
      expect(description).not.toContain('[x|http://evil]');
      expect(description).not.toContain('{code}');
      expect(description).not.toContain('!img!');
    });

    it('should not include IaC section when includeIaCSnippet is false', async () => {
      const message = createBatchMessage({
        notificationType: 'remediation',
        remediationCount: 1,
        contentOptions: {
          includeManualRemediationLink: false,
          includeRemediationDeadline: false,
          enforceDeadline: false,
          includeIaCSnippet: false,
          includeEnableAutomationLink: false,
        },
        eventSummaries: [
          {
            eventId: 'finding-1',
            controlId: 'S3.1',
            accountId: '111',
            region: 'us-east-1',
            severity: 'High',
            resourceId: 'r1',
            remediationStatus: 'SUCCESS',
          },
        ],
      });

      await callCreateBatchIssue(message);

      const body = getPostedBody();
      const description = (body.fields as Record<string, unknown>).description as string;
      expect(description).not.toContain('/iac/');
    });
  });

  describe('error handling', () => {
    it('should throw ChannelApiError on non-2xx response', async () => {
      // ARRANGE
      fetchWithRetry.mockResolvedValue({
        ok: false,
        status: 401,
        text: () => Promise.resolve('Unauthorized'),
      });
      const message = createBatchMessage();

      // ACT & ASSERT
      await expect(callCreateBatchIssue(message)).rejects.toThrow(ChannelApiError);
    });

    it('should return JiraCreateIssueResponse on success', async () => {
      // ARRANGE
      fetchWithRetry.mockResolvedValue({
        ok: true,
        status: 201,
        json: () =>
          Promise.resolve({
            key: 'PROJ-42',
            id: '42',
            self: 'https://company.atlassian.net/rest/api/2/issue/42',
          }),
      });
      const message = createBatchMessage();

      // ACT
      const result = await callCreateBatchIssue(message);

      // ASSERT
      expect(result.key).toBe('PROJ-42');
      expect(result.id).toBe('42');
      expect(result.self).toBe('https://company.atlassian.net/rest/api/2/issue/42');
    });
  });
});
