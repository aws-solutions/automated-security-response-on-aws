// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { ChannelApiError, InputValidationError } from '../notification-channel-errors';
import { createEvent, createContentOptions } from './test-factories';
import { Logger } from '@aws-lambda-powertools/logger';
import { JiraClient, JiraSendParams, resolveCustomFields, isPriorityFieldError } from '../jira-client';
import { TemplateVariableContext, resolveTemplateVariables } from '../template-variables';
import { JiraCredentials } from '../types';
import { setupIaCTestEnvironment, teardownIaCTestEnvironment } from '../test-helpers/iacTestSetup';
import {
  MAX_JIRA_CUSTOM_FIELDS,
  MAX_JIRA_CUSTOM_FIELD_KEY_LENGTH,
  MAX_JIRA_CUSTOM_FIELD_VALUE_LENGTH,
} from '@asr/data-models';

const defaultCredentials: JiraCredentials = { username: 'user@company.com', apiToken: 'test-token-123' };

function createSendParams(overrides: Partial<JiraSendParams> = {}): JiraSendParams {
  return {
    instanceUrl: 'https://company.atlassian.net',
    projectKey: 'SEC',
    issueType: 'Bug',
    credentials: defaultCredentials,
    event: createEvent(),
    configName: 'Test Config',
    contentOptions: createContentOptions(),
    ...overrides,
  };
}

describe('JiraClient', () => {
  let fetchWithRetry: jest.Mock;
  let logger: Logger;
  let client: JiraClient;

  beforeEach(() => {
    setupIaCTestEnvironment();
    fetchWithRetry = jest.fn().mockResolvedValue({
      ok: true,
      status: 201,
      json: () =>
        Promise.resolve({ key: 'SEC-42', id: '10042', self: 'https://company.atlassian.net/rest/api/2/issue/10042' }),
    });
    logger = new Logger({ logLevel: 'SILENT' });
    client = new JiraClient({ fetchWithRetry, logger });
  });

  afterAll(() => teardownIaCTestEnvironment());

  it('should construct correct issue payload with project key, summary, description, issue type, and priority', async () => {
    // ARRANGE
    const params = createSendParams();

    // ACT
    const result = await client.createIssue(params);

    // ASSERT
    const body = JSON.parse(fetchWithRetry.mock.calls[0][1].body);
    expect(body.fields.project.key).toBe('SEC');
    expect(body.fields.summary).toContain('CIS.1.1 High finding: Test finding');
    expect(body.fields.issuetype.name).toBe('Bug');
    expect(body.fields.priority.name).toBe('High');
    expect(body.fields.description).toContain('*Configuration:* Test Config');
    expect(body.fields.description).toContain('*Severity:* High');
    expect(body.fields.description).toContain('*Control:* CIS.1.1');
    expect(result.key).toBe('SEC-42');
  });

  it('should map severity to JIRA priority correctly', async () => {
    // ARRANGE / ACT / ASSERT
    const severityToPriority: Record<string, string> = {
      Critical: 'Highest',
      High: 'High',
      Medium: 'Medium',
      Low: 'Low',
      Informational: 'Lowest',
      CRITICAL: 'Highest',
      HIGH: 'High',
      MEDIUM: 'Medium',
      LOW: 'Low',
      INFORMATIONAL: 'Lowest',
    };

    for (const [severity, expectedPriority] of Object.entries(severityToPriority)) {
      fetchWithRetry.mockResolvedValue({
        ok: true,
        status: 201,
        json: () => Promise.resolve({ key: 'SEC-1', id: '1', self: 'url' }),
      });
      const params = createSendParams({ event: createEvent({ severity }) });

      await client.createIssue(params);

      const body = JSON.parse(fetchWithRetry.mock.calls[fetchWithRetry.mock.calls.length - 1][1].body);
      expect(body.fields.priority.name).toBe(expectedPriority);
    }
  });

  it('should use Basic Auth header with base64-encoded credentials', async () => {
    // ARRANGE
    const params = createSendParams({
      credentials: { username: 'admin@corp.com', apiToken: 'secret-token' },
    });

    // ACT
    await client.createIssue(params);

    // ASSERT
    const expectedAuth = `Basic ${Buffer.from('admin@corp.com:secret-token').toString('base64')}`;
    expect(fetchWithRetry.mock.calls[0][1].headers.Authorization).toBe(expectedAuth);
  });

  it('should POST to {instanceUrl}/rest/api/2/issue', async () => {
    // ARRANGE
    const params = createSendParams({ instanceUrl: 'https://jira.example.com' });

    // ACT
    await client.createIssue(params);

    // ASSERT
    expect(fetchWithRetry.mock.calls[0][0]).toBe('https://jira.example.com/rest/api/2/issue');
    expect(fetchWithRetry.mock.calls[0][1].method).toBe('POST');
    expect(fetchWithRetry.mock.calls[0][1].headers['Content-Type']).toBe('application/json');
  });

  it('should throw ChannelApiError on non-2xx response', async () => {
    // ARRANGE
    fetchWithRetry.mockResolvedValue({
      ok: false,
      status: 401,
      text: () => Promise.resolve('Unauthorized'),
    });
    const params = createSendParams();

    // ACT & ASSERT
    await expect(client.createIssue(params)).rejects.toThrow(ChannelApiError);
  });

  it('should throw ChannelApiError when response is missing issue key', async () => {
    // ARRANGE
    fetchWithRetry.mockResolvedValue({
      ok: true,
      status: 200,
      json: () => Promise.resolve({ noKey: true }),
    });
    const params = createSendParams();

    // ACT & ASSERT
    await expect(client.createIssue(params)).rejects.toThrow(ChannelApiError);
  });

  it('should retry without the priority field when JIRA rejects priority with a 400', async () => {
    // ARRANGE
    const priorityError = JSON.stringify({
      errorMessages: [],
      errors: { priority: 'Specify the Priority (name) in the string format' },
    });
    fetchWithRetry
      .mockResolvedValueOnce({ ok: false, status: 400, text: () => Promise.resolve(priorityError) })
      .mockResolvedValueOnce({
        ok: true,
        status: 201,
        json: () => Promise.resolve({ key: 'SEC-7', id: '7', self: 'url' }),
      });
    const params = createSendParams();

    // ACT
    const result = await client.createIssue(params);

    // ASSERT
    expect(fetchWithRetry).toHaveBeenCalledTimes(2);
    const firstBody = JSON.parse(fetchWithRetry.mock.calls[0][1].body);
    const retryBody = JSON.parse(fetchWithRetry.mock.calls[1][1].body);
    expect(firstBody.fields.priority).toBeDefined();
    expect(retryBody.fields.priority).toBeUndefined();
    expect(retryBody.fields.summary).toBe(firstBody.fields.summary);
    expect(result.key).toBe('SEC-7');
  });

  it('should not retry on a 400 that is unrelated to the priority field', async () => {
    // ARRANGE
    const otherError = JSON.stringify({ errorMessages: [], errors: { summary: 'Summary is required' } });
    fetchWithRetry.mockResolvedValue({ ok: false, status: 400, text: () => Promise.resolve(otherError) });
    const params = createSendParams();

    // ACT & ASSERT
    await expect(client.createIssue(params)).rejects.toThrow(ChannelApiError);
    expect(fetchWithRetry).toHaveBeenCalledTimes(1);
  });

  it('should throw ChannelApiError when the priority-less retry also fails', async () => {
    // ARRANGE
    const priorityError = JSON.stringify({ errorMessages: [], errors: { priority: 'invalid' } });
    fetchWithRetry
      .mockResolvedValueOnce({ ok: false, status: 400, text: () => Promise.resolve(priorityError) })
      .mockResolvedValueOnce({ ok: false, status: 400, text: () => Promise.resolve('still broken') });
    const params = createSendParams();

    // ACT & ASSERT
    await expect(client.createIssue(params)).rejects.toThrow(ChannelApiError);
    expect(fetchWithRetry).toHaveBeenCalledTimes(2);
  });

  it('should return JiraCreateIssueResponse on success', async () => {
    // ARRANGE
    fetchWithRetry.mockResolvedValue({
      ok: true,
      status: 201,
      json: () => Promise.resolve({ key: 'PROJ-99', id: '99', self: 'https://jira.example.com/rest/api/2/issue/99' }),
    });
    const params = createSendParams();

    // ACT
    const result = await client.createIssue(params);

    // ASSERT
    expect(result.key).toBe('PROJ-99');
    expect(result.id).toBe('99');
    expect(result.self).toBe('https://jira.example.com/rest/api/2/issue/99');
  });

  it('should include remediation links in description when enabled', async () => {
    // ARRANGE
    const params = createSendParams({
      contentOptions: {
        ...createContentOptions(),
        includeManualRemediationLink: true,
        includeEnableAutomationLink: true,
      },
    });

    // ACT
    await client.createIssue(params);

    // ASSERT
    const body = JSON.parse(fetchWithRetry.mock.calls[0][1].body);
    expect(body.fields.description).toContain('/findings?findingId=');
    expect(body.fields.description).toContain('/controls?controlId=');
  });

  it('should include deadline in description when enabled', async () => {
    // ARRANGE
    const params = createSendParams({
      contentOptions: {
        ...createContentOptions(),
        includeRemediationDeadline: true,
        remediationDeadlineDays: 30,
      },
    });

    // ACT
    await client.createIssue(params);

    // ASSERT
    const body = JSON.parse(fetchWithRetry.mock.calls[0][1].body);
    expect(body.fields.description).toContain('Remediation Deadline');
  });

  it('should render IaC download links in description for eligible remediation events', async () => {
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
    await client.createIssue(params);

    // ASSERT
    const body = JSON.parse(fetchWithRetry.mock.calls[0][1].body);
    expect(body.fields.description).toContain('*IaC Templates:*');
    expect(body.fields.description).toContain('/iac/');
    expect(body.fields.description).toContain('format=cloudformation-yaml');
    expect(body.fields.description).toContain('format=terraform');
  });

  it('should omit IaC links for non-remediation (finding) events', async () => {
    // ARRANGE
    const params = createSendParams({
      event: createEvent({ eventType: 'finding' }),
      contentOptions: { ...createContentOptions(), includeIaCSnippet: true, iacFormats: ['cloudformation-yaml'] },
    });

    // ACT
    await client.createIssue(params);

    // ASSERT
    const body = JSON.parse(fetchWithRetry.mock.calls[0][1].body);
    expect(body.fields.description).not.toContain('IaC Templates');
  });

  it('should truncate total description at 32,767 characters with truncation indicator', async () => {
    // ARRANGE — use a long event description so the base exceeds the JIRA limit
    const params = createSendParams({
      event: createEvent({
        eventType: 'remediation',
        remediationStatus: 'SUCCESS',
        description: 'D'.repeat(40_000),
      }),
      contentOptions: { ...createContentOptions(), includeIaCSnippet: true, iacFormats: ['cloudformation-yaml'] },
    });

    // ACT
    await client.createIssue(params);

    // ASSERT
    const body = JSON.parse(fetchWithRetry.mock.calls[0][1].body);
    expect(body.fields.description.length).toBeLessThanOrEqual(32_767);
    expect(body.fields.description).toContain('…(truncated — JIRA limit)');
  });

  it('should include resolved custom fields in payload', async () => {
    // ARRANGE
    const params = createSendParams({
      customFields: [
        { key: 'customfield_10001', value: 'Finding: ${FINDING_ID}' },
        { key: 'customfield_10002', value: '${SEVERITY}' },
      ],
    });

    // ACT
    await client.createIssue(params);

    // ASSERT
    const body = JSON.parse(fetchWithRetry.mock.calls[0][1].body);
    expect(body.fields.customfield_10001).toBe('Finding: evt-1');
    expect(body.fields.customfield_10002).toBe('High');
  });

  it('should strip JIRA wiki markup from substituted custom field values', async () => {
    // ARRANGE
    const params = createSendParams({
      event: createEvent({ resourceId: 'bucket{code}injected{code}' }),
      customFields: [{ key: 'customfield_10001', value: 'Resource: ${RESOURCE_ARN}' }],
    });

    // ACT
    await client.createIssue(params);

    // ASSERT — macro braces removed from the substituted value, literal template text retained
    const body = JSON.parse(fetchWithRetry.mock.calls[0][1].body);
    expect(body.fields.customfield_10001).toBe('Resource: bucketcodeinjectedcode');
  });

  it('should strip wiki markup from finding values in the description while preserving the solution labels', async () => {
    // ARRANGE
    const params = createSendParams({
      event: createEvent({ findingDescription: 'see [evil|http://x] {code}p{code}' }),
    });

    // ACT
    await client.createIssue(params);

    // ASSERT — value sanitized, but the solution's own *bold* labels remain intact
    const body = JSON.parse(fetchWithRetry.mock.calls[0][1].body);
    expect(body.fields.description).toContain('*Finding Description:* see evilhttp://x codepcode');
    expect(body.fields.description).toContain('*Severity:* High');
  });
});

describe('isPriorityFieldError', () => {
  it('should return true when the error body references the priority field', () => {
    // ARRANGE
    const body = JSON.stringify({ errorMessages: [], errors: { priority: 'invalid' } });

    // ACT / ASSERT
    expect(isPriorityFieldError(body)).toBe(true);
  });

  it('should return false for errors on other fields', () => {
    // ARRANGE
    const body = JSON.stringify({ errorMessages: [], errors: { summary: 'required' } });

    // ACT / ASSERT
    expect(isPriorityFieldError(body)).toBe(false);
  });

  it('should return false for a non-JSON body', () => {
    // ARRANGE / ACT / ASSERT
    expect(isPriorityFieldError('Bad Request')).toBe(false);
  });

  it('should return false for JSON without an errors object', () => {
    // ARRANGE / ACT / ASSERT
    expect(isPriorityFieldError('{}')).toBe(false);
  });
});

describe('resolveTemplateVariables', () => {
  const context: TemplateVariableContext = {
    findingId: 'arn:aws:securityhub:us-east-1:123:finding/abc',
    controlId: 'S3.1',
    severity: 'Critical',
    accountId: '123456789012',
    region: 'us-east-1',
    resourceArn: 'arn:aws:s3:::my-bucket',
    configName: 'Production Alerts',
  };

  it('should replace all known variables', () => {
    // ARRANGE
    const input =
      '${FINDING_ID} | ${CONTROL_ID} | ${SEVERITY} | ${ACCOUNT_ID} | ${REGION} | ${RESOURCE_ARN} | ${CONFIG_NAME}';

    // ACT
    const result = resolveTemplateVariables(input, context);

    // ASSERT
    expect(result).toBe(
      'arn:aws:securityhub:us-east-1:123:finding/abc | S3.1 | Critical | 123456789012 | us-east-1 | arn:aws:s3:::my-bucket | Production Alerts',
    );
  });

  it('should leave unrecognized variables unchanged', () => {
    // ARRANGE
    const input = '${UNKNOWN_VAR} and ${ANOTHER}';

    // ACT
    const result = resolveTemplateVariables(input, context);

    // ASSERT
    expect(result).toBe('${UNKNOWN_VAR} and ${ANOTHER}');
  });

  it('should be idempotent — resolving twice produces the same result as resolving once', () => {
    // ARRANGE
    const input = 'Control: ${CONTROL_ID}, Account: ${ACCOUNT_ID}';

    // ACT
    const firstPass = resolveTemplateVariables(input, context);
    const secondPass = resolveTemplateVariables(firstPass, context);

    // ASSERT
    expect(secondPass).toBe(firstPass);
  });
});

describe('resolveCustomFields', () => {
  const context: TemplateVariableContext = {
    findingId: 'evt-1',
    controlId: 'CIS.1.1',
    severity: 'High',
    accountId: '123456789012',
    region: 'us-east-1',
    resourceArn: 'arn:aws:s3:::bucket',
    configName: 'Config',
  };

  it('should resolve variables in all field values', () => {
    // ARRANGE
    const fields = [
      { key: 'customfield_10001', value: 'Control: ${CONTROL_ID}' },
      { key: 'customfield_10002', value: 'Region: ${REGION}' },
    ];

    // ACT
    const result = resolveCustomFields(fields, context);

    // ASSERT
    expect(result).toEqual({
      customfield_10001: 'Control: CIS.1.1',
      customfield_10002: 'Region: us-east-1',
    });
  });

  it('should throw InputValidationError when custom fields exceed max count', () => {
    // ARRANGE
    const fields = Array.from({ length: MAX_JIRA_CUSTOM_FIELDS + 1 }, (_, i) => ({
      key: `customfield_${10000 + i}`,
      value: 'val',
    }));

    // ACT & ASSERT
    expect(() => resolveCustomFields(fields, context)).toThrow(InputValidationError);
  });

  it('should throw InputValidationError when custom field key exceeds max length', () => {
    // ARRANGE
    const fields = [{ key: 'customfield_' + '1'.repeat(MAX_JIRA_CUSTOM_FIELD_KEY_LENGTH), value: 'val' }];

    // ACT & ASSERT
    expect(() => resolveCustomFields(fields, context)).toThrow(InputValidationError);
  });

  it('should throw InputValidationError when custom field key does not match required pattern', () => {
    // ARRANGE
    const fields = [{ key: 'summary', value: 'override' }];

    // ACT & ASSERT
    expect(() => resolveCustomFields(fields, context)).toThrow(InputValidationError);
  });

  it('should throw InputValidationError when custom field value exceeds max length', () => {
    // ARRANGE
    const fields = [{ key: 'customfield_10001', value: 'x'.repeat(MAX_JIRA_CUSTOM_FIELD_VALUE_LENGTH + 1) }];

    // ACT & ASSERT
    expect(() => resolveCustomFields(fields, context)).toThrow(InputValidationError);
  });
});
