// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { ChannelApiError } from '../notification-channel-errors';
import { createEvent, createContentOptions } from './test-factories';
import { Logger } from '@aws-lambda-powertools/logger';
import { ServiceNowClient, ServiceNowSendParams } from '../servicenow-client';
import { RESERVED_SERVICENOW_FIELD_KEYS } from '@asr/data-models';
import { ServiceNowCredentials } from '../types';
import { setupIaCTestEnvironment, teardownIaCTestEnvironment } from '../test-helpers/iacTestSetup';
import { resetChannelLambdaEnvironmentCache } from '../channelLambdaEnvironment';

const defaultCredentials: ServiceNowCredentials = { username: 'admin', password: 'secret123' };

function createSendParams(overrides: Partial<ServiceNowSendParams> = {}): ServiceNowSendParams {
  return {
    instanceUrl: 'https://company.service-now.com',
    tableName: 'incident',
    credentials: defaultCredentials,
    event: createEvent(),
    configId: 'config-1',
    configName: 'Test Config',
    contentOptions: createContentOptions(),
    ...overrides,
  };
}

describe('ServiceNowClient', () => {
  let fetchWithRetry: jest.Mock;
  let logger: Logger;
  let client: ServiceNowClient;

  beforeEach(() => {
    setupIaCTestEnvironment();
    fetchWithRetry = jest.fn().mockResolvedValue({
      ok: true,
      status: 201,
      json: () => Promise.resolve({ result: { sys_id: 'abc123', number: 'INC0010042' } }),
    });
    logger = new Logger({ logLevel: 'SILENT' });
    client = new ServiceNowClient({ fetchWithRetry, logger });
  });

  afterEach(() => teardownIaCTestEnvironment());

  it('should format short_description using the shared formatSubject function truncated to 160 chars', async () => {
    // ARRANGE
    const params = createSendParams({
      event: createEvent({ controlId: 'CIS.1.1', severity: 'High', accountId: '123456789012' }),
    });

    // ACT
    await client.createRecord(params);

    // ASSERT
    const body = JSON.parse(fetchWithRetry.mock.calls[0][1].body);
    expect(body.short_description).toBe('[ASR] CIS.1.1 High finding: Test finding');
    expect(body.short_description.length).toBeLessThanOrEqual(160);
  });

  it('should truncate short_description to 160 characters when it exceeds the limit', async () => {
    // ARRANGE
    const longControlId = 'CTRL.' + 'x'.repeat(200);
    const params = createSendParams({
      event: createEvent({ controlId: longControlId, severity: 'Critical', accountId: '999999999999' }),
    });

    // ACT
    await client.createRecord(params);

    // ASSERT
    const body = JSON.parse(fetchWithRetry.mock.calls[0][1].body);
    expect(body.short_description.length).toBeLessThanOrEqual(160);
    expect(body.short_description).toContain('[ASR]');
  });

  it('should map severity to urgency/impact using ServiceNow 1-3 scale', async () => {
    // ARRANGE
    const severityToUrgency: Record<string, number> = {
      Critical: 1,
      High: 2,
      Medium: 3,
      Low: 3,
      Informational: 3,
      CRITICAL: 1,
      HIGH: 2,
      MEDIUM: 3,
      LOW: 3,
      INFORMATIONAL: 3,
    };

    // ACT / ASSERT
    for (const [severity, expectedUrgency] of Object.entries(severityToUrgency)) {
      fetchWithRetry.mockResolvedValue({
        ok: true,
        status: 201,
        json: () => Promise.resolve({ result: { sys_id: 'id-1' } }),
      });
      const params = createSendParams({ event: createEvent({ severity }) });

      await client.createRecord(params);

      const body = JSON.parse(fetchWithRetry.mock.calls[fetchWithRetry.mock.calls.length - 1][1].body);
      expect(body.urgency).toBe(expectedUrgency);
      expect(body.impact).toBe(expectedUrgency);
    }
  });

  it('should include finding details, resource ARN, and ASR console link in work_notes', async () => {
    // ARRANGE
    const params = createSendParams({
      event: createEvent({
        eventId: 'arn:aws:securityhub:us-east-1:123:finding/abc',
        controlId: 'S3.1',
        severity: 'Critical',
        resourceId: 'arn:aws:s3:::my-bucket',
        accountId: '123456789012',
        region: 'us-east-1',
      }),
      configId: 'cfg-42',
      configName: 'Production Alerts',
    });

    // ACT
    await client.createRecord(params);

    // ASSERT
    const body = JSON.parse(fetchWithRetry.mock.calls[0][1].body);
    expect(body.work_notes).toContain('arn:aws:securityhub:us-east-1:123:finding/abc');
    expect(body.work_notes).toContain('S3.1');
    expect(body.work_notes).toContain('arn:aws:s3:::my-bucket');
    expect(body.work_notes).toContain('/findings?findingId=');
  });

  it('should omit the ASR console link from work_notes when the Web UI is not deployed', async () => {
    // ARRANGE: no Web UI deployed → WEB_UI_URL unset
    delete process.env.WEB_UI_URL;
    resetChannelLambdaEnvironmentCache();
    const params = createSendParams({
      event: createEvent({
        eventId: 'arn:aws:securityhub:us-east-1:123:finding/abc',
        controlId: 'S3.1',
        resourceId: 'arn:aws:s3:::my-bucket',
      }),
    });

    // ACT
    await client.createRecord(params);

    // ASSERT: other details remain, but no broken relative console link is emitted
    const body = JSON.parse(fetchWithRetry.mock.calls[0][1].body);
    expect(body.work_notes).toContain('arn:aws:securityhub:us-east-1:123:finding/abc');
    expect(body.work_notes).toContain('S3.1');
    expect(body.work_notes).toContain('arn:aws:s3:::my-bucket');
    expect(body.work_notes).not.toContain('ASR Console:');
    expect(body.work_notes).not.toContain('/findings?findingId=');
  });

  it('should use Basic Auth header with base64-encoded username:password', async () => {
    // ARRANGE
    const params = createSendParams({
      credentials: { username: 'svc_account', password: 'p@ssw0rd!' },
    });

    // ACT
    await client.createRecord(params);

    // ASSERT
    const expectedAuth = `Basic ${Buffer.from('svc_account:p@ssw0rd!').toString('base64')}`;
    expect(fetchWithRetry.mock.calls[0][1].headers.Authorization).toBe(expectedAuth);
  });

  it('should POST to {instanceUrl}/api/now/table/{tableName} with Content-Type and Accept headers', async () => {
    // ARRANGE
    const params = createSendParams({
      instanceUrl: 'https://myinst.service-now.com',
      tableName: 'security_incident',
    });

    // ACT
    await client.createRecord(params);

    // ASSERT
    expect(fetchWithRetry.mock.calls[0][0]).toBe('https://myinst.service-now.com/api/now/table/security_incident');
    expect(fetchWithRetry.mock.calls[0][1].method).toBe('POST');
    expect(fetchWithRetry.mock.calls[0][1].headers['Content-Type']).toBe('application/json');
    expect(fetchWithRetry.mock.calls[0][1].headers['Accept']).toBe('application/json');
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
    await expect(client.createRecord(params)).rejects.toThrow(ChannelApiError);
  });

  it('should return result with sys_id when response contains it', async () => {
    // ARRANGE
    fetchWithRetry.mockResolvedValue({
      ok: true,
      status: 201,
      json: () => Promise.resolve({ result: { sys_id: 'sys-id-999', number: 'INC0099' } }),
    });
    const params = createSendParams();

    // ACT
    const result = await client.createRecord(params);

    // ASSERT
    expect(result.sysId).toBe('sys-id-999');
  });

  it('should return empty result when response body is not valid JSON', async () => {
    // ARRANGE
    fetchWithRetry.mockResolvedValue({
      ok: true,
      status: 201,
      json: () => Promise.reject(new SyntaxError('Unexpected token')),
    });
    const params = createSendParams();

    // ACT
    const result = await client.createRecord(params);

    // ASSERT
    expect(result).toEqual({});
  });

  it('should handle response without sys_id gracefully', async () => {
    // ARRANGE
    fetchWithRetry.mockResolvedValue({
      ok: true,
      status: 201,
      json: () => Promise.resolve({ result: {} }),
    });
    const params = createSendParams();

    // ACT
    const result = await client.createRecord(params);

    // ASSERT
    expect(result.sysId).toBeUndefined();
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
    await client.createRecord(params);

    // ASSERT
    const body = JSON.parse(fetchWithRetry.mock.calls[0][1].body);
    expect(body.description).toContain('/findings?findingId=');
    expect(body.description).toContain('/controls?controlId=');
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
    await client.createRecord(params);

    // ASSERT
    const body = JSON.parse(fetchWithRetry.mock.calls[0][1].body);
    expect(body.description).toContain('Remediation Deadline');
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
    await client.createRecord(params);

    // ASSERT
    const body = JSON.parse(fetchWithRetry.mock.calls[0][1].body);
    expect(body.description).toContain('IaC Templates:');
    expect(body.description).toContain('/iac/');
    expect(body.description).toContain('format=cloudformation-yaml');
    expect(body.description).toContain('format=terraform');
  });

  it('should omit IaC links for non-remediation (finding) events', async () => {
    // ARRANGE
    const params = createSendParams({
      event: createEvent({ eventType: 'finding' }),
      contentOptions: { ...createContentOptions(), includeIaCSnippet: true, iacFormats: ['cloudformation-yaml'] },
    });

    // ACT
    await client.createRecord(params);

    // ASSERT
    const body = JSON.parse(fetchWithRetry.mock.calls[0][1].body);
    expect(body.description).not.toContain('IaC Templates');
  });

  it('should resolve template variables in custom fields', async () => {
    // ARRANGE
    const params = createSendParams({
      event: createEvent({ controlId: 'S3.1', severity: 'High', accountId: '111222333444' }),
      customFields: [
        { key: 'u_control', value: '${CONTROL_ID}' },
        { key: 'u_severity', value: '${SEVERITY}' },
        { key: 'u_account', value: '${ACCOUNT_ID}' },
      ],
    });

    // ACT
    await client.createRecord(params);

    // ASSERT
    const body = JSON.parse(fetchWithRetry.mock.calls[0][1].body);
    expect(body.u_control).toBe('S3.1');
    expect(body.u_severity).toBe('High');
    expect(body.u_account).toBe('111222333444');
  });

  it('should throw error when custom fields exceed 20 entries', async () => {
    // ARRANGE
    const tooManyFields = Array.from({ length: 21 }, (_, i) => ({
      key: `u_field_${i}`,
      value: 'val',
    }));
    const params = createSendParams({ customFields: tooManyFields });

    // ACT & ASSERT
    await expect(client.createRecord(params)).rejects.toThrow(/20/);
  });

  it('should throw error when custom field key exceeds 64 characters', async () => {
    // ARRANGE
    const params = createSendParams({
      customFields: [{ key: 'k'.repeat(65), value: 'val' }],
    });

    // ACT & ASSERT
    await expect(client.createRecord(params)).rejects.toThrow(/64/);
  });

  it('should throw error when resolved custom field value exceeds 256 characters', async () => {
    // ARRANGE
    const longArn = 'arn:aws:s3:::' + 'a'.repeat(250);
    const params = createSendParams({
      event: createEvent({ resourceId: longArn }),
      customFields: [{ key: 'u_resource', value: '${RESOURCE_ARN}' }],
    });

    // ACT & ASSERT
    await expect(client.createRecord(params)).rejects.toThrow(/256/);
  });

  it('should spread resolved custom fields into the record payload', async () => {
    // ARRANGE
    const params = createSendParams({
      customFields: [
        { key: 'u_environment', value: 'production' },
        { key: 'u_team', value: 'security-ops' },
      ],
    });

    // ACT
    await client.createRecord(params);

    // ASSERT
    const body = JSON.parse(fetchWithRetry.mock.calls[0][1].body);
    expect(body.u_environment).toBe('production');
    expect(body.u_team).toBe('security-ops');
  });

  it('should have RESERVED_SERVICENOW_FIELD_KEYS matching the base record payload keys', async () => {
    // ARRANGE
    const params = createSendParams();

    // ACT
    await client.createRecord(params);

    // ASSERT
    const body = JSON.parse(fetchWithRetry.mock.calls[0][1].body);
    const basePayloadKeys = new Set(Object.keys(body));
    expect(basePayloadKeys).toEqual(RESERVED_SERVICENOW_FIELD_KEYS);
  });
});
