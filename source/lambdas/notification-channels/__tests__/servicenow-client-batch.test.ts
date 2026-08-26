// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { ServiceNowClient } from '../servicenow-client';
import { ChannelApiError, InputValidationError } from '../notification-channel-errors';
import { BatchChannelFanoutMessage, BatchEventSummary, ServiceNowCredentials } from '../types';
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
      type: 'servicenow',
      enabled: true,
      credentialsSecretArn: 'arn:aws:secretsmanager:us-east-1:123456789012:secret:snow-creds',
      endpointUrl: 'https://company.service-now.com',
      tableName: 'incident',
    },
    isBatch: true,
    findingCount: 5,
    remediationCount: 0,
    startGenerationTime: '2024-06-15T10:30:00Z',
    eventSummaries: [],
  };
  return { ...defaults, ...overrides };
}

const defaultCredentials: ServiceNowCredentials = { username: 'admin', password: 'secret123' };

describe('ServiceNowClient.createBatchRecord', () => {
  let fetchWithRetry: jest.Mock;
  let logger: Logger;
  let client: ServiceNowClient;

  beforeEach(() => {
    fetchWithRetry = jest.fn().mockResolvedValue({
      ok: true,
      status: 201,
      json: () => Promise.resolve({ result: { sys_id: 'batch-sys-id', number: 'INC0010099' } }),
    });
    logger = new Logger({ logLevel: 'SILENT' });
    client = new ServiceNowClient({ fetchWithRetry, logger });
  });

  interface ServiceNowRecordBody {
    short_description: string;
    description: string;
    urgency: number;
    impact: number;
    [key: string]: unknown;
  }

  function getPostedBody(): ServiceNowRecordBody {
    const calls = fetchWithRetry.mock.calls;
    if (calls.length === 0) throw new Error('fetchWithRetry was never called');
    return JSON.parse(calls[0][1].body);
  }

  async function callCreateBatchRecord(
    message: BatchChannelFanoutMessage,
    overrides: Partial<Omit<Parameters<typeof client.createBatchRecord>[0], 'message'>> = {},
  ) {
    return client.createBatchRecord({
      instanceUrl: 'https://company.service-now.com',
      tableName: 'incident',
      credentials: defaultCredentials,
      message,
      ...overrides,
    });
  }

  describe('short_description format', () => {
    it('should set short_description using buildBatchSubject pattern "{configName} - {count} {noun(s)}"', async () => {
      // ARRANGE
      const message = createBatchMessage({ configName: 'MyConfig', findingCount: 5, notificationType: 'finding' });

      // ACT
      await callCreateBatchRecord(message);

      // ASSERT
      const body = getPostedBody();
      expect(body.short_description).toBe('MyConfig - 5 findings');
    });

    it('should use singular noun when count is 1', async () => {
      // ARRANGE
      const message = createBatchMessage({ configName: 'MyConfig', findingCount: 1, notificationType: 'finding' });

      // ACT
      await callCreateBatchRecord(message);

      // ASSERT
      const body = getPostedBody();
      expect(body.short_description).toBe('MyConfig - 1 finding');
    });

    it('should use remediationCount and "remediation" noun for remediation type', async () => {
      // ARRANGE
      const message = createBatchMessage({
        configName: 'MyConfig',
        notificationType: 'remediation',
        findingCount: 0,
        remediationCount: 3,
      });

      // ACT
      await callCreateBatchRecord(message);

      // ASSERT
      const body = getPostedBody();
      expect(body.short_description).toBe('MyConfig - 3 remediations');
    });

    it('should truncate short_description to max 160 characters', async () => {
      // ARRANGE
      const longConfigName = 'A'.repeat(300);
      const message = createBatchMessage({ configName: longConfigName, findingCount: 3 });

      // ACT
      await callCreateBatchRecord(message);

      // ASSERT
      const body = getPostedBody();
      expect(body.short_description.length).toBeLessThanOrEqual(160);
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
      await callCreateBatchRecord(message);

      // ASSERT
      const body = getPostedBody();
      const description = body.description;
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
      await callCreateBatchRecord(message);

      // ASSERT
      const body = getPostedBody();
      const description = body.description;
      expect(description).toContain('4 remediations');
    });

    it('should include export URL in description when present', async () => {
      // ARRANGE
      const message = createBatchMessage({
        exportUrl: 'https://s3.amazonaws.com/bucket/export.csv',
      });

      // ACT
      await callCreateBatchRecord(message);

      // ASSERT
      const body = getPostedBody();
      const description = body.description;
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
      await callCreateBatchRecord(message);

      // ASSERT
      const body = getPostedBody();
      const description = body.description;
      expect(description).not.toContain('CIS.1.1');
      expect(description).not.toContain('CIS.2.1');
      expect(description).not.toContain('test-user');
      expect(description).not.toContain('my-bucket');
    });

    it('should include chunk metadata in description when totalChunks > 0', async () => {
      // ARRANGE
      const message = createBatchMessage({ chunkIndex: 2, totalChunks: 5 });

      // ACT
      await callCreateBatchRecord(message);

      // ASSERT
      const body = getPostedBody();
      const description = body.description;
      expect(description).toMatch(/Part 2 of 5/);
    });

    it('should omit chunk metadata from description when totalChunks is undefined', async () => {
      // ARRANGE
      const message = createBatchMessage({ chunkIndex: undefined, totalChunks: undefined });

      // ACT
      await callCreateBatchRecord(message);

      // ASSERT
      const body = getPostedBody();
      const description = body.description;
      expect(description).not.toMatch(/Part \d+ of \d+/);
    });
  });

  describe('urgency and impact', () => {
    it('should set urgency and impact to 2 (Medium) for all batch records', async () => {
      // ARRANGE
      const message = createBatchMessage();

      // ACT
      await callCreateBatchRecord(message);

      // ASSERT
      const body = getPostedBody();
      expect(body.urgency).toBe(2);
      expect(body.impact).toBe(2);
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
      await callCreateBatchRecord(message, {
        customFields: [
          { key: 'u_config', value: 'Config: ${CONFIG_NAME}' },
          { key: 'u_type', value: 'Type: ${NOTIFICATION_TYPE}' },
          { key: 'u_findings', value: 'Findings: ${FINDING_COUNT}' },
          { key: 'u_remediations', value: 'Remediations: ${REMEDIATION_COUNT}' },
        ],
      });

      // ASSERT
      const body = getPostedBody();
      expect(body.u_config).toBe('Config: Security Alerts');
      expect(body.u_type).toBe('Type: finding');
      expect(body.u_findings).toBe('Findings: 10');
      expect(body.u_remediations).toBe('Remediations: 0');
    });

    it('should preserve single-event variable placeholders as literal syntax', async () => {
      // ARRANGE
      const message = createBatchMessage();

      // ACT
      await callCreateBatchRecord(message, {
        customFields: [
          { key: 'u_finding', value: 'Finding: ${FINDING_ID}' },
          { key: 'u_control', value: 'Control: ${CONTROL_ID}' },
          { key: 'u_severity', value: 'Severity: ${SEVERITY}' },
        ],
      });

      // ASSERT
      const body = getPostedBody();
      expect(body.u_finding).toBe('Finding: ${FINDING_ID}');
      expect(body.u_control).toBe('Control: ${CONTROL_ID}');
      expect(body.u_severity).toBe('Severity: ${SEVERITY}');
    });

    it('should throw InputValidationError when custom fields exceed max count', async () => {
      // ARRANGE
      const message = createBatchMessage();
      const tooManyFields = Array.from({ length: 21 }, (_, i) => ({ key: `u_field_${i}`, value: 'val' }));

      // ACT & ASSERT
      await expect(callCreateBatchRecord(message, { customFields: tooManyFields })).rejects.toThrow(
        InputValidationError,
      );
    });

    it('should throw InputValidationError when custom field key exceeds max length', async () => {
      // ARRANGE
      const message = createBatchMessage();
      const longKey = 'u_' + 'a'.repeat(63);

      // ACT & ASSERT
      await expect(callCreateBatchRecord(message, { customFields: [{ key: longKey, value: 'val' }] })).rejects.toThrow(
        InputValidationError,
      );
    });

    it('should throw InputValidationError when resolved custom field value exceeds max length', async () => {
      // ARRANGE
      const message = createBatchMessage({ configName: 'x'.repeat(300) });

      // ACT & ASSERT
      await expect(
        callCreateBatchRecord(message, { customFields: [{ key: 'u_name', value: '${CONFIG_NAME}' }] }),
      ).rejects.toThrow(InputValidationError);
    });

    it('should throw InputValidationError when custom field key conflicts with a reserved field', async () => {
      // ARRANGE
      const message = createBatchMessage();

      // ACT & ASSERT
      await expect(
        callCreateBatchRecord(message, { customFields: [{ key: 'short_description', value: 'override' }] }),
      ).rejects.toThrow(InputValidationError);
    });
  });

  describe('API request', () => {
    it('should POST to {instanceUrl}/api/now/table/{tableName}', async () => {
      // ARRANGE
      const message = createBatchMessage();

      // ACT
      await callCreateBatchRecord(message, {
        instanceUrl: 'https://myinst.service-now.com',
        tableName: 'security_incident',
      });

      // ASSERT
      expect(fetchWithRetry.mock.calls[0][0]).toBe('https://myinst.service-now.com/api/now/table/security_incident');
      expect(fetchWithRetry.mock.calls[0][1].method).toBe('POST');
      expect(fetchWithRetry.mock.calls[0][1].headers['Content-Type']).toBe('application/json');
      expect(fetchWithRetry.mock.calls[0][1].headers['Accept']).toBe('application/json');
    });

    it('should use Basic Auth header with base64-encoded credentials', async () => {
      // ARRANGE
      const message = createBatchMessage();
      const credentials: ServiceNowCredentials = { username: 'svc_account', password: 'p@ssw0rd!' };

      // ACT
      await callCreateBatchRecord(message, { credentials });

      // ASSERT
      const expectedAuth = `Basic ${Buffer.from('svc_account:p@ssw0rd!').toString('base64')}`;
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
          iacFormats: ['terraform', 'cdk'],
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

      await callCreateBatchRecord(message);

      const body = getPostedBody();
      expect(body.description).toContain('S3.1');
      expect(body.description).toContain('terraform');
      expect(body.description).not.toMatch(/EC2\.1.*terraform/);
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

      await callCreateBatchRecord(message);

      const body = getPostedBody();
      expect(body.description).not.toContain('/iac/');
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
      await expect(callCreateBatchRecord(message)).rejects.toThrow(ChannelApiError);
    });

    it('should return result with sysId on success', async () => {
      // ARRANGE
      fetchWithRetry.mockResolvedValue({
        ok: true,
        status: 201,
        json: () => Promise.resolve({ result: { sys_id: 'sys-id-batch', number: 'INC0042' } }),
      });
      const message = createBatchMessage();

      // ACT
      const result = await callCreateBatchRecord(message);

      // ASSERT
      expect(result.sysId).toBe('sys-id-batch');
    });
  });
});
