// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { mockClient } from 'aws-sdk-client-mock';
import { SNSClient, PublishCommand } from '@aws-sdk/client-sns';
import { S3Client, PutObjectCommand } from '@aws-sdk/client-s3';
import { DynamoDBDocumentClient, PutCommand } from '@aws-sdk/lib-dynamodb';
import { Logger } from '@aws-lambda-powertools/logger';
import { NotificationConfigurationItem, NotificationBatchItem, FindingId } from '@asr/data-models';
import { BatchProcessorService } from '../batchProcessorService';
import { NotificationConfigurationRepository } from '../../common/repositories/notificationConfigurationRepository';
import { NotificationBatchRepository } from '../../common/repositories/notificationBatchRepository';
import { FindingRepository } from '../../common/repositories/findingRepository';
import { DynamoDBTestSetup } from '../../common/__tests__/dynamodbSetup';
import {
  notificationConfigTableName,
  notificationBatchesTableName,
  findingsTableName,
  remediationHistoryTableName,
  channelFanoutTopicArn,
} from '../../common/__tests__/envSetup';
import { asConfigId } from '../../common/__tests__/utils';
import { sendMetrics } from '../../common/utils/metricsUtils';

const snsMock = mockClient(SNSClient);
const s3Mock = mockClient(S3Client);

const PAST_WINDOW_END = '2020-01-01T00:00:00.000Z';
const FUTURE_WINDOW_END = '2099-01-01T00:00:00.000Z';

const FINDING_ID_1 = 'arn:aws:securityhub:us-east-1:123456789012:security-control/S3.1/finding/abc-111' as FindingId;
const FINDING_ID_2 = 'arn:aws:securityhub:us-east-1:123456789012:security-control/S3.2/finding/abc-222' as FindingId;

const createMockConfig = (overrides: Partial<NotificationConfigurationItem> = {}): NotificationConfigurationItem => ({
  configId: asConfigId('aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'),
  name: 'Batch Test Config',
  enabled: true,
  notificationType: 'finding',
  severityFilter: ['All'],
  controlIds: [],
  resourceFilterIds: [],
  deliveryChannels: [
    { type: 'email', enabled: true, recipients: [{ recipientType: 'custom', emailAddresses: ['test@example.com'] }] },
  ],
  batchWindow: { enabled: true, duration: 5, unit: 'Minutes' },
  batchExport: { enabled: true },
  contentOptions: {
    includeManualRemediationLink: false,
    includeRemediationDeadline: false,
    enforceDeadline: false,
    includeIaCSnippet: false,
    includeEnableAutomationLink: false,
  },
  version: 1,
  createdAt: '2024-01-01T00:00:00.000Z',
  createdBy: 'admin@example.com',
  ...overrides,
});

const createOpenBatch = (
  configId: string,
  windowEnd: string,
  findingIds: FindingId[] = [],
  remediationIds: FindingId[] = [],
): NotificationBatchItem => ({
  configId,
  windowEnd,
  status: 'open',
  findingIds,
  remediationIds,
  itemCount: findingIds.length + remediationIds.length,
  expireAt: Math.floor(new Date(windowEnd).getTime() / 1000) + 60,
  createdAt: '2024-01-01T00:00:00.000Z',
});

async function insertFinding(
  docClient: DynamoDBDocumentClient,
  findingId: FindingId,
  remediationStatus: string,
): Promise<void> {
  // findingType is derived from the ARN — extract the control path
  const match = findingId.match(/:security-control\/([^/]+)\//);
  const findingType = match ? `security-control/${match[1]}` : 'unknown';

  await docClient.send(
    new PutCommand({
      TableName: findingsTableName,
      Item: {
        findingType,
        findingId,
        accountId: '123456789012',
        resourceId: 'arn:aws:s3:::test-bucket',
        severity: 'High',
        region: 'us-east-1',
        remediationStatus,
        lastUpdatedTime: new Date().toISOString(),
        'securityHubUpdatedAtTime#findingId': `${new Date().toISOString()}#${findingId}`,
        FINDING_CONSTANT: 'finding',
        findingIdControl: findingType,
        'severityNormalized#securityHubUpdatedAtTime#findingId': `70#${new Date().toISOString()}#${findingId}`,
        findingJSON: Buffer.from('{}'),
      },
    }),
  );
}

async function insertRemediationHistory(
  docClient: DynamoDBDocumentClient,
  findingId: FindingId,
  remediationStatus: string,
): Promise<void> {
  const match = findingId.match(/:security-control\/([^/]+)\//);
  const findingType = match ? `security-control/${match[1]}` : 'unknown';
  const now = new Date().toISOString();
  const executionId = `exec-${Date.now()}`;

  await docClient.send(
    new PutCommand({
      TableName: remediationHistoryTableName,
      Item: {
        findingType,
        findingId,
        accountId: '123456789012',
        resourceId: 'arn:aws:s3:::test-bucket',
        resourceType: 'AwsS3Bucket',
        resourceTypeNormalized: 'S3Bucket',
        severity: 'High',
        region: 'us-east-1',
        remediationStatus,
        lastUpdatedTime: now,
        lastUpdatedBy: 'test-user',
        executionId,
        'findingId#executionId': `${findingId}#${executionId}`,
        'lastUpdatedTime#findingId': `${now}#${findingId}`,
        REMEDIATION_CONSTANT: 'remediation',
        expireAt: 9999999999,
      },
    }),
  );
}

describe('BatchProcessorService', () => {
  const principal = 'test-user@example.com';
  let docClient: DynamoDBDocumentClient;
  let service: BatchProcessorService;
  let configRepo: NotificationConfigurationRepository;
  let batchRepo: NotificationBatchRepository;
  const logger = new Logger({ logLevel: 'SILENT' });

  beforeAll(async () => {
    await DynamoDBTestSetup.initialize();
    docClient = DynamoDBTestSetup.getDocClient();
    await DynamoDBTestSetup.createNotificationConfigTable(notificationConfigTableName);
    await DynamoDBTestSetup.createNotificationBatchesTable(notificationBatchesTableName);
    await DynamoDBTestSetup.createFindingsTable(findingsTableName);
    await DynamoDBTestSetup.createRemediationHistoryTable(remediationHistoryTableName);
  });

  afterAll(async () => {
    await DynamoDBTestSetup.deleteTable(notificationConfigTableName);
    await DynamoDBTestSetup.deleteTable(notificationBatchesTableName);
    await DynamoDBTestSetup.deleteTable(findingsTableName);
    await DynamoDBTestSetup.deleteTable(remediationHistoryTableName);
  });

  beforeEach(async () => {
    snsMock.reset();
    (sendMetrics as jest.Mock).mockClear();
    snsMock.on(PublishCommand).resolves({ MessageId: 'mock-msg-id' });
    s3Mock.reset();
    s3Mock.on(PutObjectCommand).resolves({});
    await DynamoDBTestSetup.clearTable(notificationConfigTableName, 'notificationConfig');
    await DynamoDBTestSetup.clearTable(notificationBatchesTableName, 'notificationBatches');
    await DynamoDBTestSetup.clearTable(findingsTableName, 'findings');
    await DynamoDBTestSetup.clearTable(remediationHistoryTableName, 'remediationHistory');

    configRepo = new NotificationConfigurationRepository(notificationConfigTableName, docClient);
    batchRepo = new NotificationBatchRepository(principal, notificationBatchesTableName, docClient);

    service = new BatchProcessorService(
      notificationConfigTableName,
      notificationBatchesTableName,
      findingsTableName,
      remediationHistoryTableName,
      docClient,
      logger,
      snsMock as unknown as SNSClient,
      channelFanoutTopicArn,
      new S3Client({}),
      'test-csv-export-bucket',
    );
  });

  describe('processBatches', () => {
    it('should process a ready batch and publish to SNS', async () => {
      const config = createMockConfig();
      await configRepo.create(config, principal);
      await insertFinding(docClient, FINDING_ID_1, 'NOT_STARTED');

      const batch = createOpenBatch(config.configId, PAST_WINDOW_END, [FINDING_ID_1]);
      await batchRepo.appendEventId(config.configId, PAST_WINDOW_END, FINDING_ID_1, 'findingIds', batch.expireAt);

      const result = await service.processBatches();

      expect(result.processedCount).toBe(1);
      expect(result.sentCount).toBe(1);
      expect(result.skippedCount).toBe(0);
      expect(result.failedCount).toBe(0);
      expect(snsMock.commandCalls(PublishCommand)).toHaveLength(1);

      const snsCall = snsMock.commandCalls(PublishCommand)[0];
      const message = JSON.parse(snsCall.args[0].input.Message!);
      expect(message.isBatch).toBe(true);
      expect(message.configId).toBe(config.configId);
      expect(message.findingCount).toBe(1);
    });

    it('should emit a batch_processing_time success metric for a processed batch', async () => {
      // ARRANGE
      const config = createMockConfig();
      await configRepo.create(config, principal);
      await insertFinding(docClient, FINDING_ID_1, 'NOT_STARTED');
      await batchRepo.appendEventId(config.configId, PAST_WINDOW_END, FINDING_ID_1, 'findingIds', 9999999999);

      // ACT
      await service.processBatches();

      // ASSERT
      expect(sendMetrics).toHaveBeenCalledWith({
        batch_processing_time: expect.any(Number),
        config_id: config.configId,
        result: 'success',
      });
    });

    it('should emit a batch_processing_time failed metric when batch processing throws', async () => {
      // ARRANGE
      const config = createMockConfig();
      await configRepo.create(config, principal);
      await insertFinding(docClient, FINDING_ID_1, 'NOT_STARTED');
      await batchRepo.appendEventId(config.configId, PAST_WINDOW_END, FINDING_ID_1, 'findingIds', 9999999999);
      snsMock.on(PublishCommand).rejects(new Error('SNS publish failed'));

      // ACT
      const result = await service.processBatches();

      // ASSERT
      expect(result.failedCount).toBe(1);
      expect(sendMetrics).toHaveBeenCalledWith({
        batch_processing_time: expect.any(Number),
        config_id: config.configId,
        result: 'failed',
      });
    });

    it('should skip configs with batching disabled', async () => {
      const config = createMockConfig({ batchWindow: { enabled: false } });
      await configRepo.create(config, principal);

      const result = await service.processBatches();

      expect(result.processedCount).toBe(0);
      expect(snsMock.commandCalls(PublishCommand)).toHaveLength(0);
    });

    it('should not process batches whose window has not elapsed', async () => {
      const config = createMockConfig();
      await configRepo.create(config, principal);

      await batchRepo.appendEventId(config.configId, FUTURE_WINDOW_END, FINDING_ID_1, 'findingIds', 9999999999);

      const result = await service.processBatches();

      expect(result.processedCount).toBe(0);
      expect(snsMock.commandCalls(PublishCommand)).toHaveLength(0);
    });

    it('should skip batch when config is disabled and update status to dispatched', async () => {
      const config = createMockConfig({ enabled: false });
      await configRepo.create(config, principal);
      await batchRepo.appendEventId(config.configId, PAST_WINDOW_END, FINDING_ID_1, 'findingIds', 9999999999);

      const result = await service.processBatches();

      expect(result.processedCount).toBe(1);
      expect(result.skippedCount).toBe(1);
      expect(result.sentCount).toBe(0);
      expect(snsMock.commandCalls(PublishCommand)).toHaveLength(0);

      // Verify the batch status was transitioned to 'dispatched' (not stuck in 'processing')
      const openBatches = await batchRepo.queryOpenBatchesReady(config.configId, new Date().toISOString());
      expect(openBatches).toHaveLength(0);
    });

    it('should roll back batch status to open when all channels fail', async () => {
      const config = createMockConfig();
      await configRepo.create(config, principal);
      await insertFinding(docClient, FINDING_ID_1, 'NOT_STARTED');
      await batchRepo.appendEventId(config.configId, PAST_WINDOW_END, FINDING_ID_1, 'findingIds', 9999999999);

      snsMock.on(PublishCommand).rejects(new Error('SNS publish failed'));

      const result = await service.processBatches();

      expect(result.failedCount).toBe(1);
      expect(result.sentCount).toBe(0);

      // Verify the batch status was rolled back to 'open' so it can be retried
      const batches = await batchRepo.queryByConfigId(config.configId);
      expect(batches).toHaveLength(1);
      expect(batches[0].status).toBe('open');
    });

    it('should mark dispatched on partial SNS failure to avoid duplicate notifications', async () => {
      const config = createMockConfig({
        deliveryChannels: [
          {
            type: 'email',
            enabled: true,
            recipients: [{ recipientType: 'custom', emailAddresses: ['test@example.com'] }],
          },
          {
            type: 'slack',
            enabled: true,
            credentialsSecretArn: 'arn:aws:secretsmanager:us-east-1:123456789012:secret:asr/notifications/slack',
          },
        ],
      });
      await configRepo.create(config, principal);
      await insertFinding(docClient, FINDING_ID_1, 'NOT_STARTED');
      await batchRepo.appendEventId(config.configId, PAST_WINDOW_END, FINDING_ID_1, 'findingIds', 9999999999);

      // First call succeeds (email), second call fails (slack)
      snsMock.on(PublishCommand).resolvesOnce({ MessageId: 'msg-1' }).rejectsOnce(new Error('Slack publish failed'));

      const result = await service.processBatches();

      // Partial failure: batch is dispatched (not rolled back) to prevent duplicates
      expect(result.sentCount).toBe(1);
      expect(result.failedCount).toBe(0);

      const batches = await batchRepo.queryByConfigId(config.configId);
      expect(batches).toHaveLength(1);
      expect(batches[0].status).toBe('dispatched');
    });

    it('should roll back batch status when filterRemediatedFindings fails', async () => {
      const config = createMockConfig();
      await configRepo.create(config, principal);
      await insertFinding(docClient, FINDING_ID_1, 'NOT_STARTED');
      await batchRepo.appendEventId(config.configId, PAST_WINDOW_END, FINDING_ID_1, 'findingIds', 9999999999);

      // Simulate a transient DynamoDB error during finding lookup
      jest
        .spyOn(FindingRepository.prototype, 'findByFindingIds')
        .mockRejectedValueOnce(new Error('Transient DDB error'));

      const result = await service.processBatches();

      expect(result.failedCount).toBe(1);
      expect(result.sentCount).toBe(0);

      // Verify the batch was rolled back to 'open' instead of stuck in 'processing'
      const batches = await batchRepo.queryByConfigId(config.configId);
      expect(batches).toHaveLength(1);
      expect(batches[0].status).toBe('open');

      jest.restoreAllMocks();
    });

    it('should exclude remediated findings from batch notification', async () => {
      const config = createMockConfig();
      await configRepo.create(config, principal);

      await insertFinding(docClient, FINDING_ID_1, 'SUCCESS');
      await insertFinding(docClient, FINDING_ID_2, 'NOT_STARTED');

      await batchRepo.appendEventId(config.configId, PAST_WINDOW_END, FINDING_ID_1, 'findingIds', 9999999999);
      await batchRepo.appendEventId(config.configId, PAST_WINDOW_END, FINDING_ID_2, 'findingIds', 9999999999);

      const result = await service.processBatches();

      expect(result.sentCount).toBe(1);
      const snsCall = snsMock.commandCalls(PublishCommand)[0];
      const message = JSON.parse(snsCall.args[0].input.Message!);
      expect(message.findingCount).toBe(1);
    });

    it('should warn with the config id when a finding id carries no derivable partition key', async () => {
      // ARRANGE — a bare-hash id (Macie's Security Hub V2 FindingInfoUid shape) encodes no
      // partition key, so it is never queried and its finding cannot appear in the batch. That is
      // materially different from being filtered out as remediated, so it must be reported.
      const config = createMockConfig();
      await configRepo.create(config, principal);

      const nonDerivableId = '9f8e7d6c5b4a392817060f1e2d3c4b5a' as FindingId;
      await insertFinding(docClient, FINDING_ID_1, 'NOT_STARTED');
      await batchRepo.appendEventId(config.configId, PAST_WINDOW_END, FINDING_ID_1, 'findingIds', 9999999999);
      await batchRepo.appendEventId(config.configId, PAST_WINDOW_END, nonDerivableId, 'findingIds', 9999999999);

      const warnSpy = jest.spyOn(logger, 'warn');

      // ACT
      const result = await service.processBatches();

      // ASSERT — the derivable finding still ships, and the omission is logged with configId
      expect(result.sentCount).toBe(1);
      expect(warnSpy).toHaveBeenCalledWith(
        'Findings omitted from batch: no partition key derivable from the finding id',
        expect.objectContaining({
          configId: config.configId,
          nonDerivableCount: 1,
          nonDerivableIds: [nonDerivableId],
        }),
      );

      warnSpy.mockRestore();
    });

    it('should skip batch when all findings are remediated', async () => {
      const config = createMockConfig();
      await configRepo.create(config, principal);

      await insertFinding(docClient, FINDING_ID_1, 'SUCCESS');
      await batchRepo.appendEventId(config.configId, PAST_WINDOW_END, FINDING_ID_1, 'findingIds', 9999999999);

      const result = await service.processBatches();

      expect(result.processedCount).toBe(1);
      expect(result.skippedCount).toBe(1);
      expect(result.sentCount).toBe(0);
      expect(snsMock.commandCalls(PublishCommand)).toHaveLength(0);
    });

    it('should skip batch when no delivery channels are enabled', async () => {
      const config = createMockConfig({
        deliveryChannels: [
          {
            type: 'email',
            enabled: false,
            recipients: [{ recipientType: 'custom', emailAddresses: ['test@example.com'] }],
          },
        ],
      });
      await configRepo.create(config, principal);
      await insertFinding(docClient, FINDING_ID_1, 'NOT_STARTED');
      await batchRepo.appendEventId(config.configId, PAST_WINDOW_END, FINDING_ID_1, 'findingIds', 9999999999);

      const result = await service.processBatches();

      expect(result.processedCount).toBe(1);
      expect(result.skippedCount).toBe(1);
      expect(snsMock.commandCalls(PublishCommand)).toHaveLength(0);
    });

    it('should publish to multiple enabled channels', async () => {
      const config = createMockConfig({
        deliveryChannels: [
          {
            type: 'email',
            enabled: true,
            recipients: [{ recipientType: 'custom', emailAddresses: ['test@example.com'] }],
          },
          {
            type: 'slack',
            enabled: true,
            credentialsSecretArn: 'arn:aws:secretsmanager:us-east-1:123456789012:secret:asr/notifications/slack',
          },
        ],
      });
      await configRepo.create(config, principal);
      await insertFinding(docClient, FINDING_ID_1, 'NOT_STARTED');
      await batchRepo.appendEventId(config.configId, PAST_WINDOW_END, FINDING_ID_1, 'findingIds', 9999999999);

      const result = await service.processBatches();

      expect(result.sentCount).toBe(1);
      expect(snsMock.commandCalls(PublishCommand)).toHaveLength(2);

      const channelTypes = snsMock
        .commandCalls(PublishCommand)
        .map((call) => call.args[0].input.MessageAttributes?.channelType?.StringValue);
      expect(channelTypes).toContain('email');
      expect(channelTypes).toContain('slack');
    });

    it('should process batches with only remediation events', async () => {
      const config = createMockConfig({ notificationType: 'remediation' });
      await configRepo.create(config, principal);

      await batchRepo.appendEventId(config.configId, PAST_WINDOW_END, 'rem-1', 'remediationIds', 9999999999);

      const result = await service.processBatches();

      expect(result.sentCount).toBe(1);
      expect(snsMock.commandCalls(PublishCommand)).toHaveLength(1);

      const message = JSON.parse(snsMock.commandCalls(PublishCommand)[0].args[0].input.Message!);
      expect(message.remediationCount).toBe(1);
    });

    it('should deduplicate remediationIds so the count reflects unique remediations', async () => {
      // ARRANGE
      const config = createMockConfig({ notificationType: 'remediation' });
      await configRepo.create(config, principal);

      // Simulate the orchestrator publishing QUEUED and SUCCESS events for the same finding
      await batchRepo.appendEventId(config.configId, PAST_WINDOW_END, 'rem-1', 'remediationIds', 9999999999);
      await batchRepo.appendEventId(config.configId, PAST_WINDOW_END, 'rem-1', 'remediationIds', 9999999999);
      await batchRepo.appendEventId(config.configId, PAST_WINDOW_END, 'rem-2', 'remediationIds', 9999999999);
      await batchRepo.appendEventId(config.configId, PAST_WINDOW_END, 'rem-2', 'remediationIds', 9999999999);

      // ACT
      const result = await service.processBatches();

      // ASSERT
      expect(result.sentCount).toBe(1);
      const message = JSON.parse(snsMock.commandCalls(PublishCommand)[0].args[0].input.Message!);
      expect(message.remediationCount).toBe(2);
    });

    it('should fetch remediation history and export CSV for remediation-only batches', async () => {
      const config = createMockConfig({ notificationType: 'remediation' });
      await configRepo.create(config, principal);

      const remediatedArn =
        'arn:aws:securityhub:us-east-1:123456789012:security-control/S3.1/finding/rem-csv-1' as FindingId;
      await batchRepo.appendEventId(config.configId, PAST_WINDOW_END, remediatedArn, 'remediationIds', 9999999999);

      // Insert a history entry — the batch processor should source the CSV row from this table
      // (not the findings table), which is the entire point of this code path.
      await insertRemediationHistory(docClient, remediatedArn, 'SUCCESS');

      const result = await service.processBatches();

      expect(result.sentCount).toBe(1);

      // Verify the CSV was written to S3 with the history-derived row.
      const putCalls = s3Mock.commandCalls(PutObjectCommand);
      expect(putCalls).toHaveLength(1);
      const putInput = putCalls[0].args[0].input;
      expect(putInput.Bucket).toBe('test-csv-export-bucket');
      expect(putInput.Key).toContain(`batch-export-remediation-${config.configId}`);
      expect(putInput.ContentType).toBe('text/csv');
      const csvBody = putInput.Body as string;
      expect(csvBody).toContain(remediatedArn);
      expect(csvBody).toContain('S3.1');
      expect(csvBody).toContain('SUCCESS');

      // Verify the SNS message includes the presigned export URL and event summaries from history.
      const message = JSON.parse(snsMock.commandCalls(PublishCommand)[0].args[0].input.Message!);
      expect(message.remediationCount).toBe(1);
      expect(message.exportUrl).toEqual(expect.stringContaining('test-csv-export-bucket'));
      expect(message.linkAccessExpirationTime).toEqual(expect.any(String));
      expect(message.eventSummaries).toBeDefined();
      expect(message.eventSummaries[0].controlId).toContain('S3.1');
      expect(message.eventSummaries[0].remediationStatus).toBe('SUCCESS');
    });

    it('should emit IaC CSV columns only for SUCCESS remediation rows, keyed off canonical status not display detail', async () => {
      const config = createMockConfig({
        notificationType: 'remediation',
        contentOptions: {
          includeManualRemediationLink: false,
          includeRemediationDeadline: false,
          enforceDeadline: false,
          includeIaCSnippet: true,
          iacFormats: ['cloudformation-yaml', 'terraform', 'cloudformation-json', 'cdk'],
          includeEnableAutomationLink: false,
        },
      });
      await configRepo.create(config, principal);

      const successArn =
        'arn:aws:securityhub:us-east-1:123456789012:security-control/S3.1/finding/iac-success' as FindingId;
      const failedArn =
        'arn:aws:securityhub:us-east-1:123456789012:security-control/S3.2/finding/iac-failed' as FindingId;

      await batchRepo.appendEventId(config.configId, PAST_WINDOW_END, successArn, 'remediationIds', 9999999999);
      await batchRepo.appendEventId(config.configId, PAST_WINDOW_END, failedArn, 'remediationIds', 9999999999);

      await insertRemediationHistory(docClient, successArn, 'SUCCESS');
      await insertRemediationHistory(docClient, failedArn, 'FAILED');

      const result = await service.processBatches();
      expect(result.sentCount).toBe(1);

      const putCalls = s3Mock.commandCalls(PutObjectCommand);
      expect(putCalls).toHaveLength(1);
      const csvBody = putCalls[0].args[0].input.Body as string;
      const rows = csvBody.split('\n');

      // Header should include IaC columns
      expect(rows[0]).toContain('IaC CloudFormation (YAML)');
      expect(rows[0]).toContain('IaC Terraform');

      // SUCCESS row should have IaC URLs
      const successRow = rows.find((r) => r.includes('iac-success'));
      expect(successRow).toContain('/iac/');
      expect(successRow).toContain('format=cloudformation-yaml');

      // FAILED row should NOT have IaC URLs (cells empty)
      const failedRow = rows.find((r) => r.includes('iac-failed'));
      expect(failedRow).not.toContain('/iac/');
    });

    it('should NOT emit IaC CSV columns for finding-type exports (IaC is remediation-only)', async () => {
      const config = createMockConfig({
        notificationType: 'finding',
        contentOptions: {
          includeManualRemediationLink: false,
          includeRemediationDeadline: false,
          enforceDeadline: false,
          includeIaCSnippet: true,
          iacFormats: ['cloudformation-yaml', 'terraform', 'cloudformation-json', 'cdk'],
          includeEnableAutomationLink: false,
        },
      });
      await configRepo.create(config, principal);

      // A finding awaiting remediation. Finding-type exports must never surface
      // IaC columns, since IaC links are remediation-only.
      await insertFinding(docClient, FINDING_ID_1, 'NOT_STARTED');
      await batchRepo.appendEventId(config.configId, PAST_WINDOW_END, FINDING_ID_1, 'findingIds', 9999999999);

      const result = await service.processBatches();
      expect(result.sentCount).toBe(1);

      const putCalls = s3Mock.commandCalls(PutObjectCommand);
      expect(putCalls).toHaveLength(1);
      const csvBody = putCalls[0].args[0].input.Body as string;
      const rows = csvBody.split('\n');

      // Header must not contain any IaC columns, and no row should carry an
      // IaC download URL.
      expect(rows[0]).not.toContain('IaC CloudFormation (YAML)');
      expect(rows[0]).not.toContain('IaC CloudFormation (JSON)');
      expect(rows[0]).not.toContain('IaC Terraform');
      expect(rows[0]).not.toContain('IaC CDK (TypeScript)');
      expect(csvBody).not.toContain('/iac/');
    });

    it('should skip CSV export when remediationIds cannot be resolved to findings', async () => {
      const config = createMockConfig({ notificationType: 'remediation' });
      await configRepo.create(config, principal);

      // Unparseable remediation ID → findByFindingIds returns []
      await batchRepo.appendEventId(config.configId, PAST_WINDOW_END, 'not-an-arn', 'remediationIds', 9999999999);

      const result = await service.processBatches();

      expect(result.sentCount).toBe(1);
      const message = JSON.parse(snsMock.commandCalls(PublishCommand)[0].args[0].input.Message!);
      expect(message.exportUrl).toBeUndefined();
    });

    it('should return zero counts when no configs exist', async () => {
      const result = await service.processBatches();

      expect(result).toEqual({ processedCount: 0, sentCount: 0, skippedCount: 0, failedCount: 0 });
    });

    it('should process multiple configs independently', async () => {
      const config1 = createMockConfig({
        configId: asConfigId('11111111-1111-1111-1111-111111111111'),
        name: 'Config One',
      });
      const config2 = createMockConfig({
        configId: asConfigId('22222222-2222-2222-2222-222222222222'),
        name: 'Config Two',
      });
      await configRepo.create(config1, principal);
      await configRepo.create(config2, principal);

      await insertFinding(docClient, FINDING_ID_1, 'NOT_STARTED');
      await insertFinding(docClient, FINDING_ID_2, 'NOT_STARTED');

      await batchRepo.appendEventId(config1.configId, PAST_WINDOW_END, FINDING_ID_1, 'findingIds', 9999999999);
      await batchRepo.appendEventId(config2.configId, PAST_WINDOW_END, FINDING_ID_2, 'findingIds', 9999999999);

      const result = await service.processBatches();

      expect(result.processedCount).toBe(2);
      expect(result.sentCount).toBe(2);
      expect(snsMock.commandCalls(PublishCommand)).toHaveLength(2);
    });

    describe('overflow aggregation', () => {
      it('aggregates overflow items into a single notification per window', async () => {
        // ARRANGE — primary batch with one finding, plus two overflow continuations
        // seeded with additional findings. Without aggregation, the batch processor
        // would have emitted three separate notifications and leaked the overflow
        // suffix through `batchWindowEnd`.
        const config = createMockConfig();
        await configRepo.create(config, principal);

        const overflowFinding1 =
          'arn:aws:securityhub:us-east-1:123456789012:security-control/S3.3/finding/ovf-1' as FindingId;
        const overflowFinding2 =
          'arn:aws:securityhub:us-east-1:123456789012:security-control/S3.4/finding/ovf-2' as FindingId;
        await insertFinding(docClient, FINDING_ID_1, 'NOT_STARTED');
        await insertFinding(docClient, overflowFinding1, 'NOT_STARTED');
        await insertFinding(docClient, overflowFinding2, 'NOT_STARTED');

        const expireAt = 9999999999;
        await batchRepo.appendEventId(config.configId, PAST_WINDOW_END, FINDING_ID_1, 'findingIds', expireAt);
        // Overflow keys are `~${windowEnd}#NNNN`; createOpenBatch derives expireAt from
        // the windowEnd which produces NaN for composite keys, so override it.
        await docClient.send(
          new PutCommand({
            TableName: notificationBatchesTableName,
            Item: {
              ...createOpenBatch(config.configId, PAST_WINDOW_END, [overflowFinding1]),
              windowEnd: `~${PAST_WINDOW_END}#0001`,
              expireAt,
            },
          }),
        );
        await docClient.send(
          new PutCommand({
            TableName: notificationBatchesTableName,
            Item: {
              ...createOpenBatch(config.configId, PAST_WINDOW_END, [overflowFinding2]),
              windowEnd: `~${PAST_WINDOW_END}#0002`,
              expireAt,
            },
          }),
        );

        const result = await service.processBatches();

        // ASSERT — one logical batch, one SNS message, finding counts reflect the merge.
        expect(result.processedCount).toBe(1);
        expect(result.sentCount).toBe(1);
        expect(snsMock.commandCalls(PublishCommand)).toHaveLength(1);

        const message = JSON.parse(snsMock.commandCalls(PublishCommand)[0].args[0].input.Message!);
        expect(message.findingCount).toBe(3);
        expect(message.batchWindowEnd).toBeUndefined();

        // Overflow items are intentionally left in 'open' and age out via DynamoDB TTL;
        // they sort outside the windowEnd range of queryOpenBatchesReady so they cannot
        // be re-read as independent batches.
        const readyNext = await batchRepo.queryOpenBatchesReady(config.configId, new Date().toISOString());
        expect(readyNext).toHaveLength(0);
      });

      it('aggregates overflow items into the remediated-skip path', async () => {
        const config = createMockConfig();
        await configRepo.create(config, principal);

        const remediated = 'arn:aws:securityhub:us-east-1:123456789012:security-control/S3.5/finding/done' as FindingId;
        await insertFinding(docClient, FINDING_ID_1, 'SUCCESS');
        await insertFinding(docClient, remediated, 'SUCCESS');
        await batchRepo.appendEventId(config.configId, PAST_WINDOW_END, FINDING_ID_1, 'findingIds', 9999999999);
        await docClient.send(
          new PutCommand({
            TableName: notificationBatchesTableName,
            Item: {
              ...createOpenBatch(config.configId, PAST_WINDOW_END, [remediated]),
              windowEnd: `~${PAST_WINDOW_END}#0001`,
              expireAt: 9999999999,
            },
          }),
        );

        const result = await service.processBatches();

        expect(result.skippedCount).toBe(1);
        expect(snsMock.commandCalls(PublishCommand)).toHaveLength(0);

        // Primary is dispatched; overflow stays 'open' until TTL removes it.
        const primary = await batchRepo.findById(config.configId, PAST_WINDOW_END);
        expect(primary?.status).toBe('dispatched');
      });
    });

    describe('orphan batches (config deleted mid-batch)', () => {
      it('drains the batch and skips publish when the config disappears between snapshot and flush', async () => {
        const config = createMockConfig();
        await configRepo.create(config, principal);
        await insertFinding(docClient, FINDING_ID_1, 'NOT_STARTED');
        await batchRepo.appendEventId(config.configId, PAST_WINDOW_END, FINDING_ID_1, 'findingIds', 9999999999);

        jest.spyOn(NotificationConfigurationRepository.prototype, 'findConfigById').mockResolvedValueOnce(undefined);

        const result = await service.processBatches();

        expect(result.processedCount).toBe(1);
        expect(result.sentCount).toBe(0);
        expect(result.skippedCount).toBe(1);
        expect(result.failedCount).toBe(0);
        expect(snsMock.commandCalls(PublishCommand)).toHaveLength(0);

        const remaining = await batchRepo.queryOpenBatchesReady(config.configId, new Date().toISOString());
        expect(remaining).toHaveLength(0);

        jest.restoreAllMocks();
      });

      it('continues processing other configs when one is orphaned', async () => {
        const orphan = createMockConfig({
          configId: asConfigId('11111111-1111-1111-1111-111111111111'),
          name: 'Orphan Config',
        });
        const healthy = createMockConfig({
          configId: asConfigId('22222222-2222-2222-2222-222222222222'),
          name: 'Healthy Config',
        });
        await configRepo.create(orphan, principal);
        await configRepo.create(healthy, principal);

        await insertFinding(docClient, FINDING_ID_1, 'NOT_STARTED');
        await insertFinding(docClient, FINDING_ID_2, 'NOT_STARTED');
        await batchRepo.appendEventId(orphan.configId, PAST_WINDOW_END, FINDING_ID_1, 'findingIds', 9999999999);
        await batchRepo.appendEventId(healthy.configId, PAST_WINDOW_END, FINDING_ID_2, 'findingIds', 9999999999);

        const realFindConfigById = NotificationConfigurationRepository.prototype.findConfigById;
        jest.spyOn(NotificationConfigurationRepository.prototype, 'findConfigById').mockImplementation(async function (
          this: NotificationConfigurationRepository,
          configId: string,
        ) {
          if (configId === orphan.configId) return undefined;
          return realFindConfigById.call(this, configId);
        });

        const result = await service.processBatches();

        expect(result.processedCount).toBe(2);
        expect(result.sentCount).toBe(1);
        expect(result.skippedCount).toBe(1);
        expect(result.failedCount).toBe(0);
        expect(snsMock.commandCalls(PublishCommand)).toHaveLength(1);

        jest.restoreAllMocks();
      });
    });
  });
});
