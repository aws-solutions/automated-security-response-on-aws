// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { DynamoDBTestSetup } from '../../common/__tests__/dynamodbSetup';

// Initialize the test client (this creates the client but doesn't create tables yet)
// We can call this synchronously even though it's marked async because it doesn't await anything
void DynamoDBTestSetup.initialize();
const testClient = DynamoDBTestSetup.getDocClient();

// Mock createDynamoDBClient before any imports - return the initialized test client
const mockCreateDynamoDBClient = jest.fn(() => testClient);
jest.mock('../../common/utils/dynamodb', () => {
  return {
    createDynamoDBClient: mockCreateDynamoDBClient,
  };
});

const mockGetCachedParameter = jest.fn();
const mockGetCachedParametersByPath = jest.fn();
const mockClearSSMCache = jest.fn();

jest.mock('../../common/utils/ssmCache', () => ({
  getCachedParameter: mockGetCachedParameter,
  getCachedParametersByPath: mockGetCachedParametersByPath,
  clearSSMCache: mockClearSSMCache,
  getSSMClient: jest.fn(() => ({})),
}));

const mockCaptureAWSv3Client = jest.fn((client) => client);
const mockCaptureLambdaHandler = jest.fn();
jest.mock('../../common/utils/tracer', () => ({
  getTracer: jest.fn(() => ({
    captureAWSv3Client: mockCaptureAWSv3Client,
    captureLambdaHandler: mockCaptureLambdaHandler,
  })),
}));

import { ASFFFinding, ASFFSeverity, OCSFComplianceFinding } from '@asr/data-models';
import { SFNClient, StartExecutionCommand } from '@aws-sdk/client-sfn';
import { GetParameterCommand, SSMClient } from '@aws-sdk/client-ssm';
import { DynamoDBDocumentClient, GetCommand, PutCommand } from '@aws-sdk/lib-dynamodb';
import { Context, SQSBatchResponse, SQSEvent, SQSRecord } from 'aws-lambda';
import { mockClient } from 'aws-sdk-client-mock';
import nock from 'nock';
import { configTableName, findingsTableName, remediationHistoryTableName } from '../../common/__tests__/envSetup';
import { FINDING_PRINCIPAL } from '../../common/constants/apiConstant';
import { FindingRepository } from '../../common/repositories/findingRepository';
import { normalizeResourceType } from '../../common/services/findingDataService';
import { executeOrchestrator } from '../../common/utils/orchestrator';
import { calculateTtlTimestamp } from '../../common/utils/ttlUtils';
import { PreProcessor, handler } from '../preProcessor';

describe('PreProcessor Lambda', () => {
  let context: Context;
  let docClient: DynamoDBDocumentClient;
  let sfnMock = mockClient(SFNClient);
  const ssmMock = mockClient(SSMClient);
  const ASFFFindingId =
    'arn:aws:securityhub:us-east-1:123456789012:subscription/aws-foundational-security-best-practices/v/1.0.0/S3.1/finding/asff-finding-id';
  const OCSFFindingId =
    'arn:aws:securityhub:us-east-1:123456789012:subscription/aws-foundational-security-best-practices/v/1.0.0/S3.1/finding/ocsf-test';

  const createMockFinding = (overrides: Partial<ASFFFinding> = {}): ASFFFinding => ({
    SchemaVersion: '2018-10-08',
    Id: ASFFFindingId,
    ProductArn: 'arn:aws:securityhub:us-east-1::product/aws/securityhub',
    GeneratorId: 'aws-foundational-security-best-practices/v/1.0.0/S3.1',
    AwsAccountId: '123456789012',
    Types: ['Software and Configuration Checks/AWS Security Best Practices'],
    CreatedAt: '2023-01-01T00:00:00.000Z',
    UpdatedAt: '2024-01-01T00:00:00.000Z',
    Severity: { Label: 'HIGH', Normalized: 70 },
    Title: 'S3 bucket should prohibit public read access',
    Description: 'This control checks whether your S3 buckets allow public read access.',
    Resources: [{ Type: 'AwsS3Bucket', Id: 'arn:aws:s3:::test-bucket', Region: 'us-east-1', Partition: 'aws' }],
    Compliance: { Status: 'FAILED', SecurityControlId: 'S3.1' },
    Region: 'us-east-1',
    WorkflowState: 'NEW',
    RecordState: 'ACTIVE',
    ...overrides,
  });

  const createMockOCSFFinding = (overrides: Partial<OCSFComplianceFinding> = {}): OCSFComplianceFinding => ({
    class_uid: 2003,
    activity_id: 1,
    category_uid: 1,
    severity_id: 3,
    type_uid: 1,
    time: 1672531200,
    status_id: 0,
    severity: 'High',
    cloud: {
      account: { uid: '123456789012' },
      region: 'us-east-1',
    },
    finding_info: {
      uid: OCSFFindingId,
      created_time: 1672531200,
      created_time_dt: '2023-01-01T00:00:00Z',
      modified_time_dt: '2024-01-01T00:00:00Z',
      title: 'OCSF Test Finding',
    },
    compliance: {
      status: 'fail',
      control: 'S3.1',
      standards: ['standards/nist-800-53/v/5.0.0'],
    },
    resources: [
      {
        type: 'AWS::S3::Bucket',
        role_id: 'role',
        uid: 'test-bucket',
        uid_alt: 'arn:aws:s3:::test-bucket',
        region: 'us-east-1',
        owner: {
          account: { uid: '123456789012' },
        },
      },
    ],
    ...overrides,
  });

  const createSQSRecord = (
    finding: ASFFFinding | OCSFComplianceFinding,
    additionalPayload = {},
    messageId?: string,
  ): SQSRecord => ({
    messageId: messageId ?? 'test-message-id',
    receiptHandle: 'test-receipt-handle',
    body: JSON.stringify({
      detail: { findings: [finding] },
      'detail-type': 'Imported Finding',
      source: 'aws.securityhub',
      account: '123456789012',
      ...additionalPayload,
    }),
    attributes: {
      ApproximateReceiveCount: '1',
      SentTimestamp: '1234567890000',
      SenderId: 'test-sender',
      ApproximateFirstReceiveTimestamp: '1234567890000',
    },
    messageAttributes: {},
    md5OfBody: 'test-md5',
    eventSource: 'aws:sqs',
    eventSourceARN: 'arn:aws:sqs:us-east-1:123456789012:test-queue',
    awsRegion: 'us-east-1',
  });

  const setupMetricsMocks = () => {
    ssmMock.reset();
    nock.cleanAll();

    // Cache mocks are already set up in beforeEach, just ensure SSM fallback
    ssmMock
      .resolves({ Parameter: { Value: 'test-uuid' } })
      .on(GetParameterCommand, { Name: '/Solutions/SO0111/version' })
      .resolves({ Parameter: { Value: '1.0.0' } });

    return nock('https://metrics.awssolutionsbuilder.com').post('/generic').reply(200).persist();
  };

  const setupFilterMetricsMocks = () => {
    mockGetCachedParametersByPath.mockImplementation((path: string, logger?: any) => {
      return Promise.resolve({});
    });

    ssmMock
      .on(GetParameterCommand, { Name: expect.stringContaining('Filters') })
      .resolves({ Parameter: { Value: 'Disabled' } });

    return setupMetricsMocks();
  };

  beforeAll(async () => {
    docClient = DynamoDBTestSetup.getDocClient();
    await DynamoDBTestSetup.createFindingsTable(findingsTableName);
    await DynamoDBTestSetup.createConfigTable(configTableName);
    await DynamoDBTestSetup.createRemediationHistoryTable(remediationHistoryTableName);
  });

  afterAll(async () => {
    await DynamoDBTestSetup.deleteTable(findingsTableName);
    await DynamoDBTestSetup.deleteTable(configTableName);
    await DynamoDBTestSetup.deleteTable(remediationHistoryTableName);
  });

  beforeEach(async () => {
    sfnMock.restore();
    sfnMock = mockClient(SFNClient);
    ssmMock.reset();
    nock.cleanAll();
    mockCreateDynamoDBClient.mockClear();
    mockCaptureAWSv3Client.mockClear();

    mockGetCachedParameter.mockClear();
    mockGetCachedParametersByPath.mockClear();
    mockClearSSMCache.mockClear();

    mockGetCachedParameter.mockImplementation((paramName: string, logger?: any) => {
      switch (paramName) {
        case '/Solutions/SO0111/metrics_uuid':
          return Promise.resolve('test-uuid');
        case '/Solutions/SO0111/version':
          return Promise.resolve('1.0.0');
        default:
          return Promise.resolve('some-value');
      }
    });

    mockGetCachedParametersByPath.mockImplementation((path: string, logger?: any) => {
      return Promise.resolve({});
    });

    const docClient = DynamoDBTestSetup.getDocClient();
    mockCaptureAWSv3Client.mockImplementation((client) => client || docClient);
    mockCaptureLambdaHandler.mockReturnValue(
      () => (target: any, propertyKey: string, descriptor: PropertyDescriptor) => descriptor,
    );

    // Mock metrics endpoint for normalizeFinding calls
    nock('https://metrics.awssolutionsbuilder.com').post('/generic').reply(200, { status: 'success' }).persist();

    // Mock SSM client for normalizeFinding calls
    ssmMock.on(GetParameterCommand).resolves({
      Parameter: { Value: 'some-value' },
    });

    mockCreateDynamoDBClient.mockReturnValue(docClient);

    context = {
      callbackWaitsForEmptyEventLoop: true,
      functionName: 'test-function',
      functionVersion: '1',
      invokedFunctionArn: 'test-arn',
      memoryLimitInMB: '128',
      awsRequestId: 'test-request-id',
      logGroupName: 'test-log-group',
      logStreamName: 'test-log-stream',
      getRemainingTimeInMillis: () => 1000,
      done: () => {},
      fail: () => {},
      succeed: () => {},
    };

    // Clear tables
    await DynamoDBTestSetup.clearTable(findingsTableName, 'findings');
    await DynamoDBTestSetup.clearTable(configTableName, 'config');
    await DynamoDBTestSetup.clearTable(remediationHistoryTableName, 'remediationHistory');
  });

  const setupControlConfig = async (controlId: string, enabled: boolean) => {
    await docClient.send(
      new PutCommand({
        TableName: configTableName,
        Item: { controlId, automatedRemediationEnabled: enabled },
      }),
    );
  };

  describe('New Finding Processing', () => {
    it('should create new finding with auto-remediation enabled', async () => {
      const finding = createMockFinding();
      await setupControlConfig('S3.1', true);
      sfnMock.on(StartExecutionCommand).resolves({
        executionArn: 'arn:aws:states:us-east-1:123456789012:execution:test-state-machine:test-execution-id',
      });

      const record = createSQSRecord(finding);
      await PreProcessor.recordHandler(record);

      // Verify finding was created in database
      const result = await docClient.send(
        new GetCommand({
          TableName: findingsTableName,
          Key: { findingType: 'aws-foundational-security-best-practices/v/1.0.0/S3.1', findingId: finding.Id },
        }),
      );

      expect(result.Item).toBeDefined();
      expect(result.Item?.remediationStatus).toBe('IN_PROGRESS');
      expect(result.Item?.findingDescription).toBe(finding.Title);
      expect(result.Item?.accountId).toBe(finding.AwsAccountId);
      expect(result.Item?.resourceId).toBe(finding.Resources[0].Id);
      expect(result.Item?.severity).toBe(finding.Severity.Label);

      // Verify orchestrator was called
      expect(sfnMock.commandCalls(StartExecutionCommand)).toHaveLength(1);
      const orchestratorCall = sfnMock.commandCalls(StartExecutionCommand)[0];
      expect(orchestratorCall.args[0].input.stateMachineArn).toBe(process.env.ORCHESTRATOR_ARN);
    });

    it('should create new finding and history item with auto-remediation enabled', async () => {
      const finding = createMockFinding({
        Id: 'arn:aws:securityhub:us-east-1:123456789012:subscription/aws-foundational-security-best-practices/v/1.0.0/S3.1/finding/history-test-finding',
      });
      await setupControlConfig('S3.1', true);
      sfnMock.on(StartExecutionCommand).resolves({
        executionArn: 'arn:aws:states:us-east-1:123456789012:execution:test-state-machine:history-test-execution-id',
      });

      const record = createSQSRecord(finding);
      await PreProcessor.recordHandler(record);

      const findingResult = await docClient.send(
        new GetCommand({
          TableName: findingsTableName,
          Key: { findingType: 'aws-foundational-security-best-practices/v/1.0.0/S3.1', findingId: finding.Id },
        }),
      );

      expect(findingResult.Item).toBeDefined();
      expect(findingResult.Item?.remediationStatus).toBe('IN_PROGRESS');

      const historyResult = await docClient.send(
        new GetCommand({
          TableName: remediationHistoryTableName,
          Key: {
            findingType: 'aws-foundational-security-best-practices/v/1.0.0/S3.1',
            'findingId#executionId': `${finding.Id}#arn:aws:states:us-east-1:123456789012:execution:test-state-machine:history-test-execution-id`,
          },
        }),
      );

      expect(historyResult.Item).toBeDefined();
      expect(historyResult.Item?.findingId).toBe(finding.Id);
      expect(historyResult.Item?.executionId).toBe(
        'arn:aws:states:us-east-1:123456789012:execution:test-state-machine:history-test-execution-id',
      );
      expect(historyResult.Item?.remediationStatus).toBe('IN_PROGRESS');
      expect(historyResult.Item?.accountId).toBe(finding.AwsAccountId);
      expect(historyResult.Item?.resourceId).toBe(finding.Resources[0].Id);
      expect(historyResult.Item?.severity).toBe(finding.Severity.Label);
      expect(historyResult.Item?.lastUpdatedBy).toBe(FINDING_PRINCIPAL);
    });

    it('should create new finding with auto-remediation disabled', async () => {
      const finding = createMockFinding({
        Id: 'arn:aws:securityhub:us-east-1:123456789012:subscription/aws-foundational-security-best-practices/v/1.0.0/S3.1/finding/test-finding-disabled',
      });
      await setupControlConfig('S3.1', false);

      const record = createSQSRecord(finding);
      await PreProcessor.recordHandler(record);

      // Verify finding was created with NOT_STARTED status
      const result = await docClient.send(
        new GetCommand({
          TableName: findingsTableName,
          Key: { findingType: 'aws-foundational-security-best-practices/v/1.0.0/S3.1', findingId: finding.Id },
        }),
      );

      expect(result.Item?.remediationStatus).toBe('NOT_STARTED');
      expect(sfnMock.commandCalls(StartExecutionCommand)).toHaveLength(0);
    });
  });

  describe('Existing Finding Processing', () => {
    it('should update existing finding and trigger remediation for failed status', async () => {
      const finding = createMockFinding({
        Id: 'arn:aws:securityhub:us-east-1:123456789012:subscription/aws-foundational-security-best-practices/v/1.0.0/S3.1/finding/existing-failed-finding',
      });
      await setupControlConfig('S3.1', true);

      // Create existing finding with FAILED status
      const findingRepo = new FindingRepository('test', findingsTableName, docClient);
      await findingRepo.put({
        findingType: 'aws-foundational-security-best-practices/v/1.0.0/S3.1',
        findingId: finding.Id,
        findingDescription: 'Old description',
        accountId: finding.AwsAccountId,
        resourceId: finding.Resources[0].Id,
        resourceType: finding.Resources[0].Type,
        resourceTypeNormalized: normalizeResourceType(finding.Resources[0].Type),
        severity: 'MEDIUM',
        severityNormalized: 2,
        region: finding.Region!,
        remediationStatus: 'FAILED',
        securityHubUpdatedAtTime: '2023-01-01T00:00:00.000Z',
        lastUpdatedTime: '2023-01-01T00:00:00.000Z',
        'securityHubUpdatedAtTime#findingId': '2023-01-01T00:00:00.000Z#' + finding.Id,
        'severityNormalized#securityHubUpdatedAtTime#findingId': '2#2023-01-01T00:00:00.000Z#' + finding.Id,
        findingJSON: new Uint8Array(),
        findingIdControl: finding.Id + '#aws-foundational-security-best-practices/v/1.0.0/S3.1',
        FINDING_CONSTANT: 'finding',
        suppressed: false,
        creationTime: finding.CreatedAt,
        expireAt: calculateTtlTimestamp('2023-01-01T00:00:00.000Z'),
      });

      sfnMock.on(StartExecutionCommand).resolves({
        executionArn: 'arn:aws:states:us-east-1:123456789012:execution:test-state-machine:test-execution-id-2',
      });

      const record = createSQSRecord(finding);
      await PreProcessor.recordHandler(record);

      // Verify finding was updated
      const result = await docClient.send(
        new GetCommand({
          TableName: findingsTableName,
          Key: { findingType: 'aws-foundational-security-best-practices/v/1.0.0/S3.1', findingId: finding.Id },
        }),
      );

      expect(result.Item?.remediationStatus).toBe('IN_PROGRESS');
      expect(result.Item?.findingDescription).toBe(finding.Title);
      expect(result.Item?.severity).toBe('HIGH');
      expect(sfnMock.commandCalls(StartExecutionCommand)).toHaveLength(1);
    });

    it('should update existing finding and create history item for retry scenario', async () => {
      const finding = createMockFinding({
        Id: 'arn:aws:securityhub:us-east-1:123456789012:subscription/aws-foundational-security-best-practices/v/1.0.0/S3.1/finding/existing-retry-finding',
      });
      await setupControlConfig('S3.1', true);

      const findingRepo = new FindingRepository('test', findingsTableName, docClient);
      await findingRepo.put({
        findingType: 'aws-foundational-security-best-practices/v/1.0.0/S3.1',
        findingId: finding.Id,
        findingDescription: 'Old description',
        accountId: finding.AwsAccountId,
        resourceId: finding.Resources[0].Id,
        resourceType: finding.Resources[0].Type,
        resourceTypeNormalized: normalizeResourceType(finding.Resources[0].Type),
        severity: 'MEDIUM',
        severityNormalized: 2,
        region: finding.Region!,
        remediationStatus: 'FAILED',
        securityHubUpdatedAtTime: '2023-01-01T00:00:00.000Z',
        lastUpdatedTime: '2023-01-01T00:00:00.000Z',
        'securityHubUpdatedAtTime#findingId': '2023-01-01T00:00:00.000Z#' + finding.Id,
        'severityNormalized#securityHubUpdatedAtTime#findingId': '2#2023-01-01T00:00:00.000Z#' + finding.Id,
        findingJSON: new Uint8Array(),
        findingIdControl: finding.Id + '#aws-foundational-security-best-practices/v/1.0.0/S3.1',
        FINDING_CONSTANT: 'finding',
        suppressed: false,
        creationTime: finding.CreatedAt,
        expireAt: calculateTtlTimestamp('2023-01-01T00:00:00.000Z'),
      });

      sfnMock.on(StartExecutionCommand).resolves({
        executionArn: 'arn:aws:states:us-east-1:123456789012:execution:test-state-machine:retry-execution-id',
      });

      const record = createSQSRecord(finding);
      await PreProcessor.recordHandler(record);

      const findingResult = await docClient.send(
        new GetCommand({
          TableName: findingsTableName,
          Key: { findingType: 'aws-foundational-security-best-practices/v/1.0.0/S3.1', findingId: finding.Id },
        }),
      );

      expect(findingResult.Item?.remediationStatus).toBe('IN_PROGRESS');

      const historyResult = await docClient.send(
        new GetCommand({
          TableName: remediationHistoryTableName,
          Key: {
            findingType: 'aws-foundational-security-best-practices/v/1.0.0/S3.1',
            'findingId#executionId': `${finding.Id}#arn:aws:states:us-east-1:123456789012:execution:test-state-machine:retry-execution-id`,
          },
        }),
      );

      expect(historyResult.Item).toBeDefined();
      expect(historyResult.Item?.findingId).toBe(finding.Id);
      expect(historyResult.Item?.executionId).toBe(
        'arn:aws:states:us-east-1:123456789012:execution:test-state-machine:retry-execution-id',
      );
      expect(historyResult.Item?.remediationStatus).toBe('IN_PROGRESS');
    });

    it('should update existing finding without triggering remediation for IN_PROGRESS status', async () => {
      const finding = createMockFinding({
        Id: 'arn:aws:securityhub:us-east-1:123456789012:subscription/aws-foundational-security-best-practices/v/1.0.0/S3.1/finding/existing-in-progress-finding',
      });
      await setupControlConfig('S3.1', true);

      // Create existing finding with IN_PROGRESS status
      const findingRepo = new FindingRepository('test', findingsTableName, docClient);
      await findingRepo.put({
        findingType: 'aws-foundational-security-best-practices/v/1.0.0/S3.1',
        findingId: finding.Id,
        findingDescription: 'Old description',
        accountId: finding.AwsAccountId,
        resourceId: finding.Resources[0].Id,
        resourceType: finding.Resources[0].Type,
        resourceTypeNormalized: normalizeResourceType(finding.Resources[0].Type),
        severity: 'MEDIUM',
        severityNormalized: 2,
        region: finding.Region!,
        remediationStatus: 'IN_PROGRESS',
        securityHubUpdatedAtTime: '2023-01-01T00:00:00.000Z',
        lastUpdatedTime: '2023-01-01T00:00:00.000Z',
        'securityHubUpdatedAtTime#findingId': '2023-01-01T00:00:00.000Z#' + finding.Id,
        'severityNormalized#securityHubUpdatedAtTime#findingId': '2#2023-01-01T00:00:00.000Z#' + finding.Id,
        findingJSON: new Uint8Array(),
        findingIdControl: finding.Id + '#aws-foundational-security-best-practices/v/1.0.0/S3.1',
        FINDING_CONSTANT: 'finding',
        suppressed: false,
        creationTime: finding.CreatedAt,
        expireAt: calculateTtlTimestamp('2023-01-01T00:00:00.000Z'),
      });

      const record = createSQSRecord(finding);
      await PreProcessor.recordHandler(record);

      // Verify finding was updated but status preserved
      const result = await docClient.send(
        new GetCommand({
          TableName: findingsTableName,
          Key: { findingType: 'aws-foundational-security-best-practices/v/1.0.0/S3.1', findingId: finding.Id },
        }),
      );

      expect(result.Item?.remediationStatus).toBe('IN_PROGRESS');
      expect(result.Item?.findingDescription).toBe(finding.Title);
      expect(sfnMock.commandCalls(StartExecutionCommand)).toHaveLength(0);
    });

    it('should preserve suppressed status when updating existing finding', async () => {
      const finding = createMockFinding({
        Id: 'arn:aws:securityhub:us-east-1:123456789012:subscription/aws-foundational-security-best-practices/v/1.0.0/S3.1/finding/suppressed-finding',
      });
      await setupControlConfig('S3.1', true);
      sfnMock.on(StartExecutionCommand).resolves({
        executionArn:
          'arn:aws:states:us-east-1:123456789012:execution:test-state-machine:suppressed-finding-execution-id',
      });

      // Create existing suppressed finding
      const findingRepo = new FindingRepository('test', findingsTableName, docClient);
      await findingRepo.put({
        findingType: 'aws-foundational-security-best-practices/v/1.0.0/S3.1',
        findingId: finding.Id,
        findingDescription: 'Old description',
        accountId: finding.AwsAccountId,
        resourceId: finding.Resources[0].Id,
        resourceType: finding.Resources[0].Type,
        resourceTypeNormalized: normalizeResourceType(finding.Resources[0].Type),
        severity: 'MEDIUM',
        severityNormalized: 2,
        region: finding.Region!,
        remediationStatus: 'NOT_STARTED',
        securityHubUpdatedAtTime: '2023-01-01T00:00:00.000Z',
        lastUpdatedTime: '2023-01-01T00:00:00.000Z',
        'securityHubUpdatedAtTime#findingId': '2023-01-01T00:00:00.000Z#' + finding.Id,
        'severityNormalized#securityHubUpdatedAtTime#findingId': '2#2023-01-01T00:00:00.000Z#' + finding.Id,
        findingJSON: new Uint8Array(),
        findingIdControl: finding.Id + '#aws-foundational-security-best-practices/v/1.0.0/S3.1',
        FINDING_CONSTANT: 'finding',
        suppressed: true,
        creationTime: finding.CreatedAt,
        expireAt: calculateTtlTimestamp('2023-01-01T00:00:00.000Z'),
      });

      const record = createSQSRecord(finding);
      await PreProcessor.recordHandler(record);

      // Verify suppressed status is preserved
      const result = await docClient.send(
        new GetCommand({
          TableName: findingsTableName,
          Key: { findingType: 'aws-foundational-security-best-practices/v/1.0.0/S3.1', findingId: finding.Id },
        }),
      );

      expect(result.Item?.suppressed).toBe(true);
    });
  });

  describe('History Creation Error Handling', () => {
    it('should continue orchestrator execution even if history creation fails', async () => {
      await DynamoDBTestSetup.createRemediationHistoryTable('test-history-table-fail');
      process.env.REMEDIATION_HISTORY_TABLE_ARN =
        'arn:aws:dynamodb:us-east-1:123456789012:table/test-history-table-fail';

      const finding = createMockFinding({
        Id: 'arn:aws:securityhub:us-east-1:123456789012:subscription/aws-foundational-security-best-practices/v/1.0.0/S3.1/finding/history-fail-finding',
      });
      await setupControlConfig('S3.1', true);

      const mockHistoryRepo = {
        createRemediationHistory: jest.fn().mockRejectedValue(new Error('History creation failed')),
      };

      jest.doMock('../preProcessor', () => {
        const originalModule = jest.requireActual('../preProcessor');
        return {
          ...originalModule,
          getRemediationHistoryRepository: () => mockHistoryRepo,
        };
      });

      sfnMock.on(StartExecutionCommand).resolves({
        executionArn: 'arn:aws:states:us-east-1:123456789012:execution:test-state-machine:history-fail-execution-id',
      });

      const record = createSQSRecord(finding);

      await expect(PreProcessor.recordHandler(record)).resolves.toBeUndefined();

      const findingResult = await docClient.send(
        new GetCommand({
          TableName: findingsTableName,
          Key: { findingType: 'aws-foundational-security-best-practices/v/1.0.0/S3.1', findingId: finding.Id },
        }),
      );

      expect(findingResult.Item).toBeDefined();
      expect(findingResult.Item?.remediationStatus).toBe('IN_PROGRESS');

      expect(sfnMock.commandCalls(StartExecutionCommand)).toHaveLength(1);

      await DynamoDBTestSetup.deleteTable('test-history-table-fail');
      delete process.env.REMEDIATION_HISTORY_TABLE_ARN;
      jest.clearAllMocks();
    });
  });

  describe('Error Handling and Edge Cases', () => {
    it('should not throw error for null/empty SQS record body', async () => {
      const emptyRecord = createSQSRecord(createMockFinding());
      emptyRecord.body = '';

      const metricsScope = setupMetricsMocks();

      await expect(PreProcessor.recordHandler(emptyRecord)).resolves.toBeUndefined();

      await new Promise((resolve) => setTimeout(resolve, 5));
      expect(metricsScope.isDone()).toBe(true);
    });

    it('should not throw error for malformed JSON in SQS record and send metrics', async () => {
      const malformedRecord = createSQSRecord(createMockFinding());
      malformedRecord.body = '{ invalid json';

      const metricsScope = setupMetricsMocks();

      await expect(PreProcessor.recordHandler(malformedRecord)).resolves.toBeUndefined();

      await new Promise((resolve) => setTimeout(resolve, 5));
      expect(metricsScope.isDone()).toBe(true);
    });

    it('should not throw error for missing findingId and send metrics', async () => {
      const finding = createMockFinding({ Id: undefined as any });
      const record = createSQSRecord(finding);

      const metricsScope = setupMetricsMocks();

      const result = await PreProcessor.recordHandler(record);

      expect(result).toBeUndefined();

      await new Promise((resolve) => setTimeout(resolve, 5));
      expect(metricsScope.isDone()).toBe(true);
    });

    it('should throw error for missing SecurityControlId and send metrics', async () => {
      const finding = createMockFinding({ Compliance: { Status: 'FAILED' } as any });
      const record = createSQSRecord(finding);

      const metricsScope = setupMetricsMocks();

      const result = await PreProcessor.recordHandler(record);

      expect(result).toBeUndefined();

      await new Promise((resolve) => setTimeout(resolve, 5));
      expect(metricsScope.isDone()).toBe(true);
    });

    it('should skip processing for unsupported finding types', async () => {
      const finding = createMockFinding({ Compliance: { Status: 'FAILED', SecurityControlId: 'UNSUPPORTED.1' } });
      const record = createSQSRecord(finding);

      // Don't setup config for UNSUPPORTED.1
      await PreProcessor.recordHandler(record);

      // Verify no finding was created
      const result = await docClient.send(
        new GetCommand({
          TableName: findingsTableName,
          Key: { findingType: 'aws-foundational-security-best-practices/v/1.0.0/UNSUPPORTED.1', findingId: finding.Id },
        }),
      );

      expect(result.Item).toBeUndefined();
      expect(sfnMock.commandCalls(StartExecutionCommand)).toHaveLength(0);
    });

    it('should handle orchestrator execution failure and send metrics', async () => {
      const finding = createMockFinding({
        Id: 'arn:aws:securityhub:us-east-1:123456789012:subscription/aws-foundational-security-best-practices/v/1.0.0/S3.1/finding/orchestrator-fail-finding',
      });
      await setupControlConfig('S3.1', true);
      sfnMock.on(StartExecutionCommand).rejects(new Error('Orchestrator failed'));

      const metricsScope = setupMetricsMocks();
      const record = createSQSRecord(finding);

      await expect(PreProcessor.recordHandler(record)).rejects.toThrow('Orchestrator failed');

      await new Promise((resolve) => setTimeout(resolve, 5));
      expect(metricsScope.isDone()).toBe(true);
    });

    it('should handle DynamoDB errors during finding sync and send metrics', async () => {
      await setupControlConfig('S3.1', true);

      const ddbMock = mockClient(DynamoDBDocumentClient);
      ddbMock.on(PutCommand).rejects(new Error('DynamoDB error'));
      mockCreateDynamoDBClient.mockReturnValueOnce(ddbMock as any);

      const finding = createMockFinding();
      const record = createSQSRecord(finding);

      const metricsScope = setupMetricsMocks();

      await expect(PreProcessor.recordHandler(record)).rejects.toThrow();

      await new Promise((resolve) => setTimeout(resolve, 5));
      expect(metricsScope.isDone()).toBe(true);

      ddbMock.restore();
    });
  });

  describe('Batch Processing', () => {
    it('should handle mixed success and failure in batch', async () => {
      await setupControlConfig('S3.1', true);
      sfnMock.on(StartExecutionCommand).rejectsOnce(new Error('Test SFN Error')).resolvesOnce({
        executionArn: 'arn:aws:states:us-east-1:123456789012:execution:test-state-machine:test-execution-id-3',
      });

      const thisFindingWillFail = createMockFinding({
        Id: 'arn:aws:securityhub:us-east-1:123456789012:subscription/aws-foundational-security-best-practices/v/1.0.0/S3.1/finding/valid-finding',
      });
      const thisFindingWillSucceed = createMockFinding({
        Id: 'arn:aws:securityhub:us-east-1:123456789012:subscription/aws-foundational-security-best-practices/v/1.0.0/S3.1/finding/second-valid-finding',
      });

      const metricsScope = setupMetricsMocks();

      const sqsEvent: SQSEvent = {
        Records: [createSQSRecord(thisFindingWillFail), createSQSRecord(thisFindingWillSucceed)],
      };

      const result = (await handler(sqsEvent, context, () => {})) as SQSBatchResponse;

      expect(result.batchItemFailures).toHaveLength(1);
      expect(result.batchItemFailures[0].itemIdentifier).toBe('test-message-id');

      // Verify valid finding was processed
      const dbResult = await docClient.send(
        new GetCommand({
          TableName: findingsTableName,
          Key: {
            findingType: 'aws-foundational-security-best-practices/v/1.0.0/S3.1',
            findingId: thisFindingWillSucceed.Id,
          },
        }),
      );
      expect(dbResult.Item).toBeDefined();

      await new Promise((resolve) => setImmediate(resolve));
      expect(metricsScope.isDone()).toBe(true);
    });

    it('should handle mixed ASFF and OCSF findings in batch', async () => {
      await setupControlConfig('S3.1', true);
      sfnMock.on(StartExecutionCommand).resolves({
        executionArn: 'arn:aws:states:us-east-1:123456789012:execution:test-state-machine:test-execution-id-4',
      });

      const asffFinding = createMockFinding({ Id: ASFFFindingId });
      const ocsfFinding = createMockOCSFFinding({
        finding_info: { ...createMockOCSFFinding().finding_info, uid: OCSFFindingId },
      });

      const sqsEvent: SQSEvent = {
        Records: [createSQSRecord(asffFinding, {}, 'asff-finding'), createSQSRecord(ocsfFinding, {}, 'ocsf-finding')],
      };

      const result = (await handler(sqsEvent, context, () => {})) as SQSBatchResponse;
      expect(result.batchItemFailures).toHaveLength(0);

      // Verify both findings were processed
      const asffResult = await docClient.send(
        new GetCommand({
          TableName: findingsTableName,
          Key: { findingType: 'aws-foundational-security-best-practices/v/1.0.0/S3.1', findingId: asffFinding.Id },
        }),
      );
      const ocsfResult = await docClient.send(
        new GetCommand({
          TableName: findingsTableName,
          Key: {
            findingType: 'aws-foundational-security-best-practices/v/1.0.0/S3.1',
            findingId: ocsfFinding.finding_info.uid,
          },
        }),
      );

      expect(asffResult.Item).toBeDefined();
      expect(ocsfResult.Item).toBeDefined();
      expect(sfnMock.commandCalls(StartExecutionCommand)).toHaveLength(2);
    });
  });

  describe('Utility Methods', () => {
    it('should build orchestrator input correctly', () => {
      const finding = createMockFinding();
      const payload = { source: 'aws.securityhub', account: '123456789012', region: 'us-east-1' };

      const result = PreProcessor.buildOrchestratorInput(payload, finding);
      const parsed = JSON.parse(result);

      expect(parsed.detail.findings).toHaveLength(1);
      expect(parsed.detail.findings[0]).toEqual(finding);
      expect(parsed.source).toBe('aws.securityhub');
      expect(parsed.account).toBe('123456789012');
      expect(parsed.region).toBe('us-east-1');
    });

    it('should convert ASFF finding to minimal FindingTableItem for history', () => {
      const finding = createMockFinding({
        Id: 'test-finding-id',
        AwsAccountId: '123456789012',
        Resources: [{ Type: 'AwsS3Bucket', Id: 'arn:aws:s3:::test-bucket', Region: 'us-east-1' }],
        Severity: { Label: 'HIGH' },
        Region: 'us-west-2',
        Compliance: { Status: 'FAILED', SecurityControlId: 'S3.1' },
      });

      const result = (PreProcessor as any).convertToMinimalFindingForHistory(finding);

      expect(result.findingType).toBe('S3.1');
      expect(result.findingId).toBe('test-finding-id');
      expect(result.accountId).toBe('123456789012');
      expect(result.resourceId).toBe('arn:aws:s3:::test-bucket');
      expect(result.resourceType).toBe('AwsS3Bucket');
      expect(result.severity).toBe('HIGH');
      expect(result.region).toBe('us-west-2');
      expect(result.remediationStatus).toBe('IN_PROGRESS');
      expect(result.lastUpdatedBy).toBe(FINDING_PRINCIPAL);
      expect(result.executionId).toBe('');
      expect(result.error).toBeUndefined();

      expect(result.findingDescription).toBe('');
      expect(result.suppressed).toBe(false);
      expect(result.FINDING_CONSTANT).toBe('finding');
      expect(result.expireAt).toBe(0);
      expect(result.findingJSON).toEqual(new Uint8Array(0));
    });

    it('should handle missing optional fields in ASFF finding conversion', () => {
      const finding = createMockFinding({
        Id: 'test-finding-id-2',
        AwsAccountId: '123456789012',
        Resources: [{ Type: 'AwsEc2Instance', Id: 'i-1234567890abcdef0' }],
        Severity: {}, // No Label
        Region: undefined, // No region
        Compliance: { Status: 'FAILED', SecurityControlId: 'EC2.1' },
      });

      const result = (PreProcessor as any).convertToMinimalFindingForHistory(finding);

      expect(result.findingType).toBe('EC2.1');
      expect(result.findingId).toBe('test-finding-id-2');
      expect(result.resourceId).toBe('i-1234567890abcdef0');
      expect(result.resourceType).toBe('AwsEc2Instance');
      expect(result.severity).toBe('MEDIUM');
      expect(result.region).toBe('us-east-1');
    });

    it('should execute orchestrator with correct parameters', async () => {
      sfnMock.on(StartExecutionCommand).resolves({
        executionArn: 'arn:aws:states:us-east-1:123456789012:execution:test-state-machine:test-finding-id',
      });

      const testInput = JSON.stringify({ test: 'data' });

      // Create a mock logger for the executeOrchestrator function
      const mockLogger = {
        debug: jest.fn(),
        warn: jest.fn(),
      } as any;

      const executionId = await executeOrchestrator(testInput, mockLogger);

      expect(executionId).toBe('arn:aws:states:us-east-1:123456789012:execution:test-state-machine:test-finding-id');
      expect(sfnMock.commandCalls(StartExecutionCommand)).toHaveLength(1);
      const call = sfnMock.commandCalls(StartExecutionCommand)[0];
      expect(call.args[0].input).toEqual({
        stateMachineArn: process.env.ORCHESTRATOR_ARN,
        input: testInput,
      });
    });

    it('should map notified finding for orchestrator correctly', () => {
      const finding = createMockFinding({
        Id: 'test-finding-id',
        Workflow: { Status: 'NOTIFIED' },
      });

      const orchestratorInput = JSON.stringify({
        source: 'aws.securityhub',
        account: '123456789012',
        region: 'us-east-1',
        detail: {
          findings: [finding],
          actionName: 'None',
        },
      });

      const result = (PreProcessor as any).mapNotifiedFindingForOrchestrator(finding, orchestratorInput);
      const parsedOutput = JSON.parse(result.orchestratorInput);

      expect(result.finding.Workflow.Status).toBe('NEW');
      expect(result.finding.Id).toBe('test-finding-id');
      expect(parsedOutput.detail.findings).toHaveLength(1);
      expect(parsedOutput.detail.findings[0].Workflow.Status).toBe('NEW');
      expect(parsedOutput.detail.findings[0].Id).toBe('test-finding-id');
      expect(parsedOutput.source).toBe('aws.securityhub');
      expect(parsedOutput.account).toBe('123456789012');
      expect(parsedOutput.region).toBe('us-east-1');
    });
  });

  describe('Different Finding Types and Scenarios', () => {
    it('should handle EC2 finding type', async () => {
      const finding = createMockFinding({
        Id: 'arn:aws:securityhub:us-east-1:123456789012:subscription/aws-foundational-security-best-practices/v/1.0.0/EC2.1/finding/ec2-finding',
        Compliance: { Status: 'FAILED', SecurityControlId: 'EC2.1' },
        Resources: [{ Type: 'AwsEc2Instance', Id: 'i-1234567890abcdef0' }],
      });

      await setupControlConfig('EC2.1', true);
      sfnMock.on(StartExecutionCommand).resolves({
        executionArn: 'arn:aws:states:us-east-1:123456789012:execution:test-state-machine:ec2-execution-id',
      });

      const record = createSQSRecord(finding);
      await PreProcessor.recordHandler(record);

      const result = await docClient.send(
        new GetCommand({
          TableName: findingsTableName,
          Key: { findingType: 'aws-foundational-security-best-practices/v/1.0.0/EC2.1', findingId: finding.Id },
        }),
      );

      expect(result.Item?.resourceType).toBe('AwsEc2Instance');
      expect(result.Item?.resourceId).toBe('i-1234567890abcdef0');
    });

    it('should handle finding with multiple resources', async () => {
      const finding = createMockFinding({
        Id: 'arn:aws:securityhub:us-east-1:123456789012:subscription/aws-foundational-security-best-practices/v/1.0.0/S3.1/finding/multi-resource-finding',
        Resources: [
          { Type: 'AwsS3Bucket', Id: 'arn:aws:s3:::bucket1' },
          { Type: 'AwsS3Bucket', Id: 'arn:aws:s3:::bucket2' },
        ],
      });

      await setupControlConfig('S3.1', true);
      sfnMock.on(StartExecutionCommand).resolves({
        executionArn: 'arn:aws:states:us-east-1:123456789012:execution:test-state-machine:multi-resource-execution-id',
      });

      const record = createSQSRecord(finding);
      await PreProcessor.recordHandler(record);

      const result = await docClient.send(
        new GetCommand({
          TableName: findingsTableName,
          Key: { findingType: 'aws-foundational-security-best-practices/v/1.0.0/S3.1', findingId: finding.Id },
        }),
      );

      // Should use first resource
      expect(result.Item?.resourceId).toBe('arn:aws:s3:::bucket1');
    });

    it('should handle finding with different severity levels', async () => {
      const severities = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];

      for (const severity of severities) {
        const finding = createMockFinding({
          Id: `arn:aws:securityhub:us-east-1:123456789012:subscription/aws-foundational-security-best-practices/v/1.0.0/S3.1/finding/severity-${severity.toLowerCase()}-finding`,
          Severity: { Label: severity as ASFFSeverity },
        });

        await setupControlConfig('S3.1', true);
        sfnMock.on(StartExecutionCommand).resolves({
          executionArn: `arn:aws:states:us-east-1:123456789012:execution:test-state-machine:severity-${severity.toLowerCase()}-execution-id`,
        });

        const record = createSQSRecord(finding);
        await PreProcessor.recordHandler(record);

        const result = await docClient.send(
          new GetCommand({
            TableName: findingsTableName,
            Key: { findingType: 'aws-foundational-security-best-practices/v/1.0.0/S3.1', findingId: finding.Id },
          }),
        );

        expect(result.Item?.severity).toBe(severity);
      }
    });
  });

  describe('Configuration Edge Cases', () => {
    it('should handle config check when control exists but auto-remediation is disabled', async () => {
      const finding = createMockFinding({
        Id: 'arn:aws:securityhub:us-east-1:123456789012:subscription/aws-foundational-security-best-practices/v/1.0.0/S3.1/finding/disabled-auto-remediation',
      });
      await setupControlConfig('S3.1', false);

      const record = createSQSRecord(finding);
      await PreProcessor.recordHandler(record);

      const result = await docClient.send(
        new GetCommand({
          TableName: findingsTableName,
          Key: { findingType: 'aws-foundational-security-best-practices/v/1.0.0/S3.1', findingId: finding.Id },
        }),
      );

      expect(result.Item?.remediationStatus).toBe('NOT_STARTED');
      expect(sfnMock.commandCalls(StartExecutionCommand)).toHaveLength(0);
    });

    it('should handle missing config table entry', async () => {
      const finding = createMockFinding({
        Id: 'arn:aws:securityhub:us-east-1:123456789012:subscription/aws-foundational-security-best-practices/v/1.0.0/S3.1/finding/missing-config-finding',
        Compliance: { Status: 'FAILED', SecurityControlId: 'MISSING.1' },
      });

      // Don't create config entry for MISSING.1
      const record = createSQSRecord(finding);
      await PreProcessor.recordHandler(record);

      // Should skip processing
      const result = await docClient.send(
        new GetCommand({
          TableName: findingsTableName,
          Key: { findingType: 'aws-foundational-security-best-practices/v/1.0.0/MISSING.1', findingId: finding.Id },
        }),
      );

      expect(result.Item).toBeUndefined();
    });
  });

  describe('Timestamp and Data Integrity', () => {
    it('should not update finding when securityHubUpdatedAtTime is older', async () => {
      const finding = createMockFinding({
        Id: 'arn:aws:securityhub:us-east-1:123456789012:subscription/aws-foundational-security-best-practices/v/1.0.0/S3.1/finding/timestamp-test-finding',
        UpdatedAt: '2023-01-01T00:00:00.000Z', // Older timestamp
      });
      await setupControlConfig('S3.1', true);

      // Create existing finding with newer timestamp
      const findingRepo = new FindingRepository('test', findingsTableName, docClient);
      await findingRepo.put({
        findingType: 'aws-foundational-security-best-practices/v/1.0.0/S3.1',
        findingId: finding.Id,
        findingDescription: 'Original description',
        accountId: finding.AwsAccountId,
        resourceId: finding.Resources[0].Id,
        resourceType: finding.Resources[0].Type,
        resourceTypeNormalized: normalizeResourceType(finding.Resources[0].Type),
        severity: 'MEDIUM',
        severityNormalized: 2,
        region: finding.Region!,
        remediationStatus: 'SUCCESS',
        securityHubUpdatedAtTime: '2024-01-01T00:00:00.000Z', // Newer timestamp
        lastUpdatedTime: '2024-01-01T00:00:00.000Z',
        'securityHubUpdatedAtTime#findingId': '2024-01-01T00:00:00.000Z#' + finding.Id,
        'severityNormalized#securityHubUpdatedAtTime#findingId': '2#2023-01-01T00:00:00.000Z#' + finding.Id,
        findingJSON: new Uint8Array(),
        findingIdControl: finding.Id + '#aws-foundational-security-best-practices/v/1.0.0/S3.1',
        FINDING_CONSTANT: 'finding',
        suppressed: false,
        creationTime: finding.CreatedAt,
        expireAt: calculateTtlTimestamp('2023-01-01T00:00:00.000Z'),
      });

      const record = createSQSRecord(finding);
      await PreProcessor.recordHandler(record);

      // Verify finding was NOT updated
      const result = await docClient.send(
        new GetCommand({
          TableName: findingsTableName,
          Key: { findingType: 'aws-foundational-security-best-practices/v/1.0.0/S3.1', findingId: finding.Id },
        }),
      );

      expect(result.Item?.findingDescription).toBe('Original description');
      expect(result.Item?.severity).toBe('MEDIUM');
      expect(sfnMock.commandCalls(StartExecutionCommand)).toHaveLength(0);
    });
  });

  describe('OCSF Finding Support', () => {
    it('should process new OCSF finding with auto-remediation enabled', async () => {
      const ocsfFinding = createMockOCSFFinding();
      await setupControlConfig('S3.1', true);
      sfnMock.on(StartExecutionCommand).resolves({
        executionArn: 'arn:aws:states:us-east-1:123456789012:execution:test-state-machine:ocsf-new-execution-id',
      });

      const record = createSQSRecord(ocsfFinding);
      await PreProcessor.recordHandler(record);

      const result = await docClient.send(
        new GetCommand({
          TableName: findingsTableName,
          Key: {
            findingType: 'aws-foundational-security-best-practices/v/1.0.0/S3.1',
            findingId: ocsfFinding.finding_info.uid,
          },
        }),
      );

      expect(result.Item).toBeDefined();
      expect(result.Item?.remediationStatus).toBe('IN_PROGRESS');
      expect(result.Item?.findingDescription).toBe('OCSF Test Finding');
      expect(result.Item?.accountId).toBe('123456789012');
      expect(result.Item?.resourceId).toBe('arn:aws:s3:::test-bucket');
      expect(result.Item?.severity).toBe('HIGH');
      expect(sfnMock.commandCalls(StartExecutionCommand)).toHaveLength(1);
    });

    it('should handle OCSF finding with different severity levels', async () => {
      const severityMappings = [
        { ocsf: 'Low', expected: 'LOW', timestamp: '2024-01-01T00:00:00Z' },
        { ocsf: 'Medium', expected: 'MEDIUM', timestamp: '2024-01-02T00:00:00Z' },
        { ocsf: 'High', expected: 'HIGH', timestamp: '2024-01-03T00:00:00Z' },
        { ocsf: 'Critical', expected: 'CRITICAL', timestamp: '2024-01-04T00:00:00Z' },
      ];

      for (const { ocsf, expected, timestamp } of severityMappings) {
        const ocsfFinding = createMockOCSFFinding({
          severity: ocsf as any,
          finding_info: { ...createMockOCSFFinding().finding_info, uid: OCSFFindingId, modified_time_dt: timestamp },
        });

        await setupControlConfig('S3.1', true);
        sfnMock.on(StartExecutionCommand).resolves({
          executionArn: 'arn:aws:states:us-east-1:123456789012:execution:test-state-machine:ocsf-existing-execution-id',
        });

        const record = createSQSRecord(ocsfFinding);
        await PreProcessor.recordHandler(record);

        const result = await docClient.send(
          new GetCommand({
            TableName: findingsTableName,
            Key: {
              findingType: 'aws-foundational-security-best-practices/v/1.0.0/S3.1',
              findingId: ocsfFinding.finding_info.uid,
            },
          }),
        );

        expect(result.Item?.severity).toBe(expected);
      }
    });

    it('should update existing OCSF finding and trigger remediation for failed status', async () => {
      const ocsfFinding = createMockOCSFFinding({
        finding_info: {
          ...createMockOCSFFinding().finding_info,
          uid: 'arn:aws:securityhub:us-east-1:123456789012:subscription/aws-foundational-security-best-practices/v/1.0.0/S3.1/finding/ocsf-existing-failed',
          modified_time_dt: '2024-01-02T00:00:00.000Z', // Newer than existing finding
        },
        compliance: {
          status: 'fail',
          control: 'S3.1',
          standards: ['standards/nist-800-53/v/5.0.0'],
        },
      });
      await setupControlConfig('S3.1', true);
      setupFilterMetricsMocks();

      // Create existing finding with FAILED status
      const findingRepo = new FindingRepository('test', findingsTableName, docClient);
      await findingRepo.put({
        findingType: 'aws-foundational-security-best-practices/v/1.0.0/S3.1',
        findingId: ocsfFinding.finding_info.uid,
        findingDescription: 'Old OCSF description',
        accountId: '123456789012',
        resourceId: 'arn:aws:s3:::test-bucket',
        resourceType: 'AWS::S3::Bucket',
        resourceTypeNormalized: 'awss3bucket',
        severity: 'MEDIUM',
        severityNormalized: 2,
        region: 'us-east-1',
        remediationStatus: 'FAILED',
        securityHubUpdatedAtTime: '2023-01-01T00:00:00.000Z',
        lastUpdatedTime: '2023-01-01T00:00:00.000Z',
        'securityHubUpdatedAtTime#findingId': '2023-01-01T00:00:00.000Z#' + ocsfFinding.finding_info.uid,
        'severityNormalized#securityHubUpdatedAtTime#findingId':
          '2#2023-01-01T00:00:00.000Z#' + ocsfFinding.finding_info.uid,
        findingJSON: new Uint8Array(),
        findingIdControl: ocsfFinding.finding_info.uid + '#aws-foundational-security-best-practices/v/1.0.0/S3.1',
        FINDING_CONSTANT: 'finding',
        suppressed: false,
        creationTime: '2023-01-01T00:00:00Z',
        expireAt: calculateTtlTimestamp('2023-01-01T00:00:00.000Z'),
      });

      sfnMock.on(StartExecutionCommand).resolves({
        executionArn: 'arn:aws:states:us-east-1:123456789012:execution:test-state-machine:ocsf-severity-execution-id',
      });

      const record = createSQSRecord(ocsfFinding);
      await PreProcessor.recordHandler(record);

      const result = await docClient.send(
        new GetCommand({
          TableName: findingsTableName,
          Key: {
            findingType: 'aws-foundational-security-best-practices/v/1.0.0/S3.1',
            findingId: ocsfFinding.finding_info.uid,
          },
        }),
      );

      expect(result.Item?.remediationStatus).toBe('IN_PROGRESS');
      expect(result.Item?.findingDescription).toBe('OCSF Test Finding');
      expect(result.Item?.severity).toBe('HIGH');
      expect(sfnMock.commandCalls(StartExecutionCommand)).toHaveLength(1);
    });

    it('should handle OCSF finding with missing control ID and send metrics', async () => {
      const invalidOcsfFinding = createMockOCSFFinding({
        compliance: {
          status: 'fail',
          control: '',
          standards: ['aws-foundational-security-best-practices'],
        },
      });

      const metricsScope = setupMetricsMocks();
      const record = createSQSRecord(invalidOcsfFinding);

      await expect(PreProcessor.recordHandler(record)).rejects.toThrow(
        'One or more parameter values are not valid. The AttributeValue for a key attribute cannot contain an empty string value. Key: controlId',
      );

      await new Promise((resolve) => setImmediate(resolve));
      expect(metricsScope.isDone()).toBe(true);
    });

    it('should process OCSF finding with uid fallback when uid_alt is undefined', async () => {
      // ARRANGE
      const ocsfFinding = createMockOCSFFinding({
        finding_info: {
          ...createMockOCSFFinding().finding_info,
          uid: 'arn:aws:securityhub:us-east-1:123456789012:subscription/aws-foundational-security-best-practices/v/1.0.0/CloudFormation.1/finding/uid-fallback-test',
        },
        resources: [
          {
            type: 'AWS::CloudFormation::Stack',
            uid: 'arn:aws:cloudformation:us-east-1:123456789012:stack/asr/some-stack-id',
            region: 'us-east-1',
            role_id: 'role',
            owner: {
              account: { uid: '123456789012' },
            },
          },
        ],
      });
      await setupControlConfig('S3.1', true);
      sfnMock.on(StartExecutionCommand).resolves({
        executionArn: 'arn:aws:states:us-east-1:123456789012:execution:test-state-machine:uid-fallback-execution-id',
      });

      // ACT
      const record = createSQSRecord(ocsfFinding);
      await PreProcessor.recordHandler(record);

      // ASSERT
      const result = await docClient.send(
        new GetCommand({
          TableName: findingsTableName,
          Key: {
            findingType: 'aws-foundational-security-best-practices/v/1.0.0/CloudFormation.1',
            findingId: ocsfFinding.finding_info.uid,
          },
        }),
      );

      expect(result.Item).toBeDefined();
      expect(result.Item?.remediationStatus).toBe('IN_PROGRESS');
      expect(result.Item?.resourceId).toBe('arn:aws:cloudformation:us-east-1:123456789012:stack/asr/some-stack-id');
      expect(sfnMock.commandCalls(StartExecutionCommand)).toHaveLength(1);
    });

    it('should process OCSF finding with name fallback when uid and uid_alt are undefined', async () => {
      // ARRANGE
      const ocsfFinding = createMockOCSFFinding({
        finding_info: {
          ...createMockOCSFFinding().finding_info,
          uid: 'arn:aws:securityhub:us-east-1:123456789012:subscription/aws-foundational-security-best-practices/v/1.0.0/S3.1/finding/ocsf-name-fallback',
        },
        compliance: {
          status: 'fail',
          control: 'S3.1',
          standards: ['standards/nist-800-53/v/5.0.0'],
        },
        resources: [
          {
            type: 'AWS::S3::Bucket',
            name: 'test-bucket-name',
            region: 'us-east-1',
            role_id: 'role',
            owner: {
              account: { uid: '123456789012' },
            },
          },
        ],
      });
      await setupControlConfig('S3.1', true);
      setupFilterMetricsMocks();
      sfnMock.on(StartExecutionCommand).resolves({
        executionArn: 'arn:aws:states:us-east-1:123456789012:execution:test-state-machine:name-fallback-execution-id',
      });

      // ACT
      const record = createSQSRecord(ocsfFinding);
      await PreProcessor.recordHandler(record);

      // ASSERT
      const result = await docClient.send(
        new GetCommand({
          TableName: findingsTableName,
          Key: {
            findingType: 'aws-foundational-security-best-practices/v/1.0.0/S3.1',
            findingId: ocsfFinding.finding_info.uid,
          },
        }),
      );

      expect(result.Item).toBeDefined();
      expect(result.Item?.remediationStatus).toBe('IN_PROGRESS');
      expect(result.Item?.resourceId).toBe('test-bucket-name');
      expect(sfnMock.commandCalls(StartExecutionCommand)).toHaveLength(1);
    });
  });

  describe('Archived Findings Processing', () => {
    it('should not modify existing ASFF archived finding without triggering orchestrator', async () => {
      const finding = createMockFinding({
        Id: 'arn:aws:securityhub:us-east-1:123456789012:subscription/aws-foundational-security-best-practices/v/1.0.0/S3.1/finding/archived-asff-finding',
        RecordState: 'ARCHIVED',
      });
      await setupControlConfig('S3.1', true);

      // Create existing finding first
      const findingRepo = new FindingRepository('test', findingsTableName, docClient);
      await findingRepo.put({
        findingType: 'aws-foundational-security-best-practices/v/1.0.0/S3.1',
        findingId: finding.Id,
        findingDescription: 'Existing finding',
        accountId: finding.AwsAccountId,
        resourceId: finding.Resources[0].Id,
        resourceType: finding.Resources[0].Type,
        resourceTypeNormalized: normalizeResourceType(finding.Resources[0].Type),
        severity: 'HIGH',
        severityNormalized: 3,
        region: finding.Region!,
        remediationStatus: 'NOT_STARTED',
        securityHubUpdatedAtTime: '2023-01-01T00:00:00.000Z',
        lastUpdatedTime: '2023-01-01T00:00:00.000Z',
        'securityHubUpdatedAtTime#findingId': '2023-01-01T00:00:00.000Z#' + finding.Id,
        'severityNormalized#securityHubUpdatedAtTime#findingId': '3#2023-01-01T00:00:00.000Z#' + finding.Id,
        findingJSON: new Uint8Array(),
        findingIdControl: finding.Id + '#S3.1',
        FINDING_CONSTANT: 'finding',
        suppressed: false,
        creationTime: finding.CreatedAt,
        expireAt: calculateTtlTimestamp('2023-01-01T00:00:00.000Z'),
      });

      const record = createSQSRecord(finding);
      await PreProcessor.recordHandler(record);

      // Verify archived finding was deleted from database
      const result = await docClient.send(
        new GetCommand({
          TableName: findingsTableName,
          Key: { findingType: 'aws-foundational-security-best-practices/v/1.0.0/S3.1', findingId: finding.Id },
        }),
      );
      expect(result.Item).toBeUndefined();
      expect(sfnMock.commandCalls(StartExecutionCommand)).toHaveLength(0);
    });

    it('should handle ASFF archived finding when no existing record exists', async () => {
      const finding = createMockFinding({
        Id: 'arn:aws:securityhub:us-east-1:123456789012:subscription/aws-foundational-security-best-practices/v/1.0.0/S3.1/finding/new-archived-asff-finding',
        RecordState: 'ARCHIVED',
      });
      await setupControlConfig('S3.1', true);

      const record = createSQSRecord(finding);
      await PreProcessor.recordHandler(record);

      // Verify no finding was created
      const result = await docClient.send(
        new GetCommand({
          TableName: findingsTableName,
          Key: { findingType: 'aws-foundational-security-best-practices/v/1.0.0/S3.1', findingId: finding.Id },
        }),
      );
      expect(result.Item).toBeUndefined();
      expect(sfnMock.commandCalls(StartExecutionCommand)).toHaveLength(0);
    });

    it('should not modify existing OCSF archived finding with status_id 5', async () => {
      const ocsfFinding = createMockOCSFFinding({
        finding_info: {
          ...createMockOCSFFinding().finding_info,
          uid: 'arn:aws:securityhub:us-east-1:123456789012:subscription/aws-foundational-security-best-practices/v/1.0.0/S3.1/finding/archived-ocsf-status-finding',
        },
        status_id: 5,
      });
      await setupControlConfig('S3.1', true);

      // Create existing finding first
      const findingRepo = new FindingRepository('test', findingsTableName, docClient);
      await findingRepo.put({
        findingType: 'aws-foundational-security-best-practices/v/1.0.0/S3.1',
        findingId: ocsfFinding.finding_info.uid,
        findingDescription: 'Existing OCSF finding',
        accountId: '123456789012',
        resourceId: 'arn:aws:s3:::test-bucket',
        resourceType: 'AWS::S3::Bucket',
        resourceTypeNormalized: 'awss3bucket',
        severity: 'HIGH',
        severityNormalized: 3,
        region: 'us-east-1',
        remediationStatus: 'NOT_STARTED',
        securityHubUpdatedAtTime: '2023-01-01T00:00:00.000Z',
        lastUpdatedTime: '2023-01-01T00:00:00.000Z',
        'securityHubUpdatedAtTime#findingId': '2023-01-01T00:00:00.000Z#' + ocsfFinding.finding_info.uid,
        'severityNormalized#securityHubUpdatedAtTime#findingId':
          '3#2023-01-01T00:00:00.000Z#' + ocsfFinding.finding_info.uid,
        findingJSON: new Uint8Array(),
        findingIdControl: ocsfFinding.finding_info.uid + '#aws-foundational-security-best-practices/v/1.0.0/S3.1',
        FINDING_CONSTANT: 'finding',
        suppressed: false,
        creationTime: '2023-01-01T00:00:00Z',
        expireAt: calculateTtlTimestamp('2023-01-01T00:00:00.000Z'),
      });

      const record = createSQSRecord(ocsfFinding);
      await PreProcessor.recordHandler(record);

      // Verify archived finding was deleted from database
      const result = await docClient.send(
        new GetCommand({
          TableName: findingsTableName,
          Key: {
            findingType: 'aws-foundational-security-best-practices/v/1.0.0/S3.1',
            findingId: ocsfFinding.finding_info.uid,
          },
        }),
      );
      expect(result.Item).toBeUndefined();
      expect(sfnMock.commandCalls(StartExecutionCommand)).toHaveLength(0);
    });

    it('should not modify existing OCSF archived finding with activity_id 3', async () => {
      const ocsfFinding = createMockOCSFFinding({
        finding_info: {
          ...createMockOCSFFinding().finding_info,
          uid: 'arn:aws:securityhub:us-east-1:123456789012:subscription/aws-foundational-security-best-practices/v/1.0.0/S3.1/finding/archived-ocsf-activity-finding',
        },
        activity_id: 3,
      });
      await setupControlConfig('S3.1', true);

      // Create existing finding first
      const findingRepo = new FindingRepository('test', findingsTableName, docClient);
      await findingRepo.put({
        findingType: 'aws-foundational-security-best-practices/v/1.0.0/S3.1',
        findingId: ocsfFinding.finding_info.uid,
        findingDescription: 'Existing OCSF finding',
        accountId: '123456789012',
        resourceId: 'arn:aws:s3:::test-bucket',
        resourceType: 'AWS::S3::Bucket',
        resourceTypeNormalized: 'awss3bucket',
        severity: 'HIGH',
        severityNormalized: 3,
        region: 'us-east-1',
        remediationStatus: 'IN_PROGRESS',
        securityHubUpdatedAtTime: '2023-01-01T00:00:00.000Z',
        lastUpdatedTime: '2023-01-01T00:00:00.000Z',
        'securityHubUpdatedAtTime#findingId': '2023-01-01T00:00:00.000Z#' + ocsfFinding.finding_info.uid,
        'severityNormalized#securityHubUpdatedAtTime#findingId':
          '2#2023-01-01T00:00:00.000Z#' + ocsfFinding.finding_info.uid,
        findingJSON: new Uint8Array(),
        findingIdControl: ocsfFinding.finding_info.uid + '#aws-foundational-security-best-practices/v/1.0.0/S3.1',
        FINDING_CONSTANT: 'finding',
        suppressed: false,
        creationTime: '2023-01-01T00:00:00Z',
        expireAt: calculateTtlTimestamp('2023-01-01T00:00:00.000Z'),
      });

      const record = createSQSRecord(ocsfFinding);
      await PreProcessor.recordHandler(record);

      // Verify archived finding was deleted from database
      const result = await docClient.send(
        new GetCommand({
          TableName: findingsTableName,
          Key: {
            findingType: 'aws-foundational-security-best-practices/v/1.0.0/S3.1',
            findingId: ocsfFinding.finding_info.uid,
          },
        }),
      );
      expect(result.Item).toBeUndefined();
      expect(sfnMock.commandCalls(StartExecutionCommand)).toHaveLength(0);
    });

    it('should handle OCSF archived finding when no existing record exists', async () => {
      const ocsfFinding = createMockOCSFFinding({
        finding_info: {
          ...createMockOCSFFinding().finding_info,
          uid: 'arn:aws:securityhub:us-east-1:123456789012:subscription/aws-foundational-security-best-practices/v/1.0.0/S3.1/finding/new-archived-ocsf-finding',
        },
        status_id: 5,
      });
      await setupControlConfig('S3.1', true);

      const record = createSQSRecord(ocsfFinding);
      await PreProcessor.recordHandler(record);

      // Verify no finding was created
      const result = await docClient.send(
        new GetCommand({
          TableName: findingsTableName,
          Key: {
            findingType: 'aws-foundational-security-best-practices/v/1.0.0/S3.1',
            findingId: ocsfFinding.finding_info.uid,
          },
        }),
      );
      expect(result.Item).toBeUndefined();
      expect(sfnMock.commandCalls(StartExecutionCommand)).toHaveLength(0);
    });
  });

  describe('Filtering Metrics', () => {
    it('should send filtering metric with "none" when all filters disabled', async () => {
      const finding = createMockFinding({ Id: 'metrics-test-finding' });
      await setupControlConfig('S3.1', true);
      sfnMock.on(StartExecutionCommand).resolves({
        executionArn: 'arn:aws:states:us-east-1:123456789012:execution:test-state-machine:metrics-execution-id',
      });

      const metricsScope = setupFilterMetricsMocks();
      const record = createSQSRecord(finding);
      await PreProcessor.recordHandler(record);

      await new Promise((resolve) => setImmediate(resolve));

      expect(metricsScope.isDone()).toBe(true);

      const result = await docClient.send(
        new GetCommand({
          TableName: findingsTableName,
          Key: { findingType: 'S3.1', findingId: finding.Id },
        }),
      );
      expect(result.Item?.remediationStatus).toBe('IN_PROGRESS');
    });

    it('should send filtering metric even when finding processing fails', async () => {
      const finding = createMockFinding({ Id: 'metrics-error-finding' });
      await setupControlConfig('S3.1', true);

      const ddbMock = mockClient(DynamoDBDocumentClient);
      ddbMock.on(GetCommand, { TableName: configTableName }).resolves({
        Item: { controlId: 'S3.1', automatedRemediationEnabled: true },
      });
      ddbMock.on(PutCommand).rejects(new Error('DynamoDB error'));
      mockCreateDynamoDBClient.mockReturnValueOnce(ddbMock as any);

      const metricsScope = setupFilterMetricsMocks();
      const record = createSQSRecord(finding);

      await expect(PreProcessor.recordHandler(record)).rejects.toThrow('DynamoDB error');

      await new Promise((resolve) => setTimeout(resolve, 100));

      expect(metricsScope.isDone()).toBe(true);

      ddbMock.restore();
    });

    it('should send filtering metric for OCSF findings', async () => {
      const ocsfFinding = createMockOCSFFinding({
        finding_info: {
          ...createMockOCSFFinding().finding_info,
          uid: 'arn:aws:securityhub:us-east-1:123456789012:subscription/aws-foundational-security-best-practices/v/1.0.0/S3.1/finding/ocsf-metrics-test',
        },
      });
      await setupControlConfig('S3.1', true);
      sfnMock.on(StartExecutionCommand).resolves({
        executionArn: 'arn:aws:states:us-east-1:123456789012:execution:test-state-machine:filter-metrics-execution-id',
      });

      const metricsScope = setupFilterMetricsMocks();
      const record = createSQSRecord(ocsfFinding);
      await PreProcessor.recordHandler(record);

      await new Promise((resolve) => setImmediate(resolve));

      expect(metricsScope.isDone()).toBe(true);

      const result = await docClient.send(
        new GetCommand({
          TableName: findingsTableName,
          Key: {
            findingType: 'aws-foundational-security-best-practices/v/1.0.0/S3.1',
            findingId: ocsfFinding.finding_info.uid,
          },
        }),
      );
      expect(result.Item?.remediationStatus).toBe('IN_PROGRESS');
    });

    it('should send filtering metric when auto-remediation is disabled', async () => {
      const finding = createMockFinding({ Id: 'metrics-disabled-finding' });
      await setupControlConfig('S3.1', false);

      const metricsScope = setupFilterMetricsMocks();
      const record = createSQSRecord(finding);
      await PreProcessor.recordHandler(record);

      await new Promise((resolve) => setImmediate(resolve));

      expect(metricsScope.isDone()).toBe(true);

      const result = await docClient.send(
        new GetCommand({
          TableName: findingsTableName,
          Key: { findingType: 'S3.1', findingId: finding.Id },
        }),
      );
      expect(result.Item?.remediationStatus).toBe('NOT_STARTED');
    });

    it('should send filtering metric for existing finding updates', async () => {
      const finding = createMockFinding({ Id: 'metrics-existing-finding' });
      await setupControlConfig('S3.1', true);

      const findingRepo = new FindingRepository('test', findingsTableName, docClient);
      await findingRepo.put({
        findingType: 'S3.1',
        findingId: finding.Id,
        findingDescription: 'Existing finding',
        accountId: finding.AwsAccountId,
        resourceId: finding.Resources[0].Id,
        resourceType: finding.Resources[0].Type,
        resourceTypeNormalized: normalizeResourceType(finding.Resources[0].Type),
        severity: 'MEDIUM',
        severityNormalized: 2,
        region: finding.Region!,
        remediationStatus: 'FAILED',
        securityHubUpdatedAtTime: '2023-01-01T00:00:00.000Z',
        lastUpdatedTime: '2023-01-01T00:00:00.000Z',
        'securityHubUpdatedAtTime#findingId': '2023-01-01T00:00:00.000Z#' + finding.Id,
        'severityNormalized#securityHubUpdatedAtTime#findingId': '2#2023-01-01T00:00:00.000Z#' + finding.Id,
        findingJSON: new Uint8Array(),
        findingIdControl: finding.Id + '#S3.1',
        FINDING_CONSTANT: 'finding',
        suppressed: false,
        creationTime: finding.CreatedAt,
        expireAt: calculateTtlTimestamp('2023-01-01T00:00:00.000Z'),
      });

      sfnMock.on(StartExecutionCommand).resolves({
        executionArn: 'arn:aws:states:us-east-1:123456789012:execution:test-state-machine:filter-pass-execution-id',
      });
      const metricsScope = setupFilterMetricsMocks();
      const record = createSQSRecord(finding);
      await PreProcessor.recordHandler(record);

      await new Promise((resolve) => setImmediate(resolve));

      expect(metricsScope.isDone()).toBe(true);

      const result = await docClient.send(
        new GetCommand({
          TableName: findingsTableName,
          Key: { findingType: 'S3.1', findingId: finding.Id },
        }),
      );
      expect(result.Item?.remediationStatus).toBe('IN_PROGRESS');
    });
  });

  describe('Complex Workflow Scenarios', () => {
    it('should handle finding that transitions from NOT_STARTED to remediation', async () => {
      const finding = createMockFinding({ Id: ASFFFindingId });
      await setupControlConfig('S3.1', false); // Initially disabled
      setupFilterMetricsMocks();

      // First processing - auto-remediation disabled
      let record = createSQSRecord(finding);
      await PreProcessor.recordHandler(record);

      let result = await docClient.send(
        new GetCommand({
          TableName: findingsTableName,
          Key: { findingType: 'aws-foundational-security-best-practices/v/1.0.0/S3.1', findingId: finding.Id },
        }),
      );
      expect(result.Item?.remediationStatus).toBe('NOT_STARTED');

      // Enable auto-remediation
      await setupControlConfig('S3.1', true);
      sfnMock.on(StartExecutionCommand).resolves({
        executionArn:
          'arn:aws:states:us-east-1:123456789012:execution:test-state-machine:auto-remediation-execution-id',
      });

      // Second processing - should now trigger remediation
      const updatedFinding = createMockFinding({
        Id: ASFFFindingId,
        UpdatedAt: '2024-01-02T00:00:00.000Z', // Newer timestamp
      });
      record = createSQSRecord(updatedFinding);
      await PreProcessor.recordHandler(record);

      result = await docClient.send(
        new GetCommand({
          TableName: findingsTableName,
          Key: { findingType: 'aws-foundational-security-best-practices/v/1.0.0/S3.1', findingId: finding.Id },
        }),
      );
      expect(result.Item?.remediationStatus).toBe('IN_PROGRESS');
      expect(sfnMock.commandCalls(StartExecutionCommand)).toHaveLength(1);
    });

    it('should handle concurrent processing of same finding', async () => {
      const finding = createMockFinding({ Id: ASFFFindingId });
      await setupControlConfig('S3.1', true);
      sfnMock.on(StartExecutionCommand).resolves({
        executionArn: 'arn:aws:states:us-east-1:123456789012:execution:test-state-machine:asff-finding-execution-id',
      });

      const record = createSQSRecord(finding);

      // Process same finding concurrently
      await Promise.all([PreProcessor.recordHandler(record), PreProcessor.recordHandler(record)]);

      const result = await docClient.send(
        new GetCommand({
          TableName: findingsTableName,
          Key: { findingType: 'aws-foundational-security-best-practices/v/1.0.0/S3.1', findingId: finding.Id },
        }),
      );

      expect(result.Item).toBeDefined();
      expect(result.Item?.remediationStatus).toBe('IN_PROGRESS');
    });

    it('should handle finding with empty string SecurityControlId and send metrics', async () => {
      const finding = createMockFinding({
        Compliance: { Status: 'FAILED', SecurityControlId: '' },
      });
      const record = createSQSRecord(finding);

      const metricsScope = setupMetricsMocks();

      await expect(PreProcessor.recordHandler(record)).rejects.toThrow(
        'One or more parameter values are not valid. The AttributeValue for a key attribute cannot contain an empty string value. Key: controlId',
      );

      await new Promise((resolve) => setImmediate(resolve));
      expect(metricsScope.isDone()).toBe(true);
    });

    it('should handle null record parameter', async () => {
      const metricsScope = setupMetricsMocks();

      await expect(PreProcessor.recordHandler(null as any)).resolves.toBeUndefined();

      await new Promise((resolve) => setTimeout(resolve, 5));
      expect(metricsScope.isDone()).toBe(true);
    });

    it('should handle record with null body', async () => {
      const record = createSQSRecord(createMockFinding());
      record.body = null as any;
      const metricsScope = setupMetricsMocks();

      await expect(PreProcessor.recordHandler(record)).resolves.toBeUndefined();

      await new Promise((resolve) => setTimeout(resolve, 5));
      expect(metricsScope.isDone()).toBe(true);
    });
  });

  describe('ResourceType Normalization', () => {
    it('should normalize ASFF ResourceType AwsS3Bucket to awss3bucket', async () => {
      // ARRANGE
      const finding = createMockFinding({
        Id: 'arn:aws:securityhub:us-east-1:123456789012:subscription/aws-foundational-security-best-practices/v/1.0.0/S3.1/finding/asff-resource-type-test',
        Resources: [{ Type: 'AwsS3Bucket', Id: 'arn:aws:s3:::test-bucket', Region: 'us-east-1', Partition: 'aws' }],
      });
      await setupControlConfig('S3.1', true);
      sfnMock.on(StartExecutionCommand).resolves({
        executionArn: 'arn:aws:states:us-east-1:123456789012:execution:test-state-machine:asff-resource-type-execution',
      });

      // ACT
      const record = createSQSRecord(finding);
      await PreProcessor.recordHandler(record);

      // ASSERT
      const result = await docClient.send(
        new GetCommand({
          TableName: findingsTableName,
          Key: { findingType: 'aws-foundational-security-best-practices/v/1.0.0/S3.1', findingId: finding.Id },
        }),
      );

      expect(result.Item).toBeDefined();
      expect(result.Item?.resourceType).toBe('AwsS3Bucket');
      expect(result.Item?.resourceTypeNormalized).toBe('awss3bucket');
    });

    it('should normalize OCSF ResourceType AWS::S3::Bucket to awss3bucket', async () => {
      // ARRANGE
      const ocsfFinding = createMockOCSFFinding({
        finding_info: {
          ...createMockOCSFFinding().finding_info,
          uid: 'arn:aws:securityhub:us-east-1:123456789012:subscription/aws-foundational-security-best-practices/v/1.0.0/S3.1/finding/ocsf-resource-type-test',
        },
        resources: [
          {
            type: 'AWS::S3::Bucket',
            role_id: 'role',
            uid: 'test-bucket',
            uid_alt: 'arn:aws:s3:::test-bucket',
            region: 'us-east-1',
            owner: {
              account: { uid: '123456789012' },
            },
          },
        ],
      });
      await setupControlConfig('S3.1', true);
      sfnMock.on(StartExecutionCommand).resolves({
        executionArn: 'arn:aws:states:us-east-1:123456789012:execution:test-state-machine:ocsf-resource-type-execution',
      });

      // ACT
      const record = createSQSRecord(ocsfFinding);
      await PreProcessor.recordHandler(record);

      // ASSERT
      const result = await docClient.send(
        new GetCommand({
          TableName: findingsTableName,
          Key: {
            findingType: 'aws-foundational-security-best-practices/v/1.0.0/S3.1',
            findingId: ocsfFinding.finding_info.uid,
          },
        }),
      );

      expect(result.Item).toBeDefined();
      expect(result.Item?.resourceType).toBe('AWS::S3::Bucket');
      expect(result.Item?.resourceTypeNormalized).toBe('awss3bucket');
    });
  });

  describe('NOTIFIED Status Handling', () => {
    it('should handle NOTIFIED status for regular Security Hub findings', async () => {
      const finding = createMockFinding({
        Id: 'arn:aws:securityhub:us-east-1:123456789012:subscription/aws-foundational-security-best-practices/v/1.0.0/S3.1/finding/notified-regular-finding',
        Workflow: { Status: 'NOTIFIED' },
      });
      await setupControlConfig('S3.1', true);

      sfnMock.on(StartExecutionCommand).resolves({
        executionArn: 'arn:aws:states:us-east-1:123456789012:execution:test-state-machine:notified-regular-execution',
      });

      const findingRepo = new FindingRepository('test', findingsTableName, docClient);
      await findingRepo.put({
        findingType: 'aws-foundational-security-best-practices/v/1.0.0/S3.1',
        findingId: finding.Id,
        findingDescription: 'Old description',
        accountId: finding.AwsAccountId,
        resourceId: finding.Resources[0].Id,
        resourceType: finding.Resources[0].Type,
        resourceTypeNormalized: normalizeResourceType(finding.Resources[0].Type),
        severity: 'MEDIUM',
        severityNormalized: 2,
        region: finding.Region!,
        remediationStatus: 'FAILED',
        securityHubUpdatedAtTime: '2023-01-01T00:00:00.000Z',
        lastUpdatedTime: '2023-01-01T00:00:00.000Z',
        'securityHubUpdatedAtTime#findingId': '2023-01-01T00:00:00.000Z#' + finding.Id,
        'severityNormalized#securityHubUpdatedAtTime#findingId': '2#2023-01-01T00:00:00.000Z#' + finding.Id,
        findingJSON: new Uint8Array(),
        findingIdControl: finding.Id + '#aws-foundational-security-best-practices/v/1.0.0/S3.1',
        FINDING_CONSTANT: 'finding',
        suppressed: false,
        creationTime: finding.CreatedAt,
        expireAt: calculateTtlTimestamp('2023-01-01T00:00:00.000Z'),
      });

      const record = createSQSRecord(finding, { 'detail-type': 'Security Hub Findings - Imported' });
      await PreProcessor.recordHandler(record);

      const result = await docClient.send(
        new GetCommand({
          TableName: findingsTableName,
          Key: { findingType: 'aws-foundational-security-best-practices/v/1.0.0/S3.1', findingId: finding.Id },
        }),
      );

      expect(result.Item?.remediationStatus).toBe('FAILED'); // Status preserved for NOTIFIED findings
      expect(sfnMock.commandCalls(StartExecutionCommand)).toHaveLength(1);
    });

    it('should not preserve NOTIFIED status for Custom Action detail-type', async () => {
      const finding = createMockFinding({
        Id: 'arn:aws:securityhub:us-east-1:123456789012:subscription/aws-foundational-security-best-practices/v/1.0.0/S3.1/finding/notified-custom-action-finding',
        Workflow: { Status: 'NOTIFIED' },
      });
      await setupControlConfig('S3.1', true);

      const findingRepo = new FindingRepository('test', findingsTableName, docClient);
      await findingRepo.put({
        findingType: 'aws-foundational-security-best-practices/v/1.0.0/S3.1',
        findingId: finding.Id,
        findingDescription: 'Old description',
        accountId: finding.AwsAccountId,
        resourceId: finding.Resources[0].Id,
        resourceType: finding.Resources[0].Type,
        resourceTypeNormalized: normalizeResourceType(finding.Resources[0].Type),
        severity: 'MEDIUM',
        severityNormalized: 2,
        region: finding.Region!,
        remediationStatus: 'FAILED',
        securityHubUpdatedAtTime: '2023-01-01T00:00:00.000Z',
        lastUpdatedTime: '2023-01-01T00:00:00.000Z',
        'securityHubUpdatedAtTime#findingId': '2023-01-01T00:00:00.000Z#' + finding.Id,
        'severityNormalized#securityHubUpdatedAtTime#findingId': '2#2023-01-01T00:00:00.000Z#' + finding.Id,
        findingJSON: new Uint8Array(),
        findingIdControl: finding.Id + '#aws-foundational-security-best-practices/v/1.0.0/S3.1',
        FINDING_CONSTANT: 'finding',
        suppressed: false,
        creationTime: finding.CreatedAt,
        expireAt: calculateTtlTimestamp('2023-01-01T00:00:00.000Z'),
      });

      sfnMock.on(StartExecutionCommand).resolves({
        executionArn: 'arn:aws:states:us-east-1:123456789012:execution:test-state-machine:custom-action-execution-id',
      });

      const record = createSQSRecord(finding, { 'detail-type': 'Security Hub Findings - Custom Action' });
      await PreProcessor.recordHandler(record);

      const result = await docClient.send(
        new GetCommand({
          TableName: findingsTableName,
          Key: { findingType: 'aws-foundational-security-best-practices/v/1.0.0/S3.1', findingId: finding.Id },
        }),
      );

      expect(result.Item?.remediationStatus).toBe('IN_PROGRESS');
      expect(sfnMock.commandCalls(StartExecutionCommand)).toHaveLength(1);
    });

    it('should not preserve NOTIFIED status for API Action detail-type', async () => {
      const finding = createMockFinding({
        Id: 'arn:aws:securityhub:us-east-1:123456789012:subscription/aws-foundational-security-best-practices/v/1.0.0/S3.1/finding/notified-api-action-finding',
        Workflow: { Status: 'NOTIFIED' },
      });
      await setupControlConfig('S3.1', true);

      const findingRepo = new FindingRepository('test', findingsTableName, docClient);
      await findingRepo.put({
        findingType: 'aws-foundational-security-best-practices/v/1.0.0/S3.1',
        findingId: finding.Id,
        findingDescription: 'Old description',
        accountId: finding.AwsAccountId,
        resourceId: finding.Resources[0].Id,
        resourceType: finding.Resources[0].Type,
        resourceTypeNormalized: normalizeResourceType(finding.Resources[0].Type),
        severity: 'MEDIUM',
        severityNormalized: 2,
        region: finding.Region!,
        remediationStatus: 'FAILED',
        securityHubUpdatedAtTime: '2023-01-01T00:00:00.000Z',
        lastUpdatedTime: '2023-01-01T00:00:00.000Z',
        'securityHubUpdatedAtTime#findingId': '2023-01-01T00:00:00.000Z#' + finding.Id,
        'severityNormalized#securityHubUpdatedAtTime#findingId': '2#2023-01-01T00:00:00.000Z#' + finding.Id,
        findingJSON: new Uint8Array(),
        findingIdControl: finding.Id + '#aws-foundational-security-best-practices/v/1.0.0/S3.1',
        FINDING_CONSTANT: 'finding',
        suppressed: false,
        creationTime: finding.CreatedAt,
        expireAt: calculateTtlTimestamp('2023-01-01T00:00:00.000Z'),
      });

      sfnMock.on(StartExecutionCommand).resolves({
        executionArn: 'arn:aws:states:us-east-1:123456789012:execution:test-state-machine:api-action-execution-id',
      });

      const record = createSQSRecord(finding, { 'detail-type': 'Security Hub Findings - API Action' });
      await PreProcessor.recordHandler(record);

      const result = await docClient.send(
        new GetCommand({
          TableName: findingsTableName,
          Key: { findingType: 'aws-foundational-security-best-practices/v/1.0.0/S3.1', findingId: finding.Id },
        }),
      );

      expect(result.Item?.remediationStatus).toBe('IN_PROGRESS');
      expect(sfnMock.commandCalls(StartExecutionCommand)).toHaveLength(1);
    });

    it('should handle malformed orchestratorInput and preserve NOTIFIED status', async () => {
      const finding = createMockFinding({
        Id: 'arn:aws:securityhub:us-east-1:123456789012:subscription/aws-foundational-security-best-practices/v/1.0.0/S3.1/finding/notified-malformed-input-finding',
        Workflow: { Status: 'NOTIFIED' },
      });
      await setupControlConfig('S3.1', true);

      const findingRepo = new FindingRepository('test', findingsTableName, docClient);
      await findingRepo.put({
        findingType: 'aws-foundational-security-best-practices/v/1.0.0/S3.1',
        findingId: finding.Id,
        findingDescription: 'Old description',
        accountId: finding.AwsAccountId,
        resourceId: finding.Resources[0].Id,
        resourceType: finding.Resources[0].Type,
        resourceTypeNormalized: normalizeResourceType(finding.Resources[0].Type),
        severity: 'MEDIUM',
        severityNormalized: 2,
        region: finding.Region!,
        remediationStatus: 'FAILED',
        securityHubUpdatedAtTime: '2023-01-01T00:00:00.000Z',
        lastUpdatedTime: '2023-01-01T00:00:00.000Z',
        'securityHubUpdatedAtTime#findingId': '2023-01-01T00:00:00.000Z#' + finding.Id,
        'severityNormalized#securityHubUpdatedAtTime#findingId': '2#2023-01-01T00:00:00.000Z#' + finding.Id,
        findingJSON: new Uint8Array(),
        findingIdControl: finding.Id + '#aws-foundational-security-best-practices/v/1.0.0/S3.1',
        FINDING_CONSTANT: 'finding',
        suppressed: false,
        creationTime: finding.CreatedAt,
        expireAt: calculateTtlTimestamp('2023-01-01T00:00:00.000Z'),
      });

      const record = createSQSRecord(finding);
      record.body = '{ invalid json }';
      await PreProcessor.recordHandler(record);

      const result = await docClient.send(
        new GetCommand({
          TableName: findingsTableName,
          Key: { findingType: 'aws-foundational-security-best-practices/v/1.0.0/S3.1', findingId: finding.Id },
        }),
      );

      expect(result.Item?.remediationStatus).toBe('FAILED');
      expect(sfnMock.commandCalls(StartExecutionCommand)).toHaveLength(0);
    });

    it('should not preserve status for non-NOTIFIED workflow status', async () => {
      const finding = createMockFinding({
        Id: 'arn:aws:securityhub:us-east-1:123456789012:subscription/aws-foundational-security-best-practices/v/1.0.0/S3.1/finding/non-notified-finding',
        Workflow: { Status: 'NEW' },
      });
      await setupControlConfig('S3.1', true);

      const findingRepo = new FindingRepository('test', findingsTableName, docClient);
      await findingRepo.put({
        findingType: 'aws-foundational-security-best-practices/v/1.0.0/S3.1',
        findingId: finding.Id,
        findingDescription: 'Old description',
        accountId: finding.AwsAccountId,
        resourceId: finding.Resources[0].Id,
        resourceType: finding.Resources[0].Type,
        resourceTypeNormalized: normalizeResourceType(finding.Resources[0].Type),
        severity: 'MEDIUM',
        severityNormalized: 2,
        region: finding.Region!,
        remediationStatus: 'FAILED',
        securityHubUpdatedAtTime: '2023-01-01T00:00:00.000Z',
        lastUpdatedTime: '2023-01-01T00:00:00.000Z',
        'securityHubUpdatedAtTime#findingId': '2023-01-01T00:00:00.000Z#' + finding.Id,
        'severityNormalized#securityHubUpdatedAtTime#findingId': '2#2023-01-01T00:00:00.000Z#' + finding.Id,
        findingJSON: new Uint8Array(),
        findingIdControl: finding.Id + '#aws-foundational-security-best-practices/v/1.0.0/S3.1',
        FINDING_CONSTANT: 'finding',
        suppressed: false,
        creationTime: finding.CreatedAt,
        expireAt: calculateTtlTimestamp('2023-01-01T00:00:00.000Z'),
      });

      sfnMock.on(StartExecutionCommand).resolves({
        executionArn: 'arn:aws:states:us-east-1:123456789012:execution:test-state-machine:non-notified-execution-id',
      });

      const record = createSQSRecord(finding, { 'detail-type': 'Security Hub Findings - Imported' });
      await PreProcessor.recordHandler(record);

      const result = await docClient.send(
        new GetCommand({
          TableName: findingsTableName,
          Key: { findingType: 'aws-foundational-security-best-practices/v/1.0.0/S3.1', findingId: finding.Id },
        }),
      );

      expect(result.Item?.remediationStatus).toBe('IN_PROGRESS'); // Status should be updated
      expect(sfnMock.commandCalls(StartExecutionCommand)).toHaveLength(1);
    });

    it('should trigger remediation for new NOTIFIED findings with regular detail-type', async () => {
      const finding = createMockFinding({
        Id: 'arn:aws:securityhub:us-east-1:123456789012:subscription/aws-foundational-security-best-practices/v/1.0.0/S3.1/finding/new-notified-finding',
        Workflow: { Status: 'NOTIFIED' },
      });
      await setupControlConfig('S3.1', true);

      sfnMock.on(StartExecutionCommand).resolves({
        executionArn: 'arn:aws:states:us-east-1:123456789012:execution:test-state-machine:new-notified-execution',
      });

      const record = createSQSRecord(finding, { 'detail-type': 'Security Hub Findings - Imported' });
      await PreProcessor.recordHandler(record);

      const result = await docClient.send(
        new GetCommand({
          TableName: findingsTableName,
          Key: { findingType: 'aws-foundational-security-best-practices/v/1.0.0/S3.1', findingId: finding.Id },
        }),
      );

      expect(result.Item?.remediationStatus).toBe('IN_PROGRESS'); // New finding with NOTIFIED and auto-remediation enabled should trigger
      expect(sfnMock.commandCalls(StartExecutionCommand)).toHaveLength(1);

      const sfnCall = sfnMock.commandCalls(StartExecutionCommand)[0];
      const inputString = sfnCall.args[0].input?.input;
      expect(inputString).toBeDefined();
      const input = JSON.parse(inputString!);
      expect(input.detail.findings[0].Workflow.Status).toBe('NEW');

      expect(input.findings).toBeUndefined();
    });
  });
});
