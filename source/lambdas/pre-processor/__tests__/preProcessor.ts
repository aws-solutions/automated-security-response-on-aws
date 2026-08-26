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

import { ASFFFinding, ASFFSeverity, OCSFComplianceFinding, NotificationConfigurationItem } from '@asr/data-models';
import type { NormalizedFinding } from '@asr/data-models';
import { SFNClient, StartExecutionCommand } from '@aws-sdk/client-sfn';
import { GetParameterCommand, SSMClient } from '@aws-sdk/client-ssm';
import { DynamoDBDocumentClient, GetCommand, PutCommand } from '@aws-sdk/lib-dynamodb';
import { Context, SQSBatchResponse, SQSEvent, SQSRecord } from 'aws-lambda';
import { mockClient } from 'aws-sdk-client-mock';
import nock from 'nock';
import {
  remediationConfigTableName,
  findingsTableName,
  remediationHistoryTableName,
  notificationConfigTableName,
  resourceFiltersTableName,
} from '../../common/__tests__/envSetup';
import { FINDING_PRINCIPAL } from '../../common/constants/apiConstant';

import { FindingRepository } from '../../common/repositories/findingRepository';
import { NotificationConfigurationRepository } from '../../common/repositories/notificationConfigurationRepository';
import { normalizeResourceType } from '../../common/services/findingDataService';
import { executeOrchestrator } from '../../common/utils/orchestrator';
import { calculateTtlTimestamp } from '../../common/utils/ttlUtils';
import {
  PreProcessor,
  handler,
  convertToMinimalFindingForHistory,
  __findingNotificationConfigEvaluator,
} from '../preProcessor';
import {
  mockVulnerabilityFinding,
  mockIamAccessAnalyzerAsffFinding,
  mockDetectionFinding,
  mockSpoofedGuardDutyDetectionFinding,
  mockSpoofedIamAccessAnalyzerAsffFinding,
  mockSpoofedIamAccessAnalyzerAsffFindingWithControlId,
  mockSpoofedGuardDutyAsffFindingWithControlId,
} from './fixtures/multiServiceFixtures';
import { asFindingId, asConfigId, asResolvedFindingType } from '../../common/__tests__/utils';

describe('PreProcessor Lambda', () => {
  let context: Context;
  let docClient: DynamoDBDocumentClient;
  let sfnMock = mockClient(SFNClient);
  const ssmMock = mockClient(SSMClient);
  const securityHubFindingArn = (suffix: string) =>
    `arn:aws:securityhub:us-east-1:123456789012:subscription/aws-foundational-security-best-practices/v/1.0.0/S3.1/finding/${suffix}`;
  const ASFFFindingId = securityHubFindingArn('asff-finding-id');
  const OCSFFindingId = securityHubFindingArn('ocsf-test');

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

  const createMockNormalizedFinding = (overrides: Partial<NormalizedFinding> = {}): NormalizedFinding => {
    const mockFinding = createMockFinding();
    return {
      id: ASFFFindingId,
      productArn: 'arn:aws:securityhub:us-east-1::product/aws/securityhub',
      findingTypeIdentifier: { type: 'securityControl', value: 'S3.1' },
      accountId: '123456789012',
      region: 'us-east-1',
      severity: 'HIGH',
      complianceStatus: 'FAILED',
      recordState: 'ACTIVE',
      workflowStatus: 'NEW',
      resources: [{ type: 'AwsS3Bucket', id: 'arn:aws:s3:::test-bucket', region: 'us-east-1', tags: undefined }],
      title: 'S3 bucket should prohibit public read access',
      description: 'This control checks whether your S3 buckets allow public read access.',
      createdAt: '2023-01-01T00:00:00.000Z',
      updatedAt: '2024-01-01T00:00:00.000Z',
      format: 'ASFF',
      raw: mockFinding as unknown as Record<string, unknown>,
      ...overrides,
    };
  };

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

    return setupMetricsMocks();
  };

  beforeAll(async () => {
    docClient = DynamoDBTestSetup.getDocClient();
    await DynamoDBTestSetup.createFindingsTable(findingsTableName);
    await DynamoDBTestSetup.createConfigTable(remediationConfigTableName);
    await DynamoDBTestSetup.createRemediationHistoryTable(remediationHistoryTableName);
  });

  afterAll(async () => {
    await DynamoDBTestSetup.deleteTable(findingsTableName);
    await DynamoDBTestSetup.deleteTable(remediationConfigTableName);
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
    await DynamoDBTestSetup.clearTable(remediationConfigTableName, 'config');
    await DynamoDBTestSetup.clearTable(remediationHistoryTableName, 'remediationHistory');
  });

  const setupControlConfig = async (controlId: string, enabled: boolean) => {
    await docClient.send(
      new PutCommand({
        TableName: remediationConfigTableName,
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
          Key: {
            findingType: 'aws-foundational-security-best-practices/v/1.0.0/S3.1',
            findingId: asFindingId(finding.Id),
          },
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
          Key: {
            findingType: 'aws-foundational-security-best-practices/v/1.0.0/S3.1',
            findingId: asFindingId(finding.Id),
          },
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
          Key: {
            findingType: 'aws-foundational-security-best-practices/v/1.0.0/S3.1',
            findingId: asFindingId(finding.Id),
          },
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
        findingId: asFindingId(finding.Id),
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
          Key: {
            findingType: 'aws-foundational-security-best-practices/v/1.0.0/S3.1',
            findingId: asFindingId(finding.Id),
          },
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
        findingId: asFindingId(finding.Id),
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
          Key: {
            findingType: 'aws-foundational-security-best-practices/v/1.0.0/S3.1',
            findingId: asFindingId(finding.Id),
          },
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
        findingId: asFindingId(finding.Id),
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
          Key: {
            findingType: 'aws-foundational-security-best-practices/v/1.0.0/S3.1',
            findingId: asFindingId(finding.Id),
          },
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
        findingId: asFindingId(finding.Id),
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
          Key: {
            findingType: 'aws-foundational-security-best-practices/v/1.0.0/S3.1',
            findingId: asFindingId(finding.Id),
          },
        }),
      );

      expect(result.Item?.suppressed).toBe(true);
    });
  });

  describe('History Creation Error Handling', () => {
    it('should continue orchestrator execution even if history creation fails', async () => {
      await DynamoDBTestSetup.createRemediationHistoryTable('test-history-table-fail');
      process.env.REMEDIATION_HISTORY_TABLE_NAME = 'test-history-table-fail';

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
          Key: {
            findingType: 'aws-foundational-security-best-practices/v/1.0.0/S3.1',
            findingId: asFindingId(finding.Id),
          },
        }),
      );

      expect(findingResult.Item).toBeDefined();
      expect(findingResult.Item?.remediationStatus).toBe('IN_PROGRESS');

      expect(sfnMock.commandCalls(StartExecutionCommand)).toHaveLength(1);

      await DynamoDBTestSetup.deleteTable('test-history-table-fail');
      delete process.env.REMEDIATION_HISTORY_TABLE_NAME;
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
          Key: {
            findingType: 'aws-foundational-security-best-practices/v/1.0.0/UNSUPPORTED.1',
            findingId: asFindingId(finding.Id),
          },
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
            findingId: asFindingId(thisFindingWillSucceed.Id),
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
            findingId: asFindingId(ocsfFinding.finding_info.uid),
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
      const normalized = createMockNormalizedFinding();
      const payload = { source: 'aws.securityhub', account: '123456789012', region: 'us-east-1' };

      const result = PreProcessor.buildOrchestratorInput(normalized, payload);
      const parsed = JSON.parse(result);

      expect(parsed.detail.findings).toHaveLength(1);
      expect(parsed.detail.findings[0]).toEqual(normalized.raw);
      expect(parsed.detail.findingFormat).toBe('ASFF');
      expect(parsed.source).toBe('aws.securityhub');
      expect(parsed.account).toBe('123456789012');
      expect(parsed.region).toBe('us-east-1');
    });

    it('should convert ASFF finding to minimal FindingTableItem for history', () => {
      // ARRANGE — a consolidated Security Hub ARN, so the partition key is derived from the id
      const findingId = 'arn:aws:securityhub:us-east-1:123456789012:security-control/S3.1/finding/minimal-history';
      const finding = createMockFinding({
        Id: findingId,
        AwsAccountId: '123456789012',
        Resources: [{ Type: 'AwsS3Bucket', Id: 'arn:aws:s3:::test-bucket', Region: 'us-east-1' }],
        Severity: { Label: 'HIGH' },
        Region: 'us-west-2',
        Compliance: { Status: 'FAILED', SecurityControlId: 'S3.1' },
      });

      // ACT
      const result = convertToMinimalFindingForHistory(finding, asResolvedFindingType('security-control/S3.1'));

      // ASSERT — the prefixed ARN form, not the bare Compliance.SecurityControlId
      expect(result.findingType).toBe('security-control/S3.1');
      expect(result.findingId).toBe(findingId);
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

    it('should use the supplied findingType for a multi-service finding whose id encodes nothing', () => {
      // ARRANGE — Macie's Security Hub V2 FindingInfoUid is a bare hash, so the key can only come
      // from the caller, who resolved it upstream via resolveFindingType
      const finding = createMockFinding({
        Id: '9f8e7d6c5b4a39281706',
        Compliance: { Status: 'FAILED', SecurityControlId: 'Macie.SensitiveDataS3Object' },
      });

      // ACT
      const result = convertToMinimalFindingForHistory(finding, asResolvedFindingType('Macie.SensitiveDataS3Object'));

      // ASSERT
      expect(result.findingType).toBe('Macie.SensitiveDataS3Object');
      expect(result.findingId).toBe('9f8e7d6c5b4a39281706');
    });

    it('should handle missing optional fields in ASFF finding conversion', () => {
      // ARRANGE
      const findingId = 'arn:aws:securityhub:us-east-1:123456789012:security-control/EC2.1/finding/minimal-history-2';
      const finding = createMockFinding({
        Id: findingId,
        AwsAccountId: '123456789012',
        Resources: [{ Type: 'AwsEc2Instance', Id: 'i-1234567890abcdef0' }],
        Severity: {}, // No Label
        Region: undefined, // No region
        Compliance: { Status: 'FAILED', SecurityControlId: 'EC2.1' },
      });

      // ACT
      const result = convertToMinimalFindingForHistory(finding, asResolvedFindingType('security-control/EC2.1'));

      // ASSERT
      expect(result.findingType).toBe('security-control/EC2.1');
      expect(result.findingId).toBe(findingId);
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
      const normalized = createMockNormalizedFinding({
        id: 'test-finding-id',
        workflowStatus: 'NOTIFIED',
        raw: createMockFinding({ Id: 'test-finding-id', Workflow: { Status: 'NOTIFIED' } }) as unknown as Record<
          string,
          unknown
        >,
      });

      const orchestratorInput = JSON.stringify({
        source: 'aws.securityhub',
        account: '123456789012',
        region: 'us-east-1',
        detail: {
          findings: [normalized.raw],
          actionName: 'None',
        },
      });

      const result = PreProcessor.mapNotifiedFindingForOrchestrator(normalized, orchestratorInput);
      const parsedOutput = JSON.parse(result.orchestratorInput);

      expect(result.normalized.workflowStatus).toBe('NEW');
      expect(result.normalized.id).toBe('test-finding-id');
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
          Key: {
            findingType: 'aws-foundational-security-best-practices/v/1.0.0/EC2.1',
            findingId: asFindingId(finding.Id),
          },
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
          Key: {
            findingType: 'aws-foundational-security-best-practices/v/1.0.0/S3.1',
            findingId: asFindingId(finding.Id),
          },
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
            Key: {
              findingType: 'aws-foundational-security-best-practices/v/1.0.0/S3.1',
              findingId: asFindingId(finding.Id),
            },
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
          Key: {
            findingType: 'aws-foundational-security-best-practices/v/1.0.0/S3.1',
            findingId: asFindingId(finding.Id),
          },
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
          Key: {
            findingType: 'aws-foundational-security-best-practices/v/1.0.0/MISSING.1',
            findingId: asFindingId(finding.Id),
          },
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
        findingId: asFindingId(finding.Id),
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
          Key: {
            findingType: 'aws-foundational-security-best-practices/v/1.0.0/S3.1',
            findingId: asFindingId(finding.Id),
          },
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
            findingId: asFindingId(ocsfFinding.finding_info.uid),
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
              findingId: asFindingId(ocsfFinding.finding_info.uid),
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
        findingId: asFindingId(ocsfFinding.finding_info.uid),
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
            findingId: asFindingId(ocsfFinding.finding_info.uid),
          },
        }),
      );

      expect(result.Item?.remediationStatus).toBe('IN_PROGRESS');
      expect(result.Item?.findingDescription).toBe('OCSF Test Finding');
      expect(result.Item?.severity).toBe('HIGH');
      expect(sfnMock.commandCalls(StartExecutionCommand)).toHaveLength(1);
    });

    it('skips OCSF findings that resolve to no control id', async () => {
      // ARRANGE: an empty compliance.control resolves to no control id, so the
      // finding is unsupported and must be skipped cleanly rather than erroring.
      const invalidOcsfFinding = createMockOCSFFinding({
        compliance: {
          status: 'fail',
          control: '',
          standards: ['aws-foundational-security-best-practices'],
        },
      });
      const record = createSQSRecord(invalidOcsfFinding);

      // ACT / ASSERT: ingestion resolves without error and starts no remediation
      await expect(PreProcessor.recordHandler(record)).resolves.toBeUndefined();
      expect(sfnMock.commandCalls(StartExecutionCommand)).toHaveLength(0);
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
            findingId: asFindingId(ocsfFinding.finding_info.uid),
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
            findingId: asFindingId(ocsfFinding.finding_info.uid),
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
        findingId: asFindingId(finding.Id),
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
          Key: {
            findingType: 'aws-foundational-security-best-practices/v/1.0.0/S3.1',
            findingId: asFindingId(finding.Id),
          },
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
          Key: {
            findingType: 'aws-foundational-security-best-practices/v/1.0.0/S3.1',
            findingId: asFindingId(finding.Id),
          },
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
        findingId: asFindingId(ocsfFinding.finding_info.uid),
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
            findingId: asFindingId(ocsfFinding.finding_info.uid),
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
        findingId: asFindingId(ocsfFinding.finding_info.uid),
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
            findingId: asFindingId(ocsfFinding.finding_info.uid),
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
            findingId: asFindingId(ocsfFinding.finding_info.uid),
          },
        }),
      );
      expect(result.Item).toBeUndefined();
      expect(sfnMock.commandCalls(StartExecutionCommand)).toHaveLength(0);
    });
  });

  describe('Filtering Metrics', () => {
    it('should send filtering metric with "none" when all filters disabled', async () => {
      const finding = createMockFinding({ Id: securityHubFindingArn('metrics-test-finding') });
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
          Key: {
            findingType: 'aws-foundational-security-best-practices/v/1.0.0/S3.1',
            findingId: asFindingId(finding.Id),
          },
        }),
      );
      expect(result.Item?.remediationStatus).toBe('IN_PROGRESS');
    });

    it('should send filtering metric even when finding processing fails', async () => {
      const finding = createMockFinding({ Id: securityHubFindingArn('metrics-error-finding') });
      await setupControlConfig('S3.1', true);

      const ddbMock = mockClient(DynamoDBDocumentClient);
      ddbMock.on(GetCommand, { TableName: remediationConfigTableName }).resolves({
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
            findingId: asFindingId(ocsfFinding.finding_info.uid),
          },
        }),
      );
      expect(result.Item?.remediationStatus).toBe('IN_PROGRESS');
    });

    it('should send filtering metric when auto-remediation is disabled', async () => {
      const finding = createMockFinding({ Id: securityHubFindingArn('metrics-disabled-finding') });
      await setupControlConfig('S3.1', false);

      const metricsScope = setupFilterMetricsMocks();
      const record = createSQSRecord(finding);
      await PreProcessor.recordHandler(record);

      await new Promise((resolve) => setImmediate(resolve));

      expect(metricsScope.isDone()).toBe(true);

      const result = await docClient.send(
        new GetCommand({
          TableName: findingsTableName,
          Key: {
            findingType: 'aws-foundational-security-best-practices/v/1.0.0/S3.1',
            findingId: asFindingId(finding.Id),
          },
        }),
      );
      expect(result.Item?.remediationStatus).toBe('NOT_STARTED');
    });

    it('should send filtering metric for existing finding updates', async () => {
      const finding = createMockFinding({ Id: securityHubFindingArn('metrics-existing-finding') });
      await setupControlConfig('S3.1', true);

      const findingRepo = new FindingRepository('test', findingsTableName, docClient);
      await findingRepo.put({
        findingType: 'aws-foundational-security-best-practices/v/1.0.0/S3.1',
        findingId: asFindingId(finding.Id),
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
        findingIdControl: finding.Id + '#aws-foundational-security-best-practices/v/1.0.0/S3.1',
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
          Key: {
            findingType: 'aws-foundational-security-best-practices/v/1.0.0/S3.1',
            findingId: asFindingId(finding.Id),
          },
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
          Key: {
            findingType: 'aws-foundational-security-best-practices/v/1.0.0/S3.1',
            findingId: asFindingId(finding.Id),
          },
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
          Key: {
            findingType: 'aws-foundational-security-best-practices/v/1.0.0/S3.1',
            findingId: asFindingId(finding.Id),
          },
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
          Key: {
            findingType: 'aws-foundational-security-best-practices/v/1.0.0/S3.1',
            findingId: asFindingId(finding.Id),
          },
        }),
      );

      expect(result.Item).toBeDefined();
      expect(result.Item?.remediationStatus).toBe('IN_PROGRESS');
    });

    it('skips findings with an empty SecurityControlId', async () => {
      // ARRANGE: an empty SecurityControlId resolves to no control id, so the
      // finding is unsupported and must be skipped cleanly rather than erroring.
      const finding = createMockFinding({
        Compliance: { Status: 'FAILED', SecurityControlId: '' },
      });
      const record = createSQSRecord(finding);

      // ACT / ASSERT: ingestion resolves without error and starts no remediation
      await expect(PreProcessor.recordHandler(record)).resolves.toBeUndefined();
      expect(sfnMock.commandCalls(StartExecutionCommand)).toHaveLength(0);
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
          Key: {
            findingType: 'aws-foundational-security-best-practices/v/1.0.0/S3.1',
            findingId: asFindingId(finding.Id),
          },
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
            findingId: asFindingId(ocsfFinding.finding_info.uid),
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
        findingId: asFindingId(finding.Id),
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
          Key: {
            findingType: 'aws-foundational-security-best-practices/v/1.0.0/S3.1',
            findingId: asFindingId(finding.Id),
          },
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
        findingId: asFindingId(finding.Id),
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
          Key: {
            findingType: 'aws-foundational-security-best-practices/v/1.0.0/S3.1',
            findingId: asFindingId(finding.Id),
          },
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
        findingId: asFindingId(finding.Id),
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
          Key: {
            findingType: 'aws-foundational-security-best-practices/v/1.0.0/S3.1',
            findingId: asFindingId(finding.Id),
          },
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
        findingId: asFindingId(finding.Id),
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
          Key: {
            findingType: 'aws-foundational-security-best-practices/v/1.0.0/S3.1',
            findingId: asFindingId(finding.Id),
          },
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
        findingId: asFindingId(finding.Id),
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
          Key: {
            findingType: 'aws-foundational-security-best-practices/v/1.0.0/S3.1',
            findingId: asFindingId(finding.Id),
          },
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
          Key: {
            findingType: 'aws-foundational-security-best-practices/v/1.0.0/S3.1',
            findingId: asFindingId(finding.Id),
          },
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

  describe('SUPPRESSED Status Handling', () => {
    it('should not trigger remediation for new SUPPRESSED findings', async () => {
      const finding = createMockFinding({
        Id: 'arn:aws:securityhub:us-east-1:123456789012:subscription/aws-foundational-security-best-practices/v/1.0.0/S3.1/finding/new-suppressed-finding',
        Workflow: { Status: 'SUPPRESSED' },
      });
      await setupControlConfig('S3.1', true);

      const record = createSQSRecord(finding, { 'detail-type': 'Security Hub Findings - Imported' });
      await PreProcessor.recordHandler(record);

      const result = await docClient.send(
        new GetCommand({
          TableName: findingsTableName,
          Key: {
            findingType: 'aws-foundational-security-best-practices/v/1.0.0/S3.1',
            findingId: asFindingId(finding.Id),
          },
        }),
      );

      // ARRANGE / ACT / ASSERT
      // Verify database item was created for the new finding
      expect(result.Item).toBeDefined();
      expect(result.Item?.findingId).toBe(finding.Id);
      expect(result.Item?.findingType).toBe('aws-foundational-security-best-practices/v/1.0.0/S3.1');
      expect(result.Item?.accountId).toBe(finding.AwsAccountId);
      expect(result.Item?.resourceId).toBe(finding.Resources[0].Id);

      // Verify finding was created with NOT_STARTED status (no remediation triggered)
      expect(result.Item?.remediationStatus).toBe('NOT_STARTED');
      expect(result.Item?.error).toBeUndefined();
      expect(result.Item?.executionId).toBeUndefined(); // No execution ID when remediation not triggered

      // Verify orchestrator was NOT invoked
      expect(sfnMock.commandCalls(StartExecutionCommand)).toHaveLength(0);
    });

    it('should not trigger remediation for existing SUPPRESSED findings', async () => {
      const finding = createMockFinding({
        Id: 'arn:aws:securityhub:us-east-1:123456789012:subscription/aws-foundational-security-best-practices/v/1.0.0/S3.1/finding/existing-suppressed-finding',
        Workflow: { Status: 'SUPPRESSED' },
      });
      await setupControlConfig('S3.1', true);

      // ARRANGE: Create existing finding with NOT_STARTED status
      const findingRepo = new FindingRepository('test', findingsTableName, docClient);
      await findingRepo.put({
        findingType: 'aws-foundational-security-best-practices/v/1.0.0/S3.1',
        findingId: asFindingId(finding.Id),
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
        suppressed: false,
        creationTime: finding.CreatedAt,
        expireAt: calculateTtlTimestamp('2023-01-01T00:00:00.000Z'),
      });

      // ACT: Process SUPPRESSED finding
      const record = createSQSRecord(finding, { 'detail-type': 'Security Hub Findings - Imported' });
      await PreProcessor.recordHandler(record);

      // ASSERT: Verify status was preserved (not changed)
      const result = await docClient.send(
        new GetCommand({
          TableName: findingsTableName,
          Key: {
            findingType: 'aws-foundational-security-best-practices/v/1.0.0/S3.1',
            findingId: asFindingId(finding.Id),
          },
        }),
      );

      expect(result.Item?.remediationStatus).toBe('NOT_STARTED'); // Status preserved
      expect(result.Item?.error).toBeUndefined();

      // Verify orchestrator was NOT invoked
      expect(sfnMock.commandCalls(StartExecutionCommand)).toHaveLength(0);
    });

    it('should not trigger remediation for existing SUPPRESSED findings with previous FAILED status', async () => {
      const finding = createMockFinding({
        Id: 'arn:aws:securityhub:us-east-1:123456789012:subscription/aws-foundational-security-best-practices/v/1.0.0/S3.1/finding/suppressed-previously-failed',
        Workflow: { Status: 'SUPPRESSED' },
      });
      await setupControlConfig('S3.1', true);

      // ARRANGE: Create existing finding with FAILED status (from previous remediation attempt)
      const findingRepo = new FindingRepository('test', findingsTableName, docClient);
      await findingRepo.put({
        findingType: 'aws-foundational-security-best-practices/v/1.0.0/S3.1',
        findingId: asFindingId(finding.Id),
        findingDescription: 'Old description',
        accountId: finding.AwsAccountId,
        resourceId: finding.Resources[0].Id,
        resourceType: finding.Resources[0].Type,
        resourceTypeNormalized: normalizeResourceType(finding.Resources[0].Type),
        severity: 'MEDIUM',
        severityNormalized: 2,
        region: finding.Region!,
        remediationStatus: 'FAILED',
        error: 'Previous remediation failed',
        executionId: 'arn:aws:states:us-east-1:123456789012:execution:test-state-machine:old-execution',
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

      // ACT: Process SUPPRESSED finding
      const record = createSQSRecord(finding, { 'detail-type': 'Security Hub Findings - Imported' });
      await PreProcessor.recordHandler(record);

      // ASSERT: Verify previous FAILED status was preserved
      const result = await docClient.send(
        new GetCommand({
          TableName: findingsTableName,
          Key: {
            findingType: 'aws-foundational-security-best-practices/v/1.0.0/S3.1',
            findingId: asFindingId(finding.Id),
          },
        }),
      );

      expect(result.Item?.remediationStatus).toBe('FAILED'); // Previous status preserved
      expect(result.Item?.error).toBe('Previous remediation failed'); // Previous error preserved
      expect(result.Item?.executionId).toBe(
        'arn:aws:states:us-east-1:123456789012:execution:test-state-machine:old-execution',
      ); // Previous execution ID preserved

      // Verify orchestrator was NOT invoked (no new remediation attempt)
      expect(sfnMock.commandCalls(StartExecutionCommand)).toHaveLength(0);
    });

    it('should not trigger remediation for SUPPRESSED findings with Custom Action', async () => {
      const finding = createMockFinding({
        Id: 'arn:aws:securityhub:us-east-1:123456789012:subscription/aws-foundational-security-best-practices/v/1.0.0/S3.1/finding/suppressed-custom-action',
        Workflow: { Status: 'SUPPRESSED' },
      });
      await setupControlConfig('S3.1', true);

      // ACT: Process SUPPRESSED finding with Custom Action
      const record = createSQSRecord(finding, { 'detail-type': 'Security Hub Findings - Custom Action' });
      await PreProcessor.recordHandler(record);

      // ASSERT: Verify remediation was NOT triggered even for Custom Action
      const result = await docClient.send(
        new GetCommand({
          TableName: findingsTableName,
          Key: {
            findingType: 'aws-foundational-security-best-practices/v/1.0.0/S3.1',
            findingId: asFindingId(finding.Id),
          },
        }),
      );

      expect(result.Item?.remediationStatus).toBe('NOT_STARTED');
      expect(sfnMock.commandCalls(StartExecutionCommand)).toHaveLength(0);
    });

    it('should update finding data but not trigger remediation for SUPPRESSED findings', async () => {
      const finding = createMockFinding({
        Id: 'arn:aws:securityhub:us-east-1:123456789012:subscription/aws-foundational-security-best-practices/v/1.0.0/S3.1/finding/suppressed-data-update',
        Workflow: { Status: 'SUPPRESSED' },
        Title: 'Updated title',
        Description: 'Updated description',
      });
      await setupControlConfig('S3.1', true);

      // ARRANGE: Create existing finding with old data
      const findingRepo = new FindingRepository('test', findingsTableName, docClient);
      await findingRepo.put({
        findingType: 'aws-foundational-security-best-practices/v/1.0.0/S3.1',
        findingId: asFindingId(finding.Id),
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
        suppressed: false,
        creationTime: finding.CreatedAt,
        expireAt: calculateTtlTimestamp('2023-01-01T00:00:00.000Z'),
      });

      // ACT: Process SUPPRESSED finding with updated data
      const record = createSQSRecord(finding, { 'detail-type': 'Security Hub Findings - Imported' });
      await PreProcessor.recordHandler(record);

      // ASSERT: Verify finding data was updated but remediation was not triggered
      const result = await docClient.send(
        new GetCommand({
          TableName: findingsTableName,
          Key: {
            findingType: 'aws-foundational-security-best-practices/v/1.0.0/S3.1',
            findingId: asFindingId(finding.Id),
          },
        }),
      );

      expect(result.Item?.findingDescription).toBe('Updated title'); // Data updated
      expect(result.Item?.remediationStatus).toBe('NOT_STARTED'); // Status preserved
      expect(sfnMock.commandCalls(StartExecutionCommand)).toHaveLength(0); // No orchestrator invocation
    });
  });

  describe('Multi-Service Finding Processing', () => {
    describe('buildOrchestratorInput', () => {
      it('should build orchestrator input with native finding, remediationId, and findingFormat', () => {
        const payload = {
          detail: { findings: [{ old: 'finding' }], source: 'aws.securityhub' },
          'detail-type': 'Imported Finding',
        };
        const nativeFinding = { class_uid: 2002, finding_info: { uid: 'test' } };
        const normalized = createMockNormalizedFinding({
          id: 'test',
          findingTypeIdentifier: { type: 'multiService', value: 'Inspector.InstanceVulnerability' },
          format: 'OCSF',
          raw: nativeFinding as unknown as Record<string, unknown>,
        });
        const result = JSON.parse(PreProcessor.buildOrchestratorInput(normalized, payload));
        expect(result.detail.findings).toEqual([nativeFinding]);
        expect(result.detail.remediationId).toBe('Inspector.InstanceVulnerability');
        expect(result.detail.findingFormat).toBe('OCSF');
        expect(result.detail.actionName).toBe('None');
        expect(result['detail-type']).toBe('Imported Finding');
      });

      it('should default to ASFF findingFormat for securityControl findings', () => {
        const payload = {
          detail: { findings: [{ old: 'finding' }] },
          'detail-type': 'Imported Finding',
        };
        const normalized = createMockNormalizedFinding();
        const result = JSON.parse(PreProcessor.buildOrchestratorInput(normalized, payload));
        expect(result.detail.findingFormat).toBe('ASFF');
        expect(result.detail.remediationId).toBe('S3.1');
        expect(result.detail.findingType).toBe('securityControl');
      });

      it('should handle payload with missing detail gracefully', () => {
        const payload = { 'detail-type': 'Imported Finding' };
        const nativeFinding = { class_uid: 2004 };
        const normalized = createMockNormalizedFinding({
          findingTypeIdentifier: { type: 'multiService', value: 'GuardDuty.IAMUser' },
          format: 'OCSF',
          raw: nativeFinding as unknown as Record<string, unknown>,
        });
        const result = JSON.parse(PreProcessor.buildOrchestratorInput(normalized, payload));
        expect(result.detail.findings).toEqual([nativeFinding]);
        expect(result.detail.remediationId).toBe('GuardDuty.IAMUser');
      });
    });

    const createMultiServiceSQSRecord = (finding: Record<string, unknown>, messageId?: string): SQSRecord => ({
      messageId: messageId ?? 'multi-service-msg-id',
      receiptHandle: 'test-receipt-handle',
      body: JSON.stringify({
        detail: { findings: [finding] },
        'detail-type': 'Imported Finding',
        source: 'aws.securityhub',
        account: '123456789012',
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

    it('should trigger orchestrator and persist finding for multi-service finding with auto-remediation enabled', async () => {
      await setupControlConfig('Inspector.InstanceVulnerability', true);
      setupFilterMetricsMocks();
      sfnMock.on(StartExecutionCommand).resolves({
        executionArn: 'arn:aws:states:us-east-1:123456789012:execution:test:multi-service-exec',
      });

      const record = createMultiServiceSQSRecord(mockVulnerabilityFinding);
      await PreProcessor.recordHandler(record);

      // Verify orchestrator was called with correct input
      expect(sfnMock.commandCalls(StartExecutionCommand)).toHaveLength(1);
      const rawInput = sfnMock.commandCalls(StartExecutionCommand)[0].args[0].input.input;
      if (!rawInput) throw new Error('Expected rawInput to be defined');
      const input = JSON.parse(rawInput);
      expect(input.detail.remediationId).toBe('Inspector.InstanceVulnerability');
      expect(input.detail.findingFormat).toBe('OCSF');
      expect(input.detail.findings[0].class_uid).toBe(2002);

      // Verify finding was persisted in DynamoDB
      const findingResult = await docClient.send(
        new GetCommand({
          TableName: findingsTableName,
          Key: {
            findingType: 'Inspector.InstanceVulnerability',
            findingId: asFindingId('inspector-finding-1'),
          },
        }),
      );
      expect(findingResult.Item).toBeDefined();
      expect(findingResult.Item?.remediationStatus).toBe('IN_PROGRESS');
      expect(findingResult.Item?.accountId).toBe('123456789012');

      // Verify remediation history was created
      const historyResult = await docClient.send(
        new GetCommand({
          TableName: remediationHistoryTableName,
          Key: {
            findingType: 'Inspector.InstanceVulnerability',
            'findingId#executionId': `inspector-finding-1#arn:aws:states:us-east-1:123456789012:execution:test:multi-service-exec`,
          },
        }),
      );
      expect(historyResult.Item).toBeDefined();
      expect(historyResult.Item?.remediationStatus).toBe('IN_PROGRESS');
    });

    it('should persist finding but not trigger orchestrator for multi-service finding with auto-remediation disabled', async () => {
      await setupControlConfig('Inspector.InstanceVulnerability', false);
      setupFilterMetricsMocks();

      const record = createMultiServiceSQSRecord(mockVulnerabilityFinding);
      await PreProcessor.recordHandler(record);

      expect(sfnMock.commandCalls(StartExecutionCommand)).toHaveLength(0);

      // Verify finding was persisted with NOT_STARTED status
      const findingResult = await docClient.send(
        new GetCommand({
          TableName: findingsTableName,
          Key: {
            findingType: 'Inspector.InstanceVulnerability',
            findingId: asFindingId('inspector-finding-1'),
          },
        }),
      );
      expect(findingResult.Item).toBeDefined();
      expect(findingResult.Item?.remediationStatus).toBe('NOT_STARTED');
    });

    it('should return early for unsupported multi-service finding type', async () => {
      // Don't set up config for Inspector.InstanceVulnerability — it won't be in the table
      const record = createMultiServiceSQSRecord(mockVulnerabilityFinding);
      await PreProcessor.recordHandler(record);

      expect(sfnMock.commandCalls(StartExecutionCommand)).toHaveLength(0);
    });

    it('should trigger orchestrator for IAA ASFF finding with no Compliance block (complianceStatus forced to FAILED)', async () => {
      // Raw IAA findings reach ASR without a Compliance block, so asffToNormalized
      // defaults complianceStatus to NOT_AVAILABLE. The multi-service ASFF branch
      // must override to FAILED so shouldTriggerRemediation's gate passes — matches
      // the OCSF multi-service mappers (Inspector/GuardDuty/Macie).
      await setupControlConfig('IAMAccessAnalyzer.ExternalAccess', true);
      setupFilterMetricsMocks();
      sfnMock.on(StartExecutionCommand).resolves({
        executionArn: 'arn:aws:states:us-east-1:123456789012:execution:test:iaa-exec',
      });

      const record = createMultiServiceSQSRecord(mockIamAccessAnalyzerAsffFinding);
      await PreProcessor.recordHandler(record);

      expect(sfnMock.commandCalls(StartExecutionCommand)).toHaveLength(1);
      const rawInput = sfnMock.commandCalls(StartExecutionCommand)[0].args[0].input.input;
      if (!rawInput) throw new Error('Expected rawInput to be defined');
      const input = JSON.parse(rawInput);
      expect(input.detail.remediationId).toBe('IAMAccessAnalyzer.ExternalAccess');
      expect(input.detail.findingFormat).toBe('ASFF');

      const findingResult = await docClient.send(
        new GetCommand({
          TableName: findingsTableName,
          Key: {
            findingType: 'IAMAccessAnalyzer.ExternalAccess',
            findingId: asFindingId(mockIamAccessAnalyzerAsffFinding.Id),
          },
        }),
      );
      expect(findingResult.Item).toBeDefined();
      expect(findingResult.Item?.remediationStatus).toBe('IN_PROGRESS');
    });

    describe('source authenticity — unverified ProductArn is dropped, not routed', () => {
      // A finding that matches a multi-service rule by ProductName/Types/resource but whose
      // ProductArn is not the reserved AWS service ARN must be dropped: not persisted, no
      // orchestrator execution, and crucially not allowed to fall through to standard
      // SecurityControlId-based routing.

      it('drops a spoofed IAA ASFF finding carrying a crafted SecurityControlId (closes the standard-path bypass)', async () => {
        // ARRANGE — enable the control so a regressed drop WOULD record + start the orchestrator
        // via the standard SecurityControlId path. The empty StartExecution assertion is then a
        // key-independent proof that the finding never reached that path.
        await setupControlConfig('IAMAccessAnalyzer.ExternalAccess', true);
        setupFilterMetricsMocks();
        sfnMock.on(StartExecutionCommand).resolves({
          executionArn: 'arn:aws:states:us-east-1:123456789012:execution:test:should-not-run',
        });

        // ACT
        const record = createMultiServiceSQSRecord(mockSpoofedIamAccessAnalyzerAsffFindingWithControlId);
        await PreProcessor.recordHandler(record);

        // ASSERT — no orchestrator, no findings-table row under the multi-service control id
        expect(sfnMock.commandCalls(StartExecutionCommand)).toHaveLength(0);
        const findingResult = await docClient.send(
          new GetCommand({
            TableName: findingsTableName,
            Key: {
              findingType: 'IAMAccessAnalyzer.ExternalAccess',
              findingId: asFindingId(mockSpoofedIamAccessAnalyzerAsffFindingWithControlId.Id),
            },
          }),
        );
        expect(findingResult.Item).toBeUndefined();
      });

      it('drops a spoofed GuardDuty ASFF finding carrying a crafted SecurityControlId', async () => {
        // ARRANGE
        await setupControlConfig('GuardDuty.IAMUser', true);
        setupFilterMetricsMocks();
        sfnMock.on(StartExecutionCommand).resolves({
          executionArn: 'arn:aws:states:us-east-1:123456789012:execution:test:should-not-run',
        });

        // ACT
        const record = createMultiServiceSQSRecord(mockSpoofedGuardDutyAsffFindingWithControlId);
        await PreProcessor.recordHandler(record);

        // ASSERT
        expect(sfnMock.commandCalls(StartExecutionCommand)).toHaveLength(0);
        const findingResult = await docClient.send(
          new GetCommand({
            TableName: findingsTableName,
            Key: {
              findingType: 'GuardDuty.IAMUser',
              findingId: asFindingId(mockSpoofedGuardDutyAsffFindingWithControlId.Id),
            },
          }),
        );
        expect(findingResult.Item).toBeUndefined();
      });

      it('drops a spoofed IAA ASFF finding (no Compliance block) cleanly, without throwing', async () => {
        // ARRANGE
        await setupControlConfig('IAMAccessAnalyzer.ExternalAccess', true);
        setupFilterMetricsMocks();

        // ACT / ASSERT — resolves (dropped), not rejected (would mean retry/DLQ)
        const record = createMultiServiceSQSRecord(mockSpoofedIamAccessAnalyzerAsffFinding);
        await expect(PreProcessor.recordHandler(record)).resolves.toBeUndefined();

        expect(sfnMock.commandCalls(StartExecutionCommand)).toHaveLength(0);
        const findingResult = await docClient.send(
          new GetCommand({
            TableName: findingsTableName,
            Key: {
              findingType: 'IAMAccessAnalyzer.ExternalAccess',
              findingId: asFindingId(mockSpoofedIamAccessAnalyzerAsffFinding.Id),
            },
          }),
        );
        expect(findingResult.Item).toBeUndefined();
      });

      it('drops a spoofed GuardDuty OCSF finding whose product uid is the default product ARN', async () => {
        // ARRANGE
        await setupControlConfig('GuardDuty.IAMUser', true);
        setupFilterMetricsMocks();

        // ACT
        const record = createMultiServiceSQSRecord(mockSpoofedGuardDutyDetectionFinding);
        await PreProcessor.recordHandler(record);

        // ASSERT
        expect(sfnMock.commandCalls(StartExecutionCommand)).toHaveLength(0);
        const findingResult = await docClient.send(
          new GetCommand({
            TableName: findingsTableName,
            Key: { findingType: 'GuardDuty.IAMUser', findingId: asFindingId('guardduty-spoof-1') },
          }),
        );
        expect(findingResult.Item).toBeUndefined();
      });

      it('does not add a dropped spoofed finding to batchItemFailures (no retry/DLQ)', async () => {
        // ARRANGE
        await setupControlConfig('IAMAccessAnalyzer.ExternalAccess', true);
        setupFilterMetricsMocks();

        // ACT
        const sqsEvent: SQSEvent = {
          Records: [
            createMultiServiceSQSRecord(mockSpoofedIamAccessAnalyzerAsffFindingWithControlId, 'spoof-batch-msg'),
          ],
        };
        const result = (await handler(sqsEvent, context, () => {})) as SQSBatchResponse;

        // ASSERT — the message is treated as successfully processed (dropped), not failed
        expect(result.batchItemFailures).toHaveLength(0);
        expect(sfnMock.commandCalls(StartExecutionCommand)).toHaveLength(0);
      });

      it('still routes a genuine finding with the reserved ARN (gate is specific, not a blanket block)', async () => {
        // ARRANGE — genuine GuardDuty OCSF finding with the reserved guardduty product ARN
        await setupControlConfig('GuardDuty.IAMUser', true);
        setupFilterMetricsMocks();
        sfnMock.on(StartExecutionCommand).resolves({
          executionArn: 'arn:aws:states:us-east-1:123456789012:execution:test:genuine-exec',
        });

        // ACT
        const record = createMultiServiceSQSRecord(mockDetectionFinding);
        await PreProcessor.recordHandler(record);

        // ASSERT — routed and persisted IN_PROGRESS
        expect(sfnMock.commandCalls(StartExecutionCommand)).toHaveLength(1);
        const findingResult = await docClient.send(
          new GetCommand({
            TableName: findingsTableName,
            Key: { findingType: 'GuardDuty.IAMUser', findingId: asFindingId('guardduty-finding-1') },
          }),
        );
        expect(findingResult.Item).toBeDefined();
        expect(findingResult.Item?.remediationStatus).toBe('IN_PROGRESS');
      });
    });
  });

  // Feature: automated-remediation-controls, Property 14.1: Filter evaluation integration tests
  // Validates: Section 4.2: Filter Evaluation Logic
  describe('Resource Filter Evaluation Integration', () => {
    const resourceFiltersTableName = process.env.RESOURCE_FILTERS_TABLE_NAME ?? 'test-resource-filters';

    const setupControlConfigWithFilters = async (
      controlId: string,
      enabled: boolean,
      filters: string[],
      filterMode: 'include' | 'exclude' = 'include',
    ) => {
      await docClient.send(
        new PutCommand({
          TableName: remediationConfigTableName,
          Item: {
            controlId,
            automatedRemediationEnabled: enabled,
            filters: filters.length > 0 ? new Set(filters) : undefined,
            filterMode,
          },
        }),
      );
    };

    const setupResourceFilter = async (
      filterId: string,
      options: {
        name?: string;
        accountIds?: string[];
        organizationalUnits?: string[];
        tags?: Array<{ key: string; value: string }>;
        arnPatterns?: string[];
      } = {},
    ) => {
      await docClient.send(
        new PutCommand({
          TableName: resourceFiltersTableName,
          Item: {
            filterId,
            name: options.name ?? `Filter ${filterId}`,
            accountIds: options.accountIds?.length ? new Set(options.accountIds) : undefined,
            organizationalUnits: options.organizationalUnits?.length ? new Set(options.organizationalUnits) : undefined,
            tags: options.tags ?? [],
            arnPatterns: options.arnPatterns?.length ? new Set(options.arnPatterns) : undefined,
          },
        }),
      );
    };

    beforeAll(async () => {
      await DynamoDBTestSetup.createResourceFiltersTable(resourceFiltersTableName);
    });

    afterAll(async () => {
      await DynamoDBTestSetup.deleteTable(resourceFiltersTableName);
    });

    beforeEach(async () => {
      await DynamoDBTestSetup.clearTable(resourceFiltersTableName, 'resourceFilters');
    });

    describe('Include Mode Filter Evaluation', () => {
      it('should allow remediation when finding matches filter criteria in include mode', async () => {
        // ARRANGE
        const finding = createMockFinding({
          Id: 'arn:aws:securityhub:us-east-1:111111111111:subscription/aws-foundational-security-best-practices/v/1.0.0/S3.1/finding/include-match-finding',
          AwsAccountId: '111111111111',
          Resources: [
            {
              Type: 'AwsS3Bucket',
              Id: 'arn:aws:s3:::my-production-bucket',
              Region: 'us-east-1',
              Partition: 'aws',
            },
          ],
        });

        await setupResourceFilter('filter-include-1', {
          accountIds: ['111111111111'],
        });
        await setupControlConfigWithFilters('S3.1', true, ['filter-include-1'], 'include');

        sfnMock.on(StartExecutionCommand).resolves({
          executionArn: 'arn:aws:states:us-east-1:123456789012:execution:test-state-machine:include-match-execution',
        });

        // ACT
        const record = createSQSRecord(finding);
        await PreProcessor.recordHandler(record);

        // ASSERT
        const result = await docClient.send(
          new GetCommand({
            TableName: findingsTableName,
            Key: {
              findingType: 'aws-foundational-security-best-practices/v/1.0.0/S3.1',
              findingId: asFindingId(finding.Id),
            },
          }),
        );

        expect(result.Item).toBeDefined();
        expect(result.Item?.remediationStatus).toBe('IN_PROGRESS');
        expect(sfnMock.commandCalls(StartExecutionCommand)).toHaveLength(1);
      });

      it('should block remediation when finding does not match filter criteria in include mode', async () => {
        // ARRANGE
        const finding = createMockFinding({
          Id: 'arn:aws:securityhub:us-east-1:222222222222:subscription/aws-foundational-security-best-practices/v/1.0.0/S3.1/finding/include-no-match-finding',
          AwsAccountId: '222222222222',
          Resources: [
            {
              Type: 'AwsS3Bucket',
              Id: 'arn:aws:s3:::my-dev-bucket',
              Region: 'us-east-1',
              Partition: 'aws',
            },
          ],
        });

        await setupResourceFilter('filter-include-2', {
          accountIds: ['111111111111'],
        });
        await setupControlConfigWithFilters('S3.1', true, ['filter-include-2'], 'include');

        sfnMock.on(StartExecutionCommand).resolves({
          executionArn: 'arn:aws:states:us-east-1:123456789012:execution:test-state-machine:include-no-match-execution',
        });

        // ACT
        const record = createSQSRecord(finding);
        await PreProcessor.recordHandler(record);

        // ASSERT
        const result = await docClient.send(
          new GetCommand({
            TableName: findingsTableName,
            Key: {
              findingType: 'aws-foundational-security-best-practices/v/1.0.0/S3.1',
              findingId: asFindingId(finding.Id),
            },
          }),
        );

        expect(result.Item).toBeUndefined();
        expect(sfnMock.commandCalls(StartExecutionCommand)).toHaveLength(0);
      });

      it('should require all filters to match in include mode (logical AND)', async () => {
        // ARRANGE
        const finding = createMockFinding({
          Id: 'arn:aws:securityhub:us-east-1:111111111111:subscription/aws-foundational-security-best-practices/v/1.0.0/S3.1/finding/include-multi-filter-finding',
          AwsAccountId: '111111111111',
          Resources: [
            {
              Type: 'AwsS3Bucket',
              Id: 'arn:aws:s3:::my-bucket',
              Region: 'us-east-1',
              Partition: 'aws',
              Tags: { Environment: 'production' },
            },
          ],
        });

        await setupResourceFilter('filter-account', {
          accountIds: ['111111111111'],
        });
        await setupResourceFilter('filter-arn', {
          arnPatterns: ['arn:aws:s3:::other-bucket-*'],
        });
        await setupControlConfigWithFilters('S3.1', true, ['filter-account', 'filter-arn'], 'include');

        sfnMock.on(StartExecutionCommand).resolves({
          executionArn:
            'arn:aws:states:us-east-1:123456789012:execution:test-state-machine:include-multi-filter-execution',
        });

        // ACT
        const record = createSQSRecord(finding);
        await PreProcessor.recordHandler(record);

        // ASSERT
        const result = await docClient.send(
          new GetCommand({
            TableName: findingsTableName,
            Key: {
              findingType: 'aws-foundational-security-best-practices/v/1.0.0/S3.1',
              findingId: asFindingId(finding.Id),
            },
          }),
        );

        expect(result.Item).toBeUndefined();
        expect(sfnMock.commandCalls(StartExecutionCommand)).toHaveLength(0);
      });
    });

    describe('Exclude Mode Filter Evaluation', () => {
      it('should allow remediation when finding does not match filter criteria in exclude mode', async () => {
        // ARRANGE
        const finding = createMockFinding({
          Id: 'arn:aws:securityhub:us-east-1:333333333333:subscription/aws-foundational-security-best-practices/v/1.0.0/S3.1/finding/exclude-no-match-finding',
          AwsAccountId: '333333333333',
          Resources: [
            {
              Type: 'AwsS3Bucket',
              Id: 'arn:aws:s3:::my-dev-bucket',
              Region: 'us-east-1',
              Partition: 'aws',
            },
          ],
        });

        await setupResourceFilter('filter-exclude-1', {
          accountIds: ['111111111111', '222222222222'],
        });
        await setupControlConfigWithFilters('S3.1', true, ['filter-exclude-1'], 'exclude');

        sfnMock.on(StartExecutionCommand).resolves({
          executionArn: 'arn:aws:states:us-east-1:123456789012:execution:test-state-machine:exclude-no-match-execution',
        });

        // ACT
        const record = createSQSRecord(finding);
        await PreProcessor.recordHandler(record);

        // ASSERT
        const result = await docClient.send(
          new GetCommand({
            TableName: findingsTableName,
            Key: {
              findingType: 'aws-foundational-security-best-practices/v/1.0.0/S3.1',
              findingId: asFindingId(finding.Id),
            },
          }),
        );

        expect(result.Item).toBeDefined();
        expect(result.Item?.remediationStatus).toBe('IN_PROGRESS');
        expect(sfnMock.commandCalls(StartExecutionCommand)).toHaveLength(1);
      });

      it('should block remediation when finding matches filter criteria in exclude mode', async () => {
        // ARRANGE
        const finding = createMockFinding({
          Id: 'arn:aws:securityhub:us-east-1:111111111111:subscription/aws-foundational-security-best-practices/v/1.0.0/S3.1/finding/exclude-match-finding',
          AwsAccountId: '111111111111',
          Resources: [
            {
              Type: 'AwsS3Bucket',
              Id: 'arn:aws:s3:::my-production-bucket',
              Region: 'us-east-1',
              Partition: 'aws',
            },
          ],
        });

        await setupResourceFilter('filter-exclude-2', {
          accountIds: ['111111111111'],
        });
        await setupControlConfigWithFilters('S3.1', true, ['filter-exclude-2'], 'exclude');

        sfnMock.on(StartExecutionCommand).resolves({
          executionArn: 'arn:aws:states:us-east-1:123456789012:execution:test-state-machine:exclude-match-execution',
        });

        // ACT
        const record = createSQSRecord(finding);
        await PreProcessor.recordHandler(record);

        // ASSERT
        const result = await docClient.send(
          new GetCommand({
            TableName: findingsTableName,
            Key: {
              findingType: 'aws-foundational-security-best-practices/v/1.0.0/S3.1',
              findingId: asFindingId(finding.Id),
            },
          }),
        );

        expect(result.Item).toBeUndefined();
        expect(sfnMock.commandCalls(StartExecutionCommand)).toHaveLength(0);
      });

      it('should block remediation when any filter matches in exclude mode (any match)', async () => {
        // ARRANGE
        const finding = createMockFinding({
          Id: 'arn:aws:securityhub:us-east-1:111111111111:subscription/aws-foundational-security-best-practices/v/1.0.0/S3.1/finding/exclude-any-match-finding',
          AwsAccountId: '111111111111',
          Resources: [
            {
              Type: 'AwsS3Bucket',
              Id: 'arn:aws:s3:::my-bucket',
              Region: 'us-east-1',
              Partition: 'aws',
            },
          ],
        });

        await setupResourceFilter('filter-exclude-account', {
          accountIds: ['111111111111'],
        });
        await setupResourceFilter('filter-exclude-arn', {
          arnPatterns: ['arn:aws:s3:::other-bucket-*'],
        });
        await setupControlConfigWithFilters('S3.1', true, ['filter-exclude-account', 'filter-exclude-arn'], 'exclude');

        sfnMock.on(StartExecutionCommand).resolves({
          executionArn:
            'arn:aws:states:us-east-1:123456789012:execution:test-state-machine:exclude-any-match-execution',
        });

        // ACT
        const record = createSQSRecord(finding);
        await PreProcessor.recordHandler(record);

        // ASSERT
        const result = await docClient.send(
          new GetCommand({
            TableName: findingsTableName,
            Key: {
              findingType: 'aws-foundational-security-best-practices/v/1.0.0/S3.1',
              findingId: asFindingId(finding.Id),
            },
          }),
        );

        expect(result.Item).toBeUndefined();
        expect(sfnMock.commandCalls(StartExecutionCommand)).toHaveLength(0);
      });
    });

    describe('Edge Cases', () => {
      it('should allow remediation when no filters are configured', async () => {
        // ARRANGE
        const finding = createMockFinding({
          Id: 'arn:aws:securityhub:us-east-1:123456789012:subscription/aws-foundational-security-best-practices/v/1.0.0/S3.1/finding/no-filters-finding',
        });

        await setupControlConfigWithFilters('S3.1', true, [], 'include');

        sfnMock.on(StartExecutionCommand).resolves({
          executionArn: 'arn:aws:states:us-east-1:123456789012:execution:test-state-machine:no-filters-execution',
        });

        // ACT
        const record = createSQSRecord(finding);
        await PreProcessor.recordHandler(record);

        // ASSERT
        const result = await docClient.send(
          new GetCommand({
            TableName: findingsTableName,
            Key: {
              findingType: 'aws-foundational-security-best-practices/v/1.0.0/S3.1',
              findingId: asFindingId(finding.Id),
            },
          }),
        );

        expect(result.Item).toBeDefined();
        expect(result.Item?.remediationStatus).toBe('IN_PROGRESS');
        expect(sfnMock.commandCalls(StartExecutionCommand)).toHaveLength(1);
      });

      it('should block remediation when filter ID does not exist in filters table', async () => {
        // ARRANGE
        const finding = createMockFinding({
          Id: 'arn:aws:securityhub:us-east-1:123456789012:subscription/aws-foundational-security-best-practices/v/1.0.0/S3.1/finding/missing-filter-finding',
        });

        await setupControlConfigWithFilters('S3.1', true, ['non-existent-filter-id'], 'include');

        sfnMock.on(StartExecutionCommand).resolves({
          executionArn: 'arn:aws:states:us-east-1:123456789012:execution:test-state-machine:missing-filter-execution',
        });

        // ACT
        const record = createSQSRecord(finding);
        await PreProcessor.recordHandler(record);

        // ASSERT
        expect(sfnMock.commandCalls(StartExecutionCommand)).toHaveLength(0);
      });

      it('should match ARN patterns with wildcards', async () => {
        // ARRANGE
        const finding = createMockFinding({
          Id: 'arn:aws:securityhub:us-east-1:123456789012:subscription/aws-foundational-security-best-practices/v/1.0.0/S3.1/finding/arn-wildcard-finding',
          Resources: [
            {
              Type: 'AwsS3Bucket',
              Id: 'arn:aws:s3:::my-production-bucket-2024',
              Region: 'us-east-1',
              Partition: 'aws',
            },
          ],
        });

        await setupResourceFilter('filter-arn-wildcard', {
          arnPatterns: ['arn:aws:s3:::my-production-*'],
        });
        await setupControlConfigWithFilters('S3.1', true, ['filter-arn-wildcard'], 'include');

        sfnMock.on(StartExecutionCommand).resolves({
          executionArn: 'arn:aws:states:us-east-1:123456789012:execution:test-state-machine:arn-wildcard-execution',
        });

        // ACT
        const record = createSQSRecord(finding);
        await PreProcessor.recordHandler(record);

        // ASSERT
        const result = await docClient.send(
          new GetCommand({
            TableName: findingsTableName,
            Key: {
              findingType: 'aws-foundational-security-best-practices/v/1.0.0/S3.1',
              findingId: asFindingId(finding.Id),
            },
          }),
        );

        expect(result.Item).toBeDefined();
        expect(result.Item?.remediationStatus).toBe('IN_PROGRESS');
        expect(sfnMock.commandCalls(StartExecutionCommand)).toHaveLength(1);
      });

      it('should not trigger remediation when auto-remediation is disabled even if filters match', async () => {
        // ARRANGE
        const finding = createMockFinding({
          Id: 'arn:aws:securityhub:us-east-1:111111111111:subscription/aws-foundational-security-best-practices/v/1.0.0/S3.1/finding/disabled-with-filters-finding',
          AwsAccountId: '111111111111',
        });

        await setupResourceFilter('filter-disabled', {
          accountIds: ['111111111111'],
        });
        await setupControlConfigWithFilters('S3.1', false, ['filter-disabled'], 'include');

        // ACT
        const record = createSQSRecord(finding);
        await PreProcessor.recordHandler(record);

        // ASSERT
        const result = await docClient.send(
          new GetCommand({
            TableName: findingsTableName,
            Key: {
              findingType: 'aws-foundational-security-best-practices/v/1.0.0/S3.1',
              findingId: asFindingId(finding.Id),
            },
          }),
        );

        expect(result.Item).toBeDefined();
        expect(result.Item?.remediationStatus).toBe('NOT_STARTED');
        expect(sfnMock.commandCalls(StartExecutionCommand)).toHaveLength(0);
      });

      it('should handle filter with multiple criteria types (account + ARN pattern)', async () => {
        // ARRANGE
        const finding = createMockFinding({
          Id: 'arn:aws:securityhub:us-east-1:111111111111:subscription/aws-foundational-security-best-practices/v/1.0.0/S3.1/finding/multi-criteria-finding',
          AwsAccountId: '111111111111',
          Resources: [
            {
              Type: 'AwsS3Bucket',
              Id: 'arn:aws:s3:::prod-bucket-123',
              Region: 'us-east-1',
              Partition: 'aws',
            },
          ],
        });

        await setupResourceFilter('filter-multi-criteria', {
          accountIds: ['111111111111'],
          arnPatterns: ['arn:aws:s3:::prod-*'],
        });
        await setupControlConfigWithFilters('S3.1', true, ['filter-multi-criteria'], 'include');

        sfnMock.on(StartExecutionCommand).resolves({
          executionArn: 'arn:aws:states:us-east-1:123456789012:execution:test-state-machine:multi-criteria-execution',
        });

        // ACT
        const record = createSQSRecord(finding);
        await PreProcessor.recordHandler(record);

        // ASSERT
        const result = await docClient.send(
          new GetCommand({
            TableName: findingsTableName,
            Key: {
              findingType: 'aws-foundational-security-best-practices/v/1.0.0/S3.1',
              findingId: asFindingId(finding.Id),
            },
          }),
        );

        expect(result.Item).toBeDefined();
        expect(result.Item?.remediationStatus).toBe('IN_PROGRESS');
        expect(sfnMock.commandCalls(StartExecutionCommand)).toHaveLength(1);
      });
    });
  });

  describe('Deadline Enforcement Eligibility Stamping', () => {
    let notificationConfigRepository: NotificationConfigurationRepository;
    const enforcementConfigId = asConfigId('aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee');
    const findingTypeKey = 'aws-foundational-security-best-practices/v/1.0.0/S3.1';

    const createEnforcementConfig = (
      overrides: Partial<NotificationConfigurationItem> = {},
    ): NotificationConfigurationItem => ({
      configId: enforcementConfigId,
      name: 'S3.1 Deadline Enforcement',
      enabled: true,
      notificationType: 'finding',
      severityFilter: ['All'],
      controlIds: ['S3.1'],
      resourceFilterIds: [],
      deliveryChannels: [
        {
          type: 'email',
          enabled: true,
          recipients: [{ recipientType: 'custom', emailAddresses: ['test@example.com'] }],
        },
      ],
      batchWindow: { enabled: false },
      contentOptions: {
        includeManualRemediationLink: false,
        includeRemediationDeadline: true,
        remediationDeadlineDays: 5,
        enforceDeadline: true,
        includeIaCSnippet: false,
        includeEnableAutomationLink: false,
      },
      version: 1,
      createdAt: '2024-01-01T00:00:00.000Z',
      createdBy: 'admin@example.com',
      ...overrides,
    });

    const getStoredFinding = async (finding: ASFFFinding) => {
      const result = await docClient.send(
        new GetCommand({
          TableName: findingsTableName,
          Key: { findingType: findingTypeKey, findingId: asFindingId(finding.Id) },
        }),
      );
      return result.Item;
    };

    beforeAll(async () => {
      await DynamoDBTestSetup.createNotificationConfigTable(notificationConfigTableName);
      await DynamoDBTestSetup.createResourceFiltersTable(resourceFiltersTableName);
    });

    afterAll(async () => {
      await DynamoDBTestSetup.deleteTable(notificationConfigTableName);
      await DynamoDBTestSetup.deleteTable(resourceFiltersTableName);
    });

    beforeEach(async () => {
      await DynamoDBTestSetup.clearTable(notificationConfigTableName, 'notificationConfig');
      await DynamoDBTestSetup.clearTable(resourceFiltersTableName, 'resourceFilters');
      // The module-scope evaluator caches enforcement configs for 30s; reset it
      // so each case sees the configs it seeds.
      __findingNotificationConfigEvaluator.clearCache();
      notificationConfigRepository = new NotificationConfigurationRepository(notificationConfigTableName, docClient);
    });

    it('stamps remediationDueBy and enforcementConfigIds when a finding matches an enforcement config', async () => {
      // ARRANGE: enforcement config matches S3.1, auto-remediation disabled so status stays
      // NOT_STARTED. A recently-created finding keeps the creation-time deadline above the
      // 24-hour grace floor, so the stamp is deadline-based and deterministic.
      const dayMs = 24 * 60 * 60 * 1000;
      const recentCreatedAt = new Date(Date.now() - 60 * 1000).toISOString();
      await notificationConfigRepository.create(createEnforcementConfig(), FINDING_PRINCIPAL);
      await setupControlConfig('S3.1', false);
      const finding = createMockFinding({ CreatedAt: recentCreatedAt });

      // ACT
      await PreProcessor.recordHandler(createSQSRecord(finding));

      // ASSERT: due date is creationTime + 5 days and the config id is recorded
      const stored = await getStoredFinding(finding);
      expect(stored?.remediationStatus).toBe('NOT_STARTED');
      expect(stored?.remediationDueBy).toBe(new Date(Date.parse(recentCreatedAt) + 5 * dayMs).toISOString());
      const configIds =
        stored?.enforcementConfigIds instanceof Set
          ? Array.from(stored.enforcementConfigIds)
          : stored?.enforcementConfigIds;
      expect(configIds).toEqual([enforcementConfigId]);
    });

    it('emits a failure metric and still ingests when deadline eligibility evaluation throws', async () => {
      // ARRANGE: a matching enforcement config so the stamp path is reached, but the
      // eligibility evaluation throws. Ingestion must still succeed (finding persisted,
      // no stamp) and a DeadlineEnforcementStampFailure metric must be emitted.
      await notificationConfigRepository.create(createEnforcementConfig(), FINDING_PRINCIPAL);
      await setupControlConfig('S3.1', false);
      const finding = createMockFinding();

      // The evaluator is a module-scoped singleton constructed at import time with
      // its own repository bound to the config table, so a genuine boundary
      // failure cannot be injected without rebuilding the module. Spy on the
      // evaluator instead to simulate any downstream failure (DDB error, config
      // parse error, etc.) surfacing from evaluateFindingConfigs; the test asserts
      // the handler's failure contract (still ingest, emit metric) regardless of
      // the underlying cause.
      const evaluateSpy = jest
        .spyOn(__findingNotificationConfigEvaluator, 'evaluateFindingConfigs')
        .mockRejectedValueOnce(new Error('evaluator boom'));
      const stdoutSpy = jest.spyOn(process.stdout, 'write').mockReturnValue(true);

      // ACT
      await PreProcessor.recordHandler(createSQSRecord(finding));

      // ASSERT: ingestion succeeded without an enforcement stamp
      const stored = await getStoredFinding(finding);
      expect(stored?.remediationStatus).toBe('NOT_STARTED');
      expect(stored?.remediationDueBy).toBeUndefined();
      expect(stored?.enforcementConfigIds).toBeUndefined();

      // ASSERT: the failure metric was emitted to the EMF (stdout) channel
      const emittedMetric = stdoutSpy.mock.calls.some((call) =>
        String(call[0]).includes('DeadlineEnforcementStampFailure'),
      );
      expect(emittedMetric).toBe(true);

      stdoutSpy.mockRestore();
      evaluateSpy.mockRestore();
    });

    it('persists metric-enrichment flags as true when an enabled finding config matches', async () => {
      // ARRANGE: a matching finding config that both notifies and configures a remediation deadline
      await notificationConfigRepository.create(createEnforcementConfig(), FINDING_PRINCIPAL);
      await setupControlConfig('S3.1', false);
      const finding = createMockFinding();

      // ACT
      await PreProcessor.recordHandler(createSQSRecord(finding));

      // ASSERT
      const stored = await getStoredFinding(finding);
      expect(stored?.hasFindingNotificationsEnabled).toBe(true);
      expect(stored?.hasFindingRemediationDeadlineConfigured).toBe(true);
    });

    it('persists metric-enrichment flags as false when no finding config matches', async () => {
      // ARRANGE: no notification configs seeded
      await setupControlConfig('S3.1', false);
      const finding = createMockFinding();

      // ACT
      await PreProcessor.recordHandler(createSQSRecord(finding));

      // ASSERT
      const stored = await getStoredFinding(finding);
      expect(stored?.hasFindingNotificationsEnabled).toBe(false);
      expect(stored?.hasFindingRemediationDeadlineConfigured).toBe(false);
    });

    it('does not stamp when no enforcement config matches the finding control id', async () => {
      // ARRANGE: config targets a different control
      await notificationConfigRepository.create(createEnforcementConfig({ controlIds: ['IAM.1'] }), FINDING_PRINCIPAL);
      await setupControlConfig('S3.1', false);
      const finding = createMockFinding();

      // ACT
      await PreProcessor.recordHandler(createSQSRecord(finding));

      // ASSERT
      const stored = await getStoredFinding(finding);
      expect(stored?.remediationStatus).toBe('NOT_STARTED');
      expect(stored?.remediationDueBy).toBeUndefined();
      expect(stored?.enforcementConfigIds).toBeUndefined();
    });

    it('does not stamp when the finding does not match the config resource filters', async () => {
      // ARRANGE: config references a resource filter scoped to a different account
      const filterId = '99999999-9999-9999-9999-999999999999';
      await docClient.send(
        new PutCommand({
          TableName: resourceFiltersTableName,
          Item: {
            filterId,
            name: 'Other account only',
            accountIds: new Set(['999999999999']),
            organizationalUnits: [],
            tags: [],
            arnPatterns: [],
          },
        }),
      );
      await notificationConfigRepository.create(
        createEnforcementConfig({ resourceFilterIds: [filterId] }),
        FINDING_PRINCIPAL,
      );
      await setupControlConfig('S3.1', false);
      const finding = createMockFinding();

      // ACT
      await PreProcessor.recordHandler(createSQSRecord(finding));

      // ASSERT
      const stored = await getStoredFinding(finding);
      expect(stored?.remediationStatus).toBe('NOT_STARTED');
      expect(stored?.remediationDueBy).toBeUndefined();
      expect(stored?.enforcementConfigIds).toBeUndefined();
    });

    it('does not stamp an auto-remediated finding that is written as IN_PROGRESS', async () => {
      // ARRANGE: matching config, but auto-remediation enabled so the finding is IN_PROGRESS
      await notificationConfigRepository.create(createEnforcementConfig(), FINDING_PRINCIPAL);
      await setupControlConfig('S3.1', true);
      sfnMock.on(StartExecutionCommand).resolves({
        executionArn: 'arn:aws:states:us-east-1:123456789012:execution:test-state-machine:enforcement-skip',
      });
      const finding = createMockFinding();

      // ACT
      await PreProcessor.recordHandler(createSQSRecord(finding));

      // ASSERT: finding is being remediated, so it must not be stamped
      const stored = await getStoredFinding(finding);
      expect(stored?.remediationStatus).toBe('IN_PROGRESS');
      expect(stored?.remediationDueBy).toBeUndefined();
      expect(stored?.enforcementConfigIds).toBeUndefined();
    });

    it('re-stamps an existing finding and tightens the deadline when a shorter-deadline config is added', async () => {
      // ARRANGE: first ingestion stamps the finding via the longer (5-day) config. A recently-created
      // finding keeps both the 5-day and 2-day deadlines above the 24-hour grace floor, so the stamp
      // tracks the configured deadline (not the floor) and the tightening is deterministic.
      const dayMs = 24 * 60 * 60 * 1000;
      const recentCreatedAt = new Date(Date.now() - 60 * 1000).toISOString();
      const shorterDeadlineConfigId = asConfigId('bbbbbbbb-cccc-dddd-eeee-ffffffffffff');
      await notificationConfigRepository.create(createEnforcementConfig(), FINDING_PRINCIPAL);
      await setupControlConfig('S3.1', false);
      const finding = createMockFinding({ CreatedAt: recentCreatedAt });
      await PreProcessor.recordHandler(createSQSRecord(finding));

      const firstStamp = await getStoredFinding(finding);
      expect(firstStamp?.remediationStatus).toBe('NOT_STARTED');
      expect(firstStamp?.remediationDueBy).toBe(new Date(Date.parse(recentCreatedAt) + 5 * dayMs).toISOString());

      // ARRANGE: add a second matching config with a shorter (2-day) deadline and
      // reset the evaluator cache so the re-evaluation sees both configs
      await notificationConfigRepository.create(
        createEnforcementConfig({
          configId: shorterDeadlineConfigId,
          name: 'S3.1 Shorter Deadline',
          contentOptions: {
            includeManualRemediationLink: false,
            includeRemediationDeadline: true,
            remediationDeadlineDays: 2,
            enforceDeadline: true,
            includeIaCSnippet: false,
            includeEnableAutomationLink: false,
          },
        }),
        FINDING_PRINCIPAL,
      );
      __findingNotificationConfigEvaluator.clearCache();

      // ACT: re-ingest the same finding with a newer UpdatedAt so the existing-finding
      // path writes the update and re-evaluates eligibility
      const updatedFinding = createMockFinding({ CreatedAt: recentCreatedAt, UpdatedAt: '2099-01-01T00:00:00.000Z' });
      await PreProcessor.recordHandler(createSQSRecord(updatedFinding));

      // ASSERT: the deadline tightens to creationTime + 2 days and both config ids are recorded
      const stored = await getStoredFinding(finding);
      expect(stored?.remediationStatus).toBe('NOT_STARTED');
      expect(stored?.remediationDueBy).toBe(new Date(Date.parse(recentCreatedAt) + 2 * dayMs).toISOString());
      const configIds =
        stored?.enforcementConfigIds instanceof Set
          ? Array.from(stored.enforcementConfigIds)
          : stored?.enforcementConfigIds;
      expect(configIds).toEqual(expect.arrayContaining([enforcementConfigId, shorterDeadlineConfigId]));
      expect(configIds).toHaveLength(2);
    });
  });

  describe('EventBridge envelope time threading', () => {
    const findingTypeKey = 'aws-foundational-security-best-practices/v/1.0.0/S3.1';

    const getStoredSecurityHubUpdatedAtTime = async (finding: ASFFFinding): Promise<string | undefined> => {
      const result = await docClient.send(
        new GetCommand({
          TableName: findingsTableName,
          Key: { findingType: findingTypeKey, findingId: asFindingId(finding.Id) },
        }),
      );
      return result.Item?.securityHubUpdatedAtTime as string | undefined;
    };

    it('uses a valid EventBridge envelope time as the ordering key over the ASFF UpdatedAt', async () => {
      // ARRANGE: a valid envelope time that differs from the finding's ASFF UpdatedAt
      await setupControlConfig('S3.1', false);
      const eventBridgeTime = '2024-06-01T12:00:00.000Z';
      const finding = createMockFinding({ UpdatedAt: '2023-01-01T00:00:00.000Z' });

      // ACT
      await PreProcessor.recordHandler(createSQSRecord(finding, { time: eventBridgeTime }));

      // ASSERT: the persisted ordering key is the envelope time, not the ASFF UpdatedAt
      expect(await getStoredSecurityHubUpdatedAtTime(finding)).toBe(eventBridgeTime);
    });

    it('falls back to the ASFF UpdatedAt when the EventBridge envelope time is malformed', async () => {
      // ARRANGE: a malformed envelope time and a finding with a well-formed ASFF UpdatedAt
      await setupControlConfig('S3.1', false);
      const asffUpdatedAt = '2023-01-01T00:00:00.000Z';
      const finding = createMockFinding({ UpdatedAt: asffUpdatedAt });

      // ACT
      await PreProcessor.recordHandler(createSQSRecord(finding, { time: 'not-a-date' }));

      // ASSERT: the malformed time is ignored and the ASFF UpdatedAt drives ordering
      expect(await getStoredSecurityHubUpdatedAtTime(finding)).toBe(asffUpdatedAt);
    });
  });
});
