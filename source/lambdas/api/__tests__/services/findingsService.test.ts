// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { Logger } from '@aws-lambda-powertools/logger';
import { DynamoDBDocumentClient, PutCommand, GetCommand } from '@aws-sdk/lib-dynamodb';
import { SFNClient, StartExecutionCommand } from '@aws-sdk/client-sfn';
import { mockClient } from 'aws-sdk-client-mock';
import nock from 'nock';
import {
  cleanupMetricsMocks,
  createMetricsTestScope,
  setupMetricsMocks,
} from '../../../common/__tests__/metricsMockSetup';
import { FindingRepository } from '../../../common/repositories/findingRepository';
import { RemediationHistoryRepository } from '../../../common/repositories/remediationHistoryRepository';
import { ControlsRepository } from '../../../common/repositories/controlsRepository';
import { AuthenticatedUser } from '../../services/authorization';
import { FindingsService } from '../../services/findingsService';
import { DynamoDBTestSetup } from '../../../common/__tests__/dynamodbSetup';
import { findingsTableName } from '../../../common/__tests__/envSetup';
import { asFindingId } from '../../../common/__tests__/utils';
import { IdGenerator } from '../../../common/utils/idGenerator';
import { buildOrchestratorInput } from '../../../common/utils/findingExtraction';
import { ASFFFinding, FindingTableItem, type FindingId } from '@asr/data-models';
import { gzip } from 'pako';

const createMockFinding = (overrides: Partial<FindingTableItem> = {}): FindingTableItem => ({
  findingType: 'security-control',
  findingId: asFindingId('test-finding-id'),
  findingDescription: 'Test finding description',
  accountId: '123456789012',
  resourceId: 'arn:aws:s3:::test-bucket',
  resourceType: 'AWS::S3::Bucket',
  resourceTypeNormalized: 'awss3bucket',
  severity: 'HIGH',
  severityNormalized: 3,
  region: 'us-east-1',
  remediationStatus: 'NOT_STARTED',
  securityHubUpdatedAtTime: '2023-01-01T00:00:00Z',
  lastUpdatedTime: '2023-01-01T00:00:00Z',
  'securityHubUpdatedAtTime#findingId': '2023-01-01T00:00:00Z#test-finding-id',
  'severityNormalized#securityHubUpdatedAtTime#findingId': '3#2023-01-01T00:00:00Z#test-finding-id',
  findingJSON: new Uint8Array(Buffer.from('{"test": "data"}')),
  findingIdControl: 'security-control',
  FINDING_CONSTANT: 'finding' as const,
  creationTime: '2023-01-01T00:00:00Z',
  suppressed: false,
  expireAt: Math.floor(Date.now() / 1000) + 8 * 24 * 60 * 60,
  ...overrides,
});

// Mock the repositories
jest.mock('../../../common/repositories/findingRepository');
jest.mock('../../../common/repositories/remediationHistoryRepository');
jest.mock('../../../common/repositories/controlsRepository');
jest.mock('../../../common/utils/dynamodb');

// Step Functions is the real system boundary for orchestration: the
// executeOrchestrator util just wraps SFNClient.send(StartExecutionCommand).
// Mock the SDK client (not our own wrapper) so these tests exercise the real
// orchestrator path and can assert on the StartExecutionCommand that is built.
const sfnMock = mockClient(SFNClient);

describe('FindingsService', () => {
  let findingsService: FindingsService;
  let mockRepository: jest.Mocked<FindingRepository>;
  let mockHistoryRepository: jest.Mocked<RemediationHistoryRepository>;
  let mockControlsRepository: jest.Mocked<ControlsRepository>;
  let mockLogger: Logger;
  let mockAuthenticatedUser: AuthenticatedUser;
  let dynamoDBDocumentClient: DynamoDBDocumentClient;

  beforeAll(async () => {
    await DynamoDBTestSetup.initialize();
    dynamoDBDocumentClient = DynamoDBTestSetup.getDocClient();
    await DynamoDBTestSetup.createFindingsTable(findingsTableName);
  });

  afterAll(async () => {
    await DynamoDBTestSetup.deleteTable(findingsTableName);
  });

  beforeEach(async () => {
    await DynamoDBTestSetup.clearTable(findingsTableName, 'findings');
    setupMetricsMocks();

    sfnMock.reset();
    sfnMock.on(StartExecutionCommand).resolves({ executionArn: 'exec-arn-123' });

    process.env.FINDINGS_TABLE_NAME = findingsTableName;
    process.env.REMEDIATION_HISTORY_TABLE_NAME = 'test-remediation-history-table';

    mockLogger = new Logger({ serviceName: 'test' });
    jest.spyOn(mockLogger, 'error').mockImplementation();
    jest.spyOn(mockLogger, 'info').mockImplementation();
    jest.spyOn(mockLogger, 'debug').mockImplementation();

    mockRepository = new (FindingRepository as jest.Mock)() as jest.Mocked<FindingRepository>;
    mockHistoryRepository =
      new (RemediationHistoryRepository as jest.Mock)() as jest.Mocked<RemediationHistoryRepository>;
    mockControlsRepository = new (ControlsRepository as jest.Mock)() as jest.Mocked<ControlsRepository>;
    // Mirrors a config table seeded with these controls; anything else is absent from the map.
    mockControlsRepository.findRollbackStateByControlIds.mockImplementation(async (controlIds: string[]) => {
      const seeded = ['GuardDuty.IAMUser', 'KMS.4', 'S3.5', 'EC2.8'];
      return new Map(controlIds.filter((id) => seeded.includes(id)).map((id) => [id, true]));
    });

    findingsService = new FindingsService(
      mockLogger,
      undefined,
      undefined,
      mockRepository,
      mockHistoryRepository,
      mockControlsRepository,
    );

    mockAuthenticatedUser = {
      username: 'test-user',
      groups: ['AdminGroup'],
      authorizedAccounts: undefined,
      email: 'test-user@example.com',
    };
  });

  afterEach(async () => {
    jest.clearAllMocks();
    delete process.env.FINDINGS_TABLE_NAME;
    delete process.env.REMEDIATION_HISTORY_TABLE_NAME;
    cleanupMetricsMocks();

    // Allow the async metrics api call to be invoked
    await new Promise((resolve) => setTimeout(resolve, 5));
  });

  describe('searchFindings', () => {
    it('should handle Error exceptions in searchFindings and log them correctly', async () => {
      // Arrange
      const request = {
        NextToken: 'a'.repeat(50),
      };
      const errorException = new Error('Database connection failed');
      errorException.stack = 'Error stack trace';

      mockRepository.searchFindings.mockRejectedValue(errorException);

      await expect(findingsService.searchFindings(mockAuthenticatedUser, request)).rejects.toThrow(
        'Database connection failed',
      );

      expect(mockLogger.error).toHaveBeenCalledWith(
        'Error searching findings',
        expect.objectContaining({
          request: {
            NextToken: 'a'.repeat(20) + '...',
          },
          error: 'Database connection failed',
          stack: 'Error stack trace',
        }),
      );
    });

    it('should handle non-Error exceptions in searchFindings and log them correctly', async () => {
      const request = {
        NextToken: 'short-token',
      };
      const nonErrorException = 'String error message';

      mockRepository.searchFindings.mockRejectedValue(nonErrorException);

      await expect(findingsService.searchFindings(mockAuthenticatedUser, request)).rejects.toBe('String error message');

      // Verify that the error logging handles non-Error exceptions correctly
      expect(mockLogger.error).toHaveBeenCalledWith(
        'Error searching findings',
        expect.objectContaining({
          request: {
            NextToken: 'short-token...',
          },
          error: 'String error message',
          stack: undefined,
        }),
      );
    });

    it('should handle request without NextToken in error logging', async () => {
      const request = {};
      const errorException = new Error('Repository error');

      mockRepository.searchFindings.mockRejectedValue(errorException);

      await expect(findingsService.searchFindings(mockAuthenticatedUser, request)).rejects.toThrow('Repository error');

      // Verify that the error logging handles requests without NextToken
      expect(mockLogger.error).toHaveBeenCalledWith(
        'Error searching findings',
        expect.objectContaining({
          request: {
            NextToken: undefined,
          },
          error: 'Repository error',
          stack: expect.any(String),
        }),
      );
    });

    it('should publish search metrics when searching findings', async () => {
      // ARRANGE
      const request = {
        Filters: {
          StringFilters: [
            {
              FieldName: 'severity',
              Filter: { Value: 'HIGH', Comparison: 'EQUALS' as const },
            },
          ],
          CompositeFilters: [
            {
              Operator: 'AND' as const,
              StringFilters: [
                {
                  FieldName: 'remediationStatus',
                  Filter: { Value: 'FAILED', Comparison: 'EQUALS' as const },
                },
              ],
            },
          ],
        },
        SortCriteria: [{ Field: 'UpdatedAt', SortOrder: 'desc' as const }],
      };

      // Setup separate mock for non-Search metrics API calls
      nock('https://metrics.awssolutionsbuilder.com').post('/generic').reply(200).persist();
      const metricsScope = createMetricsTestScope(
        /.*search_operation.*filter_types_used.*severity.*remediationStatus.*filter_count.*%3A2.*has_composite_filters.*true.*sort_fields_used.*UpdatedAt.*resource_type.*Findings.*/,
      );
      metricsScope.persist();

      mockRepository.searchFindings.mockResolvedValue({ items: [], nextToken: undefined });

      // ACT
      await findingsService.searchFindings(mockAuthenticatedUser, request);

      // Poll for the fire-and-forget metrics POST to land instead of waiting a fixed interval,
      // which races under load and makes this test flaky.
      for (let attempt = 0; attempt < 100 && !metricsScope.isDone(); attempt++) {
        await new Promise((resolve) => setTimeout(resolve, 10));
      }

      // ASSERT
      expect(metricsScope.isDone()).toBe(true);
    });

    it('strips internal-only fields, including metric-enrichment attributes, from the API response', async () => {
      // ARRANGE: a stored finding carrying internal and metric-enrichment attributes
      const storedFinding = createMockFinding({
        firstDetectedTime: '2023-01-01T00:00:00Z',
        hasFindingNotificationsEnabled: true,
        hasFindingRemediationDeadlineConfigured: false,
      });
      mockRepository.searchFindings.mockResolvedValue({ items: [storedFinding], nextToken: undefined });

      // ACT
      const result = await findingsService.searchFindings(mockAuthenticatedUser, {});

      // ASSERT: metric-enrichment attributes and other internal fields are not exposed
      const apiFinding = result.Findings[0];
      expect(apiFinding).not.toHaveProperty('firstDetectedTime');
      expect(apiFinding).not.toHaveProperty('hasFindingNotificationsEnabled');
      expect(apiFinding).not.toHaveProperty('hasFindingRemediationDeadlineConfigured');
      expect(apiFinding).not.toHaveProperty('findingJSON');
      expect(apiFinding).not.toHaveProperty('FINDING_CONSTANT');
      expect(apiFinding).toHaveProperty('expireAt');
      // ...while API-relevant data is still present
      expect(apiFinding.findingId).toBe(storedFinding.findingId);
      expect(apiFinding).toHaveProperty('consoleLink');
    });
  });

  describe('exportFindings', () => {
    beforeEach(() => {
      process.env.CSV_EXPORT_BUCKET_NAME = 'test-export-bucket';

      jest
        .spyOn(findingsService['s3Client'], 'uploadCsvAndGeneratePresignedUrl')
        .mockResolvedValue('https://test-bucket.s3.amazonaws.com/test-file.csv?presigned=true');
    });

    afterEach(() => {
      delete process.env.CSV_EXPORT_BUCKET_NAME;
      jest.restoreAllMocks();
    });

    it('should generate CSV with user-friendly headers', async () => {
      new FindingsService(mockLogger);

      const findingItem = {
        findingType: 'security-control/Lambda.3',
        findingId: 'arn:aws:securityhub:us-east-1:123456789012:security-control/Lambda.3/finding/test',
        'securityHubUpdatedAtTime#findingId':
          '2023-01-01T00:00:00Z#arn:aws:securityhub:us-east-1:123456789012:security-control/Lambda.3/finding/test',
        accountId: '123456789012',
        resourceId: 'arn:aws:lambda:us-east-1:123456789012:function:test',
        resourceType: 'AWS::Lambda::Function',
        resourceTypeNormalized: 'awslambdafunction',
        severity: 'HIGH',
        region: 'us-east-1',
        remediationStatus: 'NOT_STARTED',
        securityHubUpdatedAtTime: '2023-01-01T00:00:00Z',
        findingDescription: 'Lambda function not configured with tracing',
        FINDING_CONSTANT: 'finding',
        lastUpdatedBy: 'test-user@example.com',
        lastUpdatedTime: '2023-01-01T00:00:00Z',
        suppressed: false,
        findingJSON: Buffer.from('{}'),
        findingIdControl: 'Lambda.3',
        expireAt: Math.floor(Date.now() / 1000) + 90 * 24 * 60 * 60,
      };

      await dynamoDBDocumentClient.send(
        new PutCommand({
          TableName: findingsTableName,
          Item: findingItem,
        }),
      );

      mockRepository.searchFindings.mockResolvedValue({
        items: [findingItem as any],
        nextToken: undefined,
      });

      jest
        .spyOn(findingsService['s3Client'], 'uploadCsvAndGeneratePresignedUrl')
        .mockResolvedValue('https://test-bucket.s3.amazonaws.com/test-file.csv?presigned=true');

      const exportRequest = {
        SortCriteria: [
          {
            Field: 'securityHubUpdatedAtTime',
            SortOrder: 'desc' as const,
          },
        ],
      };

      const result = await findingsService.exportFindings(mockAuthenticatedUser, exportRequest);

      expect(result.downloadUrl).toBe('https://test-bucket.s3.amazonaws.com/test-file.csv?presigned=true');
      expect(result.status).toBe('complete');
      expect(result.totalExported).toBe(1);
      expect(result.message).toBeUndefined();

      const uploadCall = jest.mocked(findingsService['s3Client'].uploadCsvAndGeneratePresignedUrl).mock.calls[0];
      const csvContent = uploadCall[2];

      const expectedHeaders =
        'Finding ID,Control ID,Title,Account,Region,Severity,Resource Type,Resource ID,Remediation Status,Detected At,Security Hub Updated Time,Suppressed';
      expect(csvContent).toContain(expectedHeaders);

      const lines = csvContent.split('\n');
      expect(lines[0]).toBe(expectedHeaders);
      expect(lines[1]).toContain('arn:aws:securityhub:us-east-1:123456789012:security-control/Lambda.3/finding/test');
      expect(lines[1]).toContain('123456789012');
      expect(lines[1]).toContain('NOT_STARTED');
      expect(lines[1]).toContain('false');
    });

    it('should generate CSV with headers only when no data exists', async () => {
      mockRepository.searchFindings.mockResolvedValue({
        items: [],
        nextToken: undefined,
      });

      jest
        .spyOn(findingsService['s3Client'], 'uploadCsvAndGeneratePresignedUrl')
        .mockResolvedValue('https://test-bucket.s3.amazonaws.com/test-file.csv?presigned=true');

      const exportRequest = {
        SortCriteria: [
          {
            Field: 'securityHubUpdatedAtTime',
            SortOrder: 'desc' as const,
          },
        ],
      };

      const result = await findingsService.exportFindings(mockAuthenticatedUser, exportRequest);

      expect(result.downloadUrl).toBe('https://test-bucket.s3.amazonaws.com/test-file.csv?presigned=true');
      expect(result.status).toBe('complete');
      expect(result.totalExported).toBe(0);
      expect(result.message).toBeUndefined();

      const uploadCall = jest.mocked(findingsService['s3Client'].uploadCsvAndGeneratePresignedUrl).mock.calls[0];
      const csvContent = uploadCall[2];

      const expectedHeaders =
        'Finding ID,Control ID,Title,Account,Region,Severity,Resource Type,Resource ID,Remediation Status,Detected At,Security Hub Updated Time,Suppressed';
      expect(csvContent).toBe(expectedHeaders);
    });

    it('should handle CSV special characters correctly', async () => {
      const findingItem = {
        findingType: 'security-control/Lambda.3',
        findingId: 'arn:aws:securityhub:us-east-1:123456789012:security-control/Lambda.3/finding/test',
        'securityHubUpdatedAtTime#findingId':
          '2023-01-01T00:00:00Z#arn:aws:securityhub:us-east-1:123456789012:security-control/Lambda.3/finding/test',
        accountId: '123456789012',
        resourceId: 'arn:aws:lambda:us-east-1:123456789012:function:test',
        resourceType: 'AWS::Lambda::Function',
        resourceTypeNormalized: 'awslambdafunction',
        severity: 'HIGH',
        region: 'us-east-1',
        remediationStatus: 'NOT_STARTED',
        securityHubUpdatedAtTime: '2023-01-01T00:00:00Z',
        findingDescription: 'Lambda function "test", has issues',
        FINDING_CONSTANT: 'finding',
        lastUpdatedBy: 'test-user@example.com',
        lastUpdatedTime: '2023-01-01T00:00:00Z',
        suppressed: false,
        findingJSON: Buffer.from('{}'),
        findingIdControl: 'Lambda.3',
        expireAt: Math.floor(Date.now() / 1000) + 90 * 24 * 60 * 60,
      };

      await dynamoDBDocumentClient.send(
        new PutCommand({
          TableName: findingsTableName,
          Item: findingItem,
        }),
      );

      mockRepository.searchFindings.mockResolvedValue({
        items: [findingItem as any],
        nextToken: undefined,
      });

      jest
        .spyOn(findingsService['s3Client'], 'uploadCsvAndGeneratePresignedUrl')
        .mockResolvedValue('https://test-bucket.s3.amazonaws.com/test-file.csv?presigned=true');

      const exportRequest = {
        SortCriteria: [
          {
            Field: 'securityHubUpdatedAtTime',
            SortOrder: 'desc' as const,
          },
        ],
      };

      const result = await findingsService.exportFindings(mockAuthenticatedUser, exportRequest);

      expect(result.status).toBe('complete');
      expect(result.totalExported).toBe(1);

      const uploadCall = jest.mocked(findingsService['s3Client'].uploadCsvAndGeneratePresignedUrl).mock.calls[0];
      const csvContent = uploadCall[2];

      expect(csvContent).toContain('"Lambda function ""test"", has issues"');
    });

    it('should apply filters when exporting findings', async () => {
      const highSeverityFinding = {
        findingType: 'security-control/Lambda.3',
        findingId: 'arn:aws:securityhub:us-east-1:123456789012:security-control/Lambda.3/finding/high',
        'securityHubUpdatedAtTime#findingId':
          '2023-01-01T00:00:00Z#arn:aws:securityhub:us-east-1:123456789012:security-control/Lambda.3/finding/high',
        accountId: '123456789012',
        resourceId: 'arn:aws:lambda:us-east-1:123456789012:function:test-high',
        resourceType: 'AWS::Lambda::Function',
        resourceTypeNormalized: 'awslambdafunction',
        severity: 'HIGH',
        region: 'us-east-1',
        remediationStatus: 'NOT_STARTED',
        securityHubUpdatedAtTime: '2023-01-01T00:00:00Z',
        findingDescription: 'High severity finding',
        FINDING_CONSTANT: 'finding',
        lastUpdatedBy: 'test-user@example.com',
        lastUpdatedTime: '2023-01-01T00:00:00Z',
        suppressed: false,
        findingJSON: Buffer.from('{}'),
        findingIdControl: 'Lambda.3',
        expireAt: Math.floor(Date.now() / 1000) + 90 * 24 * 60 * 60,
      };

      const lowSeverityFinding = {
        findingType: 'security-control/Lambda.4',
        findingId: 'arn:aws:securityhub:us-east-1:123456789012:security-control/Lambda.4/finding/low',
        'securityHubUpdatedAtTime#findingId':
          '2023-01-01T00:00:00Z#arn:aws:securityhub:us-east-1:123456789012:security-control/Lambda.4/finding/low',
        accountId: '123456789012',
        resourceId: 'arn:aws:lambda:us-east-1:123456789012:function:test-low',
        resourceType: 'AWS::Lambda::Function',
        resourceTypeNormalized: 'awslambdafunction',
        severity: 'LOW',
        region: 'us-east-1',
        remediationStatus: 'NOT_STARTED',
        securityHubUpdatedAtTime: '2023-01-01T00:00:00Z',
        findingDescription: 'Low severity finding',
        FINDING_CONSTANT: 'finding',
        lastUpdatedBy: 'test-user@example.com',
        lastUpdatedTime: '2023-01-01T00:00:00Z',
        suppressed: false,
        findingJSON: Buffer.from('{}'),
        findingIdControl: 'Lambda.4',
        expireAt: Math.floor(Date.now() / 1000) + 90 * 24 * 60 * 60,
      };

      await dynamoDBDocumentClient.send(
        new PutCommand({
          TableName: findingsTableName,
          Item: highSeverityFinding,
        }),
      );

      await dynamoDBDocumentClient.send(
        new PutCommand({
          TableName: findingsTableName,
          Item: lowSeverityFinding,
        }),
      );

      mockRepository.searchFindings.mockResolvedValue({
        items: [highSeverityFinding as any],
        nextToken: undefined,
      });

      jest
        .spyOn(findingsService['s3Client'], 'uploadCsvAndGeneratePresignedUrl')
        .mockResolvedValue('https://test-bucket.s3.amazonaws.com/test-file.csv?presigned=true');

      const exportRequest = {
        Filters: {
          CompositeFilters: [
            {
              Operator: 'OR' as const,
              StringFilters: [
                {
                  FieldName: 'severity',
                  Filter: {
                    Value: 'HIGH',
                    Comparison: 'EQUALS' as const,
                  },
                },
              ],
            },
          ],
          CompositeOperator: 'AND' as const,
        },
        SortCriteria: [
          {
            Field: 'securityHubUpdatedAtTime',
            SortOrder: 'desc' as const,
          },
        ],
      };

      const result = await findingsService.exportFindings(mockAuthenticatedUser, exportRequest);

      expect(result.status).toBe('complete');
      expect(result.totalExported).toBe(1);

      const uploadCall = jest.mocked(findingsService['s3Client'].uploadCsvAndGeneratePresignedUrl).mock.calls[0];
      const csvContent = uploadCall[2];

      const lines = csvContent.split('\n');

      expect(lines.length).toBe(2);
      expect(csvContent).toContain('High severity finding');
      expect(csvContent).not.toContain('Low severity finding');
    });

    it('should return partial status when hitting record limit', async () => {
      const createFinding = (i: number) => ({
        findingType: 'security-control/Lambda.3',
        findingId: `arn:aws:securityhub:us-east-1:123456789012:security-control/Lambda.3/finding/test-${i}`,
        'securityHubUpdatedAtTime#findingId': `2023-01-01T00:00:00Z#arn:aws:securityhub:us-east-1:123456789012:security-control/Lambda.3/finding/test-${i}`,
        accountId: '123456789012',
        resourceId: `arn:aws:lambda:us-east-1:123456789012:function:test-${i}`,
        resourceType: 'AWS::Lambda::Function',
        resourceTypeNormalized: 'awslambdafunction',
        severity: 'HIGH',
        region: 'us-east-1',
        remediationStatus: 'NOT_STARTED',
        securityHubUpdatedAtTime: '2023-01-01T00:00:00Z',
        findingDescription: `Finding ${i}`,
        FINDING_CONSTANT: 'finding',
        lastUpdatedBy: 'test-user@example.com',
        lastUpdatedTime: '2023-01-01T00:00:00Z',
        suppressed: false,
        findingJSON: Buffer.from('{}'),
        findingIdControl: 'Lambda.3',
        expireAt: Math.floor(Date.now() / 1000) + 90 * 24 * 60 * 60,
      });

      let callCount = 0;
      mockRepository.searchFindings.mockImplementation(async () => {
        callCount++;
        const items = Array.from({ length: 100 }, (_, i) => createFinding(callCount * 100 + i));
        return {
          items: items as any,
          nextToken: callCount < 500 ? `token-${callCount}` : undefined,
        };
      });

      jest
        .spyOn(findingsService['s3Client'], 'uploadCsvAndGeneratePresignedUrl')
        .mockResolvedValue('https://test-bucket.s3.amazonaws.com/test-file.csv?presigned=true');

      const exportRequest = {
        SortCriteria: [
          {
            Field: 'securityHubUpdatedAtTime',
            SortOrder: 'desc' as const,
          },
        ],
      };

      const result = await findingsService.exportFindings(mockAuthenticatedUser, exportRequest);

      expect(result.status).toBe('partial');
      expect(result.totalExported).toBe(50000);
      expect(result.message).toBe('Maximum export size reached. Apply filters to reduce dataset.');
    });
  });

  describe('buildOrchestratorInput (common utility)', () => {
    const fakeIdGenerator: IdGenerator = {
      randomUUID: () => '00000000-0000-0000-0000-000000000001',
    };
    const fakeClock = { now: () => new Date('2024-06-01T12:00:00Z') };

    it('should use the injected IdGenerator for UUIDs and produce correct action payloads', () => {
      const asffFinding: ASFFFinding = {
        SchemaVersion: '2018-10-08',
        Id: 'arn:aws:securityhub:us-east-1:123456789012:finding/test',
        ProductArn: 'arn:aws:securityhub:us-east-1::product/aws/securityhub',
        GeneratorId: 'aws-foundational-security-best-practices/v/1.0.0/S3.1',
        AwsAccountId: '123456789012',
        Types: ['Software and Configuration Checks'],
        CreatedAt: '2024-01-01T00:00:00Z',
        UpdatedAt: '2024-01-01T00:00:00Z',
        Severity: { Label: 'HIGH', Normalized: 70 },
        Title: 'Test',
        Description: 'Test',
        Resources: [{ Type: 'AwsS3Bucket', Id: 'arn:aws:s3:::bucket', Region: 'us-east-1' }],
        Compliance: { Status: 'FAILED', SecurityControlId: 'S3.1' },
        Region: 'us-east-1',
        WorkflowState: 'NEW',
        RecordState: 'ACTIVE',
      };

      const orchestratorInput = buildOrchestratorInput('S3.1', asffFinding, 'Remediate', fakeIdGenerator, fakeClock);
      const parsed = JSON.parse(orchestratorInput);

      // ASSERT
      expect(parsed.id).toBe('00000000-0000-0000-0000-000000000001');
      expect(parsed.detail.docParameters).toBeUndefined();
      expect(parsed.detail.actionName).toBe('Remediate with ASR');
      // Security Hub findings must NOT carry the multi-service Detail fields —
      // those would force resolve_ssm_doc_for_finding into the multi-service
      // path and bypass the standard control-runbook resolution.
      expect(parsed.detail.findingType).toBeUndefined();
      expect(parsed.detail.remediationId).toBeUndefined();
      expect(parsed.detail.findingFormat).toBeUndefined();

      // Non-GuardDuty rollback without snapshotRollbackParams: no docParameters
      const rollbackInput = buildOrchestratorInput('S3.1', asffFinding, 'Rollback', fakeIdGenerator, fakeClock);
      const parsedRollback = JSON.parse(rollbackInput);
      expect(parsedRollback.detail.docParameters).toBeUndefined();
      expect(parsedRollback.detail.actionName).toBe('ASR:Rollback');

      // When a backup key is supplied to a multi-service control, it flows into
      // docParameters as BackupS3KeyName so AWSSupport-ContainIAMPrincipal can locate the backup.
      const rollbackWithKey = buildOrchestratorInput(
        'GuardDuty.IAMUser',
        asffFinding,
        'Rollback',
        fakeIdGenerator,
        fakeClock,
        '2026/06/12/20/59/exec-contain.json',
      );
      expect(JSON.parse(rollbackWithKey).detail.docParameters).toEqual({
        Action: 'Restore',
        BackupS3KeyName: '2026/06/12/20/59/exec-contain.json',
      });

      const ticketInput = buildOrchestratorInput(
        'S3.1',
        asffFinding,
        'RemediateAndGenerateTicket',
        fakeIdGenerator,
        fakeClock,
      );
      expect(JSON.parse(ticketInput).detail.actionName).toBe('ASR:Remediate&Ticket');
    });

    it('should emit multi-service Detail fields when the row is a multi-service finding', () => {
      const guardDutyAsff: ASFFFinding = {
        SchemaVersion: '2018-10-08',
        Id: 'arn:aws:guardduty:us-east-1:123456789012:detector/abc/finding/def',
        ProductArn: 'arn:aws:securityhub:us-east-1::product/aws/guardduty',
        GeneratorId: 'GuardDuty.IAMUser',
        AwsAccountId: '123456789012',
        Types: [],
        CreatedAt: '2024-01-01T00:00:00Z',
        UpdatedAt: '2024-01-01T00:00:00Z',
        Severity: { Label: 'HIGH', Normalized: 70 },
        Title: 'Anomalous IAM activity',
        Description: '',
        Resources: [{ Type: 'AwsIamAccessKey', Id: 'arn:aws:iam::123456789012:user/u', Region: 'us-east-1' }],
        Compliance: { Status: 'FAILED', SecurityControlId: 'GuardDuty.IAMUser' },
        Region: 'us-east-1',
        WorkflowState: 'NEW',
        RecordState: 'ACTIVE',
      };
      const guardDutyItem = createMockFinding({
        findingType: 'GuardDuty.IAMUser',
        findingId: asFindingId(guardDutyAsff.Id),
      });

      const parsed = JSON.parse(
        buildOrchestratorInput(guardDutyItem.findingType, guardDutyAsff, 'Remediate', fakeIdGenerator, fakeClock),
      );

      // resolve_ssm_doc_for_finding._resolve_doc_for_multi_service_finding
      // looks for these three fields on Detail to route the finding via the
      // multi-service path. Without them the orchestrator falls back to the
      // SH-standard / non-SH-product paths and resolves an empty doc name.
      // findingFormat is always ASFF on the API path because the table only
      // stores the ASFF representation, even for OCSF-ingested findings.
      expect(parsed.detail.findingType).toBe('multiService');
      expect(parsed.detail.remediationId).toBe('GuardDuty.IAMUser');
      expect(parsed.detail.findingFormat).toBe('ASFF');

      // IAM Access Analyzer was ingested as ASFF originally and is also ASFF
      // on the API path — same field value, different reason.
      const iamAccessAnalyzerItem = createMockFinding({ findingType: 'IAMAccessAnalyzer.ExternalAccess' });
      const iamAccessAnalyzerParsed = JSON.parse(
        buildOrchestratorInput(
          iamAccessAnalyzerItem.findingType,
          guardDutyAsff,
          'Remediate',
          fakeIdGenerator,
          fakeClock,
        ),
      );
      expect(iamAccessAnalyzerParsed.detail.findingFormat).toBe('ASFF');
      expect(iamAccessAnalyzerParsed.detail.remediationId).toBe('IAMAccessAnalyzer.ExternalAccess');
    });
  });

  describe('executeAction - Rollback (optimistic lock)', () => {
    const GUARDDUTY_FINDING_TYPE = 'GuardDuty.IAMUser';
    // Valid GuardDuty finding ARN so getControlIdFromFindingId resolves the type.
    const findingId = asFindingId(
      'arn:aws:securityhub:us-east-1:123456789012:subscription/aws/guardduty/GuardDuty.IAMUser/finding/rb-1',
    );

    const guardDutyHistoryEntry = {
      findingType: GUARDDUTY_FINDING_TYPE,
      findingId,
      'findingId#executionId': `${findingId}#exec-contain`,
      accountId: '123456789012',
      resourceId: 'arn:aws:iam::123456789012:user/u',
      resourceType: 'AwsIamAccessKey',
      resourceTypeNormalized: 'AwsIamAccessKey',
      severity: 'HIGH',
      region: 'us-east-1',
      remediationStatus: 'SUCCESS' as const,
      lastUpdatedTime: '2024-01-01T00:00:00Z',
      'lastUpdatedTime#findingId': `2024-01-01T00:00:00Z#${findingId}`,
      lastUpdatedBy: 'tester',
      REMEDIATION_CONSTANT: 'remediation' as const,
      expireAt: Math.floor(Date.now() / 1000) + 8 * 24 * 60 * 60,
      rollbackBackupKey: '2026/06/12/20/59/exec-contain.json',
      // Valid pako-gzipped ASFF JSON so extractASFFFinding can decode it on the
      // rollback path (mirrors what the pre-processor writes to history).
      findingJSON: gzip(
        JSON.stringify({
          Id: findingId,
          AwsAccountId: '123456789012',
          GeneratorId: 'GuardDuty.IAMUser',
          Compliance: { SecurityControlId: 'GuardDuty.IAMUser' },
          Resources: [{ Type: 'AwsIamAccessKey', Id: 'arn:aws:iam::123456789012:user/u', Region: 'us-east-1' }],
          ProductArn: 'arn:aws:securityhub:us-east-1::product/aws/guardduty',
        }),
      ),
    };

    beforeEach(() => {
      // The default IdGenerator uses global crypto.randomUUID, which is absent
      // in this test env; inject a deterministic one so buildOrchestratorInput works.
      const fakeIdGenerator: IdGenerator = { randomUUID: () => '00000000-0000-0000-0000-000000000abc' };

      mockRepository = new (FindingRepository as jest.Mock)() as jest.Mocked<FindingRepository>;
      // Rollback reconstructs the finding from history (carries findingJSON).
      mockHistoryRepository =
        new (RemediationHistoryRepository as jest.Mock)() as jest.Mocked<RemediationHistoryRepository>;
      mockHistoryRepository.createRemediationHistory.mockResolvedValue(undefined);
      mockHistoryRepository.findLatestSuccessWithFindingJSON.mockResolvedValue(guardDutyHistoryEntry);

      findingsService = new FindingsService(
        mockLogger,
        fakeIdGenerator,
        undefined,
        mockRepository,
        mockHistoryRepository,
        mockControlsRepository,
      );

      mockRepository.createIfNotExists.mockResolvedValue('SUCCESS');
    });

    it('reconstructs the finding from history and acquires the lock before invoking the orchestrator', async () => {
      mockRepository.tryAcquireRollbackLock.mockResolvedValue({ outcome: 'ACQUIRED', previousStatus: 'SUCCESS' });

      await findingsService.executeAction({ actionType: 'Rollback', findingIds: [findingId] }, 'tester');

      // History reconstruction is the source of truth for rollback (not a re-find).
      expect(mockHistoryRepository.findLatestSuccessWithFindingJSON).toHaveBeenCalledWith(findingId);
      // Lock acquired on the reconstructed finding before any orchestration.
      expect(mockRepository.tryAcquireRollbackLock).toHaveBeenCalledWith(
        GUARDDUTY_FINDING_TYPE,
        findingId,
        expect.any(String),
        expect.any(String),
      );
      // Orchestrator Step Function started exactly once for the locked finding.
      const startCalls = sfnMock.commandCalls(StartExecutionCommand);
      expect(startCalls).toHaveLength(1);
      // The Contain backup key from history flows through to the Step Function
      // input (Action=Restore) so the Restore can locate the backup.
      const parsed = JSON.parse(startCalls[0].args[0].input.input ?? '{}');
      expect(parsed.detail.docParameters).toEqual({
        Action: 'Restore',
        BackupS3KeyName: '2026/06/12/20/59/exec-contain.json',
      });
      // Rollback history is append-only (must not overwrite the prior SUCCESS row).
      expect(mockHistoryRepository.createRemediationHistory).toHaveBeenCalled();
    });

    it('rejects a second concurrent rollback when the lock is already held', async () => {
      mockRepository.tryAcquireRollbackLock.mockResolvedValue({ outcome: 'IN_PROGRESS' });

      await expect(
        findingsService.executeAction({ actionType: 'Rollback', findingIds: [findingId] }, 'tester'),
      ).rejects.toThrow(/already in progress/i);

      expect(mockHistoryRepository.createRemediationHistory).not.toHaveBeenCalled();
    });

    it('rejects rollback for a non-eligible finding type without touching the lock', async () => {
      const cfnFindingId = asFindingId(
        'arn:aws:securityhub:us-east-1:123456789012:subscription/aws-foundational-security-best-practices/v/1.0.0/CloudFormation.1/finding/x',
      );
      mockHistoryRepository.findLatestSuccessWithFindingJSON.mockResolvedValue({
        ...guardDutyHistoryEntry,
        findingType: 'CloudFormation.1',
        remediationConfigTableKey: 'CloudFormation.1',
        findingId: cfnFindingId,
      });

      await expect(
        findingsService.executeAction({ actionType: 'Rollback', findingIds: [cfnFindingId] }, 'tester'),
      ).rejects.toThrow(`Not eligible for rollback: ${cfnFindingId} (CloudFormation.1)`);

      expect(mockRepository.tryAcquireRollbackLock).not.toHaveBeenCalled();
    });

    describe('executeAction - Rollback lock release on a rejected batch (DynamoDB Local)', () => {
      // The lock semantics are the repository's conditional writes, so these run the real
      // FindingRepository against DynamoDB Local (the module is auto-mocked for the rest of this
      // file; requireActual gets the real class). History and controls stay mocked: they are not
      // what is under test here.
      const { FindingRepository: RealFindingRepository } = jest.requireActual<
        typeof import('../../../common/repositories/findingRepository')
      >('../../../common/repositories/findingRepository');

      const findingId = asFindingId(
        'arn:aws:securityhub:us-east-1:123456789012:subscription/aws/guardduty/GuardDuty.IAMUser/finding/rel-1',
      );
      const secondId = asFindingId(
        'arn:aws:securityhub:us-east-1:123456789012:subscription/aws/guardduty/GuardDuty.IAMUser/finding/rel-2',
      );

      const historyEntryFor = (id: FindingId) => ({
        ...guardDutyHistoryEntry,
        findingId: id,
        'findingId#executionId': `${id}#exec-contain`,
        'lastUpdatedTime#findingId': `2024-01-01T00:00:00Z#${id}`,
      });

      const readRow = async (id: FindingId) => {
        const result = await dynamoDBDocumentClient.send(
          new GetCommand({ TableName: findingsTableName, Key: { findingType: GUARDDUTY_FINDING_TYPE, findingId: id } }),
        );
        return result.Item;
      };

      let realRepository: FindingRepository;
      let service: FindingsService;

      beforeEach(async () => {
        realRepository = new RealFindingRepository('test', findingsTableName, dynamoDBDocumentClient);
        const historyRepository =
          new (RemediationHistoryRepository as jest.Mock)() as jest.Mocked<RemediationHistoryRepository>;
        historyRepository.createRemediationHistory.mockResolvedValue(undefined);
        historyRepository.findLatestSuccessWithFindingJSON.mockImplementation(async (id) => historyEntryFor(id));
        service = new FindingsService(
          mockLogger,
          { randomUUID: () => '00000000-0000-0000-0000-000000000abc' },
          undefined,
          realRepository,
          historyRepository,
          mockControlsRepository,
        );
        // Live rows: the first is rollback-initiable, the second has already been rolled back.
        await realRepository.put(
          createMockFinding({ findingType: GUARDDUTY_FINDING_TYPE, findingId, remediationStatus: 'ROLLBACK_FAILED' }),
        );
        await realRepository.put(
          createMockFinding({
            findingType: GUARDDUTY_FINDING_TYPE,
            findingId: secondId,
            remediationStatus: 'ROLLBACK_SUCCESS',
          }),
        );
      });

      it('hands back the lock it took when another finding in the batch is rejected', async () => {
        await expect(
          service.executeAction({ actionType: 'Rollback', findingIds: [findingId, secondId] }, 'tester'),
        ).rejects.toThrow(`Not eligible: ${secondId} (already rolled back)`);

        // The first finding is back where it was, not parked in ROLLBACK_IN_PROGRESS.
        const first = await readRow(findingId);
        expect(first?.remediationStatus).toBe('ROLLBACK_FAILED');
        expect(first?.rollbackStartedAt).toBeUndefined();
        expect(sfnMock.commandCalls(StartExecutionCommand)).toHaveLength(0);

        // ...and a corrected retry can lock it straight away rather than waiting for staleness.
        await expect(
          service.executeAction({ actionType: 'Rollback', findingIds: [findingId] }, 'tester'),
        ).resolves.toBeDefined();
        expect((await readRow(findingId))?.remediationStatus).toBe('ROLLBACK_IN_PROGRESS');
      });

      it('releases only the locks of findings never sent to the Orchestrator when an invocation throws', async () => {
        // Three findings lock. The Orchestrator accepts the first and throws on the second, so
        // the third is never attempted. The first is running and stays locked. The second stays
        // locked too: StartExecution has no idempotent name, so a call that threw may still have
        // been accepted, and releasing it would let a second request start a duplicate rollback.
        // Only the third — provably never started — goes back.
        const thirdId = asFindingId(`${secondId}-third`);
        await realRepository.put(
          createMockFinding({ findingType: GUARDDUTY_FINDING_TYPE, findingId: secondId, remediationStatus: 'SUCCESS' }),
        );
        await realRepository.put(
          createMockFinding({ findingType: GUARDDUTY_FINDING_TYPE, findingId: thirdId, remediationStatus: 'SUCCESS' }),
        );
        sfnMock.reset();
        sfnMock
          .on(StartExecutionCommand)
          .resolvesOnce({ executionArn: 'arn:aws:states:us-east-1:123456789012:execution:sm:one' })
          .rejectsOnce(new Error('StartExecution failed'));

        await expect(
          service.executeAction({ actionType: 'Rollback', findingIds: [findingId, secondId, thirdId] }, 'tester'),
        ).rejects.toThrow('Failed to execute action on findings');

        expect((await readRow(findingId))?.remediationStatus).toBe('ROLLBACK_IN_PROGRESS');
        expect((await readRow(secondId))?.remediationStatus).toBe('ROLLBACK_IN_PROGRESS');
        const third = await readRow(thirdId);
        expect(third?.remediationStatus).toBe('SUCCESS');
        expect(third?.rollbackStartedAt).toBeUndefined();
      });

      it.each([
        ['FAILED', 'remediation did not succeed'],
        ['ROLLBACK_SUCCESS', 'already rolled back'],
        // A status this build does not know: stored as-is so the row shape is what a newer
        // writer would leave, which the typed item cannot express — hence the raw put.
        ['SOME_FUTURE_STATUS', 'status SOME_FUTURE_STATUS'],
      ])('refuses a %s finding naming the reason "%s", without writing history', async (status, reason) => {
        // The reason comes from the status the conditional write observed atomically when it
        // was refused (ReturnValuesOnConditionCheckFailure), not from a separate read.
        const row = {
          ...createMockFinding({ findingType: GUARDDUTY_FINDING_TYPE, findingId: secondId }),
          remediationStatus: status,
        };
        await dynamoDBDocumentClient.send(new PutCommand({ TableName: findingsTableName, Item: row }));

        await expect(
          service.executeAction({ actionType: 'Rollback', findingIds: [secondId] }, 'tester'),
        ).rejects.toThrow(`Not eligible: ${secondId} (${reason})`);

        expect((await readRow(secondId))?.remediationStatus).toBe(status);
        expect(sfnMock.commandCalls(StartExecutionCommand)).toHaveLength(0);
      });

      it('refuses a finding with no remediation status as "no remediation recorded"', async () => {
        const { remediationStatus: _omitted, ...withoutStatus } = createMockFinding({
          findingType: GUARDDUTY_FINDING_TYPE,
          findingId: secondId,
        });
        await dynamoDBDocumentClient.send(new PutCommand({ TableName: findingsTableName, Item: withoutStatus }));

        await expect(
          service.executeAction({ actionType: 'Rollback', findingIds: [secondId] }, 'tester'),
        ).rejects.toThrow(`Not eligible: ${secondId} (no remediation recorded)`);
      });

      it('leaves a finding locked when the whole batch was accepted', async () => {
        await service.executeAction({ actionType: 'Rollback', findingIds: [findingId] }, 'tester');

        expect((await readRow(findingId))?.remediationStatus).toBe('ROLLBACK_IN_PROGRESS');
        expect(sfnMock.commandCalls(StartExecutionCommand)).toHaveLength(1);
      });

      it('releases the lock when the Orchestrator returns no executionId (provably not started)', async () => {
        // A clean StartExecution response with no executionArn means the orchestrator did not
        // start: the finding is reported unresolved. Unlike the throw path (which may have been
        // accepted and so stays locked), this one is provably unstarted, so its lock must be
        // handed back rather than left ROLLBACK_IN_PROGRESS until stale — otherwise the caller is
        // told "not processed" while an immediate retry is refused as "already in progress".
        sfnMock.reset();
        sfnMock.on(StartExecutionCommand).resolves({}); // no executionArn

        const { unresolvedIds } = await service.executeAction(
          { actionType: 'Rollback', findingIds: [findingId] },
          'tester',
        );

        // Reported unresolved to the caller...
        expect(unresolvedIds).toContain(findingId);
        // ...and the lock is released back to the status it replaced, not parked in progress.
        const row = await readRow(findingId);
        expect(row?.remediationStatus).toBe('ROLLBACK_FAILED');
        expect(row?.rollbackStartedAt).toBeUndefined();
        // ...so an immediate retry can lock it straight away rather than being refused as in-progress.
        sfnMock.reset();
        sfnMock
          .on(StartExecutionCommand)
          .resolves({ executionArn: 'arn:aws:states:us-east-1:123456789012:execution:sm:retry' });
        await service.executeAction({ actionType: 'Rollback', findingIds: [findingId] }, 'tester');
        expect((await readRow(findingId))?.remediationStatus).toBe('ROLLBACK_IN_PROGRESS');
      });
    });
  });

  describe('executeAction - key-based resolution', () => {
    // Macie's finding id is a bare hash (the Security Hub V2 FindingInfoUid), not an ARN, so the
    // partition key cannot be derived from it. The UI sends explicit (findingId, findingType) keys
    // and the service must resolve via findByKeys rather than findByFindingIds.
    const MACIE_FINDING_TYPE = 'Macie.SensitiveDataS3Object';
    const macieFindingId = asFindingId('12984ad04a62649e69fcb701d3557c1d');

    const macieFinding = createMockFinding({
      findingType: MACIE_FINDING_TYPE,
      findingId: macieFindingId,
      resourceId: 'asr-macie-real-9e785a',
      // Macie findings identify an S3 object (SensitiveData:S3Object); the stored
      // resource type is AwsS3Object. This is the type the manual-remediation
      // resource-type guard checks against.
      resourceType: 'AwsS3Object',
      resourceTypeNormalized: 'awss3object',
      findingJSON: gzip(
        JSON.stringify({
          Id: macieFindingId,
          AwsAccountId: '123456789012',
          GeneratorId: 'Macie.SensitiveDataS3Object',
          Compliance: { SecurityControlId: 'Macie.SensitiveDataS3Object' },
          Resources: [{ Type: 'AwsS3Object', Id: 'asr-macie-real-9e785a', Region: 'us-east-1' }],
          ProductArn: 'arn:aws:securityhub:us-east-1::product/aws/macie',
        }),
      ),
    });

    beforeEach(() => {
      const fakeIdGenerator: IdGenerator = { randomUUID: () => '00000000-0000-0000-0000-000000000abc' };
      mockRepository = new (FindingRepository as jest.Mock)() as jest.Mocked<FindingRepository>;
      mockHistoryRepository =
        new (RemediationHistoryRepository as jest.Mock)() as jest.Mocked<RemediationHistoryRepository>;
      mockHistoryRepository.createRemediationHistoryWithFindingUpdate.mockResolvedValue(undefined);
      findingsService = new FindingsService(
        mockLogger,
        fakeIdGenerator,
        undefined,
        mockRepository,
        mockHistoryRepository,
        mockControlsRepository,
      );
    });

    it('resolves findings by explicit keys (not by deriving the partition key from the id)', async () => {
      mockRepository.findByKeys.mockResolvedValue([macieFinding]);

      await findingsService.executeAction(
        {
          actionType: 'Remediate',
          findingIds: [macieFindingId],
          findingKeys: [{ findingId: macieFindingId, findingType: MACIE_FINDING_TYPE }],
        },
        'tester',
      );

      expect(mockRepository.findByKeys).toHaveBeenCalledWith([
        { findingId: macieFindingId, findingType: MACIE_FINDING_TYPE },
      ]);
      expect(mockRepository.findByFindingIds).not.toHaveBeenCalled();
      expect(sfnMock.commandCalls(StartExecutionCommand)).toHaveLength(1);
    });

    it('falls back to findByFindingIds when no explicit keys are supplied', async () => {
      mockRepository.findByFindingIds.mockResolvedValue({ findings: [macieFinding], nonDerivableIds: [] });

      await findingsService.executeAction({ actionType: 'Remediate', findingIds: [macieFindingId] }, 'tester');

      expect(mockRepository.findByFindingIds).toHaveBeenCalledWith([macieFindingId]);
      expect(mockRepository.findByKeys).not.toHaveBeenCalled();
    });

    it('throws when neither keys nor id derivation resolve any finding', async () => {
      mockRepository.findByKeys.mockResolvedValue([]);

      await expect(
        findingsService.executeAction(
          {
            actionType: 'Remediate',
            findingIds: [macieFindingId],
            findingKeys: [{ findingId: macieFindingId, findingType: MACIE_FINDING_TYPE }],
          },
          'tester',
        ),
      ).rejects.toThrow(/No findings found/i);
    });
  });

  describe('executeAction - multi-service resource-type guard', () => {
    // A manual Web UI remediation reads the stored finding and dispatches by its
    // findingType. Findings stored under an earlier build (before ingest-time
    // resource-type gating) could carry a remediation on a resource type it
    // cannot act on. The service must skip these (surfaced as unresolvedIds) and
    // never start an orchestrator execution.
    beforeEach(() => {
      const fakeIdGenerator: IdGenerator = { randomUUID: () => '00000000-0000-0000-0000-0000000000de' };
      mockRepository = new (FindingRepository as jest.Mock)() as jest.Mocked<FindingRepository>;
      mockHistoryRepository =
        new (RemediationHistoryRepository as jest.Mock)() as jest.Mocked<RemediationHistoryRepository>;
      mockHistoryRepository.createRemediationHistoryWithFindingUpdate.mockResolvedValue(undefined);
      findingsService = new FindingsService(
        mockLogger,
        fakeIdGenerator,
        undefined,
        mockRepository,
        mockHistoryRepository,
        mockControlsRepository,
      );
    });
    const unsupportedCases: { name: string; findingType: string; resourceType: string }[] = [
      {
        name: 'Inspector on a Lambda function',
        findingType: 'Inspector.InstanceVulnerability',
        resourceType: 'AwsLambdaFunction',
      },
      {
        name: 'Inspector on an ECR image',
        findingType: 'Inspector.InstanceVulnerability',
        resourceType: 'AwsEcrContainerImage',
      },
      {
        name: 'GuardDuty on a non-access-key resource',
        findingType: 'GuardDuty.IAMUser',
        resourceType: 'AwsEc2Instance',
      },
      {
        name: 'Macie on a non-S3-object resource',
        findingType: 'Macie.SensitiveDataS3Object',
        resourceType: 'AwsEc2Instance',
      },
      {
        name: 'IAM Access Analyzer on an unsupported resource',
        findingType: 'IAMAccessAnalyzer.ExternalAccess',
        resourceType: 'AwsEc2Instance',
      },
    ];

    it.each(unsupportedCases)(
      'skips remediation and returns unresolvedIds for $name',
      async ({ findingType, resourceType }) => {
        const findingId = asFindingId(`unsupported-${findingType}`);
        const finding = createMockFinding({ findingType, findingId, resourceType });
        mockRepository.findByFindingIds.mockResolvedValue({ findings: [finding], nonDerivableIds: [] });

        const result = await findingsService.executeAction(
          { actionType: 'Remediate', findingIds: [findingId] },
          'tester',
        );

        expect(result.unresolvedIds).toEqual([findingId]);
        // No orchestrator execution should have been started for the unsupported finding.
        expect(sfnMock.commandCalls(StartExecutionCommand)).toHaveLength(0);
      },
    );

    it('still remediates a supported multi-service finding (Inspector on EC2)', async () => {
      const findingId = asFindingId('arn:aws:securityhub:us-east-1:123456789012:finding/inspector-ec2');
      const finding = createMockFinding({
        findingType: 'Inspector.InstanceVulnerability',
        findingId,
        resourceType: 'AwsEc2Instance',
        resourceTypeNormalized: 'awsec2instance',
        findingJSON: gzip(
          JSON.stringify({
            Id: findingId,
            AwsAccountId: '123456789012',
            GeneratorId: 'Inspector.InstanceVulnerability',
            Compliance: { SecurityControlId: 'Inspector.InstanceVulnerability' },
            Resources: [
              { Type: 'AwsEc2Instance', Id: 'arn:aws:ec2:us-east-1:123456789012:instance/i-abc', Region: 'us-east-1' },
            ],
            ProductArn: 'arn:aws:securityhub:us-east-1::product/aws/inspector',
          }),
        ),
      });
      mockHistoryRepository.createRemediationHistoryWithFindingUpdate.mockResolvedValue(undefined);
      mockRepository.findByFindingIds.mockResolvedValue({ findings: [finding], nonDerivableIds: [] });

      const result = await findingsService.executeAction(
        { actionType: 'Remediate', findingIds: [findingId] },
        'tester',
      );

      expect(result.unresolvedIds).toBeUndefined();
      expect(sfnMock.commandCalls(StartExecutionCommand)).toHaveLength(1);
    });
  });
});
