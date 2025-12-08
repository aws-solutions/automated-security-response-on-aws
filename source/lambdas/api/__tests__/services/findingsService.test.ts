// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { Logger } from '@aws-lambda-powertools/logger';
import { DynamoDBDocumentClient, PutCommand } from '@aws-sdk/lib-dynamodb';
import nock from 'nock';
import {
  cleanupMetricsMocks,
  createMetricsTestScope,
  setupMetricsMocks,
} from '../../../common/__tests__/metricsMockSetup';
import { FindingRepository } from '../../../common/repositories/findingRepository';
import { AuthenticatedUser } from '../../services/authorization';
import { FindingsService } from '../../services/findingsService';
import { DynamoDBTestSetup } from '../../../common/__tests__/dynamodbSetup';
import { findingsTableName } from '../../../common/__tests__/envSetup';

// Mock the repository
jest.mock('../../../common/repositories/findingRepository');
jest.mock('../../../common/utils/dynamodb');

describe('FindingsService', () => {
  let findingsService: FindingsService;
  let mockRepository: jest.Mocked<FindingRepository>;
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

    process.env.FINDINGS_TABLE_NAME = findingsTableName;
    process.env.REMEDIATION_HISTORY_TABLE_NAME = 'test-remediation-history-table';

    mockLogger = new Logger({ serviceName: 'test' });
    jest.spyOn(mockLogger, 'error').mockImplementation();
    jest.spyOn(mockLogger, 'info').mockImplementation();
    jest.spyOn(mockLogger, 'debug').mockImplementation();

    findingsService = new FindingsService(mockLogger);

    mockRepository = (findingsService as any).findingRepository as jest.Mocked<FindingRepository>;

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
              FieldName: 'Severity.Label',
              Filter: { Value: 'HIGH', Comparison: 'EQUALS' as const },
            },
          ],
          CompositeFilters: [
            {
              Operator: 'AND' as const,
              StringFilters: [
                {
                  FieldName: 'ComplianceStatus',
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
        /.*search_operation.*filter_types_used.*Severity\.Label.*ComplianceStatus.*filter_count.*%3A2.*has_composite_filters.*true.*sort_fields_used.*UpdatedAt.*resource_type.*Findings.*/,
      );
      metricsScope.persist();

      mockRepository.searchFindings.mockResolvedValue({ items: [], nextToken: undefined });

      // ACT
      await findingsService.searchFindings(mockAuthenticatedUser, request);

      // Allow the async metrics api call to be invoked
      await new Promise((resolve) => setTimeout(resolve, 5));

      // ASSERT
      expect(metricsScope.isDone()).toBe(true);
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
        'Finding ID,Finding Type,Finding Title,Account,Resource ID,Resource Type,Severity,Region,Remediation Status,Security Hub Updated Time,Suppressed';
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
        'Finding ID,Finding Type,Finding Title,Account,Resource ID,Resource Type,Severity,Region,Remediation Status,Security Hub Updated Time,Suppressed';
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
});
