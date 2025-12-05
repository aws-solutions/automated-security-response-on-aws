// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { Logger } from '@aws-lambda-powertools/logger';
import { DynamoDBDocumentClient, PutCommand } from '@aws-sdk/lib-dynamodb';
import { RemediationService } from '../../services/remediationService';
import { AuthenticatedUser } from '../../services/authorization';
import { RemediationsRequest } from '@asr/data-models';
import { DynamoDBTestSetup } from '../../../common/__tests__/dynamodbSetup';
import { findingsTableName } from '../../../common/__tests__/envSetup';
import {
  setupMetricsMocks,
  cleanupMetricsMocks,
  createMetricsTestScope,
} from '../../../common/__tests__/metricsMockSetup';

describe('RemediationService', () => {
  let remediationService: RemediationService;
  let mockLogger: Logger;
  let mockAuthenticatedUser: AuthenticatedUser;
  let dynamoDBDocumentClient: DynamoDBDocumentClient;
  const remediationHistoryTableName = 'test-remediation-history-table';

  beforeAll(async () => {
    await DynamoDBTestSetup.initialize();
    dynamoDBDocumentClient = DynamoDBTestSetup.getDocClient();
    await DynamoDBTestSetup.createFindingsTable(findingsTableName);
    await DynamoDBTestSetup.createRemediationHistoryTable(remediationHistoryTableName);
  });

  afterAll(async () => {
    await DynamoDBTestSetup.deleteTable(findingsTableName);
    await DynamoDBTestSetup.deleteTable(remediationHistoryTableName);
  });

  beforeEach(async () => {
    await DynamoDBTestSetup.clearTable(findingsTableName, 'findings');
    await DynamoDBTestSetup.clearTable(remediationHistoryTableName, 'remediationHistory');
    setupMetricsMocks();

    process.env.REMEDIATION_HISTORY_TABLE_NAME = remediationHistoryTableName;
    process.env.FINDINGS_TABLE_NAME = findingsTableName;

    mockLogger = new Logger({ serviceName: 'test' });
    jest.spyOn(mockLogger, 'error').mockImplementation();
    jest.spyOn(mockLogger, 'info').mockImplementation();
    jest.spyOn(mockLogger, 'debug').mockImplementation();

    remediationService = new RemediationService(mockLogger);

    mockAuthenticatedUser = {
      username: 'test-user@example.com',
      email: 'test-user@example.com',
      groups: ['AdminGroup'],
    };
  });

  afterEach(async () => {
    jest.clearAllMocks();
    cleanupMetricsMocks();
    delete process.env.REMEDIATION_HISTORY_TABLE_NAME;
    delete process.env.FINDINGS_TABLE_NAME;

    // Allow the async metrics api call to be invoked
    await new Promise((resolve) => setTimeout(resolve, 5));
  });

  describe('searchRemediations', () => {
    it('should successfully search remediations and return results', async () => {
      const remediationItem = {
        findingType: 'security-control/Lambda.3',
        findingId: 'arn:aws:securityhub:us-east-1:123456789012:security-control/Lambda.3/finding/test',
        'findingId#executionId':
          'arn:aws:securityhub:us-east-1:123456789012:security-control/Lambda.3/finding/test#arn:aws:states:us-east-1:123456789012:execution:TestStateMachine:exec-123',
        accountId: '123456789012',
        resourceId: 'arn:aws:lambda:us-east-1:123456789012:function:test',
        resourceType: 'AWS::Lambda::Function',
        resourceTypeNormalized: 'awslambdafunction',
        severity: 'HIGH',
        region: 'us-east-1',
        remediationStatus: 'SUCCESS',
        lastUpdatedTime: '2023-01-01T00:00:00Z',
        'lastUpdatedTime#findingId':
          '2023-01-01T00:00:00Z#arn:aws:securityhub:us-east-1:123456789012:security-control/Lambda.3/finding/test',
        REMEDIATION_CONSTANT: 'remediation',
        lastUpdatedBy: 'test-user@example.com',
        executionId: 'arn:aws:states:us-east-1:123456789012:execution:TestStateMachine:exec-123',
        expireAt: Math.floor(Date.now() / 1000) + 90 * 24 * 60 * 60, // 90 days from now
      };

      await dynamoDBDocumentClient.send(
        new PutCommand({
          TableName: remediationHistoryTableName,
          Item: remediationItem,
        }),
      );

      const request: RemediationsRequest = {
        SortCriteria: [
          {
            Field: 'lastUpdatedTime',
            SortOrder: 'desc',
          },
        ],
      };

      const result = await remediationService.searchRemediations(mockAuthenticatedUser, request);

      expect(result).toEqual({
        Remediations: [
          {
            findingType: 'security-control/Lambda.3',
            findingId: 'arn:aws:securityhub:us-east-1:123456789012:security-control/Lambda.3/finding/test',
            accountId: '123456789012',
            resourceId: 'arn:aws:lambda:us-east-1:123456789012:function:test',
            resourceType: 'AWS::Lambda::Function',
            resourceTypeNormalized: 'awslambdafunction',
            severity: 'HIGH',
            region: 'us-east-1',
            remediationStatus: 'SUCCESS',
            lastUpdatedTime: '2023-01-01T00:00:00Z',
            lastUpdatedBy: 'test-user@example.com',
            executionId: 'arn:aws:states:us-east-1:123456789012:execution:TestStateMachine:exec-123',
            consoleLink:
              'https://us-east-1.console.aws.amazon.com/states/home?region=us-east-1#/v2/executions/details/arn%3Aaws%3Astates%3Aus-east-1%3A123456789012%3Aexecution%3ATestStateMachine%3Aexec-123',
          },
        ],
        NextToken: undefined,
      });

      expect(mockLogger.debug).toHaveBeenCalledWith('Searching remediations with request', {
        remediationsRequest: request,
      });

      expect(mockLogger.debug).toHaveBeenCalledWith('Remediation search completed successfully', {
        remediationsCount: 1,
        hasNextToken: false,
      });
    });

    it('should apply account filtering for AccountOperator users', async () => {
      const remediation1 = {
        findingType: 'security-control/Lambda.3',
        findingId: 'arn:aws:securityhub:us-east-1:123456789012:security-control/Lambda.3/finding/test-1',
        'findingId#executionId':
          'arn:aws:securityhub:us-east-1:123456789012:security-control/Lambda.3/finding/test-1#exec-1',
        accountId: '123456789012',
        resourceId: 'arn:aws:lambda:us-east-1:123456789012:function:test-1',
        resourceType: 'AWS::Lambda::Function',
        resourceTypeNormalized: 'awslambdafunction',
        severity: 'HIGH',
        region: 'us-east-1',
        remediationStatus: 'SUCCESS',
        lastUpdatedTime: '2023-01-01T00:00:00Z',
        'lastUpdatedTime#findingId':
          '2023-01-01T00:00:00Z#arn:aws:securityhub:us-east-1:123456789012:security-control/Lambda.3/finding/test-1',
        REMEDIATION_CONSTANT: 'remediation',
        lastUpdatedBy: 'account-operator@example.com',
        executionId: 'exec-1',
        expireAt: Math.floor(Date.now() / 1000) + 90 * 24 * 60 * 60,
      };

      const remediation2 = {
        findingType: 'security-control/Lambda.3',
        findingId: 'arn:aws:securityhub:us-east-1:987654321098:security-control/Lambda.3/finding/test-2',
        'findingId#executionId':
          'arn:aws:securityhub:us-east-1:987654321098:security-control/Lambda.3/finding/test-2#exec-2',
        accountId: '987654321098',
        resourceId: 'arn:aws:lambda:us-east-1:987654321098:function:test-2',
        resourceType: 'AWS::Lambda::Function',
        resourceTypeNormalized: 'awslambdafunction',
        severity: 'MEDIUM',
        region: 'us-east-1',
        remediationStatus: 'FAILED',
        lastUpdatedTime: '2023-01-02T00:00:00Z',
        'lastUpdatedTime#findingId':
          '2023-01-02T00:00:00Z#arn:aws:securityhub:us-east-1:987654321098:security-control/Lambda.3/finding/test-2',
        REMEDIATION_CONSTANT: 'remediation',
        lastUpdatedBy: 'account-operator@example.com',
        executionId: 'exec-2',
        expireAt: Math.floor(Date.now() / 1000) + 90 * 24 * 60 * 60,
      };

      const remediation3 = {
        findingType: 'security-control/Lambda.3',
        findingId: 'arn:aws:securityhub:us-east-1:111111111111:security-control/Lambda.3/finding/test-3',
        'findingId#executionId':
          'arn:aws:securityhub:us-east-1:111111111111:security-control/Lambda.3/finding/test-3#exec-3',
        accountId: '111111111111', // This account should be filtered out
        resourceId: 'arn:aws:lambda:us-east-1:111111111111:function:test-3',
        resourceType: 'AWS::Lambda::Function',
        resourceTypeNormalized: 'awslambdafunction',
        severity: 'LOW',
        region: 'us-east-1',
        remediationStatus: 'SUCCESS',
        lastUpdatedTime: '2023-01-03T00:00:00Z',
        'lastUpdatedTime#findingId':
          '2023-01-03T00:00:00Z#arn:aws:securityhub:us-east-1:111111111111:security-control/Lambda.3/finding/test-3',
        REMEDIATION_CONSTANT: 'remediation',
        lastUpdatedBy: 'account-operator@example.com',
        executionId: 'exec-3',
        expireAt: Math.floor(Date.now() / 1000) + 90 * 24 * 60 * 60,
      };

      await Promise.all([
        dynamoDBDocumentClient.send(new PutCommand({ TableName: remediationHistoryTableName, Item: remediation1 })),
        dynamoDBDocumentClient.send(new PutCommand({ TableName: remediationHistoryTableName, Item: remediation2 })),
        dynamoDBDocumentClient.send(new PutCommand({ TableName: remediationHistoryTableName, Item: remediation3 })),
      ]);

      const accountOperatorUser: AuthenticatedUser = {
        username: 'account-operator@example.com',
        email: 'account-operator@example.com',
        groups: ['AccountOperatorGroup'],
        authorizedAccounts: ['123456789012', '987654321098'],
      };

      const request: RemediationsRequest = {
        SortCriteria: [
          {
            Field: 'lastUpdatedTime',
            SortOrder: 'desc',
          },
        ],
      };

      const result = await remediationService.searchRemediations(accountOperatorUser, request);

      expect(result.Remediations).toHaveLength(2);
      expect(result.Remediations.map((r) => r.accountId)).toEqual(
        expect.arrayContaining(['123456789012', '987654321098']),
      );
      expect(result.Remediations.map((r) => r.accountId)).not.toContain('111111111111');
    });

    it('should handle filters in the request', async () => {
      const successHighRemediation = {
        findingType: 'security-control/Lambda.3',
        findingId: 'arn:aws:securityhub:us-east-1:123456789012:security-control/Lambda.3/finding/success-high',
        'findingId#executionId':
          'arn:aws:securityhub:us-east-1:123456789012:security-control/Lambda.3/finding/success-high#exec-1',
        accountId: '123456789012',
        resourceId: 'arn:aws:lambda:us-east-1:123456789012:function:success-high',
        resourceType: 'AWS::Lambda::Function',
        resourceTypeNormalized: 'awslambdafunction',
        severity: 'HIGH',
        region: 'us-east-1',
        remediationStatus: 'SUCCESS',
        lastUpdatedTime: '2023-01-01T00:00:00Z',
        'lastUpdatedTime#findingId':
          '2023-01-01T00:00:00Z#arn:aws:securityhub:us-east-1:123456789012:security-control/Lambda.3/finding/success-high',
        REMEDIATION_CONSTANT: 'remediation',
        lastUpdatedBy: 'test-user@example.com',
        executionId: 'exec-1',
        expireAt: Math.floor(Date.now() / 1000) + 90 * 24 * 60 * 60,
      };

      const failedHighRemediation = {
        findingType: 'security-control/Lambda.3',
        findingId: 'arn:aws:securityhub:us-east-1:123456789012:security-control/Lambda.3/finding/failed-high',
        'findingId#executionId':
          'arn:aws:securityhub:us-east-1:123456789012:security-control/Lambda.3/finding/failed-high#exec-2',
        accountId: '123456789012',
        resourceId: 'arn:aws:lambda:us-east-1:123456789012:function:failed-high',
        resourceType: 'AWS::Lambda::Function',
        resourceTypeNormalized: 'awslambdafunction',
        severity: 'HIGH',
        region: 'us-east-1',
        remediationStatus: 'FAILED',
        lastUpdatedTime: '2023-01-02T00:00:00Z',
        'lastUpdatedTime#findingId':
          '2023-01-02T00:00:00Z#arn:aws:securityhub:us-east-1:123456789012:security-control/Lambda.3/finding/failed-high',
        REMEDIATION_CONSTANT: 'remediation',
        lastUpdatedBy: 'test-user@example.com',
        executionId: 'exec-2',
        expireAt: Math.floor(Date.now() / 1000) + 90 * 24 * 60 * 60,
      };

      const successMediumRemediation = {
        findingType: 'security-control/Lambda.3',
        findingId: 'arn:aws:securityhub:us-east-1:123456789012:security-control/Lambda.3/finding/success-medium',
        'findingId#executionId':
          'arn:aws:securityhub:us-east-1:123456789012:security-control/Lambda.3/finding/success-medium#exec-3',
        accountId: '123456789012',
        resourceId: 'arn:aws:lambda:us-east-1:123456789012:function:success-medium',
        resourceType: 'AWS::Lambda::Function',
        resourceTypeNormalized: 'awslambdafunction',
        severity: 'MEDIUM',
        region: 'us-east-1',
        remediationStatus: 'SUCCESS',
        lastUpdatedTime: '2023-01-03T00:00:00Z',
        'lastUpdatedTime#findingId':
          '2023-01-03T00:00:00Z#arn:aws:securityhub:us-east-1:123456789012:security-control/Lambda.3/finding/success-medium',
        REMEDIATION_CONSTANT: 'remediation',
        lastUpdatedBy: 'test-user@example.com',
        executionId: 'exec-3',
        expireAt: Math.floor(Date.now() / 1000) + 90 * 24 * 60 * 60,
      };

      await Promise.all([
        dynamoDBDocumentClient.send(
          new PutCommand({ TableName: remediationHistoryTableName, Item: successHighRemediation }),
        ),
        dynamoDBDocumentClient.send(
          new PutCommand({ TableName: remediationHistoryTableName, Item: failedHighRemediation }),
        ),
        dynamoDBDocumentClient.send(
          new PutCommand({ TableName: remediationHistoryTableName, Item: successMediumRemediation }),
        ),
      ]);

      const request: RemediationsRequest = {
        Filters: {
          CompositeFilters: [
            {
              Operator: 'AND',
              StringFilters: [
                {
                  FieldName: 'remediationStatus',
                  Filter: {
                    Value: 'SUCCESS',
                    Comparison: 'EQUALS',
                  },
                },
                {
                  FieldName: 'severity',
                  Filter: {
                    Value: 'HIGH',
                    Comparison: 'EQUALS',
                  },
                },
              ],
            },
          ],
        },
        SortCriteria: [
          {
            Field: 'lastUpdatedTime',
            SortOrder: 'asc',
          },
        ],
      };

      const result = await remediationService.searchRemediations(mockAuthenticatedUser, request);

      expect(result.Remediations).toHaveLength(1);
      expect(result.Remediations[0].remediationStatus).toBe('SUCCESS');
      expect(result.Remediations[0].severity).toBe('HIGH');
      expect(result.Remediations[0].findingId).toContain('success-high');
    });

    it('should return empty results when no data exists', async () => {
      const request: RemediationsRequest = {
        SortCriteria: [
          {
            Field: 'lastUpdatedTime',
            SortOrder: 'desc',
          },
        ],
      };

      const result = await remediationService.searchRemediations(mockAuthenticatedUser, request);

      expect(result).toEqual({
        Remediations: [],
        NextToken: undefined,
      });

      expect(mockLogger.debug).toHaveBeenCalledWith('Searching remediations with request', {
        remediationsRequest: request,
      });

      expect(mockLogger.debug).toHaveBeenCalledWith('Remediation search completed successfully', {
        remediationsCount: 0,
        hasNextToken: false,
      });
    });

    it('should remove internal fields from API response', async () => {
      const remediationItem = {
        findingType: 'security-control/Lambda.3',
        findingId: 'test-finding-id',
        'findingId#executionId': 'internal-composite-key',
        'lastUpdatedTime#findingId': 'internal-lsi-key',
        REMEDIATION_CONSTANT: 'remediation',
        expireAt: 1672531200,
        accountId: '123456789012',
        resourceId: 'test-resource',
        resourceType: 'AWS::Lambda::Function',
        resourceTypeNormalized: 'awslambdafunction',
        severity: 'HIGH',
        region: 'us-east-1',
        remediationStatus: 'SUCCESS',
        lastUpdatedTime: '2023-01-01T00:00:00Z',
        lastUpdatedBy: 'test-user@example.com',
        executionId: 'arn:aws:states:us-east-1:123456789012:execution:TestStateMachine:exec-123',
      };

      await dynamoDBDocumentClient.send(
        new PutCommand({
          TableName: remediationHistoryTableName,
          Item: remediationItem,
        }),
      );

      const request: RemediationsRequest = {};

      const result = await remediationService.searchRemediations(mockAuthenticatedUser, request);

      expect(result.Remediations[0]).toEqual({
        findingType: 'security-control/Lambda.3',
        findingId: 'test-finding-id',
        accountId: '123456789012',
        resourceId: 'test-resource',
        resourceType: 'AWS::Lambda::Function',
        resourceTypeNormalized: 'awslambdafunction',
        severity: 'HIGH',
        region: 'us-east-1',
        remediationStatus: 'SUCCESS',
        lastUpdatedTime: '2023-01-01T00:00:00Z',
        lastUpdatedBy: 'test-user@example.com',
        executionId: 'arn:aws:states:us-east-1:123456789012:execution:TestStateMachine:exec-123',
        consoleLink:
          'https://us-east-1.console.aws.amazon.com/states/home?region=us-east-1#/v2/executions/details/arn%3Aaws%3Astates%3Aus-east-1%3A123456789012%3Aexecution%3ATestStateMachine%3Aexec-123',
      });

      expect(result.Remediations[0]).not.toHaveProperty('findingId#executionId');
      expect(result.Remediations[0]).not.toHaveProperty('lastUpdatedTime#findingId');
      expect(result.Remediations[0]).not.toHaveProperty('REMEDIATION_CONSTANT');
      expect(result.Remediations[0]).not.toHaveProperty('expireAt');
    });

    it('should publish search metrics when searching remediations', async () => {
      // ARRANGE
      const request: RemediationsRequest = {
        Filters: {
          StringFilters: [
            {
              FieldName: 'remediationStatus',
              Filter: { Value: 'SUCCESS', Comparison: 'EQUALS' as const },
            },
          ],
          CompositeFilters: [
            {
              Operator: 'AND' as const,
              StringFilters: [
                {
                  FieldName: 'severity',
                  Filter: { Value: 'HIGH', Comparison: 'EQUALS' as const },
                },
              ],
            },
          ],
        },
        SortCriteria: [{ Field: 'lastUpdatedTime', SortOrder: 'desc' as const }],
      };

      const metricsScope = createMetricsTestScope(
        /.*search_operation.*filter_types_used.*remediationStatus.*severity.*filter_count.*%3A2.*has_composite_filters.*true.*sort_fields_used.*lastUpdatedTime.*resource_type.*Remediations.*/,
      );
      metricsScope.persist();

      // ACT
      await remediationService.searchRemediations(mockAuthenticatedUser, request);

      // Allow the async metrics api call to be invoked
      await new Promise((resolve) => setTimeout(resolve, 5));

      // ASSERT
      expect(metricsScope.isDone()).toBe(true);
    });
  });

  describe('exportRemediationHistory', () => {
    beforeEach(() => {
      process.env.CSV_EXPORT_BUCKET_NAME = 'test-export-bucket';

      jest
        .spyOn(remediationService['s3Client'], 'uploadCsvAndGeneratePresignedUrl')
        .mockResolvedValue('https://test-bucket.s3.amazonaws.com/test-file.csv?presigned=true');
    });

    afterEach(() => {
      delete process.env.CSV_EXPORT_BUCKET_NAME;
      jest.restoreAllMocks();
    });

    it('should generate CSV with user-friendly headers', async () => {
      const remediationItem = {
        findingType: 'security-control/Lambda.3',
        findingId: 'arn:aws:securityhub:us-east-1:123456789012:security-control/Lambda.3/finding/test',
        'findingId#executionId':
          'arn:aws:securityhub:us-east-1:123456789012:security-control/Lambda.3/finding/test#arn:aws:states:us-east-1:123456789012:execution:TestStateMachine:exec-123',
        accountId: '123456789012',
        resourceId: 'arn:aws:lambda:us-east-1:123456789012:function:test',
        resourceType: 'AWS::Lambda::Function',
        resourceTypeNormalized: 'awslambdafunction',
        severity: 'HIGH',
        region: 'us-east-1',
        remediationStatus: 'SUCCESS',
        lastUpdatedTime: '2023-01-01T00:00:00Z',
        'lastUpdatedTime#findingId':
          '2023-01-01T00:00:00Z#arn:aws:securityhub:us-east-1:123456789012:security-control/Lambda.3/finding/test',
        REMEDIATION_CONSTANT: 'remediation',
        lastUpdatedBy: 'test-user@example.com',
        executionId: 'arn:aws:states:us-east-1:123456789012:execution:TestStateMachine:exec-123',
        expireAt: Math.floor(Date.now() / 1000) + 90 * 24 * 60 * 60,
        error: 'Test error message',
      };

      await dynamoDBDocumentClient.send(
        new PutCommand({
          TableName: remediationHistoryTableName,
          Item: remediationItem,
        }),
      );

      const exportRequest = {
        SortCriteria: [
          {
            Field: 'lastUpdatedTime',
            SortOrder: 'desc' as const,
          },
        ],
      };

      const result = await remediationService.exportRemediationHistory(mockAuthenticatedUser, exportRequest);

      expect(result.downloadUrl).toBe('https://test-bucket.s3.amazonaws.com/test-file.csv?presigned=true');
      expect(result.status).toBe('complete');
      expect(result.totalExported).toBe(1);
      expect(result.message).toBeUndefined();

      const uploadCall = jest.mocked(remediationService['s3Client'].uploadCsvAndGeneratePresignedUrl).mock.calls[0];
      const csvContent = uploadCall[2];

      const expectedHeaders =
        'Finding ID,Account,Resource ID,Resource Type,Finding Type,Severity,Region,Status,Execution Timestamp,Executed By,Execution ID,Error';
      expect(csvContent).toContain(expectedHeaders);

      const lines = csvContent.split('\n');
      expect(lines[0]).toBe(expectedHeaders);
      expect(lines[1]).toContain('arn:aws:securityhub:us-east-1:123456789012:security-control/Lambda.3/finding/test');
      expect(lines[1]).toContain('123456789012');
      expect(lines[1]).toContain('SUCCESS');
      expect(lines[1]).toContain('Test error message');
    });

    it('should generate CSV with headers only when no data exists', async () => {
      const exportRequest = {
        SortCriteria: [
          {
            Field: 'lastUpdatedTime',
            SortOrder: 'desc' as const,
          },
        ],
      };

      const result = await remediationService.exportRemediationHistory(mockAuthenticatedUser, exportRequest);

      expect(result.downloadUrl).toBe('https://test-bucket.s3.amazonaws.com/test-file.csv?presigned=true');
      expect(result.status).toBe('complete');
      expect(result.totalExported).toBe(0);
      expect(result.message).toBeUndefined();

      const uploadCall = jest.mocked(remediationService['s3Client'].uploadCsvAndGeneratePresignedUrl).mock.calls[0];
      const csvContent = uploadCall[2];

      const expectedHeaders =
        'Finding ID,Account,Resource ID,Resource Type,Finding Type,Severity,Region,Status,Execution Timestamp,Executed By,Execution ID,Error';
      expect(csvContent).toBe(expectedHeaders);
    });

    it('should return partial status when hitting record limit', async () => {
      const createRemediation = (i: number) => ({
        findingId: `arn:aws:securityhub:us-east-1:123456789012:security-control/Lambda.3/finding/test-${i}`,
        'lastUpdatedTime#findingId': `2023-01-01T00:00:00Z#arn:aws:securityhub:us-east-1:123456789012:security-control/Lambda.3/finding/test-${i}`,
        accountId: '123456789012',
        resourceId: `arn:aws:lambda:us-east-1:123456789012:function:test-${i}`,
        resourceType: 'AWS::Lambda::Function',
        findingType: 'security-control/Lambda.3',
        severity: 'HIGH',
        region: 'us-east-1',
        remediationStatus: 'SUCCESS',
        executionTimestamp: '2023-01-01T00:00:00Z',
        executedBy: 'test-user@example.com',
        executionId: `exec-${i}`,
        lastUpdatedTime: '2023-01-01T00:00:00Z',
        REMEDIATION_CONSTANT: 'remediation',
      });

      // Spy on repository to return 100 items per call, simulating 500 batches to hit 50K record limit
      let callCount = 0;
      jest
        .spyOn(remediationService['remediationHistoryRepository'], 'searchRemediations')
        .mockImplementation(async () => {
          callCount++;
          // Return 100 items per batch, with nextToken until we hit 500 batches (50K records)
          const items = Array.from({ length: 100 }, (_, i) => createRemediation(callCount * 100 + i));
          return {
            items: items as any,
            nextToken: callCount < 500 ? `token-${callCount}` : undefined,
          };
        });

      jest
        .spyOn(remediationService['s3Client'], 'uploadCsvAndGeneratePresignedUrl')
        .mockResolvedValue('https://test-bucket.s3.amazonaws.com/test-file.csv?presigned=true');

      const exportRequest = {
        SortCriteria: [
          {
            Field: 'lastUpdatedTime',
            SortOrder: 'desc' as const,
          },
        ],
      };

      const result = await remediationService.exportRemediationHistory(mockAuthenticatedUser, exportRequest);

      expect(result.status).toBe('partial');
      expect(result.totalExported).toBe(50000);
      expect(result.message).toBe('Maximum export size reached. Apply filters to reduce dataset.');
    });
  });
});
