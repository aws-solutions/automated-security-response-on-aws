// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { Logger } from '@aws-lambda-powertools/logger';
import nock from 'nock';
import {
  cleanupMetricsMocks,
  createMetricsTestScope,
  setupMetricsMocks,
} from '../../../common/__tests__/metricsMockSetup';
import { FindingRepository } from '../../../common/repositories/findingRepository';
import { AuthenticatedUser } from '../../services/authorization';
import { FindingsService } from '../../services/findingsService';

// Mock the repository
jest.mock('../../../common/repositories/findingRepository');
jest.mock('../../../common/utils/dynamodb');

describe('FindingsService', () => {
  let findingsService: FindingsService;
  let mockRepository: jest.Mocked<FindingRepository>;
  let mockLogger: Logger;
  let mockAuthenticatedUser: AuthenticatedUser;

  beforeEach(() => {
    setupMetricsMocks();

    process.env.FINDINGS_TABLE_NAME = 'testFindingsTable';

    mockLogger = new Logger({ serviceName: 'test' });
    jest.spyOn(mockLogger, 'error').mockImplementation();

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
});
