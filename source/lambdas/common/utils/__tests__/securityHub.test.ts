// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { SecurityHubClient, GetFindingsCommandInput } from '@aws-sdk/client-securityhub';
import { SecurityHubUtils } from '../securityHub';
import { ASFFFinding } from '@asr/data-models';

// Mock the AWS SDK
const mockSend = jest.fn();
jest.mock('@aws-sdk/client-securityhub', () => ({
  SecurityHubClient: jest.fn(() => ({
    send: mockSend,
  })),
  GetFindingsCommand: jest.fn(),
}));

// Mock the logger
const mockLogger = {
  debug: jest.fn(),
  info: jest.fn(),
  error: jest.fn(),
};

jest.mock('../logger', () => ({
  getLogger: jest.fn(() => mockLogger),
}));

describe('SecurityHubUtils', () => {
  let securityHubUtils: SecurityHubUtils;

  const mockFilters: NonNullable<GetFindingsCommandInput['Filters']> = {
    RecordState: [{ Value: 'ACTIVE', Comparison: 'EQUALS' }],
    ComplianceStatus: [{ Value: 'FAILED', Comparison: 'EQUALS' }],
  };

  const mockFindings: ASFFFinding[] = [
    {
      Id: 'finding-1',
      ProductArn: 'arn:aws:securityhub:us-east-1:123456789012:product/aws/securityhub',
      GeneratorId: 'aws-foundational-security-best-practices/v/1.0.0/S3.1',
      AwsAccountId: '123456789012',
      Region: 'us-east-1',
      Title: 'Test Finding 1',
      Description: 'Test finding description',
    } as ASFFFinding,
    {
      Id: 'finding-2',
      ProductArn: 'arn:aws:securityhub:us-east-1:123456789012:product/aws/securityhub',
      GeneratorId: 'aws-foundational-security-best-practices/v/1.0.0/S3.2',
      AwsAccountId: '123456789012',
      Region: 'us-east-1',
      Title: 'Test Finding 2',
      Description: 'Test finding description 2',
    } as ASFFFinding,
  ];

  beforeEach(() => {
    const securityHubClient = new SecurityHubClient({});
    securityHubUtils = new SecurityHubUtils(securityHubClient);
    mockSend.mockClear();
    jest.clearAllMocks();
  });

  describe('processAllFindings', () => {
    it('should process all findings with pagination', async () => {
      const mockResponse1 = {
        Findings: [mockFindings[0]],
        NextToken: 'next-token-123',
      };

      const mockResponse2 = {
        Findings: [mockFindings[1]],
        NextToken: undefined,
      };

      mockSend.mockResolvedValueOnce(mockResponse1).mockResolvedValueOnce(mockResponse2);

      const processedBatches: ASFFFinding[][] = [];
      const processBatch = jest.fn(async (findings: ASFFFinding[]) => {
        processedBatches.push(findings);
      });

      const result = await securityHubUtils.processAllFindings(processBatch, mockFilters);

      expect(result.totalProcessed).toBe(2);
      expect(result.apiCallCount).toBe(2);
      expect(processedBatches).toHaveLength(2);
      expect(processedBatches[0]).toEqual([mockFindings[0]]);
      expect(processedBatches[1]).toEqual([mockFindings[1]]);
      expect(processBatch).toHaveBeenCalledTimes(2);
      expect(mockSend).toHaveBeenCalledTimes(2);
      expect(mockLogger.info).toHaveBeenCalledWith('Processed 2 findings with 2 API calls');
    });

    it('should handle single page response', async () => {
      const mockResponse = {
        Findings: mockFindings,
        NextToken: undefined,
      };

      mockSend.mockResolvedValueOnce(mockResponse);

      const processedBatches: ASFFFinding[][] = [];
      const processBatch = jest.fn(async (findings: ASFFFinding[]) => {
        processedBatches.push(findings);
      });

      const result = await securityHubUtils.processAllFindings(processBatch, mockFilters);

      expect(result.totalProcessed).toBe(2);
      expect(result.apiCallCount).toBe(1);
      expect(processedBatches).toHaveLength(1);
      expect(processedBatches[0]).toEqual(mockFindings);
      expect(processBatch).toHaveBeenCalledTimes(1);
      expect(mockSend).toHaveBeenCalledTimes(1);
    });

    it('should handle empty findings response', async () => {
      const mockResponse = {
        Findings: [],
        NextToken: undefined,
      };

      mockSend.mockResolvedValueOnce(mockResponse);

      const processBatch = jest.fn();

      const result = await securityHubUtils.processAllFindings(processBatch, mockFilters);

      expect(result.totalProcessed).toBe(0);
      expect(result.apiCallCount).toBe(1);
      expect(processBatch).not.toHaveBeenCalled();
      expect(mockSend).toHaveBeenCalledTimes(1);
    });

    it('should handle API errors', async () => {
      const mockError = new Error('SecurityHub API Error');
      mockSend.mockRejectedValueOnce(mockError);

      const processBatch = jest.fn();

      await expect(securityHubUtils.processAllFindings(processBatch, mockFilters)).rejects.toThrow(
        'SecurityHub API Error',
      );

      expect(mockLogger.error).toHaveBeenCalledWith(
        'Failed to process findings from Security Hub',
        expect.objectContaining({
          error: 'SecurityHub API Error',
        }),
      );
    });

    it('should handle processing errors from callback', async () => {
      const mockResponse = {
        Findings: mockFindings,
        NextToken: undefined,
      };

      mockSend.mockResolvedValueOnce(mockResponse);

      const processBatch = jest.fn().mockRejectedValueOnce(new Error('Processing Error'));

      await expect(securityHubUtils.processAllFindings(processBatch, mockFilters)).rejects.toThrow('Processing Error');
    });
  });
});
