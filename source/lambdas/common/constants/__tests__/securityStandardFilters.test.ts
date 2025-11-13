// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import {
  getOptimizedFindingFilters,
  getOptimizedFindingFiltersByControlId,
  getSupportedControlIds,
  getSupportedControlIdsInChunks,
  chunkArray,
  STANDARDS_WITH_REMEDIATIONS,
} from '../securityStandardFilters';
import { DynamoDBDocumentClient, ScanCommand } from '@aws-sdk/lib-dynamodb';
import { mockClient } from 'aws-sdk-client-mock';

describe('SecurityStandardFilters', () => {
  describe('getOptimizedFindingFilters', () => {
    it('should return filters with all required criteria', () => {
      const filters = getOptimizedFindingFilters();

      expect(filters.RecordState).toEqual([{ Value: 'ACTIVE', Comparison: 'EQUALS' }]);
      expect(filters.ComplianceStatus).toEqual([
        { Value: 'PASSED', Comparison: 'NOT_EQUALS' },
        { Value: 'NOT_AVAILABLE', Comparison: 'NOT_EQUALS' },
      ]);
      expect(filters.ProductArn).toEqual([{ Value: 'arn:aws:securityhub', Comparison: 'PREFIX' }]);
    });

    it('should include GeneratorId filters for all supported standards', () => {
      const filters = getOptimizedFindingFilters();

      expect(filters.GeneratorId).toHaveLength(STANDARDS_WITH_REMEDIATIONS.length);
      expect(filters.GeneratorId).toEqual(
        STANDARDS_WITH_REMEDIATIONS.map((standard) => ({
          Value: standard,
          Comparison: 'PREFIX',
        })),
      );
    });

    it('should include all expected security standards', () => {
      const filters = getOptimizedFindingFilters();
      const generatorIds = filters.GeneratorId?.map((g) => g.Value) || [];

      expect(generatorIds).toContain('aws-foundational-security-best-practices');
      expect(generatorIds).toContain('arn:aws:securityhub:::ruleset/cis-aws-foundations-benchmark');
      expect(generatorIds).toContain('security-control');
      expect(generatorIds).toContain('pci-dss');
      expect(generatorIds).toContain('nist-800-53');
    });
  });

  describe('chunkArray', () => {
    it('should split array into chunks of specified size', () => {
      const array = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
      const chunks = chunkArray(array, 3);

      expect(chunks).toEqual([[1, 2, 3], [4, 5, 6], [7, 8, 9], [10]]);
    });

    it('should return single chunk when array is smaller than chunk size', () => {
      const array = [1, 2, 3];
      const chunks = chunkArray(array, 5);

      expect(chunks).toEqual([[1, 2, 3]]);
    });

    it('should return empty array when input is empty', () => {
      const chunks = chunkArray([], 3);
      expect(chunks).toEqual([]);
    });

    it('should return empty array when chunk size is 0 or negative', () => {
      expect(chunkArray([1, 2, 3], 0)).toEqual([]);
      expect(chunkArray([1, 2, 3], -1)).toEqual([]);
    });
  });

  describe('getSupportedControlIds', () => {
    const dynamoMock = mockClient(DynamoDBDocumentClient);
    const mockDynamoClient = dynamoMock as unknown as DynamoDBDocumentClient;
    const tableName = 'test-remediation-config-table';

    beforeEach(() => {
      dynamoMock.reset();
    });

    it('should return empty array when no controlIds found', async () => {
      dynamoMock.resolves({ Items: [] });

      const controlIds = await getSupportedControlIds(mockDynamoClient, tableName);

      expect(controlIds).toEqual([]);
    });

    it('should return controlIds when found', async () => {
      const mockControlIds = ['S3.1', 'EC2.1', 'IAM.1'];
      dynamoMock.resolves({
        Items: mockControlIds.map((controlId) => ({ controlId })),
      });

      const controlIds = await getSupportedControlIds(mockDynamoClient, tableName);

      expect(controlIds).toEqual(mockControlIds);
    });

    it('should handle pagination when scanning DynamoDB', async () => {
      dynamoMock
        .resolvesOnce({
          Items: [{ controlId: 'S3.1' }, { controlId: 'EC2.1' }],
          LastEvaluatedKey: { controlId: 'EC2.1' },
        })
        .resolvesOnce({
          Items: [{ controlId: 'IAM.1' }],
        });

      const controlIds = await getSupportedControlIds(mockDynamoClient, tableName);

      expect(controlIds).toEqual(['S3.1', 'EC2.1', 'IAM.1']);
      expect(dynamoMock.commandCalls(ScanCommand)).toHaveLength(2);
    });
  });

  describe('getSupportedControlIdsInChunks', () => {
    const dynamoMock = mockClient(DynamoDBDocumentClient);
    const mockDynamoClient = dynamoMock as unknown as DynamoDBDocumentClient;
    const tableName = 'test-remediation-config-table';

    beforeEach(() => {
      dynamoMock.reset();
    });

    it('should return chunks of controlIds with default size 20', async () => {
      const mockControlIds = Array.from({ length: 25 }, (_, i) => `CONTROL.${i + 1}`);
      dynamoMock.resolves({
        Items: mockControlIds.map((controlId) => ({ controlId })),
      });

      const chunks = await getSupportedControlIdsInChunks(mockDynamoClient, tableName);

      expect(chunks).toHaveLength(2);
      expect(chunks[0]).toHaveLength(20);
      expect(chunks[1]).toHaveLength(5);
    });

    it('should return chunks with custom size', async () => {
      const mockControlIds = ['S3.1', 'EC2.1', 'IAM.1', 'RDS.1', 'VPC.1'];
      dynamoMock.resolves({
        Items: mockControlIds.map((controlId) => ({ controlId })),
      });

      const chunks = await getSupportedControlIdsInChunks(mockDynamoClient, tableName, 2);

      expect(chunks).toEqual([['S3.1', 'EC2.1'], ['IAM.1', 'RDS.1'], ['VPC.1']]);
    });
  });

  describe('getOptimizedFindingFiltersByControlId', () => {
    it('should return base filters when no controlIds provided', async () => {
      const filters = await getOptimizedFindingFiltersByControlId([]);
      const baseFilters = getOptimizedFindingFilters();

      expect(filters).toEqual(baseFilters);
    });

    it('should add ComplianceSecurityControlId filters when controlIds are provided', async () => {
      const mockControlIds = ['S3.1', 'EC2.1', 'IAM.1'];

      const filters = await getOptimizedFindingFiltersByControlId(mockControlIds);

      expect(filters.ComplianceSecurityControlId).toHaveLength(3);
      expect(filters.ComplianceSecurityControlId).toEqual([
        { Value: 'S3.1', Comparison: 'EQUALS' },
        { Value: 'EC2.1', Comparison: 'EQUALS' },
        { Value: 'IAM.1', Comparison: 'EQUALS' },
      ]);
    });

    it('should handle large arrays of controlIds without warnings', async () => {
      const mockControlIds = Array.from({ length: 25 }, (_, i) => `CONTROL.${i + 1}`);

      const filters = await getOptimizedFindingFiltersByControlId(mockControlIds);

      expect(filters.ComplianceSecurityControlId).toHaveLength(25);
      expect(filters.ComplianceSecurityControlId?.[0]).toEqual({ Value: 'CONTROL.1', Comparison: 'EQUALS' });
      expect(filters.ComplianceSecurityControlId?.[24]).toEqual({ Value: 'CONTROL.25', Comparison: 'EQUALS' });
    });

    it('should include all base filters when controlIds are provided', async () => {
      const mockControlIds = ['S3.1'];
      const filters = await getOptimizedFindingFiltersByControlId(mockControlIds);
      const baseFilters = getOptimizedFindingFilters();

      expect(filters.RecordState).toEqual(baseFilters.RecordState);
      expect(filters.ComplianceStatus).toEqual(baseFilters.ComplianceStatus);
      expect(filters.ProductArn).toEqual(baseFilters.ProductArn);
      expect(filters.GeneratorId).toEqual(baseFilters.GeneratorId);

      expect(filters.ComplianceSecurityControlId).toEqual([{ Value: 'S3.1', Comparison: 'EQUALS' }]);
    });
  });
});
