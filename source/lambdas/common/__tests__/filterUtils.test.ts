// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { getLogger } from '../utils/logger';
import { ASRParameters } from '../utils/constants';
import {
  applyAccountFilter,
  applyFilters,
  applyOUFilter,
  applyTagFilter,
  FilterConfig,
  getFilterConfigurations,
  clearFilterConfigCache,
} from '../utils/filterUtils';
import { ASFFFinding } from '@asr/data-models';
import { SSMClient, GetParametersByPathCommand } from '@aws-sdk/client-ssm';
import { OrganizationsClient, DescribeOrganizationCommand, ListParentsCommand } from '@aws-sdk/client-organizations';
import { ResourceGroupsTaggingAPIClient, GetResourcesCommand } from '@aws-sdk/client-resource-groups-tagging-api';
import { mockClient } from 'aws-sdk-client-mock';

const mockSSMClient = mockClient(SSMClient);
const mockOrganizationsClient = mockClient(OrganizationsClient);
const mockResourceGroupsTaggingAPIClient = mockClient(ResourceGroupsTaggingAPIClient);

describe('filterUtils', () => {
  const mockLogger = getLogger('test');

  const mockFinding: Partial<ASFFFinding> = {
    Id: 'test-finding-id',
    AwsAccountId: '123456789012',
    Resources: [
      {
        Id: 'arn:aws:s3:::test-bucket',
        Type: 'AwsS3Bucket',
        Partition: 'aws',
        Region: 'us-east-1',
      },
    ],
    Region: 'us-east-1',
  };

  beforeEach(() => {
    mockSSMClient.reset();
    mockOrganizationsClient.reset();
    mockResourceGroupsTaggingAPIClient.reset();
    clearFilterConfigCache();
  });

  describe('getFilterConfigurations', () => {
    it('should retrieve filter configurations from SSM parameters', async () => {
      mockSSMClient.on(GetParametersByPathCommand).resolves({
        Parameters: [
          { Name: ASRParameters.ACCOUNT_FILTERS, Value: '123456789012,234567890123' },
          { Name: ASRParameters.ACCOUNT_FILTER_MODE, Value: 'Include' },
          { Name: ASRParameters.OU_FILTERS, Value: 'ou-1234,ou-5678' },
          { Name: ASRParameters.OU_FILTER_MODE, Value: 'Exclude' },
          { Name: ASRParameters.TAG_FILTERS, Value: 'Environment,Project' },
          { Name: ASRParameters.TAG_FILTER_MODE, Value: 'Include' },
        ],
      });

      const result = await getFilterConfigurations(mockLogger);

      expect(result).toEqual({
        accountFilters: ['123456789012', '234567890123'],
        accountFilterMode: 'Include',
        ouFilters: ['ou-1234', 'ou-5678'],
        ouFilterMode: 'Exclude',
        tagFilters: ['Environment', 'Project'],
        tagFilterMode: 'Include',
      });
    });

    it('should handle empty parameter values', async () => {
      mockSSMClient.on(GetParametersByPathCommand).resolves({
        Parameters: [
          { Name: ASRParameters.ACCOUNT_FILTERS, Value: '' },
          { Name: ASRParameters.ACCOUNT_FILTER_MODE, Value: 'Disabled' },
          { Name: ASRParameters.OU_FILTERS, Value: '' },
          { Name: ASRParameters.OU_FILTER_MODE, Value: 'Disabled' },
          { Name: ASRParameters.TAG_FILTERS, Value: '' },
          { Name: ASRParameters.TAG_FILTER_MODE, Value: 'Disabled' },
        ],
      });

      const result = await getFilterConfigurations(mockLogger);

      expect(result).toEqual({
        accountFilters: [],
        accountFilterMode: 'Disabled',
        ouFilters: [],
        ouFilterMode: 'Disabled',
        tagFilters: [],
        tagFilterMode: 'Disabled',
      });
    });

    it('should handle missing parameters', async () => {
      mockSSMClient.on(GetParametersByPathCommand).resolves({
        Parameters: [
          { Name: ASRParameters.ACCOUNT_FILTERS, Value: '123456789012' },
          { Name: ASRParameters.ACCOUNT_FILTER_MODE, Value: 'Include' },
        ],
      });

      const result = await getFilterConfigurations(mockLogger);

      expect(result).toEqual({
        accountFilters: ['123456789012'],
        accountFilterMode: 'Include',
        ouFilters: [],
        ouFilterMode: 'Disabled',
        tagFilters: [],
        tagFilterMode: 'Disabled',
      });
    });

    it('should handle invalid filter mode values', async () => {
      mockSSMClient.on(GetParametersByPathCommand).resolves({
        Parameters: [
          { Name: ASRParameters.ACCOUNT_FILTERS, Value: '123456789012' },
          { Name: ASRParameters.ACCOUNT_FILTER_MODE, Value: 'InvalidMode' }, // Invalid mode
          { Name: ASRParameters.OU_FILTERS, Value: 'ou-1234' },
          { Name: ASRParameters.OU_FILTER_MODE, Value: 'Include' },
        ],
      });

      const result = await getFilterConfigurations(mockLogger);

      expect(result.accountFilterMode).toBe('Disabled'); // Should default to Disabled
      expect(result.ouFilterMode).toBe('Include');
    });

    it('should handle SSM client errors', async () => {
      mockSSMClient.on(GetParametersByPathCommand).rejects(new Error('SSM API error'));

      const result = await getFilterConfigurations(mockLogger);

      expect(result).toEqual({
        accountFilters: [],
        accountFilterMode: 'Disabled',
        ouFilters: [],
        ouFilterMode: 'Disabled',
        tagFilters: [],
        tagFilterMode: 'Disabled',
      });
    });

    it('should cache filter configurations and avoid repeated SSM calls', async () => {
      mockSSMClient.on(GetParametersByPathCommand).resolves({
        Parameters: [
          { Name: ASRParameters.ACCOUNT_FILTERS, Value: '123456789012' },
          { Name: ASRParameters.ACCOUNT_FILTER_MODE, Value: 'Include' },
        ],
      });

      const result1 = await getFilterConfigurations(mockLogger);
      expect(mockSSMClient.commandCalls(GetParametersByPathCommand)).toHaveLength(1);

      const result2 = await getFilterConfigurations(mockLogger);
      expect(mockSSMClient.commandCalls(GetParametersByPathCommand)).toHaveLength(1); // Still 1, no new call

      expect(result1).toEqual(result2);
      expect(result1.accountFilters).toEqual(['123456789012']);
      expect(result1.accountFilterMode).toBe('Include');
    });

    it('should return stale cache when SSM fails after initial success', async () => {
      mockSSMClient.on(GetParametersByPathCommand).resolvesOnce({
        Parameters: [
          { Name: ASRParameters.ACCOUNT_FILTERS, Value: '123456789012' },
          { Name: ASRParameters.ACCOUNT_FILTER_MODE, Value: 'Include' },
        ],
      });

      const result1 = await getFilterConfigurations(mockLogger);
      expect(result1.accountFilters).toEqual(['123456789012']);

      clearFilterConfigCache();

      mockSSMClient.on(GetParametersByPathCommand).rejects(new Error('SSM throttling'));

      const result2 = await getFilterConfigurations(mockLogger);

      expect(result2).toEqual({
        accountFilters: [],
        accountFilterMode: 'Disabled',
        ouFilters: [],
        ouFilterMode: 'Disabled',
        tagFilters: [],
        tagFilterMode: 'Disabled',
      });
    });
  });

  describe('applyAccountFilter', () => {
    it('should pass when account filtering is disabled', async () => {
      const filterConfig: FilterConfig = {
        accountFilters: [],
        accountFilterMode: 'Disabled',
        ouFilters: [],
        ouFilterMode: 'Disabled',
        tagFilters: [],
        tagFilterMode: 'Disabled',
      };

      const result = await applyAccountFilter(mockFinding as ASFFFinding, filterConfig, mockLogger);

      expect(result).toBe(true);
    });

    it('should pass when account filter list is empty', async () => {
      const filterConfig: FilterConfig = {
        accountFilters: [],
        accountFilterMode: 'Include', // Even though mode is Include, empty list should pass
        ouFilters: [],
        ouFilterMode: 'Disabled',
        tagFilters: [],
        tagFilterMode: 'Disabled',
      };

      const result = await applyAccountFilter(mockFinding as ASFFFinding, filterConfig, mockLogger);

      expect(result).toBe(true);
    });

    it('should pass when account is in include list', async () => {
      const filterConfig: FilterConfig = {
        accountFilters: ['123456789012', '234567890123'],
        accountFilterMode: 'Include',
        ouFilters: [],
        ouFilterMode: 'Disabled',
        tagFilters: [],
        tagFilterMode: 'Disabled',
      };

      const result = await applyAccountFilter(mockFinding as ASFFFinding, filterConfig, mockLogger);

      expect(result).toBe(true);
    });

    it('should fail when account is not in include list', async () => {
      const filterConfig: FilterConfig = {
        accountFilters: ['234567890123', '345678901234'],
        accountFilterMode: 'Include',
        ouFilters: [],
        ouFilterMode: 'Disabled',
        tagFilters: [],
        tagFilterMode: 'Disabled',
      };

      const result = await applyAccountFilter(mockFinding as ASFFFinding, filterConfig, mockLogger);

      expect(result).toBe(false);
    });

    it('should pass when account is not in exclude list', async () => {
      const filterConfig: FilterConfig = {
        accountFilters: ['234567890123', '345678901234'],
        accountFilterMode: 'Exclude',
        ouFilters: [],
        ouFilterMode: 'Disabled',
        tagFilters: [],
        tagFilterMode: 'Disabled',
      };

      const result = await applyAccountFilter(mockFinding as ASFFFinding, filterConfig, mockLogger);

      expect(result).toBe(true);
    });

    it('should fail when account is in exclude list', async () => {
      const filterConfig: FilterConfig = {
        accountFilters: ['123456789012', '234567890123'],
        accountFilterMode: 'Exclude',
        ouFilters: [],
        ouFilterMode: 'Disabled',
        tagFilters: [],
        tagFilterMode: 'Disabled',
      };

      const result = await applyAccountFilter(mockFinding as ASFFFinding, filterConfig, mockLogger);

      expect(result).toBe(false);
    });
  });

  describe('applyOUFilter', () => {
    it('should pass when OU filtering is disabled', async () => {
      const filterConfig: FilterConfig = {
        accountFilters: [],
        accountFilterMode: 'Disabled',
        ouFilters: [],
        ouFilterMode: 'Disabled',
        tagFilters: [],
        tagFilterMode: 'Disabled',
      };

      const result = await applyOUFilter(mockFinding as ASFFFinding, filterConfig, mockLogger);

      expect(result).toBe(true);
    });

    it('should not call Organizations API when OU filtering is disabled', async () => {
      const filterConfig: FilterConfig = {
        accountFilters: [],
        accountFilterMode: 'Disabled',
        ouFilters: [],
        ouFilterMode: 'Disabled',
        tagFilters: [],
        tagFilterMode: 'Disabled',
      };

      mockOrganizationsClient.on(ListParentsCommand).resolves({
        Parents: [{ Id: 'ou-1234', Type: 'ORGANIZATIONAL_UNIT' }],
      });

      await applyOUFilter(mockFinding as ASFFFinding, filterConfig, mockLogger);

      expect(mockOrganizationsClient.commandCalls(ListParentsCommand)).toHaveLength(0);
    });

    it('should handle concurrent requests for same account', async () => {
      const filterConfig: FilterConfig = {
        accountFilters: [],
        accountFilterMode: 'Disabled',
        ouFilters: ['ou-1234'],
        ouFilterMode: 'Include',
        tagFilters: [],
        tagFilterMode: 'Disabled',
      };

      clearFilterConfigCache();
      mockOrganizationsClient.reset();
      mockOrganizationsClient.on(ListParentsCommand).resolves({
        Parents: [{ Id: 'ou-1234', Type: 'ORGANIZATIONAL_UNIT' }],
      });

      const results = await Promise.all([
        applyOUFilter(mockFinding as ASFFFinding, filterConfig, mockLogger),
        applyOUFilter(mockFinding as ASFFFinding, filterConfig, mockLogger),
        applyOUFilter(mockFinding as ASFFFinding, filterConfig, mockLogger),
      ]);

      expect(results).toEqual([true, true, true]);

      // Verify API calls were made successfully
      expect(mockOrganizationsClient.commandCalls(ListParentsCommand).length).toBeGreaterThan(0);
    });

    it('should cache parent OUs and avoid repeated API calls', async () => {
      const filterConfig: FilterConfig = {
        accountFilters: [],
        accountFilterMode: 'Disabled',
        ouFilters: ['ou-1234'],
        ouFilterMode: 'Include',
        tagFilters: [],
        tagFilterMode: 'Disabled',
      };

      clearFilterConfigCache();
      mockOrganizationsClient.reset();
      mockOrganizationsClient.on(ListParentsCommand).resolves({
        Parents: [{ Id: 'ou-1234', Type: 'ORGANIZATIONAL_UNIT' }],
      });

      const result1 = await applyOUFilter(mockFinding as ASFFFinding, filterConfig, mockLogger);
      expect(result1).toBe(true);
      expect(mockOrganizationsClient.commandCalls(ListParentsCommand)).toHaveLength(1);

      const result2 = await applyOUFilter(mockFinding as ASFFFinding, filterConfig, mockLogger);
      expect(result2).toBe(true);
      expect(mockOrganizationsClient.commandCalls(ListParentsCommand)).toHaveLength(1); // Still 1
    });

    it('should pass when OU filter list is empty', async () => {
      const filterConfig: FilterConfig = {
        accountFilters: [],
        accountFilterMode: 'Disabled',
        ouFilters: [],
        ouFilterMode: 'Include', // Even though mode is Include, empty list should pass
        tagFilters: [],
        tagFilterMode: 'Disabled',
      };

      const result = await applyOUFilter(mockFinding as ASFFFinding, filterConfig, mockLogger);

      expect(result).toBe(true);
    });

    it('should pass when account OU is in include list', async () => {
      const filterConfig: FilterConfig = {
        accountFilters: [],
        accountFilterMode: 'Disabled',
        ouFilters: ['ou-1234', 'ou-5678'],
        ouFilterMode: 'Include',
        tagFilters: [],
        tagFilterMode: 'Disabled',
      };

      mockOrganizationsClient
        .on(DescribeOrganizationCommand)
        .resolves({})
        .on(ListParentsCommand)
        .resolves({
          Parents: [{ Id: 'ou-1234', Type: 'ORGANIZATIONAL_UNIT' }],
        });

      const result = await applyOUFilter(mockFinding as ASFFFinding, filterConfig, mockLogger);

      expect(result).toBe(true);
    });

    it('should fail when account OU is not in include list', async () => {
      const filterConfig: FilterConfig = {
        accountFilters: [],
        accountFilterMode: 'Disabled',
        ouFilters: ['ou-5678', 'ou-9012'],
        ouFilterMode: 'Include',
        tagFilters: [],
        tagFilterMode: 'Disabled',
      };

      clearFilterConfigCache();
      mockOrganizationsClient.reset();
      mockOrganizationsClient.on(ListParentsCommand).resolves({
        Parents: [{ Id: 'ou-1234', Type: 'ORGANIZATIONAL_UNIT' }],
      });

      const result = await applyOUFilter(mockFinding as ASFFFinding, filterConfig, mockLogger);

      expect(result).toBe(false);
    });

    it('should pass when Organizations API is not available', async () => {
      const filterConfig: FilterConfig = {
        accountFilters: [],
        accountFilterMode: 'Disabled',
        ouFilters: ['ou-1234'],
        ouFilterMode: 'Include',
        tagFilters: [],
        tagFilterMode: 'Disabled',
      };

      mockOrganizationsClient.on(DescribeOrganizationCommand).rejects(new Error('Organizations not available'));

      const result = await applyOUFilter(mockFinding as ASFFFinding, filterConfig, mockLogger);

      expect(result).toBe(true);
    });

    it('should pass when account has no parent OUs', async () => {
      const filterConfig: FilterConfig = {
        accountFilters: [],
        accountFilterMode: 'Disabled',
        ouFilters: ['ou-1234'],
        ouFilterMode: 'Include',
        tagFilters: [],
        tagFilterMode: 'Disabled',
      };

      mockOrganizationsClient.on(DescribeOrganizationCommand).resolves({}).on(ListParentsCommand).resolves({
        Parents: [],
      });

      const result = await applyOUFilter(mockFinding as ASFFFinding, filterConfig, mockLogger);

      expect(result).toBe(true);
    });
  });

  describe('applyTagFilter', () => {
    it('should pass when tag filtering is disabled', async () => {
      const filterConfig: FilterConfig = {
        accountFilters: [],
        accountFilterMode: 'Disabled',
        ouFilters: [],
        ouFilterMode: 'Disabled',
        tagFilters: [],
        tagFilterMode: 'Disabled',
      };

      const result = await applyTagFilter(mockFinding as ASFFFinding, filterConfig, mockLogger);

      expect(result).toBe(true);
    });

    it('should pass when tag filter list is empty', async () => {
      const filterConfig: FilterConfig = {
        accountFilters: [],
        accountFilterMode: 'Disabled',
        ouFilters: [],
        ouFilterMode: 'Disabled',
        tagFilters: [],
        tagFilterMode: 'Include', // Even though mode is Include, empty list should pass
      };

      const result = await applyTagFilter(mockFinding as ASFFFinding, filterConfig, mockLogger);

      expect(result).toBe(true);
    });

    it('should pass when finding has no resources', async () => {
      const filterConfig: FilterConfig = {
        accountFilters: [],
        accountFilterMode: 'Disabled',
        ouFilters: [],
        ouFilterMode: 'Disabled',
        tagFilters: ['Environment'],
        tagFilterMode: 'Include',
      };

      const findingWithNoResources = { ...mockFinding, Resources: [] };

      const result = await applyTagFilter(findingWithNoResources as ASFFFinding, filterConfig, mockLogger);

      expect(result).toBe(true);
    });

    it('should pass when resource has tag in include list', async () => {
      const filterConfig: FilterConfig = {
        accountFilters: [],
        accountFilterMode: 'Disabled',
        ouFilters: [],
        ouFilterMode: 'Disabled',
        tagFilters: ['Environment', 'Project'],
        tagFilterMode: 'Include',
      };

      mockResourceGroupsTaggingAPIClient.on(GetResourcesCommand).resolves({
        ResourceTagMappingList: [
          {
            Tags: [
              { Key: 'Environment', Value: 'Production' },
              { Key: 'Owner', Value: 'TeamA' },
            ],
          },
        ],
      });

      const result = await applyTagFilter(mockFinding as ASFFFinding, filterConfig, mockLogger);

      expect(result).toBe(true);
    });

    it('should pass when resource has no tags', async () => {
      const filterConfig: FilterConfig = {
        accountFilters: [],
        accountFilterMode: 'Disabled',
        ouFilters: [],
        ouFilterMode: 'Disabled',
        tagFilters: ['Environment'],
        tagFilterMode: 'Include',
      };

      mockResourceGroupsTaggingAPIClient.on(GetResourcesCommand).resolves({
        ResourceTagMappingList: [],
      });

      const result = await applyTagFilter(mockFinding as ASFFFinding, filterConfig, mockLogger);

      expect(result).toBe(true);
    });

    it('should pass when resource does not have excluded tags', async () => {
      const filterConfig: FilterConfig = {
        accountFilters: [],
        accountFilterMode: 'Disabled',
        ouFilters: [],
        ouFilterMode: 'Disabled',
        tagFilters: ['ExcludeMe'],
        tagFilterMode: 'Exclude',
      };

      const findingWithSafeTags: Partial<ASFFFinding> = {
        ...mockFinding,
        Resources: [
          {
            Id: 'arn:aws:s3:::test-bucket',
            Type: 'AwsS3Bucket',
            Partition: 'aws',
            Region: 'us-east-1',
            Tags: {
              Environment: 'Production',
              Owner: 'TeamA',
            },
          },
        ],
      };

      const result = await applyTagFilter(findingWithSafeTags as ASFFFinding, filterConfig, mockLogger);

      expect(result).toBe(true);
    });

    it('should fail when resource has excluded tags', async () => {
      const filterConfig: FilterConfig = {
        accountFilters: [],
        accountFilterMode: 'Disabled',
        ouFilters: [],
        ouFilterMode: 'Disabled',
        tagFilters: ['ExcludeMe'],
        tagFilterMode: 'Exclude',
      };

      const findingWithExcludedTags: Partial<ASFFFinding> = {
        ...mockFinding,
        Resources: [
          {
            Id: 'arn:aws:s3:::test-bucket',
            Type: 'AwsS3Bucket',
            Partition: 'aws',
            Region: 'us-east-1',
            Tags: {
              Environment: 'Production',
              ExcludeMe: 'true',
            },
          },
        ],
      };

      const result = await applyTagFilter(findingWithExcludedTags as ASFFFinding, filterConfig, mockLogger);

      expect(result).toBe(false);
    });

    it('should check all resources and pass if any has matching tags', async () => {
      const filterConfig: FilterConfig = {
        accountFilters: [],
        accountFilterMode: 'Disabled',
        ouFilters: [],
        ouFilterMode: 'Disabled',
        tagFilters: ['Environment'],
        tagFilterMode: 'Include',
      };

      mockResourceGroupsTaggingAPIClient.on(GetResourcesCommand).rejects(new Error('Tagging API error'));

      const result = await applyTagFilter(mockFinding as ASFFFinding, filterConfig, mockLogger);

      expect(result).toBe(true);
    });
  });

  describe('applyFilters integration', () => {
    it('should pass when all filters are disabled', async () => {
      mockSSMClient.on(GetParametersByPathCommand).resolves({
        Parameters: [
          { Name: ASRParameters.ACCOUNT_FILTER_MODE, Value: 'Disabled' },
          { Name: ASRParameters.OU_FILTER_MODE, Value: 'Disabled' },
          { Name: ASRParameters.TAG_FILTER_MODE, Value: 'Disabled' },
        ],
      });

      const result = await applyFilters(mockFinding as ASFFFinding, mockLogger);

      expect(result).toEqual({
        passed: true,
        appliedFilter: 'none',
      });
    });

    it('should fail when account filter fails', async () => {
      mockSSMClient.on(GetParametersByPathCommand).resolves({
        Parameters: [
          { Name: ASRParameters.ACCOUNT_FILTERS, Value: '234567890123,345678901234' },
          { Name: ASRParameters.ACCOUNT_FILTER_MODE, Value: 'Include' },
          { Name: ASRParameters.OU_FILTER_MODE, Value: 'Disabled' },
          { Name: ASRParameters.TAG_FILTER_MODE, Value: 'Disabled' },
        ],
      });

      const result = await applyFilters(mockFinding as ASFFFinding, mockLogger);

      expect(result).toEqual({
        passed: false,
        appliedFilter: 'account_id_filter',
      });
    });

    it('should return OUs_filter when OU filter fails', async () => {
      clearFilterConfigCache();
      mockSSMClient.reset();
      mockSSMClient.on(GetParametersByPathCommand).resolves({
        Parameters: [
          { Name: ASRParameters.ACCOUNT_FILTER_MODE, Value: 'Disabled' },
          { Name: ASRParameters.OU_FILTERS, Value: 'ou-5678,ou-9012' },
          { Name: ASRParameters.OU_FILTER_MODE, Value: 'Include' },
          { Name: ASRParameters.TAG_FILTER_MODE, Value: 'Disabled' },
        ],
      });

      mockOrganizationsClient.reset();
      mockOrganizationsClient.on(ListParentsCommand).resolves({
        Parents: [{ Id: 'ou-1234', Type: 'ORGANIZATIONAL_UNIT' }],
      });

      const result = await applyFilters(mockFinding as ASFFFinding, mockLogger);

      expect(result).toEqual({
        passed: false,
        appliedFilter: 'OUs_filter',
      });
    });

    it('should return tags_filter when tag filter fails', async () => {
      mockSSMClient.on(GetParametersByPathCommand).resolves({
        Parameters: [
          { Name: ASRParameters.ACCOUNT_FILTER_MODE, Value: 'Disabled' },
          { Name: ASRParameters.OU_FILTER_MODE, Value: 'Disabled' },
          { Name: ASRParameters.TAG_FILTERS, Value: 'Environment' },
          { Name: ASRParameters.TAG_FILTER_MODE, Value: 'Include' },
        ],
      });

      const findingWithNonMatchingTags: Partial<ASFFFinding> = {
        ...mockFinding,
        Resources: [
          {
            Id: 'arn:aws:s3:::test-bucket',
            Type: 'AwsS3Bucket',
            Partition: 'aws',
            Region: 'us-east-1',
            Tags: {
              Owner: 'TeamA',
              CostCenter: '12345',
            },
          },
        ],
      };

      const result = await applyFilters(findingWithNonMatchingTags as ASFFFinding, mockLogger);

      expect(result).toEqual({
        passed: false,
        appliedFilter: 'tags_filter',
      });
    });

    it('should pass all filters and return none', async () => {
      mockSSMClient.on(GetParametersByPathCommand).resolves({
        Parameters: [
          { Name: ASRParameters.ACCOUNT_FILTERS, Value: '123456789012' },
          { Name: ASRParameters.ACCOUNT_FILTER_MODE, Value: 'Include' },
          { Name: ASRParameters.OU_FILTERS, Value: 'ou-1234' },
          { Name: ASRParameters.OU_FILTER_MODE, Value: 'Include' },
          { Name: ASRParameters.TAG_FILTERS, Value: 'Environment' },
          { Name: ASRParameters.TAG_FILTER_MODE, Value: 'Include' },
        ],
      });

      mockOrganizationsClient
        .on(DescribeOrganizationCommand)
        .resolves({})
        .on(ListParentsCommand)
        .resolves({
          Parents: [{ Id: 'ou-1234', Type: 'ORGANIZATIONAL_UNIT' }],
        });

      mockResourceGroupsTaggingAPIClient.on(GetResourcesCommand).resolves({
        ResourceTagMappingList: [
          {
            Tags: [
              { Key: 'Environment', Value: 'Production' },
              { Key: 'Owner', Value: 'TeamA' },
            ],
          },
        ],
      });

      const findingWithMatchingTags: Partial<ASFFFinding> = {
        ...mockFinding,
        Resources: [
          {
            Id: 'arn:aws:s3:::test-bucket',
            Type: 'AwsS3Bucket',
            Partition: 'aws',
            Region: 'us-east-1',
            Tags: {
              Environment: 'Production',
              Owner: 'TeamA',
            },
          },
        ],
      };

      const result = await applyFilters(findingWithMatchingTags as ASFFFinding, mockLogger);

      expect(result).toEqual({
        passed: true,
        appliedFilter: 'none',
      });
    });
  });
});
