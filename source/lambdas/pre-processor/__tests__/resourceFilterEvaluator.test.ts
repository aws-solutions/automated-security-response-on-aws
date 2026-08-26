// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { DynamoDBDocumentClient, PutCommand } from '@aws-sdk/lib-dynamodb';
import { mockClient } from 'aws-sdk-client-mock';
import { ListParentsCommand, OrganizationsClient, ChildNotFoundException } from '@aws-sdk/client-organizations';
import { ResourceFilterEvaluator } from '../ResourceFilterEvaluator';
import { DynamoDBTestSetup } from '../../common/__tests__/dynamodbSetup';
import { resourceFiltersTableName } from '../../common/__tests__/envSetup';
import { getLogger } from '../../common/utils/logger';
import { NormalizedFinding } from '@asr/data-models';
import { FiltersRepository } from '../../common/repositories/filtersRepository';
import { Clock } from '../../common/utils/clock';

const mockOrganizationsClient = mockClient(OrganizationsClient);

describe('ResourceFilterEvaluator', () => {
  const mockLogger = getLogger('test');
  let dynamoDBDocumentClient: DynamoDBDocumentClient;
  let filtersRepository: FiltersRepository;
  let evaluator: ResourceFilterEvaluator;
  const fixedDate = new Date('2025-01-15T00:00:00Z');
  const stubClock: Clock = { now: () => fixedDate };

  const createMockFinding = (overrides: Partial<NormalizedFinding> = {}): NormalizedFinding => ({
    id: 'test-finding-id',
    productArn: 'arn:aws:securityhub:us-east-1::product/aws/securityhub',
    findingTypeIdentifier: { type: 'securityControl', value: 'S3.1' },
    accountId: '111111111111',
    region: 'us-east-1',
    severity: 'HIGH',
    complianceStatus: 'FAILED',
    recordState: 'ACTIVE',
    workflowStatus: 'NEW',
    resources: [
      {
        type: 'AwsS3Bucket',
        id: 'arn:aws:s3:::my-test-bucket',
        tags: { Environment: 'production', Team: 'security' },
      },
    ],
    title: 'Test Finding',
    description: 'Test description',
    createdAt: '2024-01-01T00:00:00Z',
    updatedAt: '2024-01-01T00:00:00Z',
    format: 'ASFF',
    raw: {},
    ...overrides,
  });

  beforeAll(async () => {
    dynamoDBDocumentClient = DynamoDBTestSetup.getDocClient();
    await DynamoDBTestSetup.createResourceFiltersTable(resourceFiltersTableName);
  });

  afterAll(async () => {
    await DynamoDBTestSetup.deleteTable(resourceFiltersTableName);
  });

  beforeEach(async () => {
    await DynamoDBTestSetup.clearTable(resourceFiltersTableName, 'resourceFilters');
    filtersRepository = new FiltersRepository(resourceFiltersTableName, dynamoDBDocumentClient);
    evaluator = new ResourceFilterEvaluator(
      filtersRepository,
      mockLogger,
      new OrganizationsClient({ maxAttempts: 15, retryMode: 'standard' }),
      stubClock,
    );
    mockOrganizationsClient.reset();
  });

  describe('evaluateFilters with no filters', () => {
    it('returns passed when no filters are configured', async () => {
      const finding = createMockFinding();
      const result = await evaluator.evaluateFilters(finding, [], 'include');
      expect(result.passed).toBe(true);
      expect(result.reason).toBe('no_filters_configured');
    });
  });

  describe('filter definition cache', () => {
    const putAccountFilter = async (filterId: string): Promise<void> => {
      await dynamoDBDocumentClient.send(
        new PutCommand({
          TableName: resourceFiltersTableName,
          Item: {
            filterId,
            name: `Filter ${filterId}`,
            accountIds: new Set(['111111111111']),
            organizationalUnits: [],
            tags: [],
            arnPatterns: [],
          },
        }),
      );
    };

    it('fetches filter definitions once across evaluations that share a cache, still resolving each correctly', async () => {
      // ARRANGE — one filter, two findings, a shared cache.
      const filterId = 'filter-cached';
      await putAccountFilter(filterId);
      const batchFindByIds = jest.spyOn(filtersRepository, 'batchFindByIds');
      const cache = new Map();

      // ACT — two evaluations against the same filter set sharing the cache.
      const first = await evaluator.evaluateFilters(
        createMockFinding({ accountId: '111111111111' }),
        [filterId],
        'include',
        cache,
      );
      const second = await evaluator.evaluateFilters(
        createMockFinding({ accountId: '999999999999' }),
        [filterId],
        'include',
        cache,
      );

      // ASSERT — definitions fetched from DynamoDB once; each finding evaluated on its own merits.
      expect(batchFindByIds).toHaveBeenCalledTimes(1);
      expect(first.passed).toBe(true);
      expect(second.passed).toBe(false);
    });

    it('fetches filter definitions on every evaluation when no cache is supplied', async () => {
      // ARRANGE
      const filterId = 'filter-uncached';
      await putAccountFilter(filterId);
      const batchFindByIds = jest.spyOn(filtersRepository, 'batchFindByIds');
      const finding = createMockFinding({ accountId: '111111111111' });

      // ACT
      await evaluator.evaluateFilters(finding, [filterId], 'include');
      await evaluator.evaluateFilters(finding, [filterId], 'include');

      // ASSERT
      expect(batchFindByIds).toHaveBeenCalledTimes(2);
    });
  });

  describe('evaluateFilters with include mode', () => {
    it('passes when finding matches all filter criteria', async () => {
      // ARRANGE
      const filterId = 'filter-1';
      await dynamoDBDocumentClient.send(
        new PutCommand({
          TableName: resourceFiltersTableName,
          Item: {
            filterId,
            name: 'Production Filter',
            accountIds: new Set(['111111111111']),
            organizationalUnits: [],
            tags: [],
            arnPatterns: [],
          },
        }),
      );

      const finding = createMockFinding({ accountId: '111111111111' });

      // ACT
      const result = await evaluator.evaluateFilters(finding, [filterId], 'include');

      // ASSERT
      expect(result.passed).toBe(true);
      expect(result.reason).toBe('all_filters_matched');
    });

    it('fails when finding does not match filter account ID', async () => {
      // ARRANGE
      const filterId = 'filter-1';
      await dynamoDBDocumentClient.send(
        new PutCommand({
          TableName: resourceFiltersTableName,
          Item: {
            filterId,
            name: 'Production Filter',
            accountIds: new Set(['222222222222']),
            organizationalUnits: [],
            tags: [],
            arnPatterns: [],
          },
        }),
      );

      const finding = createMockFinding({ accountId: '111111111111' });

      // ACT
      const result = await evaluator.evaluateFilters(finding, [filterId], 'include');

      // ASSERT
      expect(result.passed).toBe(false);
      expect(result.reason).toContain('filter_not_matched');
    });

    it('requires all filters to match in include mode', async () => {
      // ARRANGE
      await dynamoDBDocumentClient.send(
        new PutCommand({
          TableName: resourceFiltersTableName,
          Item: {
            filterId: 'filter-1',
            name: 'Account Filter',
            accountIds: new Set(['111111111111']),
            organizationalUnits: [],
            tags: [],
            arnPatterns: [],
          },
        }),
      );
      await dynamoDBDocumentClient.send(
        new PutCommand({
          TableName: resourceFiltersTableName,
          Item: {
            filterId: 'filter-2',
            name: 'Different Account Filter',
            accountIds: new Set(['222222222222']),
            organizationalUnits: [],
            tags: [],
            arnPatterns: [],
          },
        }),
      );

      const finding = createMockFinding({ accountId: '111111111111' });

      // ACT
      const result = await evaluator.evaluateFilters(finding, ['filter-1', 'filter-2'], 'include');

      // ASSERT
      expect(result.passed).toBe(false);
    });
  });

  describe('evaluateFilters with exclude mode', () => {
    it('passes when finding does not match any filter', async () => {
      // ARRANGE
      const filterId = 'filter-1';
      await dynamoDBDocumentClient.send(
        new PutCommand({
          TableName: resourceFiltersTableName,
          Item: {
            filterId,
            name: 'Excluded Accounts',
            accountIds: new Set(['222222222222']),
            organizationalUnits: [],
            tags: [],
            arnPatterns: [],
          },
        }),
      );

      const finding = createMockFinding({ accountId: '111111111111' });

      // ACT
      const result = await evaluator.evaluateFilters(finding, [filterId], 'exclude');

      // ASSERT
      expect(result.passed).toBe(true);
      expect(result.reason).toBe('no_exclusion_filters_matched');
    });

    it('fails when finding matches any exclusion filter', async () => {
      // ARRANGE
      const filterId = 'filter-1';
      await dynamoDBDocumentClient.send(
        new PutCommand({
          TableName: resourceFiltersTableName,
          Item: {
            filterId,
            name: 'Excluded Accounts',
            accountIds: new Set(['111111111111']),
            organizationalUnits: [],
            tags: [],
            arnPatterns: [],
          },
        }),
      );

      const finding = createMockFinding({ accountId: '111111111111' });

      // ACT
      const result = await evaluator.evaluateFilters(finding, [filterId], 'exclude');

      // ASSERT
      expect(result.passed).toBe(false);
      expect(result.reason).toContain('filter_matched_exclusion');
    });
  });

  describe('tag matching', () => {
    it('matches when resource has all required tags', async () => {
      // ARRANGE
      const filterId = 'filter-1';
      await dynamoDBDocumentClient.send(
        new PutCommand({
          TableName: resourceFiltersTableName,
          Item: {
            filterId,
            name: 'Tag Filter',
            accountIds: [],
            organizationalUnits: [],
            tags: [{ key: 'Environment', value: 'production' }],
            arnPatterns: [],
          },
        }),
      );

      const finding = createMockFinding({
        resources: [{ type: 'AwsS3Bucket', id: 'arn:aws:s3:::bucket', tags: { Environment: 'production' } }],
      });

      // ACT
      const result = await evaluator.evaluateFilters(finding, [filterId], 'include');

      // ASSERT
      expect(result.passed).toBe(true);
    });

    it('does not match when resource is missing required tag', async () => {
      // ARRANGE
      const filterId = 'filter-1';
      await dynamoDBDocumentClient.send(
        new PutCommand({
          TableName: resourceFiltersTableName,
          Item: {
            filterId,
            name: 'Tag Filter',
            accountIds: [],
            organizationalUnits: [],
            tags: [{ key: 'Environment', value: 'production' }],
            arnPatterns: [],
          },
        }),
      );

      const finding = createMockFinding({
        resources: [{ type: 'AwsS3Bucket', id: 'arn:aws:s3:::bucket', tags: { Environment: 'development' } }],
      });

      // ACT
      const result = await evaluator.evaluateFilters(finding, [filterId], 'include');

      // ASSERT
      expect(result.passed).toBe(false);
    });

    it('ignores tag filter when resource has no tags', async () => {
      // ARRANGE
      const filterId = 'filter-1';
      await dynamoDBDocumentClient.send(
        new PutCommand({
          TableName: resourceFiltersTableName,
          Item: {
            filterId,
            name: 'Tag Filter',
            accountIds: [],
            organizationalUnits: [],
            tags: [{ key: 'Environment', value: 'production' }],
            arnPatterns: [],
          },
        }),
      );

      const finding = createMockFinding({
        resources: [{ type: 'AwsS3Bucket', id: 'arn:aws:s3:::bucket' }],
      });

      // ACT
      const result = await evaluator.evaluateFilters(finding, [filterId], 'include');

      // ASSERT
      expect(result.passed).toBe(false);
    });

    it('treats tag-only filter as non-match when resource does not support tagging (include mode)', async () => {
      // ARRANGE: Filter with only tag criteria, finding with no resources (non-taggable)
      const filterId = 'filter-1';
      await dynamoDBDocumentClient.send(
        new PutCommand({
          TableName: resourceFiltersTableName,
          Item: {
            filterId,
            name: 'Tag Only Filter',
            accountIds: [],
            organizationalUnits: [],
            tags: [{ key: 'Environment', value: 'production' }],
            arnPatterns: [],
          },
        }),
      );

      const finding = createMockFinding({
        resources: [],
      });

      // ACT
      const result = await evaluator.evaluateFilters(finding, [filterId], 'include');

      // ASSERT: Tag-only filter does not match non-taggable resources, so remediation is blocked in include mode
      expect(result.passed).toBe(false);
      expect(result.reason).toContain('filter_not_matched');
    });

    it('treats tag-only filter as non-match when resource does not support tagging (exclude mode)', async () => {
      // ARRANGE: Filter with only tag criteria, finding with no resources (non-taggable)
      const filterId = 'filter-1';
      await dynamoDBDocumentClient.send(
        new PutCommand({
          TableName: resourceFiltersTableName,
          Item: {
            filterId,
            name: 'Tag Only Exclusion Filter',
            accountIds: [],
            organizationalUnits: [],
            tags: [{ key: 'Environment', value: 'production' }],
            arnPatterns: [],
          },
        }),
      );

      const finding = createMockFinding({
        resources: [],
      });

      // ACT
      const result = await evaluator.evaluateFilters(finding, [filterId], 'exclude');

      // ASSERT: Tag-only filter does not match non-taggable resources, so remediation is allowed in exclude mode
      expect(result.passed).toBe(true);
      expect(result.reason).toBe('no_exclusion_filters_matched');
    });
  });

  describe('ARN pattern matching', () => {
    it('matches exact ARN', async () => {
      // ARRANGE
      const filterId = 'filter-1';
      await dynamoDBDocumentClient.send(
        new PutCommand({
          TableName: resourceFiltersTableName,
          Item: {
            filterId,
            name: 'ARN Filter',
            accountIds: [],
            organizationalUnits: [],
            tags: [],
            arnPatterns: new Set(['arn:aws:s3:::my-test-bucket']),
          },
        }),
      );

      const finding = createMockFinding({
        resources: [{ type: 'AwsS3Bucket', id: 'arn:aws:s3:::my-test-bucket' }],
      });

      // ACT
      const result = await evaluator.evaluateFilters(finding, [filterId], 'include');

      // ASSERT
      expect(result.passed).toBe(true);
    });

    it('matches ARN with wildcard in resource', async () => {
      // ARRANGE
      const filterId = 'filter-1';
      await dynamoDBDocumentClient.send(
        new PutCommand({
          TableName: resourceFiltersTableName,
          Item: {
            filterId,
            name: 'ARN Filter',
            accountIds: [],
            organizationalUnits: [],
            tags: [],
            arnPatterns: new Set(['arn:aws:s3:::my-*']),
          },
        }),
      );

      const finding = createMockFinding({
        resources: [{ type: 'AwsS3Bucket', id: 'arn:aws:s3:::my-test-bucket' }],
      });

      // ACT
      const result = await evaluator.evaluateFilters(finding, [filterId], 'include');

      // ASSERT
      expect(result.passed).toBe(true);
    });

    it('matches ARN with wildcard in account', async () => {
      // ARRANGE
      const filterId = 'filter-1';
      await dynamoDBDocumentClient.send(
        new PutCommand({
          TableName: resourceFiltersTableName,
          Item: {
            filterId,
            name: 'ARN Filter',
            accountIds: [],
            organizationalUnits: [],
            tags: [],
            arnPatterns: new Set(['arn:aws:ec2:us-east-1:*:instance/i-12345']),
          },
        }),
      );

      const finding = createMockFinding({
        resources: [{ type: 'AwsEc2Instance', id: 'arn:aws:ec2:us-east-1:111111111111:instance/i-12345' }],
      });

      // ACT
      const result = await evaluator.evaluateFilters(finding, [filterId], 'include');

      // ASSERT
      expect(result.passed).toBe(true);
    });

    it('does not match when ARN pattern does not match', async () => {
      // ARRANGE
      const filterId = 'filter-1';
      await dynamoDBDocumentClient.send(
        new PutCommand({
          TableName: resourceFiltersTableName,
          Item: {
            filterId,
            name: 'ARN Filter',
            accountIds: [],
            organizationalUnits: [],
            tags: [],
            arnPatterns: new Set(['arn:aws:s3:::other-bucket']),
          },
        }),
      );

      const finding = createMockFinding({
        resources: [{ type: 'AwsS3Bucket', id: 'arn:aws:s3:::my-test-bucket' }],
      });

      // ACT
      const result = await evaluator.evaluateFilters(finding, [filterId], 'include');

      // ASSERT
      expect(result.passed).toBe(false);
    });

    it('matches ARN with multiple wildcards', async () => {
      // ARRANGE
      const filterId = 'filter-1';
      await dynamoDBDocumentClient.send(
        new PutCommand({
          TableName: resourceFiltersTableName,
          Item: {
            filterId,
            name: 'ARN Filter',
            accountIds: [],
            organizationalUnits: [],
            tags: [],
            arnPatterns: new Set(['arn:aws:s3:::*-test-*']),
          },
        }),
      );

      const finding = createMockFinding({
        resources: [{ type: 'AwsS3Bucket', id: 'arn:aws:s3:::my-test-bucket' }],
      });

      // ACT
      const result = await evaluator.evaluateFilters(finding, [filterId], 'include');

      // ASSERT
      expect(result.passed).toBe(true);
    });

    it('does not match when wildcard pattern suffix does not match', async () => {
      // ARRANGE
      const filterId = 'filter-1';
      await dynamoDBDocumentClient.send(
        new PutCommand({
          TableName: resourceFiltersTableName,
          Item: {
            filterId,
            name: 'ARN Filter',
            accountIds: [],
            organizationalUnits: [],
            tags: [],
            arnPatterns: new Set(['arn:aws:s3:::*-prod']),
          },
        }),
      );

      const finding = createMockFinding({
        resources: [{ type: 'AwsS3Bucket', id: 'arn:aws:s3:::my-test-bucket' }],
      });

      // ACT
      const result = await evaluator.evaluateFilters(finding, [filterId], 'include');

      // ASSERT
      expect(result.passed).toBe(false);
    });
  });

  describe('OU matching', () => {
    it('matches when account belongs to immediate parent OU', async () => {
      // ARRANGE
      mockOrganizationsClient
        .on(ListParentsCommand, { ChildId: '111111111111' })
        .resolves({ Parents: [{ Id: 'ou-1234-12345678', Type: 'ORGANIZATIONAL_UNIT' }] })
        .on(ListParentsCommand, { ChildId: 'ou-1234-12345678' })
        .resolves({ Parents: [{ Id: 'r-root', Type: 'ROOT' }] });

      const filterId = 'filter-1';
      await dynamoDBDocumentClient.send(
        new PutCommand({
          TableName: resourceFiltersTableName,
          Item: {
            filterId,
            name: 'OU Filter',
            accountIds: [],
            organizationalUnits: new Set(['ou-1234-12345678']),
            tags: [],
            arnPatterns: [],
          },
        }),
      );

      const finding = createMockFinding({ accountId: '111111111111' });

      // ACT
      const result = await evaluator.evaluateFilters(finding, [filterId], 'include');

      // ASSERT
      expect(result.passed).toBe(true);
    });

    it('matches when account belongs to ancestor OU in hierarchy', async () => {
      // ARRANGE: Account -> Child OU -> Parent OU -> Root
      mockOrganizationsClient
        .on(ListParentsCommand, { ChildId: '111111111111' })
        .resolves({ Parents: [{ Id: 'ou-child-11111111', Type: 'ORGANIZATIONAL_UNIT' }] })
        .on(ListParentsCommand, { ChildId: 'ou-child-11111111' })
        .resolves({ Parents: [{ Id: 'ou-parent-22222222', Type: 'ORGANIZATIONAL_UNIT' }] })
        .on(ListParentsCommand, { ChildId: 'ou-parent-22222222' })
        .resolves({ Parents: [{ Id: 'r-root', Type: 'ROOT' }] });

      const filterId = 'filter-1';
      await dynamoDBDocumentClient.send(
        new PutCommand({
          TableName: resourceFiltersTableName,
          Item: {
            filterId,
            name: 'OU Filter',
            accountIds: [],
            organizationalUnits: new Set(['ou-parent-22222222']),
            tags: [],
            arnPatterns: [],
          },
        }),
      );

      const finding = createMockFinding({ accountId: '111111111111' });

      // ACT
      const result = await evaluator.evaluateFilters(finding, [filterId], 'include');

      // ASSERT
      expect(result.passed).toBe(true);
    });

    it('does not match when account does not belong to filter OU', async () => {
      // ARRANGE
      mockOrganizationsClient
        .on(ListParentsCommand, { ChildId: '111111111111' })
        .resolves({ Parents: [{ Id: 'ou-9999-99999999', Type: 'ORGANIZATIONAL_UNIT' }] })
        .on(ListParentsCommand, { ChildId: 'ou-9999-99999999' })
        .resolves({ Parents: [{ Id: 'r-root', Type: 'ROOT' }] });

      const filterId = 'filter-1';
      await dynamoDBDocumentClient.send(
        new PutCommand({
          TableName: resourceFiltersTableName,
          Item: {
            filterId,
            name: 'OU Filter',
            accountIds: [],
            organizationalUnits: new Set(['ou-1234-12345678']),
            tags: [],
            arnPatterns: [],
          },
        }),
      );

      const finding = createMockFinding({ accountId: '111111111111' });

      // ACT
      const result = await evaluator.evaluateFilters(finding, [filterId], 'include');

      // ASSERT
      expect(result.passed).toBe(false);
    });

    it('handles ChildNotFoundException gracefully and caches the result', async () => {
      // ARRANGE
      mockOrganizationsClient.on(ListParentsCommand).rejects(
        new ChildNotFoundException({
          message: 'Account not found',
          $metadata: {},
        }),
      );

      const filterId = 'filter-1';
      await dynamoDBDocumentClient.send(
        new PutCommand({
          TableName: resourceFiltersTableName,
          Item: {
            filterId,
            name: 'OU Filter',
            accountIds: [],
            organizationalUnits: new Set(['ou-1234-12345678']),
            tags: [],
            arnPatterns: [],
          },
        }),
      );

      const finding = createMockFinding({ accountId: '111111111111' });

      // ACT
      const result = await evaluator.evaluateFilters(finding, [filterId], 'include');

      // ASSERT
      expect(result.passed).toBe(false);
    });

    it('does not cache transient errors and retries on next invocation', async () => {
      // ARRANGE: First call fails with transient error, second call succeeds
      let callCount = 0;
      mockOrganizationsClient.on(ListParentsCommand).callsFake(() => {
        callCount++;
        if (callCount === 1) {
          throw new Error('Throttling');
        }
        // For subsequent calls, return the OU hierarchy
        return { Parents: [{ Id: 'ou-1234-12345678', Type: 'ORGANIZATIONAL_UNIT' }] };
      });

      // Second call for hierarchy traversal (after finding immediate parent)
      mockOrganizationsClient
        .on(ListParentsCommand, { ChildId: 'ou-1234-12345678' })
        .resolves({ Parents: [{ Id: 'r-root', Type: 'ROOT' }] });

      const filterId = 'filter-1';
      await dynamoDBDocumentClient.send(
        new PutCommand({
          TableName: resourceFiltersTableName,
          Item: {
            filterId,
            name: 'OU Filter',
            accountIds: [],
            organizationalUnits: new Set(['ou-1234-12345678']),
            tags: [],
            arnPatterns: [],
          },
        }),
      );

      const finding = createMockFinding({ accountId: '111111111111' });

      // ACT: First call fails due to transient error - OU lookup fails, so filter doesn't match
      const result1 = await evaluator.evaluateFilters(finding, [filterId], 'include');
      expect(result1.passed).toBe(false);

      // ACT: Second call should retry and succeed (not use cached empty result)
      const result2 = await evaluator.evaluateFilters(finding, [filterId], 'include');

      // ASSERT
      expect(result2.passed).toBe(true);
    });
  });

  describe('combined filter criteria', () => {
    it('requires all criteria within a filter to match', async () => {
      // ARRANGE
      const filterId = 'filter-1';
      await dynamoDBDocumentClient.send(
        new PutCommand({
          TableName: resourceFiltersTableName,
          Item: {
            filterId,
            name: 'Combined Filter',
            accountIds: new Set(['111111111111']),
            organizationalUnits: [],
            tags: [{ key: 'Environment', value: 'production' }],
            arnPatterns: [],
          },
        }),
      );

      const finding = createMockFinding({
        accountId: '111111111111',
        resources: [{ type: 'AwsS3Bucket', id: 'arn:aws:s3:::bucket', tags: { Environment: 'development' } }],
      });

      // ACT
      const result = await evaluator.evaluateFilters(finding, [filterId], 'include');

      // ASSERT
      expect(result.passed).toBe(false);
    });

    it('passes when all criteria within a filter match', async () => {
      // ARRANGE
      const filterId = 'filter-1';
      await dynamoDBDocumentClient.send(
        new PutCommand({
          TableName: resourceFiltersTableName,
          Item: {
            filterId,
            name: 'Combined Filter',
            accountIds: new Set(['111111111111']),
            organizationalUnits: [],
            tags: [{ key: 'Environment', value: 'production' }],
            arnPatterns: [],
          },
        }),
      );

      const finding = createMockFinding({
        accountId: '111111111111',
        resources: [{ type: 'AwsS3Bucket', id: 'arn:aws:s3:::bucket', tags: { Environment: 'production' } }],
      });

      // ACT
      const result = await evaluator.evaluateFilters(finding, [filterId], 'include');

      // ASSERT
      expect(result.passed).toBe(true);
    });
  });

  describe('missing filters', () => {
    it('blocks remediation when filter IDs do not exist in table', async () => {
      // ARRANGE
      const finding = createMockFinding();

      // ACT
      const result = await evaluator.evaluateFilters(finding, ['non-existent-filter'], 'include');

      // ASSERT
      expect(result.passed).toBe(false);
      expect(result.reason).toBe('no_valid_filters_found');
    });

    it('blocks remediation in exclude mode when filter IDs do not exist in table', async () => {
      // ARRANGE
      const finding = createMockFinding();

      // ACT
      const result = await evaluator.evaluateFilters(finding, ['non-existent-filter'], 'exclude');

      // ASSERT
      expect(result.passed).toBe(false);
      expect(result.reason).toBe('no_valid_filters_found');
    });
  });

  describe('partial filter set (a configured filter is missing)', () => {
    it('blocks remediation in exclude mode when a configured filter ID is missing', async () => {
      // ARRANGE — a real exclude filter requested alongside a deleted/non-existent ID.
      const filterId = 'filter-1';
      await dynamoDBDocumentClient.send(
        new PutCommand({
          TableName: resourceFiltersTableName,
          Item: {
            filterId,
            name: 'Excluded Accounts',
            accountIds: new Set(['222222222222']),
            organizationalUnits: [],
            tags: [],
            arnPatterns: [],
          },
        }),
      );
      const finding = createMockFinding({ accountId: '111111111111' });

      // ACT — real repository: the missing ID is silently omitted by BatchGetItem.
      const result = await evaluator.evaluateFilters(finding, [filterId, 'non-existent-filter'], 'exclude');

      // ASSERT
      expect(result.passed).toBe(false);
      expect(result.reason).toBe('incomplete_filter_retrieval_in_exclude_mode');
    });

    it('blocks remediation in include mode when a configured filter ID is missing but the surviving filter matches', async () => {
      // ARRANGE — a real filter the finding matches, requested alongside a deleted/non-existent ID.
      // Returning only the matching filter would otherwise let remediation proceed, dropping the
      // missing filter's constraint (the SEC-005 bypass).
      const filterId = 'filter-present';
      await dynamoDBDocumentClient.send(
        new PutCommand({
          TableName: resourceFiltersTableName,
          Item: {
            filterId,
            name: 'Included Accounts',
            accountIds: new Set(['111111111111']),
            organizationalUnits: [],
            tags: [],
            arnPatterns: [],
          },
        }),
      );
      const finding = createMockFinding({ accountId: '111111111111' });

      // ACT — real repository: the missing ID is silently omitted by BatchGetItem.
      const result = await evaluator.evaluateFilters(finding, [filterId, 'non-existent-filter'], 'include');

      // ASSERT
      expect(result.passed).toBe(false);
      expect(result.reason).toBe('incomplete_filter_retrieval_in_include_mode');
    });
  });
});
