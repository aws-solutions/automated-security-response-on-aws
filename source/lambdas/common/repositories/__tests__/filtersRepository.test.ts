// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { ConditionalCheckFailedException } from '@aws-sdk/client-dynamodb';
import { DynamoDBDocumentClient, GetCommand, PutCommand, ScanCommand } from '@aws-sdk/lib-dynamodb';
import { CreateFilterRequest, UpdateFilterRequest } from '@asr/data-models';
import { FiltersRepository } from '../filtersRepository';
import { DynamoDBTestSetup } from '../../__tests__/dynamodbSetup';
import { resourceFiltersTableName } from '../../__tests__/envSetup';

const FILTER_ID = '550e8400-e29b-41d4-a716-446655440000';

const SEED_FILTER = {
  filterId: FILTER_ID,
  name: 'Production Accounts',
  accountIds: new Set(['123456789012']),
  organizationalUnits: new Set(['ou-abcd-12345678']),
  tags: [{ key: 'Environment', value: 'Production' }],
  arnPatterns: new Set(['arn:aws:s3:::prod-*']),
  version: 1,
  createdAt: '2024-01-01T00:00:00Z',
  createdBy: 'admin@example.com',
  lastModified: '2024-01-01T00:00:00Z',
  modifiedBy: 'admin@example.com',
};

const VALID_UPDATE_REQUEST: UpdateFilterRequest = {
  name: 'Updated Filter',
  accountIds: ['123456789012', '987654321098'],
  organizationalUnits: ['ou-abcd-12345678'],
  tags: [{ key: 'Env', value: 'Staging' }],
  arnPatterns: ['arn:aws:s3:::staging-*'],
  version: 1,
};

const VALID_CREATE_REQUEST: CreateFilterRequest = {
  name: 'New Filter',
  accountIds: ['111111111111', '222222222222'],
  organizationalUnits: ['ou-abcd-12345678'],
  tags: [{ key: 'Environment', value: 'Production' }],
  arnPatterns: ['arn:aws:s3:::prod-*'],
};

describe('FiltersRepository', () => {
  let repository: FiltersRepository;
  let dynamoDBDocumentClient: DynamoDBDocumentClient;

  beforeAll(async () => {
    dynamoDBDocumentClient = DynamoDBTestSetup.getDocClient();
    await DynamoDBTestSetup.createResourceFiltersTable(resourceFiltersTableName);
  });

  afterAll(async () => {
    await DynamoDBTestSetup.deleteTable(resourceFiltersTableName);
  });

  beforeEach(async () => {
    await DynamoDBTestSetup.clearTable(resourceFiltersTableName, 'resourceFilters');
    repository = new FiltersRepository(resourceFiltersTableName, dynamoDBDocumentClient);
  });

  describe('findAll', () => {
    it('should return empty array when table is empty', async () => {
      // ACT
      const result = await repository.findAll();

      // ASSERT
      expect(result).toEqual([]);
      expect(result).toHaveLength(0);
    });

    it('should retrieve all filters successfully', async () => {
      // ARRANGE
      const filterItems = [
        {
          filterId: '550e8400-e29b-41d4-a716-446655440001',
          name: 'Production Accounts',
          accountIds: new Set(['111111111111', '222222222222']),
          organizationalUnits: new Set(['ou-abcd-12345678']),
          tags: [{ key: 'env', value: 'prod' }],
          arnPatterns: new Set(['arn:aws:s3:::prod-*']),
          version: 1,
          createdAt: '2024-01-01T00:00:00Z',
          createdBy: 'admin-user',
          lastModified: '2024-01-01T00:00:00Z',
          modifiedBy: 'admin-user',
        },
        {
          filterId: '550e8400-e29b-41d4-a716-446655440002',
          name: 'Dev Accounts',
          accountIds: new Set(['333333333333']),
          organizationalUnits: new Set(['ou-efgh-87654321']),
          tags: [{ key: 'env', value: 'dev' }],
          arnPatterns: new Set(['arn:aws:ec2:*:*:instance/*']),
          version: 2,
          createdAt: '2024-01-02T00:00:00Z',
          createdBy: 'dev-user',
          lastModified: '2024-01-03T00:00:00Z',
          modifiedBy: 'dev-user',
        },
      ];

      await Promise.all(
        filterItems.map((item) =>
          dynamoDBDocumentClient.send(
            new PutCommand({
              TableName: resourceFiltersTableName,
              Item: item,
            }),
          ),
        ),
      );

      // ACT
      const result = await repository.findAll();

      // ASSERT
      expect(result).toHaveLength(2);
      const filterIds = result.map((f) => f.filterId);
      expect(filterIds).toContain('550e8400-e29b-41d4-a716-446655440001');
      expect(filterIds).toContain('550e8400-e29b-41d4-a716-446655440002');
    });

    it('should return filters with all expected properties', async () => {
      // ARRANGE
      const filterItem = {
        filterId: '550e8400-e29b-41d4-a716-446655440001',
        name: 'Production Accounts',
        accountIds: new Set(['111111111111', '222222222222']),
        organizationalUnits: new Set(['ou-abcd-12345678']),
        tags: [{ key: 'env', value: 'prod' }],
        arnPatterns: new Set(['arn:aws:s3:::prod-*']),
        version: 1,
        createdAt: '2024-01-01T00:00:00Z',
        createdBy: 'admin-user',
        lastModified: '2024-01-02T00:00:00Z',
        modifiedBy: 'admin-user',
      };

      await dynamoDBDocumentClient.send(
        new PutCommand({
          TableName: resourceFiltersTableName,
          Item: filterItem,
        }),
      );

      // ACT
      const result = await repository.findAll();

      // ASSERT
      const filter = result[0];
      expect(filter).toHaveProperty('filterId', '550e8400-e29b-41d4-a716-446655440001');
      expect(filter).toHaveProperty('name', 'Production Accounts');
      expect(filter.accountIds).toContain('111111111111');
      expect(filter.accountIds).toContain('222222222222');
      expect(filter.organizationalUnits).toContain('ou-abcd-12345678');
      expect(filter.tags).toEqual([{ key: 'env', value: 'prod' }]);
      expect(filter.arnPatterns).toContain('arn:aws:s3:::prod-*');
      expect(filter).toHaveProperty('version', 1);
      expect(filter).toHaveProperty('createdAt', '2024-01-01T00:00:00Z');
      expect(filter).toHaveProperty('createdBy', 'admin-user');
      expect(filter).toHaveProperty('lastModified', '2024-01-02T00:00:00Z');
      expect(filter).toHaveProperty('modifiedBy', 'admin-user');
    });

    it('should transform accountIds from Set to Array', async () => {
      // ARRANGE
      const filterItem = {
        filterId: '550e8400-e29b-41d4-a716-446655440001',
        name: 'Multi-Account Filter',
        accountIds: new Set(['111111111111', '222222222222', '333333333333']),
        version: 1,
      };

      await dynamoDBDocumentClient.send(
        new PutCommand({
          TableName: resourceFiltersTableName,
          Item: filterItem,
        }),
      );

      // ACT
      const result = await repository.findAll();

      // ASSERT
      expect(result).toHaveLength(1);
      expect(Array.isArray(result[0].accountIds)).toBe(true);
      expect(result[0].accountIds).toContain('111111111111');
      expect(result[0].accountIds).toContain('222222222222');
      expect(result[0].accountIds).toContain('333333333333');
    });

    it('should transform organizationalUnits from Set to Array', async () => {
      // ARRANGE
      const filterItem = {
        filterId: '550e8400-e29b-41d4-a716-446655440001',
        name: 'OU Filter',
        organizationalUnits: new Set(['ou-abcd-12345678', 'ou-efgh-87654321']),
        version: 1,
      };

      await dynamoDBDocumentClient.send(
        new PutCommand({
          TableName: resourceFiltersTableName,
          Item: filterItem,
        }),
      );

      // ACT
      const result = await repository.findAll();

      // ASSERT
      expect(result).toHaveLength(1);
      expect(Array.isArray(result[0].organizationalUnits)).toBe(true);
      expect(result[0].organizationalUnits).toContain('ou-abcd-12345678');
      expect(result[0].organizationalUnits).toContain('ou-efgh-87654321');
    });

    it('should transform arnPatterns from Set to Array', async () => {
      // ARRANGE
      const filterItem = {
        filterId: '550e8400-e29b-41d4-a716-446655440001',
        name: 'ARN Filter',
        arnPatterns: new Set(['arn:aws:s3:::bucket-*', 'arn:aws:ec2:*:*:instance/*']),
        version: 1,
      };

      await dynamoDBDocumentClient.send(
        new PutCommand({
          TableName: resourceFiltersTableName,
          Item: filterItem,
        }),
      );

      // ACT
      const result = await repository.findAll();

      // ASSERT
      expect(result).toHaveLength(1);
      expect(Array.isArray(result[0].arnPatterns)).toBe(true);
      expect(result[0].arnPatterns).toContain('arn:aws:s3:::bucket-*');
      expect(result[0].arnPatterns).toContain('arn:aws:ec2:*:*:instance/*');
    });

    it('should handle filters with undefined Set fields', async () => {
      // ARRANGE
      const filterItem = {
        filterId: '550e8400-e29b-41d4-a716-446655440001',
        name: 'Minimal Filter',
        version: 1,
      };

      await dynamoDBDocumentClient.send(
        new PutCommand({
          TableName: resourceFiltersTableName,
          Item: filterItem,
        }),
      );

      // ACT
      const result = await repository.findAll();

      // ASSERT
      expect(result).toHaveLength(1);
      expect(result[0].accountIds).toEqual([]);
      expect(result[0].organizationalUnits).toEqual([]);
      expect(result[0].arnPatterns).toEqual([]);
    });

    it('should handle filters with undefined tags by defaulting to empty array', async () => {
      // ARRANGE
      const filterItem = {
        filterId: '550e8400-e29b-41d4-a716-446655440001',
        name: 'No Tags Filter',
        version: 1,
      };

      await dynamoDBDocumentClient.send(
        new PutCommand({
          TableName: resourceFiltersTableName,
          Item: filterItem,
        }),
      );

      // ACT
      const result = await repository.findAll();

      // ASSERT
      expect(result).toHaveLength(1);
      expect(result[0].tags).toEqual([]);
    });

    it('should handle filters with empty createdAt, createdBy, lastModified, and modifiedBy', async () => {
      // ARRANGE
      const filterItem = {
        filterId: '550e8400-e29b-41d4-a716-446655440001',
        name: 'No Audit Fields',
        version: 1,
      };

      await dynamoDBDocumentClient.send(
        new PutCommand({
          TableName: resourceFiltersTableName,
          Item: filterItem,
        }),
      );

      // ACT
      const result = await repository.findAll();

      // ASSERT
      expect(result).toHaveLength(1);
      expect(result[0].createdAt).toBe('');
      expect(result[0].createdBy).toBe('');
      expect(result[0].lastModified).toBe('');
      expect(result[0].modifiedBy).toBe('');
    });

    it('should handle filters with multiple tags', async () => {
      // ARRANGE
      const filterItem = {
        filterId: '550e8400-e29b-41d4-a716-446655440001',
        name: 'Multi-Tag Filter',
        tags: [
          { key: 'env', value: 'prod' },
          { key: 'team', value: 'security' },
          { key: 'cost-center', value: 'CC-1234' },
        ],
        version: 1,
      };

      await dynamoDBDocumentClient.send(
        new PutCommand({
          TableName: resourceFiltersTableName,
          Item: filterItem,
        }),
      );

      // ACT
      const result = await repository.findAll();

      // ASSERT
      expect(result).toHaveLength(1);
      expect(result[0].tags).toHaveLength(3);
      expect(result[0].tags).toEqual([
        { key: 'env', value: 'prod' },
        { key: 'team', value: 'security' },
        { key: 'cost-center', value: 'CC-1234' },
      ]);
    });

    it('should handle filters where Set fields are already arrays (DynamoDB Local behavior)', async () => {
      // ARRANGE
      const filterItem = {
        filterId: '550e8400-e29b-41d4-a716-446655440001',
        name: 'Array Fields Filter',
        accountIds: ['111111111111', '222222222222'],
        organizationalUnits: ['ou-abcd-12345678'],
        arnPatterns: ['arn:aws:s3:::bucket-*'],
        version: 1,
      };

      await dynamoDBDocumentClient.send(
        new PutCommand({
          TableName: resourceFiltersTableName,
          Item: filterItem,
        }),
      );

      // ACT
      const result = await repository.findAll();

      // ASSERT
      expect(result).toHaveLength(1);
      expect(Array.isArray(result[0].accountIds)).toBe(true);
      expect(result[0].accountIds).toContain('111111111111');
      expect(result[0].accountIds).toContain('222222222222');
      expect(Array.isArray(result[0].organizationalUnits)).toBe(true);
      expect(result[0].organizationalUnits).toContain('ou-abcd-12345678');
      expect(Array.isArray(result[0].arnPatterns)).toBe(true);
      expect(result[0].arnPatterns).toContain('arn:aws:s3:::bucket-*');
    });

    it('should handle pagination when table has many items', async () => {
      // ARRANGE
      const filterCount = 30;
      for (let i = 1; i <= filterCount; i++) {
        await dynamoDBDocumentClient.send(
          new PutCommand({
            TableName: resourceFiltersTableName,
            Item: {
              filterId: `550e8400-e29b-41d4-a716-${String(i).padStart(12, '0')}`,
              name: `Filter ${i}`,
              version: 1,
            },
          }),
        );
      }

      // ACT
      const result = await repository.findAll();

      // ASSERT
      expect(result).toHaveLength(filterCount);
      const uniqueIds = new Set(result.map((f) => f.filterId));
      expect(uniqueIds.size).toBe(filterCount);
    });
  });

  describe('findByName', () => {
    it('should return matching filter when name exists', async () => {
      // ARRANGE
      await dynamoDBDocumentClient.send(
        new PutCommand({ TableName: resourceFiltersTableName, Item: { ...SEED_FILTER } }),
      );

      // ACT
      const result = await repository.findByName('Production Accounts');

      // ASSERT
      expect(result).toHaveLength(1);
      expect(result[0].filterId).toBe(FILTER_ID);
      expect(result[0].name).toBe('Production Accounts');
    });

    it('should return empty array when name does not exist', async () => {
      // ARRANGE
      await dynamoDBDocumentClient.send(
        new PutCommand({ TableName: resourceFiltersTableName, Item: { ...SEED_FILTER } }),
      );

      // ACT
      const result = await repository.findByName('Nonexistent Filter');

      // ASSERT
      expect(result).toEqual([]);
    });

    it('should return empty array when table is empty', async () => {
      // ACT
      const result = await repository.findByName('Any Name');

      // ASSERT
      expect(result).toEqual([]);
    });
  });

  describe('updateFilter', () => {
    it('should update all fields and increment version', async () => {
      // ARRANGE
      await dynamoDBDocumentClient.send(
        new PutCommand({ TableName: resourceFiltersTableName, Item: { ...SEED_FILTER } }),
      );

      // ACT
      const result = await repository.updateFilter(
        FILTER_ID,
        VALID_UPDATE_REQUEST,
        'editor@example.com',
        '2025-03-20T00:00:00Z',
      );

      // ASSERT
      expect(result.filterId).toBe(FILTER_ID);
      expect(result.name).toBe('Updated Filter');
      expect(result.accountIds.sort()).toEqual(['123456789012', '987654321098']);
      expect(result.organizationalUnits).toEqual(['ou-abcd-12345678']);
      expect(result.tags).toEqual([{ key: 'Env', value: 'Staging' }]);
      expect(result.arnPatterns).toEqual(['arn:aws:s3:::staging-*']);
      expect(result.version).toBe(2);
      expect(result.modifiedBy).toBe('editor@example.com');
      expect(result.lastModified).toBe('2025-03-20T00:00:00Z');
      expect(result.createdAt).toBe('2024-01-01T00:00:00Z');
      expect(result.createdBy).toBe('admin@example.com');
    });

    it('should persist changes to DynamoDB', async () => {
      // ARRANGE
      await dynamoDBDocumentClient.send(
        new PutCommand({ TableName: resourceFiltersTableName, Item: { ...SEED_FILTER } }),
      );

      // ACT
      await repository.updateFilter(FILTER_ID, VALID_UPDATE_REQUEST, 'editor@example.com', '2025-03-20T00:00:00Z');

      // ASSERT
      const dbItem = await dynamoDBDocumentClient.send(
        new GetCommand({ TableName: resourceFiltersTableName, Key: { filterId: FILTER_ID } }),
      );
      expect(dbItem.Item?.name).toBe('Updated Filter');
      expect(dbItem.Item?.version).toBe(2);
      expect(dbItem.Item?.modifiedBy).toBe('editor@example.com');
    });

    it('should throw ConditionalCheckFailedException when version does not match', async () => {
      // ARRANGE
      await dynamoDBDocumentClient.send(
        new PutCommand({ TableName: resourceFiltersTableName, Item: { ...SEED_FILTER, version: 5 } }),
      );

      // ACT & ASSERT
      await expect(
        repository.updateFilter(FILTER_ID, VALID_UPDATE_REQUEST, 'editor@example.com', '2025-03-20T00:00:00Z'),
      ).rejects.toThrow();
    });

    it('should throw ConditionalCheckFailedException when filter does not exist', async () => {
      // ACT & ASSERT
      await expect(
        repository.updateFilter('nonexistent-id', VALID_UPDATE_REQUEST, 'editor@example.com', '2025-03-20T00:00:00Z'),
      ).rejects.toThrow();
    });

    it('should remove accountIds attribute when empty array is provided', async () => {
      // ARRANGE
      await dynamoDBDocumentClient.send(
        new PutCommand({ TableName: resourceFiltersTableName, Item: { ...SEED_FILTER } }),
      );
      const request: UpdateFilterRequest = {
        ...VALID_UPDATE_REQUEST,
        accountIds: [],
        tags: [{ key: 'Team', value: 'Security' }],
      };

      // ACT
      const result = await repository.updateFilter(FILTER_ID, request, 'editor@example.com', '2025-03-20T00:00:00Z');

      // ASSERT
      expect(result.accountIds).toEqual([]);

      const dbItem = await dynamoDBDocumentClient.send(
        new GetCommand({ TableName: resourceFiltersTableName, Key: { filterId: FILTER_ID } }),
      );
      expect(dbItem.Item?.accountIds).toBeUndefined();
    });

    it('should remove organizationalUnits attribute when empty array is provided', async () => {
      // ARRANGE
      await dynamoDBDocumentClient.send(
        new PutCommand({ TableName: resourceFiltersTableName, Item: { ...SEED_FILTER } }),
      );
      const request: UpdateFilterRequest = {
        ...VALID_UPDATE_REQUEST,
        organizationalUnits: [],
      };

      // ACT
      const result = await repository.updateFilter(FILTER_ID, request, 'editor@example.com', '2025-03-20T00:00:00Z');

      // ASSERT
      expect(result.organizationalUnits).toEqual([]);
    });

    it('should remove arnPatterns attribute when empty array is provided', async () => {
      // ARRANGE
      await dynamoDBDocumentClient.send(
        new PutCommand({ TableName: resourceFiltersTableName, Item: { ...SEED_FILTER } }),
      );
      const request: UpdateFilterRequest = {
        ...VALID_UPDATE_REQUEST,
        arnPatterns: [],
      };

      // ACT
      const result = await repository.updateFilter(FILTER_ID, request, 'editor@example.com', '2025-03-20T00:00:00Z');

      // ASSERT
      expect(result.arnPatterns).toEqual([]);
    });

    it('should remove all Set attributes when all arrays are empty (tags-only filter)', async () => {
      // ARRANGE
      await dynamoDBDocumentClient.send(
        new PutCommand({ TableName: resourceFiltersTableName, Item: { ...SEED_FILTER } }),
      );
      const request: UpdateFilterRequest = {
        name: 'Tags Only',
        accountIds: [],
        organizationalUnits: [],
        tags: [{ key: 'Team', value: 'Security' }],
        arnPatterns: [],
        version: 1,
      };

      // ACT
      const result = await repository.updateFilter(FILTER_ID, request, 'editor@example.com', '2025-03-20T00:00:00Z');

      // ASSERT
      expect(result.accountIds).toEqual([]);
      expect(result.organizationalUnits).toEqual([]);
      expect(result.arnPatterns).toEqual([]);
      expect(result.tags).toEqual([{ key: 'Team', value: 'Security' }]);
      expect(result.name).toBe('Tags Only');
    });

    it('should replace tags with full replacement on update', async () => {
      // ARRANGE
      await dynamoDBDocumentClient.send(
        new PutCommand({ TableName: resourceFiltersTableName, Item: { ...SEED_FILTER } }),
      );
      const request: UpdateFilterRequest = {
        ...VALID_UPDATE_REQUEST,
        tags: [
          { key: 'NewKey1', value: 'NewVal1' },
          { key: 'NewKey2', value: 'NewVal2' },
        ],
      };

      // ACT
      const result = await repository.updateFilter(FILTER_ID, request, 'editor@example.com', '2025-03-20T00:00:00Z');

      // ASSERT
      expect(result.tags).toEqual([
        { key: 'NewKey1', value: 'NewVal1' },
        { key: 'NewKey2', value: 'NewVal2' },
      ]);
    });

    it('should set tags to empty array when no tags provided', async () => {
      // ARRANGE
      await dynamoDBDocumentClient.send(
        new PutCommand({ TableName: resourceFiltersTableName, Item: { ...SEED_FILTER } }),
      );
      const request: UpdateFilterRequest = {
        ...VALID_UPDATE_REQUEST,
        tags: [],
      };

      // ACT
      const result = await repository.updateFilter(FILTER_ID, request, 'editor@example.com', '2025-03-20T00:00:00Z');

      // ASSERT
      expect(result.tags).toEqual([]);
    });

    it('should preserve createdAt and createdBy from original item', async () => {
      // ARRANGE
      await dynamoDBDocumentClient.send(
        new PutCommand({ TableName: resourceFiltersTableName, Item: { ...SEED_FILTER } }),
      );

      // ACT
      const result = await repository.updateFilter(
        FILTER_ID,
        VALID_UPDATE_REQUEST,
        'different-user@example.com',
        '2025-06-15T12:00:00Z',
      );

      // ASSERT
      expect(result.createdAt).toBe('2024-01-01T00:00:00Z');
      expect(result.createdBy).toBe('admin@example.com');
      expect(result.modifiedBy).toBe('different-user@example.com');
      expect(result.lastModified).toBe('2025-06-15T12:00:00Z');
    });

    it('should support successive updates with incrementing versions', async () => {
      // ARRANGE
      await dynamoDBDocumentClient.send(
        new PutCommand({ TableName: resourceFiltersTableName, Item: { ...SEED_FILTER } }),
      );

      // ACT
      const firstUpdate = await repository.updateFilter(
        FILTER_ID,
        { ...VALID_UPDATE_REQUEST, name: 'First Update', version: 1 },
        'user1@example.com',
        '2025-01-01T00:00:00Z',
      );
      const secondUpdate = await repository.updateFilter(
        FILTER_ID,
        { ...VALID_UPDATE_REQUEST, name: 'Second Update', version: 2 },
        'user2@example.com',
        '2025-02-01T00:00:00Z',
      );

      // ASSERT
      expect(firstUpdate.version).toBe(2);
      expect(firstUpdate.name).toBe('First Update');
      expect(secondUpdate.version).toBe(3);
      expect(secondUpdate.name).toBe('Second Update');
      expect(secondUpdate.modifiedBy).toBe('user2@example.com');
    });
  });

  describe('createFilter', () => {
    it('should create a filter with all fields and persist to DynamoDB', async () => {
      // ACT
      const result = await repository.createFilter(
        FILTER_ID,
        VALID_CREATE_REQUEST,
        'admin@example.com',
        '2025-01-01T00:00:00Z',
      );

      // ASSERT
      expect(result.filterId).toBe(FILTER_ID);
      expect(result.name).toBe('New Filter');
      expect(result.accountIds.sort()).toEqual(['111111111111', '222222222222']);
      expect(result.organizationalUnits).toEqual(['ou-abcd-12345678']);
      expect(result.tags).toEqual([{ key: 'Environment', value: 'Production' }]);
      expect(result.arnPatterns).toEqual(['arn:aws:s3:::prod-*']);
      expect(result.version).toBe(1);
      expect(result.createdAt).toBe('2025-01-01T00:00:00Z');
      expect(result.createdBy).toBe('admin@example.com');
      expect(result.lastModified).toBe('2025-01-01T00:00:00Z');
      expect(result.modifiedBy).toBe('admin@example.com');

      const dbItem = await dynamoDBDocumentClient.send(
        new GetCommand({ TableName: resourceFiltersTableName, Key: { filterId: FILTER_ID } }),
      );
      expect(dbItem.Item?.filterId).toBe(FILTER_ID);
      expect(dbItem.Item?.name).toBe('New Filter');
      expect(dbItem.Item?.version).toBe(1);
    });

    it('should omit empty Set fields from DynamoDB item', async () => {
      // ARRANGE
      const request: CreateFilterRequest = {
        ...VALID_CREATE_REQUEST,
        accountIds: [],
        organizationalUnits: [],
        arnPatterns: [],
        tags: [{ key: 'Team', value: 'Security' }],
      };

      // ACT
      const result = await repository.createFilter(FILTER_ID, request, 'admin@example.com', '2025-01-01T00:00:00Z');

      // ASSERT
      expect(result.accountIds).toEqual([]);
      expect(result.organizationalUnits).toEqual([]);
      expect(result.arnPatterns).toEqual([]);
      expect(result.tags).toEqual([{ key: 'Team', value: 'Security' }]);

      const dbItem = await dynamoDBDocumentClient.send(
        new GetCommand({ TableName: resourceFiltersTableName, Key: { filterId: FILTER_ID } }),
      );
      expect(dbItem.Item?.accountIds).toBeUndefined();
      expect(dbItem.Item?.organizationalUnits).toBeUndefined();
      expect(dbItem.Item?.arnPatterns).toBeUndefined();
    });

    it('should create a filter with only accountIds', async () => {
      // ARRANGE
      const request: CreateFilterRequest = {
        ...VALID_CREATE_REQUEST,
        organizationalUnits: [],
        tags: [],
        arnPatterns: [],
      };

      // ACT
      const result = await repository.createFilter(FILTER_ID, request, 'admin@example.com', '2025-01-01T00:00:00Z');

      // ASSERT
      expect(result.accountIds.sort()).toEqual(['111111111111', '222222222222']);
      expect(result.organizationalUnits).toEqual([]);
      expect(result.tags).toEqual([]);
      expect(result.arnPatterns).toEqual([]);
    });

    it('should create a filter with only arnPatterns', async () => {
      // ARRANGE
      const request: CreateFilterRequest = {
        ...VALID_CREATE_REQUEST,
        accountIds: [],
        organizationalUnits: [],
        tags: [],
        arnPatterns: ['arn:aws:ec2:us-east-1:*:instance/*', 'arn:aws:s3:::*'],
      };

      // ACT
      const result = await repository.createFilter(FILTER_ID, request, 'admin@example.com', '2025-01-01T00:00:00Z');

      // ASSERT
      expect(result.accountIds).toEqual([]);
      expect(result.arnPatterns.sort()).toEqual(['arn:aws:ec2:us-east-1:*:instance/*', 'arn:aws:s3:::*']);
    });

    it('should reject duplicate filterId via ConditionExpression', async () => {
      // ARRANGE
      await repository.createFilter(FILTER_ID, VALID_CREATE_REQUEST, 'admin@example.com', '2025-01-01T00:00:00Z');

      // ACT & ASSERT
      await expect(
        repository.createFilter(
          FILTER_ID,
          { ...VALID_CREATE_REQUEST, name: 'Duplicate' },
          'admin@example.com',
          '2025-02-01T00:00:00Z',
        ),
      ).rejects.toThrow(ConditionalCheckFailedException);
    });

    it('should set lastModified and modifiedBy equal to createdAt and createdBy', async () => {
      // ACT
      const result = await repository.createFilter(
        FILTER_ID,
        VALID_CREATE_REQUEST,
        'creator@example.com',
        '2025-06-15T12:00:00Z',
      );

      // ASSERT
      expect(result.createdAt).toBe(result.lastModified);
      expect(result.createdBy).toBe(result.modifiedBy);
      expect(result.createdBy).toBe('creator@example.com');
    });

    it('should be retrievable via findAll and findByName after creation', async () => {
      // ARRANGE
      await repository.createFilter(FILTER_ID, VALID_CREATE_REQUEST, 'admin@example.com', '2025-01-01T00:00:00Z');

      // ACT
      const allFilters = await repository.findAll();
      const byName = await repository.findByName('New Filter');

      // ASSERT
      expect(allFilters).toHaveLength(1);
      expect(allFilters[0].filterId).toBe(FILTER_ID);
      expect(byName).toHaveLength(1);
      expect(byName[0].filterId).toBe(FILTER_ID);
    });
  });

  describe('deleteFilter', () => {
    it('should remove an existing filter from DynamoDB', async () => {
      // ARRANGE
      await dynamoDBDocumentClient.send(
        new PutCommand({ TableName: resourceFiltersTableName, Item: { ...SEED_FILTER } }),
      );

      // ACT
      await repository.deleteFilter(FILTER_ID);

      // ASSERT
      const dbItem = await dynamoDBDocumentClient.send(
        new GetCommand({ TableName: resourceFiltersTableName, Key: { filterId: FILTER_ID } }),
      );
      expect(dbItem.Item).toBeUndefined();
    });

    it('should not throw when deleting a non-existent filter', async () => {
      // ACT & ASSERT
      await expect(repository.deleteFilter('non-existent-filter-id')).resolves.not.toThrow();
    });

    it('should return void on successful deletion', async () => {
      // ARRANGE
      await dynamoDBDocumentClient.send(
        new PutCommand({ TableName: resourceFiltersTableName, Item: { ...SEED_FILTER } }),
      );

      // ACT
      const result = await repository.deleteFilter(FILTER_ID);

      // ASSERT
      expect(result).toBeUndefined();
    });

    it('should not affect other filters in the table', async () => {
      // ARRANGE
      const otherFilterId = '550e8400-e29b-41d4-a716-446655440099';
      await dynamoDBDocumentClient.send(
        new PutCommand({ TableName: resourceFiltersTableName, Item: { ...SEED_FILTER } }),
      );
      await dynamoDBDocumentClient.send(
        new PutCommand({
          TableName: resourceFiltersTableName,
          Item: { ...SEED_FILTER, filterId: otherFilterId, name: 'Other Filter' },
        }),
      );

      // ACT
      await repository.deleteFilter(FILTER_ID);

      // ASSERT
      const scanResult = await dynamoDBDocumentClient.send(new ScanCommand({ TableName: resourceFiltersTableName }));
      expect(scanResult.Items).toHaveLength(1);
      expect(scanResult.Items![0].filterId).toBe(otherFilterId);
    });

    it('should make the filter unretrievable via findAll after deletion', async () => {
      // ARRANGE
      await repository.createFilter(FILTER_ID, VALID_CREATE_REQUEST, 'admin@example.com', '2025-01-01T00:00:00Z');

      // ACT
      await repository.deleteFilter(FILTER_ID);

      // ASSERT
      const allFilters = await repository.findAll();
      expect(allFilters).toEqual([]);
    });

    it('should make the filter unretrievable via findByName after deletion', async () => {
      // ARRANGE
      await repository.createFilter(FILTER_ID, VALID_CREATE_REQUEST, 'admin@example.com', '2025-01-01T00:00:00Z');

      // ACT
      await repository.deleteFilter(FILTER_ID);

      // ASSERT
      const byName = await repository.findByName(VALID_CREATE_REQUEST.name);
      expect(byName).toEqual([]);
    });

    it('should allow re-creation of a filter with the same id after deletion', async () => {
      // ARRANGE
      await repository.createFilter(FILTER_ID, VALID_CREATE_REQUEST, 'admin@example.com', '2025-01-01T00:00:00Z');
      await repository.deleteFilter(FILTER_ID);

      // ACT
      const recreated = await repository.createFilter(
        FILTER_ID,
        { ...VALID_CREATE_REQUEST, name: 'Recreated Filter' },
        'admin@example.com',
        '2025-06-01T00:00:00Z',
      );

      // ASSERT
      expect(recreated.filterId).toBe(FILTER_ID);
      expect(recreated.name).toBe('Recreated Filter');
      expect(recreated.version).toBe(1);
    });
  });

  describe('batchFindByIds', () => {
    it('should return an empty list when no filter IDs provided', async () => {
      // ACT
      const result = await repository.batchFindByIds([]);

      // ASSERT
      expect(result).toEqual([]);
    });

    it('should return an empty list when filter IDs do not exist', async () => {
      // ACT
      const result = await repository.batchFindByIds(['non-existent-1', 'non-existent-2']);

      // ASSERT — missing IDs are silently omitted by BatchGetItem; callers detect deletion via the
      // absent filters by comparing the returned set against the requested IDs.
      expect(result).toEqual([]);
    });

    it('should return matching filters for valid IDs', async () => {
      // ARRANGE
      const filterId1 = '550e8400-e29b-41d4-a716-446655440001';
      const filterId2 = '550e8400-e29b-41d4-a716-446655440002';
      await dynamoDBDocumentClient.send(
        new PutCommand({
          TableName: resourceFiltersTableName,
          Item: { filterId: filterId1, name: 'Filter 1', version: 1 },
        }),
      );
      await dynamoDBDocumentClient.send(
        new PutCommand({
          TableName: resourceFiltersTableName,
          Item: { filterId: filterId2, name: 'Filter 2', version: 1 },
        }),
      );

      // ACT
      const result = await repository.batchFindByIds([filterId1, filterId2]);

      // ASSERT
      expect(result).toHaveLength(2);
      const filterIds = result.map((f) => f.filterId);
      expect(filterIds).toContain(filterId1);
      expect(filterIds).toContain(filterId2);
    });

    it('should return only existing filters when some IDs do not exist', async () => {
      // ARRANGE
      const filterId1 = '550e8400-e29b-41d4-a716-446655440001';
      await dynamoDBDocumentClient.send(
        new PutCommand({
          TableName: resourceFiltersTableName,
          Item: { filterId: filterId1, name: 'Filter 1', version: 1 },
        }),
      );

      // ACT
      const result = await repository.batchFindByIds([filterId1, 'non-existent-filter']);

      // ASSERT — a deleted filter yields a smaller set; the caller compares the returned filters
      // against the requested IDs to decide whether to fail closed.
      expect(result).toHaveLength(1);
      expect(result[0].filterId).toBe(filterId1);
    });

    it('should return filters with all DynamoDB item properties', async () => {
      // ARRANGE
      const filterId = '550e8400-e29b-41d4-a716-446655440001';
      await dynamoDBDocumentClient.send(
        new PutCommand({
          TableName: resourceFiltersTableName,
          Item: {
            filterId,
            name: 'Full Filter',
            accountIds: new Set(['111111111111']),
            organizationalUnits: new Set(['ou-abcd-12345678']),
            tags: [{ key: 'env', value: 'prod' }],
            arnPatterns: new Set(['arn:aws:s3:::bucket-*']),
            version: 1,
            createdAt: '2024-01-01T00:00:00Z',
            createdBy: 'admin',
            lastModified: '2024-01-01T00:00:00Z',
            modifiedBy: 'admin',
          },
        }),
      );

      // ACT
      const result = await repository.batchFindByIds([filterId]);

      // ASSERT
      expect(result).toHaveLength(1);
      expect(result[0].filterId).toBe(filterId);
      expect(result[0].name).toBe('Full Filter');
      expect(result[0].tags).toEqual([{ key: 'env', value: 'prod' }]);
    });
  });
});
