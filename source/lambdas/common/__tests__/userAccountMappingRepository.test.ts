// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { DynamoDBDocumentClient, GetCommand, PutCommand } from '@aws-sdk/lib-dynamodb';
import { UserAccountMapping } from '@asr/data-models';
import { UserAccountMappingRepository } from '../repositories/userAccountMappingRepository';
import { DynamoDBTestSetup } from './dynamodbSetup';
import { userAccountMappingTableName } from './envSetup';

export const createMockUserAccountMapping = (overrides: Partial<UserAccountMapping> = {}): UserAccountMapping => ({
  userId: 'user@example.com',
  accountIds: ['123456789012', '987654321098'],
  invitedBy: 'admin@example.com',
  invitationTimestamp: '2023-01-01T00:00:00Z',
  lastModifiedBy: 'modifier@example.com',
  lastModifiedTimestamp: '2023-01-01T00:00:00Z',
  ...overrides,
});

describe('UserAccountMappingRepository', () => {
  const principal = 'test-user@example.com';
  let dynamoDBDocumentClient: DynamoDBDocumentClient;
  let repository: UserAccountMappingRepository;

  beforeAll(async () => {
    await DynamoDBTestSetup.initialize();
    dynamoDBDocumentClient = DynamoDBTestSetup.getDocClient();
    await DynamoDBTestSetup.createUserAccountMappingTable(userAccountMappingTableName);
  });

  afterAll(async () => {
    await DynamoDBTestSetup.deleteTable(userAccountMappingTableName);
  });

  beforeEach(async () => {
    await DynamoDBTestSetup.clearTable(userAccountMappingTableName, 'userAccountMapping');
    repository = new UserAccountMappingRepository(principal, userAccountMappingTableName, dynamoDBDocumentClient);
  });

  describe('getUserAccounts', () => {
    it('should return account IDs for existing user', async () => {
      // ARRANGE
      const mapping = createMockUserAccountMapping({ userId: 'existing-user@example.com' });
      await dynamoDBDocumentClient.send(
        new PutCommand({
          TableName: userAccountMappingTableName,
          Item: mapping,
        }),
      );

      // ACT
      const result = await repository.getUserAccounts('existing-user@example.com');

      // ASSERT
      expect(result).toEqual(['123456789012', '987654321098']);
    });

    it('should return undefined for non-existent user', async () => {
      // ACT
      const result = await repository.getUserAccounts('non-existent@example.com');

      // ASSERT
      expect(result).toBeUndefined();
    });

    it('should handle user with single account ID', async () => {
      // ARRANGE
      const mapping = createMockUserAccountMapping({
        userId: 'single-account@example.com',
        accountIds: ['123456789012'],
      });
      await dynamoDBDocumentClient.send(
        new PutCommand({
          TableName: userAccountMappingTableName,
          Item: mapping,
        }),
      );

      // ACT
      const result = await repository.getUserAccounts('single-account@example.com');

      // ASSERT
      expect(result).toEqual(['123456789012']);
    });

    it('should handle user with empty account IDs array', async () => {
      // ARRANGE
      const mapping = createMockUserAccountMapping({
        userId: 'empty-accounts@example.com',
        accountIds: [],
      });
      await dynamoDBDocumentClient.send(
        new PutCommand({
          TableName: userAccountMappingTableName,
          Item: mapping,
        }),
      );

      // ACT
      const result = await repository.getUserAccounts('empty-accounts@example.com');

      // ASSERT
      expect(result).toEqual([]);
    });
  });

  describe('findById', () => {
    it('should return user mapping for existing user', async () => {
      // ARRANGE
      const mapping = createMockUserAccountMapping({ userId: 'find-test@example.com' });
      await dynamoDBDocumentClient.send(
        new PutCommand({
          TableName: userAccountMappingTableName,
          Item: mapping,
        }),
      );

      // ACT
      const result = await repository.findById('find-test@example.com', '');

      // ASSERT
      expect(result).toBeDefined();
      expect(result?.userId).toBe('find-test@example.com');
      expect(result?.accountIds).toEqual(['123456789012', '987654321098']);
      expect((result as any).lastUpdatedBy).toBeUndefined();
    });

    it('should return undefined for non-existent user', async () => {
      // ACT
      const result = await repository.findById('non-existent@example.com', '');

      // ASSERT
      expect(result).toBeUndefined();
    });

    it('should remove lastUpdatedBy field from result', async () => {
      // ARRANGE
      const mapping = createMockUserAccountMapping({ userId: 'audit-test@example.com' });
      await dynamoDBDocumentClient.send(
        new PutCommand({
          TableName: userAccountMappingTableName,
          Item: { ...mapping, lastUpdatedBy: 'test-principal' },
        }),
      );

      // ACT
      const result = await repository.findById('audit-test@example.com', '');

      // ASSERT
      expect(result).toBeDefined();
      expect((result as any).lastUpdatedBy).toBeUndefined();
    });

    it('should ignore sort key parameter', async () => {
      // ARRANGE
      const mapping = createMockUserAccountMapping({ userId: 'sort-key-test@example.com' });
      await dynamoDBDocumentClient.send(
        new PutCommand({
          TableName: userAccountMappingTableName,
          Item: mapping,
        }),
      );

      // ACT
      const result = await repository.findById('sort-key-test@example.com', 'ignored-sort-key');

      // ASSERT
      expect(result).toBeDefined();
      expect(result?.userId).toBe('sort-key-test@example.com');
    });
  });

  describe('put operations', () => {
    it('should create new user mapping successfully', async () => {
      // ARRANGE
      const mapping = createMockUserAccountMapping({ userId: 'create-test@example.com' });

      // ACT
      await repository.put(mapping);

      // ASSERT
      const result = await dynamoDBDocumentClient.send(
        new GetCommand({
          TableName: userAccountMappingTableName,
          Key: { userId: 'create-test@example.com' },
        }),
      );
      expect(result.Item).toBeDefined();
      expect(result.Item?.userId).toBe('create-test@example.com');
      expect(result.Item?.accountIds).toEqual(['123456789012', '987654321098']);
      expect(result.Item?.lastUpdatedBy).toBe(principal);
    });

    it('should set lastModifiedBy and lastModifiedTimestamp when putting item', async () => {
      // ARRANGE
      const mapping = createMockUserAccountMapping({ userId: 'put-audit-test@example.com' });
      const beforeTimestamp = new Date().toISOString();

      // ACT
      await repository.put(mapping);

      // ASSERT
      const result = await dynamoDBDocumentClient.send(
        new GetCommand({
          TableName: userAccountMappingTableName,
          Key: { userId: 'put-audit-test@example.com' },
        }),
      );
      expect(result.Item?.lastModifiedBy).toBe(principal);
      expect(result.Item?.lastModifiedTimestamp).toBeDefined();
      expect(new Date(result.Item?.lastModifiedTimestamp).getTime()).toBeGreaterThanOrEqual(
        new Date(beforeTimestamp).getTime(),
      );
    });

    it('should override existing lastModifiedBy and lastModifiedTimestamp', async () => {
      // ARRANGE
      const mapping = createMockUserAccountMapping({
        userId: 'override-audit-test@example.com',
        lastModifiedBy: 'old-user@example.com',
        lastModifiedTimestamp: '2020-01-01T00:00:00Z',
      });
      const beforeTimestamp = new Date().toISOString();

      // ACT
      await repository.put(mapping);

      // ASSERT
      const result = await dynamoDBDocumentClient.send(
        new GetCommand({
          TableName: userAccountMappingTableName,
          Key: { userId: 'override-audit-test@example.com' },
        }),
      );
      expect(result.Item?.lastModifiedBy).toBe(principal);
      expect(result.Item?.lastModifiedTimestamp).not.toBe('2020-01-01T00:00:00Z');
      expect(new Date(result.Item?.lastModifiedTimestamp).getTime()).toBeGreaterThanOrEqual(
        new Date(beforeTimestamp).getTime(),
      );
    });

    it('should update existing user mapping', async () => {
      // ARRANGE
      const mapping = createMockUserAccountMapping({ userId: 'update-test@example.com' });
      await dynamoDBDocumentClient.send(
        new PutCommand({
          TableName: userAccountMappingTableName,
          Item: mapping,
        }),
      );

      const updatedMapping = {
        ...mapping,
        accountIds: ['111111111111', '222222222222'],
        lastModifiedBy: 'new-modifier@example.com',
      };

      // ACT
      await repository.put(updatedMapping);

      // ASSERT
      const result = await repository.findById('update-test@example.com', '');
      expect(result?.accountIds).toEqual(['111111111111', '222222222222']);
      expect(result?.lastModifiedBy).toBe(principal);
    });

    it('should handle mapping with optional fields missing', async () => {
      // ARRANGE
      const mapping: UserAccountMapping = {
        userId: 'minimal-test@example.com',
        accountIds: ['123456789012'],
        invitedBy: 'admin@example.com',
        invitationTimestamp: '2023-01-01T00:00:00Z',
      };

      // ACT
      await repository.put(mapping);

      // ASSERT
      const result = await repository.findById('minimal-test@example.com', '');
      expect(result).toBeDefined();
      expect(result?.userId).toBe('minimal-test@example.com');
      expect(result?.lastModifiedBy).toBe(principal);
      expect(result?.lastModifiedTimestamp).toBeDefined();
    });
  });

  describe('delete', () => {
    it('should delete existing user mapping successfully', async () => {
      // ARRANGE
      const mapping = createMockUserAccountMapping({ userId: 'delete-test@example.com' });
      await dynamoDBDocumentClient.send(
        new PutCommand({
          TableName: userAccountMappingTableName,
          Item: mapping,
        }),
      );

      // ACT
      await repository.deleteIfExists('delete-test@example.com', '');

      // ASSERT
      const result = await dynamoDBDocumentClient.send(
        new GetCommand({
          TableName: userAccountMappingTableName,
          Key: { userId: 'delete-test@example.com' },
        }),
      );
      expect(result.Item).toBeUndefined();
    });

    it('should handle deletion of non-existent user gracefully', async () => {
      // ACT & ASSERT
      await expect(repository.deleteIfExists('non-existent@example.com', '')).resolves.not.toThrow();
    });

    it('should ignore sort key parameter', async () => {
      // ARRANGE
      const mapping = createMockUserAccountMapping({ userId: 'sort-key-delete@example.com' });
      await dynamoDBDocumentClient.send(
        new PutCommand({
          TableName: userAccountMappingTableName,
          Item: mapping,
        }),
      );

      // ACT
      await repository.deleteIfExists('sort-key-delete@example.com', 'ignored-sort-key');

      // ASSERT
      const result = await dynamoDBDocumentClient.send(
        new GetCommand({
          TableName: userAccountMappingTableName,
          Key: { userId: 'sort-key-delete@example.com' },
        }),
      );
      expect(result.Item).toBeUndefined();
    });

    it('should handle user ID with special characters', async () => {
      // ARRANGE
      const specialUserId = 'special+chars.delete@example-domain.com';
      const mapping = createMockUserAccountMapping({ userId: specialUserId });
      await dynamoDBDocumentClient.send(
        new PutCommand({
          TableName: userAccountMappingTableName,
          Item: mapping,
        }),
      );

      // ACT
      await repository.deleteIfExists(specialUserId, '');

      // ASSERT
      const result = await dynamoDBDocumentClient.send(
        new GetCommand({
          TableName: userAccountMappingTableName,
          Key: { userId: specialUserId },
        }),
      );
      expect(result.Item).toBeUndefined();
    });
  });

  describe('edge cases', () => {
    it('should handle user ID with special characters', async () => {
      // ARRANGE
      const mapping = createMockUserAccountMapping({
        userId: 'special+chars.test@example-domain.com',
      });
      await dynamoDBDocumentClient.send(
        new PutCommand({
          TableName: userAccountMappingTableName,
          Item: mapping,
        }),
      );

      // ACT
      const result = await repository.findById('special+chars.test@example-domain.com', '');

      // ASSERT
      expect(result?.userId).toBe('special+chars.test@example-domain.com');
    });

    it('should handle large number of account IDs', async () => {
      // ARRANGE
      const largeAccountIds = Array.from({ length: 100 }, (_, i) => String(123456789012 + i).padStart(12, '0'));
      const mapping = createMockUserAccountMapping({
        userId: 'large-accounts@example.com',
        accountIds: largeAccountIds,
      });
      await dynamoDBDocumentClient.send(
        new PutCommand({
          TableName: userAccountMappingTableName,
          Item: mapping,
        }),
      );

      // ACT
      const result = await repository.getUserAccounts('large-accounts@example.com');

      // ASSERT
      expect(result).toHaveLength(100);
      expect(result).toEqual(largeAccountIds);
    });

    it('should handle very long email addresses', async () => {
      // ARRANGE
      const longEmail = `${'a'.repeat(50)}@${'b'.repeat(50)}.com`;
      const mapping = createMockUserAccountMapping({
        userId: longEmail,
      });
      await dynamoDBDocumentClient.send(
        new PutCommand({
          TableName: userAccountMappingTableName,
          Item: mapping,
        }),
      );

      // ACT
      const result = await repository.findById(longEmail, '');

      // ASSERT
      expect(result?.userId).toBe(longEmail);
    });

    it('should handle timestamps with different formats', async () => {
      // ARRANGE
      const mapping = createMockUserAccountMapping({
        userId: 'timestamp-test@example.com',
        invitationTimestamp: '2023-12-31T23:59:59.999Z',
        lastModifiedTimestamp: '2024-01-01T00:00:00.000Z',
      });
      await dynamoDBDocumentClient.send(
        new PutCommand({
          TableName: userAccountMappingTableName,
          Item: mapping,
        }),
      );

      // ACT
      const result = await repository.findById('timestamp-test@example.com', '');

      // ASSERT
      expect(result?.invitationTimestamp).toBe('2023-12-31T23:59:59.999Z');
      expect(result?.lastModifiedTimestamp).toBe('2024-01-01T00:00:00.000Z');
    });
  });
});
