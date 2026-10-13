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

  describe('per-user MCP tool grants', () => {
    it('put then get round-trips the grant without overwriting account IDs', async () => {
      await repository.create(createMockUserAccountMapping());
      await repository.putUserAllowedMcpTools('user@example.com', ['list_*', 'deploy_runbook']);

      const tools = await repository.findUserAllowedMcpTools('user@example.com');
      expect(tools).toEqual(['list_*', 'deploy_runbook']);
      expect(await repository.getUserAccounts('user@example.com')).toEqual(['123456789012', '987654321098']);
    });

    it('returns undefined when the user has no mapping record', async () => {
      expect(await repository.findUserAllowedMcpTools('missing@example.com')).toBeUndefined();
    });

    it('fails closed to no tools when a pre-upgrade record has no grant field', async () => {
      await repository.create(createMockUserAccountMapping());

      expect(await repository.findUserAllowedMcpTools('user@example.com')).toEqual([]);
    });

    it('fails closed to no tools for a malformed grant', async () => {
      await dynamoDBDocumentClient.send(
        new PutCommand({
          TableName: userAccountMappingTableName,
          Item: { ...createMockUserAccountMapping(), allowedMcpTools: 'deploy_runbook' },
        }),
      );

      expect(await repository.findUserAllowedMcpTools('user@example.com')).toEqual([]);
    });

    it('put replaces an existing grant and permits an empty revoke', async () => {
      await repository.putUserAllowedMcpTools('user@example.com', ['list_*']);
      await repository.putUserAllowedMcpTools('user@example.com', []);

      expect(await repository.findUserAllowedMcpTools('user@example.com')).toEqual([]);
    });

    it('batch-loads account assignments and grants while omitting missing users', async () => {
      await repository.create(createMockUserAccountMapping());
      await repository.putUserAllowedMcpTools('user@example.com', ['list_*']);

      const authorizations = await repository.findUserAuthorizations(['USER@example.com', 'missing@example.com']);

      expect(authorizations.get('user@example.com')).toEqual({
        accountIds: ['123456789012', '987654321098'],
        allowedMcpTools: ['list_*'],
      });
      expect(authorizations.has('missing@example.com')).toBe(false);
    });
  });

  // Records written before the userId key was normalized to lowercase are still
  // keyed by their original case. The read paths must fall back to that key so a
  // pre-existing user is not silently unreachable, and re-key opportunistically
  // so the record converges to lowercase.
  describe('mixed-case record fallback and re-keying', () => {
    const MIXED_CASE_USER_ID = 'Mixed.Case@Example.com';
    const LOWERCASE_USER_ID = 'mixed.case@example.com';

    async function putRawMixedCaseRecord(): Promise<void> {
      // Written directly, bypassing the repository, so the stored key keeps its
      // original case — the pre-normalization state this fallback exists for.
      await dynamoDBDocumentClient.send(
        new PutCommand({
          TableName: userAccountMappingTableName,
          Item: createMockUserAccountMapping({ userId: MIXED_CASE_USER_ID, allowedMcpTools: ['list_*'] }),
        }),
      );
    }

    async function readRawItem(userId: string): Promise<Record<string, unknown> | undefined> {
      const response = await dynamoDBDocumentClient.send(
        new GetCommand({ TableName: userAccountMappingTableName, Key: { userId } }),
      );
      return response.Item;
    }

    it('findUserAuthorization falls back to the original-case key and re-keys it to lowercase', async () => {
      await putRawMixedCaseRecord();

      const authorization = await repository.findUserAuthorization(MIXED_CASE_USER_ID);

      expect(authorization).toEqual({
        accountIds: ['123456789012', '987654321098'],
        allowedMcpTools: ['list_*'],
      });
      // Opportunistic re-key: the record now lives under the lowercase key, and
      // the original-case record is gone, so the next read hits directly.
      expect(await readRawItem(LOWERCASE_USER_ID)).toMatchObject({ userId: LOWERCASE_USER_ID });
      expect(await readRawItem(MIXED_CASE_USER_ID)).toBeUndefined();
    });

    it('findUserAuthorization returns undefined when no record exists in either case', async () => {
      expect(await repository.findUserAuthorization('never.seen@example.com')).toBeUndefined();
    });

    it('putUserAllowedMcpTools updates the single record instead of splitting it in two', async () => {
      // GIVEN a pre-normalization record holding this user's account assignments
      await putRawMixedCaseRecord();

      // WHEN a grant is written using the mixed-case id, as the API path does
      await repository.putUserAllowedMcpTools(MIXED_CASE_USER_ID, ['execute_runbook']);

      // THEN there is exactly one record, carrying BOTH the new grant and the
      // original accounts. A blind lowercase upsert used to create a second,
      // partial item with only the grant — and because reads try the lowercase
      // key first, the user silently lost every assigned account.
      expect(await readRawItem(MIXED_CASE_USER_ID)).toBeUndefined();
      expect(await readRawItem(LOWERCASE_USER_ID)).toMatchObject({
        userId: LOWERCASE_USER_ID,
        allowedMcpTools: ['execute_runbook'],
        accountIds: ['123456789012', '987654321098'],
      });
      expect(await repository.findUserAuthorization(MIXED_CASE_USER_ID)).toEqual({
        accountIds: ['123456789012', '987654321098'],
        allowedMcpTools: ['execute_runbook'],
      });
    });

    it('putUserAllowedMcpTools writes to the original-case key when re-keying fails, not a partial lowercase item', async () => {
      // GIVEN a mixed-case record whose re-key to lowercase cannot complete: make
      // the lowercase PUT (the first write reKeyToLowercase issues) fail. The
      // record therefore stays under its original case, carrying accountIds.
      await putRawMixedCaseRecord();
      const sendSpy = jest.spyOn(dynamoDBDocumentClient, 'send');
      const originalSend = sendSpy.getMockImplementation() ?? DynamoDBDocumentClient.prototype.send;
      sendSpy.mockImplementation((command: unknown) => {
        const isReKeyPut =
          command instanceof PutCommand && (command.input.Item as { userId?: string })?.userId === LOWERCASE_USER_ID;
        if (isReKeyPut) return Promise.reject(new Error('simulated re-key write failure'));
        return (originalSend as (c: unknown) => Promise<unknown>).call(dynamoDBDocumentClient, command);
      });

      try {
        // WHEN a grant is written using the mixed-case id
        await repository.putUserAllowedMcpTools(MIXED_CASE_USER_ID, ['execute_runbook']);
      } finally {
        sendSpy.mockRestore();
      }

      // THEN the update landed on the ORIGINAL-case record — the one the item
      // still lives under — so accountIds are preserved and no partial lowercase
      // duplicate was created. A blind lowercase write would have upserted a
      // second item holding only allowedMcpTools.
      expect(await readRawItem(LOWERCASE_USER_ID)).toBeUndefined();
      expect(await readRawItem(MIXED_CASE_USER_ID)).toMatchObject({
        userId: MIXED_CASE_USER_ID,
        allowedMcpTools: ['execute_runbook'],
        accountIds: ['123456789012', '987654321098'],
      });
    });

    it('setUserAccounts updates the single migrated record rather than a stale duplicate', async () => {
      // GIVEN a pre-normalization record. This mirrors the API's
      // updateAccountOperatorUser path, which used to read/write the verbatim
      // mixed-case id while authorization read the lowercase one — so a revoke
      // landed on a stale duplicate and the old accounts survived.
      await putRawMixedCaseRecord();

      // WHEN accounts are set using the mixed-case id
      await repository.setUserAccounts(MIXED_CASE_USER_ID, ['555555555555'], 'admin@example.com');

      // THEN exactly one record remains, lowercase, carrying the new accounts and
      // preserving the existing grant — authorization now reads what was written.
      expect(await readRawItem(MIXED_CASE_USER_ID)).toBeUndefined();
      expect(await readRawItem(LOWERCASE_USER_ID)).toMatchObject({
        userId: LOWERCASE_USER_ID,
        accountIds: ['555555555555'],
        allowedMcpTools: ['list_*'],
      });
      expect(await repository.findUserAuthorization(MIXED_CASE_USER_ID)).toEqual({
        accountIds: ['555555555555'],
        allowedMcpTools: ['list_*'],
      });
    });

    it('deleteIfExists removes the record under either key case, so a re-invite cannot inherit a stale grant', async () => {
      // GIVEN a record that reads have already re-keyed to lowercase
      await putRawMixedCaseRecord();
      await repository.findUserAuthorization(MIXED_CASE_USER_ID);
      expect(await readRawItem(LOWERCASE_USER_ID)).toBeDefined();

      // WHEN deletion is driven by the verbatim mixed-case path id, as deleteUser does
      await repository.deleteIfExists(MIXED_CASE_USER_ID, '');

      // THEN neither key survives. Deleting only the supplied case left the
      // lowercase record — including allowedMcpTools — in place, so re-inviting
      // the same address restored a grant the administrator had removed.
      expect(await readRawItem(MIXED_CASE_USER_ID)).toBeUndefined();
      expect(await readRawItem(LOWERCASE_USER_ID)).toBeUndefined();
      expect(await repository.findUserAuthorization(MIXED_CASE_USER_ID)).toBeUndefined();
    });

    it('findUserAuthorizations recovers a mixed-case user the batch missed', async () => {
      await putRawMixedCaseRecord();

      const authorizations = await repository.findUserAuthorizations([MIXED_CASE_USER_ID]);

      expect(authorizations.get(LOWERCASE_USER_ID)).toEqual({
        accountIds: ['123456789012', '987654321098'],
        allowedMcpTools: ['list_*'],
      });
      // Recovering it also migrated it, so a subsequent batch finds it directly.
      expect(await readRawItem(MIXED_CASE_USER_ID)).toBeUndefined();
    });

    it('findUserAuthorizations issues no fallback read for an already-lowercase miss', async () => {
      // An all-lowercase pool must not pay for the fallback: a lowercase userId
      // that is simply absent has no original-case variant to retry.
      const authorizations = await repository.findUserAuthorizations(['absent@example.com']);

      expect(authorizations.has('absent@example.com')).toBe(false);
    });
  });
});
