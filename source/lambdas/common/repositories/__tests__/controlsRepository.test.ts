// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { DynamoDBDocumentClient, PutCommand, GetCommand, TransactWriteCommand } from '@aws-sdk/lib-dynamodb';
import type { ServiceInputTypes, ServiceOutputTypes } from '@aws-sdk/lib-dynamodb';
import type { Command, HttpHandlerOptions } from '@smithy/types';
import type { SmithyResolvedConfiguration } from '@smithy/smithy-client';
import { ControlsRepository } from '../controlsRepository';
import { DynamoDBTestSetup } from '../../__tests__/dynamodbSetup';
import { remediationConfigTableName } from '../../__tests__/envSetup';

describe('ControlsRepository', () => {
  let repository: ControlsRepository;
  let dynamoDBDocumentClient: DynamoDBDocumentClient;

  beforeAll(async () => {
    dynamoDBDocumentClient = DynamoDBTestSetup.getDocClient();
    await DynamoDBTestSetup.createConfigTable(remediationConfigTableName);
  });

  afterAll(async () => {
    await DynamoDBTestSetup.deleteTable(remediationConfigTableName);
  });

  beforeEach(async () => {
    await DynamoDBTestSetup.clearTable(remediationConfigTableName, 'config');
    repository = new ControlsRepository(remediationConfigTableName, dynamoDBDocumentClient);
  });

  describe('findAll', () => {
    it('should retrieve all controls successfully', async () => {
      // ARRANGE
      const controlItems = [
        {
          controlId: 'S3.1',
          description: 'S3 bucket should have server-side encryption enabled',
          automatedRemediationEnabled: true,
          filters: new Set(['filter-1', 'filter-2']),
          filterMode: 'include',
          version: 1,
          lastModified: '2024-01-01T00:00:00Z',
          modifiedBy: 'admin-user',
        },
        {
          controlId: 'EC2.6',
          description: 'VPC flow logging should be enabled',
          automatedRemediationEnabled: false,
          filters: new Set(['filter-3']),
          filterMode: 'exclude',
          version: 2,
          lastModified: '2024-01-02T00:00:00Z',
          modifiedBy: 'admin-user',
        },
      ];

      await Promise.all(
        controlItems.map((item) =>
          dynamoDBDocumentClient.send(
            new PutCommand({
              TableName: remediationConfigTableName,
              Item: item,
            }),
          ),
        ),
      );

      // ACT
      const result = await repository.findAll();

      // ASSERT
      expect(result).toHaveLength(2);
      const controlIds = result.map((c) => c.controlId);
      expect(controlIds).toContain('S3.1');
      expect(controlIds).toContain('EC2.6');
    });

    it('should return empty array when table is empty', async () => {
      // ACT
      const result = await repository.findAll();

      // ASSERT
      expect(result).toEqual([]);
      expect(result).toHaveLength(0);
    });

    it('should transform filters from Set to Array', async () => {
      // ARRANGE
      const controlItem = {
        controlId: 'CloudTrail.4',
        description: 'CloudTrail log file validation should be enabled',
        automatedRemediationEnabled: true,
        filters: new Set(['filter-a', 'filter-b', 'filter-c']),
        filterMode: 'include',
        version: 3,
        lastModified: '2024-01-03T00:00:00Z',
        modifiedBy: 'system',
      };

      await dynamoDBDocumentClient.send(
        new PutCommand({
          TableName: remediationConfigTableName,
          Item: controlItem,
        }),
      );

      // ACT
      const result = await repository.findAll();

      // ASSERT
      expect(result).toHaveLength(1);
      expect(Array.isArray(result[0].filters)).toBe(true);
      expect(result[0].filters).toContain('filter-a');
      expect(result[0].filters).toContain('filter-b');
      expect(result[0].filters).toContain('filter-c');
    });

    it('should handle controls with undefined filters', async () => {
      // ARRANGE
      const controlItem = {
        controlId: 'RDS.1',
        description: 'RDS snapshots should be private',
        automatedRemediationEnabled: true,
        filterMode: 'include',
        version: 1,
      };

      await dynamoDBDocumentClient.send(
        new PutCommand({
          TableName: remediationConfigTableName,
          Item: controlItem,
        }),
      );

      // ACT
      const result = await repository.findAll();

      // ASSERT
      expect(result).toHaveLength(1);
      expect(result[0].filters).toEqual([]);
    });

    it('should default filterMode to include when not specified', async () => {
      // ARRANGE
      const controlItem = {
        controlId: 'Lambda.1',
        description: 'Lambda functions should prohibit public access',
        automatedRemediationEnabled: true,
        version: 1,
      };

      await dynamoDBDocumentClient.send(
        new PutCommand({
          TableName: remediationConfigTableName,
          Item: controlItem,
        }),
      );

      // ACT
      const result = await repository.findAll();

      // ASSERT
      expect(result).toHaveLength(1);
      expect(result[0].filterMode).toBe('include');
    });

    it('should handle controls with empty lastModified and modifiedBy', async () => {
      // ARRANGE
      const controlItem = {
        controlId: 'KMS.1',
        description: 'KMS keys should not be publicly accessible',
        automatedRemediationEnabled: false,
        version: 1,
      };

      await dynamoDBDocumentClient.send(
        new PutCommand({
          TableName: remediationConfigTableName,
          Item: controlItem,
        }),
      );

      // ACT
      const result = await repository.findAll();

      // ASSERT
      expect(result).toHaveLength(1);
      expect(result[0].lastModified).toBe('');
      expect(result[0].modifiedBy).toBe('');
    });

    it('should return controls with all expected properties', async () => {
      // ARRANGE
      const controlItem = {
        controlId: 'S3.1',
        description: 'S3 bucket should have server-side encryption enabled',
        automatedRemediationEnabled: true,
        filters: new Set(['filter-1', 'filter-2']),
        filterMode: 'include',
        version: 1,
        lastModified: '2024-01-01T00:00:00Z',
        modifiedBy: 'admin-user',
      };

      await dynamoDBDocumentClient.send(
        new PutCommand({
          TableName: remediationConfigTableName,
          Item: controlItem,
        }),
      );

      // ACT
      const result = await repository.findAll();

      // ASSERT
      const control = result[0];
      expect(control).toHaveProperty('controlId', 'S3.1');
      expect(control).toHaveProperty('description', 'S3 bucket should have server-side encryption enabled');
      expect(control).toHaveProperty('automatedRemediationEnabled', true);
      expect(control.filters).toContain('filter-1');
      expect(control.filters).toContain('filter-2');
      expect(control).toHaveProperty('filterMode', 'include');
      expect(control).toHaveProperty('version', 1);
      expect(control).toHaveProperty('lastModified', '2024-01-01T00:00:00Z');
      expect(control).toHaveProperty('modifiedBy', 'admin-user');
    });
  });

  describe('bulkUpdateControls', () => {
    it('should update a single control successfully', async () => {
      // ARRANGE
      const controlItem = {
        controlId: 'S3.1',
        description: 'S3 bucket should have server-side encryption enabled',
        automatedRemediationEnabled: false,
        filterMode: 'include',
        version: 1,
        lastModified: '2024-01-01T00:00:00Z',
        modifiedBy: 'system',
      };

      await dynamoDBDocumentClient.send(
        new PutCommand({
          TableName: remediationConfigTableName,
          Item: controlItem,
        }),
      );

      const controlsToUpdate = [
        {
          controlId: 'S3.1',
          description: 'S3 bucket should have server-side encryption enabled',
          automatedRemediationEnabled: true,
          filters: ['filter-1'],
          filterMode: 'include' as const,
          version: 1,
          lastModified: '2024-01-01T00:00:00Z',
          modifiedBy: 'system',
        },
      ];

      // ACT
      const result = await repository.bulkUpdateControls(controlsToUpdate, 'admin-user', '2024-01-15T10:00:00Z');

      // ASSERT
      expect(result.successCount).toBe(1);
      expect(result.failedControlIds).toHaveLength(0);

      const updatedItem = await dynamoDBDocumentClient.send(
        new GetCommand({
          TableName: remediationConfigTableName,
          Key: { controlId: 'S3.1' },
        }),
      );
      expect(updatedItem.Item?.automatedRemediationEnabled).toBe(true);
      expect(updatedItem.Item?.version).toBe(2);
      expect(updatedItem.Item?.modifiedBy).toBe('admin-user');
      expect(updatedItem.Item?.lastModified).toBe('2024-01-15T10:00:00Z');
    });

    it('should update multiple controls in a single batch', async () => {
      // ARRANGE
      const controlItems = [
        {
          controlId: 'S3.1',
          description: 'S3 control',
          automatedRemediationEnabled: false,
          filterMode: 'include',
          version: 1,
          lastModified: '2024-01-01T00:00:00Z',
          modifiedBy: 'system',
        },
        {
          controlId: 'EC2.1',
          description: 'EC2 control',
          automatedRemediationEnabled: false,
          filterMode: 'include',
          version: 1,
          lastModified: '2024-01-01T00:00:00Z',
          modifiedBy: 'system',
        },
      ];

      await Promise.all(
        controlItems.map((item) =>
          dynamoDBDocumentClient.send(
            new PutCommand({
              TableName: remediationConfigTableName,
              Item: item,
            }),
          ),
        ),
      );

      const controlsToUpdate = [
        {
          controlId: 'S3.1',
          description: 'S3 control',
          automatedRemediationEnabled: true,
          filters: [],
          filterMode: 'include' as const,
          version: 1,
          lastModified: '2024-01-01T00:00:00Z',
          modifiedBy: 'system',
        },
        {
          controlId: 'EC2.1',
          description: 'EC2 control',
          automatedRemediationEnabled: true,
          filters: [],
          filterMode: 'exclude' as const,
          version: 1,
          lastModified: '2024-01-01T00:00:00Z',
          modifiedBy: 'system',
        },
      ];

      // ACT
      const result = await repository.bulkUpdateControls(controlsToUpdate, 'admin-user', '2024-01-15T10:00:00Z');

      // ASSERT
      expect(result.successCount).toBe(2);
      expect(result.failedControlIds).toHaveLength(0);
    });

    it('should fail immediately on version conflict without retries', async () => {
      // ARRANGE
      const controlItem = {
        controlId: 'S3.1',
        description: 'Original description',
        automatedRemediationEnabled: true,
        filters: new Set(['original-filter']),
        filterMode: 'exclude',
        version: 5,
        lastModified: '2024-01-01T00:00:00Z',
        modifiedBy: 'original-user',
      };

      await dynamoDBDocumentClient.send(
        new PutCommand({
          TableName: remediationConfigTableName,
          Item: controlItem,
        }),
      );

      const controlsToUpdate = [
        {
          controlId: 'S3.1',
          description: 'New description',
          automatedRemediationEnabled: false,
          filters: ['new-filter'],
          filterMode: 'include' as const,
          version: 1,
          lastModified: '2024-01-01T00:00:00Z',
          modifiedBy: 'system',
        },
      ];

      // ACT
      const result = await repository.bulkUpdateControls(controlsToUpdate, 'admin-user', '2024-01-15T10:00:00Z');

      // ASSERT
      expect(result.successCount).toBe(0);
      expect(result.failedControlIds).toEqual(['S3.1']);

      const unchangedItem = await dynamoDBDocumentClient.send(
        new GetCommand({
          TableName: remediationConfigTableName,
          Key: { controlId: 'S3.1' },
        }),
      );
      expect(unchangedItem.Item?.version).toBe(5);
      expect(unchangedItem.Item?.description).toBe('Original description');
      expect(unchangedItem.Item?.automatedRemediationEnabled).toBe(true);
      expect(unchangedItem.Item?.filterMode).toBe('exclude');
      expect(unchangedItem.Item?.modifiedBy).toBe('original-user');
    });

    it('should fail when control does not exist', async () => {
      // ARRANGE
      const controlsToUpdate = [
        {
          controlId: 'NONEXISTENT.1',
          description: 'Non-existent control',
          automatedRemediationEnabled: true,
          filters: [],
          filterMode: 'include' as const,
          version: 1,
          lastModified: '2024-01-01T00:00:00Z',
          modifiedBy: 'system',
        },
      ];

      // ACT
      const result = await repository.bulkUpdateControls(controlsToUpdate, 'admin-user', '2024-01-15T10:00:00Z');

      // ASSERT
      expect(result.successCount).toBe(0);
      expect(result.failedControlIds).toEqual(['NONEXISTENT.1']);
    });

    it('should store filters as String Set in DynamoDB', async () => {
      // ARRANGE
      const controlItem = {
        controlId: 'S3.1',
        description: 'S3 control',
        automatedRemediationEnabled: false,
        filterMode: 'include',
        version: 1,
        lastModified: '2024-01-01T00:00:00Z',
        modifiedBy: 'system',
      };

      await dynamoDBDocumentClient.send(
        new PutCommand({
          TableName: remediationConfigTableName,
          Item: controlItem,
        }),
      );

      const controlsToUpdate = [
        {
          controlId: 'S3.1',
          description: 'S3 control',
          automatedRemediationEnabled: true,
          filters: ['filter-a', 'filter-b'],
          filterMode: 'exclude' as const,
          version: 1,
          lastModified: '2024-01-01T00:00:00Z',
          modifiedBy: 'system',
        },
      ];

      // ACT
      const result = await repository.bulkUpdateControls(controlsToUpdate, 'admin-user', '2024-01-15T10:00:00Z');

      // ASSERT
      expect(result.successCount).toBe(1);

      const updatedItem = await dynamoDBDocumentClient.send(
        new GetCommand({
          TableName: remediationConfigTableName,
          Key: { controlId: 'S3.1' },
        }),
      );

      const filters = updatedItem.Item?.filters;
      if (filters instanceof Set) {
        expect(Array.from(filters).sort()).toEqual(['filter-a', 'filter-b']);
      } else if (Array.isArray(filters)) {
        expect(filters.sort()).toEqual(['filter-a', 'filter-b']);
      } else {
        fail('Expected filters to be Set or Array');
      }
    });

    it('should remove filters attribute when empty array is provided', async () => {
      // ARRANGE
      const controlItem = {
        controlId: 'S3.1',
        description: 'S3 control',
        automatedRemediationEnabled: false,
        filters: new Set(['existing-filter']),
        filterMode: 'include',
        version: 1,
        lastModified: '2024-01-01T00:00:00Z',
        modifiedBy: 'system',
      };

      await dynamoDBDocumentClient.send(
        new PutCommand({
          TableName: remediationConfigTableName,
          Item: controlItem,
        }),
      );

      const controlsToUpdate = [
        {
          controlId: 'S3.1',
          description: 'S3 control',
          automatedRemediationEnabled: true,
          filters: [],
          filterMode: 'include' as const,
          version: 1,
          lastModified: '2024-01-01T00:00:00Z',
          modifiedBy: 'system',
        },
      ];

      // ACT
      const result = await repository.bulkUpdateControls(controlsToUpdate, 'admin-user', '2024-01-15T10:00:00Z');

      // ASSERT
      expect(result.successCount).toBe(1);

      const updatedItem = await dynamoDBDocumentClient.send(
        new GetCommand({
          TableName: remediationConfigTableName,
          Key: { controlId: 'S3.1' },
        }),
      );
      expect(updatedItem.Item?.filters).toBeUndefined();
    });

    it('should update all control attributes correctly', async () => {
      // ARRANGE
      const controlItem = {
        controlId: 'S3.1',
        description: 'Original description',
        automatedRemediationEnabled: false,
        filters: new Set(['old-filter']),
        filterMode: 'include',
        version: 1,
        lastModified: '2024-01-01T00:00:00Z',
        modifiedBy: 'original-user',
      };

      await dynamoDBDocumentClient.send(
        new PutCommand({
          TableName: remediationConfigTableName,
          Item: controlItem,
        }),
      );

      const controlsToUpdate = [
        {
          controlId: 'S3.1',
          description: 'Updated description',
          automatedRemediationEnabled: true,
          filters: ['new-filter-1', 'new-filter-2'],
          filterMode: 'exclude' as const,
          version: 1,
          lastModified: '2024-01-01T00:00:00Z',
          modifiedBy: 'original-user',
        },
      ];

      // ACT
      const result = await repository.bulkUpdateControls(controlsToUpdate, 'new-admin', '2024-02-01T12:00:00Z');

      // ASSERT
      expect(result.successCount).toBe(1);
      expect(result.failedControlIds).toHaveLength(0);

      const updatedItem = await dynamoDBDocumentClient.send(
        new GetCommand({
          TableName: remediationConfigTableName,
          Key: { controlId: 'S3.1' },
        }),
      );

      expect(updatedItem.Item?.description).toBe('Updated description');
      expect(updatedItem.Item?.automatedRemediationEnabled).toBe(true);
      expect(updatedItem.Item?.filterMode).toBe('exclude');
      expect(updatedItem.Item?.version).toBe(2);
      expect(updatedItem.Item?.lastModified).toBe('2024-02-01T12:00:00Z');
      expect(updatedItem.Item?.modifiedBy).toBe('new-admin');
    });

    it('should handle partial batch failure when some controls have version conflicts', async () => {
      // ARRANGE
      const controlItems = [
        {
          controlId: 'S3.1',
          description: 'S3 control',
          automatedRemediationEnabled: false,
          filterMode: 'include',
          version: 1,
          lastModified: '2024-01-01T00:00:00Z',
          modifiedBy: 'system',
        },
        {
          controlId: 'EC2.1',
          description: 'EC2 control',
          automatedRemediationEnabled: false,
          filterMode: 'include',
          version: 5,
          lastModified: '2024-01-01T00:00:00Z',
          modifiedBy: 'system',
        },
      ];

      await Promise.all(
        controlItems.map((item) =>
          dynamoDBDocumentClient.send(
            new PutCommand({
              TableName: remediationConfigTableName,
              Item: item,
            }),
          ),
        ),
      );

      const controlsToUpdate = [
        {
          controlId: 'S3.1',
          description: 'S3 control',
          automatedRemediationEnabled: true,
          filters: [],
          filterMode: 'include' as const,
          version: 1,
          lastModified: '2024-01-01T00:00:00Z',
          modifiedBy: 'system',
        },
        {
          controlId: 'EC2.1',
          description: 'EC2 control',
          automatedRemediationEnabled: true,
          filters: [],
          filterMode: 'include' as const,
          version: 1,
          lastModified: '2024-01-01T00:00:00Z',
          modifiedBy: 'system',
        },
      ];

      // ACT
      const result = await repository.bulkUpdateControls(controlsToUpdate, 'admin-user', '2024-01-15T10:00:00Z');

      // ASSERT
      // A TransactWrite is all-or-nothing, but CancellationReasons names the one entry at fault:
      // the valid entry is re-driven and lands, and only the stale one is reported. This is what
      // makes the handler's partial-success (207) response reachable within a single batch.
      expect(result.successCount).toBe(1);
      expect(result.failedControlIds).toEqual(['EC2.1']);

      const applied = await dynamoDBDocumentClient.send(
        new GetCommand({ TableName: remediationConfigTableName, Key: { controlId: 'S3.1' } }),
      );
      expect(applied.Item?.version).toBe(2);
      expect(applied.Item?.automatedRemediationEnabled).toBe(true);
      expect(applied.Item?.modifiedBy).toBe('admin-user');

      const untouched = await dynamoDBDocumentClient.send(
        new GetCommand({ TableName: remediationConfigTableName, Key: { controlId: 'EC2.1' } }),
      );
      expect(untouched.Item?.version).toBe(5);
      expect(untouched.Item?.automatedRemediationEnabled).toBe(false);
      expect(untouched.Item?.modifiedBy).toBe('system');
    });
  });

  describe('bulkUpdateControls — transient cancellation codes', () => {
    // DynamoDB Local never reports TransactionConflict or throttling, so these drive the
    // repository through a client whose `send` fails the first N TransactWrite calls with a
    // scripted TransactionCanceledException and then delegates to the real client. The table
    // is real, so a successful re-drive is observable in storage rather than asserted on a mock.
    const controlOf = (controlId: string) => ({
      controlId,
      description: `${controlId} control`,
      automatedRemediationEnabled: true,
      filters: [],
      filterMode: 'include' as const,
      version: 1,
      lastModified: '2024-01-01T00:00:00Z',
      modifiedBy: 'system',
    });

    async function seed(...controlIds: string[]): Promise<void> {
      await Promise.all(
        controlIds.map((controlId) =>
          dynamoDBDocumentClient.send(
            new PutCommand({
              TableName: remediationConfigTableName,
              Item: { ...controlOf(controlId), automatedRemediationEnabled: false },
            }),
          ),
        ),
      );
    }

    function cancellation(codes: string[]): Error {
      const error = new Error('Transaction cancelled');
      error.name = 'TransactionCanceledException';
      Object.assign(error, { CancellationReasons: codes.map((Code) => ({ Code })) });
      return error;
    }

    /** A repository whose first `failures.length` TransactWrite calls are cancelled as scripted. */
    /** A request-level error: no CancellationReasons, nothing written. */
    function requestError(name: string): Error {
      const error = new Error(name);
      error.name = name;
      return error;
    }

    function repositoryWithScriptedCancellations(failures: (string[] | Error)[]): {
      repository: ControlsRepository;
      sleeps: number[];
      transactCalls: number;
    } {
      const state = { sleeps: [] as number[], transactCalls: 0 };
      // The real DynamoDB Local client with only `send` intercepted, so the seeded rows and the
      // writes that do land are real. A Proxy over the client *is* a DynamoDBDocumentClient to the
      // type system, which is what the repository constructor asks for — no cast needed.
      // `send` is overloaded (promise and callback forms); the repository only awaits the promise
      // form, so the fake implements that one.
      type PromiseSend = <Input extends ServiceInputTypes, Output extends ServiceOutputTypes>(
        command: Command<
          ServiceInputTypes,
          Input,
          ServiceOutputTypes,
          Output,
          SmithyResolvedConfiguration<HttpHandlerOptions>
        >,
        options?: HttpHandlerOptions,
      ) => Promise<Output>;
      const send: PromiseSend = async (command, options) => {
        if (command instanceof TransactWriteCommand) {
          const attempt = state.transactCalls++;
          if (attempt < failures.length) {
            const failure = failures[attempt];
            throw failure instanceof Error ? failure : cancellation(failure);
          }
        }
        return dynamoDBDocumentClient.send(command, options);
      };
      const client = new Proxy(dynamoDBDocumentClient, {
        get: (target, property, receiver) => (property === 'send' ? send : Reflect.get(target, property, receiver)),
      });
      const sleeper = { sleep: async (ms: number) => void state.sleeps.push(ms) };
      return {
        repository: new ControlsRepository(remediationConfigTableName, client, sleeper),
        get sleeps() {
          return state.sleeps;
        },
        get transactCalls() {
          return state.transactCalls;
        },
      };
    }

    it('re-drives an item that lost to a concurrent transaction instead of reporting it failed', async () => {
      await seed('S3.1', 'EC2.1');
      const scripted = repositoryWithScriptedCancellations([['None', 'TransactionConflict']]);

      const result = await scripted.repository.bulkUpdateControls(
        [controlOf('S3.1'), controlOf('EC2.1')],
        'admin-user',
        '2024-01-15T10:00:00Z',
      );

      // Both controls were valid; the conflict was transient, so nothing is reported failed.
      expect(result).toEqual({ successCount: 2, failedControlIds: [] });
      expect(scripted.transactCalls).toBe(2);
      expect(scripted.sleeps).toEqual([50]);
      const applied = await dynamoDBDocumentClient.send(
        new GetCommand({ TableName: remediationConfigTableName, Key: { controlId: 'EC2.1' } }),
      );
      expect(applied.Item?.automatedRemediationEnabled).toBe(true);
    });

    it('drops only the item that lost its version check and retries a throttled sibling', async () => {
      await seed('S3.1', 'EC2.1', 'IAM.1');
      const scripted = repositoryWithScriptedCancellations([['ConditionalCheckFailed', 'ThrottlingError', 'None']]);

      const result = await scripted.repository.bulkUpdateControls(
        [controlOf('S3.1'), controlOf('EC2.1'), controlOf('IAM.1')],
        'admin-user',
        '2024-01-15T10:00:00Z',
      );

      expect(result.successCount).toBe(2);
      expect(result.failedControlIds).toEqual(['S3.1']);
      expect(scripted.transactCalls).toBe(2);
    });

    it('gives up on a persistently contended batch after the retry budget with exponential backoff', async () => {
      await seed('S3.1');
      // Four cancellations: the initial attempt plus TRANSIENT_RETRY_MAX_ATTEMPTS re-drives.
      const scripted = repositoryWithScriptedCancellations([
        ['TransactionConflict'],
        ['TransactionConflict'],
        ['TransactionConflict'],
        ['TransactionConflict'],
      ]);

      const result = await scripted.repository.bulkUpdateControls(
        [controlOf('S3.1')],
        'admin-user',
        '2024-01-15T10:00:00Z',
      );

      expect(result).toEqual({ successCount: 0, failedControlIds: ['S3.1'] });
      expect(scripted.sleeps).toEqual([50, 100, 200]);
      expect(scripted.transactCalls).toBe(4);
    });

    it('spends the retry budget on mixed passes too, so a contended item cannot ride along indefinitely', async () => {
      await seed('S3.1', 'EC2.1', 'IAM.1', 'RDS.1', 'KMS.1');
      // Every pass removes one stale item but S3.1 stays contended. Without the budget advancing
      // on these mixed passes, S3.1 would be re-driven once per stale sibling before giving up.
      const scripted = repositoryWithScriptedCancellations([
        ['TransactionConflict', 'ConditionalCheckFailed', 'None', 'None', 'None'],
        ['TransactionConflict', 'ConditionalCheckFailed', 'None', 'None'],
        ['TransactionConflict', 'ConditionalCheckFailed', 'None'],
        ['TransactionConflict', 'ConditionalCheckFailed'],
        ['TransactionConflict'],
      ]);

      const result = await scripted.repository.bulkUpdateControls(
        ['S3.1', 'EC2.1', 'IAM.1', 'RDS.1', 'KMS.1'].map(controlOf),
        'admin-user',
        '2024-01-15T10:00:00Z',
      );

      // Initial attempt + 3 budgeted re-drives = 4 transactions; the 5th scripted cancellation is
      // never reached. Every sibling lost its version check along the way (KMS.1 on the last
      // budgeted pass), so when the budget runs out there is no collateral left for a final pass
      // and S3.1 is reported failed alongside them.
      expect(scripted.transactCalls).toBe(4);
      expect(result.successCount).toBe(0);
      expect(result.failedControlIds.sort()).toEqual(['EC2.1', 'IAM.1', 'KMS.1', 'RDS.1', 'S3.1']);
    });

    it('gives collateral items one final write without the contended item when the budget runs out', async () => {
      await seed('S3.1', 'EC2.1', 'IAM.1');
      // S3.1 stays contended on every pass; EC2.1 and IAM.1 were never at fault, they were only
      // rolled back with it. Reporting them failed would tell the operator to refresh and retry
      // two controls that nothing was wrong with.
      const scripted = repositoryWithScriptedCancellations([
        ['TransactionConflict', 'None', 'None'],
        ['TransactionConflict', 'None', 'None'],
        ['TransactionConflict', 'None', 'None'],
        ['TransactionConflict', 'None', 'None'],
      ]);

      const result = await scripted.repository.bulkUpdateControls(
        [controlOf('S3.1'), controlOf('EC2.1'), controlOf('IAM.1')],
        'admin-user',
        '2024-01-15T10:00:00Z',
      );

      // 4 cancelled transactions, one more backoff step, then a 5th carrying only EC2.1 and
      // IAM.1, which succeeds.
      expect(scripted.transactCalls).toBe(5);
      expect(scripted.sleeps).toEqual([50, 100, 200, 400]);
      expect(result).toEqual({ successCount: 2, failedControlIds: ['S3.1'] });
    });

    it('does not re-drive the final collateral pass if it is itself cancelled', async () => {
      await seed('S3.1', 'EC2.1', 'IAM.1');
      const scripted = repositoryWithScriptedCancellations([
        ['TransactionConflict', 'None', 'None'],
        ['TransactionConflict', 'None', 'None'],
        ['TransactionConflict', 'None', 'None'],
        ['TransactionConflict', 'None', 'None'],
        // The final pass carries EC2.1 and IAM.1. It is cancelled with a *mixed* result: EC2.1
        // now collides and IAM.1 is fresh collateral. Re-driving IAM.1 from here would start a
        // second final phase with the budget already spent — and could keep going, one item at a
        // time, with no backoff between passes.
        ['TransactionConflict', 'None'],
        // Never reached.
        ['TransactionConflict'],
      ]);

      const result = await scripted.repository.bulkUpdateControls(
        [controlOf('S3.1'), controlOf('EC2.1'), controlOf('IAM.1')],
        'admin-user',
        '2024-01-15T10:00:00Z',
      );

      expect(scripted.transactCalls).toBe(5);
      expect(scripted.sleeps).toEqual([50, 100, 200, 400]);
      expect(result.successCount).toBe(0);
      expect(result.failedControlIds.sort()).toEqual(['EC2.1', 'IAM.1', 'S3.1']);
    });

    it('pauses briefly between permanent-only re-drives so racing writers do not see a tight loop', async () => {
      await seed('S3.1', 'EC2.1', 'IAM.1');
      // Each pass loses a different item to a version check bumped by another writer. Such passes
      // spend no transient budget (the batch strictly shrinks), but each is preceded by a short
      // fixed pause so they are not issued back-to-back.
      const scripted = repositoryWithScriptedCancellations([
        ['ConditionalCheckFailed', 'None', 'None'],
        ['ConditionalCheckFailed', 'None'],
      ]);

      const result = await scripted.repository.bulkUpdateControls(
        [controlOf('S3.1'), controlOf('EC2.1'), controlOf('IAM.1')],
        'admin-user',
        '2024-01-15T10:00:00Z',
      );

      expect(scripted.transactCalls).toBe(3);
      expect(scripted.sleeps).toEqual([20, 20]);
      expect(result.successCount).toBe(1);
      expect(result.failedControlIds.sort()).toEqual(['EC2.1', 'S3.1']);
    });

    it('re-drives the whole batch after a request-level throttle instead of failing it', async () => {
      await seed('S3.1', 'EC2.1');
      // A ThrottlingException carries no CancellationReasons: nothing was written and every item
      // is as valid as it was, so the whole batch is re-driven under the transient budget.
      const scripted = repositoryWithScriptedCancellations([requestError('ThrottlingException')]);

      const result = await scripted.repository.bulkUpdateControls(
        [controlOf('S3.1'), controlOf('EC2.1')],
        'admin-user',
        '2024-01-15T10:00:00Z',
      );

      expect(result).toEqual({ successCount: 2, failedControlIds: [] });
      expect(scripted.transactCalls).toBe(2);
      expect(scripted.sleeps).toEqual([50]);
    });

    it('spends the transient budget on request-level throttles too', async () => {
      await seed('S3.1');
      const scripted = repositoryWithScriptedCancellations([
        requestError('ProvisionedThroughputExceededException'),
        requestError('ThrottlingException'),
        requestError('ThrottlingException'),
        requestError('ThrottlingException'),
      ]);

      const result = await scripted.repository.bulkUpdateControls(
        [controlOf('S3.1')],
        'admin-user',
        '2024-01-15T10:00:00Z',
      );

      expect(result).toEqual({ successCount: 0, failedControlIds: ['S3.1'] });
      expect(scripted.transactCalls).toBe(4);
      expect(scripted.sleeps).toEqual([50, 100, 200]);
    });

    it('still fails the batch on an error that is neither a cancellation nor transient', async () => {
      await seed('S3.1');
      const scripted = repositoryWithScriptedCancellations([requestError('AccessDeniedException')]);

      const result = await scripted.repository.bulkUpdateControls(
        [controlOf('S3.1')],
        'admin-user',
        '2024-01-15T10:00:00Z',
      );

      expect(result).toEqual({ successCount: 0, failedControlIds: ['S3.1'] });
      expect(scripted.transactCalls).toBe(1);
      expect(scripted.sleeps).toEqual([]);
    });

    it('stops re-driving at the per-batch pass cap and gives the collateral one final write', async () => {
      // Ten items; a concurrent writer bumps a different version on every pass. Each pass shrinks
      // the batch by one and spends no transient budget, so only the pass cap bounds the work.
      const ids = Array.from({ length: 10 }, (_, i) => `CTRL.${i}`);
      await seed(...ids);
      const scripted = repositoryWithScriptedCancellations(
        // Pass k (1-based) blames position 0 and leaves the rest as collateral. Eight passes blame
        // eight items; the cap then sends the remaining two as one final, uncancelled write.
        Array.from({ length: 8 }, (_, k) => ['ConditionalCheckFailed', ...Array<string>(9 - k).fill('None')]),
      );

      const result = await scripted.repository.bulkUpdateControls(
        ids.map(controlOf),
        'admin-user',
        '2024-01-15T10:00:00Z',
      );

      // 8 capped passes + the final collateral write; 7 pauses between passes + 1 before the final.
      expect(scripted.transactCalls).toBe(9);
      expect(scripted.sleeps).toEqual(Array<number>(8).fill(20));
      expect(result.successCount).toBe(2);
      expect(result.failedControlIds.sort()).toEqual(ids.slice(0, 8).sort());
    });

    it('does not re-drive collateral again if the capped final write is itself cancelled', async () => {
      const ids = Array.from({ length: 10 }, (_, i) => `CTRL.${i}`);
      await seed(...ids);
      const scripted = repositoryWithScriptedCancellations([
        ...Array.from({ length: 8 }, (_, k) => ['ConditionalCheckFailed', ...Array<string>(9 - k).fill('None')]),
        // The final write of the last two items collides too. Nothing further is attempted.
        ['TransactionConflict', 'None'],
      ]);

      const result = await scripted.repository.bulkUpdateControls(
        ids.map(controlOf),
        'admin-user',
        '2024-01-15T10:00:00Z',
      );

      expect(scripted.transactCalls).toBe(9);
      expect(result.successCount).toBe(0);
      expect(result.failedControlIds.sort()).toEqual([...ids].sort());
    });

    it('reports collateral as not written, without another attempt, when its final write is throttled', async () => {
      await seed('S3.1', 'EC2.1');
      const scripted = repositoryWithScriptedCancellations([
        ['TransactionConflict', 'None'],
        ['TransactionConflict', 'None'],
        ['TransactionConflict', 'None'],
        ['TransactionConflict', 'None'],
        // The single final write for EC2.1 is throttled at the request level. The budget that got
        // us here is what bounds the request, so EC2.1 is reported as not written and left to the
        // caller rather than re-driven again.
        requestError('ThrottlingException'),
      ]);

      const result = await scripted.repository.bulkUpdateControls(
        [controlOf('S3.1'), controlOf('EC2.1')],
        'admin-user',
        '2024-01-15T10:00:00Z',
      );

      expect(scripted.transactCalls).toBe(5);
      expect(scripted.sleeps).toEqual([50, 100, 200, 400]);
      expect(result.successCount).toBe(0);
      expect(result.failedControlIds.sort()).toEqual(['EC2.1', 'S3.1']);
    });

    it('does not blindly re-drive after a 5xx, because the write may have landed', async () => {
      await seed('S3.1', 'EC2.1');
      // An InternalServerError says nothing about whether the transaction committed. Re-driving
      // would trip every version condition if it did, and report a successful write as a
      // permanent failure; the batch is reported failed once and the caller re-reads.
      const scripted = repositoryWithScriptedCancellations([requestError('InternalServerError')]);

      const result = await scripted.repository.bulkUpdateControls(
        [controlOf('S3.1'), controlOf('EC2.1')],
        'admin-user',
        '2024-01-15T10:00:00Z',
      );

      expect(result.successCount).toBe(0);
      expect(result.failedControlIds.sort()).toEqual(['EC2.1', 'S3.1']);
      expect(scripted.transactCalls).toBe(1);
      expect(scripted.sleeps).toEqual([]);
    });

    it('fails the batch when the cancellation blames no item at all', async () => {
      await seed('S3.1');
      const scripted = repositoryWithScriptedCancellations([['None']]);

      const result = await scripted.repository.bulkUpdateControls(
        [controlOf('S3.1')],
        'admin-user',
        '2024-01-15T10:00:00Z',
      );

      expect(result).toEqual({ successCount: 0, failedControlIds: ['S3.1'] });
      expect(scripted.transactCalls).toBe(1);
    });
  });

  describe('applyFilterToAllControls', () => {
    it('should apply filter to all controls successfully', async () => {
      // ARRANGE
      const controlItems = [
        {
          controlId: 'S3.1',
          description: 'S3 control',
          automatedRemediationEnabled: false,
          filterMode: 'include',
          version: 1,
          lastModified: '2024-01-01T00:00:00Z',
          modifiedBy: 'system',
        },
        {
          controlId: 'EC2.1',
          description: 'EC2 control',
          automatedRemediationEnabled: true,
          filterMode: 'exclude',
          version: 1,
          lastModified: '2024-01-01T00:00:00Z',
          modifiedBy: 'system',
        },
      ];

      await Promise.all(
        controlItems.map((item) =>
          dynamoDBDocumentClient.send(
            new PutCommand({
              TableName: remediationConfigTableName,
              Item: item,
            }),
          ),
        ),
      );

      const filterId = '550e8400-e29b-41d4-a716-446655440000';

      // ACT
      const result = await repository.applyFilterToAllControls(filterId, 'admin-user', '2024-01-15T10:00:00Z');

      // ASSERT
      expect(result.successCount).toBe(2);
      expect(result.failedControlIds).toHaveLength(0);

      const s3Control = await dynamoDBDocumentClient.send(
        new GetCommand({
          TableName: remediationConfigTableName,
          Key: { controlId: 'S3.1' },
        }),
      );
      expect(s3Control.Item?.filters).toBeInstanceOf(Set);
      expect(Array.from(s3Control.Item?.filters as Set<string>)).toContain(filterId);
      expect(s3Control.Item?.version).toBe(2);
      expect(s3Control.Item?.modifiedBy).toBe('admin-user');

      const ec2Control = await dynamoDBDocumentClient.send(
        new GetCommand({
          TableName: remediationConfigTableName,
          Key: { controlId: 'EC2.1' },
        }),
      );
      expect(ec2Control.Item?.filters).toBeInstanceOf(Set);
      expect(Array.from(ec2Control.Item?.filters as Set<string>)).toContain(filterId);
      expect(ec2Control.Item?.version).toBe(2);
    });

    it('should return zero updates when no controls exist', async () => {
      // ARRANGE - empty table
      const filterId = '550e8400-e29b-41d4-a716-446655440000';

      // ACT
      const result = await repository.applyFilterToAllControls(filterId, 'admin-user', '2024-01-15T10:00:00Z');

      // ASSERT
      expect(result.successCount).toBe(0);
      expect(result.failedControlIds).toHaveLength(0);
    });

    it('should add filter to controls that already have existing filters', async () => {
      // ARRANGE
      const controlItem = {
        controlId: 'S3.1',
        description: 'S3 control',
        automatedRemediationEnabled: true,
        filters: new Set(['existing-filter-1', 'existing-filter-2']),
        filterMode: 'include',
        version: 1,
        lastModified: '2024-01-01T00:00:00Z',
        modifiedBy: 'system',
      };

      await dynamoDBDocumentClient.send(
        new PutCommand({
          TableName: remediationConfigTableName,
          Item: controlItem,
        }),
      );

      const newFilterId = '550e8400-e29b-41d4-a716-446655440000';

      // ACT
      const result = await repository.applyFilterToAllControls(newFilterId, 'admin-user', '2024-01-15T10:00:00Z');

      // ASSERT
      expect(result.successCount).toBe(1);

      const updatedItem = await dynamoDBDocumentClient.send(
        new GetCommand({
          TableName: remediationConfigTableName,
          Key: { controlId: 'S3.1' },
        }),
      );
      const filters = Array.from(updatedItem.Item?.filters as Set<string>).sort();
      expect(filters).toEqual(['550e8400-e29b-41d4-a716-446655440000', 'existing-filter-1', 'existing-filter-2']);
    });

    it('should be idempotent when applying the same filter twice', async () => {
      // ARRANGE
      const filterId = '550e8400-e29b-41d4-a716-446655440000';
      const controlItem = {
        controlId: 'S3.1',
        description: 'S3 control',
        automatedRemediationEnabled: true,
        filters: new Set([filterId]),
        filterMode: 'include',
        version: 1,
        lastModified: '2024-01-01T00:00:00Z',
        modifiedBy: 'system',
      };

      await dynamoDBDocumentClient.send(
        new PutCommand({
          TableName: remediationConfigTableName,
          Item: controlItem,
        }),
      );

      // ACT
      const result = await repository.applyFilterToAllControls(filterId, 'admin-user', '2024-01-15T10:00:00Z');

      // ASSERT
      expect(result.successCount).toBe(1);

      const updatedItem = await dynamoDBDocumentClient.send(
        new GetCommand({
          TableName: remediationConfigTableName,
          Key: { controlId: 'S3.1' },
        }),
      );
      const filters = Array.from(updatedItem.Item?.filters as Set<string>);
      expect(filters).toEqual([filterId]);
      expect(updatedItem.Item?.version).toBe(2);
    });

    it('should preserve other control attributes when applying filter', async () => {
      // ARRANGE
      const controlItem = {
        controlId: 'S3.1',
        description: 'S3 Block Public Access',
        automatedRemediationEnabled: true,
        filterMode: 'exclude',
        version: 3,
        lastModified: '2024-01-01T00:00:00Z',
        modifiedBy: 'previous-user',
      };

      await dynamoDBDocumentClient.send(
        new PutCommand({
          TableName: remediationConfigTableName,
          Item: controlItem,
        }),
      );

      const filterId = '550e8400-e29b-41d4-a716-446655440000';

      // ACT
      const result = await repository.applyFilterToAllControls(filterId, 'admin-user', '2024-01-15T10:00:00Z');

      // ASSERT
      expect(result.successCount).toBe(1);

      const updatedItem = await dynamoDBDocumentClient.send(
        new GetCommand({
          TableName: remediationConfigTableName,
          Key: { controlId: 'S3.1' },
        }),
      );
      expect(updatedItem.Item?.description).toBe('S3 Block Public Access');
      expect(updatedItem.Item?.automatedRemediationEnabled).toBe(true);
      expect(updatedItem.Item?.filterMode).toBe('exclude');
      expect(updatedItem.Item?.version).toBe(4);
      expect(updatedItem.Item?.modifiedBy).toBe('admin-user');
      expect(updatedItem.Item?.lastModified).toBe('2024-01-15T10:00:00Z');
    });

    it('should handle controls with higher version numbers', async () => {
      // ARRANGE
      const controlItem = {
        controlId: 'S3.1',
        description: 'S3 control',
        automatedRemediationEnabled: false,
        filterMode: 'include',
        version: 10,
        lastModified: '2024-01-01T00:00:00Z',
        modifiedBy: 'system',
      };

      await dynamoDBDocumentClient.send(
        new PutCommand({
          TableName: remediationConfigTableName,
          Item: controlItem,
        }),
      );

      const filterId = '550e8400-e29b-41d4-a716-446655440000';

      // ACT
      const result = await repository.applyFilterToAllControls(filterId, 'admin-user', '2024-01-15T10:00:00Z');

      // ASSERT
      expect(result.successCount).toBe(1);

      const updatedItem = await dynamoDBDocumentClient.send(
        new GetCommand({
          TableName: remediationConfigTableName,
          Key: { controlId: 'S3.1' },
        }),
      );
      expect(updatedItem.Item?.version).toBe(11);
    });

    it('should handle batch splitting when updating more than 100 controls', async () => {
      // ARRANGE
      const controlCount = 150;

      for (let i = 1; i <= controlCount; i++) {
        const controlItem = {
          controlId: `CTRL.${i}`,
          description: `Control ${i}`,
          automatedRemediationEnabled: false,
          filterMode: 'include',
          version: 1,
          lastModified: '2024-01-01T00:00:00Z',
          modifiedBy: 'system',
        };
        await dynamoDBDocumentClient.send(
          new PutCommand({
            TableName: remediationConfigTableName,
            Item: controlItem,
          }),
        );
      }

      const filterId = '550e8400-e29b-41d4-a716-446655440000';

      // ACT
      const result = await repository.applyFilterToAllControls(filterId, 'admin-user', '2024-01-15T10:00:00Z');

      // ASSERT
      expect(result.successCount).toBe(controlCount);
      expect(result.failedControlIds).toHaveLength(0);

      const firstControl = await dynamoDBDocumentClient.send(
        new GetCommand({
          TableName: remediationConfigTableName,
          Key: { controlId: 'CTRL.1' },
        }),
      );
      expect(firstControl.Item?.filters).toBeInstanceOf(Set);
      expect(Array.from(firstControl.Item?.filters as Set<string>)).toContain(filterId);

      const lastControl = await dynamoDBDocumentClient.send(
        new GetCommand({
          TableName: remediationConfigTableName,
          Key: { controlId: `CTRL.${controlCount}` },
        }),
      );
      expect(lastControl.Item?.filters).toBeInstanceOf(Set);
      expect(Array.from(lastControl.Item?.filters as Set<string>)).toContain(filterId);
    });

    it('should handle controls with undefined version by defaulting to 1', async () => {
      // ARRANGE
      const controlItem = {
        controlId: 'S3.1',
        description: 'S3 control',
        automatedRemediationEnabled: false,
        filterMode: 'include',
        lastModified: '2024-01-01T00:00:00Z',
        modifiedBy: 'system',
      };

      await dynamoDBDocumentClient.send(
        new PutCommand({
          TableName: remediationConfigTableName,
          Item: controlItem,
        }),
      );

      const filterId = '550e8400-e29b-41d4-a716-446655440000';

      // ACT
      const result = await repository.applyFilterToAllControls(filterId, 'admin-user', '2024-01-15T10:00:00Z');

      // ASSERT
      expect(result.successCount).toBe(1);

      const updatedItem = await dynamoDBDocumentClient.send(
        new GetCommand({
          TableName: remediationConfigTableName,
          Key: { controlId: 'S3.1' },
        }),
      );
      expect(updatedItem.Item?.version).toBe(2);
    });

    it('should handle mixed controls with and without version attribute', async () => {
      // ARRANGE
      const controlWithVersion = {
        controlId: 'S3.1',
        description: 'S3 control with version',
        automatedRemediationEnabled: false,
        filterMode: 'include',
        version: 3,
        lastModified: '2024-01-01T00:00:00Z',
        modifiedBy: 'system',
      };

      const controlWithoutVersion = {
        controlId: 'EC2.1',
        description: 'EC2 control without version',
        automatedRemediationEnabled: true,
        filterMode: 'exclude',
        lastModified: '2024-01-01T00:00:00Z',
        modifiedBy: 'system',
      };

      await Promise.all([
        dynamoDBDocumentClient.send(
          new PutCommand({
            TableName: remediationConfigTableName,
            Item: controlWithVersion,
          }),
        ),
        dynamoDBDocumentClient.send(
          new PutCommand({
            TableName: remediationConfigTableName,
            Item: controlWithoutVersion,
          }),
        ),
      ]);

      const filterId = '550e8400-e29b-41d4-a716-446655440000';

      // ACT
      const result = await repository.applyFilterToAllControls(filterId, 'admin-user', '2024-01-15T10:00:00Z');

      // ASSERT
      expect(result.successCount).toBe(2);
      expect(result.failedControlIds).toHaveLength(0);

      const s3Control = await dynamoDBDocumentClient.send(
        new GetCommand({
          TableName: remediationConfigTableName,
          Key: { controlId: 'S3.1' },
        }),
      );
      expect(s3Control.Item?.version).toBe(4);
      expect(Array.from(s3Control.Item?.filters as Set<string>)).toContain(filterId);

      const ec2Control = await dynamoDBDocumentClient.send(
        new GetCommand({
          TableName: remediationConfigTableName,
          Key: { controlId: 'EC2.1' },
        }),
      );
      expect(ec2Control.Item?.version).toBe(2);
      expect(Array.from(ec2Control.Item?.filters as Set<string>)).toContain(filterId);
    });

    it('should add filter to control without version and preserve existing filters', async () => {
      // ARRANGE
      const controlItem = {
        controlId: 'S3.1',
        description: 'S3 control',
        automatedRemediationEnabled: false,
        filters: new Set(['existing-filter']),
        filterMode: 'include',
        lastModified: '2024-01-01T00:00:00Z',
        modifiedBy: 'system',
      };

      await dynamoDBDocumentClient.send(
        new PutCommand({
          TableName: remediationConfigTableName,
          Item: controlItem,
        }),
      );

      const newFilterId = '550e8400-e29b-41d4-a716-446655440000';

      // ACT
      const result = await repository.applyFilterToAllControls(newFilterId, 'admin-user', '2024-01-15T10:00:00Z');

      // ASSERT
      expect(result.successCount).toBe(1);

      const updatedItem = await dynamoDBDocumentClient.send(
        new GetCommand({
          TableName: remediationConfigTableName,
          Key: { controlId: 'S3.1' },
        }),
      );
      const filters = Array.from(updatedItem.Item?.filters as Set<string>).sort();
      expect(filters).toEqual(['550e8400-e29b-41d4-a716-446655440000', 'existing-filter']);
      expect(updatedItem.Item?.version).toBe(2);
    });

    it('should not allow version mismatch even when attribute_not_exists condition is present', async () => {
      // ARRANGE
      const controlItem = {
        controlId: 'S3.1',
        description: 'S3 control',
        automatedRemediationEnabled: false,
        filterMode: 'include',
        version: 5,
        lastModified: '2024-01-01T00:00:00Z',
        modifiedBy: 'system',
      };

      await dynamoDBDocumentClient.send(
        new PutCommand({
          TableName: remediationConfigTableName,
          Item: controlItem,
        }),
      );

      // Simulate concurrent modification by updating the control after scan but before transaction
      const filterId = '550e8400-e29b-41d4-a716-446655440000';

      // First apply succeeds
      const result1 = await repository.applyFilterToAllControls(filterId, 'admin-user', '2024-01-15T10:00:00Z');
      expect(result1.successCount).toBe(1);

      // Second apply with same filter should still succeed (idempotent ADD operation)
      // but version will increment
      const result2 = await repository.applyFilterToAllControls(filterId, 'admin-user', '2024-01-15T11:00:00Z');
      expect(result2.successCount).toBe(1);

      const updatedItem = await dynamoDBDocumentClient.send(
        new GetCommand({
          TableName: remediationConfigTableName,
          Key: { controlId: 'S3.1' },
        }),
      );
      expect(updatedItem.Item?.version).toBe(7);
    });
  });

  describe('removeFilterFromAllControls', () => {
    it('should remove filter from all controls successfully', async () => {
      // ARRANGE
      const filterId = '550e8400-e29b-41d4-a716-446655440000';
      const controlItems = [
        {
          controlId: 'S3.1',
          description: 'S3 control',
          automatedRemediationEnabled: false,
          filters: new Set([filterId, 'other-filter']),
          filterMode: 'include',
          version: 1,
          lastModified: '2024-01-01T00:00:00Z',
          modifiedBy: 'system',
        },
        {
          controlId: 'EC2.1',
          description: 'EC2 control',
          automatedRemediationEnabled: true,
          filters: new Set([filterId]),
          filterMode: 'exclude',
          version: 1,
          lastModified: '2024-01-01T00:00:00Z',
          modifiedBy: 'system',
        },
      ];

      await Promise.all(
        controlItems.map((item) =>
          dynamoDBDocumentClient.send(
            new PutCommand({
              TableName: remediationConfigTableName,
              Item: item,
            }),
          ),
        ),
      );

      // ACT
      const result = await repository.removeFilterFromAllControls(filterId, 'admin-user', '2024-01-15T10:00:00Z');

      // ASSERT
      expect(result.successCount).toBe(2);
      expect(result.failedControlIds).toHaveLength(0);

      const s3Control = await dynamoDBDocumentClient.send(
        new GetCommand({
          TableName: remediationConfigTableName,
          Key: { controlId: 'S3.1' },
        }),
      );
      expect(Array.from(s3Control.Item?.filters as Set<string>)).not.toContain(filterId);
      expect(Array.from(s3Control.Item?.filters as Set<string>)).toContain('other-filter');
      expect(s3Control.Item?.version).toBe(2);
      expect(s3Control.Item?.modifiedBy).toBe('admin-user');

      const ec2Control = await dynamoDBDocumentClient.send(
        new GetCommand({
          TableName: remediationConfigTableName,
          Key: { controlId: 'EC2.1' },
        }),
      );
      // When all filters are removed, the filters attribute may be empty or undefined
      const ec2Filters = ec2Control.Item?.filters;
      if (ec2Filters) {
        expect(Array.from(ec2Filters as Set<string>)).not.toContain(filterId);
      }
      expect(ec2Control.Item?.version).toBe(2);
    });

    it('should return zero updates when no controls exist', async () => {
      // ARRANGE - empty table
      const filterId = '550e8400-e29b-41d4-a716-446655440000';

      // ACT
      const result = await repository.removeFilterFromAllControls(filterId, 'admin-user', '2024-01-15T10:00:00Z');

      // ASSERT
      expect(result.successCount).toBe(0);
      expect(result.failedControlIds).toHaveLength(0);
    });

    it('should be idempotent when removing a filter that does not exist on controls', async () => {
      // ARRANGE
      const controlItem = {
        controlId: 'S3.1',
        description: 'S3 control',
        automatedRemediationEnabled: true,
        filters: new Set(['existing-filter']),
        filterMode: 'include',
        version: 1,
        lastModified: '2024-01-01T00:00:00Z',
        modifiedBy: 'system',
      };

      await dynamoDBDocumentClient.send(
        new PutCommand({
          TableName: remediationConfigTableName,
          Item: controlItem,
        }),
      );

      const nonExistentFilterId = 'non-existent-filter-uuid';

      // ACT
      const result = await repository.removeFilterFromAllControls(
        nonExistentFilterId,
        'admin-user',
        '2024-01-15T10:00:00Z',
      );

      // ASSERT
      expect(result.successCount).toBe(1);

      const updatedItem = await dynamoDBDocumentClient.send(
        new GetCommand({
          TableName: remediationConfigTableName,
          Key: { controlId: 'S3.1' },
        }),
      );
      const filters = Array.from(updatedItem.Item?.filters as Set<string>);
      expect(filters).toEqual(['existing-filter']);
      expect(updatedItem.Item?.version).toBe(2);
    });

    it('should preserve other control attributes when removing filter', async () => {
      // ARRANGE
      const filterId = '550e8400-e29b-41d4-a716-446655440000';
      const controlItem = {
        controlId: 'S3.1',
        description: 'S3 Block Public Access',
        automatedRemediationEnabled: true,
        filters: new Set([filterId, 'other-filter']),
        filterMode: 'exclude',
        version: 3,
        lastModified: '2024-01-01T00:00:00Z',
        modifiedBy: 'previous-user',
      };

      await dynamoDBDocumentClient.send(
        new PutCommand({
          TableName: remediationConfigTableName,
          Item: controlItem,
        }),
      );

      // ACT
      const result = await repository.removeFilterFromAllControls(filterId, 'admin-user', '2024-01-15T10:00:00Z');

      // ASSERT
      expect(result.successCount).toBe(1);

      const updatedItem = await dynamoDBDocumentClient.send(
        new GetCommand({
          TableName: remediationConfigTableName,
          Key: { controlId: 'S3.1' },
        }),
      );
      expect(updatedItem.Item?.description).toBe('S3 Block Public Access');
      expect(updatedItem.Item?.automatedRemediationEnabled).toBe(true);
      expect(updatedItem.Item?.filterMode).toBe('exclude');
      expect(updatedItem.Item?.version).toBe(4);
      expect(updatedItem.Item?.modifiedBy).toBe('admin-user');
      expect(updatedItem.Item?.lastModified).toBe('2024-01-15T10:00:00Z');
    });

    it('should handle controls without any filters attribute', async () => {
      // ARRANGE
      const controlItem = {
        controlId: 'S3.1',
        description: 'S3 control',
        automatedRemediationEnabled: false,
        filterMode: 'include',
        version: 1,
        lastModified: '2024-01-01T00:00:00Z',
        modifiedBy: 'system',
      };

      await dynamoDBDocumentClient.send(
        new PutCommand({
          TableName: remediationConfigTableName,
          Item: controlItem,
        }),
      );

      const filterId = '550e8400-e29b-41d4-a716-446655440000';

      // ACT
      const result = await repository.removeFilterFromAllControls(filterId, 'admin-user', '2024-01-15T10:00:00Z');

      // ASSERT
      expect(result.successCount).toBe(1);

      const updatedItem = await dynamoDBDocumentClient.send(
        new GetCommand({
          TableName: remediationConfigTableName,
          Key: { controlId: 'S3.1' },
        }),
      );
      expect(updatedItem.Item?.version).toBe(2);
    });

    it('should handle batch splitting when removing filter from more than 100 controls', async () => {
      // ARRANGE
      const controlCount = 150;
      const filterId = '550e8400-e29b-41d4-a716-446655440000';

      for (let i = 1; i <= controlCount; i++) {
        const controlItem = {
          controlId: `CTRL.${i}`,
          description: `Control ${i}`,
          automatedRemediationEnabled: false,
          filters: new Set([filterId, 'other-filter']),
          filterMode: 'include',
          version: 1,
          lastModified: '2024-01-01T00:00:00Z',
          modifiedBy: 'system',
        };
        await dynamoDBDocumentClient.send(
          new PutCommand({
            TableName: remediationConfigTableName,
            Item: controlItem,
          }),
        );
      }

      // ACT
      const result = await repository.removeFilterFromAllControls(filterId, 'admin-user', '2024-01-15T10:00:00Z');

      // ASSERT
      expect(result.successCount).toBe(controlCount);
      expect(result.failedControlIds).toHaveLength(0);

      const firstControl = await dynamoDBDocumentClient.send(
        new GetCommand({
          TableName: remediationConfigTableName,
          Key: { controlId: 'CTRL.1' },
        }),
      );
      expect(Array.from(firstControl.Item?.filters as Set<string>)).not.toContain(filterId);
      expect(Array.from(firstControl.Item?.filters as Set<string>)).toContain('other-filter');

      const lastControl = await dynamoDBDocumentClient.send(
        new GetCommand({
          TableName: remediationConfigTableName,
          Key: { controlId: `CTRL.${controlCount}` },
        }),
      );
      expect(Array.from(lastControl.Item?.filters as Set<string>)).not.toContain(filterId);
      expect(Array.from(lastControl.Item?.filters as Set<string>)).toContain('other-filter');
    });

    it('should handle controls with undefined version by defaulting to 1', async () => {
      // ARRANGE
      const filterId = '550e8400-e29b-41d4-a716-446655440000';
      const controlItem = {
        controlId: 'S3.1',
        description: 'S3 control',
        automatedRemediationEnabled: false,
        filters: new Set([filterId]),
        filterMode: 'include',
        lastModified: '2024-01-01T00:00:00Z',
        modifiedBy: 'system',
      };

      await dynamoDBDocumentClient.send(
        new PutCommand({
          TableName: remediationConfigTableName,
          Item: controlItem,
        }),
      );

      // ACT
      const result = await repository.removeFilterFromAllControls(filterId, 'admin-user', '2024-01-15T10:00:00Z');

      // ASSERT
      expect(result.successCount).toBe(1);

      const updatedItem = await dynamoDBDocumentClient.send(
        new GetCommand({
          TableName: remediationConfigTableName,
          Key: { controlId: 'S3.1' },
        }),
      );
      expect(updatedItem.Item?.version).toBe(2);
    });

    it('should handle mixed controls with and without version attribute', async () => {
      // ARRANGE
      const filterId = '550e8400-e29b-41d4-a716-446655440000';
      const controlWithVersion = {
        controlId: 'S3.1',
        description: 'S3 control with version',
        automatedRemediationEnabled: false,
        filters: new Set([filterId]),
        filterMode: 'include',
        version: 3,
        lastModified: '2024-01-01T00:00:00Z',
        modifiedBy: 'system',
      };

      const controlWithoutVersion = {
        controlId: 'EC2.1',
        description: 'EC2 control without version',
        automatedRemediationEnabled: true,
        filters: new Set([filterId, 'other-filter']),
        filterMode: 'exclude',
        lastModified: '2024-01-01T00:00:00Z',
        modifiedBy: 'system',
      };

      await Promise.all([
        dynamoDBDocumentClient.send(
          new PutCommand({
            TableName: remediationConfigTableName,
            Item: controlWithVersion,
          }),
        ),
        dynamoDBDocumentClient.send(
          new PutCommand({
            TableName: remediationConfigTableName,
            Item: controlWithoutVersion,
          }),
        ),
      ]);

      // ACT
      const result = await repository.removeFilterFromAllControls(filterId, 'admin-user', '2024-01-15T10:00:00Z');

      // ASSERT
      expect(result.successCount).toBe(2);
      expect(result.failedControlIds).toHaveLength(0);

      const s3Control = await dynamoDBDocumentClient.send(
        new GetCommand({
          TableName: remediationConfigTableName,
          Key: { controlId: 'S3.1' },
        }),
      );
      expect(s3Control.Item?.version).toBe(4);

      const ec2Control = await dynamoDBDocumentClient.send(
        new GetCommand({
          TableName: remediationConfigTableName,
          Key: { controlId: 'EC2.1' },
        }),
      );
      expect(ec2Control.Item?.version).toBe(2);
      expect(Array.from(ec2Control.Item?.filters as Set<string>)).toContain('other-filter');
      expect(Array.from(ec2Control.Item?.filters as Set<string>)).not.toContain(filterId);
    });

    it('should be idempotent when removing the same filter twice', async () => {
      // ARRANGE
      const filterId = '550e8400-e29b-41d4-a716-446655440000';
      const controlItem = {
        controlId: 'S3.1',
        description: 'S3 control',
        automatedRemediationEnabled: true,
        filters: new Set([filterId, 'other-filter']),
        filterMode: 'include',
        version: 1,
        lastModified: '2024-01-01T00:00:00Z',
        modifiedBy: 'system',
      };

      await dynamoDBDocumentClient.send(
        new PutCommand({
          TableName: remediationConfigTableName,
          Item: controlItem,
        }),
      );

      // ACT - First removal
      const result1 = await repository.removeFilterFromAllControls(filterId, 'admin-user', '2024-01-15T10:00:00Z');
      expect(result1.successCount).toBe(1);

      // ACT - Second removal (filter already removed)
      const result2 = await repository.removeFilterFromAllControls(filterId, 'admin-user', '2024-01-15T11:00:00Z');
      expect(result2.successCount).toBe(1);

      // ASSERT
      const updatedItem = await dynamoDBDocumentClient.send(
        new GetCommand({
          TableName: remediationConfigTableName,
          Key: { controlId: 'S3.1' },
        }),
      );
      expect(updatedItem.Item?.version).toBe(3);
      expect(Array.from(updatedItem.Item?.filters as Set<string>)).toEqual(['other-filter']);
    });

    it('should update lastModified and modifiedBy correctly', async () => {
      // ARRANGE
      const filterId = '550e8400-e29b-41d4-a716-446655440000';
      const controlItem = {
        controlId: 'S3.1',
        description: 'S3 control',
        automatedRemediationEnabled: true,
        filters: new Set([filterId]),
        filterMode: 'include',
        version: 1,
        lastModified: '2024-01-01T00:00:00Z',
        modifiedBy: 'original-user',
      };

      await dynamoDBDocumentClient.send(
        new PutCommand({
          TableName: remediationConfigTableName,
          Item: controlItem,
        }),
      );

      // ACT
      const result = await repository.removeFilterFromAllControls(filterId, 'new-admin', '2024-02-15T15:30:00Z');

      // ASSERT
      expect(result.successCount).toBe(1);

      const updatedItem = await dynamoDBDocumentClient.send(
        new GetCommand({
          TableName: remediationConfigTableName,
          Key: { controlId: 'S3.1' },
        }),
      );
      expect(updatedItem.Item?.lastModified).toBe('2024-02-15T15:30:00Z');
      expect(updatedItem.Item?.modifiedBy).toBe('new-admin');
    });
  });

  describe('batchFindByIds', () => {
    const insertControl = async (controlId: string) =>
      dynamoDBDocumentClient.send(
        new PutCommand({
          TableName: remediationConfigTableName,
          Item: {
            controlId,
            description: `Description for ${controlId}`,
            automatedRemediationEnabled: false,
            filters: new Set(['none']),
            filterMode: 'include',
            version: 1,
            lastModified: '2024-01-01T00:00:00Z',
            modifiedBy: 'admin',
          },
        }),
      );

    it('should return empty result when input list is empty', async () => {
      const result = await repository.batchFindByIds([]);
      expect(result).toEqual({ foundControlIds: [], isComplete: true });
    });

    it('should return only controlIds that exist in the table', async () => {
      await insertControl('S3.1');
      await insertControl('EC2.6');

      const result = await repository.batchFindByIds(['S3.1', 'EC2.6', 'MISSING.1']);

      expect(result.isComplete).toBe(true);
      expect(result.foundControlIds.sort()).toEqual(['EC2.6', 'S3.1']);
    });

    it('should deduplicate input controlIds before querying DynamoDB', async () => {
      await insertControl('S3.1');

      const result = await repository.batchFindByIds(['S3.1', 'S3.1', 'S3.1']);

      expect(result.foundControlIds).toEqual(['S3.1']);
    });

    it('should return an empty foundControlIds list when none of the inputs exist', async () => {
      const result = await repository.batchFindByIds(['MISSING.1', 'MISSING.2']);

      expect(result).toEqual({ foundControlIds: [], isComplete: true });
    });
  });

  describe('createCustomControlIfAbsent', () => {
    const deployment = {
      controlId: 'DynamoDB.2',
      description: 'Enable point-in-time recovery',
      modifiedBy: 'deployer',
      lastModified: '2026-09-22T00:00:00Z',
    };

    const readControl = async (controlId: string) =>
      (await dynamoDBDocumentClient.send(new GetCommand({ TableName: remediationConfigTableName, Key: { controlId } })))
        .Item;

    it('creates the row with source custom and remediation disabled when the control is new', async () => {
      await repository.createCustomControlIfAbsent(deployment);

      expect(await readControl('DynamoDB.2')).toEqual(
        expect.objectContaining({
          controlId: 'DynamoDB.2',
          description: 'Enable point-in-time recovery',
          source: 'custom',
          automatedRemediationEnabled: false,
          filterMode: 'include',
          version: 0,
          modifiedBy: 'deployer',
        }),
      );
    });

    it('stamps source custom onto the row the stack seeds for a built-in-supported control', async () => {
      // remediation_config_provider seeds a row for every such control with no `source`
      // attribute, so it reads back as builtin. Left unstamped, findCustomControlIds
      // misses the control and the update_controls guard fails OPEN: automated
      // remediation is enabled for a manual-trigger-only custom runbook.
      await dynamoDBDocumentClient.send(
        new PutCommand({
          TableName: remediationConfigTableName,
          Item: {
            controlId: 'DynamoDB.2',
            description: 'Seeded by the stack',
            automatedRemediationEnabled: true,
            filters: new Set(['prod-only']),
            filterMode: 'exclude',
            version: 4,
            lastModified: '2024-01-01T00:00:00Z',
            modifiedBy: 'system',
          },
        }),
      );

      await repository.createCustomControlIfAbsent(deployment);

      const item = await readControl('DynamoDB.2');
      expect(item?.source).toBe('custom');
      expect((await repository.findCustomControlIds(['DynamoDB.2'])).customControlIds).toEqual(new Set(['DynamoDB.2']));
    });

    it('preserves the administrator configuration on the row it stamps', async () => {
      // Only `source` may be written: a deploy must not silently re-enable, re-scope or
      // relabel a control an administrator has configured.
      await dynamoDBDocumentClient.send(
        new PutCommand({
          TableName: remediationConfigTableName,
          Item: {
            controlId: 'DynamoDB.2',
            description: 'Seeded by the stack',
            automatedRemediationEnabled: true,
            filters: new Set(['prod-only']),
            filterMode: 'exclude',
            version: 4,
            lastModified: '2024-01-01T00:00:00Z',
            modifiedBy: 'system',
          },
        }),
      );

      await repository.createCustomControlIfAbsent(deployment);

      expect(await readControl('DynamoDB.2')).toEqual(
        expect.objectContaining({
          description: 'Seeded by the stack',
          automatedRemediationEnabled: true,
          filters: new Set(['prod-only']),
          filterMode: 'exclude',
          version: 4,
          lastModified: '2024-01-01T00:00:00Z',
          modifiedBy: 'system',
        }),
      );
    });

    it('leaves a row that already declares a source alone', async () => {
      // A redeploy must not relabel a control the solution has already classified.
      await dynamoDBDocumentClient.send(
        new PutCommand({
          TableName: remediationConfigTableName,
          Item: { controlId: 'DynamoDB.2', description: 'Already classified', source: 'builtin', version: 2 },
        }),
      );

      await repository.createCustomControlIfAbsent(deployment);

      expect(await readControl('DynamoDB.2')).toEqual(
        expect.objectContaining({ source: 'builtin', description: 'Already classified', version: 2 }),
      );
    });

    it('is idempotent across repeated deploys of the same control', async () => {
      await repository.createCustomControlIfAbsent(deployment);
      await repository.createCustomControlIfAbsent({ ...deployment, modifiedBy: 'second-deployer' });

      expect(await readControl('DynamoDB.2')).toEqual(
        expect.objectContaining({ source: 'custom', modifiedBy: 'deployer', version: 0 }),
      );
    });
  });

  describe('findCustomControlIds', () => {
    const insertControl = async (controlId: string, source?: 'builtin' | 'custom') =>
      dynamoDBDocumentClient.send(
        new PutCommand({
          TableName: remediationConfigTableName,
          Item: {
            controlId,
            description: `Description for ${controlId}`,
            automatedRemediationEnabled: false,
            filters: new Set(['none']),
            filterMode: 'include',
            version: 1,
            lastModified: '2024-01-01T00:00:00Z',
            modifiedBy: 'admin',
            ...(source ? { source } : {}),
          },
        }),
      );

    it('should report only the controls whose source is custom', async () => {
      // `source` is a DynamoDB reserved word, so the projection aliases it. A wrong alias
      // returns no attribute at all, which would read as "nothing is custom" — the exact
      // shape that makes the caller's guard fail open.
      await insertControl('MCPProbe.1', 'custom');
      await insertControl('S3.1', 'builtin');
      // Written before `source` existed: absent means built-in.
      await insertControl('LEGACY.1');

      const result = await repository.findCustomControlIds(['MCPProbe.1', 'S3.1', 'LEGACY.1']);

      expect(result.isComplete).toBe(true);
      expect([...result.customControlIds]).toEqual(['MCPProbe.1']);
    });

    it('should not report a control that is absent from the table', async () => {
      // An unknown control fails the update for its own reasons; mislabelling it as custom
      // here would refuse an enable for a control that has no custom runbook.
      const result = await repository.findCustomControlIds(['MISSING.1']);

      expect(result).toEqual({ customControlIds: new Set(), isComplete: true });
    });

    it('should report a complete read for an empty input without calling DynamoDB', async () => {
      // `isComplete: true` matters here: false would make the caller refuse an update that
      // has nothing to look up.
      const result = await repository.findCustomControlIds([]);

      expect(result).toEqual({ customControlIds: new Set(), isComplete: true });
    });

    it('should deduplicate input controlIds before querying DynamoDB', async () => {
      // BatchGetItem rejects a request containing duplicate keys, so the dedup is required
      // rather than an optimisation.
      await insertControl('MCPProbe.1', 'custom');

      const result = await repository.findCustomControlIds(['MCPProbe.1', 'MCPProbe.1', 'MCPProbe.1']);

      expect([...result.customControlIds]).toEqual(['MCPProbe.1']);
    });
  });

  describe('findRemediationStateByControlIds', () => {
    const insertControl = async (controlId: string, automatedRemediationEnabled: boolean) =>
      dynamoDBDocumentClient.send(
        new PutCommand({
          TableName: remediationConfigTableName,
          Item: {
            controlId,
            description: `Description for ${controlId}`,
            automatedRemediationEnabled,
            filters: new Set(['none']),
            filterMode: 'include',
            version: 1,
            lastModified: '2024-01-01T00:00:00Z',
            modifiedBy: 'admin',
          },
        }),
      );

    it('returns an empty map when input list is empty', async () => {
      // ARRANGE / ACT
      const result = await repository.findRemediationStateByControlIds([]);

      // ASSERT
      expect(result.size).toBe(0);
    });

    it('maps each requested control to its current remediation state', async () => {
      // ARRANGE
      await insertControl('S3.1', true);
      await insertControl('EC2.6', false);

      // ACT
      const result = await repository.findRemediationStateByControlIds(['S3.1', 'EC2.6']);

      // ASSERT
      expect(result.get('S3.1')).toBe(true);
      expect(result.get('EC2.6')).toBe(false);
    });

    it('omits controls that do not exist and deduplicates input ids', async () => {
      // ARRANGE
      await insertControl('S3.1', true);

      // ACT
      const result = await repository.findRemediationStateByControlIds(['S3.1', 'S3.1', 'MISSING.1']);

      // ASSERT
      expect(result.size).toBe(1);
      expect(result.get('S3.1')).toBe(true);
      expect(result.has('MISSING.1')).toBe(false);
    });
  });
});
