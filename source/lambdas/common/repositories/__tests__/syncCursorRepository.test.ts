// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Persistence tests for the per-account synchronization cursor and the fleet-wide sweep record. They
// run against a REAL DynamoDB Local table (never mocked) so key schemas, scope isolation, and the
// conditional (optimistic-concurrency) writes are exercised with real database semantics.

import { DynamoDBDocumentClient, QueryCommand, ScanCommand } from '@aws-sdk/lib-dynamodb';
import { StaleCursorError, SyncCursor, SyncCursorRepository, SyncSweep } from '../syncCursorRepository';
import { DynamoDBTestSetup } from '../../__tests__/dynamodbSetup';
import { findingsTableName } from '../../__tests__/envSetup';

describe('SyncCursorRepository (real DynamoDB Local)', () => {
  const principal = 'synchronization';
  let dynamoDBDocumentClient: DynamoDBDocumentClient;
  let repository: SyncCursorRepository;

  beforeAll(async () => {
    dynamoDBDocumentClient = DynamoDBTestSetup.getDocClient();
    await DynamoDBTestSetup.createFindingsTable(findingsTableName);
  });

  afterAll(async () => {
    await DynamoDBTestSetup.deleteTable(findingsTableName);
  });

  beforeEach(async () => {
    await DynamoDBTestSetup.clearTable(findingsTableName, 'findings');
    repository = new SyncCursorRepository(principal, findingsTableName, dynamoDBDocumentClient);
  });

  describe('per-account cursors', () => {
    it('keeps each account cursor independent', async () => {
      // GIVEN two accounts each reset to their own control count
      await repository.resetCursor('111111111111', 3);
      await repository.resetCursor('222222222222', 7);

      // WHEN one account's cursor advances
      const cursorA = (await repository.getCursor('111111111111')) as SyncCursor;
      cursorA.completedControlIds = ['A.1'];
      await repository.saveCursor('111111111111', cursorA);

      // THEN the other account's cursor is untouched
      const cursorB = await repository.getCursor('222222222222');
      expect(cursorB?.completedControlIds).toEqual([]);
      expect(cursorB?.totalControlIds).toBe(7);
      const reloadedA = await repository.getCursor('111111111111');
      expect(reloadedA?.completedControlIds).toEqual(['A.1']);
    });

    it('returns null for an account that has never synced', async () => {
      expect(await repository.getCursor('999999999999')).toBeNull();
    });

    it('guards each account scope independently with the version condition', async () => {
      // GIVEN a fresh cursor for one account (version 1) that then advances to version 2
      const fresh = await repository.resetCursor('111111111111', 1);
      const staleHandle: SyncCursor = { ...fresh };
      await repository.saveCursor('111111111111', fresh);

      // WHEN a stale writer tries to save the same account THEN it is rejected
      await expect(repository.saveCursor('111111111111', staleHandle)).rejects.toBeInstanceOf(StaleCursorError);

      // But the SAME stale version is accepted for a DIFFERENT account (independent version chains)
      await expect(repository.saveCursor('222222222222', staleHandle)).resolves.toBeDefined();
    });
  });

  describe('sweep record', () => {
    it('round-trips and advances its version on save', async () => {
      // GIVEN a fresh sweep record
      const created = await repository.saveSweep({
        totalAccounts: 308,
        startedAt: '2026-07-08T00:00:00.000Z',
        done: false,
        version: 0,
      });
      expect(created.version).toBe(1);

      // WHEN it is read back and marked done
      const loaded = (await repository.getSweep()) as SyncSweep;
      expect(loaded.totalAccounts).toBe(308);
      expect(loaded.done).toBe(false);

      loaded.done = true;
      const advanced = await repository.saveSweep(loaded);

      // THEN the persisted record reflects the update at the next version
      expect(advanced.version).toBe(2);
      expect((await repository.getSweep())?.done).toBe(true);
    });

    it('returns null before any sweep starts', async () => {
      expect(await repository.getSweep()).toBeNull();
    });

    it('marks the current sweep done via saveSweepDone', async () => {
      await repository.resetSweep(2);

      await repository.saveSweepDone();

      expect((await repository.getSweep())?.done).toBe(true);
    });

    it('rejects a stale sweep writer via the version guard', async () => {
      const created = await repository.saveSweep({
        totalAccounts: 2,
        startedAt: '2026-07-08T00:00:00.000Z',
        done: false,
        version: 0,
      });
      const staleHandle: SyncSweep = { ...created };
      await repository.saveSweep(created); // advances stored version

      await expect(repository.saveSweep(staleHandle)).rejects.toBeInstanceOf(StaleCursorError);
    });
  });

  describe('countCompletedAccounts (derived progress)', () => {
    it('counts only account cursors that are marked done', async () => {
      // GIVEN three account cursors: two done, one still in progress
      await repository.resetCursor('111111111111', 1);
      await repository.resetCursor('222222222222', 1);
      await repository.resetCursor('333333333333', 1);
      for (const accountId of ['111111111111', '222222222222']) {
        const cursor = (await repository.getCursor(accountId)) as SyncCursor;
        cursor.done = true;
        await repository.saveCursor(accountId, cursor);
      }

      // WHEN / THEN the derived count reflects only the done cursors
      expect(await repository.countCompletedAccounts()).toBe(2);
    });

    it('returns zero when no account has completed', async () => {
      await repository.resetCursor('111111111111', 1);
      expect(await repository.countCompletedAccounts()).toBe(0);
    });

    it('counts only cursors completed at or after the given sweep start', async () => {
      // Cursors are reset lazily per account, not cleared at sweep start, so a cursor left done from a
      // previous sweep must NOT be counted toward the current sweep's progress. A controllable clock
      // stamps each completion at a known lastSyncedAt so the sweep-start bound can be exercised.
      let currentTime = new Date('2026-07-08T00:00:00.000Z');
      const clock = { now: () => currentTime };
      const clockedRepository = new SyncCursorRepository(principal, findingsTableName, dynamoDBDocumentClient, clock);

      const completeAccount = async (accountId: string) => {
        await clockedRepository.resetCursor(accountId, 1);
        const cursor = (await clockedRepository.getCursor(accountId)) as SyncCursor;
        cursor.done = true;
        await clockedRepository.saveCursor(accountId, cursor);
      };

      // GIVEN one account completed during the previous sweep, then a new sweep starts...
      await completeAccount('111111111111');
      const previousSweepCompletion = currentTime.toISOString();
      const newSweepStartedAt = '2026-07-15T00:00:00.000Z';

      // ...and one account completes during the new sweep
      currentTime = new Date('2026-07-15T00:05:00.000Z');
      await completeAccount('222222222222');

      // THEN only the account completed in the new sweep counts toward its progress
      expect(await clockedRepository.countCompletedAccounts(newSweepStartedAt)).toBe(1);
      // A bound at the previous completion still includes both
      expect(await clockedRepository.countCompletedAccounts(previousSweepCompletion)).toBe(2);
      // And the unbounded count is unchanged (legacy behaviour)
      expect(await clockedRepository.countCompletedAccounts()).toBe(2);
    });
  });

  describe('isolation from finding reads', () => {
    it('keeps cursor and sweep items out of the findings reader GSI', async () => {
      // GIVEN a cursor and a sweep record for one account
      await repository.resetCursor('111111111111', 1);
      await repository.saveSweep({
        totalAccounts: 1,
        startedAt: '2026-07-08T00:00:00.000Z',
        done: false,
        version: 0,
      });

      // WHEN the findings reader GSI (keyed on FINDING_CONSTANT='finding') is queried
      const readerVisible = await dynamoDBDocumentClient.send(
        new QueryCommand({
          TableName: findingsTableName,
          IndexName: 'allFindings-securityHubUpdatedAtTime-GSI',
          KeyConditionExpression: 'FINDING_CONSTANT = :c',
          ExpressionAttributeValues: { ':c': 'finding' },
        }),
      );

      // THEN none of the sync bookkeeping items surface
      expect(readerVisible.Items ?? []).toHaveLength(0);

      // But they really are in the base table (a full scan sees both).
      const all = await dynamoDBDocumentClient.send(new ScanCommand({ TableName: findingsTableName }));
      const partitions = (all.Items ?? []).map((item) => item.findingType);
      expect(partitions).toEqual(expect.arrayContaining(['SYNC_CURSOR', 'SYNC_SWEEP']));
    });
  });
});
