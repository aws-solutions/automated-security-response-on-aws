// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { DynamoDBDocumentClient } from '@aws-sdk/lib-dynamodb';
import { MemberDeploymentState, RunbookId, RunbookMetadata } from '@asr/data-models';
import { CustomRunbookRepository, RunbookVersionConflictError } from '../repositories/customRunbookRepository';
import { NotFoundError } from '../utils/httpErrors';
import { DynamoDBTestSetup } from './dynamodbSetup';
import { customRunbookTableName } from './envSetup';

// Exercises the conditional-write concurrency guard against a real DynamoDB Local
// table — the mocked handler tests can't prove the ConditionalCheckFailed path.
describe('CustomRunbookRepository.createVersion (DynamoDB Local)', () => {
  let client: DynamoDBDocumentClient;
  let repo: CustomRunbookRepository;

  const runbook = (runbookId: string, version: number, overrides: Partial<RunbookMetadata> = {}): RunbookMetadata => ({
    runbookId: runbookId as RunbookId,
    version,
    controlId: 'S3.9',
    serviceName: 'S3',
    description: 'test',
    remediationAction: 'test',
    status: 'DRAFT',
    s3Key: `runbooks/${runbookId}/v${version}/runbook.yaml`,
    createdBy: 'test',
    createdAt: '2026-01-01T00:00:00Z',
    ...overrides,
  });

  beforeAll(async () => {
    client = DynamoDBTestSetup.getDocClient();
    await DynamoDBTestSetup.createCustomRunbookTable(customRunbookTableName);
    repo = new CustomRunbookRepository(customRunbookTableName, client);
  });

  afterAll(async () => {
    await DynamoDBTestSetup.deleteTable(customRunbookTableName);
  });

  it('creates a new (runbookId, version) record', async () => {
    await repo.createVersion(runbook('rb-1', 1));
    const latest = await repo.findLatestVersion('rb-1' as RunbookId);
    expect(latest?.version).toBe(1);
  });

  it('allows a higher version for the same runbookId', async () => {
    await repo.createVersion(runbook('rb-1', 2));
    const latest = await repo.findLatestVersion('rb-1' as RunbookId);
    expect(latest?.version).toBe(2);
  });

  it('rejects re-creating an existing (runbookId, version) with RunbookVersionConflictError', async () => {
    // rb-1 v1 already exists → the conditional write must fail rather than overwrite.
    await expect(repo.createVersion(runbook('rb-1', 1, { description: 'overwrite attempt' }))).rejects.toBeInstanceOf(
      RunbookVersionConflictError,
    );
    // Original record is untouched.
    const all = await repo.findByControlId('S3.9');
    const v1 = all.find((r) => r.runbookId === ('rb-1' as RunbookId) && r.version === 1);
    expect(v1?.description).toBe('test');
  });

  // recordMemberDeployment writes into a nested map that may not exist yet, which
  // DynamoDB constrains in ways a mocked client cannot demonstrate.
  describe('recordMemberDeployment', () => {
    const state = (overrides: Partial<MemberDeploymentState> = {}): MemberDeploymentState => ({
      runbookVersion: 1,
      ssmDocumentVersion: '1',
      status: 'DEPLOYED',
      attemptedAt: '2026-01-01T00:00:00.000Z',
      ...overrides,
    });

    beforeAll(async () => {
      await repo.createVersion(runbook('rb-members', 1));
    });

    it('creates deployedAccounts on first write for a record that has none', async () => {
      await repo.recordMemberDeployment('rb-members' as RunbookId, 1, '111111111111', state());

      const record = await repo.findLatestVersion('rb-members' as RunbookId);
      expect(record?.deployedAccounts).toEqual({ '111111111111': state() });
    });

    it('adds a second account without clobbering the first', async () => {
      await repo.recordMemberDeployment(
        'rb-members' as RunbookId,
        1,
        '222222222222',
        state({ status: 'FAILED', error: 'AccessDenied' }),
      );

      const record = await repo.findLatestVersion('rb-members' as RunbookId);
      expect(record?.deployedAccounts).toEqual({
        '111111111111': state(),
        '222222222222': state({ status: 'FAILED', error: 'AccessDenied' }),
      });
    });

    it('overwrites only the re-released account’s own entry', async () => {
      await repo.recordMemberDeployment(
        'rb-members' as RunbookId,
        1,
        '222222222222',
        state({ runbookVersion: 2, ssmDocumentVersion: '2' }),
      );

      const record = await repo.findLatestVersion('rb-members' as RunbookId);
      expect(record?.deployedAccounts?.['222222222222']).toEqual(state({ runbookVersion: 2, ssmDocumentVersion: '2' }));
      expect(record?.deployedAccounts?.['111111111111']).toEqual(state());
    });
  });

  // deployedAccounts is a per-version map and stageAccountsForNewVersion copies the whole
  // fleet forward, so an account released to version N lingers on every other version's map
  // with a stale runbookVersion. clearAccountFromOtherVersions removes it everywhere but the
  // version it now runs, so a later read of an older version (a rollback) does not count it
  // as still on that older version.
  describe('clearAccountFromOtherVersions', () => {
    const state = (version: number): MemberDeploymentState => ({
      runbookVersion: version,
      ssmDocumentVersion: String(version),
      status: 'DEPLOYED',
      attemptedAt: '2026-01-01T00:00:00.000Z',
    });

    beforeAll(async () => {
      await repo.createVersion(runbook('rb-clear', 1));
      await repo.createVersion(runbook('rb-clear', 2));
      // Account A appears on both version records — the stale state the clear fixes.
      await repo.recordMemberDeployment('rb-clear' as RunbookId, 1, '111111111111', state(1));
      await repo.recordMemberDeployment('rb-clear' as RunbookId, 2, '111111111111', state(2));
      await repo.recordMemberDeployment('rb-clear' as RunbookId, 2, '222222222222', state(2));
    });

    it('removes the account from every version except the one it now runs', async () => {
      await repo.clearAccountFromOtherVersions('rb-clear' as RunbookId, 2, '111111111111');

      const v1 = await repo.findVersion('rb-clear' as RunbookId, 1);
      const v2 = await repo.findVersion('rb-clear' as RunbookId, 2);
      // Cleared from v1 (the version it no longer runs)...
      expect(v1?.deployedAccounts?.['111111111111']).toBeUndefined();
      // ...but left intact on v2, and other accounts untouched.
      expect(v2?.deployedAccounts?.['111111111111']).toEqual(state(2));
      expect(v2?.deployedAccounts?.['222222222222']).toEqual(state(2));
    });

    it('is a no-op for a version that never listed the account', async () => {
      // Removing an absent key must not fail — the clear runs after a successful deploy and
      // must never turn that success into an error.
      await expect(
        repo.clearAccountFromOtherVersions('rb-clear' as RunbookId, 2, '999999999999'),
      ).resolves.toBeUndefined();
    });

    it('clears the account across many versions, not just the first query page', async () => {
      // The clear pages through every version. Seed the account on a run of versions and
      // confirm it is removed from all of them except the one it now runs — a single-page
      // read would leave the account stranded on the later versions.
      const runbookId = 'rb-clear-many' as RunbookId;
      const versions = [1, 2, 3, 4, 5];
      for (const version of versions) {
        await repo.createVersion(runbook('rb-clear-many', version));
        await repo.recordMemberDeployment(runbookId, version, '333333333333', state(version));
      }

      await repo.clearAccountFromOtherVersions(runbookId, 5, '333333333333');

      for (const version of versions.filter((v) => v !== 5)) {
        const record = await repo.findVersion(runbookId, version);
        expect(record?.deployedAccounts?.['333333333333']).toBeUndefined();
      }
      const kept = await repo.findVersion(runbookId, 5);
      expect(kept?.deployedAccounts?.['333333333333']).toEqual(state(5));
    });
  });

  // findAllVersions backs register's fleet reconstruction: it must return every version
  // record so staging can merge account state across them, even after a rollback empties the
  // numerically-highest record.
  describe('findAllVersions', () => {
    beforeAll(async () => {
      await repo.createVersion(runbook('rb-all', 1));
      await repo.createVersion(runbook('rb-all', 2));
      await repo.createVersion(runbook('rb-all', 3));
    });

    it('returns every version record for the runbook', async () => {
      const versions = await repo.findAllVersions('rb-all' as RunbookId);

      expect(versions.map((record) => record.version).sort((a, b) => a - b)).toEqual([1, 2, 3]);
    });

    it('returns an empty array for an unknown runbook', async () => {
      expect(await repo.findAllVersions('rb-none' as RunbookId)).toEqual([]);
    });
  });

  // recordMemberDeployment and updateStatus both guard their UpdateItem with
  // attribute_exists(runbookId). Without it, DynamoDB's upsert would resurrect a
  // deleted/missing (runbookId, version) as a key-only phantom; the guard turns
  // that into an explicit NotFoundError. Exercised against DynamoDB Local because a
  // mocked client can't reproduce the ConditionalCheckFailed.
  describe('missing-record guard', () => {
    const orphanState: MemberDeploymentState = {
      runbookVersion: 1,
      ssmDocumentVersion: '1',
      status: 'DEPLOYED',
      attemptedAt: '2026-01-01T00:00:00.000Z',
    };

    it('recordMemberDeployment on a missing record throws NotFoundError', async () => {
      await expect(
        repo.recordMemberDeployment('rb-missing' as RunbookId, 7, '111111111111', orphanState),
      ).rejects.toBeInstanceOf(NotFoundError);
    });

    it('updateStatus on a missing record throws NotFoundError', async () => {
      await expect(repo.updateStatus('rb-missing' as RunbookId, 7, 'DEPLOYED')).rejects.toBeInstanceOf(NotFoundError);
    });
  });

  // findDeployedVersions projects a subset of attributes and maps them onto
  // DeployedRunbookControl by hand. The mapper makes an unprojected interface field a
  // compile error; only a real scan catches the other direction — an attribute dropped
  // from the ProjectionExpression, which would surface as a silently undefined field.
  describe('findDeployedVersions', () => {
    it('returns every field of DeployedRunbookControl populated from the projection', async () => {
      await repo.createVersion(
        runbook('rb-projected', 1, {
          status: 'DEPLOYED',
          description: 'projected description',
          createdBy: 'operator@example.com',
          createdAt: '2026-02-02T00:00:00Z',
          deployedAt: '2026-02-03T00:00:00Z',
        }),
      );

      const deployed = await repo.findDeployedVersions();
      const record = deployed.find((candidate) => candidate.runbookId === ('rb-projected' as RunbookId));

      expect(record).toEqual({
        runbookId: 'rb-projected',
        version: 1,
        controlId: 'S3.9',
        description: 'projected description',
        createdAt: '2026-02-02T00:00:00Z',
        createdBy: 'operator@example.com',
        deployedAt: '2026-02-03T00:00:00Z',
      });
      // No field may be undefined: that is exactly what a dropped projection attribute
      // looks like, and it reaches the controls list rather than failing.
      expect(Object.values(record ?? {}).some((value) => value === undefined)).toBe(false);
    });

    it('omits versions that are not DEPLOYED', async () => {
      await repo.createVersion(runbook('rb-draft-only', 1, { status: 'DRAFT' }));

      const deployed = await repo.findDeployedVersions();

      expect(deployed.map((candidate) => candidate.runbookId)).not.toContain('rb-draft-only');
    });
  });
});
