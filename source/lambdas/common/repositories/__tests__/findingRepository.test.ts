// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { DynamoDBDocumentClient, GetCommand, PutCommand } from '@aws-sdk/lib-dynamodb';
import { FindingRepository, ValidationError } from '../findingRepository';
import { DynamoDBTestSetup } from '../../__tests__/dynamodbSetup';
import { findingsTableName } from '../../__tests__/envSetup';

/**
 * Builds a findings table item with sensible defaults, letting each test
 * override only the fields relevant to the behavior under test.
 */
const createFindingItem = (overrides: Record<string, unknown> = {}): Record<string, unknown> => ({
  findingType: 'S3.1',
  findingId: 'finding-001',
  remediationStatus: 'NOT_STARTED',
  FINDING_CONSTANT: 'finding',
  ...overrides,
});

describe('FindingRepository', () => {
  let repository: FindingRepository;
  let dynamoDBDocumentClient: DynamoDBDocumentClient;

  const putFinding = (item: Record<string, unknown>): Promise<unknown> =>
    dynamoDBDocumentClient.send(new PutCommand({ TableName: findingsTableName, Item: item }));

  const getFinding = (findingType: string, findingId: string) =>
    dynamoDBDocumentClient.send(new GetCommand({ TableName: findingsTableName, Key: { findingType, findingId } }));

  beforeAll(async () => {
    dynamoDBDocumentClient = DynamoDBTestSetup.getDocClient();
    await DynamoDBTestSetup.createFindingsTable(findingsTableName);
  });

  afterAll(async () => {
    await DynamoDBTestSetup.deleteTable(findingsTableName);
  });

  beforeEach(async () => {
    await DynamoDBTestSetup.clearTable(findingsTableName, 'findings');
    repository = new FindingRepository('test-principal', findingsTableName, dynamoDBDocumentClient);
  });

  describe('stampRemediationDueBy', () => {
    it('should ADD configIds and SET remediationDueBy when attribute does not exist', async () => {
      // ARRANGE
      await putFinding(createFindingItem({ findingId: 'finding-001' }));

      // ACT
      const result = await repository.stampRemediationDueBy('finding-001', 'S3.1', '2025-02-15T00:00:00Z', [
        'config-a',
        'config-b',
      ]);

      // ASSERT
      expect(result.configIdsUpdated).toBe(true);
      expect(result.dueByUpdated).toBe(true);

      const item = await getFinding('S3.1', 'finding-001');
      expect(item.Item?.remediationDueBy).toBe('2025-02-15T00:00:00Z');
      const configIds = item.Item?.enforcementConfigIds;
      expect(configIds).toBeInstanceOf(Set);
      expect(Array.from(configIds as Set<string>).sort()).toEqual(['config-a', 'config-b']);
    });

    it('should update remediationDueBy when new value is earlier than existing (monotonicity: earlier accepted)', async () => {
      // ARRANGE
      await putFinding(
        createFindingItem({
          findingId: 'finding-002',
          remediationDueBy: '2025-03-01T00:00:00Z',
          enforcementConfigIds: new Set(['config-a']),
        }),
      );

      // ACT
      const result = await repository.stampRemediationDueBy('finding-002', 'S3.1', '2025-02-01T00:00:00Z', [
        'config-b',
      ]);

      // ASSERT
      expect(result.configIdsUpdated).toBe(true);
      expect(result.dueByUpdated).toBe(true);

      const item = await getFinding('S3.1', 'finding-002');
      expect(item.Item?.remediationDueBy).toBe('2025-02-01T00:00:00Z');
      const configIds = Array.from(item.Item?.enforcementConfigIds as Set<string>).sort();
      expect(configIds).toEqual(['config-a', 'config-b']);
    });

    it('should reject remediationDueBy when new value equals existing (monotonicity: equal rejected)', async () => {
      // ARRANGE
      await putFinding(
        createFindingItem({
          findingId: 'finding-003',
          remediationDueBy: '2025-02-15T00:00:00Z',
          enforcementConfigIds: new Set(['config-a']),
        }),
      );

      // ACT
      const result = await repository.stampRemediationDueBy('finding-003', 'S3.1', '2025-02-15T00:00:00Z', [
        'config-b',
      ]);

      // ASSERT
      expect(result.configIdsUpdated).toBe(true);
      expect(result.dueByUpdated).toBe(false);

      const item = await getFinding('S3.1', 'finding-003');
      expect(item.Item?.remediationDueBy).toBe('2025-02-15T00:00:00Z');
      const configIds = Array.from(item.Item?.enforcementConfigIds as Set<string>).sort();
      expect(configIds).toEqual(['config-a', 'config-b']);
    });

    it('should reject remediationDueBy when new value is later than existing (monotonicity: later rejected)', async () => {
      // ARRANGE
      await putFinding(
        createFindingItem({
          findingId: 'finding-004',
          remediationDueBy: '2025-01-01T00:00:00Z',
          enforcementConfigIds: new Set(['config-a']),
        }),
      );

      // ACT
      const result = await repository.stampRemediationDueBy('finding-004', 'S3.1', '2025-03-01T00:00:00Z', [
        'config-c',
      ]);

      // ASSERT
      expect(result.configIdsUpdated).toBe(true);
      expect(result.dueByUpdated).toBe(false);

      const item = await getFinding('S3.1', 'finding-004');
      expect(item.Item?.remediationDueBy).toBe('2025-01-01T00:00:00Z');
      const configIds = Array.from(item.Item?.enforcementConfigIds as Set<string>).sort();
      expect(configIds).toEqual(['config-a', 'config-c']);
    });

    it('should throw when configIds is empty', async () => {
      // ARRANGE / ACT / ASSERT
      await expect(repository.stampRemediationDueBy('finding-005', 'S3.1', '2025-02-15T00:00:00Z', [])).rejects.toThrow(
        ValidationError,
      );
    });

    it('should throw ValidationError for missing key components or remediationDueBy before writing', async () => {
      // ARRANGE
      const dueBy = '2025-02-15T00:00:00Z';
      const configIds = ['config-a'];

      // ACT & ASSERT
      await expect(repository.stampRemediationDueBy('', 'S3.1', dueBy, configIds)).rejects.toThrow(ValidationError);
      await expect(repository.stampRemediationDueBy('finding-006', '', dueBy, configIds)).rejects.toThrow(
        ValidationError,
      );
      await expect(repository.stampRemediationDueBy('finding-006', 'S3.1', '   ', configIds)).rejects.toThrow(
        ValidationError,
      );
    });
  });

  describe('forceStampRemediationDueBy', () => {
    it('should unconditionally overwrite remediationDueBy and enforcementConfigIds', async () => {
      // ARRANGE
      await putFinding(
        createFindingItem({
          findingType: 'EC2.1',
          findingId: 'finding-010',
          remediationDueBy: '2025-01-01T00:00:00Z',
          enforcementConfigIds: new Set(['old-config-1', 'old-config-2']),
        }),
      );

      // ACT
      await repository.forceStampRemediationDueBy('finding-010', 'EC2.1', '2025-06-01T00:00:00Z', ['new-config-x']);

      // ASSERT
      const item = await getFinding('EC2.1', 'finding-010');
      expect(item.Item?.remediationDueBy).toBe('2025-06-01T00:00:00Z');
      const configIds = Array.from(item.Item?.enforcementConfigIds as Set<string>);
      expect(configIds).toEqual(['new-config-x']);
    });

    it('should set remediationDueBy on a finding that has no existing value', async () => {
      // ARRANGE
      await putFinding(createFindingItem({ findingType: 'EC2.1', findingId: 'finding-011' }));

      // ACT
      await repository.forceStampRemediationDueBy('finding-011', 'EC2.1', '2025-04-01T00:00:00Z', [
        'config-1',
        'config-2',
      ]);

      // ASSERT
      const item = await getFinding('EC2.1', 'finding-011');
      expect(item.Item?.remediationDueBy).toBe('2025-04-01T00:00:00Z');
      const configIds = Array.from(item.Item?.enforcementConfigIds as Set<string>).sort();
      expect(configIds).toEqual(['config-1', 'config-2']);
    });

    it('should throw when configIds is empty', async () => {
      // ARRANGE / ACT / ASSERT
      await expect(
        repository.forceStampRemediationDueBy('finding-012', 'EC2.1', '2025-04-01T00:00:00Z', []),
      ).rejects.toThrow(ValidationError);
    });

    it('should throw ValidationError for missing key components or remediationDueBy before writing', async () => {
      // ARRANGE
      const dueBy = '2025-04-01T00:00:00Z';
      const configIds = ['config-1'];

      // ACT & ASSERT
      await expect(repository.forceStampRemediationDueBy('', 'EC2.1', dueBy, configIds)).rejects.toThrow(
        ValidationError,
      );
      await expect(repository.forceStampRemediationDueBy('finding-013', '', dueBy, configIds)).rejects.toThrow(
        ValidationError,
      );
      await expect(repository.forceStampRemediationDueBy('finding-013', 'EC2.1', '', configIds)).rejects.toThrow(
        ValidationError,
      );
    });
  });

  describe('clearRemediationDueBy', () => {
    it('should remove both remediationDueBy and enforcementConfigIds attributes', async () => {
      // ARRANGE
      await putFinding(
        createFindingItem({
          findingType: 'RDS.1',
          findingId: 'finding-020',
          remediationDueBy: '2025-03-01T00:00:00Z',
          enforcementConfigIds: new Set(['config-1', 'config-2']),
        }),
      );

      // ACT
      await repository.clearRemediationDueBy('finding-020', 'RDS.1');

      // ASSERT
      const item = await getFinding('RDS.1', 'finding-020');
      expect(item.Item?.remediationDueBy).toBeUndefined();
      expect(item.Item?.enforcementConfigIds).toBeUndefined();
      expect(item.Item?.remediationStatus).toBe('NOT_STARTED');
    });

    it('should succeed even when attributes do not exist', async () => {
      // ARRANGE
      await putFinding(createFindingItem({ findingType: 'RDS.1', findingId: 'finding-021' }));

      // ACT & ASSERT (no error thrown)
      await expect(repository.clearRemediationDueBy('finding-021', 'RDS.1')).resolves.not.toThrow();
    });

    it('should throw ValidationError when findingId or controlId is empty', async () => {
      // ARRANGE / ACT / ASSERT
      await expect(repository.clearRemediationDueBy('', 'RDS.1')).rejects.toThrow(ValidationError);
      await expect(repository.clearRemediationDueBy('finding-022', '')).rejects.toThrow(ValidationError);
    });
  });

  describe('queryFindingsByDueBy', () => {
    it('should return findings with remediationDueBy earlier than currentTime', async () => {
      // ARRANGE
      const findings = [
        createFindingItem({ findingId: 'overdue-1', remediationDueBy: '2025-01-01T00:00:00Z' }),
        createFindingItem({ findingId: 'overdue-2', remediationDueBy: '2025-01-15T00:00:00Z' }),
        createFindingItem({ findingId: 'not-overdue', remediationDueBy: '2025-06-01T00:00:00Z' }),
      ];
      await Promise.all(findings.map(putFinding));

      // ACT
      const result = await repository.queryFindingsByDueBy('2025-02-01T00:00:00Z');

      // ASSERT
      expect(result.items).toHaveLength(2);
      const findingIds = result.items.map((i) => i.findingId);
      expect(findingIds).toContain('overdue-1');
      expect(findingIds).toContain('overdue-2');
      expect(findingIds).not.toContain('not-overdue');
    });

    it('should return results sorted ascending by remediationDueBy (oldest overdue first)', async () => {
      // ARRANGE
      const findings = [
        createFindingItem({
          findingType: 'EC2.1',
          findingId: 'third-overdue',
          remediationDueBy: '2025-01-20T00:00:00Z',
        }),
        createFindingItem({
          findingType: 'EC2.1',
          findingId: 'first-overdue',
          remediationDueBy: '2025-01-01T00:00:00Z',
        }),
        createFindingItem({
          findingType: 'EC2.1',
          findingId: 'second-overdue',
          remediationDueBy: '2025-01-10T00:00:00Z',
        }),
      ];
      await Promise.all(findings.map(putFinding));

      // ACT
      const result = await repository.queryFindingsByDueBy('2025-02-01T00:00:00Z');

      // ASSERT
      expect(result.items).toHaveLength(3);
      expect(result.items[0].findingId).toBe('first-overdue');
      expect(result.items[1].findingId).toBe('second-overdue');
      expect(result.items[2].findingId).toBe('third-overdue');
    });

    it('should support pagination via limit and exclusiveStartKey', async () => {
      // ARRANGE
      const findings = [
        createFindingItem({ findingId: 'page-1', remediationDueBy: '2025-01-01T00:00:00Z' }),
        createFindingItem({ findingId: 'page-2', remediationDueBy: '2025-01-02T00:00:00Z' }),
        createFindingItem({ findingId: 'page-3', remediationDueBy: '2025-01-03T00:00:00Z' }),
      ];
      await Promise.all(findings.map(putFinding));

      // ACT - first page
      const firstPage = await repository.queryFindingsByDueBy('2025-02-01T00:00:00Z', { limit: 2 });

      // ASSERT - first page
      expect(firstPage.items).toHaveLength(2);
      expect(firstPage.lastEvaluatedKey).toBeDefined();

      // ACT - second page
      const secondPage = await repository.queryFindingsByDueBy('2025-02-01T00:00:00Z', {
        limit: 2,
        exclusiveStartKey: firstPage.lastEvaluatedKey,
      });

      // ASSERT - second page
      expect(secondPage.items).toHaveLength(1);
      expect(secondPage.lastEvaluatedKey).toBeUndefined();

      const allIds = [...firstPage.items, ...secondPage.items].map((i) => i.findingId);
      expect(allIds).toEqual(['page-1', 'page-2', 'page-3']);
    });

    it('should return empty results when no findings are overdue', async () => {
      // ARRANGE
      await putFinding(createFindingItem({ findingId: 'future-finding', remediationDueBy: '2099-01-01T00:00:00Z' }));

      // ACT
      const result = await repository.queryFindingsByDueBy('2025-02-01T00:00:00Z');

      // ASSERT
      expect(result.items).toHaveLength(0);
      expect(result.lastEvaluatedKey).toBeUndefined();
    });

    it('should only index findings that have a remediationDueBy attribute (sparse GSI)', async () => {
      // ARRANGE
      const findings = [
        createFindingItem({ findingId: 'has-due-by', remediationDueBy: '2025-01-01T00:00:00Z' }),
        createFindingItem({ findingId: 'no-due-by' }),
      ];
      await Promise.all(findings.map(putFinding));

      // ACT
      const result = await repository.queryFindingsByDueBy('2025-12-01T00:00:00Z');

      // ASSERT
      expect(result.items).toHaveLength(1);
      expect(result.items[0].findingId).toBe('has-due-by');
    });

    it('bounds the page to FINDINGS_PAGE_SIZE (50) by default and clamps larger caller limits', async () => {
      // ARRANGE — 51 overdue findings; the default/clamped page size is 50
      const findings = Array.from({ length: 51 }, (_, i) =>
        createFindingItem({
          findingId: `overdue-${String(i).padStart(3, '0')}`,
          remediationDueBy: `2025-01-01T00:00:${String(i).padStart(2, '0')}Z`,
        }),
      );
      await Promise.all(findings.map(putFinding));

      // ACT & ASSERT — no limit supplied: page capped at 50 with a continuation key
      const defaultPage = await repository.queryFindingsByDueBy('2025-06-01T00:00:00Z');
      expect(defaultPage.items).toHaveLength(50);
      expect(defaultPage.lastEvaluatedKey).toBeDefined();

      // ACT & ASSERT — oversized caller limit is clamped to 50
      const clampedPage = await repository.queryFindingsByDueBy('2025-06-01T00:00:00Z', { limit: 1000 });
      expect(clampedPage.items).toHaveLength(50);
      expect(clampedPage.lastEvaluatedKey).toBeDefined();
    });
  });

  describe('queryAllStampedFindings', () => {
    it('returns every stamped finding regardless of due date (no overdue filtering, sparse GSI)', async () => {
      // ARRANGE — overdue, not-yet-overdue, and an unstamped finding
      const findings = [
        createFindingItem({ findingId: 'overdue-stamped', remediationDueBy: '2025-01-01T00:00:00Z' }),
        createFindingItem({ findingId: 'future-stamped', remediationDueBy: '2099-01-01T00:00:00Z' }),
        createFindingItem({ findingId: 'unstamped' }),
      ];
      await Promise.all(findings.map(putFinding));

      // ACT
      const result = await repository.queryAllStampedFindings();

      // ASSERT — both stamped findings returned, the unstamped one excluded by the sparse GSI
      const findingIds = result.items.map((item) => item.findingId);
      expect(result.items).toHaveLength(2);
      expect(findingIds).toContain('overdue-stamped');
      expect(findingIds).toContain('future-stamped');
      expect(findingIds).not.toContain('unstamped');
    });

    it('returns results sorted ascending by remediationDueBy', async () => {
      // ARRANGE
      const findings = [
        createFindingItem({ findingType: 'EC2.1', findingId: 'latest', remediationDueBy: '2025-03-01T00:00:00Z' }),
        createFindingItem({ findingType: 'EC2.1', findingId: 'earliest', remediationDueBy: '2025-01-01T00:00:00Z' }),
        createFindingItem({ findingType: 'EC2.1', findingId: 'middle', remediationDueBy: '2025-02-01T00:00:00Z' }),
      ];
      await Promise.all(findings.map(putFinding));

      // ACT
      const result = await repository.queryAllStampedFindings();

      // ASSERT
      expect(result.items.map((item) => item.findingId)).toEqual(['earliest', 'middle', 'latest']);
    });

    it('supports pagination via limit and exclusiveStartKey (bookmark resume)', async () => {
      // ARRANGE
      const findings = [
        createFindingItem({ findingId: 'page-1', remediationDueBy: '2025-01-01T00:00:00Z' }),
        createFindingItem({ findingId: 'page-2', remediationDueBy: '2025-01-02T00:00:00Z' }),
        createFindingItem({ findingId: 'page-3', remediationDueBy: '2025-01-03T00:00:00Z' }),
      ];
      await Promise.all(findings.map(putFinding));

      // ACT — first page, then resume from the bookmark
      const firstPage = await repository.queryAllStampedFindings({ limit: 2 });
      const secondPage = await repository.queryAllStampedFindings({
        limit: 2,
        exclusiveStartKey: firstPage.lastEvaluatedKey,
      });

      // ASSERT
      expect(firstPage.items).toHaveLength(2);
      expect(firstPage.lastEvaluatedKey).toBeDefined();
      expect(secondPage.items).toHaveLength(1);
      expect(secondPage.lastEvaluatedKey).toBeUndefined();

      const allIds = [...firstPage.items, ...secondPage.items].map((item) => item.findingId);
      expect(allIds).toEqual(['page-1', 'page-2', 'page-3']);
    });
  });

  describe('findByKeys', () => {
    it('returns findings for explicit findingType/findingId key pairs without re-deriving the partition key', async () => {
      // ARRANGE
      await putFinding(createFindingItem({ findingType: 'security-control/S3.1', findingId: 'finding-a' }));
      await putFinding(createFindingItem({ findingType: 'security-control/Lambda.3', findingId: 'finding-b' }));

      // ACT
      const items = await repository.findByKeys([
        { findingType: 'security-control/S3.1', findingId: 'finding-a' },
        { findingType: 'security-control/Lambda.3', findingId: 'finding-b' },
      ]);

      // ASSERT
      expect(items.map((item) => item.findingId).sort()).toEqual(['finding-a', 'finding-b']);
    });

    it('returns an empty array when given no keys', async () => {
      // ARRANGE / ACT
      const items = await repository.findByKeys([]);

      // ASSERT
      expect(items).toEqual([]);
    });

    it('returns only the findings that exist when some keys are missing', async () => {
      // ARRANGE
      await putFinding(createFindingItem({ findingType: 'security-control/S3.1', findingId: 'present' }));

      // ACT
      const items = await repository.findByKeys([
        { findingType: 'security-control/S3.1', findingId: 'present' },
        { findingType: 'security-control/S3.1', findingId: 'absent' },
      ]);

      // ASSERT
      expect(items).toHaveLength(1);
      expect(items[0].findingId).toBe('present');
    });

    it('returns an empty array when the batch get fails', async () => {
      // ARRANGE — repository pointed at a table that does not exist so BatchGetItem throws
      const brokenRepository = new FindingRepository('test-principal', 'nonexistent-table', dynamoDBDocumentClient);

      // ACT
      const items = await brokenRepository.findByKeys([
        { findingType: 'security-control/S3.1', findingId: 'finding-a' },
      ]);

      // ASSERT
      expect(items).toEqual([]);
    });
  });

  describe('queryByControlId', () => {
    it('returns every finding stored under a control ID and ignores findings under other controls', async () => {
      // ARRANGE — two findings share the queried control ID; a third belongs to a different control.
      await putFinding(createFindingItem({ findingType: 'S3.1', findingId: 'finding-a' }));
      await putFinding(createFindingItem({ findingType: 'S3.1', findingId: 'finding-b' }));
      await putFinding(createFindingItem({ findingType: 'EC2.1', findingId: 'finding-c' }));

      // ACT
      const result = await repository.queryByControlId('S3.1');

      // ASSERT
      expect(result.items.map((item) => item.findingId).sort()).toEqual(['finding-a', 'finding-b']);
      expect(result.lastEvaluatedKey).toBeUndefined();
    });

    it('applies a server-side remediationStatus filter when remediationStatusEquals is supplied', async () => {
      // ARRANGE — same control ID, mixed remediation statuses.
      await putFinding(
        createFindingItem({ findingType: 'S3.1', findingId: 'pending', remediationStatus: 'NOT_STARTED' }),
      );
      await putFinding(
        createFindingItem({ findingType: 'S3.1', findingId: 'in-progress', remediationStatus: 'IN_PROGRESS' }),
      );

      // ACT
      const result = await repository.queryByControlId('S3.1', { remediationStatusEquals: 'NOT_STARTED' });

      // ASSERT — only the NOT_STARTED finding passes the filter.
      expect(result.items.map((item) => item.findingId)).toEqual(['pending']);
    });

    it('paginates results via limit and exclusiveStartKey', async () => {
      // ARRANGE — three findings under one control ID, fetched a page at a time.
      await putFinding(createFindingItem({ findingType: 'S3.1', findingId: 'finding-1' }));
      await putFinding(createFindingItem({ findingType: 'S3.1', findingId: 'finding-2' }));
      await putFinding(createFindingItem({ findingType: 'S3.1', findingId: 'finding-3' }));

      // ACT — first page signals more remain, second page consumes the bookmark and completes.
      const firstPage = await repository.queryByControlId('S3.1', { limit: 2 });
      const secondPage = await repository.queryByControlId('S3.1', {
        limit: 2,
        exclusiveStartKey: firstPage.lastEvaluatedKey,
      });

      // ASSERT
      expect(firstPage.items).toHaveLength(2);
      expect(firstPage.lastEvaluatedKey).toBeDefined();
      expect(secondPage.items).toHaveLength(1);
      expect(secondPage.lastEvaluatedKey).toBeUndefined();
      const allFindingIds = [...firstPage.items, ...secondPage.items].map((item) => item.findingId).sort();
      expect(allFindingIds).toEqual(['finding-1', 'finding-2', 'finding-3']);
    });

    it('returns an empty page when no findings exist for the control ID', async () => {
      // ARRANGE — table holds a finding under a different control only.
      await putFinding(createFindingItem({ findingType: 'EC2.1', findingId: 'finding-other' }));

      // ACT
      const result = await repository.queryByControlId('S3.1');

      // ASSERT
      expect(result.items).toEqual([]);
      expect(result.lastEvaluatedKey).toBeUndefined();
    });
  });
});
