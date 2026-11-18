// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { FindingTableItem, SearchCriteria, SearchFilter } from '@asr/data-models';
import { DynamoDBDocumentClient, GetCommand } from '@aws-sdk/lib-dynamodb';
import { RemediationHistoryRepository } from '../repositories/remediationHistoryRepository';
import { Clock } from '../utils/clock';
import { DynamoDBTestSetup } from './dynamodbSetup';
import { findingsTableName, remediationHistoryTableName } from './envSetup';
import { asFindingId } from './utils';

// DynamoDB access is exercised against DynamoDB Local so the GSI selection, filter expressions and
// pagination tokens are validated against a real key schema rather than a stub.

const PRINCIPAL = 'test-user';
const MISSING_TABLE = 'test-table-that-does-not-exist';

describe('RemediationHistoryRepository (DynamoDB Local)', () => {
  let dynamoDBDocumentClient: DynamoDBDocumentClient;
  let repository: RemediationHistoryRepository;
  let now: Date;
  const clock: Clock = { now: () => now };

  const createFinding = (overrides: Partial<FindingTableItem> = {}): FindingTableItem => ({
    findingType: 'security-control/S3.1',
    findingId: asFindingId('finding-1'),
    findingDescription: 'Test finding description',
    accountId: '123456789012',
    resourceId: 'arn:aws:s3:::test-bucket',
    resourceType: 'AWS::S3::Bucket',
    resourceTypeNormalized: 'awss3bucket',
    severity: 'HIGH',
    severityNormalized: 3,
    region: 'us-east-1',
    remediationStatus: 'IN_PROGRESS',
    securityHubUpdatedAtTime: '2026-01-01T00:00:00Z',
    lastUpdatedTime: '2026-01-01T00:00:00Z',
    'securityHubUpdatedAtTime#findingId': '2026-01-01T00:00:00Z#finding-1',
    'severityNormalized#securityHubUpdatedAtTime#findingId': '3#2026-01-01T00:00:00Z#finding-1',
    findingJSON: new Uint8Array(),
    findingIdControl: 'security-control/S3.1',
    FINDING_CONSTANT: 'finding' as const,
    creationTime: '2026-01-01T00:00:00Z',
    suppressed: false,
    expireAt: 0,
    ...overrides,
  });

  async function seed(
    time: string,
    executionId: string,
    overrides: Partial<FindingTableItem> = {},
    target: RemediationHistoryRepository = repository,
  ): Promise<void> {
    now = new Date(time);
    await target.createRemediationHistory(createFinding(overrides), executionId);
  }

  const criteria = (overrides: Partial<SearchCriteria> = {}): SearchCriteria => ({
    filters: [],
    sortOrder: 'desc',
    pageSize: 50,
    ...overrides,
  });

  const filter = (
    fieldName: string,
    value: string,
    comparison: SearchFilter['comparison'] = 'EQUALS',
  ): SearchFilter => ({ fieldName, value, comparison });

  beforeAll(async () => {
    await DynamoDBTestSetup.initialize();
    dynamoDBDocumentClient = DynamoDBTestSetup.getDocClient();
    await DynamoDBTestSetup.createRemediationHistoryTable(remediationHistoryTableName);
    await DynamoDBTestSetup.createFindingsTable(findingsTableName);
  });

  afterAll(async () => {
    await DynamoDBTestSetup.deleteTable(remediationHistoryTableName);
    await DynamoDBTestSetup.deleteTable(findingsTableName);
  });

  beforeEach(async () => {
    await DynamoDBTestSetup.clearTable(remediationHistoryTableName, 'remediationHistory');
    await DynamoDBTestSetup.clearTable(findingsTableName, 'findings');
    now = new Date('2026-02-01T00:00:00Z');
    repository = new RemediationHistoryRepository(
      PRINCIPAL,
      remediationHistoryTableName,
      dynamoDBDocumentClient,
      findingsTableName,
      clock,
    );
  });

  describe('createRemediationHistory', () => {
    it('stores the history item with keys, normalized status and a ttl', async () => {
      await seed('2026-02-01T00:00:00Z', 'exec-1');

      const { entries } = await readAll();

      expect(entries).toHaveLength(1);
      expect(entries[0]).toMatchObject({
        findingType: 'security-control/S3.1',
        findingId: 'finding-1',
        'findingId#executionId': 'finding-1#exec-1',
        'lastUpdatedTime#findingId': '2026-02-01T00:00:00.000Z#finding-1',
        REMEDIATION_CONSTANT: 'remediation',
        remediationStatus: 'IN_PROGRESS',
        executionId: 'exec-1',
        lastUpdatedBy: PRINCIPAL,
        accountId: '123456789012',
        resourceId: 'arn:aws:s3:::test-bucket',
      });
      expect(entries[0].expireAt).toBeGreaterThan(Math.floor(new Date('2026-02-01T00:00:00Z').getTime() / 1000));
      expect(entries[0]).not.toHaveProperty('remediationConfigTableKey');
      expect(entries[0]).not.toHaveProperty('findingJSON');
    });

    it("keeps the finding's updater, remediation config key and finding JSON when present", async () => {
      await seed('2026-02-01T00:00:00Z', 'exec-1', {
        lastUpdatedBy: 'someone-else',
        remediationConfigTableKey: 'S3.1',
        findingJSON: new Uint8Array(Buffer.from('compressed')),
      });

      const { entries } = await readAll();

      expect(entries[0].lastUpdatedBy).toBe('someone-else');
      expect(entries[0].remediationConfigTableKey).toBe('S3.1');
      expect(Buffer.from(entries[0].findingJSON ?? []).toString()).toBe('compressed');
    });

    it('rethrows when the history table cannot be written', async () => {
      const broken = new RemediationHistoryRepository(
        PRINCIPAL,
        MISSING_TABLE,
        dynamoDBDocumentClient,
        findingsTableName,
        clock,
      );

      await expect(seed('2026-02-01T00:00:00Z', 'exec-1', {}, broken)).rejects.toThrow();
    });
  });

  describe('createRemediationHistoryWithFindingUpdate', () => {
    it('writes the history item and the updated finding in one transaction and clears the enforcement stamp', async () => {
      now = new Date('2026-02-01T00:00:00Z');
      const finding = createFinding({
        remediationDueBy: '2026-03-01T00:00:00Z',
        enforcementConfigIds: new Set(['config-1']),
      });

      await repository.createRemediationHistoryWithFindingUpdate(finding, 'exec-9');

      const stored = await dynamoDBDocumentClient.send(
        new GetCommand({
          TableName: findingsTableName,
          Key: { findingType: finding.findingType, findingId: finding.findingId },
        }),
      );
      expect(stored.Item).toMatchObject({
        findingId: 'finding-1',
        remediationStatus: 'IN_PROGRESS',
        lastUpdatedTime: '2026-02-01T00:00:00.000Z',
        lastUpdatedBy: PRINCIPAL,
      });
      expect(stored.Item).not.toHaveProperty('remediationDueBy');
      expect(stored.Item).not.toHaveProperty('enforcementConfigIds');

      const { entries } = await readAll();
      expect(entries.map((e) => e['findingId#executionId'])).toEqual(['finding-1#exec-9']);
    });

    it('rethrows and writes nothing when the transaction fails', async () => {
      const broken = new RemediationHistoryRepository(
        PRINCIPAL,
        remediationHistoryTableName,
        dynamoDBDocumentClient,
        MISSING_TABLE,
        clock,
      );

      await expect(broken.createRemediationHistoryWithFindingUpdate(createFinding(), 'exec-9')).rejects.toThrow();

      const { entries } = await readAll();
      expect(entries).toHaveLength(0);
    });
  });

  describe('searchRemediations', () => {
    beforeEach(async () => {
      await seed('2026-02-01T00:00:00Z', 'exec-1', { findingId: asFindingId('finding-1') });
      await seed('2026-02-02T00:00:00Z', 'exec-2', {
        findingId: asFindingId('finding-2'),
        accountId: '999999999999',
        resourceId: 'arn:aws:s3:::other-bucket',
        severity: 'LOW',
      });
      await seed('2026-02-03T00:00:00Z', 'exec-3', {
        findingId: asFindingId('finding-3'),
        resourceId: 'arn:aws:s3:::third-bucket',
        severity: 'CRITICAL',
      });
    });

    const ids = (items: { executionId?: string }[]) => items.map((i) => i.executionId);

    it('returns everything newest first when there are no filters', async () => {
      const result = await repository.searchRemediations(criteria());

      expect(ids(result.items)).toEqual(['exec-3', 'exec-2', 'exec-1']);
      expect(result.nextToken).toBeUndefined();
    });

    it('returns everything oldest first for ascending order', async () => {
      const result = await repository.searchRemediations(criteria({ sortOrder: 'asc' }));

      expect(ids(result.items)).toEqual(['exec-1', 'exec-2', 'exec-3']);
    });

    it('uses the account index for a single account filter', async () => {
      const result = await repository.searchRemediations(criteria({ filters: [filter('accountId', '999999999999')] }));

      expect(ids(result.items)).toEqual(['exec-2']);
    });

    it('uses the resource index for a single resource filter', async () => {
      const result = await repository.searchRemediations(
        criteria({ filters: [filter('resourceId', 'arn:aws:s3:::third-bucket')] }),
      );

      expect(ids(result.items)).toEqual(['exec-3']);
    });

    it('applies the remaining filters on top of the selected index', async () => {
      const result = await repository.searchRemediations(
        criteria({
          filters: [filter('accountId', '123456789012'), filter('severity', 'CRITICAL')],
        }),
      );

      expect(ids(result.items)).toEqual(['exec-3']);
    });

    it('falls back to a filtered scan of the full index when no filter can pick an index', async () => {
      const result = await repository.searchRemediations(
        criteria({ filters: [filter('severity', 'HIGH', 'NOT_EQUALS')] }),
      );

      expect(ids(result.items)).toEqual(['exec-3', 'exec-2']);
    });

    it('does not pick an index for a filter that is not an exact match', async () => {
      const result = await repository.searchRemediations(
        criteria({ filters: [filter('resourceId', 'bucket', 'CONTAINS')] }),
      );

      expect(ids(result.items)).toEqual(['exec-3', 'exec-2', 'exec-1']);
    });

    it('queries each finding id directly and merges the results by time', async () => {
      await seed('2026-02-04T00:00:00Z', 'exec-4', { findingId: asFindingId('finding-1') });

      const descending = await repository.searchRemediations(
        criteria({ filters: [filter('findingId', 'finding-1'), filter('findingId', 'finding-3')] }),
      );
      const ascending = await repository.searchRemediations(
        criteria({
          sortOrder: 'asc',
          filters: [filter('findingId', 'finding-1'), filter('findingId', 'finding-3')],
        }),
      );

      expect(ids(descending.items)).toEqual(['exec-4', 'exec-3', 'exec-1']);
      expect(ids(ascending.items)).toEqual(['exec-1', 'exec-3', 'exec-4']);
      expect(descending.nextToken).toBeUndefined();
    });

    it('applies the other filters to the results of a direct finding id query', async () => {
      await seed('2026-02-04T00:00:00Z', 'exec-4', { findingId: asFindingId('finding-1'), severity: 'LOW' });

      const result = await repository.searchRemediations(
        criteria({
          filters: [filter('findingId', 'finding-1'), filter('severity', 'LOW'), filter('severity', 'CRITICAL')],
        }),
      );

      expect(ids(result.items)).toEqual(['exec-4']);
    });

    it('drops direct query results that match none of the other filters', async () => {
      const result = await repository.searchRemediations(
        criteria({ filters: [filter('findingId', 'finding-1'), filter('severity', 'CRITICAL')] }),
      );

      expect(result.items).toEqual([]);
    });

    it('returns nothing for a finding id with no history', async () => {
      const result = await repository.searchRemediations(criteria({ filters: [filter('findingId', 'unknown')] }));

      expect(result.items).toEqual([]);
    });

    it('returns nothing for a direct query when the history cannot be read', async () => {
      const broken = new RemediationHistoryRepository(
        PRINCIPAL,
        MISSING_TABLE,
        dynamoDBDocumentClient,
        findingsTableName,
        clock,
      );

      const result = await broken.searchRemediations(criteria({ filters: [filter('findingId', 'finding-1')] }));

      expect(result.items).toEqual([]);
    });

    it('rethrows when the search itself fails', async () => {
      const broken = new RemediationHistoryRepository(
        PRINCIPAL,
        MISSING_TABLE,
        dynamoDBDocumentClient,
        findingsTableName,
        clock,
      );

      await expect(broken.searchRemediations(criteria())).rejects.toThrow();
    });

    it('pages through the results with the next token', async () => {
      const seen: (string | undefined)[] = [];
      let nextToken: string | undefined;
      let pages = 0;

      do {
        const result = await repository.searchRemediations(criteria({ pageSize: 2, nextToken }));
        seen.push(...ids(result.items));
        nextToken = result.nextToken;
        pages++;
      } while (nextToken && pages < 5);

      expect(seen).toEqual(['exec-3', 'exec-2', 'exec-1']);
      expect(pages).toBe(2);
    });

    it('starts from the beginning when the next token is not valid', async () => {
      const notJson = await repository.searchRemediations(criteria({ nextToken: 'not-base64-json!' }));
      const missingKeys = await repository.searchRemediations(
        criteria({ nextToken: Buffer.from(JSON.stringify({ unrelated: 1 }), 'utf-8').toString('base64') }),
      );

      expect(ids(notJson.items)).toEqual(['exec-3', 'exec-2', 'exec-1']);
      expect(ids(missingKeys.items)).toEqual(['exec-3', 'exec-2', 'exec-1']);
    });
  });

  describe('findLatestByFindingIds', () => {
    it('returns the newest entry of each finding once, ignoring duplicates and unknown ids', async () => {
      await seed('2026-02-01T00:00:00Z', 'exec-1', { findingId: asFindingId('finding-1') });
      await seed('2026-02-05T00:00:00Z', 'exec-2', { findingId: asFindingId('finding-1') });
      await seed('2026-02-03T00:00:00Z', 'exec-3', { findingId: asFindingId('finding-2') });

      const result = await repository.findLatestByFindingIds([
        asFindingId('finding-1'),
        asFindingId('finding-1'),
        asFindingId('finding-2'),
        asFindingId('unknown'),
      ]);

      expect(result.map((r) => r.executionId).sort()).toEqual(['exec-2', 'exec-3']);
    });

    it('returns nothing for an empty list', async () => {
      expect(await repository.findLatestByFindingIds([])).toEqual([]);
    });

    it('processes more ids than one concurrency chunk', async () => {
      await seed('2026-02-01T00:00:00Z', 'exec-1', { findingId: asFindingId('finding-30') });
      const ids = Array.from({ length: 30 }, (_, i) => asFindingId(`finding-${i + 1}`));

      const result = await repository.findLatestByFindingIds(ids);

      expect(result.map((r) => r.executionId)).toEqual(['exec-1']);
    });

    it('skips ids whose history cannot be read', async () => {
      const broken = new RemediationHistoryRepository(
        PRINCIPAL,
        MISSING_TABLE,
        dynamoDBDocumentClient,
        findingsTableName,
        clock,
      );

      expect(await broken.findLatestByFindingIds([asFindingId('finding-1')])).toEqual([]);
    });
  });

  describe('findLatestSuccessWithFindingJSON', () => {
    it('returns the newest successful entry that carries a finding JSON', async () => {
      const json = new Uint8Array(Buffer.from('compressed'));
      await seed('2026-02-01T00:00:00Z', 'exec-old', {
        remediationStatus: 'SUCCESS',
        findingJSON: json,
      });
      await seed('2026-02-02T00:00:00Z', 'exec-failed', { remediationStatus: 'FAILED', findingJSON: json });
      await seed('2026-02-03T00:00:00Z', 'exec-no-json', { remediationStatus: 'SUCCESS' });

      const result = await repository.findLatestSuccessWithFindingJSON(asFindingId('finding-1'));

      expect(result?.executionId).toBe('exec-old');
    });

    it('returns undefined when no entry qualifies', async () => {
      await seed('2026-02-01T00:00:00Z', 'exec-1', { remediationStatus: 'SUCCESS' });

      expect(await repository.findLatestSuccessWithFindingJSON(asFindingId('finding-1'))).toBeUndefined();
    });
  });

  describe('findRecentByFindingId', () => {
    it('returns the newest entries first, limited to the requested count', async () => {
      await seed('2026-02-01T00:00:00Z', 'exec-1');
      await seed('2026-02-02T00:00:00Z', 'exec-2');
      await seed('2026-02-03T00:00:00Z', 'exec-3');

      const limited = await repository.findRecentByFindingId('finding-1', 2);
      const defaultLimit = await repository.findRecentByFindingId('finding-1');

      expect(limited.map((e) => e.executionId)).toEqual(['exec-3', 'exec-2']);
      expect(defaultLimit.map((e) => e.executionId)).toEqual(['exec-3', 'exec-2', 'exec-1']);
    });
  });

  async function readAll() {
    const result = await repository.searchRemediations(criteria({ pageSize: 100 }));
    return { entries: result.items };
  }
});
