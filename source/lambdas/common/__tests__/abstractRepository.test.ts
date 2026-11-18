// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { PaginationToken, SearchFilter } from '@asr/data-models';
import { CreateTableCommand, DeleteTableCommand, DynamoDBClient, waitUntilTableExists } from '@aws-sdk/client-dynamodb';
import {
  BatchGetCommand,
  BatchWriteCommand,
  DynamoDBDocumentClient,
  ScanCommand,
  ScanCommandInput,
} from '@aws-sdk/lib-dynamodb';
import { mockClient } from 'aws-sdk-client-mock';
import { AbstractRepository, BatchGetWithRetryOptions, DynamoDBKey } from '../repositories/abstractRepository';
import { Sleeper } from '../utils/sleeper';
import { DynamoDBTestSetup } from './dynamodbSetup';

// AbstractRepository is exercised through a small concrete repository over a real DynamoDB Local
// table, so key conditions, index queries and filter expressions are validated by DynamoDB itself.
// The few behaviors DynamoDB Local cannot be told to produce (unprocessed batch items) use a fake
// of the SDK client, which is the system boundary.

const TABLE = 'test-abstract-repository-table';
const MISSING_TABLE = 'test-abstract-repository-table-that-does-not-exist';
const INDEX = 'byGroup';

interface TestItem {
  pk: string;
  sk: string;
  teamId?: string;
  label?: string;
  count?: number;
  lastUpdatedBy?: string;
}

class TestRepository extends AbstractRepository<TestItem> {
  protected readonly partitionKeyName = 'pk';
  protected readonly sortKeyName = 'sk';
  protected override readonly GSI_KEY_STRUCTURES: Record<string, string[]> = { [INDEX]: ['teamId', 'sk', 'pk'] };

  constructor(tableName: string, client: DynamoDBDocumentClient, sleeper?: Sleeper) {
    super('test-principal', tableName, client, sleeper);
  }

  scan(options?: Partial<ScanCommandInput>) {
    return this.findAllWithTransform((item) => item as unknown as TestItem, options);
  }

  groupItems(
    group: string,
    options: { scanIndexForward?: boolean; limit?: number; exclusiveStartKey?: DynamoDBKey } = {},
  ) {
    return this.queryIndexPK({ indexName: INDEX, partitionKeyName: 'teamId', partitionKeyValue: group, ...options });
  }

  filtered(group: string, filterExpression: string, values: Record<string, unknown>, names?: Record<string, string>) {
    return this.queryIndexWithFilter({
      indexName: INDEX,
      partitionKeyName: 'teamId',
      partitionKeyValue: group,
      filterExpression,
      expressionAttributeValues: values,
      expressionAttributeNames: names,
    });
  }

  batchGet(keys: DynamoDBKey[], options?: BatchGetWithRetryOptions) {
    return this.batchGetWithRetry<TestItem>(keys, options);
  }

  groupFilters(filters: SearchFilter[]) {
    return this.analyzeFilters(filters);
  }

  matches(item: TestItem, filter: SearchFilter) {
    return this.matchesSingleFilter(item, filter);
  }

  expression(filters: SearchFilter[]) {
    return this.buildFilterExpression(this.analyzeFilters(filters));
  }

  withoutIndexFilters(groups: Record<string, SearchFilter[]>, selected: { field: string; value: string }) {
    return this.removeMatchingFilters(groups, selected);
  }

  nextToken(items: TestItem[], indexName?: string, keyStructure?: string[]): PaginationToken | undefined {
    return this.createNextTokenFromLastItem(items, indexName, keyStructure);
  }
}

const filter = (fieldName: string, value: string, comparison: SearchFilter['comparison'] = 'EQUALS'): SearchFilter => ({
  fieldName,
  value,
  comparison,
});

const item = (pk: string, sk: string, extra: Partial<TestItem> = {}): TestItem => ({ pk, sk, ...extra });

describe('AbstractRepository (DynamoDB Local)', () => {
  let client: DynamoDBDocumentClient;
  let repository: TestRepository;
  let broken: TestRepository;

  beforeAll(async () => {
    await DynamoDBTestSetup.initialize();
    client = DynamoDBTestSetup.getDocClient();
    await client.send(
      new CreateTableCommand({
        TableName: TABLE,
        KeySchema: [
          { AttributeName: 'pk', KeyType: 'HASH' },
          { AttributeName: 'sk', KeyType: 'RANGE' },
        ],
        AttributeDefinitions: [
          { AttributeName: 'pk', AttributeType: 'S' },
          { AttributeName: 'sk', AttributeType: 'S' },
          { AttributeName: 'teamId', AttributeType: 'S' },
        ],
        GlobalSecondaryIndexes: [
          {
            IndexName: INDEX,
            KeySchema: [
              { AttributeName: 'teamId', KeyType: 'HASH' },
              { AttributeName: 'sk', KeyType: 'RANGE' },
            ],
            Projection: { ProjectionType: 'ALL' },
          },
        ],
        BillingMode: 'PAY_PER_REQUEST',
      }),
    );
    await waitUntilTableExists({ client, maxWaitTime: 30 }, { TableName: TABLE });
  });

  afterAll(async () => {
    await client.send(new DeleteTableCommand({ TableName: TABLE }));
  });

  beforeEach(async () => {
    const existing = await repository?.scan();
    for (const entry of existing ?? []) await repository.deleteById(entry.pk, entry.sk);
    repository = new TestRepository(TABLE, client);
    broken = new TestRepository(MISSING_TABLE, client);
  });

  describe('writing and reading single items', () => {
    it('treats a table that cannot be read as having nothing', async () => {
      expect(await broken.findById('p1', 's1')).toBeUndefined();
    });

    it('passes on a failure to write or delete', async () => {
      await expect(broken.put(item('p1', 's1'))).rejects.toThrow();
      await expect(broken.deleteById('p1', 's1')).rejects.toThrow();
    });
  });

  describe('writing many items', () => {
    it('passes on a failure to write a batch', async () => {
      await expect(broken.putAll(item('p1', 's1'))).rejects.toThrow();
    });
  });

  describe('querying an index', () => {
    beforeEach(async () => {
      await repository.putAll(
        item('p1', 'a', { teamId: 'g1', label: 'x', count: 1 }),
        item('p2', 'b', { teamId: 'g1', label: 'y', count: 2 }),
        item('p3', 'c', { teamId: 'g1', label: 'x', count: 3 }),
        item('p4', 'd', { teamId: 'g2', label: 'x', count: 4 }),
      );
    });

    it('returns a page with the key to continue from', async () => {
      const firstPage = await repository.groupItems('g1', { limit: 2 });
      const secondPage = await repository.groupItems('g1', {
        limit: 2,
        exclusiveStartKey: firstPage.lastEvaluatedKey as DynamoDBKey,
      });

      expect(firstPage.items.map((i) => i.sk)).toEqual(['a', 'b']);
      expect(firstPage.lastEvaluatedKey).toBeDefined();
      expect(secondPage.items.map((i) => i.sk)).toEqual(['c']);
    });

    it('passes on a failure to query', async () => {
      await expect(broken.groupItems('g1')).rejects.toThrow();
    });
  });

  describe('getting many items by key', () => {
    beforeEach(async () => {
      await repository.putAll(...['a', 'b', 'c', 'd', 'e'].map((sk) => item('p', sk, { label: sk })));
    });

    it('returns nothing for no keys, without calling DynamoDB', async () => {
      await expect(broken.batchGet([])).resolves.toEqual({ items: [], unprocessedKeys: [] });
    });
  });

  describe('when DynamoDB hands back work it did not finish', () => {
    const fakeClient = DynamoDBDocumentClient.from(new DynamoDBClient({ region: 'us-east-1' }));
    const sdkMock = mockClient(fakeClient);
    let sleeps: number[];
    let fakeRepository: TestRepository;

    beforeEach(() => {
      sdkMock.reset();
      sleeps = [];
      fakeRepository = new TestRepository(TABLE, fakeClient, {
        sleep: async (ms: number) => {
          sleeps.push(ms);
        },
      });
    });

    it('asks again for keys that came back unprocessed, waiting longer each time up to a cap', async () => {
      const key = (sk: string) => ({ pk: 'p', sk });
      sdkMock
        .on(BatchGetCommand)
        .resolvesOnce({ Responses: { [TABLE]: [item('p', 'a')] }, UnprocessedKeys: { [TABLE]: { Keys: [key('b')] } } })
        .resolvesOnce({ Responses: { [TABLE]: [] }, UnprocessedKeys: { [TABLE]: { Keys: [key('b')] } } })
        .resolvesOnce({ Responses: { [TABLE]: [item('p', 'b')] } })
        .resolves({ Responses: { [TABLE]: [] } });

      const result = await fakeRepository.batchGet([key('a'), key('b')], {
        chunkSize: 1,
        backoffBaseMs: 10,
        maxBackoffMs: 25,
      });

      expect(result.items.map((i) => i.sk)).toEqual(['a', 'b']);
      // 2^1 * 10 = 20, then 2^2 * 10 = 40 capped at 25; no wait once a request is fully processed.
      expect(sleeps).toEqual([20, 25]);
    });

    it('retries unprocessed writes and succeeds when they go through', async () => {
      const unprocessed = { [TABLE]: [{ PutRequest: { Item: item('p', 'a') } }] };
      sdkMock.on(BatchWriteCommand).resolvesOnce({ UnprocessedItems: unprocessed }).resolves({});

      await expect(fakeRepository.putAll(item('p', 'a'))).resolves.toBeUndefined();

      expect(sdkMock.commandCalls(BatchWriteCommand)).toHaveLength(2);
    });

    it('gives up on writes that stay unprocessed', async () => {
      const unprocessed = { [TABLE]: [{ PutRequest: { Item: item('p', 'a') } }] };
      sdkMock.on(BatchWriteCommand).resolves({ UnprocessedItems: unprocessed });

      await expect(fakeRepository.putAll(item('p', 'a'))).rejects.toThrow(
        'Failed to process all items after 3 attempts',
      );
      expect(sdkMock.commandCalls(BatchWriteCommand)).toHaveLength(3);
    });

    it('scans every page DynamoDB returns', async () => {
      sdkMock
        .on(ScanCommand)
        .resolvesOnce({ Items: [item('p', 'a')], LastEvaluatedKey: { pk: 'p', sk: 'a' } })
        .resolvesOnce({ Items: undefined, LastEvaluatedKey: { pk: 'p', sk: 'b' } })
        .resolvesOnce({ Items: [item('p', 'c')] });

      const items = await fakeRepository.scan();

      expect(items.map((i) => i.sk)).toEqual(['a', 'c']);
    });
  });

  describe('search filters', () => {
    it('never matches a missing field or an unsupported comparison', () => {
      expect(repository.matches(item('p', 's'), filter('label', 'x'))).toBe(false);
      expect(repository.matches(item('p', 's', { label: 'x' }), filter('label', 'x', 'BETWEEN' as never))).toBe(false);
    });

    it('compares a number with an equal-valued filter by its text', () => {
      expect(repository.matches(item('p', 's', { count: 5 }), filter('count', '5'))).toBe(true);
    });

    it.each([
      ['GREATER_THAN_OR_EQUAL', '2024-02-01T00:00:00Z', true],
      ['GREATER_THAN_OR_EQUAL', '2024-02-01T00:00:01Z', false],
      ['GREATER_THAN_OR_EQUAL', '2024-01-01T00:00:00Z', true],
      ['LESS_THAN_OR_EQUAL', '2024-02-01T00:00:00Z', true],
      ['LESS_THAN_OR_EQUAL', '2024-01-31T23:59:59Z', false],
      ['LESS_THAN_OR_EQUAL', '2024-03-01T00:00:00Z', true],
    ] as const)('%s against %s in memory matches: %s', (comparison, value, expected) => {
      const stored = item('p', 's', { label: '2024-02-01T00:00:00Z' });

      expect(repository.matches(stored, filter('label', value, comparison))).toBe(expected);
    });

    it.each(['GREATER_THAN_OR_EQUAL', 'LESS_THAN_OR_EQUAL'] as const)(
      'never matches a stored number for %s, as DynamoDB does not compare a number to a string',
      (comparison) => {
        expect(repository.matches(item('p', 's', { count: 10 }), filter('count', '9', comparison))).toBe(false);
      },
    );

    it.each(['GREATER_THAN_OR_EQUAL', 'LESS_THAN_OR_EQUAL'] as const)(
      'selects the same items as the DynamoDB filter it builds for %s',
      async (comparison) => {
        const stamps = ['2024-01-01T00:00:00Z', '2024-02-01T00:00:00Z', '2024-02-01T00:00:01Z', '2024-03-01T00:00:00Z'];
        await repository.putAll(...stamps.map((label, i) => item(`p${i}`, 's', { teamId: 'g', label })));
        const wanted = filter('label', '2024-02-01T00:00:00Z', comparison);
        const built = repository.expression([wanted]);

        const fromDynamoDb = await repository.filtered(
          'g',
          built.filterExpression as string,
          built.expressionAttributeValues ?? {},
          built.expressionAttributeNames,
        );
        const inMemory = (await repository.scan()).filter((stored) => repository.matches(stored, wanted));

        expect(inMemory.map((i) => i.label).sort()).toEqual(fromDynamoDb.items.map((i) => i.label).sort());
        expect(inMemory.length).toBeGreaterThan(0);
      },
    );

    it('builds one condition per comparison, joining the values of one field with OR and fields with AND', () => {
      const result = repository.expression([
        filter('a', '1'),
        filter('a', '2', 'NOT_EQUALS'),
        filter('b', '3', 'CONTAINS'),
        filter('c', '4', 'NOT_CONTAINS'),
        filter('d', '5', 'GREATER_THAN_OR_EQUAL'),
        filter('e', '6', 'LESS_THAN_OR_EQUAL'),
      ]);

      expect(result.filterExpression).toBe(
        '(#a = :val0 OR #a <> :val1) AND contains(#b, :val2) AND NOT contains(#c, :val3) AND #d >= :val4 AND #e <= :val5',
      );
      expect(result.expressionAttributeNames).toEqual({ '#a': 'a', '#b': 'b', '#c': 'c', '#d': 'd', '#e': 'e' });
      expect(result.expressionAttributeValues).toEqual({
        ':val0': '1',
        ':val1': '2',
        ':val2': '3',
        ':val3': '4',
        ':val4': '5',
        ':val5': '6',
      });
    });
  });

  describe('choosing an index for a search', () => {
    it('drops the filter that the chosen index already satisfies and keeps the others', () => {
      const groups = repository.groupFilters([
        filter('accountId', 'a1'),
        filter('accountId', 'a1', 'CONTAINS'),
        filter('severity', 'HIGH'),
      ]);

      const remaining = repository.withoutIndexFilters(groups, { field: 'accountId', value: 'a1' });

      expect(remaining.accountId).toEqual([filter('accountId', 'a1', 'CONTAINS')]);
      expect(remaining.severity).toEqual([filter('severity', 'HIGH')]);
      expect(groups.accountId).toHaveLength(2);
    });

    it('leaves the filters alone when the index field has none', () => {
      const groups = repository.groupFilters([filter('severity', 'HIGH')]);

      expect(repository.withoutIndexFilters(groups, { field: 'accountId', value: 'a1' })).toEqual(groups);
    });
  });

  describe('pagination tokens', () => {
    const last = item('p9', 's9', { teamId: 'g9' });

    it('uses the key fields of the index, leaving out fields the item does not have', () => {
      expect(repository.nextToken([item('p1', 's1'), last], INDEX)).toEqual({ teamId: 'g9', sk: 's9', pk: 'p9' });
      expect(repository.nextToken([item('p1', 's1')], INDEX)).toEqual({ sk: 's1', pk: 'p1' });
    });

    it('has no token when no key structure is known', () => {
      expect(repository.nextToken([last], 'unknown-index')).toBeUndefined();
      expect(repository.nextToken([last], undefined, [])).toBeUndefined();
    });
  });
});
