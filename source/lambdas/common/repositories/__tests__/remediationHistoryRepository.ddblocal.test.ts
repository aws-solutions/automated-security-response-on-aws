// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * Integration-style tests for RemediationHistoryRepository.findLatestSuccessWithFindingJSON
 * that run against DynamoDB Local (per the Unit Testing Guidelines: "Do not mock
 * the DynamoDB client"). Seeding real items and querying through DynamoDB Local
 * validates that the method's FilterExpression
 * (`remediationStatus = SUCCESS AND attribute_exists(findingJSON) AND size(findingJSON) > 0`)
 * and the newest-first GSI read actually behave as intended at the query level —
 * something a mocked client cannot verify.
 */
import { PutCommand } from '@aws-sdk/lib-dynamodb';
import { DynamoDBTestSetup } from '../../__tests__/dynamodbSetup';
import { remediationHistoryTableName, findingsTableName } from '../../__tests__/envSetup';
import { RemediationHistoryRepository } from '../remediationHistoryRepository';
import { asFindingId } from '../../__tests__/utils';

const FINDING_ID = 'arn:aws:securityhub:us-east-1:123456789012:security-control/S3.1/finding/abc';

/**
 * Inserts a remediation-history item with only the fields the GSI query and
 * FilterExpression touch. `lastUpdatedTime#findingId` is the GSI range key, so
 * a lexicographically larger value sorts newer (the query reads descending).
 */
interface SeedOptions {
  sortKey: string;
  remediationStatus: string;
  findingJSON?: Uint8Array;
}

describe('RemediationHistoryRepository.findLatestSuccessWithFindingJSON (DynamoDB Local)', () => {
  let repository: RemediationHistoryRepository;

  beforeAll(async () => {
    await DynamoDBTestSetup.initialize();
    await DynamoDBTestSetup.createRemediationHistoryTable(remediationHistoryTableName);
  });

  afterAll(async () => {
    await DynamoDBTestSetup.deleteTable(remediationHistoryTableName);
  });

  beforeEach(async () => {
    await DynamoDBTestSetup.clearTable(remediationHistoryTableName, 'remediationHistory');
    repository = new RemediationHistoryRepository(
      'test-user',
      remediationHistoryTableName,
      DynamoDBTestSetup.getDocClient(),
      findingsTableName,
    );
  });

  async function seed({ sortKey, remediationStatus, findingJSON }: SeedOptions): Promise<void> {
    await DynamoDBTestSetup.getDocClient().send(
      new PutCommand({
        TableName: remediationHistoryTableName,
        Item: {
          findingType: 'security-control/S3.1',
          'findingId#executionId': `${FINDING_ID}#${sortKey}`,
          findingId: FINDING_ID,
          'lastUpdatedTime#findingId': `${sortKey}#${FINDING_ID}`,
          REMEDIATION_CONSTANT: 'remediation',
          remediationStatus,
          expireAt: 9999999999,
          ...(findingJSON ? { findingJSON } : {}),
        },
      }),
    );
  }

  it('returns the entry with a non-empty findingJSON', async () => {
    await seed({
      sortKey: '2024-01-01T00:00:00.000Z',
      remediationStatus: 'SUCCESS',
      findingJSON: new Uint8Array([1, 2, 3]),
    });

    const result = await repository.findLatestSuccessWithFindingJSON(asFindingId(FINDING_ID));

    expect(result).toMatchObject({ remediationStatus: 'SUCCESS' });
    expect(result?.findingJSON).toBeDefined();
  });

  it('filters out SUCCESS entries that lack findingJSON', async () => {
    await seed({ sortKey: '2024-01-01T00:00:00.000Z', remediationStatus: 'SUCCESS' });

    const result = await repository.findLatestSuccessWithFindingJSON(asFindingId(FINDING_ID));

    expect(result).toBeUndefined();
  });

  it('filters out SUCCESS entries whose findingJSON is empty (size 0)', async () => {
    await seed({ sortKey: '2024-01-01T00:00:00.000Z', remediationStatus: 'SUCCESS', findingJSON: new Uint8Array() });

    const result = await repository.findLatestSuccessWithFindingJSON(asFindingId(FINDING_ID));

    expect(result).toBeUndefined();
  });

  it('filters out non-SUCCESS entries even when they carry findingJSON', async () => {
    await seed({
      sortKey: '2024-01-01T00:00:00.000Z',
      remediationStatus: 'FAILED',
      findingJSON: new Uint8Array([1, 2, 3]),
    });

    const result = await repository.findLatestSuccessWithFindingJSON(asFindingId(FINDING_ID));

    expect(result).toBeUndefined();
  });

  it('returns the newest matching entry when several qualify', async () => {
    await seed({ sortKey: '2024-01-01T00:00:00.000Z', remediationStatus: 'SUCCESS', findingJSON: new Uint8Array([1]) });
    await seed({ sortKey: '2024-03-01T00:00:00.000Z', remediationStatus: 'SUCCESS', findingJSON: new Uint8Array([3]) });
    await seed({ sortKey: '2024-02-01T00:00:00.000Z', remediationStatus: 'SUCCESS', findingJSON: new Uint8Array([2]) });

    const result = await repository.findLatestSuccessWithFindingJSON(asFindingId(FINDING_ID));

    // Newest by the GSI range key (lastUpdatedTime#findingId) is the March entry.
    expect(result?.['findingId#executionId']).toBe(`${FINDING_ID}#2024-03-01T00:00:00.000Z`);
  });

  it('returns undefined when no history exists for the finding', async () => {
    const result = await repository.findLatestSuccessWithFindingJSON(asFindingId(FINDING_ID));

    expect(result).toBeUndefined();
  });
});
