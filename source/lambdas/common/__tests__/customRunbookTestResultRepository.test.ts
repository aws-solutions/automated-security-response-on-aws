// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { DynamoDBDocumentClient, GetCommand, PutCommand } from '@aws-sdk/lib-dynamodb';
import type { RunbookTestResult } from '@asr/data-models';
import { CustomRunbookTestResultRepository } from '../repositories/customRunbookTestResultRepository';
import { DynamoDBTestSetup } from './dynamodbSetup';
import { customRunbookTableName } from './envSetup';

// ADR 0003 / unit-testing.md: the projected consistent read and the guarded
// conditional write run against DynamoDB Local, so the condition expression, the
// `version` reserved-word alias, and the key schema are validated for real
// rather than accepted by a stub.

const RUNBOOK_ID = 'rb-1';
const VERSION = 3;
const REGISTERED_DIGEST = 'a'.repeat(64);

function testResult(overrides: Partial<RunbookTestResult> = {}): RunbookTestResult {
  return {
    testStatus: 'PASSED',
    testedAt: '2026-01-01T00:00:00Z',
    testAccountId: '111122223333',
    testedContentDigest: REGISTERED_DIGEST,
    testedIamActions: ['s3:PutBucketLogging'],
    testRoleArn: 'arn:aws:iam::111122223333:role/SO0111-Remediate-Custom-Test-abc',
    ...overrides,
  };
}

describe('CustomRunbookTestResultRepository (DynamoDB Local)', () => {
  let dynamoDBDocumentClient: DynamoDBDocumentClient;
  let repository: CustomRunbookTestResultRepository;

  beforeAll(async () => {
    await DynamoDBTestSetup.initialize();
    dynamoDBDocumentClient = DynamoDBTestSetup.getDocClient();
    await DynamoDBTestSetup.createCustomRunbookTable(customRunbookTableName);
  });

  afterAll(async () => {
    await DynamoDBTestSetup.deleteTable(customRunbookTableName);
  });

  beforeEach(async () => {
    await DynamoDBTestSetup.clearTable(customRunbookTableName, 'customRunbook');
    repository = new CustomRunbookTestResultRepository(customRunbookTableName, dynamoDBDocumentClient);
  });

  async function putRegisteredVersion(registeredContentDigest?: string): Promise<void> {
    await dynamoDBDocumentClient.send(
      new PutCommand({
        TableName: customRunbookTableName,
        Item: {
          runbookId: RUNBOOK_ID,
          version: VERSION,
          controlId: 'S3.1',
          status: 'DRAFT',
          ...(registeredContentDigest ? { registeredContentDigest } : {}),
        },
      }),
    );
  }

  describe('findRegisteredVersion', () => {
    it('returns the registration digest for an existing version', async () => {
      await putRegisteredVersion(REGISTERED_DIGEST);

      const registered = await repository.findRegisteredVersion(RUNBOOK_ID, VERSION);

      expect(registered).toEqual({
        runbookId: RUNBOOK_ID,
        version: VERSION,
        registeredContentDigest: REGISTERED_DIGEST,
      });
    });

    it('reports a legacy record with no digest as undefined digest', async () => {
      await putRegisteredVersion();

      const registered = await repository.findRegisteredVersion(RUNBOOK_ID, VERSION);

      expect(registered).toEqual({ runbookId: RUNBOOK_ID, version: VERSION, registeredContentDigest: undefined });
    });

    it('returns undefined when the version does not exist', async () => {
      expect(await repository.findRegisteredVersion(RUNBOOK_ID, 99)).toBeUndefined();
    });
  });

  describe('recordTestResult', () => {
    it('stamps the outcome on a registered version whose digest matches', async () => {
      await putRegisteredVersion(REGISTERED_DIGEST);

      await repository.recordTestResult(RUNBOOK_ID, VERSION, testResult());

      const stored = await dynamoDBDocumentClient.send(
        new GetCommand({ TableName: customRunbookTableName, Key: { runbookId: RUNBOOK_ID, version: VERSION } }),
      );
      expect(stored.Item).toMatchObject({
        testStatus: 'PASSED',
        testAccountId: '111122223333',
        testedContentDigest: REGISTERED_DIGEST,
      });
      // A passing test REMOVEs testError rather than storing a NULL, so the attribute
      // is absent (matches the string | undefined type on RunbookMetadata).
      expect(stored.Item?.testError).toBeUndefined();
    });

    it('clears a prior failure reason on a passing re-test (testError removed, not null)', async () => {
      await putRegisteredVersion(REGISTERED_DIGEST);
      await repository.recordTestResult(RUNBOOK_ID, VERSION, testResult({ testStatus: 'FAILED', testError: 'boom' }));

      await repository.recordTestResult(RUNBOOK_ID, VERSION, testResult());

      const stored = await dynamoDBDocumentClient.send(
        new GetCommand({ TableName: customRunbookTableName, Key: { runbookId: RUNBOOK_ID, version: VERSION } }),
      );
      expect(stored.Item?.testStatus).toBe('PASSED');
      // The prior failure reason is cleared by REMOVE, so the attribute no longer exists.
      expect(stored.Item?.testError).toBeUndefined();
      expect(stored.Item && 'testError' in stored.Item).toBe(false);
    });

    it('rejects recording against a version that is not registered', async () => {
      await expect(repository.recordTestResult(RUNBOOK_ID, VERSION, testResult())).rejects.toMatchObject({
        name: 'ConditionalCheckFailedException',
      });
    });

    it('rejects recording when the tested digest does not match the registered one', async () => {
      await putRegisteredVersion(REGISTERED_DIGEST);

      await expect(
        repository.recordTestResult(RUNBOOK_ID, VERSION, testResult({ testedContentDigest: 'b'.repeat(64) })),
      ).rejects.toMatchObject({ name: 'ConditionalCheckFailedException' });
    });
  });
});
