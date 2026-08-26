// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { DynamoDBDocumentClient, GetCommand, PutCommand } from '@aws-sdk/lib-dynamodb';
import { RemediationHistoryRepository } from '../remediationHistoryRepository';
import { FindingTableItem } from '@asr/data-models';
import { DynamoDBTestSetup } from '../../__tests__/dynamodbSetup';
import { findingsTableName, remediationHistoryTableName } from '../../__tests__/envSetup';
import { asFindingId } from '../../__tests__/utils';
import { Clock } from '../../utils/clock';

const principal = 'test-user';
const fakeClock: Clock = { now: () => new Date('2024-06-15T12:00:00.000Z') };

const createStampedFinding = (overrides: Partial<FindingTableItem> = {}): FindingTableItem => ({
  findingType: 'security-control/Lambda.3',
  findingId: asFindingId('arn:aws:securityhub:us-east-1:123456789012:security-control/Lambda.3/finding/12345'),
  findingDescription: 'Test finding',
  accountId: '123456789012',
  resourceId: 'arn:aws:lambda:us-east-1:123456789012:function:test-function',
  resourceType: 'AwsLambdaFunction',
  resourceTypeNormalized: 'awslambdafunction',
  severity: 'HIGH',
  severityNormalized: 3,
  region: 'us-east-1',
  remediationStatus: 'NOT_STARTED',
  securityHubUpdatedAtTime: '2024-01-01T00:00:00.000Z',
  lastUpdatedTime: '2024-01-01T00:00:00.000Z',
  suppressed: false,
  creationTime: '2024-01-01T00:00:00.000Z',
  'securityHubUpdatedAtTime#findingId':
    '2024-01-01T00:00:00.000Z#arn:aws:securityhub:us-east-1:123456789012:security-control/Lambda.3/finding/12345',
  'severityNormalized#securityHubUpdatedAtTime#findingId':
    '3#2024-01-01T00:00:00.000Z#arn:aws:securityhub:us-east-1:123456789012:security-control/Lambda.3/finding/12345',
  findingJSON: new Uint8Array(),
  findingIdControl: 'Lambda.3',
  FINDING_CONSTANT: 'finding',
  expireAt: 1234567890,
  executionId: 'test-execution-789',
  remediationDueBy: '2024-02-01T00:00:00.000Z',
  enforcementConfigIds: new Set(['config-1', 'config-2']),
  ...overrides,
});

describe('RemediationHistoryRepository', () => {
  let repository: RemediationHistoryRepository;
  let dynamoDBDocumentClient: DynamoDBDocumentClient;

  const getFinding = (findingType: string, findingId: string) =>
    dynamoDBDocumentClient.send(new GetCommand({ TableName: findingsTableName, Key: { findingType, findingId } }));

  const getRemediationHistory = (findingType: string, findingIdExecutionId: string) =>
    dynamoDBDocumentClient.send(
      new GetCommand({
        TableName: remediationHistoryTableName,
        Key: { findingType, 'findingId#executionId': findingIdExecutionId },
      }),
    );

  beforeAll(async () => {
    dynamoDBDocumentClient = DynamoDBTestSetup.getDocClient();
    await DynamoDBTestSetup.createFindingsTable(findingsTableName);
    await DynamoDBTestSetup.createRemediationHistoryTable(remediationHistoryTableName);
  });

  afterAll(async () => {
    await DynamoDBTestSetup.deleteTable(findingsTableName);
    await DynamoDBTestSetup.deleteTable(remediationHistoryTableName);
  });

  beforeEach(async () => {
    await DynamoDBTestSetup.clearTable(findingsTableName, 'findings');
    await DynamoDBTestSetup.clearTable(remediationHistoryTableName, 'remediationHistory');
    repository = new RemediationHistoryRepository(
      principal,
      remediationHistoryTableName,
      dynamoDBDocumentClient,
      findingsTableName,
      fakeClock,
    );
  });

  describe('createRemediationHistoryWithFindingUpdate', () => {
    it('should create remediation history and update finding atomically', async () => {
      // ARRANGE
      const finding = createStampedFinding({
        remediationDueBy: undefined,
        enforcementConfigIds: undefined,
        executionId: 'test-execution-123',
      });
      await dynamoDBDocumentClient.send(new PutCommand({ TableName: findingsTableName, Item: finding }));

      const findingWithStatus = { ...finding, remediationStatus: 'IN_PROGRESS' as const, lastUpdatedBy: principal };

      // ACT
      await repository.createRemediationHistoryWithFindingUpdate(findingWithStatus, 'test-execution-123');

      // ASSERT: finding was updated in DDB
      const result = await getFinding(finding.findingType, finding.findingId);
      expect(result.Item).toBeDefined();
      expect(result.Item!.remediationStatus).toBe('IN_PROGRESS');
      expect(result.Item!.lastUpdatedBy).toBe(principal);
      expect(result.Item!.lastUpdatedTime).toBe('2024-06-15T12:00:00.000Z');
      expect(result.Item!.remediationDueBy).toBeUndefined();
      expect(result.Item!.enforcementConfigIds).toBeUndefined();

      // ASSERT: remediation history record was written in the same transaction
      const history = await getRemediationHistory(finding.findingType, `${finding.findingId}#test-execution-123`);
      expect(history.Item).toBeDefined();
      expect(history.Item!.remediationStatus).toBe('IN_PROGRESS');
      expect(history.Item!.executionId).toBe('test-execution-123');
      expect(history.Item!.lastUpdatedBy).toBe(principal);
      expect(history.Item!.lastUpdatedTime).toBe('2024-06-15T12:00:00.000Z');
      expect(history.Item!.REMEDIATION_CONSTANT).toBe('remediation');
    });

    it('should clear remediationDueBy and enforcementConfigIds on the updated finding', async () => {
      // ARRANGE: seed a finding that carries an enforcement stamp
      const finding = createStampedFinding();
      await dynamoDBDocumentClient.send(new PutCommand({ TableName: findingsTableName, Item: finding }));

      const findingWithStatus = { ...finding, remediationStatus: 'IN_PROGRESS' as const, lastUpdatedBy: principal };

      // ACT
      await repository.createRemediationHistoryWithFindingUpdate(findingWithStatus, 'test-execution-789');

      // ASSERT: the enforcement stamp fields are absent from the persisted finding
      const result = await getFinding(finding.findingType, finding.findingId);
      expect(result.Item).toBeDefined();
      expect(result.Item!.remediationStatus).toBe('IN_PROGRESS');
      expect(result.Item!.remediationDueBy).toBeUndefined();
      expect(result.Item!.enforcementConfigIds).toBeUndefined();
    });

    it('should throw on transaction failure', async () => {
      // ARRANGE: target a non-existent table to force a transaction failure
      const brokenRepository = new RemediationHistoryRepository(
        principal,
        remediationHistoryTableName,
        dynamoDBDocumentClient,
        'nonexistent-findings-table',
        fakeClock,
      );
      const finding = createStampedFinding({ executionId: 'test-execution-456' });
      const findingWithStatus = { ...finding, remediationStatus: 'IN_PROGRESS' as const, lastUpdatedBy: principal };

      // ACT & ASSERT
      await expect(
        brokenRepository.createRemediationHistoryWithFindingUpdate(findingWithStatus, 'test-execution-456'),
      ).rejects.toThrow(/Cannot do operations on a non-existent table/);
    });
  });
});
