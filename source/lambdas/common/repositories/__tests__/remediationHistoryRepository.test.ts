// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { DynamoDBDocumentClient, TransactWriteCommand } from '@aws-sdk/lib-dynamodb';
import { mockClient } from 'aws-sdk-client-mock';
import { RemediationHistoryRepository } from '../remediationHistoryRepository';
import { FindingTableItem } from '@asr/data-models';

const dynamoDBMock = mockClient(DynamoDBDocumentClient);

describe('RemediationHistoryRepository', () => {
  let repository: RemediationHistoryRepository;
  const mockTableName = 'testRemediationHistoryTable';
  const mockFindingsTableName = 'testFindingsTable';
  const mockPrincipal = 'test-user';

  beforeEach(() => {
    dynamoDBMock.reset();
    repository = new RemediationHistoryRepository(
      mockPrincipal,
      mockTableName,
      dynamoDBMock as any,
      mockFindingsTableName,
    );
  });

  describe('createRemediationHistoryWithFindingUpdate', () => {
    it('should create remediation history and update finding atomically', async () => {
      const mockFinding: FindingTableItem = {
        findingType: 'security-control/Lambda.3',
        findingId: 'arn:aws:securityhub:us-east-1:123456789012:security-control/Lambda.3/finding/12345',
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
          '3#2023-01-01T00:00:00.000Z#arn:aws:securityhub:us-east-1:123456789012:security-control/Lambda.3/finding/12345',
        findingJSON: new Uint8Array(),
        findingIdControl: 'Lambda.3',
        FINDING_CONSTANT: 'finding',
        expireAt: 1234567890,
        executionId: 'test-execution-123',
      };

      dynamoDBMock.on(TransactWriteCommand).resolves({});

      const findingWithStatus = {
        ...mockFinding,
        remediationStatus: 'IN_PROGRESS' as const,
        lastUpdatedBy: 'test-user',
      };

      await repository.createRemediationHistoryWithFindingUpdate(findingWithStatus, 'test-execution-123');

      expect(dynamoDBMock.commandCalls(TransactWriteCommand)).toHaveLength(1);

      const transactCall = dynamoDBMock.commandCalls(TransactWriteCommand)[0];
      const transactItems = transactCall.args[0].input.TransactItems;

      // Verify remediation history item
      expect(transactItems).toBeDefined();
      expect(transactItems!.length).toBe(2);

      const remediationHistoryItem = transactItems![0].Put?.Item;
      expect(remediationHistoryItem).toBeDefined();
      expect(remediationHistoryItem!.findingType).toBe(mockFinding.findingType);
      expect(remediationHistoryItem!.findingId).toBe(mockFinding.findingId);
      expect(remediationHistoryItem!.accountId).toBe(mockFinding.accountId);
      expect(remediationHistoryItem!.resourceId).toBe(mockFinding.resourceId);
      expect(remediationHistoryItem!.resourceType).toBe(mockFinding.resourceType);
      expect(remediationHistoryItem!.severity).toBe(mockFinding.severity);
      expect(remediationHistoryItem!.region).toBe(mockFinding.region);
      expect(remediationHistoryItem!.remediationStatus).toBe('IN_PROGRESS');
      expect(remediationHistoryItem!.REMEDIATION_CONSTANT).toBe('remediation');
      expect(remediationHistoryItem!.lastUpdatedBy).toBe('test-user');
      expect(remediationHistoryItem!.lastUpdatedTime).toBeDefined();
      expect(remediationHistoryItem!['lastUpdatedTime#findingId']).toContain(mockFinding.findingId);
      expect(remediationHistoryItem!['findingId#executionId']).toContain(mockFinding.findingId);
      expect(remediationHistoryItem!['findingId#executionId']).toContain('#');
      expect(remediationHistoryItem!.expireAt).toBeDefined();
      expect(typeof remediationHistoryItem!.expireAt).toBe('number');

      // Verify finding update
      const updatedFinding = transactItems![1].Put?.Item;
      expect(updatedFinding).toBeDefined();
      expect(updatedFinding!.findingId).toBe(mockFinding.findingId);
      expect(updatedFinding!.remediationStatus).toBe('IN_PROGRESS');
      expect(updatedFinding!.lastUpdatedBy).toBe('test-user');
      expect(updatedFinding!.lastUpdatedTime).toBeDefined();
    });

    it('should handle transaction failures', async () => {
      const mockFinding: FindingTableItem = {
        findingType: 'security-control/Lambda.3',
        findingId: 'arn:aws:securityhub:us-east-1:123456789012:security-control/Lambda.3/finding/12345',
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
        executionId: 'test-execution-456',
      };

      const error = new Error('Transaction failed');
      dynamoDBMock.on(TransactWriteCommand).rejects(error);

      const findingWithStatus = {
        ...mockFinding,
        remediationStatus: 'IN_PROGRESS' as const,
        lastUpdatedBy: 'test-user',
      };

      await expect(
        repository.createRemediationHistoryWithFindingUpdate(findingWithStatus, 'test-execution-456'),
      ).rejects.toThrow('Transaction failed');
    });
  });
});
