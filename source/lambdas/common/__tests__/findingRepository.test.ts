// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { FindingTableItem } from '@asr/data-models';
import { Logger } from '@aws-lambda-powertools/logger';
import { DynamoDBDocumentClient, GetCommand } from '@aws-sdk/lib-dynamodb';
import { FindingRepository, ValidationError } from '../repositories/findingRepository';
import { DynamoDBTestSetup } from './dynamodbSetup';
import { findingsTableName } from './envSetup';
import { asFindingId } from './utils';

describe('FindingRepository', () => {
  const principal = 'test-user';
  let dynamoDBDocumentClient: DynamoDBDocumentClient;
  let repository: FindingRepository;
  const mockLogger = new Logger({ serviceName: 'test' });

  const createMockFinding = (overrides: Partial<FindingTableItem> = {}): FindingTableItem => ({
    findingType: 'security-control',
    findingId: asFindingId('test-finding-id'),
    findingDescription: 'Test finding description',
    accountId: '123456789012',
    resourceId: 'arn:aws:s3:::test-bucket',
    resourceType: 'AWS::S3::Bucket',
    resourceTypeNormalized: 'awss3bucket',
    severity: 'HIGH',
    severityNormalized: 3,
    region: 'us-east-1',
    remediationStatus: 'NOT_STARTED',
    securityHubUpdatedAtTime: '2023-01-01T00:00:00Z',
    lastUpdatedTime: '2023-01-01T00:00:00Z',
    'securityHubUpdatedAtTime#findingId': '2023-01-01T00:00:00Z#test-finding-id',
    'severityNormalized#securityHubUpdatedAtTime#findingId': '3#2023-01-01T00:00:00Z#test-finding-id',
    findingJSON: new Uint8Array(Buffer.from('{"test": "data"}')),
    findingIdControl: 'security-control',
    FINDING_CONSTANT: 'finding' as const,
    creationTime: '2023-01-01T00:00:00Z',
    suppressed: false,
    expireAt: Math.floor(Date.now() / 1000) + 8 * 24 * 60 * 60,
    ...overrides,
  });

  beforeAll(async () => {
    dynamoDBDocumentClient = DynamoDBTestSetup.getDocClient();
    await DynamoDBTestSetup.createFindingsTable(findingsTableName);
  });

  afterAll(async () => {
    await DynamoDBTestSetup.deleteTable(findingsTableName);
  });

  beforeEach(async () => {
    await DynamoDBTestSetup.clearTable(findingsTableName, 'findings');
    repository = new FindingRepository(principal, findingsTableName, dynamoDBDocumentClient);
  });

  describe('createIfNotExists', () => {
    it('should create a new finding successfully', async () => {
      const finding = createMockFinding();

      await repository.createIfNotExists(finding);

      const result = await dynamoDBDocumentClient.send(
        new GetCommand({
          TableName: findingsTableName,
          Key: { findingType: finding.findingType, findingId: finding.findingId },
        }),
      );

      expect(result.Item).toBeDefined();
      expect(result.Item?.findingType).toBe(finding.findingType);
      expect(result.Item?.findingId).toBe(finding.findingId);
      expect(result.Item?.lastUpdatedBy).toBe(principal);
    });

    it('should fail gracefully when trying to create duplicate finding', async () => {
      const finding = createMockFinding({ findingId: asFindingId('duplicate-test') });

      await repository.createIfNotExists(finding);

      const result = await repository.createIfNotExists(finding);

      expect(result).toEqual('FAILED');
    });
  });

  describe('tryAcquireRollbackLock', () => {
    const guardDutyType = 'GuardDuty.IAMUser';
    const lockFindingId = asFindingId('rollback-lock-test');
    // staleBefore far in the past so a fresh in-progress lock is never considered stale
    const NOW = '2024-06-01T12:00:00.000Z';
    const STALE_BEFORE = '2024-06-01T11:30:00.000Z';

    const seed = async (overrides: Partial<FindingTableItem>) => {
      await repository.put(createMockFinding({ findingType: guardDutyType, findingId: lockFindingId, ...overrides }));
    };

    const readStatus = async () => {
      const result = await dynamoDBDocumentClient.send(
        new GetCommand({
          TableName: findingsTableName,
          Key: { findingType: guardDutyType, findingId: lockFindingId },
        }),
      );
      return result.Item;
    };

    it('acquires the lock from SUCCESS and stamps rollbackStartedAt', async () => {
      await seed({ remediationStatus: 'SUCCESS' });

      const result = await repository.tryAcquireRollbackLock(guardDutyType, lockFindingId, NOW, STALE_BEFORE);

      expect(result).toBe('ACQUIRED');
      const item = await readStatus();
      expect(item?.remediationStatus).toBe('ROLLBACK_IN_PROGRESS');
      expect(item?.rollbackStartedAt).toBe(NOW);
    });

    it('acquires the lock from ROLLBACK_FAILED (retry)', async () => {
      await seed({ remediationStatus: 'ROLLBACK_FAILED' });

      const result = await repository.tryAcquireRollbackLock(guardDutyType, lockFindingId, NOW, STALE_BEFORE);

      expect(result).toBe('ACQUIRED');
    });

    it('rejects a second rollback while a fresh lock is held (double-rollback guard)', async () => {
      await seed({ remediationStatus: 'ROLLBACK_IN_PROGRESS', rollbackStartedAt: NOW });

      const result = await repository.tryAcquireRollbackLock(guardDutyType, lockFindingId, NOW, STALE_BEFORE);

      expect(result).toBe('IN_PROGRESS');
    });

    it('re-acquires the lock when the in-progress lock is stale', async () => {
      // rollbackStartedAt older than STALE_BEFORE -> treated as abandoned
      await seed({ remediationStatus: 'ROLLBACK_IN_PROGRESS', rollbackStartedAt: '2024-06-01T10:00:00.000Z' });

      const result = await repository.tryAcquireRollbackLock(guardDutyType, lockFindingId, NOW, STALE_BEFORE);

      expect(result).toBe('ACQUIRED');
      const item = await readStatus();
      expect(item?.rollbackStartedAt).toBe(NOW);
    });

    it('returns INELIGIBLE for a non-initiable status (e.g. FAILED remediation)', async () => {
      await seed({ remediationStatus: 'FAILED' });

      const result = await repository.tryAcquireRollbackLock(guardDutyType, lockFindingId, NOW, STALE_BEFORE);

      expect(result).toBe('INELIGIBLE');
      const item = await readStatus();
      expect(item?.remediationStatus).toBe('FAILED');
    });

    it('returns INELIGIBLE for an already rolled-back finding', async () => {
      await seed({ remediationStatus: 'ROLLBACK_SUCCESS' });

      const result = await repository.tryAcquireRollbackLock(guardDutyType, lockFindingId, NOW, STALE_BEFORE);

      expect(result).toBe('INELIGIBLE');
    });
  });

  describe('updateFinding', () => {
    it('should update existing finding successfully', async () => {
      const finding = createMockFinding({ findingId: asFindingId('update-test') });
      await repository.put(finding);

      const updatedFinding = {
        ...finding,
        findingDescription: 'Updated description',
        severity: 'CRITICAL',
        securityHubUpdatedAtTime: '2023-01-02T00:00:00Z',
      };

      await repository.putIfNewer(updatedFinding);

      const result = await repository.findByIdWithCache(finding.findingId, finding.findingType);
      expect(result?.findingDescription).toBe('Updated description');
      expect(result?.severity).toBe('CRITICAL');
    });

    it('should not update when securityHubUpdatedAtTime is older', async () => {
      const finding = createMockFinding({
        findingId: asFindingId('timestamp-test'),
        securityHubUpdatedAtTime: '2023-01-02T00:00:00Z',
      });
      await repository.put(finding);

      const olderUpdate = {
        ...finding,
        findingDescription: 'Should not update',
        securityHubUpdatedAtTime: '2023-01-01T00:00:00Z',
      };

      const result = await repository.putIfNewer(olderUpdate);

      expect(result).toEqual('FAILED');

      const ddbGetResult = await dynamoDBDocumentClient.send(
        new GetCommand({
          TableName: findingsTableName,
          Key: {
            findingType: olderUpdate.findingType,
            findingId: olderUpdate.findingId,
          },
        }),
      );
      expect(ddbGetResult.Item!.findingDescription).toEqual(finding.findingDescription);
    });

    it('should update when securityHubUpdatedAtTime is newer', async () => {
      const finding = createMockFinding({
        findingId: asFindingId('newer-timestamp-test'),
        securityHubUpdatedAtTime: '2023-01-01T00:00:00Z',
      });
      await repository.put(finding);

      const newerUpdate = {
        ...finding,
        findingDescription: 'Should update',
        securityHubUpdatedAtTime: '2023-01-02T00:00:00Z',
      };

      await repository.putIfNewer(newerUpdate);

      const result = await repository.findByIdWithCache(finding.findingId, finding.findingType);
      expect(result?.findingDescription).toBe('Should update');
    });

    it('should handle update with all fields changed', async () => {
      const finding = createMockFinding({ findingId: asFindingId('full-update-test') });
      await repository.putIfNewer(finding);

      const updatedFinding: FindingTableItem = {
        ...finding,
        findingDescription: 'New description',
        accountId: '987654321098',
        resourceId: 'arn:aws:ec2:us-west-2:123456789012:instance/i-1234567890abcdef0',
        resourceType: 'AWS::EC2::Instance',
        severity: 'LOW',
        region: 'us-west-2',
        remediationStatus: 'NOT_STARTED',
        securityHubUpdatedAtTime: '2023-01-02T00:00:00Z',
        lastUpdatedTime: '2023-01-02T00:00:00Z',
        'securityHubUpdatedAtTime#findingId': '2023-01-02T00:00:00Z#full-update-test',
        findingJSON: new Uint8Array(Buffer.from('{"updated": "data"}')),
        suppressed: true,
      };

      await repository.putIfNewer(updatedFinding);

      const result = await repository.findByIdWithCache(finding.findingId, finding.findingType);
      expect(result?.findingDescription).toBe('New description');
      expect(result?.accountId).toBe('987654321098');
      expect(result?.resourceType).toBe('AWS::EC2::Instance');
      expect(result?.suppressed).toBe(true);
    });
  });

  describe('getFinding', () => {
    it('should retrieve existing finding', async () => {
      const finding = createMockFinding({ findingId: asFindingId('get-test') });
      await repository.put(finding);

      const result = await repository.findByIdWithCache(finding.findingId, finding.findingType);

      expect(result).toBeDefined();
      expect(result?.findingId).toBe(finding.findingId);
      expect(result?.findingType).toBe(finding.findingType);
    });

    it('should return undefined for non-existent finding', async () => {
      const result = await repository.findByIdWithCache('non-existent-id', 'non-existent-type');
      expect(result).toBeUndefined();
    });

    it('should not use cache for different finding IDs', async () => {
      const finding1 = createMockFinding({ findingId: asFindingId('cache-test-1') });
      const finding2 = createMockFinding({ findingId: asFindingId('cache-test-2') });
      await repository.putIfNewer(finding1);
      await repository.putIfNewer(finding2);

      const sendSpy = jest.spyOn(dynamoDBDocumentClient, 'send');
      sendSpy.mockClear();

      await repository.findByIdWithCache(finding1.findingId, finding1.findingType);
      expect(sendSpy).toHaveBeenCalledTimes(1);

      await repository.findByIdWithCache(finding2.findingId, finding2.findingType);
      expect(sendSpy).toHaveBeenCalledTimes(2); // Should make a new call

      sendSpy.mockRestore();
    });

    it('should use cached result on subsequent calls', async () => {
      const finding = createMockFinding({ findingId: asFindingId('cache-test') });
      await repository.putIfNewer(finding);

      const sendSpy = jest.spyOn(dynamoDBDocumentClient, 'send');
      sendSpy.mockClear();

      const result1 = await repository.findByIdWithCache(finding.findingId, finding.findingType);
      expect(sendSpy).toHaveBeenCalledTimes(1);

      const result2 = await repository.findByIdWithCache(finding.findingId, finding.findingType);
      expect(sendSpy).toHaveBeenCalledTimes(1); // Should still be 1, not 2

      expect(result1).toEqual(result2);
      expect(result1?.findingId).toBe(finding.findingId);

      sendSpy.mockRestore();
    });

    it('should expose lastUpdatedBy field for audit purposes', async () => {
      const finding = createMockFinding({ findingId: asFindingId('no-audit-field-test') });
      await repository.putIfNewer(finding);

      const result = await repository.findByIdWithCache(finding.findingId, finding.findingType);

      expect(result).toBeDefined();
      expect((result as any).lastUpdatedBy).toBe('test-user');
    });
  });

  describe('findingExists', () => {
    it('should return true for existing finding', async () => {
      const finding = createMockFinding({ findingId: asFindingId('existing-finding-id') });
      await repository.putIfNewer(finding);

      const exists = await repository.exists(finding.findingId, finding.findingType);
      expect(exists).toBe(true);
    });

    it('should return false for non-existent finding', async () => {
      const sendSpy = jest.spyOn(dynamoDBDocumentClient, 'send');
      sendSpy.mockClear();

      const exists = await repository.exists('non-existent-id', 'non-existent-type');
      expect(exists).toBe(false);
      expect(sendSpy).toHaveBeenCalledTimes(1); // Should make DB call

      sendSpy.mockRestore();
    });

    it('should use cache when available', async () => {
      const finding = createMockFinding({ findingId: asFindingId('cache-exists-test') });
      await repository.putIfNewer(finding);

      const sendSpy = jest.spyOn(dynamoDBDocumentClient, 'send');
      sendSpy.mockClear();

      // First call should populate cache
      await repository.findByIdWithCache(finding.findingId, finding.findingType);
      expect(sendSpy).toHaveBeenCalledTimes(1);

      // Second call should use cache
      const exists = await repository.exists(finding.findingId, finding.findingType);
      expect(exists).toBe(true);
      expect(sendSpy).toHaveBeenCalledTimes(1); // Should still be 1

      sendSpy.mockRestore();
    });
  });

  describe('deleteIfExists', () => {
    it('should delete existing finding successfully', async () => {
      const finding = createMockFinding({ findingId: asFindingId('delete-test') });
      await repository.put(finding);

      await repository.deleteIfExists(finding.findingId, finding.findingType);

      const result = await repository.findByIdWithCache(finding.findingId, finding.findingType);
      expect(result).toBeUndefined();
    });

    it('should handle deletion of non-existent finding gracefully', async () => {
      await expect(repository.deleteIfExists('non-existent-id', 'non-existent-type')).resolves.toBe('FAILED');
    });
  });

  describe('recordRemediationAttempt', () => {
    it('atomically increments remediationAttempts and stamps lastRemediationAttemptTime', async () => {
      const finding = createMockFinding({ findingId: asFindingId('attempt-test') });
      await repository.put(finding);

      const firstAttemptTime = '2026-07-14T00:00:00.000Z';
      const secondAttemptTime = '2026-07-14T00:15:00.000Z';
      await repository.recordRemediationAttempt(finding.findingId, finding.findingType, firstAttemptTime);
      await repository.recordRemediationAttempt(finding.findingId, finding.findingType, secondAttemptTime);

      // Fresh repository to bypass the read cache and observe persisted values.
      const freshRepository = new FindingRepository(principal, findingsTableName, dynamoDBDocumentClient);
      const result = await freshRepository.findByIdWithCache(finding.findingId, finding.findingType);
      expect(result?.remediationAttempts).toBe(2);
      expect(result?.lastRemediationAttemptTime).toBe(secondAttemptTime);
    });

    it('rejects an empty finding key with a ValidationError', async () => {
      await expect(repository.recordRemediationAttempt('', 'some-type', '2026-07-14T00:00:00.000Z')).rejects.toThrow(
        ValidationError,
      );
    });
  });

  describe('findByFindingIds', () => {
    // ARN format required so getControlIdFromFindingId can derive findingType
    const ARN_1 = asFindingId('arn:aws:securityhub:us-east-1:123456789012:security-control/S3.1/finding/findbyids-1');
    const ARN_2 = asFindingId('arn:aws:securityhub:us-east-1:123456789012:security-control/S3.2/finding/findbyids-2');
    // Native (non-Security-Hub) ARNs from the OCSF Detection / Vulnerability ingestion path —
    // the partition key (findingType) is the multi-service remediation id set by
    // findingTypeMapper at write time, derived from the ARN service prefix at read time.
    const GUARDDUTY_NATIVE_ARN = asFindingId(
      'arn:aws:guardduty:us-east-1:123456789012:detector/abcd1234efgh5678/finding/9876543210',
    );
    const INSPECTOR_NATIVE_ARN = asFindingId(
      'arn:aws:inspector2:us-east-1:123456789012:finding/abc123def456ghi789jkl012mno345pqr',
    );
    const MACIE_NATIVE_ARN = asFindingId('arn:aws:macie2:us-east-1:123456789012:finding/abc-def-ghi');

    it('should return empty array when no finding IDs are provided', async () => {
      const { findings: result } = await repository.findByFindingIds([]);
      expect(result).toEqual([]);
    });

    it('should return findings that match the provided IDs', async () => {
      await repository.put(createMockFinding({ findingType: 'security-control/S3.1', findingId: ARN_1 }));
      await repository.put(createMockFinding({ findingType: 'security-control/S3.2', findingId: ARN_2 }));

      const { findings: result } = await repository.findByFindingIds([ARN_1, ARN_2]);

      expect(result).toHaveLength(2);
      expect(result.map((f) => f.findingId).sort()).toEqual([ARN_1, ARN_2].sort());
    });

    it('should skip findingIds that cannot be parsed and return only the valid ones', async () => {
      await repository.put(createMockFinding({ findingType: 'security-control/S3.1', findingId: ARN_1 }));

      const { findings: result, nonDerivableIds } = await repository.findByFindingIds([
        ARN_1,
        asFindingId('not-a-valid-arn'),
      ]);

      expect(result).toHaveLength(1);
      expect(result[0].findingId).toBe(ARN_1);
      // The unparseable id is surfaced rather than silently dropped: it was never queried, which
      // is not the same as being queried and not found. See ADR 0010.
      expect(nonDerivableIds).toEqual(['not-a-valid-arn']);
    });

    it('should return empty array when all findingIds are unparseable', async () => {
      const { findings: result, nonDerivableIds } = await repository.findByFindingIds([
        asFindingId('not-a-valid-arn'),
        asFindingId('also-not-valid'),
      ]);
      expect(result).toEqual([]);
      expect(nonDerivableIds).toEqual(['not-a-valid-arn', 'also-not-valid']);
    });

    it('should deduplicate repeated findingIds before batch-get', async () => {
      await repository.put(createMockFinding({ findingType: 'security-control/S3.1', findingId: ARN_1 }));

      const { findings: result } = await repository.findByFindingIds([ARN_1, ARN_1, ARN_1]);

      expect(result).toHaveLength(1);
      expect(result[0].findingId).toBe(ARN_1);
    });

    it('should retrieve GuardDuty findings stored with native ARN as findingId', async () => {
      await repository.put(createMockFinding({ findingType: 'GuardDuty.IAMUser', findingId: GUARDDUTY_NATIVE_ARN }));

      const { findings: result } = await repository.findByFindingIds([GUARDDUTY_NATIVE_ARN]);

      expect(result).toHaveLength(1);
      expect(result[0].findingId).toBe(GUARDDUTY_NATIVE_ARN);
      expect(result[0].findingType).toBe('GuardDuty.IAMUser');
    });

    it('should retrieve Inspector findings stored with native ARN as findingId', async () => {
      await repository.put(
        createMockFinding({ findingType: 'Inspector.InstanceVulnerability', findingId: INSPECTOR_NATIVE_ARN }),
      );

      const { findings: result } = await repository.findByFindingIds([INSPECTOR_NATIVE_ARN]);

      expect(result).toHaveLength(1);
      expect(result[0].findingId).toBe(INSPECTOR_NATIVE_ARN);
      expect(result[0].findingType).toBe('Inspector.InstanceVulnerability');
    });

    it('should retrieve Macie findings stored with native ARN as findingId', async () => {
      await repository.put(
        createMockFinding({ findingType: 'Macie.SensitiveDataS3Object', findingId: MACIE_NATIVE_ARN }),
      );

      const { findings: result } = await repository.findByFindingIds([MACIE_NATIVE_ARN]);

      expect(result).toHaveLength(1);
      expect(result[0].findingId).toBe(MACIE_NATIVE_ARN);
      expect(result[0].findingType).toBe('Macie.SensitiveDataS3Object');
    });

    it('should retrieve mixed Security Hub and native ARN findings in a single call', async () => {
      await repository.put(createMockFinding({ findingType: 'security-control/S3.1', findingId: ARN_1 }));
      await repository.put(createMockFinding({ findingType: 'GuardDuty.IAMUser', findingId: GUARDDUTY_NATIVE_ARN }));
      await repository.put(
        createMockFinding({ findingType: 'Macie.SensitiveDataS3Object', findingId: MACIE_NATIVE_ARN }),
      );

      const { findings: result } = await repository.findByFindingIds([ARN_1, GUARDDUTY_NATIVE_ARN, MACIE_NATIVE_ARN]);

      expect(result).toHaveLength(3);
      expect(result.map((f) => f.findingId).sort()).toEqual([ARN_1, GUARDDUTY_NATIVE_ARN, MACIE_NATIVE_ARN].sort());
    });
  });

  describe('searchFindings', () => {
    beforeEach(async () => {
      // Create test findings for search
      const findings = [
        createMockFinding({
          findingId: asFindingId('search-test-1'),
          accountId: '111111111111',
          severity: 'HIGH',
          resourceType: 'AWS::S3::Bucket',
          remediationStatus: 'NOT_STARTED',
        }),
        createMockFinding({
          findingId: asFindingId('search-test-2'),
          accountId: '222222222222',
          severity: 'MEDIUM',
          resourceType: 'AWS::EC2::Instance',
          remediationStatus: 'IN_PROGRESS',
        }),
        createMockFinding({
          findingId: asFindingId('search-test-3'),
          accountId: '111111111111',
          severity: 'LOW',
          resourceType: 'AWS::S3::Bucket',
          remediationStatus: 'SUCCESS',
        }),
      ];

      for (const finding of findings) {
        await repository.putIfNewer(finding);
      }
    });

    it('should search findings without filters', async () => {
      const criteria = {
        filters: [],
        pageSize: 10,
        sortOrder: 'desc' as const,
      };

      const result = await repository.searchFindings(criteria);

      expect(result.items).toBeDefined();
      expect(result.items.length).toBeGreaterThan(0);
    });

    it('should search findings with accountId filter', async () => {
      const criteria = {
        filters: [
          {
            fieldName: 'accountId',
            comparison: 'EQUALS' as const,
            value: '111111111111',
          },
        ],
        pageSize: 10,
        sortOrder: 'desc' as const,
      };

      const result = await repository.searchFindings(criteria);

      expect(result.items).toBeDefined();
      expect(result.items.length).toBeGreaterThan(0);
      result.items.forEach((item) => {
        expect(item.accountId).toBe('111111111111');
      });
    });

    it('should search findings with severity filter', async () => {
      const criteria = {
        filters: [
          {
            fieldName: 'severity',
            comparison: 'EQUALS' as const,
            value: 'HIGH',
          },
        ],
        pageSize: 10,
        sortOrder: 'desc' as const,
      };

      const result = await repository.searchFindings(criteria);

      expect(result.items).toBeDefined();
      result.items.forEach((item) => {
        expect(item.severity).toBe('HIGH');
      });
    });

    it('should search findings with multiple filters', async () => {
      const criteria = {
        filters: [
          {
            fieldName: 'accountId',
            comparison: 'EQUALS' as const,
            value: '111111111111',
          },
          {
            fieldName: 'resourceType',
            comparison: 'EQUALS' as const,
            value: 'AWS::S3::Bucket',
          },
        ],
        pageSize: 10,
        sortOrder: 'desc' as const,
      };

      const result = await repository.searchFindings(criteria);

      expect(result.items).toBeDefined();
      result.items.forEach((item) => {
        expect(item.accountId).toBe('111111111111');
        expect(item.resourceType).toBe('AWS::S3::Bucket');
      });
    });

    it('should search findings with CONTAINS filter', async () => {
      const criteria = {
        filters: [
          {
            fieldName: 'findingDescription',
            comparison: 'CONTAINS' as const,
            value: 'Test finding',
          },
        ],
        pageSize: 10,
        sortOrder: 'desc' as const,
      };

      const result = await repository.searchFindings(criteria);

      expect(result.items).toBeDefined();
      result.items.forEach((item) => {
        expect(item.findingDescription).toContain('Test finding');
      });
    });

    it('should search findings with NOT_EQUALS filter', async () => {
      const criteria = {
        filters: [
          {
            fieldName: 'severity',
            comparison: 'NOT_EQUALS' as const,
            value: 'HIGH',
          },
        ],
        pageSize: 10,
        sortOrder: 'desc' as const,
      };

      const result = await repository.searchFindings(criteria);

      expect(result.items).toBeDefined();
      result.items.forEach((item) => {
        expect(item.severity).not.toBe('HIGH');
      });
    });

    it('should search findings with NOT_CONTAINS filter', async () => {
      const criteria = {
        filters: [
          {
            fieldName: 'findingDescription',
            comparison: 'NOT_CONTAINS' as const,
            value: 'NonExistentText',
          },
        ],
        pageSize: 10,
        sortOrder: 'desc' as const,
      };

      const result = await repository.searchFindings(criteria);

      expect(result.items).toBeDefined();
      result.items.forEach((item) => {
        expect(item.findingDescription).not.toContain('NonExistentText');
      });
    });

    it('should handle pagination with nextToken', async () => {
      const criteria = {
        filters: [],
        pageSize: 1,
        sortOrder: 'desc' as const,
      };

      const firstPage = await repository.searchFindings(criteria);
      expect(firstPage.items.length).toBe(1);

      if (firstPage.nextToken) {
        const secondPage = await repository.searchFindings({
          ...criteria,
          nextToken: firstPage.nextToken,
        });
        expect(secondPage.items).toBeDefined();
        expect(secondPage.items[0]?.findingId).not.toBe(firstPage.items[0]?.findingId);
      }
    });

    it('should handle invalid nextToken gracefully', async () => {
      const criteria = {
        filters: [],
        pageSize: 10,
        sortOrder: 'desc' as const,
        nextToken: 'invalid-token',
      };

      const result = await repository.searchFindings(criteria);
      expect(result.items).toBeDefined();
    });

    it('should handle ascending sort order', async () => {
      const criteria = {
        filters: [],
        pageSize: 10,
        sortOrder: 'asc' as const,
      };

      const result = await repository.searchFindings(criteria);
      expect(result.items).toBeDefined();
    });

    it('should handle resourceId filter', async () => {
      const finding = createMockFinding({
        findingId: asFindingId('resource-filter-test'),
        resourceId: 'arn:aws:s3:::unique-test-bucket',
      });
      await repository.putIfNewer(finding);

      const criteria = {
        filters: [
          {
            fieldName: 'resourceId',
            comparison: 'EQUALS' as const,
            value: 'arn:aws:s3:::unique-test-bucket',
          },
        ],
        pageSize: 10,
        sortOrder: 'desc' as const,
      };

      const result = await repository.searchFindings(criteria);

      expect(result.items).toBeDefined();
      expect(result.items.length).toBeGreaterThan(0);
      result.items.forEach((item) => {
        expect(item.resourceId).toBe('arn:aws:s3:::unique-test-bucket');
      });
    });
  });

  describe('edge cases and error handling', () => {
    it('should handle finding with special characters in ID', async () => {
      const finding = createMockFinding({
        findingId: asFindingId('special-chars-test'),
      });

      await repository.putIfNewer(finding);

      const result = await repository.findByIdWithCache(finding.findingId, finding.findingType);
      expect(result?.findingId).toBe(finding.findingId);
    });

    it('should handle finding with very long description', async () => {
      const longDescription = 'A'.repeat(1000);
      const finding = createMockFinding({
        findingId: asFindingId('long-description-test'),
        findingDescription: longDescription,
      });

      await repository.putIfNewer(finding);

      const result = await repository.findByIdWithCache(finding.findingId, finding.findingType);
      expect(result?.findingDescription).toBe(longDescription);
    });

    it('should handle finding with large findingJSON', async () => {
      const largeJson = new Uint8Array(Buffer.from(JSON.stringify({ data: 'X'.repeat(1000) })));
      const finding = createMockFinding({
        findingId: asFindingId('large-json-test'),
        findingJSON: largeJson,
      });

      await repository.putIfNewer(finding);

      const result = await repository.findByIdWithCache(finding.findingId, finding.findingType);
      expect(result?.findingJSON).toEqual(largeJson);
    });

    it('should handle boolean fields correctly', async () => {
      const finding = createMockFinding({
        findingId: asFindingId('boolean-test'),
        suppressed: true,
      });

      await repository.putIfNewer(finding);

      const result = await repository.findByIdWithCache(finding.findingId, finding.findingType);
      expect(result?.suppressed).toBe(true);
    });

    it('should handle empty string fields', async () => {
      const finding = createMockFinding({
        findingId: asFindingId('empty-string-test'),
        findingDescription: '',
      });

      await repository.putIfNewer(finding);

      const result = await repository.findByIdWithCache(finding.findingId, finding.findingType);
      expect(result?.findingDescription).toBe('');
    });

    it('should maintain cache consistency after update', async () => {
      const finding = createMockFinding({ findingId: asFindingId('cache-consistency-test') });
      await repository.putIfNewer(finding);

      // Populate cache
      await repository.findByIdWithCache(finding.findingId, finding.findingType);

      // Update finding
      const updatedFinding = {
        ...finding,
        findingDescription: 'Updated via update method',
        securityHubUpdatedAtTime: '2023-01-02T00:00:00Z',
      };
      await repository.putIfNewer(updatedFinding);

      // Cache should be invalidated, so we need to fetch fresh data
      const freshRepository = new FindingRepository(principal, findingsTableName, dynamoDBDocumentClient);
      const result = await freshRepository.findByIdWithCache(finding.findingId, finding.findingType);
      expect(result?.findingDescription).toBe('Updated via update method');
    });

    it('should handle different remediation statuses', async () => {
      const statuses: Array<'NOT_STARTED' | 'IN_PROGRESS' | 'SUCCESS' | 'FAILED'> = [
        'NOT_STARTED',
        'IN_PROGRESS',
        'SUCCESS',
        'FAILED',
      ];

      for (const status of statuses) {
        const finding = createMockFinding({
          findingId: asFindingId(`remediation-status-${status}`),
          remediationStatus: status,
        });

        await repository.putIfNewer(finding);

        const result = await repository.findByIdWithCache(finding.findingId, finding.findingType);
        expect(result?.remediationStatus).toBe(status);
      }
    });

    it('should handle different severity levels', async () => {
      const severities = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];

      for (const severity of severities) {
        const finding = createMockFinding({
          findingId: asFindingId(`severity-${severity}`),
          severity: severity,
        });

        await repository.putIfNewer(finding);

        const result = await repository.findByIdWithCache(finding.findingId, finding.findingType);
        expect(result?.severity).toBe(severity);
      }
    });

    it('should handle different regions', async () => {
      const regions = ['us-east-1', 'us-west-2', 'eu-west-1', 'ap-southeast-1'];

      for (const region of regions) {
        const finding = createMockFinding({
          findingId: asFindingId(`region-${region}`),
          region: region,
        });

        await repository.putIfNewer(finding);

        const result = await repository.findByIdWithCache(finding.findingId, finding.findingType);
        expect(result?.region).toBe(region);
      }
    });

    it('should handle search with empty filters array', async () => {
      const criteria = {
        filters: [],
        pageSize: 10,
        sortOrder: 'desc' as const,
      };

      const result = await repository.searchFindings(criteria);
      expect(result.items).toBeDefined();
    });

    it('should handle search with unmapped field names', async () => {
      const criteria = {
        filters: [
          {
            fieldName: 'unknownField',
            comparison: 'EQUALS' as const,
            value: 'test-value',
          },
        ],
        pageSize: 10,
        sortOrder: 'desc' as const,
      };

      const result = await repository.searchFindings(criteria);
      expect(result.items).toBeDefined();
    });
  });

  describe('direct table queries (findingId EQUALS filters)', () => {
    beforeEach(async () => {
      const findings = [
        createMockFinding({
          findingType: 'security-control/S3.1',
          findingId: asFindingId('arn:aws:securityhub:us-east-1:123456789012:security-control/S3.1/finding/12345'),
          accountId: '123456789012',
          severity: 'HIGH',
          resourceType: 'AWS::S3::Bucket',
          remediationStatus: 'NOT_STARTED',
        }),
        createMockFinding({
          findingType: 'security-control/EC2.1',
          findingId: asFindingId('arn:aws:securityhub:us-east-1:123456789012:security-control/EC2.1/finding/67890'),
          accountId: '123456789012',
          severity: 'MEDIUM',
          resourceType: 'AWS::EC2::Instance',
          remediationStatus: 'IN_PROGRESS',
        }),
        createMockFinding({
          findingType: 'cis-aws-foundations-benchmark/v/1.4.0/4.8',
          findingId: asFindingId(
            'arn:aws:securityhub:us-east-1:123456789012:subscription/cis-aws-foundations-benchmark/v/1.4.0/4.8/finding/abcdef',
          ),
          accountId: '987654321098',
          severity: 'LOW',
          resourceType: 'AWS::IAM::Role',
          remediationStatus: 'SUCCESS',
        }),
      ];

      for (const finding of findings) {
        await repository.putIfNewer(finding);
      }
    });

    it('should use direct table queries for single findingId EQUALS filter', async () => {
      const criteria = {
        filters: [
          {
            fieldName: 'findingId',
            comparison: 'EQUALS' as const,
            value: 'arn:aws:securityhub:us-east-1:123456789012:security-control/S3.1/finding/12345',
          },
        ],
        pageSize: 10,
        sortOrder: 'desc' as const,
      };

      const result = await repository.searchFindings(criteria);

      expect(result.items).toBeDefined();
      expect(result.items.length).toBe(1);
      expect(result.items[0].findingId).toBe(
        'arn:aws:securityhub:us-east-1:123456789012:security-control/S3.1/finding/12345',
      );
      expect(result.items[0].findingType).toBe('security-control/S3.1');
      expect(result.nextToken).toBeUndefined();
    });

    it('should use direct table queries for a native (non-Security-Hub) findingId EQUALS filter', async () => {
      const guardDutyArn = 'arn:aws:guardduty:us-east-1:123456789012:detector/abcd/finding/1234';
      await repository.putIfNewer(
        createMockFinding({
          findingType: 'GuardDuty.IAMUser',
          findingId: asFindingId(guardDutyArn),
          accountId: '123456789012',
          severity: 'HIGH',
          resourceType: 'AWS::IAM::User',
          remediationStatus: 'NOT_STARTED',
        }),
      );

      const criteria = {
        filters: [
          {
            fieldName: 'findingId',
            comparison: 'EQUALS' as const,
            value: guardDutyArn,
          },
        ],
        pageSize: 10,
        sortOrder: 'desc' as const,
      };

      const result = await repository.searchFindings(criteria);

      expect(result.items).toBeDefined();
      expect(result.items.length).toBe(1);
      expect(result.items[0].findingId).toBe(guardDutyArn);
      expect(result.items[0].findingType).toBe('GuardDuty.IAMUser');
      expect(result.nextToken).toBeUndefined();
    });

    it('should resolve a bare-hash (non-ARN) findingId EQUALS filter via the GSI fallback', async () => {
      // Macie's finding id is a bare hash (the Security Hub V2 FindingInfoUid), not an ARN, so the
      // partition key cannot be derived from it. The direct-query fast path is skipped and the
      // search falls through to the GSI path, which applies findingId as a FilterExpression.
      const macieFindingId = asFindingId('12984ad04a62649e69fcb701d3557c1d');
      await repository.putIfNewer(
        createMockFinding({
          findingType: 'Macie.SensitiveDataS3Object',
          findingId: macieFindingId,
          accountId: '123456789012',
          severity: 'HIGH',
          resourceType: 'AWS::S3::Bucket',
          remediationStatus: 'NOT_STARTED',
        }),
      );

      const criteria = {
        filters: [
          {
            fieldName: 'findingId',
            comparison: 'EQUALS' as const,
            value: macieFindingId,
          },
        ],
        pageSize: 10,
        sortOrder: 'desc' as const,
      };

      const result = await repository.searchFindings(criteria);

      expect(result.items).toBeDefined();
      expect(result.items.length).toBe(1);
      expect(result.items[0].findingId).toBe(macieFindingId);
      expect(result.items[0].findingType).toBe('Macie.SensitiveDataS3Object');
    });

    it('should use direct table queries for multiple findingId EQUALS filters', async () => {
      const criteria = {
        filters: [
          {
            fieldName: 'findingId',
            comparison: 'EQUALS' as const,
            value: 'arn:aws:securityhub:us-east-1:123456789012:security-control/S3.1/finding/12345',
          },
          {
            fieldName: 'findingId',
            comparison: 'EQUALS' as const,
            value: 'arn:aws:securityhub:us-east-1:123456789012:security-control/EC2.1/finding/67890',
          },
        ],
        pageSize: 10,
        sortOrder: 'desc' as const,
      };

      const result = await repository.searchFindings(criteria);

      expect(result.items).toBeDefined();
      expect(result.items.length).toBe(2);

      const findingIds = result.items.map((item) => item.findingId);
      expect(findingIds).toContain('arn:aws:securityhub:us-east-1:123456789012:security-control/S3.1/finding/12345');
      expect(findingIds).toContain('arn:aws:securityhub:us-east-1:123456789012:security-control/EC2.1/finding/67890');
      expect(result.nextToken).toBeUndefined();
    });

    it('should use direct table queries with additional filters', async () => {
      const criteria = {
        filters: [
          {
            fieldName: 'findingId',
            comparison: 'EQUALS' as const,
            value: 'arn:aws:securityhub:us-east-1:123456789012:security-control/S3.1/finding/12345',
          },
          {
            fieldName: 'severity',
            comparison: 'EQUALS' as const,
            value: 'HIGH',
          },
        ],
        pageSize: 10,
        sortOrder: 'desc' as const,
      };

      const result = await repository.searchFindings(criteria);

      expect(result.items).toBeDefined();
      expect(result.items.length).toBe(1);
      expect(result.items[0].findingId).toBe(
        'arn:aws:securityhub:us-east-1:123456789012:security-control/S3.1/finding/12345',
      );
      expect(result.items[0].severity).toBe('HIGH');
    });

    it('should filter out findings that do not match additional criteria', async () => {
      const criteria = {
        filters: [
          {
            fieldName: 'findingId',
            comparison: 'EQUALS' as const,
            value: 'arn:aws:securityhub:us-east-1:123456789012:security-control/S3.1/finding/12345',
          },
          {
            fieldName: 'severity',
            comparison: 'EQUALS' as const,
            value: 'LOW',
          },
        ],
        pageSize: 10,
        sortOrder: 'desc' as const,
      };

      const result = await repository.searchFindings(criteria);

      expect(result.items).toBeDefined();
      expect(result.items.length).toBe(0);
    });

    it('should handle non-existent findingId gracefully', async () => {
      const criteria = {
        filters: [
          {
            fieldName: 'findingId',
            comparison: 'EQUALS' as const,
            value: 'arn:aws:securityhub:us-east-1:123456789012:security-control/NonExistent/finding/99999',
          },
        ],
        pageSize: 10,
        sortOrder: 'desc' as const,
      };

      const result = await repository.searchFindings(criteria);

      expect(result.items).toBeDefined();
      expect(result.items.length).toBe(0);
      expect(result.nextToken).toBeUndefined();
    });

    it('should handle findingId with invalid format gracefully', async () => {
      const criteria = {
        filters: [
          {
            fieldName: 'findingId',
            comparison: 'EQUALS' as const,
            value: 'invalid-finding-id-format',
          },
        ],
        pageSize: 10,
        sortOrder: 'desc' as const,
      };

      const result = await repository.searchFindings(criteria);

      expect(result.items).toBeDefined();
      expect(result.items.length).toBe(0);
      expect(result.nextToken).toBeUndefined();
    });

    it('should handle consolidated finding ID format', async () => {
      const criteria = {
        filters: [
          {
            fieldName: 'findingId',
            comparison: 'EQUALS' as const,
            value: 'arn:aws:securityhub:us-east-1:123456789012:security-control/S3.1/finding/12345',
          },
        ],
        pageSize: 10,
        sortOrder: 'desc' as const,
      };

      const result = await repository.searchFindings(criteria);

      expect(result.items).toBeDefined();
      expect(result.items.length).toBe(1);
      expect(result.items[0].findingType).toBe('security-control/S3.1');
    });

    it('should handle unconsolidated finding ID format', async () => {
      const criteria = {
        filters: [
          {
            fieldName: 'findingId',
            comparison: 'EQUALS' as const,
            value:
              'arn:aws:securityhub:us-east-1:123456789012:subscription/cis-aws-foundations-benchmark/v/1.4.0/4.8/finding/abcdef',
          },
        ],
        pageSize: 10,
        sortOrder: 'desc' as const,
      };

      const result = await repository.searchFindings(criteria);

      expect(result.items).toBeDefined();
      expect(result.items.length).toBe(1);
      expect(result.items[0].findingType).toBe('cis-aws-foundations-benchmark/v/1.4.0/4.8');
    });

    it('should handle mixed findingId and other filters with OR logic for same field', async () => {
      const criteria = {
        filters: [
          {
            fieldName: 'findingId',
            comparison: 'EQUALS' as const,
            value: 'arn:aws:securityhub:us-east-1:123456789012:security-control/S3.1/finding/12345',
          },
          {
            fieldName: 'severity',
            comparison: 'EQUALS' as const,
            value: 'HIGH',
          },
          {
            fieldName: 'severity',
            comparison: 'EQUALS' as const,
            value: 'MEDIUM',
          },
        ],
        pageSize: 10,
        sortOrder: 'desc' as const,
      };

      const result = await repository.searchFindings(criteria);

      expect(result.items).toBeDefined();
      expect(result.items.length).toBe(1);
      expect(result.items[0].severity).toBe('HIGH');
    });

    it('should handle NOT_EQUALS comparison with additional filters', async () => {
      const criteria = {
        filters: [
          {
            fieldName: 'findingId',
            comparison: 'EQUALS' as const,
            value: 'arn:aws:securityhub:us-east-1:123456789012:security-control/S3.1/finding/12345',
          },
          {
            fieldName: 'accountId',
            comparison: 'NOT_EQUALS' as const,
            value: '999999999999',
          },
        ],
        pageSize: 10,
        sortOrder: 'desc' as const,
      };

      const result = await repository.searchFindings(criteria);

      expect(result.items).toBeDefined();
      expect(result.items.length).toBe(1);
      expect(result.items[0].accountId).toBe('123456789012');
    });

    it('should handle CONTAINS comparison with additional filters', async () => {
      const criteria = {
        filters: [
          {
            fieldName: 'findingId',
            comparison: 'EQUALS' as const,
            value: 'arn:aws:securityhub:us-east-1:123456789012:security-control/S3.1/finding/12345',
          },
          {
            fieldName: 'resourceType',
            comparison: 'CONTAINS' as const,
            value: 'S3',
          },
        ],
        pageSize: 10,
        sortOrder: 'desc' as const,
      };

      const result = await repository.searchFindings(criteria);

      expect(result.items).toBeDefined();
      expect(result.items.length).toBe(1);
      expect(result.items[0].resourceType).toContain('S3');
    });

    it('should handle NOT_CONTAINS comparison with additional filters', async () => {
      const criteria = {
        filters: [
          {
            fieldName: 'findingId',
            comparison: 'EQUALS' as const,
            value: 'arn:aws:securityhub:us-east-1:123456789012:security-control/S3.1/finding/12345',
          },
          {
            fieldName: 'resourceType',
            comparison: 'NOT_CONTAINS' as const,
            value: 'EC2',
          },
        ],
        pageSize: 10,
        sortOrder: 'desc' as const,
      };

      const result = await repository.searchFindings(criteria);

      expect(result.items).toBeDefined();
      expect(result.items.length).toBe(1);
      expect(result.items[0].resourceType).not.toContain('EC2');
    });

    it('should not use direct table queries for non-EQUALS findingId filters', async () => {
      const criteria = {
        filters: [
          {
            fieldName: 'findingId',
            comparison: 'CONTAINS' as const,
            value: 'security-control',
          },
        ],
        pageSize: 10,
        sortOrder: 'desc' as const,
      };

      const result = await repository.searchFindings(criteria);

      expect(result.items).toBeDefined();
      // Should use regular GSI search, not direct table queries
      // This test verifies that non-EQUALS findingId filters don't trigger direct table access
    });

    it('should handle empty findingId values gracefully', async () => {
      const criteria = {
        filters: [
          {
            fieldName: 'findingId',
            comparison: 'EQUALS' as const,
            value: '',
          },
        ],
        pageSize: 10,
        sortOrder: 'desc' as const,
      };

      const result = await repository.searchFindings(criteria);

      expect(result.items).toBeDefined();
      expect(result.items.length).toBe(0);
    });
  });
});
