// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { ASFFFinding } from '@asr/data-models';
import { DynamoDBDocumentClient, GetCommand } from '@aws-sdk/lib-dynamodb';
import { Clock } from '../utils/clock';
import { FindingDataService } from '../services/findingDataService';
import { IAM_ACCESS_ANALYZER_EXTERNAL_ACCESS_FINDING_TYPE } from '../utils/findingUtils';
import { DynamoDBTestSetup } from './dynamodbSetup';
import { findingsTableName } from './envSetup';
import { asResolvedFindingType } from './utils';

describe('FindingDataService', () => {
  const principal = 'test-user';
  let dynamoDBDocumentClient: DynamoDBDocumentClient;

  /**
   * The partition keys callers resolve upstream and pass in. FindingDataService no longer derives
   * them, so each test supplies the key its fixture would have been keyed on: the prefixed form for
   * the Security Hub control finding, and the remediation id for the Access Analyzer finding.
   *
   * Branded here rather than at each call site, since production callers receive the brand from
   * `resolveFindingType` / `resolveControlId` and only tests construct one from a literal.
   */
  const SECURITY_CONTROL_FINDING_TYPE = asResolvedFindingType('security-control/S3.1');
  const ACCESS_ANALYZER_FINDING_TYPE = asResolvedFindingType(IAM_ACCESS_ANALYZER_EXTERNAL_ACCESS_FINDING_TYPE);

  const fakeClock: Clock = {
    now: () => new Date('2024-01-15T10:00:00Z'),
  };

  const createMinimalFinding = (overrides: Partial<ASFFFinding> = {}): ASFFFinding =>
    ({
      SchemaVersion: '2018-10-08',
      Id: 'arn:aws:securityhub:us-east-1:123456789012:security-control/S3.1/finding/test-123',
      ProductArn: 'arn:aws:securityhub:us-east-1::product/aws/securityhub',
      GeneratorId: 'security-control/S3.1',
      AwsAccountId: '123456789012',
      Types: ['Software and Configuration Checks'],
      CreatedAt: '2024-01-10T00:00:00Z',
      UpdatedAt: '2024-01-12T00:00:00Z',
      Severity: { Label: 'HIGH' },
      Title: 'S3.1 S3 Block Public Access setting should be enabled',
      Region: 'us-east-1',
      Resources: [{ Type: 'AWS::S3::Bucket', Id: 'arn:aws:s3:::test-bucket' }],
      Compliance: { SecurityControlId: 'S3.1', Status: 'FAILED' },
      RecordState: 'ACTIVE',
      ...overrides,
    }) as ASFFFinding;

  beforeAll(async () => {
    dynamoDBDocumentClient = DynamoDBTestSetup.getDocClient();
    await DynamoDBTestSetup.createFindingsTable(findingsTableName);
  });

  afterAll(async () => {
    await DynamoDBTestSetup.deleteTable(findingsTableName);
  });

  beforeEach(async () => {
    await DynamoDBTestSetup.clearTable(findingsTableName, 'findings');
  });

  /**
   * When FindingDataService is constructed with a fake Clock, the injected clock
   * controls all timestamps in the output of buildFindingTableItem.
   */
  describe('injected Clock controls timestamps', () => {
    it('should use the injected clock for lastUpdatedTime in buildFindingTableItem output', async () => {
      const service = new FindingDataService(findingsTableName, dynamoDBDocumentClient, principal, fakeClock);

      const finding = createMinimalFinding();
      const result = await service.updateWithIncomingData(finding, SECURITY_CONTROL_FINDING_TYPE);

      expect(result.status).toBe('SUCCESS');
      expect(result.findingTableItem).toBeDefined();
      expect(result.findingTableItem!.lastUpdatedTime).toBe('2024-01-15T10:00:00.000Z');
    });

    it('should use the injected clock for securityHubUpdatedAtTime fallback when finding has no UpdatedAt or CreatedAt', async () => {
      const service = new FindingDataService(findingsTableName, dynamoDBDocumentClient, principal, fakeClock);

      const finding = createMinimalFinding({
        UpdatedAt: undefined,
        CreatedAt: undefined,
      } as Partial<ASFFFinding>);

      const result = await service.updateWithIncomingData(finding, SECURITY_CONTROL_FINDING_TYPE);

      expect(result.status).toBe('SUCCESS');
      expect(result.findingTableItem).toBeDefined();
      expect(result.findingTableItem!.securityHubUpdatedAtTime).toBe('2024-01-15T10:00:00.000Z');
    });
  });

  /**
   * firstDetectedTime carries Security Hub's FirstObservedAt onto the stored item so the
   * Orchestrator can report Mean Time To Remediate. It must survive the DynamoDB write on both
   * the create and update paths, and be absent when the finding does not carry FirstObservedAt.
   */
  describe('firstDetectedTime persistence', () => {
    const readStoredItem = async (findingType: string, findingId: string) => {
      const response = await dynamoDBDocumentClient.send(
        new GetCommand({ TableName: findingsTableName, Key: { findingType, findingId } }),
      );
      return response.Item;
    };

    it('persists FirstObservedAt as firstDetectedTime on create and preserves it across a newer update', async () => {
      // ARRANGE
      const service = new FindingDataService(findingsTableName, dynamoDBDocumentClient, principal, fakeClock);
      const firstObservedAt = '2024-01-05T00:00:00Z';
      const finding = createMinimalFinding({ FirstObservedAt: firstObservedAt });

      // ACT: create, then apply a newer update (later UpdatedAt) that still carries FirstObservedAt
      const created = await service.updateWithIncomingData(finding, SECURITY_CONTROL_FINDING_TYPE);
      const updated = await service.updateWithIncomingData(
        createMinimalFinding({ FirstObservedAt: firstObservedAt, UpdatedAt: '2024-01-20T00:00:00Z' }),
        SECURITY_CONTROL_FINDING_TYPE,
      );
      const storedItem = await readStoredItem(
        created.findingTableItem!.findingType,
        created.findingTableItem!.findingId,
      );

      // ASSERT: set on create (build output + stored item) and still present after the putIfNewer update
      expect(created.findingTableItem!.firstDetectedTime).toBe(firstObservedAt);
      expect(updated.status).toBe('SUCCESS');
      expect(storedItem?.firstDetectedTime).toBe(firstObservedAt);
    });

    it('preserves an existing firstDetectedTime when a newer update omits FirstObservedAt', async () => {
      // ARRANGE
      const service = new FindingDataService(findingsTableName, dynamoDBDocumentClient, principal, fakeClock);
      const firstObservedAt = '2024-01-05T00:00:00Z';

      // ACT: create with FirstObservedAt, then apply a newer update (later UpdatedAt) that omits it
      const created = await service.updateWithIncomingData(
        createMinimalFinding({ FirstObservedAt: firstObservedAt }),
        SECURITY_CONTROL_FINDING_TYPE,
      );
      const updated = await service.updateWithIncomingData(
        createMinimalFinding({ UpdatedAt: '2024-01-20T00:00:00Z' }),
        SECURITY_CONTROL_FINDING_TYPE,
      );
      const storedItem = await readStoredItem(
        created.findingTableItem!.findingType,
        created.findingTableItem!.findingId,
      );

      // ASSERT: the conditional SET omits firstDetectedTime, so the existing value is not overwritten with undefined
      expect(updated.status).toBe('SUCCESS');
      expect(storedItem?.firstDetectedTime).toBe(firstObservedAt);
    });

    it('omits firstDetectedTime when the finding has no FirstObservedAt', async () => {
      // ARRANGE
      const service = new FindingDataService(findingsTableName, dynamoDBDocumentClient, principal, fakeClock);

      // ACT
      const result = await service.updateWithIncomingData(createMinimalFinding(), SECURITY_CONTROL_FINDING_TYPE);
      const storedItem = await readStoredItem(result.findingTableItem!.findingType, result.findingTableItem!.findingId);

      // ASSERT
      expect(result.findingTableItem!.firstDetectedTime).toBeUndefined();
      expect(storedItem?.firstDetectedTime).toBeUndefined();
    });
  });

  /**
   * Metric-enrichment flags (hasFindingNotificationsEnabled / hasFindingRemediationDeadlineConfigured)
   * are supplied by the ingestion handlers from notification-config matching and must be persisted
   * to the table on both create and update, and omitted when the caller does not supply them.
   */
  describe('metric-enrichment flag persistence', () => {
    const readStoredItem = async (findingType: string, findingId: string) => {
      const response = await dynamoDBDocumentClient.send(
        new GetCommand({ TableName: findingsTableName, Key: { findingType, findingId } }),
      );
      return response.Item;
    };

    it('persists the enrichment flags on create and updates them on a newer write', async () => {
      // ARRANGE
      const service = new FindingDataService(findingsTableName, dynamoDBDocumentClient, principal, fakeClock);

      // ACT: create with both flags true, then a newer update flips them to false
      const created = await service.updateWithIncomingData(
        createMinimalFinding(),
        SECURITY_CONTROL_FINDING_TYPE,
        undefined,
        false,
        undefined,
        { hasFindingNotificationsEnabled: true, hasFindingRemediationDeadlineConfigured: true },
      );
      const updated = await service.updateWithIncomingData(
        createMinimalFinding({ UpdatedAt: '2024-01-20T00:00:00Z' }),
        SECURITY_CONTROL_FINDING_TYPE,
        undefined,
        false,
        undefined,
        { hasFindingNotificationsEnabled: false, hasFindingRemediationDeadlineConfigured: false },
      );
      const storedItem = await readStoredItem(
        created.findingTableItem!.findingType,
        created.findingTableItem!.findingId,
      );

      // ASSERT: create wrote true, and the newer update overwrote both to false
      expect(created.findingTableItem!.hasFindingNotificationsEnabled).toBe(true);
      expect(created.findingTableItem!.hasFindingRemediationDeadlineConfigured).toBe(true);
      expect(updated.status).toBe('SUCCESS');
      expect(storedItem?.hasFindingNotificationsEnabled).toBe(false);
      expect(storedItem?.hasFindingRemediationDeadlineConfigured).toBe(false);
    });

    it('omits the enrichment flags when the caller does not provide them', async () => {
      // ARRANGE
      const service = new FindingDataService(findingsTableName, dynamoDBDocumentClient, principal, fakeClock);

      // ACT
      const result = await service.updateWithIncomingData(createMinimalFinding(), SECURITY_CONTROL_FINDING_TYPE);
      const storedItem = await readStoredItem(result.findingTableItem!.findingType, result.findingTableItem!.findingId);

      // ASSERT
      expect(storedItem?.hasFindingNotificationsEnabled).toBeUndefined();
      expect(storedItem?.hasFindingRemediationDeadlineConfigured).toBeUndefined();
    });
  });

  /**
   * IAM Access Analyzer external access findings reach ASR as ASFF and carry
   * `ProductFields.ResourceOwnerAccount`. For an organization analyzer the ASFF
   * `AwsAccountId` is the administrator account while the resource lives in the
   * owner account, so the stored `accountId` must come from ResourceOwnerAccount.
   */
  describe('accountId resolution for Access Analyzer findings', () => {
    const adminAccount = '111111111111';
    const resourceOwnerAccount = '222222222222';

    const createAccessAnalyzerFinding = (overrides: Partial<ASFFFinding> = {}): ASFFFinding =>
      ({
        SchemaVersion: '2018-10-08',
        Id: 'arn:aws:access-analyzer:us-east-1:111111111111:analyzer/org-analyzer/arn:aws:kms:us-east-1:222222222222:key/00000000-0000-0000-0000-000000000000',
        ProductArn: 'arn:aws:securityhub:us-east-1::product/aws/access-analyzer',
        ProductName: 'IAM Access Analyzer',
        GeneratorId: 'aws/access-analyzer',
        AwsAccountId: adminAccount,
        Types: ['Software and Configuration Checks/AWS Security Best Practices/External Access Granted'],
        CreatedAt: '2024-01-10T00:00:00Z',
        UpdatedAt: '2024-01-12T00:00:00Z',
        Severity: { Label: 'MEDIUM' },
        Title: 'AwsKmsKey allows public access',
        Region: 'us-east-1',
        ProductFields: {
          ResourceOwnerAccount: resourceOwnerAccount,
          'aws/securityhub/ProductName': 'IAM Access Analyzer',
        },
        Resources: [
          { Type: 'AwsKmsKey', Id: 'arn:aws:kms:us-east-1:222222222222:key/00000000-0000-0000-0000-000000000000' },
        ],
        RecordState: 'ACTIVE',
        ...overrides,
      }) as ASFFFinding;

    it('uses ProductFields.ResourceOwnerAccount as accountId when present', async () => {
      // ARRANGE: org-analyzer IAA finding where AwsAccountId (admin) differs from the resource owner
      const service = new FindingDataService(findingsTableName, dynamoDBDocumentClient, principal, fakeClock);
      const finding = createAccessAnalyzerFinding();

      // ACT
      const result = await service.updateWithIncomingData(finding, ACCESS_ANALYZER_FINDING_TYPE);

      // ASSERT: stored account is the resource owner, not the administrator account
      expect(result.status).toBe('SUCCESS');
      expect(result.findingTableItem!.accountId).toBe(resourceOwnerAccount);
    });

    it('falls back to AwsAccountId when ResourceOwnerAccount is absent', async () => {
      // ARRANGE: IAA finding with no ResourceOwnerAccount (e.g. per-account analyzer)
      const service = new FindingDataService(findingsTableName, dynamoDBDocumentClient, principal, fakeClock);
      const finding = createAccessAnalyzerFinding({
        ProductFields: { 'aws/securityhub/ProductName': 'IAM Access Analyzer' },
      });

      // ACT
      const result = await service.updateWithIncomingData(finding, ACCESS_ANALYZER_FINDING_TYPE);

      // ASSERT
      expect(result.status).toBe('SUCCESS');
      expect(result.findingTableItem!.accountId).toBe(adminAccount);
    });

    it('rejects a malformed ResourceOwnerAccount rather than storing the finding', async () => {
      // ARRANGE: crafted/malformed ResourceOwnerAccount must not be stored as the account
      const service = new FindingDataService(findingsTableName, dynamoDBDocumentClient, principal, fakeClock);
      const finding = createAccessAnalyzerFinding({
        ProductFields: { ResourceOwnerAccount: 'not-an-account' },
      });

      // ACT
      const result = await service.updateWithIncomingData(finding, ACCESS_ANALYZER_FINDING_TYPE);

      // ASSERT: the finding is not persisted (fail closed on the ingestion write path)
      expect(result.status).toBe('ERROR');
      expect(result.findingTableItem).toBeUndefined();
    });

    it('does not apply ResourceOwnerAccount for non-Access-Analyzer findings', async () => {
      // ARRANGE: a Security Hub control finding that happens to carry ResourceOwnerAccount
      const service = new FindingDataService(findingsTableName, dynamoDBDocumentClient, principal, fakeClock);
      const finding = createMinimalFinding({
        ProductFields: { ResourceOwnerAccount: resourceOwnerAccount },
      });

      // ACT
      const result = await service.updateWithIncomingData(finding, SECURITY_CONTROL_FINDING_TYPE);

      // ASSERT: AwsAccountId is used, ResourceOwnerAccount is ignored
      expect(result.status).toBe('SUCCESS');
      expect(result.findingTableItem!.accountId).toBe('123456789012');
    });
  });

  /**
   * When an EventBridge event time is supplied, it becomes the ordering key for
   * putIfNewer: an update is accepted only when the incoming EventBridge time is
   * strictly newer than the stored value. The ASFF UpdatedAt timestamp does not
   * influence ordering once an EventBridge time is provided. Each case sets the
   * ASFF UpdatedAt to point in the opposite direction from the EventBridge time
   * to confirm that only the EventBridge time drives the outcome.
   */
  describe('EventBridge time controls putIfNewer ordering', () => {
    const eventBridgeTimeEarlier = '2024-01-15T10:00:00Z';
    const eventBridgeTimeLater = '2024-01-16T10:00:00Z';
    const asffUpdatedAtEarliest = '2024-01-01T00:00:00Z';
    const asffUpdatedAtLatest = '2024-12-31T00:00:00Z';

    const getPersistedSecurityHubUpdatedAtTime = async (
      findingType: string,
      findingId: string,
    ): Promise<string | undefined> => {
      const stored = await dynamoDBDocumentClient.send(
        new GetCommand({ TableName: findingsTableName, Key: { findingType, findingId } }),
      );
      return stored.Item?.securityHubUpdatedAtTime as string | undefined;
    };

    it('accepts the update when the incoming EventBridge time is newer, ignoring an older ASFF UpdatedAt', async () => {
      // ARRANGE: store the finding stamped with the earlier EventBridge time while its ASFF UpdatedAt is the latest of all values
      const service = new FindingDataService(findingsTableName, dynamoDBDocumentClient, principal, fakeClock);
      const initialFinding = createMinimalFinding({ UpdatedAt: asffUpdatedAtLatest });
      const created = await service.updateWithIncomingData(
        initialFinding,
        SECURITY_CONTROL_FINDING_TYPE,
        undefined,
        false,
        eventBridgeTimeEarlier,
      );
      expect(created.status).toBe('SUCCESS');

      // ACT: resend the finding with a newer EventBridge time but an older ASFF UpdatedAt
      const incomingFinding = createMinimalFinding({ UpdatedAt: asffUpdatedAtEarliest });
      const updated = await service.updateWithIncomingData(
        incomingFinding,
        SECURITY_CONTROL_FINDING_TYPE,
        undefined,
        false,
        eventBridgeTimeLater,
      );

      // ASSERT: the update is accepted and the persisted ordering key is the newer EventBridge time, not the ASFF UpdatedAt
      expect(updated.status).toBe('SUCCESS');
      const updatedItem = updated.findingTableItem;
      if (!updatedItem) throw new Error('expected findingTableItem to be defined');
      expect(updatedItem.securityHubUpdatedAtTime).toBe(eventBridgeTimeLater);
      const persisted = await getPersistedSecurityHubUpdatedAtTime(updatedItem.findingType, updatedItem.findingId);
      expect(persisted).toBe(eventBridgeTimeLater);
    });

    it('rejects the update when the incoming EventBridge time is equal, ignoring a newer ASFF UpdatedAt', async () => {
      // ARRANGE: store the finding stamped with the earlier EventBridge time
      const service = new FindingDataService(findingsTableName, dynamoDBDocumentClient, principal, fakeClock);
      const initialFinding = createMinimalFinding({ UpdatedAt: asffUpdatedAtEarliest });
      const created = await service.updateWithIncomingData(
        initialFinding,
        SECURITY_CONTROL_FINDING_TYPE,
        undefined,
        false,
        eventBridgeTimeEarlier,
      );
      expect(created.status).toBe('SUCCESS');

      // ACT: resend the finding with the same EventBridge time but a much newer ASFF UpdatedAt
      const incomingFinding = createMinimalFinding({ UpdatedAt: asffUpdatedAtLatest });
      const updated = await service.updateWithIncomingData(
        incomingFinding,
        SECURITY_CONTROL_FINDING_TYPE,
        undefined,
        false,
        eventBridgeTimeEarlier,
      );

      // ASSERT: the update is rejected and the persisted ordering key is unchanged
      expect(updated.status).toBe('FAILED');
      const updatedItem = updated.findingTableItem;
      if (!updatedItem) throw new Error('expected findingTableItem to be defined');
      const persisted = await getPersistedSecurityHubUpdatedAtTime(updatedItem.findingType, updatedItem.findingId);
      expect(persisted).toBe(eventBridgeTimeEarlier);
    });

    it('rejects the update when the incoming EventBridge time is older, ignoring a newer ASFF UpdatedAt', async () => {
      // ARRANGE: store the finding stamped with the later EventBridge time
      const service = new FindingDataService(findingsTableName, dynamoDBDocumentClient, principal, fakeClock);
      const initialFinding = createMinimalFinding({ UpdatedAt: asffUpdatedAtEarliest });
      const created = await service.updateWithIncomingData(
        initialFinding,
        SECURITY_CONTROL_FINDING_TYPE,
        undefined,
        false,
        eventBridgeTimeLater,
      );
      expect(created.status).toBe('SUCCESS');

      // ACT: resend the finding with an older EventBridge time but a much newer ASFF UpdatedAt
      const incomingFinding = createMinimalFinding({ UpdatedAt: asffUpdatedAtLatest });
      const updated = await service.updateWithIncomingData(
        incomingFinding,
        SECURITY_CONTROL_FINDING_TYPE,
        undefined,
        false,
        eventBridgeTimeEarlier,
      );

      // ASSERT: the update is rejected and the persisted ordering key remains the later EventBridge time
      expect(updated.status).toBe('FAILED');
      const updatedItem = updated.findingTableItem;
      if (!updatedItem) throw new Error('expected findingTableItem to be defined');
      const persisted = await getPersistedSecurityHubUpdatedAtTime(updatedItem.findingType, updatedItem.findingId);
      expect(persisted).toBe(eventBridgeTimeLater);
    });
  });
});
