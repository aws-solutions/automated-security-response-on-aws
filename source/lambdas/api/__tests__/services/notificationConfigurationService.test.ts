// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { Logger } from '@aws-lambda-powertools/logger';
import { mockClient } from 'aws-sdk-client-mock';
import {
  SNSClient,
  CreateTopicCommand,
  ListSubscriptionsByTopicCommand,
  UnsubscribeCommand,
} from '@aws-sdk/client-sns';
import { OrganizationsClient, DescribeAccountCommand } from '@aws-sdk/client-organizations';
import { AccountClient, GetAlternateContactCommand } from '@aws-sdk/client-account';
import { DynamoDBDocumentClient, PutCommand, ScanCommand } from '@aws-sdk/lib-dynamodb';
import { DynamoDBTestSetup } from '../../../common/__tests__/dynamodbSetup';
import {
  notificationConfigTableName,
  notificationBatchesTableName,
  remediationConfigTableName,
  resourceFiltersTableName,
  userAccountMappingTableName,
  mockAccountId,
} from '../../../common/__tests__/envSetup';
import { NotificationConfigurationService } from '../../services/notificationConfigurationService';
import { NotificationConfigurationRepository } from '../../../common/repositories/notificationConfigurationRepository';
import { resetApiLambdaEnvironmentCache } from '../../apiLambdaEnvironment';
import {
  CreateNotificationConfigurationRequest,
  UpdateNotificationConfigurationRequest,
  ConfigId,
} from '@asr/data-models';

const FIXED_DATE = new Date('2025-06-15T12:00:00.000Z');
const FIXED_UUID = '11111111-2222-4333-a444-000000000001';

jest.mock('../../../common/utils/idGenerator', () => ({
  getIdGenerator: () => ({ randomUUID: () => FIXED_UUID }),
}));

jest.mock('../../../common/utils/clock', () => ({
  getClock: () => ({ now: () => FIXED_DATE }),
}));

// The API test project does not auto-mock metrics. The service emits a
// configuration_crud metric on every create/update/delete, which reaches SSM
// and the SolutionsMetrics HTTPS endpoint. Left unmocked, those real requests
// run through a nock interceptor left active by an earlier suite in the
// sequential run and fail with `read EINVAL`. Stub sendMetrics so this suite
// stays off the network entirely (no test here asserts metric emission).
jest.mock('../../../common/utils/metricsUtils', () => {
  const actual = jest.requireActual('../../../common/utils/metricsUtils');
  return {
    __esModule: true,
    ...actual,
    sendMetrics: jest.fn().mockResolvedValue(undefined),
  };
});

const snsMock = mockClient(SNSClient);
const orgsMock = mockClient(OrganizationsClient);
const accountMock = mockClient(AccountClient);

const ADMIN_ACTOR = { actorEmail: 'admin@example.com', actorGroups: ['AdminGroup'] };

describe('NotificationConfigurationService', () => {
  let service: NotificationConfigurationService;
  let logger: Logger;
  let docClient: DynamoDBDocumentClient;

  beforeAll(async () => {
    docClient = DynamoDBTestSetup.getDocClient();
    await DynamoDBTestSetup.createNotificationConfigTable(notificationConfigTableName);
    await DynamoDBTestSetup.createNotificationBatchesTable(notificationBatchesTableName);
    await DynamoDBTestSetup.createConfigTable(remediationConfigTableName);
    await DynamoDBTestSetup.createResourceFiltersTable(resourceFiltersTableName);
    await DynamoDBTestSetup.createUserAccountMappingTable(userAccountMappingTableName);
  });

  afterAll(async () => {
    await DynamoDBTestSetup.deleteTable(notificationConfigTableName);
    await DynamoDBTestSetup.deleteTable(notificationBatchesTableName);
    await DynamoDBTestSetup.deleteTable(remediationConfigTableName);
    await DynamoDBTestSetup.deleteTable(resourceFiltersTableName);
    await DynamoDBTestSetup.deleteTable(userAccountMappingTableName);
  });

  beforeEach(async () => {
    await DynamoDBTestSetup.clearTable(notificationConfigTableName, 'notificationConfig');
    await DynamoDBTestSetup.clearTable(notificationBatchesTableName, 'notificationBatches');
    await DynamoDBTestSetup.clearTable(userAccountMappingTableName, 'userAccountMapping');

    snsMock.reset();
    orgsMock.reset();
    accountMock.reset();

    // getNotificationBatchesTableName reads through the cached typed accessor; reset it so each
    // test (including those that mutate process.env.NOTIFICATION_BATCHES_TABLE_NAME) sees fresh env.
    resetApiLambdaEnvironmentCache();

    logger = new Logger({ logLevel: 'SILENT' });
    service = new NotificationConfigurationService(logger);
  });

  describe('syncEmailTopicForConfig (via createConfiguration)', () => {
    it('should resolve recipient types and sync subscriptions when email channel has resolvable recipients', async () => {
      // Arrange
      const topicArn = `arn:aws:sns:us-east-1:${mockAccountId}:SO0111-asr-email-${FIXED_UUID}`;
      snsMock.on(CreateTopicCommand).resolves({ TopicArn: topicArn });
      snsMock.on(ListSubscriptionsByTopicCommand).resolves({ Subscriptions: [] });
      orgsMock.on(DescribeAccountCommand).resolves({
        Account: {
          Email: 'root@example.com',
          Id: mockAccountId,
          Arn: 'arn:aws:organizations::123456789012:account/o-abc/123456789012',
        },
      });
      accountMock.on(GetAlternateContactCommand).resolves({});

      await docClient.send(
        new PutCommand({
          TableName: userAccountMappingTableName,
          Item: { userId: 'operator@example.com', accountIds: ['111111111111'] },
        }),
      );

      // Act - scope the config to the operator's account so the accountOperators recipient resolves
      const result = await service.createConfiguration(
        {
          name: 'Recipient Resolver Test',
          enabled: true,
          notificationType: 'finding',
          severityFilter: ['Critical'],
          controlIds: [],
          resourceFilterIds: [],
          accountIds: ['111111111111'],
          deliveryChannels: [
            {
              type: 'email',
              enabled: true,
              recipients: [
                { recipientType: 'rootAccountEmail' },
                { recipientType: 'accountOperators' },
                { recipientType: 'custom', emailAddresses: ['direct@example.com'] },
              ],
            },
          ],
          batchWindow: { enabled: false },
          contentOptions: {
            includeManualRemediationLink: true,
            includeRemediationDeadline: false,
            enforceDeadline: false,
            includeIaCSnippet: false,
            includeEnableAutomationLink: true,
          },
        },
        ADMIN_ACTOR,
      );

      // Assert
      expect(result.configId).toBeDefined();
      expect(orgsMock.commandCalls(DescribeAccountCommand)).toHaveLength(1);
    });

    it('should reuse the lazily-initialized recipient resolver across multiple syncs', async () => {
      // Arrange
      snsMock.on(CreateTopicCommand).resolves({
        TopicArn: `arn:aws:sns:us-east-1:${mockAccountId}:SO0111-asr-email-topic`,
      });
      snsMock.on(ListSubscriptionsByTopicCommand).resolves({ Subscriptions: [] });
      orgsMock.on(DescribeAccountCommand).resolves({
        Account: {
          Email: 'root@example.com',
          Id: mockAccountId,
          Arn: 'arn:aws:organizations::123456789012:account/o-abc/123456789012',
        },
      });
      accountMock.on(GetAlternateContactCommand).resolves({});

      // Seed a user-account mapping so getUserAccountMappingRepository is exercised
      await docClient.send(
        new PutCommand({
          TableName: userAccountMappingTableName,
          Item: { userId: 'operator@example.com', accountIds: ['111111111111'] },
        }),
      );

      // Act - create config, then update it to trigger syncEmailTopicForConfig twice
      const created = await service.createConfiguration(
        {
          name: 'Lazy Init Test',
          enabled: true,
          notificationType: 'finding',
          severityFilter: ['Critical'],
          controlIds: [],
          resourceFilterIds: [],
          accountIds: ['111111111111'],
          deliveryChannels: [{ type: 'email', enabled: true, recipients: [{ recipientType: 'accountOperators' }] }],
          batchWindow: { enabled: false },
          contentOptions: {
            includeManualRemediationLink: true,
            includeRemediationDeadline: false,
            enforceDeadline: false,
            includeIaCSnippet: false,
            includeEnableAutomationLink: true,
          },
        },
        ADMIN_ACTOR,
      );

      await service.updateConfiguration(
        created.configId,
        {
          name: 'Lazy Init Test',
          enabled: true,
          notificationType: 'finding',
          severityFilter: ['Critical', 'High'],
          controlIds: [],
          resourceFilterIds: [],
          accountIds: ['111111111111'],
          deliveryChannels: [{ type: 'email', enabled: true, recipients: [{ recipientType: 'accountOperators' }] }],
          batchWindow: { enabled: false },
          contentOptions: {
            includeManualRemediationLink: true,
            includeRemediationDeadline: false,
            enforceDeadline: false,
            includeIaCSnippet: false,
            includeEnableAutomationLink: true,
          },
          version: 1,
        },
        ADMIN_ACTOR,
      );

      // Assert - both create and update triggered syncEmailTopicForConfig,
      // exercising getRecipientResolver and getUserAccountMappingRepository
      expect(snsMock.commandCalls(CreateTopicCommand).length).toBe(2);
    });
  });

  describe('reconciliation task creation', () => {
    const enforcingContentOptions = {
      includeManualRemediationLink: true,
      includeRemediationDeadline: true,
      remediationDeadlineDays: 30,
      enforceDeadline: true,
      includeIaCSnippet: false,
      includeEnableAutomationLink: true,
    } as const;

    const nonEnforcingContentOptions = {
      includeManualRemediationLink: true,
      includeRemediationDeadline: false,
      enforceDeadline: false,
      includeIaCSnippet: false,
      includeEnableAutomationLink: true,
    } as const;

    function buildCreateRequest(
      overrides: Partial<CreateNotificationConfigurationRequest> = {},
    ): CreateNotificationConfigurationRequest {
      return {
        name: 'Enforcement Config',
        enabled: true,
        notificationType: 'finding' as const,
        controlIds: [] as string[],
        resourceFilterIds: [] as string[],
        deliveryChannels: [
          {
            type: 'email' as const,
            enabled: true,
            recipients: [{ recipientType: 'custom' as const, emailAddresses: ['ops@example.com'] }],
          },
        ],
        batchWindow: { enabled: false },
        contentOptions: { ...enforcingContentOptions },
        ...overrides,
      };
    }

    function buildUpdateRequest(
      overrides: Partial<CreateNotificationConfigurationRequest> = {},
    ): UpdateNotificationConfigurationRequest {
      return { ...buildCreateRequest(overrides), version: 1 };
    }

    async function readReconciliationTasks(): Promise<Record<string, unknown>[]> {
      const result = await docClient.send(new ScanCommand({ TableName: notificationBatchesTableName }));
      return (result.Items ?? []).filter(
        (item): item is Record<string, unknown> =>
          typeof item.configId === 'string' && item.configId.startsWith('reconciliation#'),
      );
    }

    beforeEach(() => {
      // Email topic sync runs after the config write; stub SNS so it succeeds quietly.
      snsMock.on(CreateTopicCommand).resolves({ TopicArn: `arn:aws:sns:us-east-1:${mockAccountId}:topic` });
      snsMock.on(ListSubscriptionsByTopicCommand).resolves({ Subscriptions: [] });
    });

    it('writes an "enable" task when a config is created with enforcement on', async () => {
      // Arrange / Act
      const created = await service.createConfiguration(buildCreateRequest(), ADMIN_ACTOR);

      // Assert - single enable task carrying the new config snapshot, no old snapshot
      const tasks = await readReconciliationTasks();
      expect(tasks).toHaveLength(1);
      expect(tasks[0].taskType).toBe('enable');
      expect((tasks[0].newConfig as { configId: string }).configId).toBe(created.configId);
      expect(tasks[0].oldConfig).toBeUndefined();
      expect(tasks[0].status).toBe('PENDING');
    });

    it('writes no task when a config is created with enforcement off', async () => {
      // Arrange / Act
      await service.createConfiguration(
        buildCreateRequest({ contentOptions: { ...nonEnforcingContentOptions } }),
        ADMIN_ACTOR,
      );

      // Assert
      expect(await readReconciliationTasks()).toHaveLength(0);
    });

    it('writes a "disable" task when an enforcing config is deleted', async () => {
      // Arrange - create the enforcing config, then drop the enable task it produced
      const created = await service.createConfiguration(buildCreateRequest(), ADMIN_ACTOR);
      await DynamoDBTestSetup.clearTable(notificationBatchesTableName, 'notificationBatches');

      // Act
      await service.deleteConfiguration(created.configId, ADMIN_ACTOR);

      // Assert - disable task carries the old snapshot, no new snapshot
      const tasks = await readReconciliationTasks();
      expect(tasks).toHaveLength(1);
      expect(tasks[0].taskType).toBe('disable');
      expect((tasks[0].oldConfig as { configId: string }).configId).toBe(created.configId);
      expect(tasks[0].newConfig).toBeUndefined();
    });

    it('returns null when deleting a configuration that does not exist', async () => {
      // Arrange
      const missingConfigId = 'nonexistent-config-id' as ConfigId;

      // Act
      const result = await service.deleteConfiguration(missingConfigId, ADMIN_ACTOR);

      // Assert
      expect(result).toBeNull();
    });

    it('writes a "deadlineChange" task when remediationDeadlineDays changes', async () => {
      // Arrange
      const created = await service.createConfiguration(buildCreateRequest(), ADMIN_ACTOR);
      await DynamoDBTestSetup.clearTable(notificationBatchesTableName, 'notificationBatches');

      // Act - update only the deadline length
      await service.updateConfiguration(
        created.configId,
        buildUpdateRequest({
          contentOptions: { ...enforcingContentOptions, remediationDeadlineDays: 10 },
        }),
        ADMIN_ACTOR,
      );

      // Assert
      const tasks = await readReconciliationTasks();
      expect(tasks).toHaveLength(1);
      expect(tasks[0].taskType).toBe('deadlineChange');
    });

    it('writes a "filterChange" task when controlIds change', async () => {
      // Arrange - seed a valid control so foreign-id validation passes, then create + clear
      await docClient.send(new PutCommand({ TableName: remediationConfigTableName, Item: { controlId: 'Config.1' } }));
      const created = await service.createConfiguration(buildCreateRequest(), ADMIN_ACTOR);
      await DynamoDBTestSetup.clearTable(notificationBatchesTableName, 'notificationBatches');

      // Act - add a control ID without touching the deadline
      await service.updateConfiguration(
        created.configId,
        buildUpdateRequest({ controlIds: ['Config.1'] }),
        ADMIN_ACTOR,
      );

      // Assert
      const tasks = await readReconciliationTasks();
      expect(tasks).toHaveLength(1);
      expect(tasks[0].taskType).toBe('filterChange');
    });

    it('writes both "deadlineChange" and "filterChange" tasks when the deadline and controlIds change together', async () => {
      // Arrange - seed a valid control, create the enforcing config, then drop the enable task. A
      // local service with an incrementing id generator gives each reconciliation task a distinct
      // configId, exactly as randomUUID() does in production (the suite-wide mock returns a constant).
      let uuidCounter = 0;
      const incrementingIdGenerator = {
        randomUUID: () => `11111111-2222-4333-a444-00000000000${++uuidCounter}`,
      };
      const localService = new NotificationConfigurationService(logger, undefined, incrementingIdGenerator);
      await docClient.send(new PutCommand({ TableName: remediationConfigTableName, Item: { controlId: 'Config.1' } }));
      const created = await localService.createConfiguration(buildCreateRequest(), ADMIN_ACTOR);
      await DynamoDBTestSetup.clearTable(notificationBatchesTableName, 'notificationBatches');

      // Act - change the deadline length AND the targeted controls in a single update
      await localService.updateConfiguration(
        created.configId,
        buildUpdateRequest({
          controlIds: ['Config.1'],
          contentOptions: { ...enforcingContentOptions, remediationDeadlineDays: 10 },
        }),
        ADMIN_ACTOR,
      );

      // Assert - both reconciliation paths are enqueued so neither the deadline recompute nor the
      // control-set add/remove is dropped
      const tasks = await readReconciliationTasks();
      expect(tasks).toHaveLength(2);
      expect(tasks.map((task) => task.taskType).sort()).toEqual(['deadlineChange', 'filterChange']);
    });

    it('writes no task when an update leaves enforcement inputs unchanged', async () => {
      // Arrange
      const created = await service.createConfiguration(buildCreateRequest(), ADMIN_ACTOR);
      await DynamoDBTestSetup.clearTable(notificationBatchesTableName, 'notificationBatches');

      // Act - change only the name (not an enforcement input)
      await service.updateConfiguration(created.configId, buildUpdateRequest({ name: 'Renamed Config' }), ADMIN_ACTOR);

      // Assert
      expect(await readReconciliationTasks()).toHaveLength(0);
    });

    it('skips reconciliation gracefully when the batches table name is not configured', async () => {
      // Arrange - simulate the table name not yet being wired into the environment
      const originalTableName = process.env.NOTIFICATION_BATCHES_TABLE_NAME;
      delete process.env.NOTIFICATION_BATCHES_TABLE_NAME;

      try {
        // Act
        const created = await service.createConfiguration(buildCreateRequest(), ADMIN_ACTOR);

        // Assert - the config write succeeded and nothing was enqueued
        expect(created.configId).toBeDefined();
        process.env.NOTIFICATION_BATCHES_TABLE_NAME = originalTableName;
        expect(await readReconciliationTasks()).toHaveLength(0);
      } finally {
        process.env.NOTIFICATION_BATCHES_TABLE_NAME = originalTableName;
      }
    });

    it('swallows reconciliation write failures without failing the config operation', async () => {
      // Arrange - point reconciliation at a non-existent table so the write rejects
      const originalTableName = process.env.NOTIFICATION_BATCHES_TABLE_NAME;
      process.env.NOTIFICATION_BATCHES_TABLE_NAME = 'table-that-does-not-exist';

      try {
        // Act
        const created = await service.createConfiguration(buildCreateRequest(), ADMIN_ACTOR);

        // Assert - the config write still succeeded and no task landed in the real table
        expect(created.configId).toBeDefined();
        process.env.NOTIFICATION_BATCHES_TABLE_NAME = originalTableName;
        expect(await readReconciliationTasks()).toHaveLength(0);
      } finally {
        process.env.NOTIFICATION_BATCHES_TABLE_NAME = originalTableName;
      }
    });

    it('writes a "disable" task when an enforcing config is toggled off', async () => {
      // Arrange - create the enforcing config, then drop the enable task it produced
      const created = await service.createConfiguration(buildCreateRequest(), ADMIN_ACTOR);
      await DynamoDBTestSetup.clearTable(notificationBatchesTableName, 'notificationBatches');

      // Act - toggle the config disabled, which removes it as an enforcement contributor
      await service.toggleStatus(created.configId, { enabled: false, version: created.version }, ADMIN_ACTOR);

      // Assert - a disable task carrying the pre-toggle snapshot is enqueued
      const tasks = await readReconciliationTasks();
      expect(tasks).toHaveLength(1);
      expect(tasks[0].taskType).toBe('disable');
      expect((tasks[0].oldConfig as { configId: string }).configId).toBe(created.configId);
    });

    it('writes an "enable" task when a disabled enforcing config is toggled on', async () => {
      // Arrange - a disabled config does not enforce, so its creation enqueues nothing
      const created = await service.createConfiguration(buildCreateRequest({ enabled: false }), ADMIN_ACTOR);
      await DynamoDBTestSetup.clearTable(notificationBatchesTableName, 'notificationBatches');

      // Act - toggling it on makes it an enforcement contributor
      await service.toggleStatus(created.configId, { enabled: true, version: created.version }, ADMIN_ACTOR);

      // Assert
      const tasks = await readReconciliationTasks();
      expect(tasks).toHaveLength(1);
      expect(tasks[0].taskType).toBe('enable');
      expect((tasks[0].newConfig as { configId: string }).configId).toBe(created.configId);
    });

    it('writes no task when a non-enforcing config is toggled', async () => {
      // Arrange - a config with enforcement off never contributes deadlines regardless of enabled
      const created = await service.createConfiguration(
        buildCreateRequest({ contentOptions: { ...nonEnforcingContentOptions } }),
        ADMIN_ACTOR,
      );
      await DynamoDBTestSetup.clearTable(notificationBatchesTableName, 'notificationBatches');

      // Act
      await service.toggleStatus(created.configId, { enabled: false, version: created.version }, ADMIN_ACTOR);

      // Assert
      expect(await readReconciliationTasks()).toHaveLength(0);
    });
  });

  describe('operator account reconciliation', () => {
    // The suite-wide idGenerator returns a constant UUID, which would collide when several configs
    // are created in one test. A per-describe incrementing generator gives each config a distinct id,
    // matching production's randomUUID() behavior.
    let scopedService: NotificationConfigurationService;

    function buildScopedRequest(
      name: string,
      accountIds: string[] | undefined,
    ): CreateNotificationConfigurationRequest {
      return {
        name,
        enabled: true,
        notificationType: 'finding' as const,
        controlIds: [] as string[],
        resourceFilterIds: [] as string[],
        accountIds,
        deliveryChannels: [
          {
            type: 'email' as const,
            enabled: true,
            recipients: [{ recipientType: 'custom' as const, emailAddresses: ['ops@example.com'] }],
          },
        ],
        batchWindow: { enabled: false },
        contentOptions: {
          includeManualRemediationLink: true,
          includeRemediationDeadline: false,
          enforceDeadline: false,
          includeIaCSnippet: false,
          includeEnableAutomationLink: true,
        },
      };
    }

    beforeEach(() => {
      // Email topic sync runs after the config write; stub SNS so it succeeds quietly.
      snsMock.on(CreateTopicCommand).resolves({ TopicArn: `arn:aws:sns:us-east-1:${mockAccountId}:topic` });
      snsMock.on(ListSubscriptionsByTopicCommand).resolves({ Subscriptions: [] });

      let uuidCounter = 0;
      const incrementingIdGenerator = {
        randomUUID: () => `22222222-3333-4444-a555-00000000000${++uuidCounter}`,
      };
      scopedService = new NotificationConfigurationService(logger, undefined, incrementingIdGenerator);
    });

    it('overwrites a config scope to exactly the operator owned accounts (expanding narrower scope)', async () => {
      // Arrange - operator owns a config scoped to a single account
      const created = await scopedService.createConfiguration(buildScopedRequest('Sync Expand', ['111111111111']), {
        actorEmail: 'operator@example.com',
        actorGroups: [],
      });

      // Act - the operator now owns two accounts; the config must expand to match exactly
      await scopedService.syncOperatorConfigsToOwnedAccounts('operator@example.com', ['111111111111', '222222222222']);

      // Assert - the config scope is overwritten to the full owned set, config stays enabled
      const after = await scopedService.getConfigurationById(created.configId);
      expect(after.accountIds).toEqual(['111111111111', '222222222222']);
      expect(after.enabled).toBe(true);
      expect(after.version).toBe(created.version + 1);
    });

    it('overwrites a config scope to exactly the operator owned accounts (shrinking wider scope)', async () => {
      // Arrange - config scoped to two accounts
      const created = await scopedService.createConfiguration(
        buildScopedRequest('Sync Shrink', ['111111111111', '222222222222']),
        { actorEmail: 'operator@example.com', actorGroups: [] },
      );

      // Act - the operator now owns only one of them
      await scopedService.syncOperatorConfigsToOwnedAccounts('operator@example.com', ['222222222222']);

      // Assert - the config scope shrinks to exactly the owned set
      const after = await scopedService.getConfigurationById(created.configId);
      expect(after.accountIds).toEqual(['222222222222']);
      expect(after.enabled).toBe(true);
    });

    it('disables and clears accountIds when the operator owns no accounts', async () => {
      // Arrange - config scoped to an account the operator is about to lose entirely
      const created = await scopedService.createConfiguration(buildScopedRequest('Disable Target', ['111111111111']), {
        actorEmail: 'operator@example.com',
        actorGroups: [],
      });

      // Act - operator owns nothing (e.g. deletion path)
      await scopedService.syncOperatorConfigsToOwnedAccounts('operator@example.com', []);

      // Assert - the config is disabled and de-scoped so it dispatches to nothing
      const after = await scopedService.getConfigurationById(created.configId);
      expect(after.enabled).toBe(false);
      expect(after.accountIds).toBeUndefined();
    });

    it('does not touch configs created by a different user (createdBy must match)', async () => {
      // Arrange - an admin-created config that happens to reference the operator's account
      const created = await scopedService.createConfiguration(buildScopedRequest('Other Owner', ['111111111111']), {
        actorEmail: 'admin@example.com',
        actorGroups: ['AdminGroup'],
      });

      // Act - reconcile for an operator who did not create this config
      await scopedService.syncOperatorConfigsToOwnedAccounts('operator@example.com', ['222222222222']);

      // Assert - the config is left untouched
      const after = await scopedService.getConfigurationById(created.configId);
      expect(after.accountIds).toEqual(['111111111111']);
      expect(after.enabled).toBe(true);
      expect(after.version).toBe(created.version);
    });

    it('leaves a config unchanged when its scope already matches the owned accounts', async () => {
      // Arrange - config already scoped to exactly the accounts the operator owns
      const created = await scopedService.createConfiguration(buildScopedRequest('Already Synced', ['333333333333']), {
        actorEmail: 'operator@example.com',
        actorGroups: [],
      });

      // Act - reconcile with the same owned set (order-insensitive)
      await scopedService.syncOperatorConfigsToOwnedAccounts('operator@example.com', ['333333333333']);

      // Assert - no spurious version-bumping write
      const after = await scopedService.getConfigurationById(created.configId);
      expect(after.accountIds).toEqual(['333333333333']);
      expect(after.version).toBe(created.version);
    });

    it('reconciles multiple operator configs in a single pass', async () => {
      // Arrange - two operator-owned configs with differing scopes
      const first = await scopedService.createConfiguration(
        buildScopedRequest('Multi First', ['111111111111', '222222222222']),
        { actorEmail: 'operator@example.com', actorGroups: [] },
      );
      const second = await scopedService.createConfiguration(buildScopedRequest('Multi Second', ['111111111111']), {
        actorEmail: 'operator@example.com',
        actorGroups: [],
      });

      // Act - both must be overwritten to the same owned set
      await scopedService.syncOperatorConfigsToOwnedAccounts('operator@example.com', ['222222222222']);

      // Assert
      const firstAfter = await scopedService.getConfigurationById(first.configId);
      expect(firstAfter.accountIds).toEqual(['222222222222']);
      expect(firstAfter.enabled).toBe(true);

      const secondAfter = await scopedService.getConfigurationById(second.configId);
      expect(secondAfter.accountIds).toEqual(['222222222222']);
      expect(secondAfter.enabled).toBe(true);
    });

    it('swallows repository failures without throwing (best-effort)', async () => {
      // Arrange - point the service at a non-existent config table so findAll rejects
      const originalTableName = process.env.NOTIFICATION_CONFIG_TABLE_NAME;
      process.env.NOTIFICATION_CONFIG_TABLE_NAME = 'config-table-that-does-not-exist';
      resetApiLambdaEnvironmentCache();
      const brokenService = new NotificationConfigurationService(logger);

      try {
        // Act / Assert - the best-effort method must resolve, not reject
        await expect(
          brokenService.syncOperatorConfigsToOwnedAccounts('operator@example.com', ['111111111111']),
        ).resolves.toBeUndefined();
      } finally {
        process.env.NOTIFICATION_CONFIG_TABLE_NAME = originalTableName;
        resetApiLambdaEnvironmentCache();
      }
    });

    it('retries once after a version conflict and succeeds against the fresh config', async () => {
      // Arrange - a config the operator will have re-scoped to a single owned account
      const created = await scopedService.createConfiguration(
        buildScopedRequest('Conflict Retry', ['111111111111', '222222222222']),
        { actorEmail: 'operator@example.com', actorGroups: [] },
      );

      // Simulate a genuine concurrent writer rather than fabricating a stale version: when reconcile
      // lists configs, return the real current snapshot, then bump the stored version out from under
      // it with a real conditional write against DynamoDB Local. reconcile's first write then targets
      // a now-stale version and DynamoDB raises a real ConditionalCheckFailedException, exercising the
      // re-read-and-retry against the fresh version. findAll is used purely as a timing seam — it
      // calls through to the real implementation, which is the only place to interleave a concurrent
      // write here since the service constructs its DynamoDB client internally (no client-level seam).
      const concurrentWriter = new NotificationConfigurationRepository(notificationConfigTableName, docClient);
      const findAllSpy = jest
        .spyOn(NotificationConfigurationRepository.prototype, 'findAll')
        .mockImplementationOnce(async () => {
          const configs = await concurrentWriter.findAll();
          const current = configs.find((config) => config.configId === created.configId)!;
          await concurrentWriter.updateWithVersion(current, current.version, 'concurrent@example.com');
          return configs;
        });

      // Act - operator now owns only the second account
      await scopedService.syncOperatorConfigsToOwnedAccounts('operator@example.com', ['222222222222']);
      findAllSpy.mockRestore();

      // Assert - the retry read the fresh version and overwrote the scope to the owned set. A missing
      // retry would either leave both accounts in place or never persist the sync. The version
      // reflects exactly the concurrent bump plus the one successful retry write.
      const after = await scopedService.getConfigurationById(created.configId);
      expect(after.accountIds).toEqual(['222222222222']);
      expect(after.enabled).toBe(true);
      expect(after.version).toBe(created.version + 2);
    });

    it('logs at error level when a version conflict persists past the retry', async () => {
      // Arrange
      const created = await scopedService.createConfiguration(
        buildScopedRequest('Conflict Persists', ['111111111111']),
        { actorEmail: 'operator@example.com', actorGroups: [] },
      );

      // A relentless concurrent writer: every time reconcile reads the config (the initial list read
      // and the retry's re-read), bump the stored version with a real write afterwards so reconcile's
      // write always targets a stale version. Both attempts hit genuine ConditionalCheckFailedExceptions
      // from DynamoDB Local, so the escalation path for a persistent conflict runs end to end. The reads
      // call through to the real implementations — they are only timing seams for the interleaved writes.
      const concurrentWriter = new NotificationConfigurationRepository(notificationConfigTableName, docClient);
      const findAllSpy = jest
        .spyOn(NotificationConfigurationRepository.prototype, 'findAll')
        .mockImplementationOnce(async () => {
          const configs = await concurrentWriter.findAll();
          const current = configs.find((config) => config.configId === created.configId)!;
          await concurrentWriter.updateWithVersion(current, current.version, 'concurrent@example.com');
          return configs;
        });
      const findByIdSpy = jest
        .spyOn(NotificationConfigurationRepository.prototype, 'findConfigById')
        .mockImplementationOnce(async () => {
          const current = await concurrentWriter.findConfigById(created.configId);
          if (current) await concurrentWriter.updateWithVersion(current, current.version, 'concurrent@example.com');
          return current;
        });
      const errorSpy = jest.spyOn(logger, 'error').mockImplementation(() => undefined);

      // Act / Assert - still best-effort: resolves rather than rejecting
      await expect(
        scopedService.syncOperatorConfigsToOwnedAccounts('operator@example.com', ['222222222222']),
      ).resolves.toBeUndefined();

      expect(errorSpy).toHaveBeenCalledWith(
        'Version conflict persisted while reconciling notification config to owned accounts',
        expect.objectContaining({ configId: created.configId }),
      );

      findAllSpy.mockRestore();
      findByIdSpy.mockRestore();
      errorSpy.mockRestore();

      // The config kept its original scope because every reconciliation write lost the race.
      const after = await scopedService.getConfigurationById(created.configId);
      expect(after.accountIds).toEqual(['111111111111']);
    });

    it('continues reconciling other configs after one config fails', async () => {
      // Arrange - two affected configs; writes for the first always fail with a non-conflict error
      const failing = await scopedService.createConfiguration(buildScopedRequest('Failing First', ['111111111111']), {
        actorEmail: 'operator@example.com',
        actorGroups: [],
      });
      const healthy = await scopedService.createConfiguration(
        buildScopedRequest('Healthy Second', ['111111111111', '222222222222']),
        { actorEmail: 'operator@example.com', actorGroups: [] },
      );

      // Reject writes for the failing config (keyed by id, since findAll ordering is not guaranteed)
      // and resolve the rest without persisting; we only assert the loop reached every config.
      const updateSpy = jest
        .spyOn(NotificationConfigurationRepository.prototype, 'updateWithVersion')
        .mockImplementation(async (item) => {
          if (item.configId === failing.configId) {
            throw new Error('transient DynamoDB failure');
          }
        });

      // Act
      await scopedService.syncOperatorConfigsToOwnedAccounts('operator@example.com', ['222222222222']);
      const attemptedIds = updateSpy.mock.calls.map((call) => call[0].configId);
      updateSpy.mockRestore();

      // Assert - both configs were attempted, proving the failure did not abort the loop
      expect(attemptedIds).toContain(failing.configId);
      expect(attemptedIds).toContain(healthy.configId);
    });

    it('reconcileOperatorAccountChange overwrites configs to the new owned account set', async () => {
      // Arrange - operator owns a config scoped to two accounts
      const created = await scopedService.createConfiguration(
        buildScopedRequest('Change Sync', ['111111111111', '222222222222']),
        { actorEmail: 'operator@example.com', actorGroups: [] },
      );

      // Act - the operator's assignment changes to just the second account
      await scopedService.reconcileOperatorAccountChange('operator@example.com', ['222222222222']);

      // Assert - the config scope is overwritten to exactly the new owned set
      const after = await scopedService.getConfigurationById(created.configId);
      expect(after.accountIds).toEqual(['222222222222']);
      expect(after.enabled).toBe(true);
    });

    it('reconcileOperatorAccountChange expands configs when the operator gains an account', async () => {
      // Arrange
      const created = await scopedService.createConfiguration(buildScopedRequest('Change Add', ['111111111111']), {
        actorEmail: 'operator@example.com',
        actorGroups: [],
      });

      // Act - the operator now owns an additional account; the config must expand to match
      await scopedService.reconcileOperatorAccountChange('operator@example.com', ['111111111111', '222222222222']);

      // Assert - the config scope grows to the full owned set
      const after = await scopedService.getConfigurationById(created.configId);
      expect(after.accountIds).toEqual(['111111111111', '222222222222']);
      expect(after.version).toBe(created.version + 1);
    });

    it('reconcileOperatorAccountChange is a no-op when the update did not touch accounts (undefined)', async () => {
      // Arrange
      const created = await scopedService.createConfiguration(
        buildScopedRequest('Change Untouched', ['111111111111']),
        {
          actorEmail: 'operator@example.com',
          actorGroups: [],
        },
      );

      // Act - accountIds omitted from the update means the assignment is unchanged
      await scopedService.reconcileOperatorAccountChange('operator@example.com', undefined);

      // Assert - the config is untouched (no version bump)
      const after = await scopedService.getConfigurationById(created.configId);
      expect(after.accountIds).toEqual(['111111111111']);
      expect(after.version).toBe(created.version);
    });

    it('reconcileAfterOperatorDeletion disables and de-scopes every config the operator created', async () => {
      // Arrange - two operator-owned configs
      const first = await scopedService.createConfiguration(buildScopedRequest('Del First', ['111111111111']), {
        actorEmail: 'operator@example.com',
        actorGroups: [],
      });
      const second = await scopedService.createConfiguration(
        buildScopedRequest('Del Second', ['111111111111', '222222222222']),
        { actorEmail: 'operator@example.com', actorGroups: [] },
      );

      // Act - the operator is deleted (owns no accounts)
      await scopedService.reconcileAfterOperatorDeletion('operator@example.com');

      // Assert - both configs are disabled and de-scoped
      const firstAfter = await scopedService.getConfigurationById(first.configId);
      expect(firstAfter.enabled).toBe(false);
      expect(firstAfter.accountIds).toBeUndefined();

      const secondAfter = await scopedService.getConfigurationById(second.configId);
      expect(secondAfter.enabled).toBe(false);
      expect(secondAfter.accountIds).toBeUndefined();
    });
  });

  describe('operator authorization guards (static)', () => {
    it('assertOperatorIsCreator throws when the operator did not create the config', () => {
      expect(() =>
        NotificationConfigurationService.assertOperatorIsCreator('op@example.com', { createdBy: 'other@example.com' }),
      ).toThrow(/only modify notification configurations they created/);
    });

    it('assertOperatorIsCreator passes when the operator created the config', () => {
      expect(() =>
        NotificationConfigurationService.assertOperatorIsCreator('op@example.com', { createdBy: 'op@example.com' }),
      ).not.toThrow();
    });

    it('assertOperatorOwnsRequestedAccounts is a no-op when no accountIds are requested', () => {
      expect(() =>
        NotificationConfigurationService.assertOperatorOwnsRequestedAccounts(['111111111111'], undefined),
      ).not.toThrow();
      expect(() =>
        NotificationConfigurationService.assertOperatorOwnsRequestedAccounts(['111111111111'], []),
      ).not.toThrow();
    });

    it('assertOperatorOwnsRequestedAccounts passes when all requested accounts are owned', () => {
      expect(() =>
        NotificationConfigurationService.assertOperatorOwnsRequestedAccounts(
          ['111111111111', '222222222222'],
          ['111111111111'],
        ),
      ).not.toThrow();
    });

    it('assertOperatorOwnsRequestedAccounts throws when a requested account is not owned', () => {
      expect(() =>
        NotificationConfigurationService.assertOperatorOwnsRequestedAccounts(['111111111111'], ['999999999999']),
      ).toThrow(/do not have access/);
    });
  });

  describe('unsubscribeEmailFromAllConfigs', () => {
    function emailConfigRequest(name: string): CreateNotificationConfigurationRequest {
      return {
        name,
        enabled: true,
        notificationType: 'finding',
        controlIds: [],
        resourceFilterIds: [],
        deliveryChannels: [
          {
            type: 'email',
            enabled: true,
            recipients: [{ recipientType: 'custom', emailAddresses: ['someone@example.com'] }],
          },
        ],
        batchWindow: { enabled: false },
        contentOptions: {
          includeManualRemediationLink: true,
          includeRemediationDeadline: false,
          enforceDeadline: false,
          includeIaCSnippet: false,
          includeEnableAutomationLink: true,
        },
      };
    }

    it('unsubscribes the deleted user from every config where they hold a confirmed subscription', async () => {
      // Arrange - one enabled-email config; the target user is a confirmed subscriber
      snsMock.on(CreateTopicCommand).resolves({ TopicArn: `arn:aws:sns:us-east-1:${mockAccountId}:topic` });
      await service.createConfiguration(emailConfigRequest('Config With Subscriber'), ADMIN_ACTOR);

      snsMock.on(ListSubscriptionsByTopicCommand).resolves({
        Subscriptions: [
          {
            Protocol: 'email',
            Endpoint: 'deleted@example.com',
            SubscriptionArn: `arn:aws:sns:us-east-1:${mockAccountId}:topic:sub-1`,
          },
        ],
      });
      snsMock.on(UnsubscribeCommand).resolves({});

      // Act
      await service.unsubscribeEmailFromAllConfigs('deleted@example.com');

      // Assert - the confirmed subscription ARN is unsubscribed
      const unsubCalls = snsMock.commandCalls(UnsubscribeCommand);
      expect(unsubCalls).toHaveLength(1);
      expect(unsubCalls[0].args[0].input.SubscriptionArn).toBe(`arn:aws:sns:us-east-1:${mockAccountId}:topic:sub-1`);
    });

    it('does not unsubscribe when the deleted user has no matching subscription', async () => {
      // Arrange - the only subscriber is a different email
      snsMock.on(CreateTopicCommand).resolves({ TopicArn: `arn:aws:sns:us-east-1:${mockAccountId}:topic` });
      await service.createConfiguration(emailConfigRequest('Config Without Subscriber'), ADMIN_ACTOR);

      snsMock.on(ListSubscriptionsByTopicCommand).resolves({
        Subscriptions: [
          {
            Protocol: 'email',
            Endpoint: 'someoneelse@example.com',
            SubscriptionArn: `arn:aws:sns:us-east-1:${mockAccountId}:topic:sub-2`,
          },
        ],
      });
      snsMock.on(UnsubscribeCommand).resolves({});

      // Act
      await service.unsubscribeEmailFromAllConfigs('deleted@example.com');

      // Assert
      expect(snsMock.commandCalls(UnsubscribeCommand)).toHaveLength(0);
    });

    it('is best-effort: a subscription-list failure for one config does not throw', async () => {
      // Arrange
      snsMock.on(CreateTopicCommand).resolves({ TopicArn: `arn:aws:sns:us-east-1:${mockAccountId}:topic` });
      await service.createConfiguration(emailConfigRequest('Config That Errors'), ADMIN_ACTOR);

      snsMock.on(ListSubscriptionsByTopicCommand).rejects(new Error('SNS unavailable'));

      // Act / Assert - the method swallows the per-config failure and resolves
      await expect(service.unsubscribeEmailFromAllConfigs('deleted@example.com')).resolves.toBeUndefined();
    });
  });
});
