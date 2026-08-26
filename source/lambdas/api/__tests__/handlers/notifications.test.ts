// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import {
  CognitoIdentityProviderClient,
  AdminGetUserCommand,
  AdminListGroupsForUserCommand,
} from '@aws-sdk/client-cognito-identity-provider';
import { mockClient } from 'aws-sdk-client-mock';
import { SNSClient, PublishCommand, ListSubscriptionsByTopicCommand } from '@aws-sdk/client-sns';
import { PutCommand } from '@aws-sdk/lib-dynamodb';
import { DynamoDBTestSetup } from '../../../common/__tests__/dynamodbSetup';
import {
  notificationConfigTableName,
  remediationConfigTableName,
  resourceFiltersTableName,
  userAccountMappingTableName,
} from '../../../common/__tests__/envSetup';
import { NotificationConfigurationItem } from '@asr/data-models';
import { AdminActivityNotification } from '../../services/adminActivityNotifier';
import {
  createNotificationConfiguration,
  getNotificationConfigurations,
  getNotificationConfiguration,
  deleteNotificationConfiguration,
  updateNotificationConfiguration,
  toggleNotificationConfigurationStatus,
  getEmailSubscriptions,
} from '../../handlers/notifications';
import { createMockContext, createMockEvent, TEST_REQUEST_CONTEXT } from '../utils';
import {
  setupMetricsMocks,
  cleanupMetricsMocks,
  createMetricsTestScope,
  allowOtherMetrics,
} from '../../../common/__tests__/metricsMockSetup';

const FIXED_DATE = new Date('2025-06-15T12:00:00.000Z');

let uuidCounter = 0;
const nextUUID = () => `11111111-2222-4333-a444-${String(++uuidCounter).padStart(12, '0')}`;

jest.mock('../../../common/utils/idGenerator', () => ({
  getIdGenerator: () => ({ randomUUID: () => nextUUID() }),
}));

jest.mock('../../../common/utils/clock', () => ({
  getClock: () => ({ now: () => FIXED_DATE }),
}));

const cognitoMock = mockClient(CognitoIdentityProviderClient);
const snsMock = mockClient(SNSClient);

// The admin activity notifier is the only code path that issues an SNS PublishCommand, so the
// published message can be read back from the SNS boundary to verify what the handler emitted.
function publishedAdminNotifications(): AdminActivityNotification[] {
  return snsMock
    .commandCalls(PublishCommand)
    .map((call) => JSON.parse(call.args[0].input.Message as string) as AdminActivityNotification);
}

const VALID_CREATE_BODY = {
  name: 'Critical Production Alerts',
  enabled: true,
  notificationType: 'finding',
  severityFilter: ['Critical'],
  controlIds: ['S3.1', 'IAM.1'],
  resourceFilterIds: [],
  deliveryChannels: [
    {
      type: 'email',
      enabled: true,
      recipients: [{ recipientType: 'custom', emailAddresses: ['admin@example.com'] }],
    },
  ],
  batchWindow: { enabled: false },
  contentOptions: {
    includeManualRemediationLink: true,
    includeRemediationDeadline: false,
    includeIaCSnippet: false,
    includeEnableAutomationLink: true,
  },
};

function createPostEvent(
  body: Record<string, unknown>,
  username = 'admin@example.com',
  groups: string[] = ['AdminGroup'],
) {
  return createMockEvent({
    httpMethod: 'POST',
    path: '/notifications',
    body: JSON.stringify(body),
    headers: { 'Content-Type': 'application/json', authorization: 'Bearer valid-token' },
    requestContext: {
      ...TEST_REQUEST_CONTEXT,
      authorizer: { claims: { 'cognito:groups': groups, username } },
    },
  });
}

function createGetEvent(username = 'admin@example.com', groups: string[] = ['AdminGroup']) {
  return createGetEventWithParams({}, username, groups);
}

function createGetEventWithParams(
  queryStringParameters: Record<string, string>,
  username = 'admin@example.com',
  groups: string[] = ['AdminGroup'],
) {
  return createMockEvent({
    httpMethod: 'GET',
    path: '/notifications',
    queryStringParameters: Object.keys(queryStringParameters).length > 0 ? queryStringParameters : undefined,
    headers: { 'Content-Type': 'application/json', authorization: 'Bearer valid-token' },
    requestContext: {
      ...TEST_REQUEST_CONTEXT,
      authorizer: { claims: { 'cognito:groups': groups, username } },
    },
  });
}

function createEventWithPathId(
  method: string,
  configId: string,
  options?: { body?: Record<string, unknown>; username?: string; groups?: string[] },
) {
  return createMockEvent({
    httpMethod: method,
    path: `/notifications/${configId}`,
    pathParameters: { id: configId },
    ...(options?.body && { body: JSON.stringify(options.body) }),
    headers: { 'Content-Type': 'application/json', authorization: 'Bearer valid-token' },
    requestContext: {
      ...TEST_REQUEST_CONTEXT,
      authorizer: {
        claims: {
          'cognito:groups': options?.groups ?? ['AdminGroup'],
          username: options?.username ?? 'admin@example.com',
        },
      },
    },
  });
}

function createGetByIdEvent(configId: string, username = 'admin@example.com', groups: string[] = ['AdminGroup']) {
  return createEventWithPathId('GET', configId, { username, groups });
}

function createDeleteEvent(configId: string, username = 'admin@example.com', groups: string[] = ['AdminGroup']) {
  return createEventWithPathId('DELETE', configId, { username, groups });
}

function createPutEvent(
  configId: string,
  body: Record<string, unknown>,
  username = 'admin@example.com',
  groups: string[] = ['AdminGroup'],
) {
  return createEventWithPathId('PUT', configId, { body, username, groups });
}

function createPatchEvent(
  configId: string,
  body: Record<string, unknown>,
  username = 'admin@example.com',
  groups: string[] = ['AdminGroup'],
) {
  return createEventWithPathId('PATCH', configId, { body, username, groups });
}

async function createConfig(name = VALID_CREATE_BODY.name): Promise<NotificationConfigurationItem> {
  const result = await createNotificationConfiguration(
    createPostEvent({ ...VALID_CREATE_BODY, name }),
    createMockContext(),
  );
  expect(result.statusCode).toBe(201);
  return JSON.parse(result.body) as NotificationConfigurationItem;
}

function setupCognitoMock(username: string, groups: string[]) {
  cognitoMock.reset();
  cognitoMock.on(AdminGetUserCommand).resolves({
    Username: username,
    UserAttributes: [
      { Name: 'email', Value: username },
      { Name: 'custom:invitedBy', Value: 'system@example.com' },
    ],
    UserCreateDate: new Date(),
    UserStatus: 'CONFIRMED',
  });
  cognitoMock.on(AdminListGroupsForUserCommand).resolves({
    Groups: groups.map((g) => ({ GroupName: g })),
  });
}

describe('Notification Configurations Handler', () => {
  const DEFAULT_CONTROL_IDS = ['S3.1', 'IAM.1'];

  const seedControl = async (controlId: string): Promise<void> => {
    await DynamoDBTestSetup.getDocClient().send(
      new PutCommand({
        TableName: remediationConfigTableName,
        Item: {
          controlId,
          description: `Seeded for notification tests: ${controlId}`,
          automatedRemediationEnabled: false,
          filters: [],
          filterMode: 'include',
          version: 1,
          lastModified: '2024-01-01T00:00:00.000Z',
          modifiedBy: 'seed',
        },
      }),
    );
  };

  // Seeds the user→account mapping that the authorizer reads to populate an operator's
  // authorizedAccounts. Without a mapping, an operator is treated as owning no accounts.
  const seedOperatorAccounts = async (userId: string, accountIds: string[]): Promise<void> => {
    await DynamoDBTestSetup.getDocClient().send(
      new PutCommand({
        TableName: userAccountMappingTableName,
        Item: { userId, accountIds },
      }),
    );
  };

  beforeAll(async () => {
    await DynamoDBTestSetup.initialize();
    await DynamoDBTestSetup.createNotificationConfigTable(notificationConfigTableName);
    await DynamoDBTestSetup.createConfigTable(remediationConfigTableName);
    await DynamoDBTestSetup.createResourceFiltersTable(resourceFiltersTableName);
    await DynamoDBTestSetup.createUserAccountMappingTable(userAccountMappingTableName);
  });

  afterAll(async () => {
    await DynamoDBTestSetup.deleteTable(notificationConfigTableName);
    await DynamoDBTestSetup.deleteTable(remediationConfigTableName);
    await DynamoDBTestSetup.deleteTable(resourceFiltersTableName);
    await DynamoDBTestSetup.deleteTable(userAccountMappingTableName);
  });

  beforeEach(async () => {
    uuidCounter = 0;
    setupMetricsMocks();
    snsMock.reset();
    snsMock.on(PublishCommand).resolves({ MessageId: 'admin-notification' });
    await DynamoDBTestSetup.clearTable(notificationConfigTableName, 'notificationConfig');
    await DynamoDBTestSetup.clearTable(remediationConfigTableName, 'config');
    await DynamoDBTestSetup.clearTable(resourceFiltersTableName, 'resourceFilters');
    await DynamoDBTestSetup.clearTable(userAccountMappingTableName, 'userAccountMapping');

    // Seed the controls referenced by VALID_CREATE_BODY so existing happy-path
    // tests continue to succeed after foreign-id validation was added.
    for (const controlId of DEFAULT_CONTROL_IDS) {
      await seedControl(controlId);
    }

    setupCognitoMock('admin@example.com', ['AdminGroup']);
  });

  afterEach(() => {
    cleanupMetricsMocks();
  });

  describe('admin activity notifications', () => {
    it('notifies CHANNEL_CREATED on create', async () => {
      // ARRANGE / ACT
      const created = await createConfig('Notify Create');

      // ASSERT
      const notifications = publishedAdminNotifications();
      expect(notifications).toHaveLength(1);
      expect(notifications[0]).toMatchObject({
        action: 'CHANNEL_CREATED',
        resourceType: 'notification-channel',
        resourceId: created.configId,
        resourceName: 'Notify Create',
      });
    });

    it('notifies CHANNEL_TOGGLED on status toggle', async () => {
      // ARRANGE
      const created = await createConfig('Notify Toggle');
      snsMock.resetHistory();

      // ACT
      await toggleNotificationConfigurationStatus(
        createPatchEvent(created.configId, { enabled: false, version: created.version }),
        createMockContext(),
      );

      // ASSERT
      const notifications = publishedAdminNotifications();
      expect(notifications).toHaveLength(1);
      expect(notifications[0]).toMatchObject({ action: 'CHANNEL_TOGGLED', resourceId: created.configId });
    });

    it('notifies CHANNEL_DELETED on delete', async () => {
      // ARRANGE
      const created = await createConfig('Notify Delete');
      snsMock.resetHistory();

      // ACT
      await deleteNotificationConfiguration(createDeleteEvent(created.configId), createMockContext());

      // ASSERT
      const notifications = publishedAdminNotifications();
      expect(notifications).toHaveLength(1);
      expect(notifications[0]).toMatchObject({
        action: 'CHANNEL_DELETED',
        resourceId: created.configId,
        resourceName: 'Notify Delete',
      });
    });
  });

  describe('GET /notifications', () => {
    it('should return 200 with empty list when no configurations exist', async () => {
      const result = await getNotificationConfigurations(createGetEvent(), createMockContext());

      expect(result.statusCode).toBe(200);
      expect(JSON.parse(result.body)).toEqual({ configurations: [] });
    });

    it('should return 200 with all configurations', async () => {
      await createNotificationConfiguration(createPostEvent(VALID_CREATE_BODY), createMockContext());
      await createNotificationConfiguration(
        createPostEvent({ ...VALID_CREATE_BODY, name: 'Second Config' }),
        createMockContext(),
      );

      const result = await getNotificationConfigurations(createGetEvent(), createMockContext());

      expect(result.statusCode).toBe(200);
      const body = JSON.parse(result.body);
      expect(body.configurations).toHaveLength(2);
    });

    it('should allow AccountOperatorGroup to read', async () => {
      setupCognitoMock('operator@example.com', ['AccountOperatorGroup']);
      const result = await getNotificationConfigurations(
        createGetEvent('operator@example.com', ['AccountOperatorGroup']),
        createMockContext(),
      );

      expect(result.statusCode).toBe(200);
    });

    it('should return all configurations to an operator, including those they did not create', async () => {
      // Visibility is unrestricted: operators see every config (read-only for ones they cannot
      // modify). Edit authority is creator-based and enforced only on the mutation paths.
      await createNotificationConfiguration(createPostEvent(VALID_CREATE_BODY), createMockContext());
      await createNotificationConfiguration(
        createPostEvent({ ...VALID_CREATE_BODY, name: 'Another Admin Config' }),
        createMockContext(),
      );
      setupCognitoMock('operator@example.com', ['AccountOperatorGroup']);

      const result = await getNotificationConfigurations(
        createGetEvent('operator@example.com', ['AccountOperatorGroup']),
        createMockContext(),
      );

      expect(result.statusCode).toBe(200);
      expect(JSON.parse(result.body).configurations).toHaveLength(2);
    });
  });

  describe('POST /notifications', () => {
    it('should return 201 with created configuration', async () => {
      const result = await createNotificationConfiguration(createPostEvent(VALID_CREATE_BODY), createMockContext());

      expect(result.statusCode).toBe(201);
      const body = JSON.parse(result.body);
      expect(body.configId).toBe('11111111-2222-4333-a444-000000000001');
      expect(body.name).toBe('Critical Production Alerts');
      expect(body.version).toBe(1);
      expect(body.createdBy).toBe('admin@example.com');
      expect(body.createdAt).toBe(FIXED_DATE.toISOString());
    });

    it('should throw on missing name', async () => {
      const { name: _name, ...bodyWithoutName } = VALID_CREATE_BODY;
      await expect(
        createNotificationConfiguration(createPostEvent(bodyWithoutName), createMockContext()),
      ).rejects.toThrow('Invalid notification configuration');
    });

    it('should throw on empty deliveryChannels', async () => {
      await expect(
        createNotificationConfiguration(
          createPostEvent({ ...VALID_CREATE_BODY, deliveryChannels: [] }),
          createMockContext(),
        ),
      ).rejects.toThrow('Invalid notification configuration');
    });

    it('should throw when no delivery channel is enabled', async () => {
      const disabledChannel = {
        ...VALID_CREATE_BODY,
        deliveryChannels: [
          {
            type: 'email',
            enabled: false,
            recipients: [{ recipientType: 'custom', emailAddresses: ['a@b.com'] }],
          },
        ],
      };
      await expect(
        createNotificationConfiguration(createPostEvent(disabledChannel), createMockContext()),
      ).rejects.toThrow('Invalid notification configuration');
    });

    it('should throw when duplicate delivery channel types are provided', async () => {
      const duplicateChannels = {
        ...VALID_CREATE_BODY,
        deliveryChannels: [
          {
            type: 'email',
            enabled: true,
            recipients: [{ recipientType: 'custom', emailAddresses: ['a@b.com'] }],
          },
          {
            type: 'email',
            enabled: true,
            recipients: [{ recipientType: 'custom', emailAddresses: ['c@d.com'] }],
          },
        ],
      };
      await expect(
        createNotificationConfiguration(createPostEvent(duplicateChannels), createMockContext()),
      ).rejects.toThrow('Invalid notification configuration');
    });

    it('should throw on duplicate name', async () => {
      await createNotificationConfiguration(createPostEvent(VALID_CREATE_BODY), createMockContext());

      await expect(
        createNotificationConfiguration(createPostEvent(VALID_CREATE_BODY), createMockContext()),
      ).rejects.toThrow('already exists');
    });

    it('should atomically prevent concurrent duplicate names', async () => {
      const [result1, result2] = await Promise.allSettled([
        createNotificationConfiguration(createPostEvent(VALID_CREATE_BODY), createMockContext()),
        createNotificationConfiguration(createPostEvent(VALID_CREATE_BODY), createMockContext()),
      ]);

      const results = [result1, result2];
      const fulfilled = results.filter((r) => r.status === 'fulfilled');
      const rejected = results.filter((r) => r.status === 'rejected');

      expect(fulfilled).toHaveLength(1);
      expect(rejected).toHaveLength(1);
    });

    it('should allow an operator to create a configuration scoped to their owned accounts', async () => {
      // Operators are permitted to create configs; when they omit accountIds the backend
      // auto-scopes the config to the accounts they own (exercises applyOperatorAccountScope).
      setupCognitoMock('operator@example.com', ['AccountOperatorGroup']);
      await seedOperatorAccounts('operator@example.com', ['111111111111']);
      const result = await createNotificationConfiguration(
        createPostEvent(VALID_CREATE_BODY, 'operator@example.com', ['AccountOperatorGroup']),
        createMockContext(),
      );

      expect(result.statusCode).toBe(201);
      // The config is scoped to the operator's owned accounts, not left globally scoped.
      expect(JSON.parse(result.body).accountIds).toEqual(['111111111111']);
    });

    it('should reject an operator with no assigned accounts from creating a configuration', async () => {
      // Regression: an operator owning no accounts must not auto-scope to an empty accountIds
      // array, which would be treated as a global-scope config matching every account.
      setupCognitoMock('operator@example.com', ['AccountOperatorGroup']);
      await expect(
        createNotificationConfiguration(
          createPostEvent(VALID_CREATE_BODY, 'operator@example.com', ['AccountOperatorGroup']),
          createMockContext(),
        ),
      ).rejects.toThrow(
        'Account operators with no assigned accounts cannot create or modify notification configurations',
      );
    });

    it('should reject an operator creating a config scoped to accounts they do not own', async () => {
      setupCognitoMock('operator@example.com', ['AccountOperatorGroup']);
      await expect(
        createNotificationConfiguration(
          createPostEvent({ ...VALID_CREATE_BODY, accountIds: ['999999999999'] }, 'operator@example.com', [
            'AccountOperatorGroup',
          ]),
          createMockContext(),
        ),
      ).rejects.toThrow('You do not have access to one or more of the specified accounts');
    });

    describe('foreign-id validation', () => {
      it('should reject create with unknown controlIds', async () => {
        await expect(
          createNotificationConfiguration(
            createPostEvent({ ...VALID_CREATE_BODY, name: 'Bad Controls', controlIds: ['S3.1', 'DOES.NOT.EXIST'] }),
            createMockContext(),
          ),
        ).rejects.toThrow('Unknown controlIds: DOES.NOT.EXIST');
      });

      it('should reject create with unknown resourceFilterIds', async () => {
        const unknownFilterId = 'ffffffff-ffff-4fff-afff-ffffffffffff';
        await expect(
          createNotificationConfiguration(
            createPostEvent({ ...VALID_CREATE_BODY, name: 'Bad Filters', resourceFilterIds: [unknownFilterId] }),
            createMockContext(),
          ),
        ).rejects.toThrow(`Unknown resourceFilterIds: ${unknownFilterId}`);
      });

      it('should include both controlId and resourceFilterId errors in a single response', async () => {
        const unknownFilterId = 'ffffffff-ffff-4fff-afff-ffffffffffff';
        await expect(
          createNotificationConfiguration(
            createPostEvent({
              ...VALID_CREATE_BODY,
              name: 'Bad Both',
              controlIds: ['NOPE.1'],
              resourceFilterIds: [unknownFilterId],
            }),
            createMockContext(),
          ),
        ).rejects.toThrow(/Unknown controlIds: NOPE\.1.*Unknown resourceFilterIds/);
      });

      it('should not create the configuration when validation fails', async () => {
        await expect(
          createNotificationConfiguration(
            createPostEvent({ ...VALID_CREATE_BODY, name: 'Invalid Create', controlIds: ['NOPE.1'] }),
            createMockContext(),
          ),
        ).rejects.toThrow('Unknown controlIds');

        const list = await getNotificationConfigurations(createGetEvent(), createMockContext());
        expect(JSON.parse(list.body).configurations).toHaveLength(0);
      });
    });
  });

  describe('GET /notifications/{id}', () => {
    it('should return 200 with the configuration', async () => {
      const created = await createConfig();

      const result = await getNotificationConfiguration(createGetByIdEvent(created.configId), createMockContext());

      expect(result.statusCode).toBe(200);
      const body = JSON.parse(result.body);
      expect(body.configId).toBe(created.configId);
      expect(body.name).toBe(VALID_CREATE_BODY.name);
    });

    it('should throw on non-existent id', async () => {
      await expect(
        getNotificationConfiguration(createGetByIdEvent('aaaaaaaa-bbbb-4ccc-addd-eeeeeeeeeeee'), createMockContext()),
      ).rejects.toThrow('not found');
    });

    it('should throw on invalid UUID', async () => {
      await expect(getNotificationConfiguration(createGetByIdEvent('not-a-uuid'), createMockContext())).rejects.toThrow(
        'id must be a valid UUID',
      );
    });
  });

  describe('DELETE /notifications/{id}', () => {
    const createUnattachedConfig = async (
      name = 'Unattached Config',
      username = 'admin@example.com',
      groups: string[] = ['AdminGroup'],
    ) => {
      // A config with no controls and no resource filters attached so the
      // delete path is not blocked by the "detach first" rule.
      const result = await createNotificationConfiguration(
        createPostEvent({ ...VALID_CREATE_BODY, name, controlIds: [], resourceFilterIds: [] }, username, groups),
        createMockContext(),
      );
      expect(result.statusCode).toBe(201);
      return JSON.parse(result.body) as NotificationConfigurationItem;
    };

    it('should return 200 and remove configuration', async () => {
      const created = await createUnattachedConfig();

      const result = await deleteNotificationConfiguration(createDeleteEvent(created.configId), createMockContext());

      expect(result.statusCode).toBe(200);
      await expect(
        getNotificationConfiguration(createGetByIdEvent(created.configId), createMockContext()),
      ).rejects.toThrow('not found');
    });

    it('should return 200 when deleting a non-existent configuration (idempotent)', async () => {
      // ARRANGE - assert the no-op path records no Delete CRUD metric
      const metricsScope = createMetricsTestScope(/.*configuration_crud.*operation.*Delete.*/);

      // ACT
      const result = await deleteNotificationConfiguration(
        createDeleteEvent('aaaaaaaa-bbbb-4ccc-addd-eeeeeeeeeeee'),
        createMockContext(),
      );

      // ASSERT
      expect(result.statusCode).toBe(200);
      expect(metricsScope.isDone()).toBe(false);
    });

    it('should throw on invalid UUID', async () => {
      await expect(
        deleteNotificationConfiguration(createDeleteEvent('not-a-uuid'), createMockContext()),
      ).rejects.toThrow('id must be a valid UUID');
    });

    it('should allow DelegatedAdminGroup users to delete', async () => {
      setupCognitoMock('delegated@example.com', ['DelegatedAdminGroup']);
      const created = await createUnattachedConfig('Delegated Delete');
      setupCognitoMock('delegated@example.com', ['DelegatedAdminGroup']);

      const result = await deleteNotificationConfiguration(
        createDeleteEvent(created.configId, 'delegated@example.com', ['DelegatedAdminGroup']),
        createMockContext(),
      );
      expect(result.statusCode).toBe(200);
    });

    it('should reject an operator deleting a configuration they did not create', async () => {
      // Edit authority is creator-based: this config was created by admin@example.com, so an
      // operator may read it but not delete it.
      const created = await createUnattachedConfig('Admin-Created Delete Target');
      setupCognitoMock('operator@example.com', ['AccountOperatorGroup']);
      await expect(
        deleteNotificationConfiguration(
          createDeleteEvent(created.configId, 'operator@example.com', ['AccountOperatorGroup']),
          createMockContext(),
        ),
      ).rejects.toThrow('Account operators can only modify notification configurations they created');
    });

    it('should allow an operator to delete a configuration they created', async () => {
      setupCognitoMock('operator@example.com', ['AccountOperatorGroup']);
      await seedOperatorAccounts('operator@example.com', ['111111111111']);
      const created = await createUnattachedConfig('Operator-Created Delete Target', 'operator@example.com', [
        'AccountOperatorGroup',
      ]);
      setupCognitoMock('operator@example.com', ['AccountOperatorGroup']);

      const result = await deleteNotificationConfiguration(
        createDeleteEvent(created.configId, 'operator@example.com', ['AccountOperatorGroup']),
        createMockContext(),
      );
      expect(result.statusCode).toBe(200);
    });

    it('should free the name for reuse after deletion', async () => {
      const created = await createUnattachedConfig(VALID_CREATE_BODY.name);

      await deleteNotificationConfiguration(createDeleteEvent(created.configId), createMockContext());

      const recreated = await createNotificationConfiguration(createPostEvent(VALID_CREATE_BODY), createMockContext());
      expect(recreated.statusCode).toBe(201);
    });

    describe('attached-entity block rule', () => {
      it('should allow delete when the configuration has attached controls (log only)', async () => {
        // VALID_CREATE_BODY includes controlIds: ['S3.1', 'IAM.1']
        const created = await createConfig();

        const result = await deleteNotificationConfiguration(createDeleteEvent(created.configId), createMockContext());
        expect(result.statusCode).toBe(200);
      });
    });
  });

  describe('PUT /notifications/{id}', () => {
    it('should return 200 with updated configuration', async () => {
      const created = await createConfig();

      const updateBody = { ...VALID_CREATE_BODY, name: 'Updated Name', version: 1 };
      const result = await updateNotificationConfiguration(
        createPutEvent(created.configId, updateBody),
        createMockContext(),
      );

      expect(result.statusCode).toBe(200);
      const body = JSON.parse(result.body);
      expect(body.name).toBe('Updated Name');
      expect(body.version).toBe(2);
    });

    it('should update without changing the name', async () => {
      const created = await createConfig();

      const updateBody = { ...VALID_CREATE_BODY, severityFilter: ['High'], version: 1 };
      const result = await updateNotificationConfiguration(
        createPutEvent(created.configId, updateBody),
        createMockContext(),
      );

      expect(result.statusCode).toBe(200);
      const body = JSON.parse(result.body);
      expect(body.severityFilter).toEqual(['High']);
      expect(body.name).toBe(VALID_CREATE_BODY.name);
      expect(body.version).toBe(2);
    });

    it('should free old name after rename', async () => {
      const created = await createConfig('Original Name');

      await updateNotificationConfiguration(
        createPutEvent(created.configId, { ...VALID_CREATE_BODY, name: 'New Name', version: 1 }),
        createMockContext(),
      );

      // Old name should be available for a new config
      const reused = await createNotificationConfiguration(
        createPostEvent({ ...VALID_CREATE_BODY, name: 'Original Name' }),
        createMockContext(),
      );
      expect(reused.statusCode).toBe(201);
    });

    it('should throw on non-existent id', async () => {
      const updateBody = { ...VALID_CREATE_BODY, version: 1 };
      await expect(
        updateNotificationConfiguration(
          createPutEvent('aaaaaaaa-bbbb-4ccc-addd-eeeeeeeeeeee', updateBody),
          createMockContext(),
        ),
      ).rejects.toThrow('not found');
    });

    it('should throw on invalid UUID', async () => {
      const updateBody = { ...VALID_CREATE_BODY, version: 1 };
      await expect(
        updateNotificationConfiguration(createPutEvent('not-a-uuid', updateBody), createMockContext()),
      ).rejects.toThrow('id must be a valid UUID');
    });

    it('should throw on version conflict with machine-readable code and currentVersion', async () => {
      const created = await createConfig();

      const updateBody = { ...VALID_CREATE_BODY, version: 99 };
      await expect(
        updateNotificationConfiguration(createPutEvent(created.configId, updateBody), createMockContext()),
      ).rejects.toMatchObject({
        name: 'ConflictError',
        code: 'VERSION_CONFLICT',
        context: expect.objectContaining({
          configId: created.configId,
          expectedVersion: 99,
          currentVersion: 1,
        }),
      });
    });

    it('should throw when renaming to an existing name', async () => {
      await createConfig('First Config');
      const second = await createConfig('Second Config');

      const updateBody = { ...VALID_CREATE_BODY, name: 'First Config', version: 1 };
      await expect(
        updateNotificationConfiguration(createPutEvent(second.configId, updateBody), createMockContext()),
      ).rejects.toThrow('already exists');
    });

    it('should reject an operator updating a configuration they did not create', async () => {
      const created = await createConfig();
      setupCognitoMock('operator@example.com', ['AccountOperatorGroup']);

      await expect(
        updateNotificationConfiguration(
          createPutEvent(created.configId, { ...VALID_CREATE_BODY, version: 1 }, 'operator@example.com', [
            'AccountOperatorGroup',
          ]),
          createMockContext(),
        ),
      ).rejects.toThrow('Account operators can only modify notification configurations they created');
    });

    it('should allow an operator to update a configuration they created', async () => {
      setupCognitoMock('operator@example.com', ['AccountOperatorGroup']);
      await seedOperatorAccounts('operator@example.com', ['111111111111']);
      const created = await createNotificationConfiguration(
        createPostEvent(VALID_CREATE_BODY, 'operator@example.com', ['AccountOperatorGroup']),
        createMockContext(),
      );
      const createdConfig = JSON.parse(created.body) as NotificationConfigurationItem;
      setupCognitoMock('operator@example.com', ['AccountOperatorGroup']);

      const result = await updateNotificationConfiguration(
        createPutEvent(
          createdConfig.configId,
          { ...VALID_CREATE_BODY, name: 'Operator Updated', version: 1 },
          'operator@example.com',
          ['AccountOperatorGroup'],
        ),
        createMockContext(),
      );

      expect(result.statusCode).toBe(200);
      expect(JSON.parse(result.body).name).toBe('Operator Updated');
    });

    it('should throw on invalid body', async () => {
      const created = await createConfig();

      await expect(
        updateNotificationConfiguration(createPutEvent(created.configId, { version: 1 }), createMockContext()),
      ).rejects.toThrow('Invalid notification configuration update');
    });

    describe('foreign-id validation', () => {
      it('should reject update with unknown controlIds and leave the config unchanged', async () => {
        const created = await createConfig();

        await expect(
          updateNotificationConfiguration(
            createPutEvent(created.configId, {
              ...VALID_CREATE_BODY,
              controlIds: ['NOPE.1'],
              version: 1,
            }),
            createMockContext(),
          ),
        ).rejects.toThrow('Unknown controlIds: NOPE.1');

        const fetched = await getNotificationConfiguration(createGetByIdEvent(created.configId), createMockContext());
        const body = JSON.parse(fetched.body);
        expect(body.version).toBe(1);
        expect(body.controlIds).toEqual(VALID_CREATE_BODY.controlIds);
      });

      it('should reject update with unknown resourceFilterIds', async () => {
        const created = await createConfig();
        const unknownFilterId = 'ffffffff-ffff-4fff-afff-ffffffffffff';

        await expect(
          updateNotificationConfiguration(
            createPutEvent(created.configId, {
              ...VALID_CREATE_BODY,
              resourceFilterIds: [unknownFilterId],
              version: 1,
            }),
            createMockContext(),
          ),
        ).rejects.toThrow(`Unknown resourceFilterIds: ${unknownFilterId}`);
      });
    });
  });

  describe('PATCH /notifications/{id}', () => {
    it('should return 200 with toggled status to disabled', async () => {
      const created = await createConfig();

      const result = await toggleNotificationConfigurationStatus(
        createPatchEvent(created.configId, { enabled: false, version: 1 }),
        createMockContext(),
      );

      expect(result.statusCode).toBe(200);
      const body = JSON.parse(result.body);
      expect(body.enabled).toBe(false);
      expect(body.version).toBe(2);
    });

    it('should toggle back to enabled', async () => {
      const created = await createConfig();

      // Disable
      await toggleNotificationConfigurationStatus(
        createPatchEvent(created.configId, { enabled: false, version: 1 }),
        createMockContext(),
      );

      // Re-enable
      const result = await toggleNotificationConfigurationStatus(
        createPatchEvent(created.configId, { enabled: true, version: 2 }),
        createMockContext(),
      );

      expect(result.statusCode).toBe(200);
      const body = JSON.parse(result.body);
      expect(body.enabled).toBe(true);
      expect(body.version).toBe(3);
    });

    it('should throw on non-existent id', async () => {
      await expect(
        toggleNotificationConfigurationStatus(
          createPatchEvent('aaaaaaaa-bbbb-4ccc-addd-eeeeeeeeeeee', { enabled: false, version: 1 }),
          createMockContext(),
        ),
      ).rejects.toThrow('not found');
    });

    it('should throw on invalid UUID', async () => {
      await expect(
        toggleNotificationConfigurationStatus(
          createPatchEvent('not-a-uuid', { enabled: false, version: 1 }),
          createMockContext(),
        ),
      ).rejects.toThrow('id must be a valid UUID');
    });

    it('should throw on version conflict with machine-readable code and currentVersion', async () => {
      const created = await createConfig();

      await expect(
        toggleNotificationConfigurationStatus(
          createPatchEvent(created.configId, { enabled: false, version: 99 }),
          createMockContext(),
        ),
      ).rejects.toMatchObject({
        name: 'ConflictError',
        code: 'VERSION_CONFLICT',
        context: expect.objectContaining({
          configId: created.configId,
          expectedVersion: 99,
          currentVersion: 1,
        }),
      });
    });

    it('should reject an operator toggling a configuration they did not create', async () => {
      const created = await createConfig();
      setupCognitoMock('operator@example.com', ['AccountOperatorGroup']);

      await expect(
        toggleNotificationConfigurationStatus(
          createPatchEvent(created.configId, { enabled: false, version: 1 }, 'operator@example.com', [
            'AccountOperatorGroup',
          ]),
          createMockContext(),
        ),
      ).rejects.toThrow('Account operators can only modify notification configurations they created');
    });

    it('should allow an operator to toggle a configuration they created', async () => {
      setupCognitoMock('operator@example.com', ['AccountOperatorGroup']);
      await seedOperatorAccounts('operator@example.com', ['111111111111']);
      const created = await createNotificationConfiguration(
        createPostEvent(VALID_CREATE_BODY, 'operator@example.com', ['AccountOperatorGroup']),
        createMockContext(),
      );
      const createdConfig = JSON.parse(created.body) as NotificationConfigurationItem;
      setupCognitoMock('operator@example.com', ['AccountOperatorGroup']);

      const result = await toggleNotificationConfigurationStatus(
        createPatchEvent(createdConfig.configId, { enabled: false, version: 1 }, 'operator@example.com', [
          'AccountOperatorGroup',
        ]),
        createMockContext(),
      );

      expect(result.statusCode).toBe(200);
      expect(JSON.parse(result.body).enabled).toBe(false);
    });

    it('should throw on invalid body', async () => {
      const created = await createConfig();

      await expect(
        toggleNotificationConfigurationStatus(
          createPatchEvent(created.configId, { enabled: 'yes', version: 1 }),
          createMockContext(),
        ),
      ).rejects.toThrow('Invalid toggle status request');
    });
  });

  describe('GET /notifications/{id}/subscriptions', () => {
    it('should reject an operator listing subscriptions for a configuration they did not create', async () => {
      const created = await createConfig();
      setupCognitoMock('operator@example.com', ['AccountOperatorGroup']);

      await expect(
        getEmailSubscriptions(
          createGetByIdEvent(created.configId, 'operator@example.com', ['AccountOperatorGroup']),
          createMockContext(),
        ),
      ).rejects.toThrow('Account operators can only modify notification configurations they created');
    });

    it('should allow an operator to list subscriptions for a configuration they created', async () => {
      setupCognitoMock('operator@example.com', ['AccountOperatorGroup']);
      await seedOperatorAccounts('operator@example.com', ['111111111111']);
      const created = await createNotificationConfiguration(
        createPostEvent(VALID_CREATE_BODY, 'operator@example.com', ['AccountOperatorGroup']),
        createMockContext(),
      );
      const createdConfig = JSON.parse(created.body) as NotificationConfigurationItem;
      setupCognitoMock('operator@example.com', ['AccountOperatorGroup']);
      snsMock.on(ListSubscriptionsByTopicCommand).resolves({ Subscriptions: [] });

      const result = await getEmailSubscriptions(
        createGetByIdEvent(createdConfig.configId, 'operator@example.com', ['AccountOperatorGroup']),
        createMockContext(),
      );

      expect(result.statusCode).toBe(200);
    });
  });

  describe('Solutions Metrics', () => {
    it('should emit configuration_crud Create metric on successful create', async () => {
      // ARRANGE
      const metricsScope = createMetricsTestScope(/.*configuration_crud.*1.*operation.*Create.*/);

      // ACT
      const result = await createNotificationConfiguration(createPostEvent(VALID_CREATE_BODY), createMockContext());

      // ASSERT
      expect(result.statusCode).toBe(201);
      expect(metricsScope.isDone()).toBe(true);
    });

    it('should emit configuration_crud Update metric on successful update', async () => {
      // ARRANGE
      const created = await createConfig();
      const metricsScope = createMetricsTestScope(/.*configuration_crud.*1.*operation.*Update.*/);

      // ACT
      const result = await updateNotificationConfiguration(
        createPutEvent(created.configId, { ...VALID_CREATE_BODY, name: 'Renamed', version: 1 }),
        createMockContext(),
      );

      // ASSERT
      expect(result.statusCode).toBe(200);
      expect(metricsScope.isDone()).toBe(true);
    });

    it('should emit configuration_crud Update metric on successful toggle', async () => {
      // ARRANGE
      const created = await createConfig();
      const metricsScope = createMetricsTestScope(/.*configuration_crud.*1.*operation.*Update.*/);

      // ACT
      const result = await toggleNotificationConfigurationStatus(
        createPatchEvent(created.configId, { enabled: false, version: 1 }),
        createMockContext(),
      );

      // ASSERT
      expect(result.statusCode).toBe(200);
      expect(metricsScope.isDone()).toBe(true);
    });

    it('should emit configuration_crud Delete metric on delete', async () => {
      // ARRANGE
      const created = await createConfig();
      const metricsScope = createMetricsTestScope(/.*configuration_crud.*1.*operation.*Delete.*/);

      // ACT
      const result = await deleteNotificationConfiguration(createDeleteEvent(created.configId), createMockContext());

      // ASSERT
      expect(result.statusCode).toBe(200);
      expect(metricsScope.isDone()).toBe(true);
    });

    it('should emit configuration_validation_errors when body validation fails', async () => {
      // ARRANGE
      const { name: _name, ...bodyWithoutName } = VALID_CREATE_BODY;
      const metricsScope = createMetricsTestScope(/.*configuration_validation_errors.*1.*/);

      // ACT & ASSERT
      await expect(
        createNotificationConfiguration(createPostEvent(bodyWithoutName), createMockContext()),
      ).rejects.toThrow('Invalid notification configuration');
      expect(metricsScope.isDone()).toBe(true);
    });

    it('should not emit configuration_crud when create validation fails', async () => {
      // ARRANGE
      const { name: _name, ...bodyWithoutName } = VALID_CREATE_BODY;
      const metricsScope = createMetricsTestScope(/.*configuration_crud.*/);
      // The validation-failure path legitimately emits configuration_validation_errors;
      // absorb it so only the configuration_crud assertion below is exercised.
      allowOtherMetrics();

      // ACT & ASSERT
      await expect(
        createNotificationConfiguration(createPostEvent(bodyWithoutName), createMockContext()),
      ).rejects.toThrow('Invalid notification configuration');
      expect(metricsScope.isDone()).toBe(false);
    });
  });
});
