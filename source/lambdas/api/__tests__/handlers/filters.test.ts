// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import {
  CognitoIdentityProviderClient,
  AdminGetUserCommand,
  AdminListGroupsForUserCommand,
} from '@aws-sdk/client-cognito-identity-provider';
import { DynamoDBDocumentClient, PutCommand, GetCommand, ScanCommand } from '@aws-sdk/lib-dynamodb';
import { mockClient } from 'aws-sdk-client-mock';
import { DynamoDBTestSetup } from '../../../common/__tests__/dynamodbSetup';
import {
  resourceFiltersTableName,
  userAccountMappingTableName,
  remediationConfigTableName,
  notificationConfigTableName,
  notificationBatchesTableName,
} from '../../../common/__tests__/envSetup';
import {
  setupMetricsMocks,
  cleanupMetricsMocks,
  createMetricsTestScope,
} from '../../../common/__tests__/metricsMockSetup';
import { createFilter, deleteFilter, getFilters, updateFilter } from '../../handlers/filters';
import { createMockContext, createMockEvent, TEST_REQUEST_CONTEXT } from '../utils';

const cognitoMock = mockClient(CognitoIdentityProviderClient);

const FILTER_ID = '550e8400-e29b-41d4-a716-446655440000';

const SEED_FILTER = {
  filterId: FILTER_ID,
  name: 'Production Accounts',
  accountIds: new Set(['123456789012']),
  organizationalUnits: new Set(['ou-abcd-12345678']),
  tags: [{ key: 'Environment', value: 'Production' }],
  arnPatterns: new Set(['arn:aws:s3:::prod-*']),
  version: 1,
  createdAt: '2024-01-01T00:00:00Z',
  createdBy: 'admin@example.com',
  lastModified: '2024-01-01T00:00:00Z',
  modifiedBy: 'admin@example.com',
};

const VALID_UPDATE_BODY = {
  name: 'Updated Filter Name',
  accountIds: ['123456789012', '987654321098'],
  organizationalUnits: ['ou-abcd-12345678'],
  tags: [{ key: 'Env', value: 'Staging' }],
  arnPatterns: ['arn:aws:s3:::staging-*'],
  version: 1,
};

function createUpdateEvent(
  filterId: string,
  body: Record<string, unknown>,
  username = 'admin-user@example.com',
  groups: string[] = ['AdminGroup'],
) {
  return createMockEvent({
    httpMethod: 'PUT',
    path: `/filters/${filterId}`,
    pathParameters: { filterId },
    body: JSON.stringify(body),
    headers: {
      'Content-Type': 'application/json',
      authorization: 'Bearer valid-token',
    },
    requestContext: {
      ...TEST_REQUEST_CONTEXT,
      authorizer: {
        claims: {
          'cognito:groups': groups,
          username,
        },
      },
    },
  });
}

const ENFORCING_CONFIG_ID = '11111111-1111-4111-8111-111111111111';

function buildNotificationConfig(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  const { contentOptions, ...rest } = overrides as { contentOptions?: Record<string, unknown> };
  return {
    CONFIG_CONSTANT: 'CONFIG',
    configId: ENFORCING_CONFIG_ID,
    name: 'Deadline Enforcing Config',
    enabled: true,
    notificationType: 'finding',
    enabledType: 'finding',
    severityFilter: ['All'],
    controlIds: ['S3.5'],
    resourceFilterIds: [FILTER_ID],
    deliveryChannels: [],
    batchWindow: { enabled: false },
    contentOptions: {
      includeManualRemediationLink: false,
      includeRemediationDeadline: true,
      remediationDeadlineDays: 1,
      enforceDeadline: true,
      includeIaCSnippet: false,
      includeEnableAutomationLink: false,
      ...contentOptions,
    },
    version: 1,
    createdAt: '2026-01-01T00:00:00Z',
    createdBy: 'admin@example.com',
    ...rest,
  };
}

async function seedNotificationConfig(
  dynamoDBDocumentClient: DynamoDBDocumentClient,
  overrides: Record<string, unknown> = {},
): Promise<void> {
  await dynamoDBDocumentClient.send(
    new PutCommand({ TableName: notificationConfigTableName, Item: buildNotificationConfig(overrides) }),
  );
}

async function readReconciliationTasks(
  dynamoDBDocumentClient: DynamoDBDocumentClient,
): Promise<Record<string, unknown>[]> {
  const result = await dynamoDBDocumentClient.send(new ScanCommand({ TableName: notificationBatchesTableName }));
  return (result.Items ?? []).filter(
    (item): item is Record<string, unknown> =>
      typeof item.configId === 'string' && item.configId.startsWith('reconciliation#'),
  );
}

describe('FiltersHandler Integration Tests', () => {
  let dynamoDBDocumentClient: DynamoDBDocumentClient;

  beforeAll(async () => {
    await DynamoDBTestSetup.initialize();
    dynamoDBDocumentClient = DynamoDBTestSetup.getDocClient();
    await DynamoDBTestSetup.createResourceFiltersTable(resourceFiltersTableName);
    await DynamoDBTestSetup.createUserAccountMappingTable(userAccountMappingTableName);
    await DynamoDBTestSetup.createConfigTable(remediationConfigTableName);
    await DynamoDBTestSetup.createNotificationConfigTable(notificationConfigTableName);
    await DynamoDBTestSetup.createNotificationBatchesTable(notificationBatchesTableName);
  });

  afterAll(async () => {
    await DynamoDBTestSetup.deleteTable(resourceFiltersTableName);
    await DynamoDBTestSetup.deleteTable(userAccountMappingTableName);
    await DynamoDBTestSetup.deleteTable(remediationConfigTableName);
    await DynamoDBTestSetup.deleteTable(notificationConfigTableName);
    await DynamoDBTestSetup.deleteTable(notificationBatchesTableName);
    cleanupMetricsMocks();
  });

  beforeEach(async () => {
    await DynamoDBTestSetup.clearTable(resourceFiltersTableName, 'resourceFilters');
    await DynamoDBTestSetup.clearTable(remediationConfigTableName, 'config');
    await DynamoDBTestSetup.clearTable(userAccountMappingTableName, 'userAccountMapping');
    await DynamoDBTestSetup.clearTable(notificationConfigTableName, 'notificationConfig');
    await DynamoDBTestSetup.clearTable(notificationBatchesTableName, 'notificationBatches');

    cognitoMock.reset();
    setupMetricsMocks();

    cognitoMock.on(AdminGetUserCommand).resolves({
      Username: 'admin-user@example.com',
      UserAttributes: [
        { Name: 'email', Value: 'admin-user@example.com' },
        { Name: 'custom:invitedBy', Value: 'system@example.com' },
      ],
      UserCreateDate: new Date(),
      UserStatus: 'CONFIRMED',
    });

    cognitoMock.on(AdminListGroupsForUserCommand).resolves({
      Groups: [{ GroupName: 'AdminGroup' }],
    });
  });

  describe('getFilters', () => {
    it('should return 200 with empty filters when no data exists', async () => {
      // ARRANGE
      const event = createMockEvent({
        httpMethod: 'GET',
        path: '/filters',
        headers: {
          'Content-Type': 'application/json',
          authorization: 'Bearer valid-token',
        },
        requestContext: {
          ...TEST_REQUEST_CONTEXT,
          authorizer: {
            claims: {
              'cognito:groups': ['AdminGroup'],
              username: 'admin-user@example.com',
            },
          },
        },
      });
      const context = createMockContext();

      // ACT
      const result = await getFilters(event, context);

      // ASSERT
      expect(result.statusCode).toBe(200);
      const body = JSON.parse(result.body);
      expect(body.filters).toEqual([]);
    });

    it('should return 200 with filters and all attributes when data exists', async () => {
      // ARRANGE
      await dynamoDBDocumentClient.send(
        new PutCommand({
          TableName: resourceFiltersTableName,
          Item: {
            filterId: '550e8400-e29b-41d4-a716-446655440000',
            name: 'Production Accounts',
            accountIds: new Set(['123456789012', '987654321098']),
            organizationalUnits: new Set(['ou-abcd-12345678']),
            tags: [{ key: 'Environment', value: 'Production' }],
            arnPatterns: new Set(['arn:aws:s3:::prod-*']),
            version: 1,
            createdAt: '2024-01-01T00:00:00Z',
            createdBy: 'admin-user@example.com',
            lastModified: '2024-01-01T00:00:00Z',
            modifiedBy: 'admin-user@example.com',
          },
        }),
      );

      const event = createMockEvent({
        httpMethod: 'GET',
        path: '/filters',
        headers: {
          'Content-Type': 'application/json',
          authorization: 'Bearer valid-token',
        },
        requestContext: {
          ...TEST_REQUEST_CONTEXT,
          authorizer: {
            claims: {
              'cognito:groups': ['AdminGroup'],
              username: 'admin-user@example.com',
            },
          },
        },
      });
      const context = createMockContext();

      // ACT
      const result = await getFilters(event, context);

      // ASSERT
      expect(result.statusCode).toBe(200);
      const body = JSON.parse(result.body);
      expect(body.filters).toHaveLength(1);
      const filter = body.filters[0];
      expect(filter.filterId).toBe('550e8400-e29b-41d4-a716-446655440000');
      expect(filter.name).toBe('Production Accounts');
      expect(filter.accountIds.sort()).toEqual(['123456789012', '987654321098']);
      expect(filter.organizationalUnits).toEqual(['ou-abcd-12345678']);
      expect(filter.tags).toEqual([{ key: 'Environment', value: 'Production' }]);
      expect(filter.arnPatterns).toEqual(['arn:aws:s3:::prod-*']);
      expect(filter.version).toBe(1);
      expect(filter.createdAt).toBe('2024-01-01T00:00:00Z');
      expect(filter.createdBy).toBe('admin-user@example.com');
      expect(filter.lastModified).toBe('2024-01-01T00:00:00Z');
      expect(filter.modifiedBy).toBe('admin-user@example.com');
    });

    it('should allow AccountOperator to read filters', async () => {
      // ARRANGE
      await dynamoDBDocumentClient.send(
        new PutCommand({
          TableName: resourceFiltersTableName,
          Item: {
            filterId: '550e8400-e29b-41d4-a716-446655440001',
            name: 'Test Filter',
            version: 1,
            createdAt: '2024-01-01T00:00:00Z',
            createdBy: 'admin@example.com',
            lastModified: '2024-01-01T00:00:00Z',
            modifiedBy: 'admin@example.com',
          },
        }),
      );

      cognitoMock.reset();
      cognitoMock.on(AdminGetUserCommand).resolves({
        Username: 'operator@example.com',
        UserAttributes: [
          { Name: 'email', Value: 'operator@example.com' },
          { Name: 'custom:invitedBy', Value: 'admin@example.com' },
        ],
        UserCreateDate: new Date(),
        UserStatus: 'CONFIRMED',
      });
      cognitoMock.on(AdminListGroupsForUserCommand).resolves({
        Groups: [{ GroupName: 'AccountOperatorGroup' }],
      });
      await dynamoDBDocumentClient.send(
        new PutCommand({
          TableName: userAccountMappingTableName,
          Item: {
            userId: 'operator@example.com',
            accountIds: ['123456789012'],
          },
        }),
      );

      const event = createMockEvent({
        httpMethod: 'GET',
        path: '/filters',
        headers: {
          'Content-Type': 'application/json',
          authorization: 'Bearer valid-token',
        },
        requestContext: {
          ...TEST_REQUEST_CONTEXT,
          authorizer: {
            claims: {
              'cognito:groups': ['AccountOperatorGroup'],
              username: 'operator@example.com',
            },
          },
        },
      });
      const context = createMockContext();

      // ACT
      const result = await getFilters(event, context);

      // ASSERT
      expect(result.statusCode).toBe(200);
      const body = JSON.parse(result.body);
      expect(body.filters).toHaveLength(1);
    });

    it('should reject unauthorized users', async () => {
      // ARRANGE
      const event = createMockEvent({
        httpMethod: 'GET',
        path: '/filters',
        headers: {
          'Content-Type': 'application/json',
          authorization: 'Bearer valid-token',
        },
        requestContext: {
          ...TEST_REQUEST_CONTEXT,
          authorizer: {
            claims: {
              'cognito:groups': ['UnknownGroup'],
              username: 'unknown-user@example.com',
            },
          },
        },
      });
      const context = createMockContext();

      // ACT & ASSERT
      await expect(getFilters(event, context)).rejects.toThrow('You are not authorized to access this endpoint.');
    });

    it('should allow DelegatedAdmin to read filters', async () => {
      // ARRANGE
      await dynamoDBDocumentClient.send(
        new PutCommand({
          TableName: resourceFiltersTableName,
          Item: {
            filterId: '550e8400-e29b-41d4-a716-446655440003',
            name: 'Test Filter',
            version: 1,
            createdAt: '2024-01-01T00:00:00Z',
            createdBy: 'admin@example.com',
            lastModified: '2024-01-01T00:00:00Z',
            modifiedBy: 'admin@example.com',
          },
        }),
      );

      cognitoMock.reset();
      cognitoMock.on(AdminGetUserCommand).resolves({
        Username: 'delegated@example.com',
        UserAttributes: [
          { Name: 'email', Value: 'delegated@example.com' },
          { Name: 'custom:invitedBy', Value: 'admin@example.com' },
        ],
        UserCreateDate: new Date(),
        UserStatus: 'CONFIRMED',
      });
      cognitoMock.on(AdminListGroupsForUserCommand).resolves({
        Groups: [{ GroupName: 'DelegatedAdminGroup' }],
      });

      const event = createMockEvent({
        httpMethod: 'GET',
        path: '/filters',
        headers: {
          'Content-Type': 'application/json',
          authorization: 'Bearer valid-token',
        },
        requestContext: {
          ...TEST_REQUEST_CONTEXT,
          authorizer: {
            claims: {
              'cognito:groups': ['DelegatedAdminGroup'],
              username: 'delegated@example.com',
            },
          },
        },
      });
      const context = createMockContext();

      // ACT
      const result = await getFilters(event, context);

      // ASSERT
      expect(result.statusCode).toBe(200);
      const body = JSON.parse(result.body);
      expect(body.filters).toHaveLength(1);
    });

    it('should return filters with default values when optional Set fields are missing', async () => {
      // ARRANGE
      const filterItem = {
        filterId: '550e8400-e29b-41d4-a716-446655440002',
        name: 'Minimal Filter',
        version: 1,
        createdAt: '2024-06-01T00:00:00Z',
        createdBy: 'admin@example.com',
        lastModified: '2024-06-01T00:00:00Z',
        modifiedBy: 'admin@example.com',
      };

      await dynamoDBDocumentClient.send(
        new PutCommand({
          TableName: resourceFiltersTableName,
          Item: filterItem,
        }),
      );

      const event = createMockEvent({
        httpMethod: 'GET',
        path: '/filters',
        headers: {
          'Content-Type': 'application/json',
          authorization: 'Bearer valid-token',
        },
        requestContext: {
          ...TEST_REQUEST_CONTEXT,
          authorizer: {
            claims: {
              'cognito:groups': ['AdminGroup'],
              username: 'admin-user@example.com',
            },
          },
        },
      });
      const context = createMockContext();

      // ACT
      const result = await getFilters(event, context);

      // ASSERT
      expect(result.statusCode).toBe(200);
      const body = JSON.parse(result.body);
      expect(body.filters).toHaveLength(1);
      expect(body.filters[0]).toEqual({
        filterId: '550e8400-e29b-41d4-a716-446655440002',
        name: 'Minimal Filter',
        accountIds: [],
        organizationalUnits: [],
        tags: [],
        arnPatterns: [],
        version: 1,
        createdAt: '2024-06-01T00:00:00Z',
        createdBy: 'admin@example.com',
        lastModified: '2024-06-01T00:00:00Z',
        modifiedBy: 'admin@example.com',
      });
    });
  });

  describe('updateFilter', () => {
    it('should return 200 and update filter with all fields', async () => {
      // ARRANGE
      await dynamoDBDocumentClient.send(
        new PutCommand({ TableName: resourceFiltersTableName, Item: { ...SEED_FILTER } }),
      );
      const event = createUpdateEvent(FILTER_ID, VALID_UPDATE_BODY);
      const context = createMockContext();

      // ACT
      const result = await updateFilter(event, context);

      // ASSERT
      expect(result.statusCode).toBe(200);
      const body = JSON.parse(result.body);
      expect(body.name).toBe('Updated Filter Name');
      expect(body.accountIds.sort()).toEqual(['123456789012', '987654321098']);
      expect(body.organizationalUnits).toEqual(['ou-abcd-12345678']);
      expect(body.tags).toEqual([{ key: 'Env', value: 'Staging' }]);
      expect(body.arnPatterns).toEqual(['arn:aws:s3:::staging-*']);
      expect(body.version).toBe(2);
      expect(body.modifiedBy).toBe('admin-user@example.com');
      expect(body.lastModified).toBeDefined();

      const dbItem = await dynamoDBDocumentClient.send(
        new GetCommand({ TableName: resourceFiltersTableName, Key: { filterId: FILTER_ID } }),
      );
      expect(dbItem.Item?.version).toBe(2);
      expect(dbItem.Item?.name).toBe('Updated Filter Name');
    });

    it('enqueues a filterChange reconciliation task for each enforcing config that applies the filter', async () => {
      // ARRANGE
      await dynamoDBDocumentClient.send(
        new PutCommand({ TableName: resourceFiltersTableName, Item: { ...SEED_FILTER } }),
      );
      await seedNotificationConfig(dynamoDBDocumentClient);
      const event = createUpdateEvent(FILTER_ID, VALID_UPDATE_BODY);
      const context = createMockContext();

      // ACT
      const result = await updateFilter(event, context);

      // ASSERT
      expect(result.statusCode).toBe(200);
      const tasks = await readReconciliationTasks(dynamoDBDocumentClient);
      expect(tasks).toHaveLength(1);
      expect(tasks[0].taskType).toBe('filterChange');
      expect((tasks[0].oldConfig as Record<string, unknown>).configId).toBe(ENFORCING_CONFIG_ID);
      expect((tasks[0].newConfig as Record<string, unknown>).configId).toBe(ENFORCING_CONFIG_ID);
    });

    it('does not enqueue a reconciliation task for a config that is not deadline-enforcing', async () => {
      // ARRANGE - config applies the filter but enforcement is off
      await dynamoDBDocumentClient.send(
        new PutCommand({ TableName: resourceFiltersTableName, Item: { ...SEED_FILTER } }),
      );
      await seedNotificationConfig(dynamoDBDocumentClient, { contentOptions: { enforceDeadline: false } });
      const event = createUpdateEvent(FILTER_ID, VALID_UPDATE_BODY);
      const context = createMockContext();

      // ACT
      const result = await updateFilter(event, context);

      // ASSERT
      expect(result.statusCode).toBe(200);
      expect(await readReconciliationTasks(dynamoDBDocumentClient)).toHaveLength(0);
    });

    it('does not enqueue a reconciliation task when no config applies the filter', async () => {
      // ARRANGE - enforcing config references a different filter
      await dynamoDBDocumentClient.send(
        new PutCommand({ TableName: resourceFiltersTableName, Item: { ...SEED_FILTER } }),
      );
      await seedNotificationConfig(dynamoDBDocumentClient, { resourceFilterIds: ['some-other-filter'] });
      const event = createUpdateEvent(FILTER_ID, VALID_UPDATE_BODY);
      const context = createMockContext();

      // ACT
      const result = await updateFilter(event, context);

      // ASSERT
      expect(result.statusCode).toBe(200);
      expect(await readReconciliationTasks(dynamoDBDocumentClient)).toHaveLength(0);
    });

    it('still updates the filter when no enforcing config applies it', async () => {
      // ARRANGE
      await dynamoDBDocumentClient.send(
        new PutCommand({ TableName: resourceFiltersTableName, Item: { ...SEED_FILTER } }),
      );
      const event = createUpdateEvent(FILTER_ID, VALID_UPDATE_BODY);
      const context = createMockContext();

      // ACT
      const result = await updateFilter(event, context);

      // ASSERT - update succeeds and no tasks are written
      expect(result.statusCode).toBe(200);
      expect(await readReconciliationTasks(dynamoDBDocumentClient)).toHaveLength(0);
    });

    it('should return 409 Conflict when version does not match (optimistic locking)', async () => {
      // ARRANGE
      await dynamoDBDocumentClient.send(
        new PutCommand({ TableName: resourceFiltersTableName, Item: { ...SEED_FILTER, version: 3 } }),
      );
      const event = createUpdateEvent(FILTER_ID, { ...VALID_UPDATE_BODY, version: 1 });
      const context = createMockContext();

      // ACT & ASSERT
      await expect(updateFilter(event, context)).rejects.toThrow('Data was modified by another user, please refresh');
    });

    it('should return 409 Conflict when filter does not exist', async () => {
      // ARRANGE
      const event = createUpdateEvent('550e8400-e29b-41d4-a716-446655440099', VALID_UPDATE_BODY);
      const context = createMockContext();

      // ACT & ASSERT
      await expect(updateFilter(event, context)).rejects.toThrow('Data was modified by another user, please refresh');
    });

    it('should return 400 for invalid account ID, OU, ARN, empty criteria, long name, and empty name', async () => {
      // ARRANGE
      await dynamoDBDocumentClient.send(
        new PutCommand({ TableName: resourceFiltersTableName, Item: { ...SEED_FILTER } }),
      );
      const context = createMockContext();

      const invalidCases = [
        { ...VALID_UPDATE_BODY, accountIds: ['not-12-digits'] },
        { ...VALID_UPDATE_BODY, organizationalUnits: ['invalid-ou'] },
        { ...VALID_UPDATE_BODY, arnPatterns: ['not-an-arn'] },
        { name: 'Empty', accountIds: [], organizationalUnits: [], tags: [], arnPatterns: [], version: 1 },
        { ...VALID_UPDATE_BODY, name: 'x'.repeat(101) },
        { ...VALID_UPDATE_BODY, name: '' },
      ];

      // ACT & ASSERT
      for (const invalidBody of invalidCases) {
        const event = createUpdateEvent(FILTER_ID, invalidBody);
        await expect(updateFilter(event, context)).rejects.toThrow('Invalid filter update request');
      }
    });

    it('should return 400 when filter name conflicts with another filter', async () => {
      // ARRANGE
      await dynamoDBDocumentClient.send(
        new PutCommand({ TableName: resourceFiltersTableName, Item: { ...SEED_FILTER } }),
      );
      await dynamoDBDocumentClient.send(
        new PutCommand({
          TableName: resourceFiltersTableName,
          Item: {
            filterId: '550e8400-e29b-41d4-a716-446655440001',
            name: 'Taken Name',
            accountIds: new Set(['111111111111']),
            version: 1,
            createdAt: '2024-01-01T00:00:00Z',
            createdBy: 'admin@example.com',
            lastModified: '2024-01-01T00:00:00Z',
            modifiedBy: 'admin@example.com',
          },
        }),
      );
      const event = createUpdateEvent(FILTER_ID, { ...VALID_UPDATE_BODY, name: 'Taken Name' });
      const context = createMockContext();

      // ACT & ASSERT
      await expect(updateFilter(event, context)).rejects.toThrow('A filter with the name "Taken Name" already exists');
    });

    it('should allow updating a filter while keeping the same name', async () => {
      // ARRANGE
      await dynamoDBDocumentClient.send(
        new PutCommand({ TableName: resourceFiltersTableName, Item: { ...SEED_FILTER } }),
      );
      const event = createUpdateEvent(FILTER_ID, { ...VALID_UPDATE_BODY, name: 'Production Accounts' });
      const context = createMockContext();

      // ACT
      const result = await updateFilter(event, context);

      // ASSERT
      expect(result.statusCode).toBe(200);
      expect(JSON.parse(result.body).name).toBe('Production Accounts');
    });

    it('should reject AccountOperator and allow DelegatedAdmin for update operations', async () => {
      // ARRANGE
      await dynamoDBDocumentClient.send(
        new PutCommand({ TableName: resourceFiltersTableName, Item: { ...SEED_FILTER } }),
      );
      const context = createMockContext();

      // AccountOperator should be rejected
      cognitoMock.reset();
      cognitoMock.on(AdminGetUserCommand).resolves({
        Username: 'operator@example.com',
        UserAttributes: [
          { Name: 'email', Value: 'operator@example.com' },
          { Name: 'custom:invitedBy', Value: 'admin@example.com' },
        ],
        UserCreateDate: new Date(),
        UserStatus: 'CONFIRMED',
      });
      cognitoMock.on(AdminListGroupsForUserCommand).resolves({
        Groups: [{ GroupName: 'AccountOperatorGroup' }],
      });
      await dynamoDBDocumentClient.send(
        new PutCommand({
          TableName: userAccountMappingTableName,
          Item: { userId: 'operator@example.com', accountIds: ['123456789012'] },
        }),
      );

      const operatorEvent = createUpdateEvent(FILTER_ID, VALID_UPDATE_BODY, 'operator@example.com', [
        'AccountOperatorGroup',
      ]);
      await expect(updateFilter(operatorEvent, context)).rejects.toThrow(
        'You are not authorized to access this endpoint.',
      );

      // DelegatedAdmin should succeed
      cognitoMock.reset();
      cognitoMock.on(AdminGetUserCommand).resolves({
        Username: 'delegated@example.com',
        UserAttributes: [
          { Name: 'email', Value: 'delegated@example.com' },
          { Name: 'custom:invitedBy', Value: 'admin@example.com' },
        ],
        UserCreateDate: new Date(),
        UserStatus: 'CONFIRMED',
      });
      cognitoMock.on(AdminListGroupsForUserCommand).resolves({
        Groups: [{ GroupName: 'DelegatedAdminGroup' }],
      });

      const delegatedEvent = createUpdateEvent(FILTER_ID, VALID_UPDATE_BODY, 'delegated@example.com', [
        'DelegatedAdminGroup',
      ]);
      const result = await updateFilter(delegatedEvent, context);

      // ASSERT
      expect(result.statusCode).toBe(200);
      expect(JSON.parse(result.body).modifiedBy).toBe('delegated@example.com');
    });

    it('should handle removing optional Set fields by setting them to empty arrays', async () => {
      // ARRANGE
      await dynamoDBDocumentClient.send(
        new PutCommand({ TableName: resourceFiltersTableName, Item: { ...SEED_FILTER } }),
      );
      const event = createUpdateEvent(FILTER_ID, {
        name: 'Tags Only Filter',
        accountIds: [],
        organizationalUnits: [],
        tags: [{ key: 'Team', value: 'Security' }],
        arnPatterns: [],
        version: 1,
      });
      const context = createMockContext();

      // ACT
      const result = await updateFilter(event, context);

      // ASSERT
      expect(result.statusCode).toBe(200);
      const body = JSON.parse(result.body);
      expect(body.accountIds).toEqual([]);
      expect(body.organizationalUnits).toEqual([]);
      expect(body.arnPatterns).toEqual([]);
      expect(body.tags).toEqual([{ key: 'Team', value: 'Security' }]);
    });
  });

  describe('createFilter', () => {
    function createCreateEvent(
      body: Record<string, unknown>,
      username = 'admin-user@example.com',
      groups: string[] = ['AdminGroup'],
    ) {
      return createMockEvent({
        httpMethod: 'POST',
        path: '/filters',
        body: JSON.stringify(body),
        headers: {
          'Content-Type': 'application/json',
          authorization: 'Bearer valid-token',
        },
        requestContext: {
          ...TEST_REQUEST_CONTEXT,
          authorizer: {
            claims: {
              'cognito:groups': groups,
              username,
            },
          },
        },
      });
    }

    const VALID_CREATE_BODY = {
      name: 'New Production Filter',
      accountIds: ['123456789012'],
      organizationalUnits: ['ou-abcd-12345678'],
      tags: [{ key: 'Environment', value: 'Production' }],
      arnPatterns: ['arn:aws:s3:::prod-*'],
    };

    it('should return 201 and create a filter with all fields', async () => {
      // ARRANGE
      const event = createCreateEvent(VALID_CREATE_BODY);
      const context = createMockContext();

      // ACT
      const result = await createFilter(event, context);

      // ASSERT
      expect(result.statusCode).toBe(201);
      const body = JSON.parse(result.body);
      expect(body.filterId).toBeDefined();
      expect(body.name).toBe('New Production Filter');
      expect(body.accountIds).toEqual(['123456789012']);
      expect(body.organizationalUnits).toEqual(['ou-abcd-12345678']);
      expect(body.tags).toEqual([{ key: 'Environment', value: 'Production' }]);
      expect(body.arnPatterns).toEqual(['arn:aws:s3:::prod-*']);
      expect(body.version).toBe(1);
      expect(body.createdBy).toBe('admin-user@example.com');
      expect(body.modifiedBy).toBe('admin-user@example.com');
      expect(body.createdAt).toBeDefined();
      expect(body.lastModified).toBe(body.createdAt);

      const scanResult = await dynamoDBDocumentClient.send(new ScanCommand({ TableName: resourceFiltersTableName }));
      expect(scanResult.Items).toHaveLength(1);
      expect(scanResult.Items![0].filterId).toBe(body.filterId);
    });

    it('should create a filter with only accountIds', async () => {
      // ARRANGE
      const event = createCreateEvent({
        name: 'Account Only Filter',
        accountIds: ['111111111111'],
        organizationalUnits: [],
        tags: [],
        arnPatterns: [],
      });
      const context = createMockContext();

      // ACT
      const result = await createFilter(event, context);

      // ASSERT
      expect(result.statusCode).toBe(201);
      const body = JSON.parse(result.body);
      expect(body.accountIds).toEqual(['111111111111']);
      expect(body.organizationalUnits).toEqual([]);
      expect(body.tags).toEqual([]);
      expect(body.arnPatterns).toEqual([]);
    });

    it('should create a filter with only tags', async () => {
      // ARRANGE
      const event = createCreateEvent({
        name: 'Tags Only Filter',
        accountIds: [],
        organizationalUnits: [],
        tags: [{ key: 'Team', value: 'Security' }],
        arnPatterns: [],
      });
      const context = createMockContext();

      // ACT
      const result = await createFilter(event, context);

      // ASSERT
      expect(result.statusCode).toBe(201);
      const body = JSON.parse(result.body);
      expect(body.tags).toEqual([{ key: 'Team', value: 'Security' }]);
    });

    it('should reject creation with no filter criteria', async () => {
      // ARRANGE
      const event = createCreateEvent({
        name: 'Empty Filter',
        accountIds: [],
        organizationalUnits: [],
        tags: [],
        arnPatterns: [],
      });
      const context = createMockContext();

      // ACT & ASSERT
      await expect(createFilter(event, context)).rejects.toThrow('Invalid filter creation request');
    });

    it('should reject creation with invalid account ID', async () => {
      // ARRANGE
      const event = createCreateEvent({
        ...VALID_CREATE_BODY,
        accountIds: ['not-12-digits'],
      });
      const context = createMockContext();

      // ACT & ASSERT
      await expect(createFilter(event, context)).rejects.toThrow('Invalid filter creation request');
    });

    it('should reject creation with invalid OU identifier', async () => {
      // ARRANGE
      const event = createCreateEvent({
        ...VALID_CREATE_BODY,
        organizationalUnits: ['invalid-ou'],
      });
      const context = createMockContext();

      // ACT & ASSERT
      await expect(createFilter(event, context)).rejects.toThrow('Invalid filter creation request');
    });

    it('should reject creation with invalid ARN pattern', async () => {
      // ARRANGE
      const event = createCreateEvent({
        ...VALID_CREATE_BODY,
        arnPatterns: ['not-an-arn'],
      });
      const context = createMockContext();

      // ACT & ASSERT
      await expect(createFilter(event, context)).rejects.toThrow('Invalid filter creation request');
    });

    it('should reject creation with empty tag key', async () => {
      // ARRANGE
      const event = createCreateEvent({
        ...VALID_CREATE_BODY,
        tags: [{ key: '', value: 'Production' }],
      });
      const context = createMockContext();

      // ACT & ASSERT
      await expect(createFilter(event, context)).rejects.toThrow('Invalid filter creation request');
    });

    it('should reject creation with empty tag value', async () => {
      // ARRANGE
      const event = createCreateEvent({
        ...VALID_CREATE_BODY,
        tags: [{ key: 'Env', value: '' }],
      });
      const context = createMockContext();

      // ACT & ASSERT
      await expect(createFilter(event, context)).rejects.toThrow('Invalid filter creation request');
    });

    it('should allow creation with duplicate tag keys', async () => {
      // ARRANGE
      const event = createCreateEvent({
        ...VALID_CREATE_BODY,
        tags: [
          { key: 'Env', value: 'Production' },
          { key: 'Env', value: 'Staging' },
        ],
      });
      const context = createMockContext();

      // ACT
      const result = await createFilter(event, context);

      // ASSERT
      expect(result.statusCode).toBe(201);
      const body = JSON.parse(result.body);
      expect(body.tags).toEqual([
        { key: 'Env', value: 'Production' },
        { key: 'Env', value: 'Staging' },
      ]);
    });

    it('should reject creation with name exceeding 100 characters', async () => {
      // ARRANGE
      const event = createCreateEvent({
        ...VALID_CREATE_BODY,
        name: 'x'.repeat(101),
      });
      const context = createMockContext();

      // ACT & ASSERT
      await expect(createFilter(event, context)).rejects.toThrow('Invalid filter creation request');
    });

    it('should reject creation with empty name', async () => {
      // ARRANGE
      const event = createCreateEvent({
        ...VALID_CREATE_BODY,
        name: '',
      });
      const context = createMockContext();

      // ACT & ASSERT
      await expect(createFilter(event, context)).rejects.toThrow('Invalid filter creation request');
    });

    it('should reject creation when filter name already exists', async () => {
      // ARRANGE
      await dynamoDBDocumentClient.send(
        new PutCommand({
          TableName: resourceFiltersTableName,
          Item: {
            filterId: '550e8400-e29b-41d4-a716-446655440099',
            name: 'New Production Filter',
            accountIds: new Set(['111111111111']),
            version: 1,
            createdAt: '2024-01-01T00:00:00Z',
            createdBy: 'admin@example.com',
            lastModified: '2024-01-01T00:00:00Z',
            modifiedBy: 'admin@example.com',
          },
        }),
      );
      const event = createCreateEvent(VALID_CREATE_BODY);
      const context = createMockContext();

      // ACT & ASSERT
      await expect(createFilter(event, context)).rejects.toThrow(
        'A filter with the name "New Production Filter" already exists',
      );
    });

    it('should reject AccountOperator from creating filters', async () => {
      // ARRANGE
      cognitoMock.reset();
      cognitoMock.on(AdminGetUserCommand).resolves({
        Username: 'operator@example.com',
        UserAttributes: [
          { Name: 'email', Value: 'operator@example.com' },
          { Name: 'custom:invitedBy', Value: 'admin@example.com' },
        ],
        UserCreateDate: new Date(),
        UserStatus: 'CONFIRMED',
      });
      cognitoMock.on(AdminListGroupsForUserCommand).resolves({
        Groups: [{ GroupName: 'AccountOperatorGroup' }],
      });
      await dynamoDBDocumentClient.send(
        new PutCommand({
          TableName: userAccountMappingTableName,
          Item: { userId: 'operator@example.com', accountIds: ['123456789012'] },
        }),
      );

      const event = createCreateEvent(VALID_CREATE_BODY, 'operator@example.com', ['AccountOperatorGroup']);
      const context = createMockContext();

      // ACT & ASSERT
      await expect(createFilter(event, context)).rejects.toThrow('You are not authorized to access this endpoint.');
    });

    it('should allow DelegatedAdmin to create filters', async () => {
      // ARRANGE
      cognitoMock.reset();
      cognitoMock.on(AdminGetUserCommand).resolves({
        Username: 'delegated@example.com',
        UserAttributes: [
          { Name: 'email', Value: 'delegated@example.com' },
          { Name: 'custom:invitedBy', Value: 'admin@example.com' },
        ],
        UserCreateDate: new Date(),
        UserStatus: 'CONFIRMED',
      });
      cognitoMock.on(AdminListGroupsForUserCommand).resolves({
        Groups: [{ GroupName: 'DelegatedAdminGroup' }],
      });

      const event = createCreateEvent(VALID_CREATE_BODY, 'delegated@example.com', ['DelegatedAdminGroup']);
      const context = createMockContext();

      // ACT
      const result = await createFilter(event, context);

      // ASSERT
      expect(result.statusCode).toBe(201);
      expect(JSON.parse(result.body).createdBy).toBe('delegated@example.com');
    });
  });

  describe('deleteFilter', () => {
    function createDeleteEvent(
      filterId: string,
      username = 'admin-user@example.com',
      groups: string[] = ['AdminGroup'],
    ) {
      return createMockEvent({
        httpMethod: 'DELETE',
        path: `/filters/${filterId}`,
        pathParameters: { filterId },
        headers: {
          'Content-Type': 'application/json',
          authorization: 'Bearer valid-token',
        },
        requestContext: {
          ...TEST_REQUEST_CONTEXT,
          authorizer: {
            claims: {
              'cognito:groups': groups,
              username,
            },
          },
        },
      });
    }

    it('should return 200 and delete a filter with no associated controls', async () => {
      // ARRANGE
      await dynamoDBDocumentClient.send(
        new PutCommand({ TableName: resourceFiltersTableName, Item: { ...SEED_FILTER } }),
      );
      const event = createDeleteEvent(FILTER_ID);
      const context = createMockContext();

      // ACT
      const result = await deleteFilter(event, context);

      // ASSERT
      expect(result.statusCode).toBe(200);
      const body = JSON.parse(result.body);
      expect(body.message).toBe('Filter deleted successfully');
      expect(body.affectedControlIds).toEqual([]);

      const scanResult = await dynamoDBDocumentClient.send(new ScanCommand({ TableName: resourceFiltersTableName }));
      expect(scanResult.Items).toHaveLength(0);
    });

    it('should return 200 and remove filter from associated controls before deleting', async () => {
      // ARRANGE
      await dynamoDBDocumentClient.send(
        new PutCommand({ TableName: resourceFiltersTableName, Item: { ...SEED_FILTER } }),
      );
      await dynamoDBDocumentClient.send(
        new PutCommand({
          TableName: remediationConfigTableName,
          Item: {
            controlId: 'S3.1',
            automatedRemediationEnabled: true,
            filters: new Set([FILTER_ID]),
            filterMode: 'include',
            version: 1,
          },
        }),
      );
      const event = createDeleteEvent(FILTER_ID);
      const context = createMockContext();

      // ACT
      const result = await deleteFilter(event, context);

      // ASSERT
      expect(result.statusCode).toBe(200);
      const body = JSON.parse(result.body);
      expect(body.message).toBe('Filter deleted successfully');
      expect(body.affectedControlIds).toEqual(['S3.1']);

      const scanResult = await dynamoDBDocumentClient.send(new ScanCommand({ TableName: resourceFiltersTableName }));
      expect(scanResult.Items).toHaveLength(0);

      const controlItem = await dynamoDBDocumentClient.send(
        new GetCommand({ TableName: remediationConfigTableName, Key: { controlId: 'S3.1' } }),
      );
      expect(controlItem.Item?.filters).toBeUndefined();
    });

    it('should return 200 when deleting a filter associated with multiple controls', async () => {
      // ARRANGE
      await dynamoDBDocumentClient.send(
        new PutCommand({ TableName: resourceFiltersTableName, Item: { ...SEED_FILTER } }),
      );
      await dynamoDBDocumentClient.send(
        new PutCommand({
          TableName: remediationConfigTableName,
          Item: {
            controlId: 'S3.1',
            automatedRemediationEnabled: true,
            filters: new Set([FILTER_ID, '00000000-0000-0000-0000-000000000001']),
            filterMode: 'include',
            version: 1,
          },
        }),
      );
      await dynamoDBDocumentClient.send(
        new PutCommand({
          TableName: remediationConfigTableName,
          Item: {
            controlId: 'EC2.1',
            automatedRemediationEnabled: false,
            filters: new Set([FILTER_ID]),
            filterMode: 'exclude',
            version: 1,
          },
        }),
      );
      const event = createDeleteEvent(FILTER_ID);
      const context = createMockContext();

      // ACT
      const result = await deleteFilter(event, context);

      // ASSERT
      expect(result.statusCode).toBe(200);
      const body = JSON.parse(result.body);
      expect(body.message).toBe('Filter deleted successfully');
      expect(body.affectedControlIds.sort()).toEqual(['EC2.1', 'S3.1']);

      const s3Control = await dynamoDBDocumentClient.send(
        new GetCommand({ TableName: remediationConfigTableName, Key: { controlId: 'S3.1' } }),
      );
      const remainingFilters = s3Control.Item?.filters;
      expect(remainingFilters).toBeDefined();
      expect(Array.from(remainingFilters as Set<string>)).toEqual(['00000000-0000-0000-0000-000000000001']);
    });

    it('should return 200 when deleting a non-existent filter (idempotent)', async () => {
      // ARRANGE
      const event = createDeleteEvent(FILTER_ID);
      const context = createMockContext();

      // ACT
      const result = await deleteFilter(event, context);

      // ASSERT
      expect(result.statusCode).toBe(200);
      const body = JSON.parse(result.body);
      expect(body.message).toBe('Filter deleted successfully');
      expect(body.affectedControlIds).toEqual([]);
    });

    it('should reject invalid UUID filterId', async () => {
      // ARRANGE
      const event = createDeleteEvent('not-a-uuid');
      const context = createMockContext();

      // ACT & ASSERT
      await expect(deleteFilter(event, context)).rejects.toThrow('filterId must be a valid UUID');
    });

    it('should reject missing filterId path parameter', async () => {
      // ARRANGE
      const event = createMockEvent({
        httpMethod: 'DELETE',
        path: '/filters/',
        pathParameters: null,
        headers: {
          'Content-Type': 'application/json',
          authorization: 'Bearer valid-token',
        },
        requestContext: {
          ...TEST_REQUEST_CONTEXT,
          authorizer: {
            claims: {
              'cognito:groups': ['AdminGroup'],
              username: 'admin-user@example.com',
            },
          },
        },
      });
      const context = createMockContext();

      // ACT & ASSERT
      await expect(deleteFilter(event, context)).rejects.toThrow('filterId must be a valid UUID');
    });

    it('should reject AccountOperator from deleting filters', async () => {
      // ARRANGE
      await dynamoDBDocumentClient.send(
        new PutCommand({ TableName: resourceFiltersTableName, Item: { ...SEED_FILTER } }),
      );
      cognitoMock.reset();
      cognitoMock.on(AdminGetUserCommand).resolves({
        Username: 'operator@example.com',
        UserAttributes: [
          { Name: 'email', Value: 'operator@example.com' },
          { Name: 'custom:invitedBy', Value: 'admin@example.com' },
        ],
        UserCreateDate: new Date(),
        UserStatus: 'CONFIRMED',
      });
      cognitoMock.on(AdminListGroupsForUserCommand).resolves({
        Groups: [{ GroupName: 'AccountOperatorGroup' }],
      });
      await dynamoDBDocumentClient.send(
        new PutCommand({
          TableName: userAccountMappingTableName,
          Item: { userId: 'operator@example.com', accountIds: ['123456789012'] },
        }),
      );

      const event = createDeleteEvent(FILTER_ID, 'operator@example.com', ['AccountOperatorGroup']);
      const context = createMockContext();

      // ACT & ASSERT
      await expect(deleteFilter(event, context)).rejects.toThrow('You are not authorized to access this endpoint.');

      const scanResult = await dynamoDBDocumentClient.send(new ScanCommand({ TableName: resourceFiltersTableName }));
      expect(scanResult.Items).toHaveLength(1);
    });

    it('should allow DelegatedAdmin to delete filters', async () => {
      // ARRANGE
      await dynamoDBDocumentClient.send(
        new PutCommand({ TableName: resourceFiltersTableName, Item: { ...SEED_FILTER } }),
      );
      cognitoMock.reset();
      cognitoMock.on(AdminGetUserCommand).resolves({
        Username: 'delegated@example.com',
        UserAttributes: [
          { Name: 'email', Value: 'delegated@example.com' },
          { Name: 'custom:invitedBy', Value: 'admin@example.com' },
        ],
        UserCreateDate: new Date(),
        UserStatus: 'CONFIRMED',
      });
      cognitoMock.on(AdminListGroupsForUserCommand).resolves({
        Groups: [{ GroupName: 'DelegatedAdminGroup' }],
      });

      const event = createDeleteEvent(FILTER_ID, 'delegated@example.com', ['DelegatedAdminGroup']);
      const context = createMockContext();

      // ACT
      const result = await deleteFilter(event, context);

      // ASSERT
      expect(result.statusCode).toBe(200);
      const body = JSON.parse(result.body);
      expect(body.message).toBe('Filter deleted successfully');

      const scanResult = await dynamoDBDocumentClient.send(new ScanCommand({ TableName: resourceFiltersTableName }));
      expect(scanResult.Items).toHaveLength(0);
    });

    it('should reject unauthorized users from deleting filters', async () => {
      // ARRANGE
      const event = createDeleteEvent(FILTER_ID, 'unknown@example.com', ['UnknownGroup']);
      const context = createMockContext();

      // ACT & ASSERT
      await expect(deleteFilter(event, context)).rejects.toThrow('You are not authorized to access this endpoint.');
    });

    it('should preserve other filters when deleting a filter from a control with multiple filters', async () => {
      // ARRANGE
      const otherFilterId = '00000000-0000-0000-0000-000000000002';
      await dynamoDBDocumentClient.send(
        new PutCommand({ TableName: resourceFiltersTableName, Item: { ...SEED_FILTER } }),
      );
      await dynamoDBDocumentClient.send(
        new PutCommand({
          TableName: remediationConfigTableName,
          Item: {
            controlId: 'S3.1',
            automatedRemediationEnabled: true,
            filters: new Set([FILTER_ID, otherFilterId]),
            filterMode: 'include',
            version: 1,
          },
        }),
      );

      const event = createDeleteEvent(FILTER_ID);
      const context = createMockContext();

      // ACT
      const result = await deleteFilter(event, context);

      // ASSERT
      expect(result.statusCode).toBe(200);
      const body = JSON.parse(result.body);
      expect(body.message).toBe('Filter deleted successfully');
      expect(body.affectedControlIds).toEqual(['S3.1']);

      // Verify filter was deleted
      const filterScanResult = await dynamoDBDocumentClient.send(
        new ScanCommand({ TableName: resourceFiltersTableName }),
      );
      expect(filterScanResult.Items).toHaveLength(0);

      // Verify control still has the other filter but not the deleted one
      const controlItem = await dynamoDBDocumentClient.send(
        new GetCommand({ TableName: remediationConfigTableName, Key: { controlId: 'S3.1' } }),
      );
      expect(controlItem.Item?.filters).toBeDefined();
      const remainingFilters = Array.from(controlItem.Item?.filters as Set<string>);
      expect(remainingFilters).toContain(otherFilterId);
      expect(remainingFilters).not.toContain(FILTER_ID);
    });

    it('should handle batch processing when deleting a filter associated with many controls', async () => {
      // ARRANGE
      await dynamoDBDocumentClient.send(
        new PutCommand({ TableName: resourceFiltersTableName, Item: { ...SEED_FILTER } }),
      );

      // Create 5 controls that reference the filter to verify batch processing works
      // (Testing with a smaller number since DynamoDB Local has the same transaction limits)
      const controlIds = ['S3.1', 'S3.2', 'EC2.1', 'EC2.2', 'IAM.1'];
      for (const controlId of controlIds) {
        await dynamoDBDocumentClient.send(
          new PutCommand({
            TableName: remediationConfigTableName,
            Item: {
              controlId,
              automatedRemediationEnabled: true,
              filters: new Set([FILTER_ID]),
              filterMode: 'include',
              version: 1,
            },
          }),
        );
      }

      const event = createDeleteEvent(FILTER_ID);
      const context = createMockContext();

      // ACT
      const result = await deleteFilter(event, context);

      // ASSERT
      expect(result.statusCode).toBe(200);
      const body = JSON.parse(result.body);
      expect(body.message).toBe('Filter deleted successfully');
      expect(body.affectedControlIds.sort()).toEqual(controlIds.sort());

      // Verify filter was deleted
      const filterScanResult = await dynamoDBDocumentClient.send(
        new ScanCommand({ TableName: resourceFiltersTableName }),
      );
      expect(filterScanResult.Items).toHaveLength(0);

      // Verify all controls had the filter removed
      for (const controlId of controlIds) {
        const controlItem = await dynamoDBDocumentClient.send(
          new GetCommand({ TableName: remediationConfigTableName, Key: { controlId } }),
        );
        expect(controlItem.Item?.filters).toBeUndefined();
      }
    });

    describe('notification-reference block rule', () => {
      it('should allow delete even when a notification configuration references the filter', async () => {
        // ARRANGE: seed one filter and one notification config that references it.
        const FILTER_ID = '11111111-2222-4333-a444-555555555555';
        await dynamoDBDocumentClient.send(
          new PutCommand({
            TableName: resourceFiltersTableName,
            Item: {
              filterId: FILTER_ID,
              name: 'referenced-filter',
              accountIds: ['123456789012'],
              organizationalUnits: [],
              tags: [],
              arnPatterns: [],
              version: 1,
              createdAt: '2024-01-01T00:00:00.000Z',
              createdBy: 'seed',
              lastModified: '2024-01-01T00:00:00.000Z',
              modifiedBy: 'seed',
            },
          }),
        );
        const configId = 'aaaaaaaa-0000-4000-8000-000000000001';
        await dynamoDBDocumentClient.send(
          new PutCommand({
            TableName: notificationConfigTableName,
            Item: {
              configId,
              name: 'Referencing Config',
              enabled: true,
              enabledType: 'finding',
              notificationType: 'finding',
              severityFilter: ['All'],
              controlIds: [],
              resourceFilterIds: [FILTER_ID],
              deliveryChannels: [
                {
                  type: 'email',
                  enabled: true,
                  recipients: [{ recipientType: 'custom', emailAddresses: ['a@example.com'] }],
                },
              ],
              batchWindow: { enabled: false },
              contentOptions: {
                includeManualRemediationLink: false,
                includeRemediationDeadline: false,
                includeIaCSnippet: false,
                includeEnableAutomationLink: false,
              },
              version: 1,
              createdAt: '2024-01-01T00:00:00.000Z',
              createdBy: 'seed',
            },
          }),
        );

        const event = createDeleteEvent(FILTER_ID);
        const context = createMockContext();

        // ACT & ASSERT — delete succeeds despite notification config reference
        const result = await deleteFilter(event, context);
        expect(result.statusCode).toBe(200);
        const body = JSON.parse(result.body);
        expect(body.message).toBe('Filter deleted successfully');

        // Filter was deleted.
        const filterScan = await dynamoDBDocumentClient.send(new ScanCommand({ TableName: resourceFiltersTableName }));
        expect(filterScan.Items).toHaveLength(0);
      });
    });
  });

  describe('createFilter - metrics', () => {
    it('should emit filter_created metric on successful filter creation', async () => {
      // ARRANGE
      const event = createMockEvent({
        httpMethod: 'POST',
        path: '/filters',
        body: JSON.stringify({
          name: 'Metrics Test Filter',
          accountIds: ['123456789012'],
          organizationalUnits: [],
          tags: [],
          arnPatterns: [],
        }),
        headers: {
          'Content-Type': 'application/json',
          authorization: 'Bearer valid-token',
        },
        requestContext: {
          ...TEST_REQUEST_CONTEXT,
          authorizer: {
            claims: {
              'cognito:groups': ['AdminGroup'],
              username: 'admin-user@example.com',
            },
          },
        },
      });
      const context = createMockContext();

      const metricsScope = createMetricsTestScope(/.*filter_created.*Metrics%20Test%20Filter.*/);

      // ACT
      const result = await createFilter(event, context);

      // ASSERT
      expect(result.statusCode).toBe(201);
      expect(metricsScope.isDone()).toBe(true);
    });
  });
});
