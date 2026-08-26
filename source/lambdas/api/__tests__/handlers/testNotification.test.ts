// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import {
  CognitoIdentityProviderClient,
  AdminGetUserCommand,
  AdminListGroupsForUserCommand,
} from '@aws-sdk/client-cognito-identity-provider';
import { SecretsManagerClient, GetSecretValueCommand } from '@aws-sdk/client-secrets-manager';
import { SNSClient, PublishCommand } from '@aws-sdk/client-sns';
import { mockClient } from 'aws-sdk-client-mock';
import { PutCommand } from '@aws-sdk/lib-dynamodb';
import { DynamoDBTestSetup } from '../../../common/__tests__/dynamodbSetup';
import {
  notificationConfigTableName,
  remediationConfigTableName,
  resourceFiltersTableName,
  userAccountMappingTableName,
} from '../../../common/__tests__/envSetup';
import { setupMetricsMocks, cleanupMetricsMocks } from '../../../common/__tests__/metricsMockSetup';
import { NotificationConfigurationItem, TestNotificationResult } from '@asr/data-models';
import { createNotificationConfiguration, testNotificationConfiguration } from '../../handlers/notifications';
import { createMockContext, createMockEvent, TEST_REQUEST_CONTEXT } from '../utils';
import { clearSecretsCache } from '../../../common/utils/secrets-utils';
import { resetChannelLambdaEnvironmentCache } from '../../../notification-channels/channelLambdaEnvironment';

const FIXED_DATE = new Date('2025-06-15T12:00:00.000Z');

let uuidCounter = 0;
const nextUUID = () => `11111111-2222-4333-a444-${String(++uuidCounter).padStart(12, '0')}`;

jest.mock('../../../common/utils/idGenerator', () => ({
  getIdGenerator: () => ({ randomUUID: () => nextUUID() }),
}));

jest.mock('../../../common/utils/clock', () => ({
  getClock: () => ({ now: () => FIXED_DATE }),
}));

// Isolate the admin activity notifier so creating a config in test setup does not add
// an extra SNS PublishCommand that would interfere with the test-notification assertions.
jest.mock('../../services/adminActivityNotifier', () => ({
  AdminActivityNotifier: jest.fn().mockImplementation(() => ({ notify: jest.fn().mockResolvedValue(undefined) })),
}));

const cognitoMock = mockClient(CognitoIdentityProviderClient);
const secretsManagerMock = mockClient(SecretsManagerClient);
const snsMock = mockClient(SNSClient);

const VALID_CREATE_BODY = {
  name: 'Test Config for Test Notification',
  enabled: true,
  notificationType: 'finding',
  severityFilter: ['Critical'],
  controlIds: ['S3.1'],
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

function createTestNotificationEvent(
  configId: string,
  options?: { body?: Record<string, unknown>; username?: string; groups?: string[] },
) {
  return createMockEvent({
    httpMethod: 'POST',
    path: `/notifications/${configId}/test`,
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

async function createConfig(name = VALID_CREATE_BODY.name): Promise<NotificationConfigurationItem> {
  const result = await createNotificationConfiguration(
    createPostEvent({ ...VALID_CREATE_BODY, name }),
    createMockContext(),
  );
  expect(result.statusCode).toBe(201);
  return JSON.parse(result.body) as NotificationConfigurationItem;
}

describe('POST /notifications/configurations/{id}/test', () => {
  beforeAll(async () => {
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
    cleanupMetricsMocks();
  });

  beforeEach(async () => {
    uuidCounter = 0;
    snsMock.reset();
    snsMock.on(PublishCommand).resolves({ MessageId: 'test-message-id' });
    secretsManagerMock.reset();
    clearSecretsCache();
    resetChannelLambdaEnvironmentCache();
    setupMetricsMocks();
    await DynamoDBTestSetup.clearTable(notificationConfigTableName, 'notificationConfig');
    await DynamoDBTestSetup.clearTable(remediationConfigTableName, 'config');
    await DynamoDBTestSetup.clearTable(resourceFiltersTableName, 'resourceFilters');
    await DynamoDBTestSetup.clearTable(userAccountMappingTableName, 'userAccountMapping');

    // Seed an operator with owned accounts so operator-created config tests can auto-scope.
    await DynamoDBTestSetup.getDocClient().send(
      new PutCommand({
        TableName: userAccountMappingTableName,
        Item: { userId: 'operator@example.com', accountIds: ['111111111111'] },
      }),
    );

    await DynamoDBTestSetup.getDocClient().send(
      new PutCommand({
        TableName: remediationConfigTableName,
        Item: {
          controlId: 'S3.1',
          description: 'Seeded for test notification tests',
          automatedRemediationEnabled: false,
          filters: [],
          filterMode: 'include',
          version: 1,
          lastModified: '2024-01-01T00:00:00.000Z',
          modifiedBy: 'seed',
        },
      }),
    );

    setupCognitoMock('admin@example.com', ['AdminGroup']);
  });

  it('should reject an operator sending a test for a configuration they did not create', async () => {
    // ARRANGE - config created by admin; edit authority is creator-based
    const created = await createConfig();
    setupCognitoMock('operator@example.com', ['AccountOperatorGroup']);
    const event = createTestNotificationEvent(created.configId, {
      username: 'operator@example.com',
      groups: ['AccountOperatorGroup'],
    });

    // ACT & ASSERT
    await expect(testNotificationConfiguration(event, createMockContext())).rejects.toThrow(
      'Account operators can only modify notification configurations they created',
    );
  });

  it('should allow an operator to send a test for a configuration they created', async () => {
    // ARRANGE - operator creates the config, then sends a test for it
    setupCognitoMock('operator@example.com', ['AccountOperatorGroup']);
    const createResult = await createNotificationConfiguration(
      createPostEvent(VALID_CREATE_BODY, 'operator@example.com', ['AccountOperatorGroup']),
      createMockContext(),
    );
    expect(createResult.statusCode).toBe(201);
    const created = JSON.parse(createResult.body) as NotificationConfigurationItem;
    setupCognitoMock('operator@example.com', ['AccountOperatorGroup']);
    const event = createTestNotificationEvent(created.configId, {
      username: 'operator@example.com',
      groups: ['AccountOperatorGroup'],
    });

    // ACT
    const response = await testNotificationConfiguration(event, createMockContext());

    // ASSERT
    expect(response.statusCode).toBe(200);
    expect((JSON.parse(response.body) as TestNotificationResult).success).toBe(true);
  });

  it('should return 400 for invalid UUID path parameter', async () => {
    // ARRANGE
    const event = createTestNotificationEvent('not-a-valid-uuid');

    // ACT & ASSERT
    await expect(testNotificationConfiguration(event, createMockContext())).rejects.toThrow('id must be a valid UUID');
  });

  it('should return 404 when configuration does not exist', async () => {
    // ARRANGE
    const nonExistentId = 'aaaaaaaa-bbbb-4ccc-addd-eeeeeeeeeeee';
    const event = createTestNotificationEvent(nonExistentId);

    // ACT & ASSERT
    await expect(testNotificationConfiguration(event, createMockContext())).rejects.toThrow(
      `Configuration ${nonExistentId} not found`,
    );
  });

  it('should return 200 with per-channel results for a valid request', async () => {
    // ARRANGE
    const created = await createConfig();
    const event = createTestNotificationEvent(created.configId);

    // ACT
    const response = await testNotificationConfiguration(event, createMockContext());

    // ASSERT
    expect(response.statusCode).toBe(200);
    const body = JSON.parse(response.body) as TestNotificationResult;
    expect(body.success).toBe(true);
    expect(body.configId).toBe(created.configId);
    expect(body.configName).toBe(created.name);
    expect(body.results.email.status).toBe('success');
    expect(snsMock.commandCalls(PublishCommand).length).toBeGreaterThanOrEqual(1);
    const publishCall = snsMock.commandCalls(PublishCommand)[0].args[0].input;
    expect(publishCall.TopicArn).toContain(`asr-notifications-${created.configId}`);
  });

  it('should parse optional channels body and forward to service', async () => {
    // ARRANGE
    const slackConfig = {
      ...VALID_CREATE_BODY,
      name: 'Slack Config',
      deliveryChannels: [
        {
          type: 'email',
          enabled: true,
          recipients: [{ recipientType: 'custom', emailAddresses: ['admin@example.com'] }],
        },
        {
          type: 'slack',
          enabled: true,
          channelId: 'C12345678',
          credentialsSecretArn: 'arn:aws:secretsmanager:us-east-1:123456789012:secret:asr/notifications/slack-AbCdEf',
        },
      ],
    };
    const createResult = await createNotificationConfiguration(createPostEvent(slackConfig), createMockContext());
    expect(createResult.statusCode).toBe(201);
    const created = JSON.parse(createResult.body) as NotificationConfigurationItem;

    secretsManagerMock
      .on(GetSecretValueCommand)
      .resolves({ SecretString: '{"webhookUrl":"https://hooks.slack.com/services/T0001/B0001/xxxxx"}' });
    const fetchSpy = jest.spyOn(global, 'fetch').mockResolvedValue({ ok: true, status: 200 } as Response);
    const event = createTestNotificationEvent(created.configId, {
      body: { channels: ['slack'] },
    });

    // ACT
    const response = await testNotificationConfiguration(event, createMockContext());

    // ASSERT
    expect(response.statusCode).toBe(200);
    const body = JSON.parse(response.body) as TestNotificationResult;
    expect(body.results.slack).toBeDefined();
    expect(body.results.slack.status).toBe('success');
    expect(body.results.email).toBeUndefined();
    expect(fetchSpy).toHaveBeenCalled();
    fetchSpy.mockRestore();
  });

  it('should allow DelegatedAdminGroup users to send test notifications', async () => {
    // ARRANGE
    const created = await createConfig();
    setupCognitoMock('delegated@example.com', ['DelegatedAdminGroup']);
    const event = createTestNotificationEvent(created.configId, {
      username: 'delegated@example.com',
      groups: ['DelegatedAdminGroup'],
    });

    // ACT
    const response = await testNotificationConfiguration(event, createMockContext());

    // ASSERT
    expect(response.statusCode).toBe(200);
    const body = JSON.parse(response.body) as TestNotificationResult;
    expect(body.success).toBe(true);
    expect(snsMock.commandCalls(PublishCommand).length).toBeGreaterThanOrEqual(1);
  });
});
