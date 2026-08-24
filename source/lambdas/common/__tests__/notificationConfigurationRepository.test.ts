// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { DynamoDBDocumentClient, GetCommand, PutCommand } from '@aws-sdk/lib-dynamodb';
import { NotificationConfigurationItem } from '@asr/data-models';
import { NotificationConfigurationRepository } from '../repositories/notificationConfigurationRepository';
import { BadRequestError, VersionConflictError } from '../utils/httpErrors';
import { DynamoDBTestSetup } from './dynamodbSetup';
import { notificationConfigTableName } from './envSetup';
import { asConfigId } from './utils';

const createMockConfig = (overrides: Partial<NotificationConfigurationItem> = {}): NotificationConfigurationItem => ({
  configId: asConfigId('aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'),
  name: 'Test Config',
  enabled: true,
  notificationType: 'finding',
  severityFilter: ['High'],
  controlIds: ['S3.1', 'IAM.1'],
  resourceFilterIds: [],
  deliveryChannels: [
    { type: 'email', enabled: true, recipients: [{ recipientType: 'custom', emailAddresses: ['test@example.com'] }] },
  ],
  batchWindow: { enabled: false },
  contentOptions: {
    includeManualRemediationLink: false,
    includeRemediationDeadline: false,
    enforceDeadline: false,
    includeIaCSnippet: false,
    includeEnableAutomationLink: false,
  },
  version: 1,
  createdAt: '2024-01-01T00:00:00.000Z',
  createdBy: 'admin@example.com',
  ...overrides,
});

describe('NotificationConfigurationRepository', () => {
  const principal = 'test-user@example.com';
  let docClient: DynamoDBDocumentClient;
  let repository: NotificationConfigurationRepository;

  beforeAll(async () => {
    await DynamoDBTestSetup.initialize();
    docClient = DynamoDBTestSetup.getDocClient();
    await DynamoDBTestSetup.createNotificationConfigTable(notificationConfigTableName);
  });

  afterAll(async () => {
    await DynamoDBTestSetup.deleteTable(notificationConfigTableName);
  });

  beforeEach(async () => {
    await DynamoDBTestSetup.clearTable(notificationConfigTableName, 'notificationConfig');
    repository = new NotificationConfigurationRepository(notificationConfigTableName, docClient);
  });

  describe('create', () => {
    it('should persist a new configuration with version 1', async () => {
      const config = createMockConfig({ createdBy: principal });

      await repository.create(config, principal);

      const result = await docClient.send(
        new GetCommand({ TableName: notificationConfigTableName, Key: { configId: config.configId } }),
      );
      expect(result.Item).toBeDefined();
      expect(result.Item!.version).toBe(1);
      expect(result.Item!.createdBy).toBe(principal);
      expect(result.Item!.CONFIG_CONSTANT).toBe('CONFIG');
    });

    it('should set enabledType to notificationType', async () => {
      const config = createMockConfig({ notificationType: 'finding' });

      await repository.create(config, principal);

      const result = await docClient.send(
        new GetCommand({ TableName: notificationConfigTableName, Key: { configId: config.configId } }),
      );
      expect(result.Item!.enabledType).toBe('finding');
    });

    it('should set lastUpdatedBy to principal', async () => {
      const config = createMockConfig();

      await repository.create(config, principal);

      const result = await docClient.send(
        new GetCommand({ TableName: notificationConfigTableName, Key: { configId: config.configId } }),
      );
      expect(result.Item!.lastUpdatedBy).toBe(principal);
    });

    it('should reject duplicate configId', async () => {
      const config = createMockConfig();
      await repository.create(config, principal);

      await expect(repository.create(config, principal)).rejects.toThrow('already exists');
    });
  });

  describe('findConfigById', () => {
    it('should return existing configuration', async () => {
      const config = createMockConfig();
      await docClient.send(new PutCommand({ TableName: notificationConfigTableName, Item: config }));

      const result = await repository.findConfigById(config.configId);

      expect(result).toBeDefined();
      expect(result!.configId).toBe(config.configId);
      expect(result!.name).toBe('Test Config');
    });

    it('should return undefined for non-existent id', async () => {
      const result = await repository.findConfigById('non-existent-id');
      expect(result).toBeUndefined();
    });
  });

  describe('findByName', () => {
    it('should find configuration by name via GSI', async () => {
      const config = createMockConfig({ name: 'Unique Name' });
      await docClient.send(new PutCommand({ TableName: notificationConfigTableName, Item: config }));

      const result = await repository.findByName('Unique Name');

      expect(result).toBeDefined();
      expect(result!.configId).toBe(config.configId);
    });

    it('should return undefined when name not found', async () => {
      const result = await repository.findByName('Does Not Exist');
      expect(result).toBeUndefined();
    });
  });

  describe('findAll', () => {
    it('should return all configurations via AllConfigsIndex', async () => {
      const config1 = createMockConfig({
        configId: asConfigId('11111111-1111-1111-1111-111111111111'),
        name: 'Config A',
      });
      const config2 = createMockConfig({
        configId: asConfigId('22222222-2222-2222-2222-222222222222'),
        name: 'Config B',
      });
      await repository.create(config1, principal);
      await repository.create(config2, principal);

      const results = await repository.findAll();

      expect(results).toHaveLength(2);
      const ids = results.map((r) => r.configId).sort();
      expect(ids).toEqual([config1.configId, config2.configId].sort());
    });

    it('should return empty array when no configurations exist', async () => {
      const results = await repository.findAll();
      expect(results).toEqual([]);
    });
  });

  describe('findByType', () => {
    it('should return only configurations matching the notification type', async () => {
      const finding = createMockConfig({
        configId: asConfigId('11111111-1111-1111-1111-111111111111'),
        name: 'Finding Config',
        notificationType: 'finding',
      });
      const remediation = createMockConfig({
        configId: asConfigId('22222222-2222-2222-2222-222222222222'),
        name: 'Remediation Config',
        notificationType: 'remediation',
      });
      await repository.create(finding, principal);
      await repository.create(remediation, principal);

      const results = await repository.findByType('finding');

      expect(results).toHaveLength(1);
      expect(results[0].configId).toBe(finding.configId);
    });

    it('should return empty array when no configurations match the type', async () => {
      const config = createMockConfig({ notificationType: 'finding' });
      await repository.create(config, principal);

      const results = await repository.findByType('remediation');

      expect(results).toEqual([]);
    });
  });

  describe('updateWithVersion', () => {
    it('should update when version matches', async () => {
      const config = createMockConfig();
      await repository.create(config, principal);

      const updated = { ...config, name: 'Updated Name' };
      await repository.updateWithVersion(updated, 1, principal);

      const result = await docClient.send(
        new GetCommand({ TableName: notificationConfigTableName, Key: { configId: config.configId } }),
      );
      expect(result.Item!.name).toBe('Updated Name');
      expect(result.Item!.version).toBe(2);
      expect(result.Item!.updatedBy).toBe(principal);
    });

    it('should set enabledType and CONFIG_CONSTANT on update', async () => {
      const config = createMockConfig({ notificationType: 'finding' });
      await repository.create(config, principal);

      await repository.updateWithVersion(config, 1, principal);

      const result = await docClient.send(
        new GetCommand({ TableName: notificationConfigTableName, Key: { configId: config.configId } }),
      );
      expect(result.Item!.enabledType).toBe('finding');
      expect(result.Item!.CONFIG_CONSTANT).toBe('CONFIG');
      expect(result.Item!.lastUpdatedBy).toBe(principal);
    });

    it('should reject when version does not match (optimistic locking)', async () => {
      const config = createMockConfig({ version: 2 });
      await docClient.send(new PutCommand({ TableName: notificationConfigTableName, Item: config }));

      await expect(repository.updateWithVersion(config, 1, principal)).rejects.toThrow(VersionConflictError);
    });

    it('should include the current version on the thrown VersionConflictError', async () => {
      const config = createMockConfig({ version: 7 });
      await docClient.send(new PutCommand({ TableName: notificationConfigTableName, Item: config }));

      await expect(repository.updateWithVersion(config, 1, principal)).rejects.toMatchObject({
        name: 'VersionConflictError',
        currentVersion: 7,
      });
    });
  });

  describe('findByResourceFilterId', () => {
    it('should return configs that reference the given resource filter ID', async () => {
      const filterId = '11111111-aaaa-bbbb-cccc-222222222222';
      const matchingConfig = createMockConfig({
        configId: asConfigId('c1111111-1111-1111-1111-111111111111'),
        resourceFilterIds: [filterId, '33333333-3333-3333-3333-333333333333'],
      });
      const otherConfig = createMockConfig({
        configId: asConfigId('c2222222-2222-2222-2222-222222222222'),
        resourceFilterIds: ['99999999-9999-9999-9999-999999999999'],
      });
      await repository.create(matchingConfig, principal);
      await repository.create(otherConfig, principal);

      const results = await repository.findByResourceFilterId(filterId);

      expect(results).toHaveLength(1);
      expect(results[0].configId).toBe(matchingConfig.configId);
    });

    it('should return an empty array when no configs reference the filter ID', async () => {
      const results = await repository.findByResourceFilterId('nonexistent-filter-id');
      expect(results).toEqual([]);
    });
  });

  describe('deleteById', () => {
    it('should delete existing configuration', async () => {
      const config = createMockConfig();
      await docClient.send(new PutCommand({ TableName: notificationConfigTableName, Item: config }));

      await repository.deleteById(config.configId);

      const result = await repository.findConfigById(config.configId);
      expect(result).toBeUndefined();
    });

    it('should not throw when deleting non-existent id', async () => {
      await expect(repository.deleteById('non-existent')).resolves.not.toThrow();
    });
  });

  describe('findPaginated', () => {
    it('should throw BadRequestError for malformed base64 nextToken', async () => {
      await expect(repository.findPaginated({ nextToken: '!!!not-base64!!!' })).rejects.toThrow(BadRequestError);
      await expect(repository.findPaginated({ nextToken: '!!!not-base64!!!' })).rejects.toThrow(
        'Invalid pagination token',
      );
    });

    it('should throw BadRequestError for valid base64 but invalid JSON nextToken', async () => {
      const token = Buffer.from('not-json').toString('base64');
      await expect(repository.findPaginated({ nextToken: token })).rejects.toThrow(BadRequestError);
    });

    it('should throw BadRequestError for valid JSON but missing required keys', async () => {
      const token = Buffer.from(JSON.stringify({ foo: 'bar' })).toString('base64');
      await expect(repository.findPaginated({ nextToken: token })).rejects.toThrow(BadRequestError);
    });

    it('should throw BadRequestError for valid JSON with non-UUID configId', async () => {
      const token = Buffer.from(JSON.stringify({ CONFIG_CONSTANT: 'CONFIG', configId: 'not-a-uuid' })).toString(
        'base64',
      );
      await expect(repository.findPaginated({ nextToken: token })).rejects.toThrow(BadRequestError);
    });

    it('should accept a valid nextToken', async () => {
      const config = createMockConfig();
      await repository.create(config, principal);

      const validToken = Buffer.from(JSON.stringify({ CONFIG_CONSTANT: 'CONFIG', configId: config.configId })).toString(
        'base64',
      );

      const result = await repository.findPaginated({ nextToken: validToken });
      expect(result.items).toBeDefined();
    });
  });
});
