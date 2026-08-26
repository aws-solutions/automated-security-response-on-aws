// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { mockClient } from 'aws-sdk-client-mock';
import { SNSClient, PublishBatchCommand } from '@aws-sdk/client-sns';
import { DynamoDBDocumentClient } from '@aws-sdk/lib-dynamodb';
import { Logger } from '@aws-lambda-powertools/logger';
import { NotificationConfigurationItem, NotificationEvent, ResourceFilterDynamoDBItem } from '@asr/data-models';
import { NotificationDispatcherService } from '../notificationDispatcherService';
import { NotificationConfigurationRepository } from '../../common/repositories/notificationConfigurationRepository';
import { FiltersRepository } from '../../common/repositories/filtersRepository';
import { DynamoDBTestSetup } from '../../common/__tests__/dynamodbSetup';
import {
  notificationConfigTableName,
  notificationBatchesTableName,
  resourceFiltersTableName,
} from '../../common/__tests__/envSetup';
import { asConfigId } from '../../common/__tests__/utils';
import { sendMetrics } from '../../common/utils/metricsUtils';

const snsMock = mockClient(SNSClient);

const FANOUT_TOPIC_ARN = 'arn:aws:sns:us-east-1:123456789012:channel-fanout';

const createMockEvent = (overrides: Partial<NotificationEvent> = {}): NotificationEvent => ({
  eventType: 'finding',
  eventId: 'arn:aws:securityhub:us-east-1:123456789012:finding/abc',
  controlId: 'S3.1',
  accountId: '123456789012',
  region: 'us-east-1',
  severity: 'High',
  resourceType: 'AwsS3Bucket',
  resourceId: 'arn:aws:s3:::my-bucket',
  title: 'S3 bucket public',
  description: 'Bucket is publicly accessible',
  detectedAt: '2024-01-01T00:00:00.000Z',
  timestamp: new Date().toISOString(),
  ...overrides,
});

const createMockConfig = (overrides: Partial<NotificationConfigurationItem> = {}): NotificationConfigurationItem => ({
  configId: asConfigId('aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'),
  name: 'Test Config',
  enabled: true,
  notificationType: 'finding',
  severityFilter: ['All'],
  controlIds: [],
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

describe('NotificationDispatcherService', () => {
  const principal = 'test-user@example.com';
  let docClient: DynamoDBDocumentClient;
  let service: NotificationDispatcherService;
  let configRepo: NotificationConfigurationRepository;
  let filtersRepo: FiltersRepository;
  const logger = new Logger({ logLevel: 'SILENT' });

  beforeAll(async () => {
    await DynamoDBTestSetup.initialize();
    docClient = DynamoDBTestSetup.getDocClient();
    await DynamoDBTestSetup.createNotificationConfigTable(notificationConfigTableName);
    await DynamoDBTestSetup.createNotificationBatchesTable(notificationBatchesTableName);
    await DynamoDBTestSetup.createResourceFiltersTable(resourceFiltersTableName);
  });

  afterAll(async () => {
    await DynamoDBTestSetup.deleteTable(notificationConfigTableName);
    await DynamoDBTestSetup.deleteTable(notificationBatchesTableName);
    await DynamoDBTestSetup.deleteTable(resourceFiltersTableName);
  });

  beforeEach(async () => {
    snsMock.reset();
    (sendMetrics as jest.Mock).mockClear();
    snsMock.on(PublishBatchCommand).resolves({
      Successful: [{ Id: '0', MessageId: 'mock-msg-id' }],
      Failed: [],
    });
    await DynamoDBTestSetup.clearTable(notificationConfigTableName, 'notificationConfig');
    await DynamoDBTestSetup.clearTable(notificationBatchesTableName, 'notificationBatches');
    await DynamoDBTestSetup.clearTable(resourceFiltersTableName, 'resourceFilters');

    configRepo = new NotificationConfigurationRepository(notificationConfigTableName, docClient);
    filtersRepo = new FiltersRepository(resourceFiltersTableName, docClient);

    service = new NotificationDispatcherService({
      configTableName: notificationConfigTableName,
      batchesTableName: notificationBatchesTableName,
      resourceFiltersTableName,
      dynamoDBClient: docClient,
      logger,
      snsClient: snsMock as unknown as SNSClient,
      channelFanoutTopicArn: FANOUT_TOPIC_ARN,
    });
  });

  describe('dispatch', () => {
    it('should publish to SNS for matching immediate config', async () => {
      await configRepo.create(createMockConfig(), principal);

      await service.dispatch(createMockEvent());

      expect(snsMock.commandCalls(PublishBatchCommand)).toHaveLength(1);
      const call = snsMock.commandCalls(PublishBatchCommand)[0];
      expect(call.args[0].input.TopicArn).toBe(FANOUT_TOPIC_ARN);
    });

    it('should not publish when no configs match the event type', async () => {
      await configRepo.create(createMockConfig({ notificationType: 'remediation' }), principal);

      await service.dispatch(createMockEvent({ eventType: 'finding' }));

      expect(snsMock.commandCalls(PublishBatchCommand)).toHaveLength(0);
    });

    it('should emit a single notification_dispatch_latency metric on immediate publish', async () => {
      // ARRANGE
      const config = createMockConfig({
        deliveryChannels: [
          {
            type: 'email',
            enabled: true,
            recipients: [{ recipientType: 'custom', emailAddresses: ['test@example.com'] }],
          },
          { type: 'sns', enabled: true, topicArn: 'arn:aws:sns:us-east-1:123456789012:customer-topic' },
        ],
      });
      await configRepo.create(config, principal);

      // ACT
      await service.dispatch(createMockEvent());

      // ASSERT
      expect(sendMetrics).toHaveBeenCalledWith({
        notification_dispatch_latency: expect.any(Number),
        config_id: config.configId,
        channel_count: 2,
      });
    });

    it('should filter by severity threshold', async () => {
      await configRepo.create(createMockConfig({ severityFilter: ['Critical'] }), principal);

      await service.dispatch(createMockEvent({ severity: 'Medium' }));

      expect(snsMock.commandCalls(PublishBatchCommand)).toHaveLength(0);
    });

    it('should filter remediation events by remediationStatusFilter', async () => {
      await configRepo.create(
        createMockConfig({ notificationType: 'remediation', remediationStatusFilter: ['Failed'] }),
        principal,
      );

      await service.dispatch(createMockEvent({ eventType: 'remediation', remediationStatus: 'SUCCESS' }));

      expect(snsMock.commandCalls(PublishBatchCommand)).toHaveLength(0);
    });

    it('should pass remediation events matching remediationStatusFilter', async () => {
      await configRepo.create(
        createMockConfig({ notificationType: 'remediation', remediationStatusFilter: ['Failed'] }),
        principal,
      );

      await service.dispatch(createMockEvent({ eventType: 'remediation', remediationStatus: 'FAILED' }));

      expect(snsMock.commandCalls(PublishBatchCommand)).toHaveLength(1);
    });

    it('should normalize LAMBDA_ERROR to Failed for remediationStatusFilter', async () => {
      await configRepo.create(
        createMockConfig({ notificationType: 'remediation', remediationStatusFilter: ['Failed'] }),
        principal,
      );

      await service.dispatch(createMockEvent({ eventType: 'remediation', remediationStatus: 'LAMBDA_ERROR' }));

      expect(snsMock.commandCalls(PublishBatchCommand)).toHaveLength(1);
    });

    it('should normalize QUEUED to In Progress for remediationStatusFilter', async () => {
      await configRepo.create(
        createMockConfig({ notificationType: 'remediation', remediationStatusFilter: ['In Progress'] }),
        principal,
      );

      await service.dispatch(createMockEvent({ eventType: 'remediation', remediationStatus: 'QUEUED' }));

      expect(snsMock.commandCalls(PublishBatchCommand)).toHaveLength(1);
    });

    it('should normalize ROLLBACK_SUCCESS to Rollback Success for remediationStatusFilter', async () => {
      await configRepo.create(
        createMockConfig({ notificationType: 'remediation', remediationStatusFilter: ['Rollback Success'] }),
        principal,
      );

      await service.dispatch(createMockEvent({ eventType: 'remediation', remediationStatus: 'ROLLBACK_SUCCESS' }));

      expect(snsMock.commandCalls(PublishBatchCommand)).toHaveLength(1);
    });

    it('should NOT classify ROLLBACK_SUCCESS as Failed', async () => {
      // Subscribers to "Failed" should not receive rollback events.
      await configRepo.create(
        createMockConfig({ notificationType: 'remediation', remediationStatusFilter: ['Failed'] }),
        principal,
      );

      await service.dispatch(createMockEvent({ eventType: 'remediation', remediationStatus: 'ROLLBACK_SUCCESS' }));

      expect(snsMock.commandCalls(PublishBatchCommand)).toHaveLength(0);
    });

    it('should normalize ROLLBACK_IN_PROGRESS to Rollback In Progress for remediationStatusFilter', async () => {
      await configRepo.create(
        createMockConfig({ notificationType: 'remediation', remediationStatusFilter: ['Rollback In Progress'] }),
        principal,
      );

      await service.dispatch(createMockEvent({ eventType: 'remediation', remediationStatus: 'ROLLBACK_IN_PROGRESS' }));

      expect(snsMock.commandCalls(PublishBatchCommand)).toHaveLength(1);
    });

    it('should NOT classify ROLLBACK_FAILED as generic Failed', async () => {
      // A subscriber to the generic "Failed" must not receive rollback failures.
      await configRepo.create(
        createMockConfig({ notificationType: 'remediation', remediationStatusFilter: ['Failed'] }),
        principal,
      );

      await service.dispatch(createMockEvent({ eventType: 'remediation', remediationStatus: 'ROLLBACK_FAILED' }));

      expect(snsMock.commandCalls(PublishBatchCommand)).toHaveLength(0);
    });

    it('should normalize ROLLBACK_FAILED to Rollback Failed for remediationStatusFilter', async () => {
      await configRepo.create(
        createMockConfig({ notificationType: 'remediation', remediationStatusFilter: ['Rollback Failed'] }),
        principal,
      );

      await service.dispatch(createMockEvent({ eventType: 'remediation', remediationStatus: 'ROLLBACK_FAILED' }));

      expect(snsMock.commandCalls(PublishBatchCommand)).toHaveLength(1);
    });

    it('should pass all remediation events when remediationStatusFilter includes All', async () => {
      await configRepo.create(
        createMockConfig({ notificationType: 'remediation', remediationStatusFilter: ['All'] }),
        principal,
      );

      await service.dispatch(createMockEvent({ eventType: 'remediation', remediationStatus: 'QUEUED' }));

      expect(snsMock.commandCalls(PublishBatchCommand)).toHaveLength(1);
    });

    it('should normalize NOT_STARTED to Not Started for remediationStatusFilter', async () => {
      await configRepo.create(
        createMockConfig({ notificationType: 'remediation', remediationStatusFilter: ['Not Started'] }),
        principal,
      );

      await service.dispatch(createMockEvent({ eventType: 'remediation', remediationStatus: 'NOT_STARTED' }));

      expect(snsMock.commandCalls(PublishBatchCommand)).toHaveLength(1);
    });

    it('should filter by controlIds when specified', async () => {
      await configRepo.create(createMockConfig({ controlIds: ['IAM.1'] }), principal);

      await service.dispatch(createMockEvent({ controlId: 'S3.1' }));

      expect(snsMock.commandCalls(PublishBatchCommand)).toHaveLength(0);
    });

    it('should pass when controlIds is empty (matches all)', async () => {
      await configRepo.create(createMockConfig({ controlIds: [] }), principal);

      await service.dispatch(createMockEvent({ controlId: 'S3.1' }));

      expect(snsMock.commandCalls(PublishBatchCommand)).toHaveLength(1);
    });

    it('should skip disabled delivery channels', async () => {
      await configRepo.create(
        createMockConfig({
          deliveryChannels: [
            {
              type: 'email',
              enabled: false,
              recipients: [{ recipientType: 'custom', emailAddresses: ['test@example.com'] }],
            },
          ],
        }),
        principal,
      );

      await service.dispatch(createMockEvent());

      expect(snsMock.commandCalls(PublishBatchCommand)).toHaveLength(0);
    });

    it('should collapse multiple enabled channels into a single PublishBatch call', async () => {
      await configRepo.create(
        createMockConfig({
          deliveryChannels: [
            {
              type: 'email',
              enabled: true,
              recipients: [{ recipientType: 'custom', emailAddresses: ['a@example.com'] }],
            },
            {
              type: 'sns',
              enabled: true,
              topicArn: 'arn:aws:sns:us-east-1:123456789012:downstream',
            },
          ],
        }),
        principal,
      );

      await service.dispatch(createMockEvent());

      const calls = snsMock.commandCalls(PublishBatchCommand);
      expect(calls).toHaveLength(1);

      const entries = calls[0].args[0].input.PublishBatchRequestEntries ?? [];
      expect(entries).toHaveLength(2);

      const channelTypes = entries.map((e) => e.MessageAttributes?.channelType?.StringValue);
      expect(channelTypes).toEqual(expect.arrayContaining(['email', 'sns']));

      // Each entry must carry a unique Id so SNS can identify partial failures.
      const ids = entries.map((e) => e.Id);
      expect(new Set(ids).size).toBe(ids.length);
    });

    it('should throw when PublishBatch returns partial failures', async () => {
      snsMock.on(PublishBatchCommand).resolves({
        Successful: [{ Id: '0', MessageId: 'msg-ok' }],
        Failed: [{ Id: '1', Code: 'InternalError', Message: 'boom', SenderFault: false }],
      });

      await configRepo.create(
        createMockConfig({
          deliveryChannels: [
            {
              type: 'email',
              enabled: true,
              recipients: [{ recipientType: 'custom', emailAddresses: ['a@example.com'] }],
            },
            {
              type: 'sns',
              enabled: true,
              topicArn: 'arn:aws:sns:us-east-1:123456789012:downstream',
            },
          ],
        }),
        principal,
      );

      await expect(service.dispatch(createMockEvent())).rejects.toThrow(/PublishBatch partial failure/);
    });
  });

  describe('clearCache', () => {
    it('should force fresh DynamoDB read after cache is cleared', async () => {
      const config = createMockConfig();
      await configRepo.create(config, principal);

      // First dispatch populates cache
      await service.dispatch(createMockEvent());
      expect(snsMock.commandCalls(PublishBatchCommand)).toHaveLength(1);

      // Delete the config from DB
      await configRepo.deleteById(config.configId);

      // Without clearing cache, still dispatches (cached)
      snsMock.resetHistory();
      await service.dispatch(createMockEvent());
      expect(snsMock.commandCalls(PublishBatchCommand)).toHaveLength(1);

      // After clearing cache, no more matches
      service.clearCache();
      snsMock.resetHistory();
      await service.dispatch(createMockEvent());
      expect(snsMock.commandCalls(PublishBatchCommand)).toHaveLength(0);
    });
  });

  describe('resourceFilterIds', () => {
    const FILTER_ID_A = '11111111-1111-1111-1111-111111111111';
    const FILTER_ID_B = '22222222-2222-2222-2222-222222222222';
    const FILTER_ID_MISSING = '33333333-3333-3333-3333-333333333333';

    const insertFilter = async (filter: Partial<ResourceFilterDynamoDBItem> & { filterId: string; name: string }) => {
      const fullFilter: ResourceFilterDynamoDBItem = {
        accountIds: [],
        organizationalUnits: [],
        tags: [],
        arnPatterns: [],
        version: 1,
        createdAt: '2024-01-01T00:00:00.000Z',
        createdBy: principal,
        lastModified: '2024-01-01T00:00:00.000Z',
        modifiedBy: principal,
        ...filter,
      };
      await filtersRepo.createFilter(
        fullFilter.filterId,
        {
          name: fullFilter.name,
          accountIds: (fullFilter.accountIds as string[]) ?? [],
          organizationalUnits: (fullFilter.organizationalUnits as string[]) ?? [],
          tags: fullFilter.tags ?? [],
          arnPatterns: (fullFilter.arnPatterns as string[]) ?? [],
        },
        principal,
        fullFilter.createdAt,
      );
    };

    it('passes when resourceFilterIds is empty (no filtering)', async () => {
      await configRepo.create(createMockConfig({ resourceFilterIds: [] }), principal);

      await service.dispatch(createMockEvent());

      expect(snsMock.commandCalls(PublishBatchCommand)).toHaveLength(1);
    });

    it('passes when any attached filter matches the event account id', async () => {
      await insertFilter({ filterId: FILTER_ID_A, name: 'prod-accounts', accountIds: ['123456789012'] });
      await configRepo.create(createMockConfig({ resourceFilterIds: [FILTER_ID_A] }), principal);

      await service.dispatch(createMockEvent({ accountId: '123456789012' }));

      expect(snsMock.commandCalls(PublishBatchCommand)).toHaveLength(1);
    });

    it('blocks when no attached filter matches the event account id', async () => {
      await insertFilter({ filterId: FILTER_ID_A, name: 'prod-accounts', accountIds: ['999999999999'] });
      await configRepo.create(createMockConfig({ resourceFilterIds: [FILTER_ID_A] }), principal);

      await service.dispatch(createMockEvent({ accountId: '123456789012' }));

      expect(snsMock.commandCalls(PublishBatchCommand)).toHaveLength(0);
    });

    it('passes when arnPatterns wildcard matches the event resource id', async () => {
      await insertFilter({
        filterId: FILTER_ID_A,
        name: 'my-buckets',
        arnPatterns: ['arn:aws:s3:::my-*'],
      });
      await configRepo.create(createMockConfig({ resourceFilterIds: [FILTER_ID_A] }), principal);

      await service.dispatch(createMockEvent({ resourceId: 'arn:aws:s3:::my-bucket' }));

      expect(snsMock.commandCalls(PublishBatchCommand)).toHaveLength(1);
    });

    it('blocks when arnPatterns do not match the event resource id', async () => {
      await insertFilter({
        filterId: FILTER_ID_A,
        name: 'only-prod-buckets',
        arnPatterns: ['arn:aws:s3:::prod-*'],
      });
      await configRepo.create(createMockConfig({ resourceFilterIds: [FILTER_ID_A] }), principal);

      await service.dispatch(createMockEvent({ resourceId: 'arn:aws:s3:::my-bucket' }));

      expect(snsMock.commandCalls(PublishBatchCommand)).toHaveLength(0);
    });

    it('passes when at least one of multiple filters matches (include-any)', async () => {
      await insertFilter({ filterId: FILTER_ID_A, name: 'other-accounts', accountIds: ['999999999999'] });
      await insertFilter({ filterId: FILTER_ID_B, name: 'this-account', accountIds: ['123456789012'] });
      await configRepo.create(createMockConfig({ resourceFilterIds: [FILTER_ID_A, FILTER_ID_B] }), principal);

      await service.dispatch(createMockEvent({ accountId: '123456789012' }));

      expect(snsMock.commandCalls(PublishBatchCommand)).toHaveLength(1);
    });

    it('still matches against surviving filters when a referenced filter has been deleted', async () => {
      // FILTER_ID_MISSING is referenced by the config but was never inserted (i.e. deleted from DynamoDB).
      // batchFindByIds silently omits the absent key and returns only the surviving filter; the event
      // should still match if any surviving filter matches.
      await insertFilter({ filterId: FILTER_ID_A, name: 'this-account', accountIds: ['123456789012'] });
      await configRepo.create(createMockConfig({ resourceFilterIds: [FILTER_ID_A, FILTER_ID_MISSING] }), principal);

      await service.dispatch(createMockEvent({ accountId: '123456789012' }));

      expect(snsMock.commandCalls(PublishBatchCommand)).toHaveLength(1);
    });

    it('blocks when a filter declares only tag criteria (not evaluable at dispatch)', async () => {
      await insertFilter({
        filterId: FILTER_ID_A,
        name: 'tag-only',
        tags: [{ key: 'Environment', value: 'prod' }],
      });
      await configRepo.create(createMockConfig({ resourceFilterIds: [FILTER_ID_A] }), principal);

      await service.dispatch(createMockEvent());

      expect(snsMock.commandCalls(PublishBatchCommand)).toHaveLength(0);
    });

    it('issues a single BatchGet on cache warm-up regardless of config count', async () => {
      const batchGetSpy = jest.spyOn(FiltersRepository.prototype, 'batchFindByIds');
      const sharedFilter = FILTER_ID_A;
      await insertFilter({ filterId: sharedFilter, name: 'shared', accountIds: ['123456789012'] });
      await configRepo.create(
        createMockConfig({
          configId: asConfigId('aaaaaaaa-0000-0000-0000-000000000001'),
          name: 'Config 1',
          resourceFilterIds: [sharedFilter],
        }),
        principal,
      );
      await configRepo.create(
        createMockConfig({
          configId: asConfigId('aaaaaaaa-0000-0000-0000-000000000002'),
          name: 'Config 2',
          resourceFilterIds: [sharedFilter],
        }),
        principal,
      );

      await service.dispatch(createMockEvent());
      await service.dispatch(createMockEvent({ eventId: 'evt-2' }));

      // Warm-up happens once per eventType; subsequent dispatches hit the cache.
      expect(batchGetSpy).toHaveBeenCalledTimes(1);
      batchGetSpy.mockRestore();
    });
  });
});
