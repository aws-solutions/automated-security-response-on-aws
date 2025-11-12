// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import nock from 'nock';
import {
  buildFailureMetric,
  buildFilteringMetric,
  sendMetrics,
  postMetricsToApi,
  getSolutionVersion,
  getSolutionUuid,
} from '../utils/metricsUtils';
import { ASFFFinding, OCSFComplianceFinding } from '@asr/data-models';
import { setupMetricsMocks, cleanupMetricsMocks, createMetricsTestScope, ssmMock } from './metricsMockSetup';
import { GetParameterCommand, PutParameterCommand, DeleteParameterCommand } from '@aws-sdk/client-ssm';
import { mockAccountId } from './envSetup';

describe('metricsUtils', () => {
  beforeEach(() => {
    setupMetricsMocks();
    jest.clearAllMocks();
  });

  afterEach(async () => {
    // wait for async HTTP requests to complete
    await new Promise((resolve) => setTimeout(resolve, 5));
  });

  afterAll(() => {
    ssmMock.restore();
    cleanupMetricsMocks();
  });

  describe('buildFailureMetric', () => {
    it('should build failure metric from ASFF finding', () => {
      const asffFinding: ASFFFinding = {
        SchemaVersion: '2018-10-08',
        Id: 'test-id',
        ProductArn: 'arn:aws:securityhub:us-east-1::product/aws/securityhub',
        GeneratorId: 'test-generator',
        AwsAccountId: '123456789012',
        Types: ['test-type'],
        CreatedAt: '2023-01-01T00:00:00Z',
        UpdatedAt: '2023-01-01T00:00:00Z',
        Severity: { Label: 'HIGH' },
        Title: 'Test Finding',
        Region: 'us-east-1',
        Compliance: { SecurityControlId: 'S3.1' },
        Resources: [{ Type: 'AWS::S3::Bucket', Id: 'test-bucket' }],
      };

      const result = buildFailureMetric(asffFinding);

      expect(result).toEqual({
        status: 'FAILED',
        status_reason: 'PRE_PROCESSOR_FAILED',
        control_id: 'arn:aws:securityhub:us-east-1::product/aws/securityhub',
        product_arn: 'S3.1',
        region: 'us-east-1',
      });
    });

    it('should build failure metric from OCSF finding', () => {
      const ocsfFinding: OCSFComplianceFinding = {
        class_uid: 2003,
        activity_id: 1,
        category_uid: 1,
        severity_id: 3,
        type_uid: 1,
        time: 1672531200,
        cloud: { account: { uid: '123456789012' }, region: 'us-west-2' },
        finding_info: { uid: 'test-uid', created_time: 1672531200, created_time_dt: '2023-01-01T00:00:00Z' },
        compliance: { control: 'EC2.1', standards: [] },
        metadata: { product: { uid: 'arn:aws:securityhub:us-west-2::product/aws/securityhub' } },
        resources: [],
      };

      const result = buildFailureMetric(ocsfFinding);

      expect(result).toEqual({
        status: 'FAILED',
        status_reason: 'PRE_PROCESSOR_FAILED',
        control_id: 'EC2.1',
        product_arn: 'arn:aws:securityhub:us-west-2::product/aws/securityhub',
        region: 'us-west-2',
      });
    });

    it('should handle undefined finding', () => {
      const result = buildFailureMetric();

      expect(result).toEqual({
        status: 'FAILED',
        status_reason: 'PRE_PROCESSOR_FAILED',
        control_id: undefined,
        product_arn: undefined,
        region: undefined,
      });
    });
  });

  describe('buildFilteringMetric', () => {
    it('should build filtering metric for account_id_filter', () => {
      const result = buildFilteringMetric('account_id_filter');

      expect(result).toEqual({
        finding_filtered_by_user: 'account_id_filter',
      });
    });

    it('should build filtering metric for OUs_filter', () => {
      const result = buildFilteringMetric('OUs_filter');

      expect(result).toEqual({
        finding_filtered_by_user: 'OUs_filter',
      });
    });

    it('should build filtering metric for tags_filter', () => {
      const result = buildFilteringMetric('tags_filter');

      expect(result).toEqual({
        finding_filtered_by_user: 'tags_filter',
      });
    });

    it('should build filtering metric for none', () => {
      const result = buildFilteringMetric('none');

      expect(result).toEqual({
        finding_filtered_by_user: 'none',
      });
    });
  });

  describe('sendMetrics', () => {
    afterEach(async () => {
      // allow async http requests to complete between tests
      await new Promise((resolve) => setTimeout(resolve, 5));
    });

    it('should send metrics', async () => {
      const requestBodyRegex = /SO0111.*test-uuid.*123456789012.*test-stack-id.*test.*data.*1\.0\.0/;
      const scope = createMetricsTestScope(requestBodyRegex);

      await sendMetrics({ test: 'data' });

      await new Promise((resolve) => setTimeout(resolve, 50));
      expect(scope.isDone()).toBe(true);
    });
  });

  describe('getSolutionVersion', () => {
    it('should return version from SSM', async () => {
      ssmMock.on(GetParameterCommand).resolves({
        Parameter: { Value: '2.0.0' },
      });

      const result = await getSolutionVersion();
      expect(result).toBe('2.0.0');
    });

    it('should return undefined on error', async () => {
      ssmMock.on(GetParameterCommand).rejects(new Error('SSM error'));

      const result = await getSolutionVersion();
      expect(result).toBeUndefined();
    });
  });

  describe('postMetricsToApi', () => {
    it('should make POST request with correct data', async () => {
      const usageData = {
        Solution: 'SO0111',
        UUID: 'test-uuid',
        AccountId: mockAccountId,
        StackId: 'test-stack-id',
        TimeStamp: '2023-01-01T00:00:00.000Z',
        Data: { test: 'data' },
        Version: '1.0.0',
      };

      const scope = createMetricsTestScope();

      postMetricsToApi(usageData);

      await new Promise((resolve) => setImmediate(resolve));
      expect(scope.isDone()).toBe(true);
    });

    it('should encode request data properly', async () => {
      const usageData = {
        Solution: 'SO0111',
        UUID: 'test-uuid',
        StackId: 'test-stack-id',
        AccountId: mockAccountId,
        TimeStamp: '2023-01-01T00:00:00.000Z',
        Data: { special: 'chars & symbols' },
        Version: '1.0.0',
      };

      const scope = createMetricsTestScope();

      postMetricsToApi(usageData);

      await new Promise((resolve) => setImmediate(resolve));
      expect(scope.isDone()).toBe(true);
    });
  });

  describe('getSolutionUuid', () => {
    it('should migrate from deprecated UUID parameter', async () => {
      // ARRANGE - Mock new UUID parameter not found, deprecated parameter exists
      ssmMock
        .on(GetParameterCommand, { Name: '/Solutions/SO0111/metrics_uuid' })
        .rejectsOnce(new Error('Parameter not found'))
        .on(GetParameterCommand, { Name: '/Solutions/SO0111/anonymous_metrics_uuid' })
        .resolves({ Parameter: { Value: 'deprecated-uuid-123' } })
        .on(PutParameterCommand)
        .resolves({})
        .on(DeleteParameterCommand)
        .resolves({});

      // ACT
      await sendMetrics({ test: 'data' });

      // ASSERT
      expect(ssmMock.commandCalls(DeleteParameterCommand)).toHaveLength(1);
      expect(ssmMock.commandCalls(PutParameterCommand)).toHaveLength(1);
      expect(ssmMock.commandCalls(PutParameterCommand)[0].args[0].input).toEqual({
        Name: '/Solutions/SO0111/metrics_uuid',
        Value: 'deprecated-uuid-123',
        Type: 'String',
      });
    });

    it('should handle error when deleting deprecated parameter', async () => {
      // ARRANGE - Mock new UUID parameter not found, deprecated parameter exists but delete fails
      ssmMock
        .on(GetParameterCommand, { Name: '/Solutions/SO0111/metrics_uuid' })
        .rejectsOnce(new Error('Parameter not found'))
        .on(GetParameterCommand, { Name: '/Solutions/SO0111/anonymous_metrics_uuid' })
        .resolves({ Parameter: { Value: 'deprecated-uuid-123' } })
        .on(DeleteParameterCommand)
        .rejects(new Error('Delete failed'))
        .on(PutParameterCommand)
        .resolves({});

      // ACT
      await sendMetrics({ test: 'data' });

      // ASSERT
      expect(ssmMock.commandCalls(DeleteParameterCommand)).toHaveLength(1);
      expect(ssmMock.commandCalls(PutParameterCommand)).toHaveLength(1);
      expect(ssmMock.commandCalls(PutParameterCommand)[0].args[0].input).toEqual({
        Name: '/Solutions/SO0111/metrics_uuid',
        Value: 'deprecated-uuid-123',
        Type: 'String',
      });
    });
  });

  describe('Parameter Caching', () => {
    it('should cache SSM parameters and avoid repeated calls', async () => {
      ssmMock.on(GetParameterCommand).resolves({
        Parameter: { Value: '123' },
      });

      const result1 = await getSolutionUuid();
      expect(ssmMock.commandCalls(GetParameterCommand)).toHaveLength(1);

      const result2 = await getSolutionUuid();
      expect(ssmMock.commandCalls(GetParameterCommand)).toHaveLength(1); // Still 1, no new call

      expect(result1).toBe(result2);
      expect(result1).toBe('123');
    });

    it('should return stale cache when SSM fails after initial success', async () => {
      ssmMock.on(GetParameterCommand).resolvesOnce({
        Parameter: { Value: '2.0.0' },
      });

      const result1 = await getSolutionVersion();
      expect(result1).toBe('2.0.0');

      ssmMock.on(GetParameterCommand).rejects(new Error('SSM throttling'));

      const result2 = await getSolutionVersion();

      expect(result2).toBe('2.0.0'); // Should return stale cache value
    });

    it('should cache different parameters independently', async () => {
      ssmMock
        .on(GetParameterCommand, { Name: '/Solutions/SO0111/metrics_uuid' })
        .resolves({ Parameter: { Value: '123' } })
        .on(GetParameterCommand, { Name: '/Solutions/SO0111/version' })
        .resolves({ Parameter: { Value: '2.0.0' } });

      const solutionUuid = await getSolutionUuid();
      const version = await getSolutionVersion();

      expect(solutionUuid).toBe('123');
      expect(version).toBe('2.0.0');
      expect(ssmMock.commandCalls(GetParameterCommand)).toHaveLength(2);

      await getSolutionUuid();
      await getSolutionVersion();
      expect(ssmMock.commandCalls(GetParameterCommand)).toHaveLength(2); // Still 2, no new calls
    });
  });
});
