// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { CloudFormationCustomResourceEvent, Context } from 'aws-lambda';
import { mockClient } from 'aws-sdk-client-mock';
import { S3Client, PutObjectCommand } from '@aws-sdk/client-s3';
import nock from 'nock';
import { BaselineConfigurationHandler } from '../baselineConfigurationHandler';

const s3Mock = mockClient(S3Client);

const CFN_RESPONSE_HOST = 'https://cloudformation-custom-resource-response-useast1.s3.amazonaws.com';
const CFN_RESPONSE_PATH = '/test';

describe('BaselineConfigurationHandler', () => {
  let handler: BaselineConfigurationHandler;
  let mockContext: Context;

  const createMockEvent = (
    requestType: 'Create' | 'Update' | 'Delete' = 'Create',
    bucketName = 'so0111-asr-remediation-us-east-1-123456789012',
  ): CloudFormationCustomResourceEvent => {
    const baseEvent = {
      RequestType: requestType,
      ResponseURL: `${CFN_RESPONSE_HOST}${CFN_RESPONSE_PATH}`,
      StackId: 'arn:aws:cloudformation:us-east-1:123456789012:stack/test-stack/12345',
      RequestId: 'test-request-id',
      ResourceType: 'Custom::BaselineConfiguration',
      LogicalResourceId: 'BaselineConfigurationResource',
      ServiceToken: 'arn:aws:lambda:us-east-1:123456789012:function:test-provider',
      ResourceProperties: {
        ServiceToken: 'arn:aws:lambda:us-east-1:123456789012:function:test-provider',
        BucketName: bucketName,
        SolutionVersion: 'v3.0.0',
      },
    };

    if (requestType === 'Update' || requestType === 'Delete') {
      return {
        ...baseEvent,
        PhysicalResourceId: 'BaselineConfigurationResource',
      } as CloudFormationCustomResourceEvent;
    }

    return baseEvent as CloudFormationCustomResourceEvent;
  };

  beforeEach(() => {
    jest.clearAllMocks();
    s3Mock.reset();
    nock.cleanAll();
    s3Mock.on(PutObjectCommand).resolves({});

    handler = new BaselineConfigurationHandler();
    mockContext = {
      logStreamName: 'test-log-stream',
      getRemainingTimeInMillis: () => 30000,
    } as Context;
  });

  afterEach(() => {
    nock.cleanAll();
  });

  describe('Create event', () => {
    it('should upload the Windows baseline to S3 and send SUCCESS', async () => {
      const cfnScope = nock(CFN_RESPONSE_HOST).put(CFN_RESPONSE_PATH).reply(200);
      const event = createMockEvent('Create');

      await handler.handler(event, mockContext);

      const putCalls = s3Mock.commandCalls(PutObjectCommand);
      expect(putCalls).toHaveLength(1);
      expect(putCalls[0].args[0].input).toEqual(
        expect.objectContaining({
          Bucket: 'so0111-asr-remediation-us-east-1-123456789012',
          Key: 'baseline-overrides/windows-security-baseline.json',
          ContentType: 'application/json',
        }),
      );

      // Verify the uploaded JSON content. AWS-RunPatchBaseline's BaselineOverride
      // requires a JSON ARRAY of per-OS baseline objects, not a bare object.
      const body = putCalls[0].args[0].input.Body as string;
      const parsed = JSON.parse(body);
      expect(Array.isArray(parsed)).toBe(true);
      expect(parsed).toHaveLength(1);
      expect(parsed[0].OperatingSystem).toBe('WINDOWS');
      expect(parsed[0].ApprovalRules.PatchRules[0].ApproveAfterDays).toBe(0);
      expect(parsed[0].ApprovalRules.PatchRules[0].PatchFilterGroup.PatchFilters[0].Values).toEqual([
        'SecurityUpdates',
        'CriticalUpdates',
      ]);

      expect(cfnScope.isDone()).toBe(true);
    });

    it('should send FAILED response when BucketName is missing', async () => {
      let capturedBody: any;
      const cfnScope = nock(CFN_RESPONSE_HOST)
        .put(CFN_RESPONSE_PATH, (body: any) => {
          capturedBody = body;
          return true;
        })
        .reply(200);

      const event = createMockEvent('Create');
      event.ResourceProperties.BucketName = '';

      await handler.handler(event, mockContext);

      expect(s3Mock.commandCalls(PutObjectCommand)).toHaveLength(0);
      expect(cfnScope.isDone()).toBe(true);
      expect(capturedBody.Status).toBe('FAILED');
    });

    it('should send FAILED response with error message when S3 upload fails', async () => {
      s3Mock.on(PutObjectCommand).rejects(new Error('Access Denied'));
      let capturedBody: any;
      const cfnScope = nock(CFN_RESPONSE_HOST)
        .put(CFN_RESPONSE_PATH, (body: any) => {
          capturedBody = body;
          return true;
        })
        .reply(200);

      const event = createMockEvent('Create');

      await handler.handler(event, mockContext);

      expect(cfnScope.isDone()).toBe(true);
      expect(capturedBody.Status).toBe('FAILED');
      expect(capturedBody.Data.Message).toBe('Access Denied');
    });
  });

  describe('Update event', () => {
    it('should re-upload the baseline on Update', async () => {
      const cfnScope = nock(CFN_RESPONSE_HOST).put(CFN_RESPONSE_PATH).reply(200);
      const event = createMockEvent('Update');

      await handler.handler(event, mockContext);

      expect(s3Mock.commandCalls(PutObjectCommand)).toHaveLength(1);
      expect(cfnScope.isDone()).toBe(true);
    });
  });

  describe('Delete event', () => {
    it('should not upload anything on Delete and send SUCCESS', async () => {
      let capturedBody: any;
      const cfnScope = nock(CFN_RESPONSE_HOST)
        .put(CFN_RESPONSE_PATH, (body: any) => {
          capturedBody = body;
          return true;
        })
        .reply(200);

      const event = createMockEvent('Delete');

      await handler.handler(event, mockContext);

      expect(s3Mock.commandCalls(PutObjectCommand)).toHaveLength(0);
      expect(cfnScope.isDone()).toBe(true);
      expect(capturedBody.Status).toBe('SUCCESS');
    });
  });

  describe('response structure', () => {
    it('should include correct CloudFormation response fields', async () => {
      let capturedBody: any;
      const cfnScope = nock(CFN_RESPONSE_HOST)
        .put(CFN_RESPONSE_PATH, (body: any) => {
          capturedBody = body;
          return true;
        })
        .reply(200);

      const event = createMockEvent('Create');

      await handler.handler(event, mockContext);

      expect(cfnScope.isDone()).toBe(true);
      expect(capturedBody).toEqual({
        Status: 'SUCCESS',
        Reason: `See CloudWatch Log Stream: ${mockContext.logStreamName}`,
        PhysicalResourceId: event.LogicalResourceId,
        StackId: event.StackId,
        RequestId: event.RequestId,
        LogicalResourceId: event.LogicalResourceId,
        Data: {
          Message: 'Windows security baseline configuration uploaded successfully',
          S3Key: 'baseline-overrides/windows-security-baseline.json',
        },
      });
    });
  });
});
