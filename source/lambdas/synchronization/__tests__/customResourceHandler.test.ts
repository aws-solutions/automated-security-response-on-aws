// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

const mockLogger = {
  info: jest.fn(),
  debug: jest.fn(),
  warn: jest.fn(),
  error: jest.fn(),
  injectLambdaContext: () => (_target: any, _propertyName: string, descriptor: PropertyDescriptor) => descriptor,
};

jest.mock('../../common/utils/logger', () => ({
  getLogger: jest.fn(() => mockLogger),
}));

global.fetch = jest.fn();

const mockTracer = {
  captureLambdaHandler: () => (_target: any, _propertyName: string, descriptor: PropertyDescriptor) => descriptor,
  captureAWSv3Client: jest.fn((client) => client),
};

jest.mock('../../common/utils/tracer', () => ({
  getTracer: jest.fn(() => mockTracer),
}));

import { CloudFormationCustomResourceEvent, Context } from 'aws-lambda';
import { mockClient } from 'aws-sdk-client-mock';
import { LambdaClient, InvokeCommand } from '@aws-sdk/client-lambda';
import { SynchronizationTrigger } from '../customResourceHandler';

const lambdaMock = mockClient(LambdaClient);

describe('SynchronizationTrigger', () => {
  let synchronizationTrigger: SynchronizationTrigger;
  let mockContext: Context;
  let mockEvent: CloudFormationCustomResourceEvent;

  const createMockEvent = (
    requestType: 'Create' | 'Update' | 'Delete' = 'Create',
  ): CloudFormationCustomResourceEvent => {
    const baseEvent = {
      RequestType: requestType,
      ResponseURL: 'https://cloudformation-custom-resource-response-useast1.s3.amazonaws.com/test',
      StackId: 'arn:aws:cloudformation:us-east-1:123456789012:stack/test-stack/12345',
      RequestId: 'test-request-id',
      ResourceType: 'Custom::SynchronizationTrigger',
      LogicalResourceId: 'InitialSynchronizationTrigger',
      ServiceToken: 'arn:aws:lambda:us-east-1:123456789012:function:test-provider',
      ResourceProperties: {
        ServiceToken: 'arn:aws:lambda:us-east-1:123456789012:function:test-provider',
        TriggerReason: 'WebUI deployment completed',
      },
    };

    if (requestType === 'Update' || requestType === 'Delete') {
      return {
        ...baseEvent,
        PhysicalResourceId: 'InitialSynchronizationTrigger',
      } as CloudFormationCustomResourceEvent;
    }

    return baseEvent as CloudFormationCustomResourceEvent;
  };

  beforeEach(() => {
    // Set environment variables
    process.env.SOLUTION_TRADEMARKEDNAME = 'automated-security-response-on-aws';
    process.env.SYNCHRONIZATION_FUNCTION_NAME = 'test-synchronization-function';

    // Reset all mocks
    jest.clearAllMocks();
    lambdaMock.reset();
    mockTracer.captureAWSv3Client.mockClear();
    (global.fetch as jest.Mock).mockClear();

    synchronizationTrigger = new SynchronizationTrigger();

    mockContext = {
      logStreamName: 'test-log-stream',
      getRemainingTimeInMillis: () => 30000,
    } as Context;

    mockEvent = createMockEvent();

    // Reset and setup fetch mock
    (global.fetch as jest.Mock).mockReset();
    (global.fetch as jest.Mock).mockResolvedValue({
      status: 200,
      statusText: 'OK',
    });

    lambdaMock.on(InvokeCommand).resolves({
      StatusCode: 202,
    });
  });

  afterEach(() => {
    jest.clearAllMocks();
    delete process.env.SOLUTION_TRADEMARKEDNAME;
    delete process.env.SYNCHRONIZATION_FUNCTION_NAME;
  });

  describe('handler', () => {
    it('should verify Lambda client mock is working', () => {
      expect(lambdaMock).toBeDefined();
      expect(mockTracer.captureAWSv3Client).toBeDefined();
      expect(process.env.SYNCHRONIZATION_FUNCTION_NAME).toBe('test-synchronization-function');
    });

    it('should trigger synchronization and send success response on Create event', async () => {
      await synchronizationTrigger.handler(mockEvent, mockContext);

      expect(mockTracer.captureAWSv3Client).toHaveBeenCalled();

      expect(lambdaMock.commandCalls(InvokeCommand)).toHaveLength(1);
      const invokeCall = lambdaMock.commandCalls(InvokeCommand)[0];
      expect(invokeCall.args[0].input).toEqual(
        expect.objectContaining({
          FunctionName: 'test-synchronization-function',
          InvocationType: 'Event',
          Payload: expect.stringContaining('"source":"custom-resource"'),
        }),
      );

      expect(global.fetch).toHaveBeenCalledWith(
        mockEvent.ResponseURL,
        expect.objectContaining({
          method: 'PUT',
          body: expect.stringContaining('"Status":"SUCCESS"'),
        }),
      );

      expect(mockLogger.info).toHaveBeenCalledWith('Stack deployment completed, triggering initial synchronization');
    });

    it('should handle synchronization trigger failure gracefully', async () => {
      lambdaMock.on(InvokeCommand).rejects(new Error('Lambda invocation failed'));

      await synchronizationTrigger.handler(mockEvent, mockContext);

      expect(global.fetch).toHaveBeenCalledWith(
        mockEvent.ResponseURL,
        expect.objectContaining({
          method: 'PUT',
          body: expect.stringContaining('"Status":"FAILED"'),
        }),
      );

      expect(mockLogger.error).toHaveBeenCalledWith('Failed to trigger synchronization', expect.any(Object));
    });

    it('should skip synchronization trigger when function name not set', async () => {
      const originalFunctionName = process.env.SYNCHRONIZATION_FUNCTION_NAME;
      delete process.env.SYNCHRONIZATION_FUNCTION_NAME;

      try {
        const triggerWithoutEnv = new SynchronizationTrigger();
        await triggerWithoutEnv.handler(mockEvent, mockContext);

        expect(lambdaMock.commandCalls(InvokeCommand)).toHaveLength(0);
        expect(mockLogger.warn).toHaveBeenCalledWith(
          'SYNCHRONIZATION_FUNCTION_NAME not set, skipping synchronization trigger',
        );
      } finally {
        if (originalFunctionName) {
          process.env.SYNCHRONIZATION_FUNCTION_NAME = originalFunctionName;
        }
      }
    });

    it('should send success response on Update event', async () => {
      const updateEvent = createMockEvent('Update');

      await synchronizationTrigger.handler(updateEvent, mockContext);

      expect(global.fetch).toHaveBeenCalledWith(
        updateEvent.ResponseURL,
        expect.objectContaining({
          method: 'PUT',
          body: expect.stringContaining('"Status":"SUCCESS"'),
        }),
      );
    });

    it('should send success response on Delete event', async () => {
      const deleteEvent = createMockEvent('Delete');

      await synchronizationTrigger.handler(deleteEvent, mockContext);

      expect(global.fetch).toHaveBeenCalledWith(
        deleteEvent.ResponseURL,
        expect.objectContaining({
          method: 'PUT',
          body: expect.stringContaining('"Status":"SUCCESS"'),
        }),
      );
    });

    it('should include correct response structure when synchronization succeeds', async () => {
      await synchronizationTrigger.handler(mockEvent, mockContext);

      const responseCall = (global.fetch as jest.Mock).mock.calls[0];
      const responseBody = JSON.parse(responseCall[1].body);

      expect(responseBody).toEqual({
        Status: 'SUCCESS',
        Reason: `See CloudWatch Log Stream: ${mockContext.logStreamName}`,
        PhysicalResourceId: mockEvent.LogicalResourceId,
        StackId: mockEvent.StackId,
        RequestId: mockEvent.RequestId,
        LogicalResourceId: mockEvent.LogicalResourceId,
        Data: {
          Message: 'Custom resource created successfully, initial synchronization triggered',
        },
      });
    });

    it('should include correct response structure when synchronization fails', async () => {
      lambdaMock.on(InvokeCommand).rejects(new Error('Lambda invocation failed'));

      await synchronizationTrigger.handler(mockEvent, mockContext);

      const responseCall = (global.fetch as jest.Mock).mock.calls[0];
      const responseBody = JSON.parse(responseCall[1].body);

      expect(responseBody).toEqual({
        Status: 'FAILED',
        Reason: `See CloudWatch Log Stream: ${mockContext.logStreamName}`,
        PhysicalResourceId: mockEvent.LogicalResourceId,
        StackId: mockEvent.StackId,
        RequestId: mockEvent.RequestId,
        LogicalResourceId: mockEvent.LogicalResourceId,
        Data: {
          Message: 'Custom resource created successfully, but synchronization trigger failed.',
          Warning: 'Lambda invocation failed',
        },
      });
    });
  });
});
