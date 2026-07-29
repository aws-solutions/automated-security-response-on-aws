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
import { ExecutionAlreadyExists, SFNClient, StartExecutionCommand } from '@aws-sdk/client-sfn';
import { Clock } from '../../common/utils/clock';
import { SynchronizationTrigger } from '../customResourceHandler';

const sfnMock = mockClient(SFNClient);

const STATE_MACHINE_ARN = 'arn:aws:states:us-east-1:123456789012:stateMachine:SO0111-ASR-SynchronizationSweep';

// Fixed clock so the deterministic per-UTC-day execution name is asserted against an exact date rather
// than a regex that only passes because the test runs on the same UTC day.
const FIXED_DATE = new Date('2025-01-15T08:30:00Z');
const stubClock: Clock = { now: () => FIXED_DATE };

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
    process.env.SOLUTION_TRADEMARKEDNAME = 'automated-security-response-on-aws';
    process.env.SYNCHRONIZATION_STATE_MACHINE_ARN = STATE_MACHINE_ARN;

    jest.clearAllMocks();
    sfnMock.reset();
    mockTracer.captureAWSv3Client.mockClear();

    synchronizationTrigger = new SynchronizationTrigger(stubClock);

    mockContext = {
      logStreamName: 'test-log-stream',
      getRemainingTimeInMillis: () => 30000,
    } as Context;

    mockEvent = createMockEvent();

    (global.fetch as jest.Mock).mockReset();
    (global.fetch as jest.Mock).mockResolvedValue({
      status: 200,
      statusText: 'OK',
    });

    sfnMock.on(StartExecutionCommand).resolves({
      executionArn: `${STATE_MACHINE_ARN.replace('stateMachine', 'execution')}:run-1`,
    });
  });

  afterEach(() => {
    jest.clearAllMocks();
    delete process.env.SOLUTION_TRADEMARKEDNAME;
    delete process.env.SYNCHRONIZATION_STATE_MACHINE_ARN;
  });

  describe('handler', () => {
    it('starts the sweep state machine and sends a success response on a Create event', async () => {
      await synchronizationTrigger.handler(mockEvent, mockContext);

      const startCalls = sfnMock.commandCalls(StartExecutionCommand);
      expect(startCalls).toHaveLength(1);
      expect(startCalls[0].args[0].input.stateMachineArn).toBe(STATE_MACHINE_ARN);
      // A deterministic per-UTC-day execution name makes the start idempotent; the injected clock lets
      // us assert the exact name rather than a coincidentally-passing regex.
      expect(startCalls[0].args[0].input.name).toBe('initial-sync-2025-01-15');

      expect(global.fetch).toHaveBeenCalledWith(
        mockEvent.ResponseURL,
        expect.objectContaining({
          method: 'PUT',
          body: expect.stringContaining('"Status":"SUCCESS"'),
        }),
      );

      expect(mockLogger.info).toHaveBeenCalledWith('Stack deployment completed, triggering initial synchronization');
    });

    it('treats an already-running sweep (ExecutionAlreadyExists) as success', async () => {
      sfnMock
        .on(StartExecutionCommand)
        .rejects(new ExecutionAlreadyExists({ message: 'already exists', $metadata: {} }));

      await synchronizationTrigger.handler(mockEvent, mockContext);

      // A duplicate start is the desired state, not a failure — the response is still SUCCESS.
      expect(global.fetch).toHaveBeenCalledWith(
        mockEvent.ResponseURL,
        expect.objectContaining({
          method: 'PUT',
          body: expect.stringContaining('"Status":"SUCCESS"'),
        }),
      );
    });

    it('sends a FAILED response when starting the state machine throws', async () => {
      sfnMock.on(StartExecutionCommand).rejects(new Error('StartExecution failed'));

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

    it('skips the trigger when the state machine ARN is not set', async () => {
      delete process.env.SYNCHRONIZATION_STATE_MACHINE_ARN;

      const triggerWithoutEnv = new SynchronizationTrigger(stubClock);
      await triggerWithoutEnv.handler(mockEvent, mockContext);

      expect(sfnMock.commandCalls(StartExecutionCommand)).toHaveLength(0);
      expect(mockLogger.warn).toHaveBeenCalledWith(
        'SYNCHRONIZATION_STATE_MACHINE_ARN not set, skipping synchronization trigger',
      );
    });

    it('sends a success response on an Update event without starting the state machine', async () => {
      const updateEvent = createMockEvent('Update');

      await synchronizationTrigger.handler(updateEvent, mockContext);

      expect(sfnMock.commandCalls(StartExecutionCommand)).toHaveLength(0);
      expect(global.fetch).toHaveBeenCalledWith(
        updateEvent.ResponseURL,
        expect.objectContaining({
          method: 'PUT',
          body: expect.stringContaining('"Status":"SUCCESS"'),
        }),
      );
    });

    it('sends a success response on a Delete event without starting the state machine', async () => {
      const deleteEvent = createMockEvent('Delete');

      await synchronizationTrigger.handler(deleteEvent, mockContext);

      expect(sfnMock.commandCalls(StartExecutionCommand)).toHaveLength(0);
      expect(global.fetch).toHaveBeenCalledWith(
        deleteEvent.ResponseURL,
        expect.objectContaining({
          method: 'PUT',
          body: expect.stringContaining('"Status":"SUCCESS"'),
        }),
      );
    });

    it('includes the correct response structure when the trigger succeeds', async () => {
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

    it('includes the correct response structure when the trigger fails', async () => {
      sfnMock.on(StartExecutionCommand).rejects(new Error('StartExecution failed'));

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
          Warning: 'StartExecution failed',
        },
      });
    });
  });
});
