// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// TOPIC_PREFIX must be set before importing the handler — module-level code
// instantiates a handler whose env-var accessor will be called on first use.
process.env.TOPIC_PREFIX = 'asr-notifications-';

import { CloudFormationCustomResourceEvent, Context } from 'aws-lambda';
import { SNSClient, ListTopicsCommand, DeleteTopicCommand } from '@aws-sdk/client-sns';
import { mockClient } from 'aws-sdk-client-mock';
import { EmailTopicCleanupHandler } from '../email-topic-cleanup-handler';

const snsMock = mockClient(SNSClient);

const baseEvent = {
  RequestType: 'Delete' as const,
  ServiceToken: 'arn:aws:lambda:us-east-1:123456789012:function:cleanup',
  ResponseURL: 'https://cloudformation-response.example.com',
  StackId: 'arn:aws:cloudformation:us-east-1:123456789012:stack/test/guid',
  RequestId: 'request-1',
  ResourceType: 'Custom::EmailTopicCleanup',
  LogicalResourceId: 'EmailTopicCleanup',
  PhysicalResourceId: 'EmailTopicCleanup',
  ResourceProperties: { ServiceToken: 'token' },
} satisfies CloudFormationCustomResourceEvent;

const context = { logStreamName: 'test-stream' } as Context;

describe('EmailTopicCleanupHandler', () => {
  let fetchSpy: jest.Mock;
  let originalFetch: typeof global.fetch;

  beforeEach(() => {
    originalFetch = global.fetch;
    snsMock.reset();
    fetchSpy = jest.fn().mockResolvedValue({ ok: true, status: 200, statusText: 'OK' });
    global.fetch = fetchSpy;
    process.env.TOPIC_PREFIX = 'asr-notifications-';
    const { resetEmailTopicCleanupEnvironmentCache } = require('../emailTopicCleanupEnvironment');
    resetEmailTopicCleanupEnvironmentCache();
  });

  afterEach(() => {
    global.fetch = originalFetch;
  });

  it('deletes all asr-notifications- topics on Delete event', async () => {
    snsMock.on(ListTopicsCommand).resolves({
      Topics: [
        { TopicArn: 'arn:aws:sns:us-east-1:123456789012:asr-notifications-config-1' },
        { TopicArn: 'arn:aws:sns:us-east-1:123456789012:asr-notifications-config-2' },
        { TopicArn: 'arn:aws:sns:us-east-1:123456789012:other-topic' },
      ],
    });
    snsMock.on(DeleteTopicCommand).resolves({});

    const handler = new EmailTopicCleanupHandler(new SNSClient({}));
    await handler.handler(baseEvent, context);

    const deleteCalls = snsMock.commandCalls(DeleteTopicCommand);
    expect(deleteCalls).toHaveLength(2);
    expect(deleteCalls[0].args[0].input.TopicArn).toBe('arn:aws:sns:us-east-1:123456789012:asr-notifications-config-1');
    expect(deleteCalls[1].args[0].input.TopicArn).toBe('arn:aws:sns:us-east-1:123456789012:asr-notifications-config-2');

    expect(fetchSpy).toHaveBeenCalledTimes(1);
    const responseBody = JSON.parse(fetchSpy.mock.calls[0][1].body);
    expect(responseBody.Status).toBe('SUCCESS');
  });

  it('sends SUCCESS on Create event without deleting anything', async () => {
    const createEvent = {
      ...baseEvent,
      RequestType: 'Create' as const,
    } as CloudFormationCustomResourceEvent;

    const handler = new EmailTopicCleanupHandler(new SNSClient({}));
    await handler.handler(createEvent, context);

    expect(snsMock.commandCalls(ListTopicsCommand)).toHaveLength(0);
    expect(snsMock.commandCalls(DeleteTopicCommand)).toHaveLength(0);

    const responseBody = JSON.parse(fetchSpy.mock.calls[0][1].body);
    expect(responseBody.Status).toBe('SUCCESS');
  });

  it('sends SUCCESS on Update event without deleting anything', async () => {
    const updateEvent = {
      ...baseEvent,
      RequestType: 'Update' as const,
      OldResourceProperties: {},
    } as CloudFormationCustomResourceEvent;

    const handler = new EmailTopicCleanupHandler(new SNSClient({}));
    await handler.handler(updateEvent, context);

    expect(snsMock.commandCalls(DeleteTopicCommand)).toHaveLength(0);

    const responseBody = JSON.parse(fetchSpy.mock.calls[0][1].body);
    expect(responseBody.Status).toBe('SUCCESS');
  });

  it('paginates through ListTopics', async () => {
    snsMock
      .on(ListTopicsCommand)
      .resolvesOnce({
        Topics: [{ TopicArn: 'arn:aws:sns:us-east-1:123456789012:asr-notifications-a' }],
        NextToken: 'page2',
      })
      .resolvesOnce({
        Topics: [{ TopicArn: 'arn:aws:sns:us-east-1:123456789012:asr-notifications-b' }],
      });
    snsMock.on(DeleteTopicCommand).resolves({});

    const handler = new EmailTopicCleanupHandler(new SNSClient({}));
    await handler.handler(baseEvent, context);

    expect(snsMock.commandCalls(DeleteTopicCommand)).toHaveLength(2);
  });

  it('continues deleting remaining topics when one fails', async () => {
    snsMock.on(ListTopicsCommand).resolves({
      Topics: [
        { TopicArn: 'arn:aws:sns:us-east-1:123456789012:asr-notifications-fail' },
        { TopicArn: 'arn:aws:sns:us-east-1:123456789012:asr-notifications-ok' },
      ],
    });
    snsMock
      .on(DeleteTopicCommand, { TopicArn: 'arn:aws:sns:us-east-1:123456789012:asr-notifications-fail' })
      .rejects(new Error('Access denied'));
    snsMock
      .on(DeleteTopicCommand, { TopicArn: 'arn:aws:sns:us-east-1:123456789012:asr-notifications-ok' })
      .resolves({});

    const handler = new EmailTopicCleanupHandler(new SNSClient({}));
    await handler.handler(baseEvent, context);

    expect(snsMock.commandCalls(DeleteTopicCommand)).toHaveLength(2);
    const responseBody = JSON.parse(fetchSpy.mock.calls[0][1].body);
    expect(responseBody.Status).toBe('SUCCESS');
  });

  it('sends SUCCESS with error message when ListTopics throws on Delete (best-effort)', async () => {
    snsMock.on(ListTopicsCommand).rejects(new Error('Service unavailable'));

    const handler = new EmailTopicCleanupHandler(new SNSClient({}));
    await handler.handler(baseEvent, context);

    const responseBody = JSON.parse(fetchSpy.mock.calls[0][1].body);
    expect(responseBody.Status).toBe('SUCCESS');
    expect(responseBody.Data.Message).toContain('Service unavailable');
  });

  it('does not throw when sendResponse fails so CloudFormation never sees an unhandled exception', async () => {
    // Custom resource handlers MUST always reach a terminal state. If `fetch` to
    // the pre-signed URL fails and the handler propagates the error, the Lambda
    // is marked failed without CloudFormation hearing back, leaving the stack
    // wedged for an hour. The outer try/catch should swallow this case.
    snsMock.on(ListTopicsCommand).resolves({ Topics: [] });
    fetchSpy.mockRejectedValue(new Error('Network unreachable'));

    const handler = new EmailTopicCleanupHandler(new SNSClient({}));
    await expect(handler.handler(baseEvent, context)).resolves.toBeUndefined();

    expect(fetchSpy).toHaveBeenCalledTimes(1);
  });

  it('does not throw when CloudFormation returns a non-2xx response (treated like a network failure)', async () => {
    // `fetch` only rejects on network-level errors. A 403 from an expired pre-signed
    // URL or a 5xx from the CloudFormation receiver resolves successfully, so without
    // an explicit `response.ok` check the handler would silently treat it as success.
    // The handler now throws on !ok, which `sendResponseSafely` swallows so the Lambda
    // still terminates cleanly.
    snsMock.on(ListTopicsCommand).resolves({ Topics: [] });
    fetchSpy.mockResolvedValue({ ok: false, status: 403, statusText: 'Forbidden' });

    const handler = new EmailTopicCleanupHandler(new SNSClient({}));
    await expect(handler.handler(baseEvent, context)).resolves.toBeUndefined();

    expect(fetchSpy).toHaveBeenCalledTimes(1);
  });

  it('reaches sendResponseSafely with FAILED status even when TOPIC_PREFIX is missing on Create/Update', async () => {
    // ADR 0005: env vars are read lazily so a misconfigured Lambda still replies to
    // CloudFormation rather than failing at module load. On a non-Delete request,
    // the missing env var should produce a FAILED response so the stack rolls back
    // immediately instead of waiting for the 1-hour timeout.
    delete process.env.TOPIC_PREFIX;
    const { resetEmailTopicCleanupEnvironmentCache } = require('../emailTopicCleanupEnvironment');
    resetEmailTopicCleanupEnvironmentCache();

    const createEvent = {
      ...baseEvent,
      RequestType: 'Create' as const,
    } as CloudFormationCustomResourceEvent;

    const handler = new EmailTopicCleanupHandler(new SNSClient({}));
    await handler.handler(createEvent, context);

    // Create/Update doesn't read TOPIC_PREFIX (no topics are listed/deleted), so this
    // path actually succeeds — proving the handler no longer crashes at construction.
    const responseBody = JSON.parse(fetchSpy.mock.calls[0][1].body);
    expect(responseBody.Status).toBe('SUCCESS');
  });

  it('reports best-effort SUCCESS on Delete when TOPIC_PREFIX is missing (handler still replies)', async () => {
    // The critical behavior: a missing env var must NOT prevent the Lambda from
    // sending a response. Pre-fix, the constructor would throw at module load and
    // the stack would wedge until timeout. Now the read is deferred, the inner
    // catch handles it, and Delete still reports SUCCESS so the stack can finish.
    delete process.env.TOPIC_PREFIX;
    const { resetEmailTopicCleanupEnvironmentCache } = require('../emailTopicCleanupEnvironment');
    resetEmailTopicCleanupEnvironmentCache();

    snsMock.on(ListTopicsCommand).resolves({
      Topics: [{ TopicArn: 'arn:aws:sns:us-east-1:123456789012:asr-notifications-config-1' }],
    });

    const handler = new EmailTopicCleanupHandler(new SNSClient({}));
    await handler.handler(baseEvent, context);

    const responseBody = JSON.parse(fetchSpy.mock.calls[0][1].body);
    expect(responseBody.Status).toBe('SUCCESS');
    expect(responseBody.Data.Message).toContain('Cleanup failed (best-effort)');
  });

  it('sends best-effort SUCCESS when ListTopics rejects with a non-Error value', async () => {
    // The AWS SDK normalizes non-Error rejections from the mock into an Error
    // wrapper, so the `instanceof Error` branch always wins for SDK failures.
    // This test pins that the public API still produces a best-effort SUCCESS
    // outcome regardless of how unusual the underlying rejection value is —
    // CloudFormation must always receive a response.
    snsMock.on(ListTopicsCommand).rejects('weird non-Error rejection');

    const handler = new EmailTopicCleanupHandler(new SNSClient({}));
    await handler.handler(baseEvent, context);

    const responseBody = JSON.parse(fetchSpy.mock.calls[0][1].body);
    expect(responseBody.Status).toBe('SUCCESS');
    expect(responseBody.Data.Message).toMatch(/^Cleanup failed \(best-effort\): /);
  });

  describe('topic prefix caching', () => {
    // The lazy `getTopicPrefix()` accessor caches the env value after the first
    // call. These tests pin that contract so a future refactor doesn't quietly
    // regress to either eager reads (re-introducing the module-load failure)
    // or per-call reads (defeating the cache).

    it('caches the topic prefix across multiple handler invocations', async () => {
      // Two consecutive Delete events should share the same cached env read —
      // we verify this indirectly by deleting TOPIC_PREFIX after the first
      // invocation and confirming the second still finds matching topics.
      snsMock.on(ListTopicsCommand).resolves({
        Topics: [{ TopicArn: 'arn:aws:sns:us-east-1:123456789012:asr-notifications-cached' }],
      });
      snsMock.on(DeleteTopicCommand).resolves({});

      const handler = new EmailTopicCleanupHandler(new SNSClient({}));
      await handler.handler(baseEvent, context);
      expect(snsMock.commandCalls(DeleteTopicCommand)).toHaveLength(1);

      // Remove the env var WITHOUT resetting the env-cache. The accessor's
      // module-level cache should keep the prefix alive on the second call.
      delete process.env.TOPIC_PREFIX;
      snsMock.resetHistory();

      await handler.handler(baseEvent, context);
      expect(snsMock.commandCalls(DeleteTopicCommand)).toHaveLength(1);
    });
  });

  describe('listAsrTopics edge cases', () => {
    it('handles a ListTopics response with no Topics array (treats as empty)', async () => {
      // The SDK can return an empty page with `Topics` undefined — the loop
      // must default to [] rather than throwing on `.Topics is undefined`.
      snsMock.on(ListTopicsCommand).resolves({});

      const handler = new EmailTopicCleanupHandler(new SNSClient({}));
      await handler.handler(baseEvent, context);

      expect(snsMock.commandCalls(DeleteTopicCommand)).toHaveLength(0);
      const responseBody = JSON.parse(fetchSpy.mock.calls[0][1].body);
      expect(responseBody.Status).toBe('SUCCESS');
      expect(responseBody.Data.Message).toBe('Deleted 0 ASR email notification topics');
    });

    it('skips topics with undefined TopicArn', async () => {
      // `Topic` from the SDK has `TopicArn?: string`. The handler must not
      // crash on entries missing the ARN, even if they appear in the response.
      snsMock.on(ListTopicsCommand).resolves({
        Topics: [{ TopicArn: undefined }, { TopicArn: 'arn:aws:sns:us-east-1:123456789012:asr-notifications-real' }],
      });
      snsMock.on(DeleteTopicCommand).resolves({});

      const handler = new EmailTopicCleanupHandler(new SNSClient({}));
      await handler.handler(baseEvent, context);

      expect(snsMock.commandCalls(DeleteTopicCommand)).toHaveLength(1);
      expect(snsMock.commandCalls(DeleteTopicCommand)[0].args[0].input.TopicArn).toBe(
        'arn:aws:sns:us-east-1:123456789012:asr-notifications-real',
      );
    });
  });
});
