// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { InvokeCommand, LambdaClient } from '@aws-sdk/client-lambda';
import { mockClient } from 'aws-sdk-client-mock';
import { userPoolId } from '../../common/__tests__/envSetup';
import {
  createAgentCoreContext,
  createAgentCoreEvent,
  createLambdaPayload,
  forwardedApiRequest,
  stubCognitoJwks,
  toolCallResult,
  type ForwardedApiRequest,
  type ToolCallResult,
} from './mcpAuthorizationTestFactories';

// The real verifyAccessToken runs here: tokens carry genuine RS256 signatures and only the
// Cognito JWKS endpoint is stubbed (see stubCognitoJwks). Mocking our own verifier would be
// the `jest.mock` on our own module that unit-testing.md rules out, and would leave the
// token-verification path these dispatch and authorization tests depend on unexercised.

process.env.API_FUNCTION_NAME = 'SO0111-ASR-APIs';
process.env.COGNITO_USER_POOL_ID = userPoolId;
process.env.MCP_GATEWAY_CLIENT_ID = 'gateway-client-1';
process.env.USER_ACCOUNT_MAPPING_TABLE_NAME = 'test-sequences-user-account-mapping';

// Multi-call sequences over the proxied governance tools.
//
// The per-tool dispatch matrix proves each tool reaches its declared route. What it
// cannot see is what happens BETWEEN calls, which is where these two flows actually
// break: an identifier or a version produced by one call has to be carried correctly
// into the next, and both of those hops are values the caller supplies rather than
// anything the tool derives. A tool can be individually correct and the sequence
// still wrong.

const lambdaMock = mockClient(LambdaClient);

import { handler } from '../mcpServerHandler';
import { resetMcpServerEnvironmentCache } from '../mcpServerEnvironment';
import { resetTokenVerifierCache } from '../tokenVerifier';

const clientId = 'gateway-client-1';
const NOTIFICATION_ID = '44444444-4444-4444-8444-444444444444';

/** Every ASR API request the handler proxied, in call order. */
function forwardedCalls(): ForwardedApiRequest[] {
  return lambdaMock.commandCalls(InvokeCommand).map((call) => forwardedApiRequest(call.args[0].input));
}

/** Stand in for the ASR API: per-route responses, so a sequence can carry values forward. */
function stubApi(responder: (path: string, body: Record<string, unknown>) => object): void {
  lambdaMock.on(InvokeCommand).callsFake((input) => {
    const { path, body } = forwardedApiRequest(input);
    return {
      Payload: createLambdaPayload(JSON.stringify({ statusCode: 200, body: JSON.stringify(responder(path, body)) })),
    };
  });
}

async function callAsAdmin(toolName: string, args: Record<string, unknown>): Promise<ToolCallResult> {
  return toolCallResult(
    await handler(createAgentCoreEvent({ groups: ['AdminGroup'], clientId }, args), createAgentCoreContext(toolName)),
  );
}

const notificationBody = {
  name: 'Findings to SNS',
  enabled: true,
  notificationType: 'finding' as const,
  deliveryChannels: [
    { type: 'sns' as const, enabled: true, topicArn: 'arn:aws:sns:us-east-1:123456789012:asr-notify' },
  ],
  batchWindow: { enabled: false },
  contentOptions: {
    includeManualRemediationLink: true,
    includeRemediationDeadline: false,
    includeIaCSnippet: false,
    includeEnableAutomationLink: true,
  },
};

// One JWKS response serves the whole suite: the pool's signing key does not change, so the
// verifier fetches it once and caches it. The cache is cleared first so module state cannot
// leak in from another suite.
beforeAll(() => {
  resetTokenVerifierCache();
  stubCognitoJwks();
});

beforeEach(() => {
  lambdaMock.reset();
  resetMcpServerEnvironmentCache();
});

afterAll(() => lambdaMock.restore());

describe('notification configuration sequence', () => {
  it('carries the id from create into test, update, and delete', async () => {
    // The id only exists after create, and the three routes that follow put it in the
    // URL rather than the body. A tool that kept it in the body would post to the
    // collection endpoint instead — creating a second configuration on "update", and
    // failing outright on test and delete.
    stubApi((path) => {
      if (path === '/notifications') return { id: NOTIFICATION_ID, version: 1 };
      return { message: 'ok' };
    });

    const created = await callAsAdmin('create_notification', notificationBody);
    expect(created.status).toBe(200);
    const newId = created.body.id;

    const tested = await callAsAdmin('test_notification', { id: newId });
    const updated = await callAsAdmin('update_notification', { ...notificationBody, id: newId, version: 1 });
    const deleted = await callAsAdmin('delete_notification', { id: newId });

    expect([tested.status, updated.status, deleted.status]).toEqual([200, 200, 200]);

    const calls = forwardedCalls();
    expect(calls.map((call) => `${call.httpMethod} ${call.path}`)).toEqual([
      'POST /notifications',
      `POST /notifications/${NOTIFICATION_ID}/test`,
      `PUT /notifications/${NOTIFICATION_ID}`,
      `DELETE /notifications/${NOTIFICATION_ID}`,
    ]);
    // The id identifies the resource in the path only.
    for (const call of calls.slice(1)) {
      expect(call.body).not.toHaveProperty('id');
    }
  });

  it('sends the version the API returned, so a stale update is the API’s decision', async () => {
    // Optimistic locking lives in the API. The MCP layer must forward whatever version
    // the caller holds unchanged — silently refreshing it here would defeat the lock and
    // let a stale edit overwrite a concurrent one.
    stubApi((path) => (path === '/notifications' ? { id: NOTIFICATION_ID, version: 7 } : { message: 'ok' }));

    const created = await callAsAdmin('create_notification', notificationBody);
    await callAsAdmin('update_notification', {
      ...notificationBody,
      id: created.body.id,
      version: created.body.version,
    });

    const updateCall = forwardedCalls().find((call) => call.httpMethod === 'PUT');
    expect(updateCall?.body.version).toBe(7);
  });
});

describe('controls tuning sequence', () => {
  it('carries each control’s version from list_controls into update_controls', async () => {
    // update_controls is a read-modify-write: the caller lists controls, flips a flag, and
    // posts them back. The version from the read is what makes the write safe, so it has
    // to survive the round trip per control — not be defaulted or dropped.
    stubApi((path) => {
      if (path === '/controls') {
        return {
          controls: [
            {
              controlId: 'S3.1',
              description: 'S3 one',
              automatedRemediationEnabled: false,
              filters: [],
              filterMode: 'include',
              version: 4,
              lastModified: '2026-01-01T00:00:00Z',
              modifiedBy: 'admin',
            },
            {
              controlId: 'EC2.2',
              description: 'EC2 two',
              automatedRemediationEnabled: false,
              filters: [],
              filterMode: 'include',
              version: 9,
              lastModified: '2026-01-01T00:00:00Z',
              modifiedBy: 'admin',
            },
          ],
        };
      }
      return { message: 'Controls updated successfully', updatedCount: 2 };
    });

    const listed = await callAsAdmin('list_controls', {});
    expect(listed.status).toBe(200);

    const enabled = (listed.body.controls as Record<string, unknown>[]).map((control) => ({
      ...control,
      automatedRemediationEnabled: true,
    }));
    const updated = await callAsAdmin('update_controls', { operation: 'update', data: enabled });

    expect(updated.status).toBe(200);
    const calls = forwardedCalls();
    expect(calls.map((call) => `${call.httpMethod} ${call.path}`)).toEqual([
      'GET /controls',
      'POST /controls/bulk-edit',
    ]);

    const submitted = calls[1].body.data as Array<Record<string, unknown>>;
    expect(submitted.map((control) => [control.controlId, control.version])).toEqual([
      ['S3.1', 4],
      ['EC2.2', 9],
    ]);
    expect(submitted.every((control) => control.automatedRemediationEnabled === true)).toBe(true);
  });

  it('passes the partial-failure detail through, so "some failed" is not read as success', async () => {
    // The route answers 207 when some controls fail. The handler normalizes every 2xx to a
    // 200 envelope — MCP has no HTTP semantics, so the envelope is not where the outcome
    // lives — which makes it the BODY's job to carry the partial failure. If the body were
    // replaced with a generic success payload, a caller would be told every control
    // updated when some did not, and this asserts that cannot happen.
    lambdaMock.on(InvokeCommand).resolves({
      Payload: createLambdaPayload(
        JSON.stringify({
          statusCode: 207,
          body: JSON.stringify({
            message: 'Some controls failed to update.',
            successCount: 1,
            failedControlIds: ['EC2.2'],
          }),
        }),
      ),
    });

    const response = await callAsAdmin('update_controls', {
      operation: 'update',
      data: [
        {
          controlId: 'S3.1',
          description: 'S3 one',
          automatedRemediationEnabled: true,
          filters: [],
          filterMode: 'include',
          version: 4,
          lastModified: '2026-01-01T00:00:00Z',
          modifiedBy: 'admin',
        },
      ],
    });

    expect(response.status).toBe(200);
    expect(response.body.failedControlIds).toEqual(['EC2.2']);
    expect(response.body.successCount).toBe(1);
    expect(response.body.message).toMatch(/failed to update/i);
  });

  // The API's bulk-edit body is a union whose `data` is a controls array for `update` but a
  // filter-id string for the filter operations. That cannot be advertised in a flat
  // one-type-per-field tool schema, so the tool takes `filterId` separately and the proxy
  // is what rebuilds the API body. If the mapping were dropped, the API would receive
  // `{ operation, filterId }`, reject it, and the filter operations would be unusable
  // over MCP — exactly what the advertised schema used to make impossible to even attempt.
  it.each(['applyFilterToAll', 'removeFilterFromAll'] as const)(
    'maps %s with a filterId argument to the API body the bulk-edit route validates',
    async (operation) => {
      const filterId = '550e8400-e29b-41d4-a716-446655440000';
      stubApi(() => ({ message: 'ok', successCount: 3, failedControlIds: [] }));

      const response = await callAsAdmin('update_controls', { operation, filterId });

      expect(response.status).toBe(200);
      const [call] = forwardedCalls();
      expect(`${call.httpMethod} ${call.path}`).toBe('POST /controls/bulk-edit');
      expect(call.body).toEqual({ operation, data: filterId });
    },
  );

  it('rejects a filter operation without filterId, naming the field, before reaching the API', async () => {
    const response = await callAsAdmin('update_controls', { operation: 'applyFilterToAll' });

    expect(response.status).toBe(400);
    expect(response.body.error).toMatch(/filterId is required for operation "applyFilterToAll"/);
    expect(forwardedCalls()).toEqual([]);
  });

  it('rejects an update without data, naming the field, before reaching the API', async () => {
    const response = await callAsAdmin('update_controls', { operation: 'update' });

    expect(response.status).toBe(400);
    expect(response.body.error).toMatch(/data is required for operation "update"/);
    expect(forwardedCalls()).toEqual([]);
  });
});
