// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { AdminGetUserCommand, CognitoIdentityProviderClient } from '@aws-sdk/client-cognito-identity-provider';
import { InvokeCommand, LambdaClient } from '@aws-sdk/client-lambda';
import { mockClient } from 'aws-sdk-client-mock';
import { userPoolId, userAccountMappingTableName } from '../../common/__tests__/envSetup';
import {
  createAgentCoreContext,
  createAgentCoreEvent,
  createLambdaPayload,
  createMachineAgentCoreEvent,
  stubCognitoJwks,
} from './mcpAuthorizationTestFactories';

// The real verifyAccessToken runs here: tokens carry genuine RS256 signatures and only the
// Cognito JWKS endpoint is stubbed (see stubCognitoJwks). Mocking our own verifier would be
// the `jest.mock` on our own module that unit-testing.md rules out, and would leave the
// token-verification path these dispatch and authorization tests depend on unexercised.

process.env.API_FUNCTION_NAME = 'SO0111-ASR-APIs';
process.env.COGNITO_USER_POOL_ID = userPoolId;
process.env.MCP_GATEWAY_CLIENT_ID = 'gateway-client-1';

// The per-user grant read runs through the real UserAccountMappingRepository against
// DynamoDB Local. Stubbing the repository would be mocking our own code, and it would
// assert nothing about the real key schema or the lowercase-key fallback the handler
// depends on to authorize a caller. Grants are therefore seeded as actual table items
// and the assertions are behavioral (what the handler decides) rather than call counts.

let userAuthorizationRepository: UserAccountMappingRepository;

const cognitoMock = mockClient(CognitoIdentityProviderClient);
const lambdaMock = mockClient(LambdaClient);

import { DynamoDBTestSetup } from '../../common/__tests__/dynamodbSetup';
import { UserAccountMappingRepository } from '../../common/repositories/userAccountMappingRepository';
import { DynamoDBDocumentClient } from '@aws-sdk/lib-dynamodb';
import { handler } from '../mcpServerHandler';
import { resetMcpServerEnvironmentCache } from '../mcpServerEnvironment';
import { resetTokenVerifierCache } from '../tokenVerifier';
import {
  MCP_TOOL_ERROR_METRIC,
  MCP_TOOL_INVOCATION_METRIC,
  MCP_TOOL_LATENCY_METRIC,
  MCP_TOOL_NAME_DIMENSION,
} from '../../common/utils/cloudWatchMetrics';

const clientId = 'gateway-client-1';
const username = 'test.user';
const userEmail = 'test.user@example.com';

function stubApiLambda(responseBody: object = { runbooks: [] }, statusCode = 200): void {
  lambdaMock.on(InvokeCommand).resolves({
    Payload: createLambdaPayload(JSON.stringify({ statusCode, body: JSON.stringify(responseBody) })),
  });
}

function stubCognitoEmail(email: string | null = userEmail): void {
  cognitoMock
    .on(AdminGetUserCommand, { UserPoolId: userPoolId, Username: username })
    .resolves({ UserAttributes: email ? [{ Name: 'email', Value: email }] : [] });
}

/**
 * Seed the caller's authorization record so the handler's real repository read finds it.
 * `accountIds` is written alongside the grant because the two live on one item — writing
 * only the grant is exactly the split-record bug the repository now guards against.
 */
async function seedUserGrant(allowedTools: readonly string[], accountIds: readonly string[] = []): Promise<void> {
  await userAuthorizationRepository.create({
    userId: userEmail,
    accountIds: [...accountIds],
    allowedMcpTools: [...allowedTools],
  });
}

beforeAll(async () => {
  // One JWKS response serves the whole suite: the pool's signing key does not change, so the
  // verifier fetches it once and caches it. The cache is cleared first so module state cannot
  // leak in from another suite.
  resetTokenVerifierCache();
  stubCognitoJwks();
  await DynamoDBTestSetup.createUserAccountMappingTable(userAccountMappingTableName);
  userAuthorizationRepository = new UserAccountMappingRepository(
    'test-principal',
    userAccountMappingTableName,
    DynamoDBTestSetup.getDocClient(),
  );
});

beforeEach(async () => {
  cognitoMock.reset();
  lambdaMock.reset();
  jest.restoreAllMocks();
  // Each test starts with no authorization record, so a test that never seeds one is
  // genuinely exercising the "no grant" path.
  await userAuthorizationRepository.deleteIfExists(userEmail, '');
  resetMcpServerEnvironmentCache();
});

afterAll(() => {
  cognitoMock.restore();
  lambdaMock.restore();
});

describe('MCP server handler authorization', () => {
  it('grants Admin every tool automatically without user or grant lookups', async () => {
    // GIVEN
    stubApiLambda();
    const event = createAgentCoreEvent({ groups: ['AdminGroup'], clientId }, { finding_id: 'finding-1' });

    // WHEN
    const response = await handler(event, createAgentCoreContext('execute_runbook'));

    // THEN
    expect(response.statusCode).toBe(200);
    expect(cognitoMock.commandCalls(AdminGetUserCommand)).toHaveLength(0);
    // No authorization record was seeded, so succeeding here proves Admin bypassed the
    // per-user grant read entirely rather than being allowed by a stored grant.
    expect(lambdaMock.commandCalls(InvokeCommand)).toHaveLength(1);
  });

  it('resolves a Delegated Admin username and allows an explicitly granted tool', async () => {
    // GIVEN
    stubCognitoEmail();
    await seedUserGrant(['execute_runbook']);
    stubApiLambda();
    const event = createAgentCoreEvent({ groups: ['DelegatedAdminGroup'], clientId }, { finding_id: 'finding-1' });

    // WHEN
    const response = await handler(event, createAgentCoreContext('execute_runbook'));

    // THEN
    expect(response.statusCode).toBe(200);
    expect(cognitoMock.commandCalls(AdminGetUserCommand)).toHaveLength(1);
    expect(lambdaMock.commandCalls(InvokeCommand)).toHaveLength(1);
  });

  it('denies a Delegated Admin tool that was not granted in the Users panel', async () => {
    // GIVEN
    stubCognitoEmail();
    await seedUserGrant(['list_runbooks']);
    const event = createAgentCoreEvent({ groups: ['DelegatedAdminGroup'], clientId }, { finding_id: 'finding-1' });

    // WHEN
    const response = await handler(event, createAgentCoreContext('execute_runbook'));

    // THEN
    expect(response.statusCode).toBe(403);
    expect(JSON.parse(response.body).error).toContain(`tool 'execute_runbook' is not granted to user '${userEmail}'`);
    expect(lambdaMock.commandCalls(InvokeCommand)).toHaveLength(0);
  });

  it('allows an Account Operator tool explicitly granted by an Admin or Delegated Admin', async () => {
    // GIVEN
    stubCognitoEmail();
    await seedUserGrant(['list_*']);
    stubApiLambda();
    const event = createAgentCoreEvent({ groups: ['AccountOperatorGroup'], clientId });

    // WHEN
    const response = await handler(event, createAgentCoreContext('list_runbooks'));

    // THEN
    expect(response.statusCode).toBe(200);
    const invocationPayload = lambdaMock.commandCalls(InvokeCommand)[0]?.args[0].input.Payload;
    if (!(invocationPayload instanceof Uint8Array)) {
      throw new Error('Expected the API Lambda invocation payload to be a byte array');
    }
    expect(JSON.parse(Buffer.from(invocationPayload).toString('utf8'))).toMatchObject({
      body: '{}',
      httpMethod: 'POST',
      path: '/runbooks/list',
      requestContext: {
        authorizer: {
          claims: {
            'cognito:groups': ['AccountOperatorGroup'],
            client_id: clientId,
            token_use: 'access',
            username,
          },
        },
      },
    });
  });

  it('does not let an Account Operator grant widen the role capability ceiling', async () => {
    // GIVEN
    stubCognitoEmail();
    await seedUserGrant(['*']);
    const event = createAgentCoreEvent({ groups: ['AccountOperatorGroup'], clientId }, { finding_id: 'finding-1' });

    // WHEN
    const response = await handler(event, createAgentCoreContext('execute_runbook'));

    // THEN
    expect(response.statusCode).toBe(403);
    expect(JSON.parse(response.body).error).toContain("not permitted for the 'AccountOperator' access tier");
    expect(lambdaMock.commandCalls(InvokeCommand)).toHaveLength(0);
  });

  it('fails closed with a retryable response when the user grant cannot be read', async () => {
    // GIVEN
    stubCognitoEmail();
    // Fail at the AWS SDK boundary so the real repository's error propagation is what
    // gets exercised, not a stubbed rejection from our own code.
    jest.spyOn(DynamoDBDocumentClient.prototype, 'send').mockRejectedValue(new Error('DynamoDB unavailable') as never);
    const event = createAgentCoreEvent({ groups: ['DelegatedAdminGroup'], clientId }, { finding_id: 'finding-1' });

    // WHEN
    const response = await handler(event, createAgentCoreContext('execute_runbook'));

    // THEN
    expect(response.statusCode).toBe(503);
    const body = JSON.parse(response.body) as { error: string };
    expect(body.error).toContain('user MCP tool grant');
    expect(body.error).toContain('retry');
    expect(body.error).not.toContain('DynamoDB unavailable');
    expect(lambdaMock.commandCalls(InvokeCommand)).toHaveLength(0);
  });

  it('fails closed with a retryable response when Cognito user resolution fails', async () => {
    // GIVEN
    cognitoMock.on(AdminGetUserCommand).rejects(new Error('Cognito unavailable'));
    const event = createAgentCoreEvent({ groups: ['DelegatedAdminGroup'], clientId });

    // WHEN
    const response = await handler(event, createAgentCoreContext('list_runbooks'));

    // THEN
    expect(response.statusCode).toBe(503);
    expect(JSON.parse(response.body).error).toContain('retry');
    expect(JSON.parse(response.body).error).not.toContain('Cognito unavailable');
    expect(lambdaMock.commandCalls(InvokeCommand)).toHaveLength(0);
  });

  it('denies a Cognito user without an email attribute', async () => {
    // GIVEN
    stubCognitoEmail(null);
    const event = createAgentCoreEvent({ groups: ['DelegatedAdminGroup'], clientId });

    // WHEN
    const response = await handler(event, createAgentCoreContext('list_runbooks'));

    // THEN
    expect(response.statusCode).toBe(403);
    expect(JSON.parse(response.body).error).toContain('no email attribute');
    expect(lambdaMock.commandCalls(InvokeCommand)).toHaveLength(0);
  });

  it('denies a caller whose groups map to no recognized ASR tier', async () => {
    // GIVEN
    const event = createAgentCoreEvent({ groups: ['SomeUnmappedGroup'], clientId });

    // WHEN
    const response = await handler(event, createAgentCoreContext('list_runbooks'));

    // THEN
    expect(response.statusCode).toBe(403);
    expect(JSON.parse(response.body).error).toContain('no recognized ASR group');
    expect(cognitoMock.commandCalls(AdminGetUserCommand)).toHaveLength(0);
  });

  it('denies a human caller carrying no groups', async () => {
    // GIVEN
    const event = createAgentCoreEvent({ clientId });

    // WHEN
    const response = await handler(event, createAgentCoreContext('list_runbooks'));

    // THEN
    expect(response.statusCode).toBe(403);
    expect(cognitoMock.commandCalls(AdminGetUserCommand)).toHaveLength(0);
  });

  it('denies a machine token before Cognito or DynamoDB lookup', async () => {
    // GIVEN
    const event = createMachineAgentCoreEvent(clientId);

    // WHEN
    const response = await handler(event, createAgentCoreContext('list_runbooks'));

    // THEN
    expect(response.statusCode).toBe(403);
    expect(JSON.parse(response.body).error).toContain('MCP is human-only');
    expect(cognitoMock.commandCalls(AdminGetUserCommand)).toHaveLength(0);
    expect(lambdaMock.commandCalls(InvokeCommand)).toHaveLength(0);
  });

  it('denies a human access token without a username', async () => {
    // GIVEN
    const event = createAgentCoreEvent({ groups: ['DelegatedAdminGroup'], clientId, username: null });

    // WHEN
    const response = await handler(event, createAgentCoreContext('list_runbooks'));

    // THEN
    expect(response.statusCode).toBe(403);
    expect(JSON.parse(response.body).error).toContain("no 'username' claim");
    expect(cognitoMock.commandCalls(AdminGetUserCommand)).toHaveLength(0);
  });

  it('rejects a request without a forwarded Authorization header', async () => {
    // WHEN
    const response = await handler({}, createAgentCoreContext('list_runbooks'));

    // THEN
    expect(response.statusCode).toBe(403);
    expect(JSON.parse(response.body).error).toContain('No Cognito identity found');
  });

  it('returns a bad gateway response when the API Lambda reports a function error', async () => {
    // GIVEN
    lambdaMock.on(InvokeCommand).resolves({
      FunctionError: 'Unhandled',
      Payload: createLambdaPayload(JSON.stringify({ errorType: 'Error', errorMessage: 'failure' })),
    });
    const event = createAgentCoreEvent({ groups: ['AdminGroup'], clientId });

    // WHEN
    const response = await handler(event, createAgentCoreContext('list_runbooks'));

    // THEN
    expect(response.statusCode).toBe(502);
    expect(JSON.parse(response.body).error).toBe('ASR API Lambda invocation failed');
  });

  it('returns a bad gateway response when the API Lambda payload is invalid', async () => {
    // GIVEN
    lambdaMock.on(InvokeCommand).resolves({ Payload: createLambdaPayload('not-json') });
    const event = createAgentCoreEvent({ groups: ['AdminGroup'], clientId });

    // WHEN
    const response = await handler(event, createAgentCoreContext('list_runbooks'));

    // THEN
    expect(response.statusCode).toBe(502);
    expect(JSON.parse(response.body).error).toBe('ASR API Lambda returned an invalid response');
  });

  it('propagates a non-success API status and reduces its body to a readable sentence', async () => {
    // GIVEN
    stubApiLambda({ message: 'Forbidden' }, 403);
    const event = createAgentCoreEvent({ groups: ['AdminGroup'], clientId });

    // WHEN
    const response = await handler(event, createAgentCoreContext('list_runbooks'));

    // THEN
    expect(response.statusCode).toBe(403);
    expect(JSON.parse(response.body).error).toBe('Forbidden');
  });

  it('does not double-encode an API error body into the error field', async () => {
    // GIVEN the shape the ASR API actually returns on a version conflict. Forwarding the whole JSON
    // body as the error message produced {"error":"{\"error\":\"ConflictError\",...}"} — a client had
    // to JSON.parse twice, and an agent printing body.error showed the user an escaped blob for
    // exactly the errors worth reading.
    stubApiLambda({ error: 'ConflictError', message: 'Data was modified by another user - please refresh.' }, 409);
    const event = createAgentCoreEvent({ groups: ['AdminGroup'], clientId });

    // WHEN
    const response = await handler(event, createAgentCoreContext('list_runbooks'));

    // THEN
    expect(response.statusCode).toBe(409);
    const { error } = JSON.parse(response.body) as { error: string };
    expect(error).toBe('ConflictError: Data was modified by another user - please refresh.');
    // The error field is a plain sentence, not another JSON document.
    expect(() => JSON.parse(error) as unknown).toThrow();
  });

  it('carries the API error code and context through, so a conflict names the version to refresh to', async () => {
    // GIVEN the structured 409 the ASR API returns on a version conflict. `describeApiFailure`
    // reduces the body to one sentence for `error`; the agent-facing `code` and `context` the
    // API computed must not be lost in that reduction — they are how a client learns what to
    // resend without a second read.
    stubApiLambda(
      {
        error: 'ConflictError',
        message: 'Data was modified by another user, please refresh',
        code: 'VERSION_CONFLICT',
        context: { filterId: 'f-1', expectedVersion: 1, currentVersion: 5 },
      },
      409,
    );
    const event = createAgentCoreEvent({ groups: ['AdminGroup'], clientId });

    // WHEN
    const response = await handler(event, createAgentCoreContext('list_runbooks'));

    // THEN
    expect(response.statusCode).toBe(409);
    expect(JSON.parse(response.body)).toEqual({
      error: 'ConflictError: Data was modified by another user, please refresh',
      code: 'VERSION_CONFLICT',
      context: { filterId: 'f-1', expectedVersion: 1, currentVersion: 5 },
    });
  });

  it('omits code and context when the API error carries none', async () => {
    stubApiLambda({ error: 'NotFoundError', message: 'Filter f-1 not found' }, 404);
    const event = createAgentCoreEvent({ groups: ['AdminGroup'], clientId });

    const response = await handler(event, createAgentCoreContext('list_runbooks'));

    expect(response.statusCode).toBe(404);
    expect(JSON.parse(response.body)).toEqual({ error: 'NotFoundError: Filter f-1 not found' });
  });

  it('unwraps an API error body whose error field is itself a JSON string', async () => {
    // GIVEN the nested form seen live from /controls/bulk-edit, where the API handler stringified
    // its own error payload into the `error` field before the gateway wrapped it again.
    stubApiLambda(
      { error: JSON.stringify({ error: 'ConflictError', message: 'All Controls failed to update.' }) },
      409,
    );
    const event = createAgentCoreEvent({ groups: ['AdminGroup'], clientId });

    // WHEN
    const response = await handler(event, createAgentCoreContext('list_runbooks'));

    // THEN
    expect(response.statusCode).toBe(409);
    expect(JSON.parse(response.body).error).toBe('ConflictError: All Controls failed to update.');
  });

  it('does not forward the interceptor bearer token in a passthrough API request body', async () => {
    // GIVEN
    stubApiLambda();
    // The full filter body, because `update_filter` advertises and validates it
    // rather than relying on passthrough — see the comment on
    // `UpdateFilterToolSchema` in handler.ts for why that changed.
    const filterBody = {
      name: 'updated filter',
      accountIds: ['111122223333'],
      organizationalUnits: [],
      tags: [],
      arnPatterns: [],
      version: 1,
    };
    const event = createAgentCoreEvent({ groups: ['AdminGroup'], clientId }, { filterId: 'filter-1', ...filterBody });

    // WHEN
    const response = await handler(event, createAgentCoreContext('update_filter'));

    // THEN
    expect(response.statusCode).toBe(200);
    const invocationPayload = lambdaMock.commandCalls(InvokeCommand)[0]?.args[0].input.Payload;
    if (!(invocationPayload instanceof Uint8Array)) {
      throw new Error('Expected the API Lambda invocation payload to be a byte array');
    }
    const apiEvent = JSON.parse(Buffer.from(invocationPayload).toString('utf8')) as { body: string };
    // The path param is lifted into the URL; everything else is the request body.
    expect(JSON.parse(apiEvent.body)).toEqual(filterBody);
    expect(apiEvent.body).not.toContain('__authorizationHeader');
    expect(apiEvent.body).not.toContain('Bearer ');
  });

  it('logs the original unexpected error while returning a generic 500', async () => {
    // GIVEN
    const logSpy = jest.spyOn(console, 'error').mockImplementation();
    lambdaMock.on(InvokeCommand).rejects(new Error('Lambda transport exploded'));
    const event = createAgentCoreEvent({ groups: ['AdminGroup'], clientId });

    try {
      // WHEN
      const response = await handler(event, createAgentCoreContext('list_runbooks'));

      // THEN the caller gets nothing but a generic message
      expect(response.statusCode).toBe(500);
      expect(JSON.parse(response.body).error).toBe('Internal server error');

      // ...while the underlying cause is preserved in the structured log. The
      // Powertools logger emits one JSON document per entry, so the assertion reads
      // the emitted record rather than positional console arguments.
      expect(logSpy).toHaveBeenCalledTimes(1);
      const logged = JSON.parse(logSpy.mock.calls[0][0] as string) as Record<string, unknown>;
      expect(logged).toMatchObject({
        level: 'ERROR',
        message: 'FAIL',
        statusCode: 500,
        errorName: 'Error',
        errorMessage: 'Lambda transport exploded',
      });
    } finally {
      logSpy.mockRestore();
    }
  });
});

describe('MCP server handler tool-name resolution', () => {
  it('rejects a token whose signature does not verify, before any claim is trusted', async () => {
    // A genuinely forged token: same claims as a valid Admin one, signed with a key the
    // stubbed pool does not publish. Only the signature distinguishes it, so this proves the
    // handler verifies rather than merely decodes — the groups claim says AdminGroup and
    // would otherwise sail through. The verifier's own cases (alg confusion, expiry, issuer,
    // wrong app client) are covered in tokenVerifier.test.ts.
    stubApiLambda();

    const response = await handler(
      createAgentCoreEvent(
        { groups: ['AdminGroup'], clientId, signedWithUnpublishedKey: true },
        { finding_id: 'finding-1' },
      ),
      createAgentCoreContext('execute_runbook'),
    );

    expect(response.statusCode).toBe(403);
    expect(JSON.parse(response.body).error).toMatch(/Access denied/);
    // Nothing downstream ran: no tool dispatched, no API call made.
    expect(lambdaMock.commandCalls(InvokeCommand)).toHaveLength(0);
  });

  it('rejects an expired token', async () => {
    // The gateway checks expiry too, but a caller invoking this Lambda directly bypasses it,
    // so the handler's own verification is what refuses a replayed stale token.
    stubApiLambda();

    const response = await handler(
      createAgentCoreEvent({ groups: ['AdminGroup'], clientId, expiresInSeconds: -60 }, { finding_id: 'finding-1' }),
      createAgentCoreContext('execute_runbook'),
    );

    expect(response.statusCode).toBe(403);
    expect(lambdaMock.commandCalls(InvokeCommand)).toHaveLength(0);
  });

  it('resolves a bare tool name without stripping its first characters', async () => {
    // GIVEN
    stubApiLambda();
    const event = createAgentCoreEvent({ groups: ['AdminGroup'], clientId });

    // WHEN
    const response = await handler(event, createAgentCoreContext('list_runbooks', { prefixed: false }));

    // THEN
    expect(response.statusCode).toBe(200);
    expect(lambdaMock.commandCalls(InvokeCommand)).toHaveLength(1);
  });

  it('resolves a prefixed tool name by stripping only the prefix', async () => {
    // GIVEN
    stubApiLambda();
    const event = createAgentCoreEvent({ groups: ['AdminGroup'], clientId });

    // WHEN
    const response = await handler(event, createAgentCoreContext('list_runbooks'));

    // THEN
    expect(response.statusCode).toBe(200);
  });

  it('returns a structured 400 when the context carries an empty tool name', async () => {
    // GIVEN
    const event = createAgentCoreEvent({ groups: ['AdminGroup'], clientId });
    const context = createAgentCoreContext('', { prefixed: false });

    // WHEN
    const response = await handler(event, context);

    // THEN
    expect(response.statusCode).toBe(400);
    expect(JSON.parse(response.body).error).toMatch(/no tool name/i);
  });
});

describe('MCP server handler invoked-ARN parsing', () => {
  it.each([
    ['an empty ARN', ''],
    ['a truncated ARN', 'arn:aws:lambda:us-east-1'],
    ['a non-numeric account', 'arn:aws:lambda:us-east-1:NOTANACCOUNT:function:SO0111-ASR-MCP-Server'],
    ['a non-Lambda ARN', 'arn:aws:iam::123456789012:role/SO0111-Something'],
  ])('returns 500 rather than attributing a call to an undefined account for %s', async (_case, invokedArn) => {
    // Indexing split(':') directly yielded `undefined`, which then reached the API request
    // context and the recorded test result — and stringified into IAM ARNs as the literal
    // 'undefined'. Failing loudly is the point; a silently wrong account is not acceptable.
    stubApiLambda();
    const event = createAgentCoreEvent({ groups: ['AdminGroup'], clientId });

    const response = await handler(event, createAgentCoreContext('list_runbooks', { invokedFunctionArn: invokedArn }));

    expect(response.statusCode).toBe(500);
    expect(lambdaMock.commandCalls(InvokeCommand)).toHaveLength(0);
  });

  it('accepts a non-commercial partition, which must not be inferred from the region', async () => {
    stubApiLambda();
    const event = createAgentCoreEvent({ groups: ['AdminGroup'], clientId });

    const response = await handler(
      event,
      createAgentCoreContext('list_runbooks', {
        invokedFunctionArn: 'arn:aws-us-gov:lambda:us-gov-west-1:123456789012:function:SO0111-ASR-MCP-Server',
      }),
    );

    expect(response.statusCode).toBe(200);
  });
});

interface CapturedMetric {
  readonly name: string;
  readonly value: number;
  readonly unit: string;
  readonly toolName: string | undefined;
}

/**
 * Parse the EMF metric documents the handler wrote to stdout. Only lines that
 * are standalone JSON with an `_aws` directive are metrics; the handler's log
 * lines are ignored.
 */
function capturedMetrics(writeSpy: jest.SpyInstance): CapturedMetric[] {
  const metrics: CapturedMetric[] = [];
  for (const call of writeSpy.mock.calls) {
    const line = call[0];
    if (typeof line !== 'string') continue;
    let doc: Record<string, unknown>;
    try {
      doc = JSON.parse(line);
    } catch {
      continue;
    }
    const aws = doc['_aws'] as { CloudWatchMetrics?: { Metrics?: { Name: string; Unit: string }[] }[] } | undefined;
    const directives = aws?.CloudWatchMetrics;
    if (!Array.isArray(directives)) continue;
    for (const directive of directives) {
      for (const metric of directive.Metrics ?? []) {
        metrics.push({
          name: metric.Name,
          value: doc[metric.Name] as number,
          unit: metric.Unit,
          toolName: doc[MCP_TOOL_NAME_DIMENSION] as string | undefined,
        });
      }
    }
  }
  return metrics;
}

describe('MCP server handler tool metrics', () => {
  let writeSpy: jest.SpyInstance;

  beforeEach(() => {
    // Set up after the outer beforeEach, which calls jest.restoreAllMocks().
    writeSpy = jest.spyOn(process.stdout, 'write').mockImplementation(() => true);
  });

  it('emits invocation and latency, and no error, on the success path', async () => {
    stubApiLambda();
    const event = createAgentCoreEvent({ groups: ['AdminGroup'], clientId }, { finding_id: 'finding-1' });

    const response = await handler(event, createAgentCoreContext('execute_runbook'));
    expect(response.statusCode).toBe(200);

    const metrics = capturedMetrics(writeSpy);
    const invocation = metrics.find((metric) => metric.name === MCP_TOOL_INVOCATION_METRIC);
    const latency = metrics.find((metric) => metric.name === MCP_TOOL_LATENCY_METRIC);
    expect(invocation).toEqual({
      name: MCP_TOOL_INVOCATION_METRIC,
      value: 1,
      unit: 'Count',
      toolName: 'execute_runbook',
    });
    expect(latency?.unit).toBe('Milliseconds');
    expect(latency?.toolName).toBe('execute_runbook');
    expect(metrics.some((metric) => metric.name === MCP_TOOL_ERROR_METRIC)).toBe(false);
  });

  it('emits the error metric on a 5xx failure', async () => {
    stubApiLambda({ error: 'boom' }, 500);
    const event = createAgentCoreEvent({ groups: ['AdminGroup'], clientId }, { finding_id: 'finding-1' });

    const response = await handler(event, createAgentCoreContext('execute_runbook'));
    expect(response.statusCode).toBeGreaterThanOrEqual(500);

    const metrics = capturedMetrics(writeSpy);
    const errors = metrics.filter((metric) => metric.name === MCP_TOOL_ERROR_METRIC);
    // A per-tool series for the dashboard and a dimensionless total the
    // aggregate alarm can evaluate.
    expect(errors.some((metric) => metric.toolName === 'execute_runbook')).toBe(true);
    expect(errors.some((metric) => metric.toolName === undefined)).toBe(true);
    expect(metrics.some((metric) => metric.name === MCP_TOOL_INVOCATION_METRIC)).toBe(true);
    expect(metrics.some((metric) => metric.name === MCP_TOOL_LATENCY_METRIC)).toBe(true);
  });

  it('does not emit the error metric on a 4xx failure', async () => {
    stubApiLambda({ error: 'not found' }, 404);
    const event = createAgentCoreEvent({ groups: ['AdminGroup'], clientId }, { finding_id: 'finding-1' });

    const response = await handler(event, createAgentCoreContext('execute_runbook'));
    expect(response.statusCode).toBe(404);

    const metrics = capturedMetrics(writeSpy);
    expect(metrics.some((metric) => metric.name === MCP_TOOL_ERROR_METRIC)).toBe(false);
    // The invocation is still counted, tagged with the tool, so a 4xx is
    // observable as an invocation without polluting the error signal.
    expect(metrics.find((metric) => metric.name === MCP_TOOL_INVOCATION_METRIC)?.toolName).toBe('execute_runbook');
  });

  it("tags the metrics with ToolName 'unknown' when no tool name resolves", async () => {
    const event = createAgentCoreEvent({ groups: ['AdminGroup'], clientId });

    // An unprefixed empty tool name fails resolveToolName before dispatch, so
    // the handler's catch emits with the 'unknown' default it started from.
    const response = await handler(event, createAgentCoreContext('', { prefixed: false }));
    expect(response.statusCode).toBe(400);

    const metrics = capturedMetrics(writeSpy);
    expect(metrics.find((metric) => metric.name === MCP_TOOL_INVOCATION_METRIC)?.toolName).toBe('unknown');
    expect(metrics.some((metric) => metric.name === MCP_TOOL_ERROR_METRIC)).toBe(false);
  });

  it("buckets an unrecognized caller-supplied tool name to 'unrecognized'", async () => {
    const event = createAgentCoreEvent({ groups: ['AdminGroup'], clientId });

    // An arbitrary name resolves (the prefix is stripped) but matches no route,
    // so Admin is denied it (403) in the catch. Emitting the raw name as a
    // dimension would let a caller mint one time series per request, so the
    // dimension collapses to a fixed bucket instead.
    const response = await handler(event, createAgentCoreContext('totally_made_up_tool'));
    expect(response.statusCode).toBe(403);

    const metrics = capturedMetrics(writeSpy);
    const toolNames = metrics.map((metric) => metric.toolName);
    expect(toolNames).toContain('unrecognized');
    expect(toolNames).not.toContain('totally_made_up_tool');
  });
});
