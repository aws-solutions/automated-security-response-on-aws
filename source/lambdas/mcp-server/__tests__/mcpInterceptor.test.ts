// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { handler } from '../mcpInterceptor';

type InterceptorEvent = Parameters<typeof handler>[0];

function callToolEvent(headers: Record<string, unknown>, args: Record<string, unknown> | undefined): InterceptorEvent {
  return {
    mcp: {
      gatewayRequest: {
        headers,
        body: {
          method: 'tools/call',
          params: { name: 'deploy_runbook', ...(args !== undefined && { arguments: args }) },
        },
      },
    },
  };
}

const argumentsOf = (result: Awaited<ReturnType<typeof handler>>) =>
  result.mcp.transformedGatewayRequest.body.params?.arguments as Record<string, unknown>;

describe('MCP gateway request interceptor', () => {
  it('injects the real Authorization header for the target Lambda to read', async () => {
    const result = await handler(callToolEvent({ Authorization: 'Bearer real.token.sig' }, { runbookId: 'r' }));

    expect(argumentsOf(result)).toEqual({ runbookId: 'r', __authorizationHeader: 'Bearer real.token.sig' });
  });

  it('overwrites a caller-supplied __authorizationHeader instead of trusting it', async () => {
    // The field is an advertised property in toolSchema.json, so a caller can always send
    // one. It must lose to the header the gateway actually validated.
    const forged = 'Bearer forged.admin.token';
    const result = await handler(
      callToolEvent({ authorization: 'Bearer real.token.sig' }, { __authorizationHeader: forged }),
    );

    expect(argumentsOf(result).__authorizationHeader).toBe('Bearer real.token.sig');
  });

  it('deletes a caller-supplied __authorizationHeader when no real header is present', async () => {
    // The privilege escalation this guards: with no genuine header, an earlier
    // `if (auth && ...)` guard left the caller's own value in place, and the Lambda decoded
    // it without verifying the signature — so an unsigned token claiming
    // cognito:groups ["AdminGroup"] reached the Admin tier.
    const unsignedAdminToken = `Bearer ${Buffer.from(JSON.stringify({ alg: 'none' })).toString('base64url')}.${Buffer.from(
      JSON.stringify({ 'cognito:groups': ['AdminGroup'], 'cognito:username': 'attacker' }),
    ).toString('base64url')}.`;

    const result = await handler(callToolEvent({}, { __authorizationHeader: unsignedAdminToken }));

    expect(argumentsOf(result)).not.toHaveProperty('__authorizationHeader');
  });

  it('finds the header whatever its casing, so a gateway casing change cannot reopen the hole', async () => {
    for (const headerName of ['authorization', 'Authorization', 'AUTHORIZATION', 'AuThOrIzAtIoN']) {
      const result = await handler(callToolEvent({ [headerName]: 'Bearer t' }, {}));
      expect(argumentsOf(result).__authorizationHeader).toBe('Bearer t');
    }
  });

  it('ignores a non-string or empty Authorization header rather than injecting garbage', async () => {
    for (const value of ['', 42, null, { token: 'x' }]) {
      const result = await handler(callToolEvent({ Authorization: value }, { __authorizationHeader: 'Bearer nope' }));
      expect(argumentsOf(result)).not.toHaveProperty('__authorizationHeader');
    }
  });

  it('creates the arguments object for a no-argument tool so auth still reaches the Lambda', async () => {
    // Tools bound to NoArgsSchema (list_controls, list_filters, ...) may arrive with no
    // `arguments` at all; without this the header had nowhere to go and every such call
    // failed as unauthenticated.
    const result = await handler(callToolEvent({ Authorization: 'Bearer t' }, undefined));

    expect(argumentsOf(result)).toEqual({ __authorizationHeader: 'Bearer t' });
  });

  it('preserves the rest of the request body', async () => {
    const result = await handler(callToolEvent({ Authorization: 'Bearer t' }, { a: 1, nested: { b: 2 } }));
    const body = result.mcp.transformedGatewayRequest.body;

    expect(body.method).toBe('tools/call');
    expect(body.params?.name).toBe('deploy_runbook');
    expect(argumentsOf(result)).toMatchObject({ a: 1, nested: { b: 2 } });
    expect(result.interceptorOutputVersion).toBe('1.0');
  });

  it('does not throw on a malformed event', async () => {
    await expect(handler({})).resolves.toEqual({
      interceptorOutputVersion: '1.0',
      mcp: { transformedGatewayRequest: { body: {} } },
    });
  });
});
