// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * AgentCore Gateway REQUEST interceptor that establishes caller identity for every
 * MCP tool call.
 *
 * ## Why it must always be authoritative
 *
 * AgentCore Gateway does not hand decoded JWT claims to a target Lambda, so the caller's
 * `Authorization` header is copied into the tool arguments as `__authorizationHeader` and
 * the MCP Lambda reads its claims from there. `__authorizationHeader` is also an advertised
 * property in `toolSchema.json`, which means a caller can send one.
 *
 * An earlier version only wrote the field when it found a non-empty header. Any request
 * where the real header was missing — or arrived under a key that version did not check —
 * left the caller's own value in place, and the Lambda's `decodeJwtPayload` accepts an
 * unverified token. An unsigned JWT carrying `cognito:groups: ["AdminGroup"]` therefore
 * reached the Admin tier (`deploy_runbook`, `execute_runbook`, `update_controls`).
 *
 * So this interceptor is unconditionally authoritative over that one field: it is set from
 * the real header when present and deleted otherwise. A caller-supplied value can never
 * survive, and with no value the Lambda fails closed with 401.
 *
 * The header lookup is case-insensitive for the same reason — relying on exact spellings
 * meant a gateway-side casing change would silently reopen the hole rather than break
 * visibly.
 */

const AUTH_ARGUMENT = '__authorizationHeader';

type GatewayHeaders = Record<string, unknown>;

interface GatewayRequestBody {
  params?: {
    arguments?: Record<string, unknown>;
    [key: string]: unknown;
  };
  [key: string]: unknown;
}

interface InterceptorEvent {
  mcp?: {
    gatewayRequest?: {
      headers?: GatewayHeaders;
      body?: GatewayRequestBody;
    };
  };
}

interface InterceptorResult {
  interceptorOutputVersion: '1.0';
  mcp: { transformedGatewayRequest: { body: GatewayRequestBody } };
}

function findAuthorizationHeader(headers: GatewayHeaders): string {
  for (const key of Object.keys(headers)) {
    if (key.toLowerCase() === 'authorization') {
      const value = headers[key];
      if (typeof value === 'string' && value.length > 0) {
        return value;
      }
    }
  }
  return '';
}

export const handler = async (event: InterceptorEvent): Promise<InterceptorResult> => {
  const gatewayRequest = event?.mcp?.gatewayRequest ?? {};
  const body: GatewayRequestBody = gatewayRequest.body ?? {};
  const authorization = findAuthorizationHeader(gatewayRequest.headers ?? {});

  if (body.params && typeof body.params === 'object') {
    // Never trust a caller-supplied value for this field: overwrite it from the real
    // header, or remove it so the target Lambda rejects the call.
    if (!body.params.arguments || typeof body.params.arguments !== 'object') {
      body.params.arguments = {};
    }
    if (authorization) {
      body.params.arguments[AUTH_ARGUMENT] = authorization;
    } else {
      delete body.params.arguments[AUTH_ARGUMENT];
    }
  }

  return {
    interceptorOutputVersion: '1.0',
    mcp: { transformedGatewayRequest: { body } },
  };
};
