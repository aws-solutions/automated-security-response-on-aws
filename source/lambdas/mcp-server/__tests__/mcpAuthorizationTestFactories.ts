// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/** Test data builders for MCP server authorization tests. */

import { createSign, generateKeyPairSync } from 'node:crypto';
import nock from 'nock';
import { userPoolId } from '../../common/__tests__/envSetup';

const SIGNING_KEY_ID = 'test-key-1';
// Cognito's issuer and JWKS URL are both derived from the pool id, and the region is its
// prefix — the same derivation `aws-jwt-verify` performs, so a token minted here is one the
// real verifier will look up keys for.
const COGNITO_HOST = `https://cognito-idp.${userPoolId.split('_')[0]}.amazonaws.com`;
const JWKS_PATH = `/${userPoolId}/.well-known/jwks.json`;
const ISSUER = `${COGNITO_HOST}/${userPoolId}`;
const ONE_HOUR_SECONDS = 3600;

/**
 * The pool's signing key, plus a second key the pool does NOT publish.
 *
 * Handler tests run the real `verifyAccessToken` — mocking our own verifier is what
 * unit-testing.md rules out — so their tokens carry genuine RS256 signatures and the only
 * stubbed boundary is Cognito's JWKS endpoint. The foreign key exists so a test can forge a
 * validly-shaped token that verification must reject.
 */
const poolKeyPair = generateKeyPairSync('rsa', { modulusLength: 2048 });
const unpublishedKeyPair = generateKeyPairSync('rsa', { modulusLength: 2048 });

interface CallerTokenOptions {
  readonly groups?: readonly string[];
  readonly clientId?: string;
  readonly username?: string | null;
  readonly email?: string | null;
  /**
   * Mint a `client_credentials` (machine) token. `isMachineToken` identifies one by
   * `sub === client_id`, so that equality — not the mere presence of `client_id` — is what
   * makes this a machine caller. A human access token from the authorization-code flow
   * carries `client_id` too.
   */
  readonly machine?: boolean;
  /**
   * Sign with a key the pool does not publish, so signature verification fails. The token is
   * otherwise well-formed, which is the point: only the signature distinguishes it.
   */
  readonly signedWithUnpublishedKey?: boolean;
  /** Seconds until the token expires. Negative values mint an already-expired token. */
  readonly expiresInSeconds?: number;
}

function base64UrlEncode(value: object): string {
  return Buffer.from(JSON.stringify(value)).toString('base64url');
}

/**
 * Stub the pool's JWKS endpoint with the public half of the signing key above.
 *
 * Persistent because each verifier instance fetches the key set once, and a suite that
 * resets the verifier cache between tests would otherwise exhaust a single interceptor. Net
 * access is deliberately NOT disabled — these suites also talk to DynamoDB Local.
 */
export function stubCognitoJwks(): nock.Scope {
  const jwk = poolKeyPair.publicKey.export({ format: 'jwk' });
  return nock(COGNITO_HOST)
    .persist()
    .get(JWKS_PATH)
    .reply(200, { keys: [{ ...jwk, kid: SIGNING_KEY_ID, alg: 'RS256', use: 'sig' }] });
}

/**
 * Build a Cognito access token, signed the way Cognito signs one: RS256 over
 * `header.payload`. `iss`, `exp` and `token_use` are set because the verifier checks all
 * three before any claim the handler reads is trusted.
 */
export function createAccessToken({
  groups,
  clientId,
  username = 'test.user',
  email = null,
  machine = false,
  signedWithUnpublishedKey = false,
  expiresInSeconds = ONE_HOUR_SECONDS,
}: CallerTokenOptions = {}): string {
  const headerSegment = base64UrlEncode({ alg: 'RS256', kid: SIGNING_KEY_ID });
  const payloadSegment = base64UrlEncode({
    token_use: 'access',
    iss: ISSUER,
    exp: Math.floor(Date.now() / 1000) + expiresInSeconds,
    ...(username ? { 'cognito:username': username, username } : {}),
    ...(email ? { email } : {}),
    ...(groups && groups.length > 0 ? { 'cognito:groups': groups } : {}),
    ...(clientId ? { client_id: clientId } : {}),
    ...(machine && clientId ? { sub: clientId } : {}),
  });
  const signer = createSign('RSA-SHA256');
  signer.update(`${headerSegment}.${payloadSegment}`);
  const key = signedWithUnpublishedKey ? unpublishedKeyPair.privateKey : poolKeyPair.privateKey;
  return `${headerSegment}.${payloadSegment}.${signer.sign(key).toString('base64url')}`;
}

/**
 * Build the tool-invocation payload the AgentCore Gateway passes to the Lambda. The
 * gateway's request interceptor injects the caller's Authorization header as
 * `__authorizationHeader`, which is how the Lambda sees the caller's identity.
 */
export function createAgentCoreEvent(
  tokenOptions: CallerTokenOptions = {},
  toolArguments: Record<string, unknown> = {},
): Record<string, unknown> {
  return {
    ...toolArguments,
    __authorizationHeader: `Bearer ${createAccessToken(tokenOptions)}`,
  };
}

/**
 * Build a tool invocation from a machine (`client_credentials`) caller: no `cognito:groups`
 * or human email, identified by `sub === client_id`. The MCP path rejects these tokens.
 */
export function createMachineAgentCoreEvent(
  clientId: string,
  toolArguments: Record<string, unknown> = {},
): Record<string, unknown> {
  return {
    ...toolArguments,
    __authorizationHeader: `Bearer ${createAccessToken({ clientId, email: null, machine: true })}`,
  };
}

interface AgentCoreContext {
  readonly clientContext: {
    readonly custom: {
      readonly bedrockAgentCoreToolName: string;
      readonly bedrockAgentCoreTargetId: string;
      readonly bedrockAgentCoreGatewayId: string;
      readonly bedrockAgentCoreMcpMessageId: string;
      readonly bedrockAgentCoreAwsRequestId: string;
      readonly bedrockAgentCoreMessageVersion: string;
    };
  };
  readonly awsRequestId: string;
  readonly invokedFunctionArn: string;
}

interface AgentCoreContextOptions {
  /**
   * Override this Lambda's own invoked ARN. The handler reads its account and partition
   * from it, so a malformed value must be rejected rather than yielding `undefined`.
   */
  readonly invokedFunctionArn?: string;
  /**
   * Whether the gateway's `<targetName>___<toolName>` prefix is present. Set `false` to
   * simulate a bare name — a direct invocation, or a gateway change — which the handler must
   * resolve unchanged rather than trimming characters off the front of it.
   */
  readonly prefixed?: boolean;
}

/** Build the AgentCore context that tells the Lambda which tool was invoked. */
export function createAgentCoreContext(
  toolName: string,
  {
    prefixed = true,
    invokedFunctionArn = 'arn:aws:lambda:us-east-1:123456789012:function:SO0111-ASR-MCP-Server',
  }: AgentCoreContextOptions = {},
): AgentCoreContext {
  return {
    clientContext: {
      custom: {
        bedrockAgentCoreToolName: prefixed ? `asr-mcp-tools___${toolName}` : toolName,
        bedrockAgentCoreTargetId: 'target-1',
        bedrockAgentCoreGatewayId: 'gateway-1',
        bedrockAgentCoreMcpMessageId: 'message-1',
        bedrockAgentCoreAwsRequestId: 'request-1',
        bedrockAgentCoreMessageVersion: '1.0',
      },
    },
    awsRequestId: 'request-1',
    // The Lambda reads its own account out of this ARN rather than trusting the request.
    invokedFunctionArn,
  };
}

/**
 * One tool invocation's outcome: the handler's status and its parsed JSON body.
 *
 * `body` is `Record<string, unknown>` rather than `any` (ADR 0001), so a test that reaches
 * into a member narrows it at the assertion site. Most uses hand the member straight to
 * `expect(...)`, which needs no narrowing; only a dereference — `.map`, `.length` — does.
 */
export interface ToolCallResult {
  readonly status: number;
  readonly body: Record<string, unknown>;
}

/** Parse a handler result into a {@link ToolCallResult}. */
export function toolCallResult(result: { readonly statusCode: number; readonly body: string }): ToolCallResult {
  return { status: result.statusCode, body: JSON.parse(result.body) as Record<string, unknown> };
}

/**
 * A Lambda `InvokeCommand` response payload, as the SDK hands one back.
 *
 * The SDK types `Payload` as a `Uint8ArrayBlobAdapter`: a `Uint8Array` that also carries
 * `transformToString`. Code under test may read it either way, so a stub has to offer both
 * — hence the intersection rather than a plain `Uint8Array`.
 */
export function createLambdaPayload(value: string): Uint8Array & { transformToString: () => string } {
  const payload = Uint8Array.from(Buffer.from(value));
  return Object.assign(payload, {
    transformToString: (): string => Buffer.from(payload).toString('utf8'),
  });
}

/** The API Gateway event the handler forwarded to the ASR API Lambda. */
export interface ForwardedApiRequest {
  readonly path: string;
  readonly httpMethod: string;
  /** Raw body, for a test that wants to assert on what is absent from it. */
  readonly rawBody: string;
  readonly body: Record<string, unknown>;
}

/**
 * Decode a forwarded `InvokeCommand` payload into the request it carried.
 *
 * The decode counterpart of {@link createLambdaPayload}, here for the same reason: every
 * handler suite needs it, and inlining it meant repeating the `Payload as Uint8Array` cast
 * per call site (ADR 0001). `Payload` is an optional union on the SDK's input type, so the
 * narrowing happens once here, as a real check rather than an assertion.
 *
 * Takes the command *input* so it serves both callers: `call.args[0].input` for a recorded
 * call, and the `input` a `callsFake` stub is handed.
 */
export function forwardedApiRequest(input: { readonly Payload?: unknown }): ForwardedApiRequest {
  const payload = input.Payload;
  if (!(payload instanceof Uint8Array)) {
    throw new Error(`Expected an InvokeCommand payload of bytes, got ${typeof payload}`);
  }
  const event = JSON.parse(Buffer.from(payload).toString('utf8')) as {
    path: string;
    httpMethod: string;
    body?: string;
  };
  const rawBody = event.body ?? '{}';
  return {
    path: event.path,
    httpMethod: event.httpMethod,
    rawBody,
    body: JSON.parse(rawBody) as Record<string, unknown>,
  };
}
