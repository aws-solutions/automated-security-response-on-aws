// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { createSign, generateKeyPairSync, type KeyObject } from 'node:crypto';
import nock from 'nock';
import { resetTokenVerifierCache, verifyAccessToken } from '../tokenVerifier';

// Signature verification for the caller's Cognito access token.
//
// The gateway validates the token as well, so this is defense in depth — but it is the
// only thing that makes the `cognito:groups` claim trustworthy on its own. Lambda admits a
// same-account caller when EITHER an identity policy or a resource policy allows the
// invoke, so no resource policy can keep an in-account principal with
// lambda:InvokeFunction out; before this check, such a caller could hand-craft a token
// claiming AdminGroup and drive every admin-tier tool.
//
// The JWT mechanics — RS256 pinning, JWKS caching, rate-limited refetch on an unknown kid —
// belong to `aws-jwt-verify` and are its tests to own. What is covered here is the wiring
// this solution is responsible for: that the pool, app client and token use are pinned,
// that a forged token is refused, and that a failure to READ the keys denies retryably
// rather than being accepted. Tokens are signed with a locally generated RSA key and the
// JWKS endpoint is stubbed with that key's public half, so the real crypto path runs.

const USER_POOL_ID = 'us-east-1_testpool';
const REGION = 'us-east-1';
const COGNITO_HOST = `https://cognito-idp.${REGION}.amazonaws.com`;
const JWKS_PATH = `/${USER_POOL_ID}/.well-known/jwks.json`;
const ISSUER = `${COGNITO_HOST}/${USER_POOL_ID}`;
const KEY_ID = 'test-key-1';
const GATEWAY_CLIENT_ID = 'gateway-client-id';

const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
const otherKeyPair = generateKeyPairSync('rsa', { modulusLength: 2048 });

const base64Url = (value: object): string => Buffer.from(JSON.stringify(value)).toString('base64url');

/** Sign a token the way Cognito does: RS256 over `header.payload`. */
function signToken({
  claims = {},
  header = {},
  key = privateKey,
}: {
  claims?: Record<string, unknown>;
  header?: Record<string, unknown>;
  key?: KeyObject;
} = {}): string {
  const headerSegment = base64Url({ alg: 'RS256', kid: KEY_ID, ...header });
  const payloadSegment = base64Url({
    token_use: 'access',
    iss: ISSUER,
    exp: Math.floor(Date.now() / 1000) + 3600,
    client_id: GATEWAY_CLIENT_ID,
    'cognito:groups': ['AdminGroup'],
    ...claims,
  });
  const signer = createSign('RSA-SHA256');
  signer.update(`${headerSegment}.${payloadSegment}`);
  const signature = signer.sign(key).toString('base64url');
  return `${headerSegment}.${payloadSegment}.${signature}`;
}

/** The JWKS document Cognito would publish for the signing key above. */
function jwksFor(key: KeyObject, kid = KEY_ID): object {
  const jwk = key.export({ format: 'jwk' });
  return { keys: [{ ...jwk, kid, alg: 'RS256', use: 'sig' }] };
}

/** Stub the pool's JWKS endpoint. Returns the scope so a test can assert it was consumed. */
function stubJwks(document: object = jwksFor(publicKey), times = 1): nock.Scope {
  return nock(COGNITO_HOST).get(JWKS_PATH).times(times).reply(200, document);
}

const options = { userPoolId: USER_POOL_ID, expectedClientId: GATEWAY_CLIENT_ID };

beforeEach(() => {
  resetTokenVerifierCache();
  nock.cleanAll();
  // Any JWKS fetch this suite did not stub must fail loudly rather than reach Cognito.
  // Loopback stays open because the shared test harness talks to DynamoDB Local.
  nock.disableNetConnect();
  nock.enableNetConnect(/127\.0\.0\.1|localhost/);
});

afterAll(() => {
  nock.cleanAll();
  nock.enableNetConnect();
});

describe('verifyAccessToken — accepting a genuine token', () => {
  it('accepts a token signed by a key the pool publishes', async () => {
    stubJwks();

    await expect(verifyAccessToken(signToken(), options)).resolves.toBeUndefined();
  });

  it('reuses the fetched key set for later tokens', async () => {
    // Every tool call carries a token. Fetching JWKS per call would add a network round
    // trip to each one and make the pool's endpoint a hot dependency. Only one response is
    // stubbed and net connections are disabled, so a second fetch would fail this test.
    const scope = stubJwks();

    await verifyAccessToken(signToken(), options);
    await verifyAccessToken(signToken(), options);

    expect(scope.isDone()).toBe(true);
  });
});

describe('verifyAccessToken — rejecting a forged or unusable token', () => {
  beforeEach(() => {
    // Answered repeatedly so a rejection is never merely a missing stub.
    stubJwks(jwksFor(publicKey), 5);
  });

  it('rejects a token signed by a different key', async () => {
    // The attack this closes: a caller who can invoke the Lambda directly mints their own
    // token with whatever groups they like. Only the signature check catches it.
    await expect(verifyAccessToken(signToken({ key: otherKeyPair.privateKey }), options)).rejects.toThrow(
      /Access denied/,
    );
  });

  it('rejects a validly signed token issued to a different application client', async () => {
    // The web UI and any customer-created M2M client live in the same pool, so their
    // tokens carry a genuine signature from it. The gateway refuses them via
    // allowedClients; the direct-invoke path has to refuse them too or it is the weaker
    // of the two entry points.
    await expect(verifyAccessToken(signToken({ claims: { client_id: 'web-ui-client' } }), options)).rejects.toThrow(
      /Access denied/,
    );
  });

  it('rejects an id token, which carries different claims than the gateway forwards', async () => {
    await expect(verifyAccessToken(signToken({ claims: { token_use: 'id' } }), options)).rejects.toThrow(
      /Access denied/,
    );
  });

  it('rejects an expired token', async () => {
    await expect(
      verifyAccessToken(signToken({ claims: { exp: Math.floor(Date.now() / 1000) - 60 } }), options),
    ).rejects.toThrow(/Access denied/);
  });

  it('rejects a token from a different user pool', async () => {
    await expect(
      verifyAccessToken(signToken({ claims: { iss: `${COGNITO_HOST}/${REGION}_otherpool` } }), options),
    ).rejects.toThrow(/Access denied/);
  });

  it('rejects a token whose signing key the pool does not publish', async () => {
    await expect(verifyAccessToken(signToken({ header: { kid: 'unknown-key' } }), options)).rejects.toThrow(
      /does not publish/,
    );
  });

  it('rejects a token that is not a well-formed JWT', async () => {
    await expect(verifyAccessToken('not-a-jwt', options)).rejects.toThrow(/Access denied/);
  });
});

describe('verifyAccessToken — when the signing keys cannot be read', () => {
  it('denies retryably rather than accepting an unverified token', async () => {
    // Failing open here would reintroduce exactly the hole this check closes, so an
    // unreachable JWKS endpoint has to deny — reported as retryable so an operator can tell
    // it apart from a bad token.
    nock(COGNITO_HOST).get(JWKS_PATH).replyWithError('getaddrinfo ENOTFOUND');

    await expect(verifyAccessToken(signToken(), options)).rejects.toThrow(/transient failure — retry/);
  });

  it('denies retryably when the endpoint answers with an error status', async () => {
    nock(COGNITO_HOST).get(JWKS_PATH).reply(503, {});

    await expect(verifyAccessToken(signToken(), options)).rejects.toThrow(/transient failure — retry/);
  });

  it('denies retryably when the key set is malformed', async () => {
    // The JWKS endpoint is a system boundary, so a response that does not match the
    // expected shape has to be rejected rather than trusted into the key cache.
    nock(COGNITO_HOST).get(JWKS_PATH).reply(200, { unexpected: true });

    await expect(verifyAccessToken(signToken(), options)).rejects.toThrow(/transient failure — retry/);
  });

  it('denies retryably while the refetch cooldown is in effect', async () => {
    // A second unknown `kid` inside the library's cooldown window cannot trigger another
    // refetch, so the key set on hand is stale rather than authoritative. Reporting that as
    // an unpublished key would tell a legitimate token holder to stop: during a signing-key
    // rotation whose refetch is failing, a token carrying the NEW kid lands here, and it
    // becomes verifiable once the cooldown elapses and the refetch succeeds.
    const unknownKid = signToken({ header: { kid: 'rotated-in-key' } });
    nock(COGNITO_HOST).get(JWKS_PATH).times(3).reply(200, jwksFor(publicKey));

    // First attempt refetches, still does not find the kid, and puts the uri in the penalty
    // box. That one is a genuine unpublished-key denial.
    await expect(verifyAccessToken(unknownKid, options)).rejects.toThrow(/does not publish/);

    await expect(verifyAccessToken(unknownKid, options)).rejects.toThrow(/transient failure — retry/);
  });
});
