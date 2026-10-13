// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import {
  assertAuthorized,
  assertRecognizedPrincipal,
  extractBearerToken,
  extractCallerIdentity,
  ForbiddenError,
} from '../cognitoAuthorizer';
import { tierForGroups } from '../contract/toolContract';
import { createAccessToken, createAgentCoreEvent, createMachineAgentCoreEvent } from './mcpAuthorizationTestFactories';

describe('Cognito MCP authorization', () => {
  test('extracts the username and groups from an access token without requiring email', () => {
    // GIVEN
    const event = createAgentCoreEvent({
      groups: ['DelegatedAdminGroup'],
      clientId: 'gateway-client',
      email: null,
    });

    // WHEN
    const identity = extractCallerIdentity(event);

    // THEN
    expect(identity).toMatchObject({
      username: 'test.user',
      groups: ['DelegatedAdminGroup'],
    });
    expect(identity.email).toBeUndefined();
    expect(() => assertRecognizedPrincipal(identity)).not.toThrow();
  });

  test('distinguishes a missing token, a non-Bearer header, and a malformed Bearer token', () => {
    // No __authorizationHeader at all → "no identity".
    expect(() => extractCallerIdentity({})).toThrow(/No Cognito identity found/);

    // A header that is present but not a Bearer token.
    expect(() => extractCallerIdentity({ __authorizationHeader: 'Basic abc123' })).toThrow(
      /present but is not a Bearer token/,
    );

    // A Bearer token whose payload cannot be decoded (not a valid three-segment JWT).
    expect(() => extractCallerIdentity({ __authorizationHeader: 'Bearer not-a-jwt' })).toThrow(/malformed/);
  });

  test('parses the Bearer scheme the way the header is actually written', () => {
    // The scheme is case-insensitive and may be followed by any run of whitespace, so all of
    // these carry the same token. `Bearer` with nothing after it, and a scheme with no
    // separator at all, are not Bearer headers.
    const token = createAccessToken({ groups: ['AdminGroup'] });
    for (const header of [`Bearer ${token}`, `bearer ${token}`, `BEARER   ${token}`, `Bearer\t${token}`]) {
      expect(extractBearerToken({ __authorizationHeader: header })).toBe(token);
    }
    for (const header of ['Bearer', 'Bearer   ', `Bearer${token}`, `Basic ${token}`]) {
      expect(() => extractBearerToken({ __authorizationHeader: header })).toThrow(/not a Bearer token/);
    }
    // Neither a JWT nor an RFC 6750 credential contains whitespace, so an embedded space or
    // newline is not a token — the latter is what the previous regex rejected via `.`.
    for (const header of [`Bearer ${token} extra`, `Bearer ${token}\nmore`]) {
      expect(() => extractBearerToken({ __authorizationHeader: header })).toThrow(/not a Bearer token/);
    }
  });

  test('parses a pathological header in linear time', () => {
    // `/^Bearer\s+(.+)$/i` backtracked quadratically on this shape — `\s+` and `.+` both match
    // a space, so every split had to be retried once a trailing newline made the match fail.
    // The header is attacker-controlled and is read BEFORE the signature is verified, so it
    // was a pre-auth CPU sink.
    //
    // This asserts the scaling, not a speed: a 10x larger input may cost at most 30x the time.
    // Linear parsing measures ~10x; the old regex measured ~100x (4k→6ms, 8k→26ms, 16k→97ms,
    // 32k→406ms). A ratio is immune to a uniformly slow runner, where an absolute bound is
    // not, and the median of three runs keeps one GC pause from deciding it.
    const timeParse = (spaces: number): number => {
      const header = `Bearer${' '.repeat(spaces)}\n`;
      const startedAt = process.hrtime.bigint();
      expect(() => extractBearerToken({ __authorizationHeader: header })).toThrow(/not a Bearer token/);
      return Number(process.hrtime.bigint() - startedAt) / 1e6;
    };
    const medianOfThree = (sample: () => number): number => [sample(), sample(), sample()].sort((a, b) => a - b)[1];

    const smallMs = medianOfThree(() => timeParse(2_000_000));
    const largeMs = medianOfThree(() => timeParse(20_000_000));

    expect(largeMs / smallMs).toBeLessThan(30);
  });

  test('rejects a machine token on the human-only MCP path', () => {
    // GIVEN
    const identity = extractCallerIdentity(createMachineAgentCoreEvent('machine-client'));

    // WHEN / THEN
    expect(() => assertRecognizedPrincipal(identity)).toThrow(
      new ForbiddenError('Access denied: MCP is human-only. Use the ASR API for machine-to-machine access.'),
    );
  });

  test('rejects a human access token without a username', () => {
    // GIVEN
    const identity = extractCallerIdentity(createAgentCoreEvent({ groups: ['DelegatedAdminGroup'], username: null }));

    // WHEN / THEN
    expect(() => assertRecognizedPrincipal(identity)).toThrow(/no 'username' claim/);
  });

  test('rejects groups outside the shipped ASR role hierarchy', () => {
    // GIVEN
    const identity = extractCallerIdentity(createAgentCoreEvent({ groups: ['UnknownGroup'] }));

    // WHEN / THEN
    expect(() => assertRecognizedPrincipal(identity)).toThrow(/no recognized ASR group/);
  });

  test('grants Admin tools automatically', () => {
    // GIVEN
    const identity = extractCallerIdentity(createAgentCoreEvent({ groups: ['AdminGroup'] }));
    assertRecognizedPrincipal(identity);

    // WHEN / THEN
    expect(() => assertAuthorized('execute_runbook', identity)).not.toThrow();
  });

  test('requires an explicit Delegated Admin user grant', () => {
    // GIVEN
    const identity = {
      ...extractCallerIdentity(createAgentCoreEvent({ groups: ['DelegatedAdminGroup'] })),
      email: 'delegate@example.com',
    };
    assertRecognizedPrincipal(identity);

    // WHEN / THEN
    expect(() => assertAuthorized('execute_runbook', identity)).toThrow(/not granted to user/);
    expect(() => assertAuthorized('execute_runbook', identity, ['execute_runbook'])).not.toThrow();
  });

  test('does not let an Account Operator grant exceed the role ceiling', () => {
    // GIVEN
    const identity = {
      ...extractCallerIdentity(createAgentCoreEvent({ groups: ['AccountOperatorGroup'] })),
      email: 'operator@example.com',
    };
    assertRecognizedPrincipal(identity);

    // WHEN / THEN
    expect(() => assertAuthorized('list_runbooks', identity, ['list_runbooks'])).not.toThrow();
    expect(() => assertAuthorized('execute_runbook', identity, ['*'])).toThrow(
      /not permitted for the 'AccountOperator' access tier/,
    );
  });
  it('reads groups from a JSON-encoded cognito:groups claim without keeping the quotes', () => {
    // Some token paths deliver cognito:groups as a JSON-ish string rather than an
    // array. Splitting it without stripping the element quotes yielded the literal
    // `"AdminGroup"`, which matches no GROUP_TO_TIER key — the caller was silently
    // demoted to an unrecognized principal despite being in the right group.
    const encodeSegment = (value: object): string => Buffer.from(JSON.stringify(value)).toString('base64url');
    const token = [
      encodeSegment({ alg: 'RS256', kid: 'test-key' }),
      encodeSegment({
        token_use: 'access',
        'cognito:username': 'test.user',
        username: 'test.user',
        'cognito:groups': '["AdminGroup"]',
      }),
      'test-signature',
    ].join('.');

    const identity = extractCallerIdentity({ __authorizationHeader: `Bearer ${token}` });

    expect(identity.groups).toEqual(['AdminGroup']);
    expect(tierForGroups(identity.groups)).toBe('Admin');
  });
  it.each([
    ['an array', '["AdminGroup"]'],
    ['a string', '"just-a-string"'],
    ['null', 'null'],
    ['a number', '42'],
  ])('rejects a Bearer token whose payload decodes to %s', (_shape, payloadJson) => {
    // JSON.parse returns `any`, so casting the result straight to a claims object let a
    // non-object through: `claims['cognito:groups']` on a string yields undefined, which
    // reads as "in no recognized ASR group" rather than "the token is malformed".
    const encodeSegment = (value: string): string => Buffer.from(value).toString('base64url');
    const token = [encodeSegment('{"alg":"RS256"}'), encodeSegment(payloadJson), 'sig'].join('.');

    expect(() => extractCallerIdentity({ __authorizationHeader: `Bearer ${token}` })).toThrow(/malformed/);
  });
});
