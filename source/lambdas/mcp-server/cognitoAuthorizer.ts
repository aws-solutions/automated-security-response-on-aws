// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * Cognito authorization for the MCP server Lambda — the single enforcement point for
 * cloud MCP tool access.
 *
 * The AgentCore Gateway authenticates the caller via Cognito and forwards the token to
 * the Lambda. This module enforces a per-tool policy using the existing ASR web UI
 * Cognito groups:
 *
 *  - AdminGroup           → every MCP tool automatically
 *  - DelegatedAdminGroup  → explicitly granted tools, unrestricted by account
 *  - AccountOperatorGroup → explicitly granted tools, restricted to assigned accounts
 *  - Any other group, or a human token in no recognized group → denied
 *
 * Group membership fails closed: only the three recognized ASR groups grant access to a
 * human caller, and a human whose groups map to none of them is denied outright.
 * The AccountOperator tier is not harmless — `get_finding_history`,
 * `list_findings_without_runbook`, `check_runbook_drift` and `check_deploy_readiness`
 * execute inside this Lambda against its own role, which holds org-wide
 * `securityhub:GetFindings`, so no API-side group or account check stands behind them.
 * Assigning that tier to an unrecognized caller would hand them that data.
 *
 * MCP is human-only. Machine (`client_credentials`) tokens remain supported by
 * the REST API under ADR 0008, but are rejected on this MCP path.
 */

import { GROUP_TO_TIER, isToolAllowedForGroups, resolveUserToolAccess, tierForGroups } from './contract/toolContract';
import { ForbiddenError } from '../common/utils/httpErrors';

// Authorization failures on the MCP path are HTTP 403 (Forbidden): the caller is
// authenticated by the gateway but not permitted for the tool/account. Reuse the
// shared ForbiddenError (statusCode 403) from httpErrors rather than a second,
// differently-shaped error class — one status-code error hierarchy across the
// codebase (see ADR 0001 / coding-conventions). Re-exported so existing importers
// of this module get the same type.
export { ForbiddenError } from '../common/utils/httpErrors';

/** The `Bearer` auth scheme, compared case-insensitively against the header's first word. */
const BEARER_SCHEME = 'bearer';

/**
 * The token out of an `Authorization: Bearer <token>` header, or undefined when the header
 * is not a Bearer header. Shared by the two readers of the header so they cannot disagree on
 * what counts as a Bearer token.
 *
 * Parsed rather than matched with `/^Bearer\s+(.+)$/i`. That regex reads better but
 * backtracks quadratically: `\s+` and `.+` both match a space, so a header of N spaces
 * ending in a character `.` cannot match forces the engine to retry every split — measured
 * at ~100ms for 16k spaces and rising with the square. The header is attacker-controlled (an
 * in-account caller invoking this Lambda directly supplies the whole event) and is read
 * BEFORE the signature is verified, so that is reachable pre-authentication. A scheme
 * comparison plus a trim is linear and says the same thing.
 */
function bearerTokenFrom(authorizationHeader: string): string | undefined {
  if (authorizationHeader.slice(0, BEARER_SCHEME.length).toLowerCase() !== BEARER_SCHEME) return undefined;
  const credential = authorizationHeader.slice(BEARER_SCHEME.length);
  // The scheme has to be followed by whitespace, so `Bearerfoo` is not a Bearer header. One
  // character is tested, so this cannot backtrack.
  if (!/^\s/.test(credential)) return undefined;
  const token = credential.trim();
  // A bearer credential is a `b64token` (RFC 6750) and a JWT is three base64url segments, so
  // neither contains whitespace. Rejecting it here keeps the newline case the old regex
  // rejected — `.` never matched one — and is a single linear scan, not a quantified group.
  if (token.length === 0 || /\s/.test(token)) return undefined;
  return token;
}

/**
 * Decoded Cognito identity extracted from the AgentCore event. All MCP calls require a
 * Cognito token — unauthenticated requests are rejected at the gateway before reaching
 * this Lambda.
 */
export interface CallerIdentity {
  readonly username?: string;
  /** Canonical Cognito email, populated by the handler after AdminGetUser. */
  readonly email?: string;
  readonly groups: readonly string[];
  /** Full claims from the gateway-validated JWT, forwarded to the API Lambda authorizer context. */
  readonly claims: Readonly<Record<string, unknown>>;
}

/**
 * The raw Bearer token the gateway interceptor forwarded, for signature verification.
 *
 * Split from {@link extractCallerIdentity} on purpose: decoding claims and *trusting* them
 * are different steps, and the handler must verify the signature before it acts on the
 * groups inside. Returning the token from the identity object instead would put a
 * credential into a structure that is forwarded onward to the API Lambda.
 */
export function extractBearerToken(event: unknown): string {
  if (!event || typeof event !== 'object') {
    throw new ForbiddenError('No request event found');
  }
  const authHeader = (event as Record<string, unknown>)['__authorizationHeader'];
  if (typeof authHeader !== 'string' || authHeader.length === 0) {
    throw new ForbiddenError('No Cognito identity found in request. MCP access requires a Cognito access token.');
  }
  const token = bearerTokenFrom(authHeader);
  if (!token) {
    throw new ForbiddenError(
      'Authorization header is present but is not a Bearer token. MCP access requires a Bearer Cognito access token.',
    );
  }
  return token;
}

/**
 * Extract the caller's identity from the AgentCore event. AgentCore Gateway does not pass
 * decoded JWT claims to the target Lambda. Instead, the REQUEST interceptor (with
 * passRequestHeaders enabled) extracts the Authorization header and injects it into the
 * tool arguments body as `__authorizationHeader`. This function decodes the JWT to extract
 * groups and username, and preserves all claims for the API Lambda's authorization context.
 * Cognito access tokens do not contain the user's email in this deployment; the handler
 * resolves it from the user pool only when a per-user grant is required.
 */
export function extractCallerIdentity(event: unknown): CallerIdentity {
  if (!event || typeof event !== 'object') {
    throw new ForbiddenError('No request event found');
  }

  const record = event as Record<string, unknown>;

  // The interceptor injects the raw Authorization header as __authorizationHeader.
  const authHeader = record['__authorizationHeader'];
  if (typeof authHeader !== 'string' || authHeader.length === 0) {
    throw new ForbiddenError('No Cognito identity found in request. MCP access requires a Cognito access token.');
  }

  const token = bearerTokenFrom(authHeader);
  if (!token) {
    // A header is present but not a Bearer token — distinct from no token at all,
    // so an operator can tell a mis-shaped Authorization header from a missing one.
    throw new ForbiddenError(
      'Authorization header is present but is not a Bearer token. MCP access requires a Bearer Cognito access token.',
    );
  }

  const claims = decodeJwtPayload(token);
  if (!claims) {
    // Bearer token present but its payload could not be decoded (invalid base64,
    // wrong segment count, or non-JSON). Report that specifically rather than the
    // generic "no identity" message, which would mislead diagnosis.
    throw new ForbiddenError(
      'The Bearer token is malformed and its claims could not be decoded. MCP access requires a valid Cognito access token.',
    );
  }

  const groups = normalizeGroups(claims['cognito:groups']);
  const username =
    typeof claims['cognito:username'] === 'string'
      ? claims['cognito:username']
      : typeof claims['username'] === 'string'
        ? claims['username']
        : undefined;
  return { username, groups, claims };
}

/**
 * True for a Cognito `client_credentials` token, which carries `sub === client_id`.
 *
 * Deliberately the same predicate the API's `apiHandler` uses to spot a machine
 * token, so the two enforcement layers agree on what a machine caller is. A human
 * access token from the authorization-code flow also carries `client_id`, so that
 * claim alone cannot make this distinction — only its equality with `sub` can.
 */
export function isMachineToken(claims: Readonly<Record<string, unknown>>): boolean {
  return typeof claims['client_id'] === 'string' && claims['sub'] === claims['client_id'];
}

/**
 * Reject machine tokens, humans without a username, and callers whose groups map to
 * no recognized ASR tier.
 *
 * Direct MCP tools run under the Lambda's own organization-wide permissions.
 * Assigning an unrecognized caller the AccountOperator tier would therefore expose
 * data without an established identity or account mapping. Deny instead.
 */
export function assertRecognizedPrincipal(
  identity: CallerIdentity,
): asserts identity is CallerIdentity & { readonly username: string } {
  if (isMachineToken(identity.claims)) {
    throw new ForbiddenError('Access denied: MCP is human-only. Use the ASR API for machine-to-machine access.');
  }
  if (!identity.username) {
    throw new ForbiddenError(
      "Access denied: the Cognito access token has no 'username' claim, so the user cannot be resolved.",
    );
  }
  if (identity.groups.some((group) => group in GROUP_TO_TIER)) return;

  throw new ForbiddenError(
    'Access denied: the caller is in no recognized ASR group. Assign one of ' +
      `${Object.keys(GROUP_TO_TIER).join(', ')} to grant access.`,
  );
}

export function assertAuthorized(toolName: string, identity: CallerIdentity, allowedTools?: readonly string[]): void {
  if (resolveUserToolAccess(toolName, identity.groups, allowedTools)) return;

  const tier = tierForGroups(identity.groups) ?? 'Unrecognized';
  // Distinguish the two denial causes so the caller knows whether to ask for a
  // role change or an explicit user grant.
  throw new ForbiddenError(
    isToolAllowedForGroups(toolName, identity.groups)
      ? `Access denied: tool '${toolName}' is not granted to user '${identity.email ?? identity.username}' ` +
          `(tier '${tier}'). ` +
          'An administrator must grant MCP tools for this user.'
      : `Access denied: tool '${toolName}' is not permitted for the '${tier}' access tier`,
  );
}

/** Normalize the cognito:groups claim — can arrive as a string, array, or JSON-encoded array. */
function normalizeGroups(claim: unknown): string[] {
  if (Array.isArray(claim)) return claim.filter((g): g is string => typeof g === 'string');
  if (typeof claim === 'string') {
    const trimmed = claim.trim();
    if (trimmed.startsWith('[') && trimmed.endsWith(']')) {
      return (
        trimmed
          .slice(1, -1)
          .split(/[,\s]+/)
          // Strip the surrounding quotes of a JSON-encoded array. Without this the
          // entries keep their literal double quotes (`"AdminGroup"`), which match no
          // GROUP_TO_TIER key, so a correctly-grouped caller is denied — fail-closed,
          // but a silent lockout for any token that delivers groups in this shape.
          .map((group) => group.trim().replace(/^"|"$/g, ''))
          .filter(Boolean)
      );
    }
    return trimmed.split(/\s+/).filter(Boolean);
  }
  return [];
}

/**
 * Decode a JWT payload **without verifying it**.
 *
 * This decodes only; it does not establish trust. The handler verifies the token's signature,
 * issuer, expiry, app client and `token_use` first — `verifyAccessToken` in `tokenVerifier.ts`,
 * called in `mcpServerHandler.ts` before `extractCallerIdentity` — so by the time any claim
 * read below is acted on, the token has been checked against the pool's published keys.
 *
 * That ordering is the guarantee, and it is the one to preserve: this function must stay
 * downstream of verification. Decoding first and verifying later, or reading claims on a path
 * that skips `verifyAccessToken`, would hand caller-controlled `cognito:groups` to the
 * authorization checks. Two further layers sit in front of it and are defence in depth rather
 * than the argument:
 *
 *  1. The AgentCore Gateway's `CUSTOM_JWT` authorizer validates the token — signature,
 *     issuer, expiry, and `allowedClients` — before the request reaches this Lambda. It
 *     cannot be relied on alone: Lambda admits a same-account caller holding
 *     `lambda:InvokeFunction`, who never passes through the gateway.
 *  2. The request interceptor is authoritative over `__authorizationHeader`: it always
 *     overwrites the field from the validated request header, and deletes it when there is
 *     none. See `lib/mcp/mcp-interceptor-source.ts`.
 */
function decodeJwtPayload(token: string): Record<string, unknown> | undefined {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return undefined;
    const payload = Buffer.from(parts[1], 'base64url').toString('utf8');
    // `JSON.parse` returns `any`, and a JWT payload segment can legitimately decode to an
    // array, string, or null. Casting straight to a claims object (ADR 0001) would let one
    // of those reach the claim reads below, where `claims['cognito:groups']` on a string
    // silently yields undefined — an unrecognized principal rather than a malformed token.
    // Validating the shape here means the caller's "malformed token" branch reports it.
    const parsed: unknown = JSON.parse(payload);
    if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) return undefined;
    return parsed as Record<string, unknown>;
  } catch {
    return undefined;
  }
}
