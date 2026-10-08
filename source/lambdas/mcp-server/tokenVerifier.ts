// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { CognitoJwtVerifier } from 'aws-jwt-verify';
import {
  FetchError,
  JwksNotAvailableInCacheError,
  JwksValidationError,
  KidNotFoundInJwksError,
  WaitPeriodNotYetEndedJwkError,
} from 'aws-jwt-verify/error';
import { ForbiddenError, ServiceUnavailableError } from '../common/utils/httpErrors';

/**
 * Denial for a token whose `kid` is not in the pool's key set, after a refetch that did
 * reach Cognito. A caller cannot turn this into a retry that helps, so it denies outright.
 */
const UNPUBLISHED_KEY_MESSAGE =
  'Access denied: the access token was signed with a key this user pool does not publish.';

export interface VerifyAccessTokenOptions {
  readonly userPoolId: string;
  /**
   * The Cognito app client whose tokens this Lambda accepts. The gateway pins the same
   * client via its JWT authorizer's `allowedClients`; checking it here as well is what
   * makes the direct-invoke path as strict as the gateway path rather than merely
   * authentic — a token minted for another client in the same pool is still validly
   * signed by that pool.
   */
  readonly expectedClientId: string;
}

/**
 * The slice of `aws-jwt-verify`'s verifier this module uses.
 *
 * Declared rather than naming `CognitoJwtVerifierSingleUserPool<...>`, which is generic over
 * the properties object passed to `create` — spelling that out would restate the
 * construction call in the type system for no added safety, since one method is all this
 * module calls. Having a name for it is also what lets the cache and {@link verifierFor}
 * state their types directly instead of recovering them with `ReturnType<typeof …>`.
 */
interface AccessTokenVerifier {
  verify(token: string): Promise<unknown>;
}

function createVerifier(options: VerifyAccessTokenOptions): AccessTokenVerifier {
  // The library derives the issuer from the pool id, pins RS256, and checks `iss`,
  // `client_id`, `token_use` and `exp` on every verify. It also owns the JWKS fetch, its
  // in-memory cache, and the rate limit on refetching for an unknown `kid` — that last one
  // matters because the `kid` comes from a token whose signature has not been checked yet,
  // so refetching per request would let a caller amplify their own request rate into
  // outbound calls to Cognito.
  return CognitoJwtVerifier.create({
    userPoolId: options.userPoolId,
    clientId: options.expectedClientId,
    tokenUse: 'access',
  });
}

let cached: { readonly key: string; readonly verifier: AccessTokenVerifier } | undefined;

/** Clear the cached verifier and its signing keys. For tests that change pools or clients. */
export function resetTokenVerifierCache(): void {
  cached = undefined;
}

/**
 * Reuse one verifier across invocations so a warm Lambda keeps its JWKS cache rather than
 * fetching the key set on every tool call.
 */
function verifierFor(options: VerifyAccessTokenOptions): AccessTokenVerifier {
  const key = `${options.userPoolId}|${options.expectedClientId}`;
  if (cached?.key !== key) {
    cached = { key, verifier: createVerifier(options) };
  }
  return cached.verifier;
}

/**
 * Translate a verification failure into the response the caller should see.
 *
 * "Bad token" and "cannot check the token" are kept distinct: the second is retryable, and
 * an operator needs to be able to tell them apart. Both still deny — failing open here
 * would reintroduce exactly the hole this check closes.
 *
 * `WaitPeriodNotYetEndedJwkError` sits with the retryable group rather than with the
 * unpublished-key denial it superficially resembles. It means the `kid` was not in the
 * cached key set AND the library's cooldown declined to refetch, which happens after a
 * refetch has just failed. So it reports that the keys could not be read, not that the key
 * does not exist: during a signing-key rotation whose refetch is failing, a legitimate token
 * carrying the new `kid` lands here, and a 403 would tell its holder to stop rather than to
 * retry once the cooldown elapses. Both branches deny, so nothing is admitted either way.
 */
function denialFor(error: unknown): Error {
  if (error instanceof KidNotFoundInJwksError) {
    return new ForbiddenError(UNPUBLISHED_KEY_MESSAGE);
  }
  if (
    error instanceof FetchError ||
    error instanceof JwksValidationError ||
    error instanceof JwksNotAvailableInCacheError ||
    error instanceof WaitPeriodNotYetEndedJwkError
  ) {
    return new ServiceUnavailableError(
      'The Cognito signing keys could not be read, so the access token cannot be verified. This is a ' +
        `transient failure — retry the request. (${error.message})`,
    );
  }
  return new ForbiddenError(`Access denied: ${error instanceof Error ? error.message : String(error)}`);
}

/**
 * Verify a Cognito access token's signature and claims.
 *
 * The AgentCore Gateway validates the token before invoking this Lambda, so this is
 * defense in depth — and the depth matters: Lambda authorizes a same-account caller if
 * EITHER an identity policy or a resource policy allows the invoke, so a resource policy
 * cannot keep an in-account principal with `lambda:InvokeFunction` out. Without this check
 * such a caller could hand-craft a token claiming `cognito:groups: ["AdminGroup"]` and
 * drive every admin-tier tool, including `deploy_runbook`. Verifying here is what makes
 * the group claims trustworthy on their own.
 *
 * Throws {@link ForbiddenError} when the token is not trustworthy and
 * {@link ServiceUnavailableError} when the signing keys cannot be read.
 */
export async function verifyAccessToken(token: string, options: VerifyAccessTokenOptions): Promise<void> {
  try {
    await verifierFor(options).verify(token);
  } catch (error) {
    throw denialFor(error);
  }
}
