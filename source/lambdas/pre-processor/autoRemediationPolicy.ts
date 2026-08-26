// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { NormalizedFinding, PreProcessorEnvironmentConfig } from '@asr/data-models';
import { GUARDDUTY_IAM_USER_FINDING_TYPE } from '../common/utils/findingUtils';

/**
 * Pure auto-remediation gating policy for the pre-processor. This module owns the
 * full "should this finding trigger auto-remediation, and if it already failed,
 * may it be retried" decision, which has three cohesive parts:
 *   1. the resource-eligibility screen (`isResourceAutoRemediable`) — can the
 *      control actually act on this finding's resource,
 *   2. the retry policy (`getRetryPolicy` + the attempt cap / cooldown), and
 *   3. the combined trigger decision (`evaluateAutoRemediation`) that folds the
 *      base requirements, the first-trigger case, and the retry rules together.
 *
 * Kept side-effect free (no AWS clients, no env read at import) so it is trivially
 * unit-testable and reusable.
 */

/**
 * GuardDuty.IAMUser remediation identifier — the only control today whose
 * principal can be a temporary (assumed-role / federated) credential that
 * AWSSupport-ContainIAMPrincipal cannot contain (there is no IAM user behind
 * an STS session). Such findings are screened out of the auto-remediation path.
 *
 * Aliases the shared constant rather than repeating the literal, so this and the
 * findings-table partition key cannot drift apart.
 */
export const GUARDDUTY_IAMUSER_REMEDIATION_ID = GUARDDUTY_IAM_USER_FINDING_TYPE;

/**
 * Matches a temporary (STS) access key id. `ASIA` is the prefix AWS uses for
 * temporary credentials issued to an assumed-role / federated session; a
 * long-term IAM user key uses `AKIA`. Anchored to a non-alphanumeric boundary
 * so it matches both a bare `ASIA…` id and a CFN-prefixed
 * `AWS::IAM::AccessKey:ASIA…` resource id.
 */
const TEMPORARY_ACCESS_KEY_PATTERN = /(?:^|[^A-Z0-9])ASIA[0-9A-Z]{8,}/;

export const DEFAULT_MAX_REMEDIATION_ATTEMPTS = 3;
export const DEFAULT_REMEDIATION_RETRY_COOLDOWN_MINUTES = 15;

export interface RetryPolicy {
  readonly maxAttempts: number;
  readonly cooldownMs: number;
}

/** Parses a positive integer env var, falling back to a default on absent/invalid input. */
export function parsePositiveInt(value: string | undefined, fallback: number): number {
  if (value === undefined) return fallback;
  const parsed = Number(value);
  return Number.isInteger(parsed) && parsed > 0 ? parsed : fallback;
}

/**
 * Derives the retry policy from the (typed) pre-processor environment config.
 * Tunable via the optional `MAX_REMEDIATION_ATTEMPTS` and
 * `REMEDIATION_RETRY_COOLDOWN_MINUTES` env vars — surfaced through the typed
 * accessor (ADR 0005) rather than read from `process.env` here — with sensible
 * defaults when unset, so no CDK change is required to get the guard.
 */
export function getRetryPolicy(
  env: Pick<PreProcessorEnvironmentConfig, 'MAX_REMEDIATION_ATTEMPTS' | 'REMEDIATION_RETRY_COOLDOWN_MINUTES'>,
): RetryPolicy {
  const maxAttempts = parsePositiveInt(env.MAX_REMEDIATION_ATTEMPTS, DEFAULT_MAX_REMEDIATION_ATTEMPTS);
  const cooldownMinutes = parsePositiveInt(
    env.REMEDIATION_RETRY_COOLDOWN_MINUTES,
    DEFAULT_REMEDIATION_RETRY_COOLDOWN_MINUTES,
  );
  return { maxAttempts, cooldownMs: cooldownMinutes * 60_000 };
}

/**
 * Returns true when the finding's resource can be auto-remediated by its
 * control. Today this only screens GuardDuty.IAMUser findings whose principal
 * is a temporary (assumed-role / federated) credential: AWSSupport-ContainIAMPrincipal
 * needs an IAM user, and an `ASIA…` credential has none, so every attempt fails.
 * Screening here keeps those findings out of the auto-remediation path entirely
 * — no wasted executions, no retry consumed, and no Security Hub failure-note
 * writeback re-importing the finding into a re-trigger loop. A real IAM user
 * ARN (`:user/`) is always remediable, and all other controls pass through.
 */
export function isResourceAutoRemediable(normalized: NormalizedFinding, remediationIdentifier: string): boolean {
  if (remediationIdentifier !== GUARDDUTY_IAMUSER_REMEDIATION_ID) return true;
  const resourceId = normalized.resources[0]?.id ?? '';
  if (resourceId.includes(':user/')) return true;
  return !TEMPORARY_ACCESS_KEY_PATTERN.test(resourceId);
}

/**
 * Decides whether to (re-)trigger auto-remediation for a finding and whether
 * the retry cap was hit (so the caller can emit a metric).
 *
 * A first-time trigger fires when the base requirements hold. A finding that
 * previously FAILED is retried only while it is under the attempt cap AND past
 * the cooldown window — this bounds a deterministically-failing finding (so it
 * cannot re-trigger indefinitely — the auto-remediation re-trigger storm) and
 * spaces the allowed retries out rather than firing them back-to-back.
 */
export interface EvaluateAutoRemediationParams {
  normalized: NormalizedFinding;
  autoRemediationEnabled: boolean;
  isResourceRemediable: boolean;
  hasBeenTriggered: boolean;
  hasPreviouslyFailedRemediation: boolean;
  attempts: number;
  lastAttemptTime: string | undefined;
  retryPolicy: RetryPolicy;
  now: Date;
}

export interface AutoRemediationDecision {
  shouldTrigger: boolean;
  capReached: boolean;
}

export function evaluateAutoRemediation(params: EvaluateAutoRemediationParams): AutoRemediationDecision {
  const {
    normalized,
    autoRemediationEnabled,
    isResourceRemediable,
    hasBeenTriggered,
    hasPreviouslyFailedRemediation,
    attempts,
    lastAttemptTime,
    retryPolicy,
    now,
  } = params;

  const baseRequirements =
    autoRemediationEnabled &&
    isResourceRemediable &&
    normalized.complianceStatus === 'FAILED' &&
    normalized.recordState !== 'ARCHIVED' &&
    normalized.workflowStatus !== 'SUPPRESSED';
  if (!baseRequirements) return { shouldTrigger: false, capReached: false };

  // First-ever trigger for this finding.
  if (!hasBeenTriggered) return { shouldTrigger: true, capReached: false };

  // Already triggered and not in a FAILED state — nothing to retry.
  if (!hasPreviouslyFailedRemediation) return { shouldTrigger: false, capReached: false };

  // Previously failed: bound retries with an attempt cap...
  if (attempts >= retryPolicy.maxAttempts) return { shouldTrigger: false, capReached: true };
  // ...and space them out with a cooldown between attempts.
  if (lastAttemptTime) {
    const elapsed = now.getTime() - Date.parse(lastAttemptTime);
    if (Number.isFinite(elapsed) && elapsed >= 0 && elapsed < retryPolicy.cooldownMs) {
      return { shouldTrigger: false, capReached: false };
    }
  }
  return { shouldTrigger: true, capReached: false };
}
