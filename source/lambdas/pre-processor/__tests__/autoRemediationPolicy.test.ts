// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { NormalizedFinding } from '@asr/data-models';
import {
  DEFAULT_MAX_REMEDIATION_ATTEMPTS,
  DEFAULT_REMEDIATION_RETRY_COOLDOWN_MINUTES,
  evaluateAutoRemediation,
  getRetryPolicy,
  isResourceAutoRemediable,
  parsePositiveInt,
  RetryPolicy,
} from '../autoRemediationPolicy';

// Synthetic (non-real) access-key ids for tests. Assembled from fragments and
// kept short so secret scanners do not flag them as real AWS keys, while still
// carrying the ASIA (temporary/STS) vs AKIA (long-term IAM user) prefix that
// isResourceAutoRemediable keys off.
const TEMP_ACCESS_KEY_ID = 'ASIA' + 'FAKETEMPKEY01';
const LONG_TERM_ACCESS_KEY_ID = 'AKIA' + 'FAKEUSERKEY01';

/**
 * Builds a complete, valid NormalizedFinding; override only the fields under
 * test. Fully populated (no `as unknown as` cast, per ADR 0001) so the test data
 * stays type-checked and resilient to field additions on NormalizedFinding.
 */
function normalized(overrides: Partial<NormalizedFinding> = {}): NormalizedFinding {
  return {
    id: 'finding-1',
    productArn: 'arn:aws:securityhub:us-east-1::product/aws/securityhub',
    findingTypeIdentifier: { type: 'securityControl', value: 'S3.8' },
    accountId: '111122223333',
    region: 'us-east-1',
    severity: 'HIGH',
    complianceStatus: 'FAILED',
    recordState: 'ACTIVE',
    workflowStatus: 'NEW',
    resources: [{ id: `AWS::IAM::AccessKey:${LONG_TERM_ACCESS_KEY_ID}`, type: 'AwsIamAccessKey' }],
    title: 'test finding',
    description: 'test finding description',
    createdAt: '2026-07-14T00:00:00.000Z',
    updatedAt: '2026-07-14T00:00:00.000Z',
    format: 'ASFF',
    raw: {},
    ...overrides,
  };
}

const TEST_POLICY: RetryPolicy = { maxAttempts: 3, cooldownMs: 15 * 60_000 };
const NOW = new Date('2026-07-14T00:00:00.000Z');

describe('isResourceAutoRemediable', () => {
  it('passes through any non-GuardDuty.IAMUser control', () => {
    const f = normalized({
      resources: [{ id: TEMP_ACCESS_KEY_ID, type: 'AwsIamAccessKey' }],
    } as Partial<NormalizedFinding>);
    expect(isResourceAutoRemediable(f, 'S3.8')).toBe(true);
  });

  it('screens out a bare temporary (ASIA) access key for GuardDuty.IAMUser', () => {
    const f = normalized({
      resources: [{ id: TEMP_ACCESS_KEY_ID, type: 'AwsIamAccessKey' }],
    } as Partial<NormalizedFinding>);
    expect(isResourceAutoRemediable(f, 'GuardDuty.IAMUser')).toBe(false);
  });

  it('screens out a CFN-prefixed temporary (ASIA) access key for GuardDuty.IAMUser', () => {
    const f = normalized({
      resources: [{ id: `AWS::IAM::AccessKey:${TEMP_ACCESS_KEY_ID}`, type: 'AwsIamAccessKey' }],
    } as Partial<NormalizedFinding>);
    expect(isResourceAutoRemediable(f, 'GuardDuty.IAMUser')).toBe(false);
  });

  it('allows a long-term (AKIA) access key for GuardDuty.IAMUser', () => {
    const f = normalized({
      resources: [{ id: `AWS::IAM::AccessKey:${LONG_TERM_ACCESS_KEY_ID}`, type: 'AwsIamAccessKey' }],
    } as Partial<NormalizedFinding>);
    expect(isResourceAutoRemediable(f, 'GuardDuty.IAMUser')).toBe(true);
  });

  it('allows a real IAM user ARN for GuardDuty.IAMUser even if other text is present', () => {
    const f = normalized({
      resources: [{ id: 'arn:aws:iam::111122223333:user/alice', type: 'AwsIamAccessKey' }],
    } as Partial<NormalizedFinding>);
    expect(isResourceAutoRemediable(f, 'GuardDuty.IAMUser')).toBe(true);
  });

  it('allows when there is no resource id', () => {
    const f = normalized({ resources: [] } as Partial<NormalizedFinding>);
    expect(isResourceAutoRemediable(f, 'GuardDuty.IAMUser')).toBe(true);
  });
});

describe('evaluateAutoRemediation', () => {
  const base = {
    autoRemediationEnabled: true,
    isResourceRemediable: true,
    hasBeenTriggered: false,
    hasPreviouslyFailedRemediation: false,
    attempts: 0,
    lastAttemptTime: undefined as string | undefined,
    retryPolicy: TEST_POLICY,
    now: NOW,
  };

  it('triggers on first sight when base requirements hold', () => {
    expect(evaluateAutoRemediation({ ...base, normalized: normalized() })).toEqual({
      shouldTrigger: true,
      capReached: false,
    });
  });

  it.each([
    ['auto-remediation disabled', { autoRemediationEnabled: false }],
    ['resource not remediable', { isResourceRemediable: false }],
  ])('does not trigger when %s', (_label, patch) => {
    expect(evaluateAutoRemediation({ ...base, ...patch, normalized: normalized() }).shouldTrigger).toBe(false);
  });

  it.each([
    ['compliance PASSED', { complianceStatus: 'PASSED' }],
    ['record ARCHIVED', { recordState: 'ARCHIVED' }],
    ['workflow SUPPRESSED', { workflowStatus: 'SUPPRESSED' }],
  ])('does not trigger when %s', (_label, overrides) => {
    const result = evaluateAutoRemediation({
      ...base,
      normalized: normalized(overrides as Partial<NormalizedFinding>),
    });
    expect(result.shouldTrigger).toBe(false);
  });

  it('does not retry a finding that was triggered and is not in FAILED state', () => {
    const result = evaluateAutoRemediation({
      ...base,
      normalized: normalized(),
      hasBeenTriggered: true,
      hasPreviouslyFailedRemediation: false,
      attempts: 1,
    });
    expect(result).toEqual({ shouldTrigger: false, capReached: false });
  });

  it('retries a previously-failed finding under the cap with no prior timestamp', () => {
    const result = evaluateAutoRemediation({
      ...base,
      normalized: normalized(),
      hasBeenTriggered: true,
      hasPreviouslyFailedRemediation: true,
      attempts: 1,
      lastAttemptTime: undefined,
    });
    expect(result).toEqual({ shouldTrigger: true, capReached: false });
  });

  it('stops retrying and flags capReached once attempts reach the cap', () => {
    const result = evaluateAutoRemediation({
      ...base,
      normalized: normalized(),
      hasBeenTriggered: true,
      hasPreviouslyFailedRemediation: true,
      attempts: TEST_POLICY.maxAttempts,
      lastAttemptTime: '2020-01-01T00:00:00.000Z',
    });
    expect(result).toEqual({ shouldTrigger: false, capReached: true });
  });

  it('does not retry while still inside the cooldown window', () => {
    const fiveMinutesAgo = new Date(NOW.getTime() - 5 * 60_000).toISOString();
    const result = evaluateAutoRemediation({
      ...base,
      normalized: normalized(),
      hasBeenTriggered: true,
      hasPreviouslyFailedRemediation: true,
      attempts: 1,
      lastAttemptTime: fiveMinutesAgo,
    });
    expect(result).toEqual({ shouldTrigger: false, capReached: false });
  });

  it('retries once the cooldown window has elapsed', () => {
    const twentyMinutesAgo = new Date(NOW.getTime() - 20 * 60_000).toISOString();
    const result = evaluateAutoRemediation({
      ...base,
      normalized: normalized(),
      hasBeenTriggered: true,
      hasPreviouslyFailedRemediation: true,
      attempts: 1,
      lastAttemptTime: twentyMinutesAgo,
    });
    expect(result).toEqual({ shouldTrigger: true, capReached: false });
  });
});

describe('parsePositiveInt', () => {
  it('returns the fallback for undefined', () => {
    expect(parsePositiveInt(undefined, 7)).toBe(7);
  });

  it.each(['0', '-1', 'abc', '1.5', ''])('returns the fallback for invalid input %p', (value) => {
    expect(parsePositiveInt(value, 7)).toBe(7);
  });

  it('parses a valid positive integer', () => {
    expect(parsePositiveInt('5', 7)).toBe(5);
  });
});

describe('getRetryPolicy', () => {
  it('uses defaults when the env config values are unset', () => {
    expect(getRetryPolicy({})).toEqual({
      maxAttempts: DEFAULT_MAX_REMEDIATION_ATTEMPTS,
      cooldownMs: DEFAULT_REMEDIATION_RETRY_COOLDOWN_MINUTES * 60_000,
    });
  });

  it('honours env config overrides', () => {
    expect(getRetryPolicy({ MAX_REMEDIATION_ATTEMPTS: '2', REMEDIATION_RETRY_COOLDOWN_MINUTES: '30' })).toEqual({
      maxAttempts: 2,
      cooldownMs: 30 * 60_000,
    });
  });
});
