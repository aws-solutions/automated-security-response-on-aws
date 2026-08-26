// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import type { NotificationConfigurationItem } from '@asr/data-models';

const MS_PER_DAY = 24 * 60 * 60 * 1000;

/**
 * Fixed, non-configurable lower bound applied to every computed `remediationDueBy`, measured from
 * the time of computation. It guarantees a finding cannot become overdue less than 24 hours after it
 * is stamped, so pre-existing backlog findings whose creation-time deadline is already in the past
 * still receive at least 24 hours of notice instead of becoming instantly overdue. This floor is
 * independent of and additional to the `remediationDeadlineDays` validation range of 1 to 90.
 */
export const MINIMUM_REMEDIATION_GRACE_HOURS = 24;
export const MINIMUM_REMEDIATION_GRACE_MS = MINIMUM_REMEDIATION_GRACE_HOURS * 60 * 60 * 1000;

/**
 * Computes a finding's `remediationDueBy` timestamp as the later of (a) its creation time plus
 * `deadlineDays` calendar days and (b) `now` plus the 24-hour Minimum_Grace_Period. Shared by the
 * write-time {@link FindingNotificationConfigEvaluator} and the async ReconciliationService so both
 * produce identical deadline values, and the single place the grace-period floor is applied.
 *
 * `now` is supplied by the caller (via `getClock().now()`) so the floor always clamps against the
 * caller's clock at the moment of computation: write-time stamping passes the ingestion time, while
 * reconciliation recompute passes the recompute time.
 */
export function computeRemediationDueBy(creationTime: string, deadlineDays: number, now: Date): string {
  const creationDate = new Date(creationTime);
  if (Number.isNaN(creationDate.getTime())) {
    // Fall back to grace floor when creationTime is invalid
    return new Date(now.getTime() + MINIMUM_REMEDIATION_GRACE_MS).toISOString();
  }
  const deadlineCandidate = creationDate.getTime() + deadlineDays * MS_PER_DAY;
  const graceFloor = now.getTime() + MINIMUM_REMEDIATION_GRACE_MS;
  return new Date(Math.max(deadlineCandidate, graceFloor)).toISOString();
}

/**
 * Determines whether a notification configuration currently enforces remediation deadlines. A
 * configuration enforces deadlines only when it is enabled, targets findings, has enforcement
 * switched on, includes the deadline in content, and specifies a deadline day count.
 *
 * Used wherever enforcement-contributing configs must be identified — eligibility evaluation at
 * write time and reconciliation value recomputation when a config changes.
 */
export function isEnforcementEnabledConfig(config: NotificationConfigurationItem): boolean {
  return (
    config.enabled &&
    config.notificationType === 'finding' &&
    config.contentOptions.enforceDeadline === true &&
    config.contentOptions.includeRemediationDeadline === true &&
    config.contentOptions.remediationDeadlineDays !== undefined
  );
}
