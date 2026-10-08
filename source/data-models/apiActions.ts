// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { FindingId } from './finding';

/**
 * Action names propagated through the orchestrator state machine via
 * `detail.actionName` (mapped to `event.CustomActionName` by the event
 * transformer). The Python `send_notifications` Lambda compares against
 * `ROLLBACK` to switch the persisted remediation status to the rollback
 * lifecycle states (`ROLLBACK_SUCCESS` / `ROLLBACK_FAILED`).
 *
 * IMPORTANT: keep these strings in sync with the Python constants in
 * `source/layer/asr_actions.py` (`CUSTOM_ACTION_NAME_ROLLBACK`).
 */
export const ASR_ACTION_NAMES = {
  REMEDIATE: 'Remediate with ASR',
  REMEDIATE_AND_TICKET: 'ASR:Remediate&Ticket',
  ROLLBACK: 'ASR:Rollback',
} as const;

export type AsrActionName = (typeof ASR_ACTION_NAMES)[keyof typeof ASR_ACTION_NAMES];

/** Maps API action types to the corresponding orchestrator action name. */
export const ACTION_TYPE_TO_ASR_ACTION_NAME: Readonly<
  Record<'Remediate' | 'RemediateAndGenerateTicket' | 'Rollback', AsrActionName>
> = {
  Remediate: ASR_ACTION_NAMES.REMEDIATE,
  RemediateAndGenerateTicket: ASR_ACTION_NAMES.REMEDIATE_AND_TICKET,
  Rollback: ASR_ACTION_NAMES.ROLLBACK,
};

/** Finding type eligible for the GuardDuty IAM credential rollback flow. */
export const ROLLBACK_ELIGIBLE_FINDING_TYPE = 'GuardDuty.IAMUser';

/**
 * Finding types eligible for rollback. Includes the legacy GuardDuty type and
 * the security controls that support snapshot-based rollback.
 */
export const ROLLBACK_ELIGIBLE_FINDING_TYPES: ReadonlySet<string> = new Set([
  ROLLBACK_ELIGIBLE_FINDING_TYPE,
  'KMS.4',
  'SNS.1',
  'RDS.6',
  'RDS.7',
  'RDS.8',
  'RDS.13',
  'RDS.16',
  'ElastiCache.1',
  'ElastiCache.2',
  'DynamoDB.6',
  'SSM.7',
  'S3.6',
  'SecretsManager.3',
]);

/** The subset of a remediation-history record that decides rollback eligibility. */
export interface RollbackEligibilityInput {
  remediationStatus?: string;
  rollbackAvailable?: boolean;
  rollbackBackupKey?: string;
  findingJSON?: Uint8Array;
}

/**
 * Whether a single remediation-history record can be rolled back on its own terms.
 *
 * Rollback is offered for the original successful containment (SUCCESS) and to retry a
 * previously failed rollback (ROLLBACK_FAILED). It is never offered for a failed remediation,
 * an in-progress run, or a rollback that already succeeded. Records that predate the
 * `rollbackAvailable` flag are treated as rollback-capable when they carry a backup key and
 * the finding snapshot needed to rebuild the request.
 *
 * This is the single source of truth shared by the REST `remediations` search
 * (`RemediationService.convertToApiResponse`, `isRollbackEligible` on each row) and the MCP
 * `get_finding_history` tool (via `FindingRemediationHistoryRepository`), so the two cannot
 * drift. Both then apply {@link narrowRollbackEligibilityToNewestPerFinding} so only the
 * newest row for a finding keeps eligibility.
 */
export function isRemediationRollbackEligible(record: RollbackEligibilityInput): boolean {
  const rollbackCapable =
    record.rollbackAvailable === true ||
    (!!record.rollbackBackupKey && !!(record.findingJSON && record.findingJSON.length > 0));
  const initiableStatus = record.remediationStatus === 'SUCCESS' || record.remediationStatus === 'ROLLBACK_FAILED';
  return rollbackCapable && initiableStatus;
}

/**
 * Narrows per-row eligibility to at most one row per finding: the single most recent
 * remediation entry, and only when that entry is itself eligible.
 *
 * Keying off the newest row *overall* — rather than the newest eligible row — is deliberate:
 * once a finding has been rolled back (its newest row is ROLLBACK_SUCCESS / ROLLBACK_IN_PROGRESS),
 * no earlier SUCCESS row may keep advertising rollback. Evaluating each row in isolation did
 * exactly that, so a history reader saw a stale "eligible" on an attempt that had already been
 * undone.
 *
 * Rows that share a finding's newest `lastUpdatedTime` are a tie. If any tied row is
 * ineligible, the finding has moved on and none of them keeps eligibility. If every tied row is
 * eligible, exactly one keeps it: the one with the greatest `executionId` (rows without one
 * compare as empty, and the first such row wins), so the choice is stable across calls and the
 * "at most one" contract holds even then.
 *
 * Operates on whatever the caller already has in hand (one page of search results, one
 * finding's history) — cross-page duplicates are harmless because the rollback lock re-validates
 * on execution. The rows are returned in their original order.
 */
export function narrowRollbackEligibilityToNewestPerFinding<
  T extends { findingId: string; lastUpdatedTime: string; executionId?: string; isRollbackEligible?: boolean },
>(rows: readonly T[]): T[] {
  const newestPerFinding = new Map<string, string>();
  for (const row of rows) {
    const existing = newestPerFinding.get(row.findingId);
    if (existing === undefined || row.lastUpdatedTime > existing) {
      newestPerFinding.set(row.findingId, row.lastUpdatedTime);
    }
  }
  // Among the rows tied at a finding's newest time: a single ineligible one disqualifies the
  // finding; otherwise the greatest executionId is the one row that stays eligible. The keeper
  // is tracked by row index, not by executionId value, so two tied rows that both lack an id
  // still resolve to exactly one.
  const tiedIneligible = new Set<string>();
  const keeperIndexByFinding = new Map<string, number>();
  rows.forEach((row, index) => {
    if (row.lastUpdatedTime !== newestPerFinding.get(row.findingId)) return;
    if (!row.isRollbackEligible) {
      tiedIneligible.add(row.findingId);
      return;
    }
    const keeper = keeperIndexByFinding.get(row.findingId);
    if (keeper === undefined || (row.executionId ?? '') > (rows[keeper].executionId ?? '')) {
      keeperIndexByFinding.set(row.findingId, index);
    }
  });
  return rows.map((row, index) => {
    if (!row.isRollbackEligible) return row;
    if (!tiedIneligible.has(row.findingId) && keeperIndexByFinding.get(row.findingId) === index) {
      return row;
    }
    return { ...row, isRollbackEligible: false };
  });
}

/**
 * How long a rollback may hold the optimistic lock (status
 * ROLLBACK_IN_PROGRESS) before it is considered stale and a new rollback may
 * re-acquire it. Bounds the GuardDuty restore runbook's worst-case runtime with
 * headroom so a crashed/timed-out execution never permanently blocks retry.
 */
export const ROLLBACK_TIMEOUT_MS = 30 * 60 * 1000;

/**
 * Derives the remediation configuration S3 bucket name for a given region and account.
 * The bucket is created by the member stack's `RemediationConfigurationBucket` construct
 * with this deterministic naming pattern.
 */
export function getRemediationConfigBucketName(region: string, accountId: string): string {
  return `so0111-asr-remediation-${region}-${accountId}`;
}

export type SuppressionResult = {
  suppressed: boolean;
};

export type RemediationResult = {
  remediationStatus: 'IN_PROGRESS' | 'FAILED';
  executionIdsByFindingId?: Map<FindingId, string>;
  error?: string;
};

export type ActionResult = SuppressionResult | RemediationResult;
