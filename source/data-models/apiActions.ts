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
 * How long a rollback may hold the optimistic lock (status
 * ROLLBACK_IN_PROGRESS) before it is considered stale and a new rollback may
 * re-acquire it. Bounds the GuardDuty restore runbook's worst-case runtime with
 * headroom so a crashed/timed-out execution never permanently blocks retry.
 */
export const ROLLBACK_TIMEOUT_MS = 30 * 60 * 1000;

export type SuppressionResult = {
  suppressed: boolean;
};

export type RemediationResult = {
  remediationStatus: 'IN_PROGRESS' | 'FAILED';
  executionIdsByFindingId?: Map<FindingId, string>;
  error?: string;
};

export type ActionResult = SuppressionResult | RemediationResult;
