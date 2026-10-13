// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * The SSM Automation statuses that mean "finished", from the `AutomationExecutionStatus`
 * enum in the GetAutomationExecution API reference.
 *
 * Shared because two independent polling loops classify the same statuses — the MCP tools'
 * loop and the API's drift-detection loop. They are deliberately separate loops (different
 * time budgets) but "which statuses are terminal" is one fact, and a set that drifts between
 * them makes a finished execution look in-progress on one side until its budget runs out.
 *
 * Deliberately excluded, because they still transition: Pending, InProgress, Waiting,
 * Cancelling, PendingApproval, Approved, Scheduled, RunbookInProgress,
 * PendingChangeCalendarOverride, ChangeCalendarOverrideApproved.
 */
export type TerminalAutomationStatus =
  | 'Success'
  | 'CompletedWithSuccess'
  | 'Failed'
  | 'CompletedWithFailure'
  | 'TimedOut'
  | 'Cancelled'
  | 'Rejected'
  | 'ChangeCalendarOverrideRejected'
  | 'Exited';

export const TERMINAL_AUTOMATION_STATUSES: ReadonlySet<string> = new Set<TerminalAutomationStatus>([
  'Success',
  'CompletedWithSuccess',
  'Failed',
  'CompletedWithFailure',
  'TimedOut',
  'Cancelled',
  'Rejected',
  'ChangeCalendarOverrideRejected',
  'Exited',
]);

/** The two statuses that mean the automation finished and did what it was asked. */
export const SUCCESSFUL_AUTOMATION_STATUSES: ReadonlySet<string> = new Set(['Success', 'CompletedWithSuccess']);

export function isTerminalAutomationStatus(status: string | undefined): status is TerminalAutomationStatus {
  return status !== undefined && TERMINAL_AUTOMATION_STATUSES.has(status);
}
