// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import {
  SSMClient,
  DeleteDocumentCommand,
  GetAutomationExecutionCommand,
  StopAutomationExecutionCommand,
  type AutomationExecution,
} from '@aws-sdk/client-ssm';
import { getIdGenerator, type IdGenerator } from '../../../common/utils/idGenerator';
import type { Clock } from '../../../common/utils/clock';
import type { Sleeper } from '../../../common/utils/sleeper';
import { getLogger } from '../../../common/utils/logger';

const logger = getLogger('McpServerSsmExecution');

const POLL_INTERVAL_MS = 3000;
/** SSM's own cap on a document name: `^[a-zA-Z0-9_\-.]{3,128}$`. */
const MAX_DOCUMENT_NAME_LENGTH = 128;

/**
 * Tag applied to every transient document these executors create. Nothing in
 * this package currently reaps documents left behind by a Lambda timeout or
 * `cleanup: false` — SSM's per-account document quota (default 500) is
 * shared with real ASR runbooks, so accumulated test debris eventually
 * blocks `deploy_runbook`. This tag is what a future reaper would filter on;
 * until one exists, an operator can find candidates with `ssm list-documents
 * --filters Key=tag:aws-solutions:asr-transient-test,Values=true`.
 */
export const TRANSIENT_DOCUMENT_TAG = { Key: 'aws-solutions:asr-transient-test', Value: 'true' } as const;

/**
 * Whether an SSM error means the document is absent, rather than a real failure.
 *
 * Matches both the typed exception name (`InvalidDocument`) AND a message that says the
 * document does not exist: SSM does not always surface a missing document as
 * `InvalidDocument`, so a caller keying only on the name rethrows a hard error for a
 * document that is simply not deployed. Shared by check_runbook_drift and
 * check_deploy_readiness so "not found" is classified the same way everywhere.
 */
export function isDocumentNotFound(error: unknown): boolean {
  if (!(error instanceof Error)) return false;
  return error.name === 'InvalidDocument' || error.message.includes('does not exist');
}

export type TerminalStatus =
  | 'Success'
  | 'Failed'
  | 'TimedOut'
  | 'Cancelled'
  | 'CompletedWithSuccess'
  | 'CompletedWithFailure'
  | 'Exited'
  | 'Rejected'
  | 'ChangeCalendarOverrideRejected';

/**
 * Every `AutomationExecutionStatus` SSM will not transition out of on its own.
 *
 * The obvious four are not the whole set: a caller-supplied runbook can contain
 * `aws:approve` (→ `Rejected`) or `aws:exit` (→ `Exited`), and SSM reports
 * `CompletedWithSuccess`/`CompletedWithFailure` instead of `Success`/`Failed`
 * for rate-controlled and multi-account executions. Omitting any of them makes
 * a finished execution poll until the timeout and then get reported as a
 * failure, so a healthy runbook looks broken.
 *
 * Deliberately excluded, because SSM does move out of them on its own:
 * `Pending`, `InProgress`, `Waiting`, `Scheduled`, `RunbookInProgress`,
 * `Cancelling` (the in-progress cancellation state, which becomes `Cancelled`),
 * `PendingApproval`/`Approved` and `PendingChangeCalendarOverride`/
 * `ChangeCalendarOverrideApproved` (which proceed to run).
 */
export function isTerminal(status: string | undefined): status is TerminalStatus {
  return (
    status === 'Success' ||
    status === 'Failed' ||
    status === 'TimedOut' ||
    status === 'Cancelled' ||
    status === 'CompletedWithSuccess' ||
    status === 'CompletedWithFailure' ||
    status === 'Exited' ||
    status === 'Rejected' ||
    status === 'ChangeCalendarOverrideRejected'
  );
}

/**
 * True for the terminal statuses that mean the automation actually succeeded.
 * SSM reports `CompletedWithSuccess` rather than `Success` for rate-controlled
 * and multi-account executions, so comparing against `'Success'` alone would
 * record a clean run as a failure.
 */
export function isSuccessful(status: string | undefined): boolean {
  return status === 'Success' || status === 'CompletedWithSuccess';
}

/**
 * True for an error the poll loop should absorb and retry rather than let
 * abort the whole test. At 200+ sequential `GetAutomationExecution` calls
 * (the schema's max timeout divided by the poll interval), a single
 * throttling response is expected, not exceptional — without this, one
 * `ThrottlingException` propagates out of `waitForTerminalStatus` and reports
 * a healthy runbook as a failed test.
 */
function hasHttpStatusCode(err: unknown): err is { $metadata: { httpStatusCode?: number } } {
  return (
    typeof err === 'object' &&
    err !== null &&
    '$metadata' in err &&
    typeof (err as Record<string, unknown>).$metadata === 'object' &&
    (err as Record<string, unknown>).$metadata !== null
  );
}

/**
 * Node socket/DNS failures that surface mid-poll with a `code` property and no
 * `$metadata`. These are transient — the connection dropped or a lookup timed
 * out — so the poll loop should retry them rather than abort the whole test.
 */
const TRANSIENT_NETWORK_CODES: ReadonlySet<string> = new Set([
  'ECONNRESET',
  'ETIMEDOUT',
  'EPIPE',
  'ENOTFOUND',
  'EAI_AGAIN',
  'ECONNREFUSED',
  'ENETUNREACH',
  'EHOSTUNREACH',
]);

function isRetryablePollError(err: unknown): boolean {
  if (!(err instanceof Error)) return false;

  // The SDK's own retryability verdict, when present, is authoritative.
  if ('$retryable' in err && (err as { $retryable?: unknown }).$retryable) return true;

  const name = 'name' in err ? String(err.name) : '';
  if (
    name === 'ThrottlingException' ||
    name === 'TooManyUpdatesException' ||
    name === 'RequestLimitExceeded' ||
    // The SDK's socket/abort timeouts surface as a named Error with no $retryable,
    // no code, and no $metadata, so none of the other branches match them. A poll
    // that hit a socket timeout should retry within the budget, not abort the run.
    name === 'TimeoutError' ||
    name === 'AbortError'
  ) {
    return true;
  }

  // Socket/DNS failures arrive as an Error with a `code` and no `$metadata`, so
  // the status-code branch below never sees them.
  const code = 'code' in err ? String((err as { code?: unknown }).code) : '';
  if (TRANSIENT_NETWORK_CODES.has(code)) return true;

  const statusCode = hasHttpStatusCode(err) ? err.$metadata.httpStatusCode : undefined;
  return statusCode === 429 || (statusCode !== undefined && statusCode >= 500);
}

/**
 * Polls `GetAutomationExecution` until the execution reaches a terminal state
 * or the budget runs out. The budget is slightly larger than the inner script
 * timeout so the script has a chance to time out first and report cleanly.
 *
 * A retryable error (throttling, a transient 5xx) is absorbed and counted
 * against the same deadline rather than propagated — at the poll interval's
 * cadence, a persistent failure still times out cleanly with the usual
 * "did not reach a terminal state" error instead of looping forever.
 */
/**
 * Best-effort stop of an automation this tool can no longer observe.
 *
 * Called only on the paths where `waitForTerminalStatus` gives up: the execution is
 * still running in the caller's account, and abandoning it leaves a remediation
 * acting on live resources with nothing watching it. Failures are swallowed — the
 * poll error is the one worth surfacing, and the execution may have reached a
 * terminal state on its own between the last poll and this call, which SSM rejects.
 */
async function tryStopExecution(
  client: SSMClient,
  executionId: string,
  toolName: string,
): Promise<{ readonly stopped: boolean; readonly stopError: string | undefined }> {
  try {
    await client.send(new StopAutomationExecutionCommand({ AutomationExecutionId: executionId, Type: 'Cancel' }));
    return { stopped: true, stopError: undefined };
  } catch (stopError) {
    const stopErrorMessage = stopError instanceof Error ? stopError.message : String(stopError);
    logger.warn(`${toolName}: could not stop execution ${executionId} after abandoning the poll: ${stopErrorMessage}`);
    return { stopped: false, stopError: stopErrorMessage };
  }
}

/**
 * A sentence the caller can act on when a stop could not be confirmed: the execution may
 * still be running and mutating live resources, so it names the manual cancel command.
 */
function manualCancelHint(executionId: string, stopError: string | undefined): string {
  return (
    `WARNING: it could not be cancelled (${stopError ?? 'unknown error'}), so it may still be running and making ` +
    `changes. Cancel it manually: aws ssm stop-automation-execution --automation-execution-id ${executionId} --type Cancel`
  );
}

export async function waitForTerminalStatus(
  client: SSMClient,
  executionId: string,
  timeoutSeconds: number,
  clock: Clock,
  sleeper: Sleeper,
  toolName: string,
): Promise<AutomationExecution> {
  const deadline = clock.now().getTime() + (timeoutSeconds + 30) * 1000;

  const pollOnce = async (): Promise<AutomationExecution | undefined> => {
    try {
      const resp = await client.send(new GetAutomationExecutionCommand({ AutomationExecutionId: executionId }));
      const execution = resp.AutomationExecution;
      if (execution && isTerminal(execution.AutomationExecutionStatus)) return execution;
    } catch (err) {
      if (!isRetryablePollError(err)) {
        await tryStopExecution(client, executionId, toolName);
        throw err;
      }
    }
    return undefined;
  };

  while (clock.now().getTime() < deadline) {
    const execution = await pollOnce();
    if (execution) return execution;
    await sleeper.sleep(POLL_INTERVAL_MS);
  }

  // One last poll before declaring a timeout. The loop sleeps at the bottom, so an
  // execution that reached a terminal state during that final sleep would otherwise
  // be reported as a timeout — and the caller would ask SSM to stop a run that had
  // already finished. That misattributed a healthy remediation as a failed one.
  const finalExecution = await pollOnce();
  if (finalExecution) return finalExecution;

  const { stopped, stopError } = await tryStopExecution(client, executionId, toolName);
  const stopClause = stopped ? 'A stop was requested for it.' : manualCancelHint(executionId, stopError);
  throw new Error(
    `${toolName}: execution ${executionId} did not reach a terminal state within ${timeoutSeconds}s + 30s poll budget. ` +
      stopClause,
  );
}

export async function tryDeleteDocument(
  client: SSMClient,
  documentName: string,
): Promise<{ readonly cleanedUp: boolean; readonly deleteError: string | undefined }> {
  try {
    await client.send(new DeleteDocumentCommand({ Name: documentName }));
    return { cleanedUp: true, deleteError: undefined };
  } catch (err) {
    return { cleanedUp: false, deleteError: err instanceof Error ? err.message : String(err) };
  }
}

/**
 * Builds a transient document name, always under `prefix`.
 *
 * A caller-supplied `explicit` name is honored only as the SUFFIX after
 * `prefix` — not verbatim. `prefix` is what scopes the Lambda's
 * `ssm:CreateDocument`/`ssm:DeleteDocument` IAM grant (e.g.
 * `arn:...:document/ASR-Custom-Test*`) and what a reaper would key off of to
 * find abandoned transient documents; honoring an arbitrary caller-supplied
 * name verbatim would let a document escape both.
 */
export function generateDocumentName(
  prefix: string,
  explicit: string | undefined,
  controlId: string | undefined,
  clock: Clock,
  idGenerator: IdGenerator = getIdGenerator(),
): string {
  if (explicit) {
    // Sanitised on the same terms as a generated name. SSM enforces
    // `^[a-zA-Z0-9_\-.]{3,128}$`, so a caller-supplied name containing a space or
    // any other character outside that set used to reach CreateDocument and fail
    // with an opaque validation error rather than being corrected here.
    const sanitized = sanitizeForSsmName(explicit);
    return clampToSsmLimit(sanitized.startsWith(prefix) ? sanitized : `${prefix}${sanitized}`);
  }
  const slug = controlId ? controlId.replace(/[^A-Za-z0-9]/g, '-') : 'adhoc';
  // Timestamp alone collides: two calls in the same millisecond produce the same
  // name, and CreateDocument then fails the second with DocumentAlreadyExists —
  // or worse, the first one's cleanup deletes the document the second is running.
  // The random suffix makes concurrent tests independent. Drawn from the injected
  // IdGenerator (ADR 0004) rather than node:crypto directly, so a test can pin it
  // and assert the generated name; 8 hex chars matches the previous 4 random bytes.
  const randomSuffix = idGenerator.randomUUID().replaceAll('-', '').slice(0, 8);
  const suffix = `${clock.now().getTime().toString(36)}-${randomSuffix}`;
  // The slug is clamped BEFORE the suffix is appended, so the suffix always
  // survives. Clamping the joined string instead truncated from the tail and could
  // cut the suffix off entirely, reinstating exactly the collision it prevents.
  // The final result is still wrapped in clampToSsmLimit as a backstop: when the
  // prefix + suffix alone already exceed the limit, `room` goes negative, the slug
  // slice is empty, and `${prefix}-${suffix}` can still be over 128 chars — which
  // CreateDocument would reject.
  const room = MAX_DOCUMENT_NAME_LENGTH - prefix.length - suffix.length - 1;
  return clampToSsmLimit(`${prefix}${slug.slice(0, Math.max(room, 0))}-${suffix}`);
}

/**
 * Replace every character SSM disallows in a document name with a hyphen.
 *
 * Deliberately more permissive than the control-ID slug rule above, which also
 * collapses `.` so `S3.9` reads as `S3-9`. A caller-supplied name is theirs to
 * shape — this only removes what `CreateDocument` would reject.
 */
function sanitizeForSsmName(value: string): string {
  return value.replace(/[^A-Za-z0-9_\-.]/g, '-');
}

/**
 * SSM document names are limited to 128 characters (`^[a-zA-Z0-9_\-.]{3,128}$`),
 * and both inputs here can exceed it — a caller-supplied `explicit` name is
 * unbounded, and a long control ID plus prefix and suffix can too. Truncating
 * from the front would drop the `ASR-` prefix the cleanup sweep relies on to find
 * abandoned transient documents, so the tail is what gives way.
 */
function clampToSsmLimit(name: string): string {
  return name.length <= MAX_DOCUMENT_NAME_LENGTH ? name : name.slice(0, MAX_DOCUMENT_NAME_LENGTH);
}
