// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import {
  SSMClient,
  CreateDocumentCommand,
  StartAutomationExecutionCommand,
  type AutomationExecution,
} from '@aws-sdk/client-ssm';
import * as yaml from 'js-yaml';
import type { Executor } from '../types';
import type { TestRemediationScriptParams } from '../../contract/toolContract';
import { MissingParameterError, ValidationError } from './errors';
import { getClock, type Clock } from '../../../common/utils/clock';
import { getSleeper, type Sleeper } from '../../../common/utils/sleeper';
import { getIdGenerator, type IdGenerator } from '../../../common/utils/idGenerator';
import { CUSTOM_RUNBOOK_TEST_ROLE_PREFIX } from './customRunbookTestRoleService';
import {
  waitForTerminalStatus,
  tryDeleteDocument,
  generateDocumentName,
  isSuccessful,
  TRANSIENT_DOCUMENT_TAG,
} from './ssmExecutionHelpers';

/**
 * Default timeout for the inner script (seconds). The outer SSM timeout budget
 * needs to be a little larger so the document itself doesn't win the race.
 */
const DEFAULT_TIMEOUT_SECONDS = 300;
const DEFAULT_RUNTIME = 'python3.11';
const DEFAULT_HANDLER = 'handler';
const DOCUMENT_NAME_PREFIX = 'ASR-Custom-TestRemediation-';

/**
 * SSM caps `aws:executeScript` at 600 seconds (the asr-remediation-authoring
 * skill's `references/ssm-best-practices.md` — "Max 600s"); the schema's own max
 * is wider, so this is the backstop that keeps a caller-supplied value from
 * reaching `CreateDocument`/`StartAutomationExecution` with a timeout SSM will
 * refuse.
 */
const MAX_EXECUTE_SCRIPT_TIMEOUT_SECONDS = 600;

/**
 * SSM's hard `CreateDocument` content quota (64 KB, in bytes — the quota also
 * counts runtime input parameter content, which this budget does not
 * account for). The schema's own `python_script` max (60,000 chars) bounds
 * the script alone; it does not bound the rendered document, which also
 * carries the wrapper's fixed fields, the input-parameter declarations, and
 * whatever `js-yaml` needs to escape the script into a scalar. Checking the
 * actual rendered size here turns an oversized script into a clear error
 * instead of an opaque `CreateDocument` rejection after everything else has
 * already run.
 */
const MAX_DOCUMENT_BYTES = 65536;

/**
 * Character bound the generated document's per-parameter `allowedPattern`
 * enforces server-side (`{0,10000}` in `buildDocumentContent` below). Also
 * checked client-side, on the actual JSON-stringified value about to be sent
 * as an SSM parameter: without this, an oversized `input_payload` value
 * creates the document successfully and only fails once `StartAutomationExecution`
 * evaluates the pattern — the exact opaque-late-failure shape
 * `validateDocumentSize` exists to prevent for document size, just one step
 * later in the flow.
 */
const MAX_INPUT_VALUE_LENGTH = 10000;

/**
 * `inputKeys` become parameter names in the generated document and are reused
 * directly as SSM `StartAutomationExecution` parameter keys. Restricting them
 * to a safe, unambiguous charset here means the YAML builder below never has
 * to reason about what an adversarial key could do to document structure.
 * Underscores are allowed: they are a normal part of SSM Automation parameter
 * names and the natural authoring style for input_payload keys mirroring
 * Python kwargs (`bucket_name`, `finding_id`) — banning them was this tool's
 * own invented narrowing, not an SSM restriction, and the message below says
 * so rather than implying otherwise.
 */
const SSM_PARAM_NAME = /^[A-Za-z][A-Za-z0-9_]*$/;

function validateInputKeys(inputKeys: readonly string[]): void {
  for (const key of inputKeys) {
    if (key === 'AutomationAssumeRole') {
      throw new ValidationError(`test_remediation_script: input_payload key "${key}" is reserved.`);
    }
    if (!SSM_PARAM_NAME.test(key)) {
      throw new ValidationError(
        `test_remediation_script: input_payload key "${key}" must start with a letter and contain only letters, ` +
          'digits, and underscores. This is a narrowing this tool applies for safety, not an SSM restriction.',
      );
    }
  }
}

export interface TestRemediationScriptResult {
  readonly documentName: string;
  readonly executionId: string | undefined;
  readonly status: string | undefined;
  readonly durationSeconds: number;
  readonly failureMessage: string | undefined;
  readonly cleanupError: string | undefined;
  readonly output: unknown;
  readonly cleanedUp: boolean;
}

/**
 * Builds the SSM Automation document YAML used to wrap the candidate Python
 * script in a single `aws:executeScript` step.
 *
 * Built as a plain object and serialised with `js-yaml`'s `dump()` rather than
 * string concatenation: every value here — the script body, input keys already
 * validated by `validateInputKeys`, description text — goes through the YAML
 * emitter's own escaping, so no value can restructure the document regardless
 * of embedded quotes, colons, or line endings (including CRLF, which a
 * hand-rolled block-scalar indenter would not survive).
 *
 * We intentionally keep the document minimal:
 *   1. Takes an `AutomationAssumeRole` parameter so the script gets IAM perms.
 *   2. Declares `InputPayload` parameters matching the user's `input_payload`.
 *   3. Exposes `$.Payload` as an output so we can read the handler's return.
 */
function buildDocumentContent(params: {
  readonly runtime: string;
  readonly handler: string;
  readonly pythonScript: string;
  readonly inputKeys: readonly string[];
  readonly timeoutSeconds: number;
}): string {
  const { runtime, handler, pythonScript, inputKeys, timeoutSeconds } = params;

  const inputParameters = Object.fromEntries(
    inputKeys.map((key) => [
      key,
      {
        type: 'String',
        description: `Input value for ${key}.`,
        // Values are opaque (arbitrary strings or JSON-stringified payloads),
        // so this bounds length and excludes control characters rather than
        // constraining shape — see `references/ssm-best-practices.md`'s
        // allowedPattern rule.
        allowedPattern: INPUT_VALUE_ALLOWED_PATTERN,
      },
    ]),
  );

  const document = {
    schemaVersion: '0.3',
    description: 'Transient ASR remediation test runner (created by asr-mcp).',
    assumeRole: '{{ AutomationAssumeRole }}',
    parameters: {
      AutomationAssumeRole: {
        type: 'String',
        description: 'IAM role SSM Automation assumes to run the script.',
        // Partition is `[a-z-]+`, not an enumerated `(aws|aws-cn|aws-us-gov)` —
        // AWS has additional restricted-availability partitions beyond those
        // three, so the partition is read from the ARN rather than matched
        // against a fixed list. Enumerating partitions here would silently
        // reject a role ARN valid in those partitions.
        //
        // The resource segment's character class includes `/` so the document schema itself
        // stays a plain IAM-role-ARN shape. Whether a path-qualified role is *usable* is a
        // separate question answered by resolveAssumeRole before the document is created:
        // the server's PassRole grant is on `role/<prefix>*`, which a path does not match.
        allowedPattern: '^arn:[a-z-]+:iam::\\d{12}:role/[\\w+=,.@/-]+$',
      },
      ...inputParameters,
    },
    mainSteps: [
      {
        name: 'RunCandidateScript',
        action: 'aws:executeScript',
        timeoutSeconds,
        // Explicit rather than relying on the implicit SSM default, per
        // `references/ssm-best-practices.md`: this is a single-step document,
        // so there is nothing to fall through to on failure or cancellation,
        // and a candidate script under test should not be silently retried.
        onFailure: 'Abort',
        onCancel: 'Abort',
        maxAttempts: 1,
        outputs: [{ Name: 'Payload', Selector: '$.Payload', Type: 'StringMap' }],
        inputs: {
          Runtime: runtime,
          Handler: handler,
          InputPayload: Object.fromEntries(inputKeys.map((key) => [key, `{{ ${key} }}`])),
          Script: pythonScript,
        },
      },
    ],
  };

  return yaml.dump(document, { lineWidth: -1 });
}

/** Throws when the rendered document exceeds SSM's 64 KB `CreateDocument` quota. */
function validateDocumentSize(documentContent: string): void {
  const size = Buffer.byteLength(documentContent, 'utf8');
  if (size > MAX_DOCUMENT_BYTES) {
    throw new ValidationError(
      `test_remediation_script: the rendered SSM document is ${size} bytes, exceeding SSM's ` +
        `${MAX_DOCUMENT_BYTES}-byte CreateDocument quota. Shorten python_script or reduce the number of input_payload keys.`,
    );
  }
}

/**
 * Single source of truth for the per-parameter allowedPattern. Used both in
 * `buildDocumentContent` (server-side enforcement via SSM) and in the client-side
 * `validateInputValues` check, so neither can drift without the other.
 */
const INPUT_VALUE_ALLOWED_PATTERN = `^[^\\x00-\\x08\\x0b\\x0c\\x0e-\\x1f]{0,${MAX_INPUT_VALUE_LENGTH}}$`;
const INPUT_VALUE_PATTERN = new RegExp(INPUT_VALUE_ALLOWED_PATTERN);

/**
 * Throws when a stringified `input_payload` value would fail the generated
 * document's own `allowedPattern` on the SSM side. Validates against the full
 * pattern (length + control-character exclusion) rather than length alone, so
 * an embedded control character is caught here instead of producing an opaque
 * server-side rejection.
 */
function validateInputValues(parameters: Readonly<Record<string, readonly string[]>>): void {
  for (const [key, values] of Object.entries(parameters)) {
    for (const value of values) {
      if (!INPUT_VALUE_PATTERN.test(value)) {
        throw new ValidationError(
          `test_remediation_script: input_payload key "${key}" is either longer than ` +
            `${MAX_INPUT_VALUE_LENGTH} characters or contains a control character disallowed ` +
            `by the generated document's allowedPattern.`,
        );
      }
    }
  }
}

/**
 * Matches the generated document's AutomationAssumeRole allowedPattern, capturing the account
 * and the full resource segment after `role/` (path included, if any).
 */
const ASSUME_ROLE_PATTERN = /^arn:[a-z-]+:iam::(\d{12}):role\/([\w+=,.@/-]+)$/;

/**
 * Resolve the AutomationAssumeRole to use for the transient execution.
 *
 * There is no fallback. `automation_assume_role` is the only source: an
 * `ASR_TEST_ASSUME_ROLE` env var would be ambient-credential behavior, and on
 * the deployed Lambda a single env var would apply to every caller, defeating
 * the per-request role the schema is designed around. It is deliberately unset
 * there, so advertising it as a fallback only produced advice a remote MCP
 * caller cannot act on — they cannot set env vars on someone else's Lambda.
 *
 * The prefix and account checks are pre-flight on purpose. The MCP server's own
 * role may only `iam:PassRole` roles named `SO0111-Remediate-Custom-Test-*`, in
 * its own account, to SSM. A role outside that scope is refused by
 * `StartAutomationExecution` with a raw IAM `AccessDenied`, which the catch
 * block below records as `failureMessage` on an HTTP 200 — indistinguishable
 * from "your script failed". Checking here turns the caller's mistake into a
 * 400 that names the constraint, matching what `validateDocumentSize` and
 * `validateInputValues` already do for the other opaque late failures. Errors
 * from an execution that actually starts still belong in `failureMessage`:
 * reporting the test outcome is this tool's contract.
 */
function resolveAssumeRole(explicit: string | undefined, expectedAccountId: string | undefined): string {
  if (!explicit) {
    throw new MissingParameterError(
      'test_remediation_script',
      'AutomationAssumeRole',
      `Pass \`automation_assume_role\`. The role name must begin with "${CUSTOM_RUNBOOK_TEST_ROLE_PREFIX}".`,
    );
  }
  const match = ASSUME_ROLE_PATTERN.exec(explicit);
  if (!match) {
    throw new ValidationError(
      `test_remediation_script: AutomationAssumeRole "${explicit}" is not a valid IAM role ARN.`,
    );
  }
  const [, accountId, roleResource] = match;
  // `accountId` is absent from the executor context only outside the Lambda (the context type
  // makes it optional). Skip the cross-account check rather than inventing an expectation, but
  // still enforce the name — that constraint holds wherever this executor runs.
  if (expectedAccountId !== undefined && accountId !== expectedAccountId) {
    throw new ValidationError(
      `test_remediation_script: AutomationAssumeRole must be a role in account ${expectedAccountId}, ` +
        `got ${accountId}. This server can only pass a role from its own account to SSM.`,
    );
  }
  // The grant is `iam:PassRole` on `arn:...:role/<prefix>*` — a resource match on the whole
  // segment after `role/`, so a path-qualified role (`role/service-role/<prefix>x`) does not
  // match it even though its final name carries the prefix. Checking only the last path segment
  // here accepted exactly those ARNs and let them fail inside StartAutomationExecution.
  if (roleResource.includes('/')) {
    throw new ValidationError(
      `test_remediation_script: AutomationAssumeRole "${roleResource}" carries an IAM path. This server may ` +
        `only pass roles at the root path named "${CUSTOM_RUNBOOK_TEST_ROLE_PREFIX}*"; create the test role ` +
        'without a path.',
    );
  }
  if (!roleResource.startsWith(CUSTOM_RUNBOOK_TEST_ROLE_PREFIX)) {
    throw new ValidationError(
      `test_remediation_script: AutomationAssumeRole "${roleResource}" must begin with ` +
        `"${CUSTOM_RUNBOOK_TEST_ROLE_PREFIX}". That is the only prefix this server is permitted to ` +
        'iam:PassRole to SSM; any other role fails inside StartAutomationExecution with an IAM denial.',
    );
  }
  return explicit;
}

/**
 * Extract the handler's return dict from the SSM execution output map.
 *
 * `GetAutomationExecution` returns `StepExecutions[].Outputs` keyed by the
 * selector names configured in the document plus the built-in `Payload` and
 * `OutputPayload` entries that `aws:executeScript` always writes. We read
 * the step's own outputs first (robust to document changes) and fall back
 * to the top-level document outputs if the step is missing.
 */
function extractPayload(execution: AutomationExecution): unknown {
  const stepOutputs = execution.StepExecutions?.[0]?.Outputs ?? {};
  const stepPayload = stepOutputs['Payload'];
  if (stepPayload && stepPayload.length > 0) {
    try {
      return JSON.parse(stepPayload[0]);
    } catch {
      return stepPayload[0];
    }
  }

  const outputs = execution.Outputs ?? {};
  const candidate = outputs['RunCandidateScript.Payload'];
  if (!candidate || candidate.length === 0) return undefined;
  const raw = candidate[0];
  try {
    return JSON.parse(raw);
  } catch {
    return raw;
  }
}

/** Stringifies `input_payload` values into the shape SSM `Parameters` expects (string arrays). */
function buildInputPayloadParameters(
  inputKeys: readonly string[],
  inputPayload: Readonly<Record<string, unknown>>,
): Record<string, string[]> {
  const parameters: Record<string, string[]> = {};
  for (const key of inputKeys) {
    const value = inputPayload[key];
    parameters[key] = [typeof value === 'string' ? value : JSON.stringify(value)];
  }
  return parameters;
}

/** Creates an executor with an injectable clock and sleeper for deterministic tests. */
export function createTestRemediationScript(
  clock: Clock = getClock(),
  sleeper: Sleeper = getSleeper(),
  idGenerator: IdGenerator = getIdGenerator(),
): Executor<TestRemediationScriptParams, TestRemediationScriptResult> {
  return async (args, context) => {
    const runtime = args.runtime ?? DEFAULT_RUNTIME;
    const handler = args.handler ?? DEFAULT_HANDLER;
    const timeoutSeconds = Math.min(
      args.timeout_seconds ?? DEFAULT_TIMEOUT_SECONDS,
      MAX_EXECUTE_SCRIPT_TIMEOUT_SECONDS,
    );
    const cleanup = args.cleanup ?? true;
    const inputPayload = args.input_payload ?? {};
    const inputKeys = Object.keys(inputPayload);

    const assumeRole = resolveAssumeRole(args.automation_assume_role, context.accountId);
    const documentName = generateDocumentName(
      DOCUMENT_NAME_PREFIX,
      args.document_name,
      args.control_id,
      clock,
      idGenerator,
    );

    const ssm = new SSMClient({ region: context.region });

    validateInputKeys(inputKeys);

    const inputPayloadParameters = buildInputPayloadParameters(inputKeys, inputPayload);
    validateInputValues(inputPayloadParameters);

    const documentContent = buildDocumentContent({
      runtime,
      handler,
      pythonScript: args.python_script,
      inputKeys,
      timeoutSeconds,
    });

    validateDocumentSize(documentContent);

    await ssm.send(
      new CreateDocumentCommand({
        Name: documentName,
        DocumentType: 'Automation',
        DocumentFormat: 'YAML',
        Content: documentContent,
        TargetType: '/',
        Tags: [TRANSIENT_DOCUMENT_TAG],
      }),
    );

    const startedAt = clock.now().getTime();
    let executionId: string | undefined;
    let execution: AutomationExecution | undefined;
    let failureMessage: string | undefined;

    try {
      // Non-string input_payload values are JSON-stringified before being passed as
      // SSM String parameters. The Python handler receives them as strings, not
      // parsed objects — the handler must JSON-parse them if it needs structured data.
      const parameters: Record<string, string[]> = {
        AutomationAssumeRole: [assumeRole],
        ...inputPayloadParameters,
      };

      const startResp = await ssm.send(
        new StartAutomationExecutionCommand({
          DocumentName: documentName,
          Parameters: parameters,
        }),
      );
      executionId = startResp.AutomationExecutionId;

      if (!executionId) {
        throw new Error('StartAutomationExecution returned no AutomationExecutionId');
      }

      execution = await waitForTerminalStatus(
        ssm,
        executionId,
        timeoutSeconds,
        clock,
        sleeper,
        'test_remediation_script',
      );
      if (!isSuccessful(execution.AutomationExecutionStatus)) {
        failureMessage = execution.FailureMessage ?? execution.AutomationExecutionStatus;
      }
    } catch (err) {
      failureMessage = err instanceof Error ? err.message : String(err);
    }

    const durationSeconds = (clock.now().getTime() - startedAt) / 1000;
    const output = execution ? extractPayload(execution) : undefined;

    const cleanupResult = cleanup
      ? await tryDeleteDocument(ssm, documentName)
      : { cleanedUp: false, deleteError: undefined };

    return {
      documentName,
      executionId,
      status: execution?.AutomationExecutionStatus,
      durationSeconds,
      failureMessage,
      cleanupError: cleanupResult.deleteError,
      output,
      cleanedUp: cleanupResult.cleanedUp,
    };
  };
}

export const testRemediationScript: Executor<TestRemediationScriptParams, TestRemediationScriptResult> =
  createTestRemediationScript();
