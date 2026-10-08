// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import {
  SSMClient,
  CreateDocumentCommand,
  StartAutomationExecutionCommand,
  type AutomationExecution,
  type StepExecution,
} from '@aws-sdk/client-ssm';
import { createHash } from 'node:crypto';
import type { RunbookTestResult } from '@asr/data-models';
import type { Executor, ExecutionContext } from '../types';
import type { TestRunbookYamlParams } from '../../contract/toolContract';
import { CustomRunbookTestResultRepository } from '../../../common/repositories/customRunbookTestResultRepository';
import { getClock, type Clock } from '../../../common/utils/clock';
import { createDynamoDBClient } from '../../../common/utils/dynamodb';
import { getSleeper, type Sleeper } from '../../../common/utils/sleeper';
import { getIdGenerator, type IdGenerator } from '../../../common/utils/idGenerator';
import {
  waitForTerminalStatus,
  tryDeleteDocument,
  generateDocumentName,
  isSuccessful,
  TRANSIENT_DOCUMENT_TAG,
} from './ssmExecutionHelpers';
import { ValidationError } from './errors';
import { CustomRunbookTestRoleService, type ProvisionedCustomRunbookTestRole } from './customRunbookTestRoleService';

const DEFAULT_TIMEOUT_SECONDS = 600;
const DOCUMENT_NAME_PREFIX = 'ASR-Custom-TestRunbook-';

/**
 * SSM's hard `CreateDocument` content quota, in bytes. The schema's own
 * `.max(65536)` on `runbook_yaml` bounds character count, not UTF-8 byte
 * length — the two only coincide for ASCII content. Checking the actual byte
 * length here turns an over-quota document into a clear error instead of an
 * opaque `CreateDocument` rejection.
 */
const MAX_DOCUMENT_BYTES = 65536;

export interface TestRunbookYamlStepResult {
  readonly stepName: string | undefined;
  readonly action: string | undefined;
  readonly status: string | undefined;
  readonly failureMessage: string | undefined;
  readonly durationSeconds: number | undefined;
  readonly outputs: Record<string, readonly string[]>;
}

export interface TestRunbookYamlResult {
  readonly documentName: string;
  readonly executionId: string | undefined;
  readonly status: string | undefined;
  readonly durationSeconds: number;
  readonly failureMessage: string | undefined;
  readonly outputs: Record<string, readonly string[]>;
  readonly steps: readonly TestRunbookYamlStepResult[];
  readonly cleanedUp: boolean;
  readonly skippedExecution: boolean;
  /** Failure to delete the transient SSM document. Distinct from `failureMessage`, which is the execution's own outcome. */
  readonly cleanupError?: string;
  /**
   * Whether this run's outcome was recorded against a registered version. Only a recorded PASSED
   * result makes a version deployable, so a caller that expected to record and sees `false` here
   * has to read `testRecordingSkippedReason` before wondering why the deploy is refused.
   */
  readonly testResultRecorded: boolean;
  /** Why no result was recorded. Absent when `testResultRecorded` is true. */
  readonly testRecordingSkippedReason?: string;
  /** Bounded version-and-permission-set-scoped role SSM assumed for a recorded test. */
  readonly testRoleArn?: string;
}

/**
 * Normalise the parameters map for StartAutomationExecution.
 * Strings are passed through; anything else is JSON-encoded so SSM receives
 * a deterministic serialisation (dicts, arrays, numbers, booleans).
 * `null`/`undefined` values are omitted rather than encoded as the literal
 * string `"null"` — SSM only accepts strings, so there is no way to pass an
 * actual null, and a caller writing `{Foo: null}` almost always means "don't
 * set this", which omitting the key lets the document's own default satisfy.
 */
function buildParameters(raw: Record<string, unknown> | undefined, testRoleArn?: string): Record<string, string[]> {
  const out: Record<string, string[]> = {};
  for (const [key, value] of Object.entries(raw ?? {})) {
    if (value === null || value === undefined) continue;
    if (Array.isArray(value)) {
      out[key] = value.map((v) => (typeof v === 'string' ? v : JSON.stringify(v)));
    } else {
      out[key] = [typeof value === 'string' ? value : JSON.stringify(value)];
    }
  }
  if (testRoleArn) out.AutomationAssumeRole = [testRoleArn];
  return out;
}

function summariseSteps(execution: AutomationExecution): readonly TestRunbookYamlStepResult[] {
  const steps = execution.StepExecutions ?? [];
  return steps.map((step: StepExecution) => ({
    stepName: step.StepName,
    action: step.Action,
    status: step.StepStatus,
    failureMessage: step.FailureMessage,
    durationSeconds:
      step.ExecutionEndTime && step.ExecutionStartTime
        ? (step.ExecutionEndTime.getTime() - step.ExecutionStartTime.getTime()) / 1000
        : undefined,
    outputs: step.Outputs ?? {},
  }));
}

interface TestRecordingOutcome {
  readonly recorded: boolean;
  readonly reason?: string;
}

/**
 * Confirm the caller named a real immutable version before creating IAM resources.
 *
 * The conditional UpdateItem below remains the authoritative write-time guard, but
 * waiting until after execution to discover a bogus key would let an Admin-tier
 * caller create test roles for arbitrary runbook/version pairs. Requiring the
 * registration digest here also closes the legacy-record gap: a DRAFT version
 * registered before digests existed cannot earn a pass for unrelated YAML.
 */
async function assertRegisteredTestTarget(
  context: ExecutionContext,
  runbookId: string,
  version: number,
  runbookYaml: string,
): Promise<void> {
  const registered = await customRunbookTestResultRepository(context).findRegisteredVersion(runbookId, version);

  if (!registered) {
    throw new ValidationError(
      `test_runbook_yaml: no registered runbook ${runbookId} version ${version} exists. Register it first.`,
    );
  }

  const registeredContentDigest = registered.registeredContentDigest;
  if (!registeredContentDigest) {
    throw new ValidationError(
      `test_runbook_yaml: runbook ${runbookId} version ${version} predates content-bound testing. ` +
        'Register the YAML as a new version before testing it for deployment.',
    );
  }

  const testedContentDigest = createHash('sha256').update(runbookYaml, 'utf8').digest('hex');
  if (registeredContentDigest !== testedContentDigest) {
    throw new ValidationError(
      `test_runbook_yaml: the supplied YAML is not the content registered for runbook ${runbookId} ` +
        `version ${version}. Test the exact registered content, or register the changed YAML as a new version.`,
    );
  }
}

/**
 * Build the custom-runbook test-result repository for this execution.
 *
 * `customRunbookTableName` is guaranteed present on the paths that call the
 * repository — recording is gated on it upstream (see recordTestOutcome and
 * prepareRegisteredTest) — but it is optional on ExecutionContext, so this
 * asserts it rather than letting an undefined table name reach DynamoDB.
 */
function customRunbookTestResultRepository(context: ExecutionContext): CustomRunbookTestResultRepository {
  if (!context.customRunbookTableName) {
    throw new ValidationError('test_runbook_yaml: no custom runbook table is configured for this host.');
  }
  // Built through the shared factory rather than a bare DynamoDBClient so this repository
  // gets the same connection pooling as every other DynamoDB caller and honors
  // DYNAMODB_ENDPOINT. Without the endpoint override the registration pre-check and the
  // recording write could not be exercised against DynamoDB Local, so a handler-level test
  // of test_runbook_yaml reached real AWS and failed on credentials.
  return new CustomRunbookTestResultRepository(
    context.customRunbookTableName,
    createDynamoDBClient({ region: context.region }),
  );
}

/**
 * Record this run's outcome against a registered runbook version, which is what
 * later lets `deploy_runbook` promote it.
 *
 * The write is deliberately narrow. It happens with the MCP server Lambda's own
 * role, never with anything the caller supplied, so a pass cannot be fabricated by a
 * caller. Nothing is recorded outside the deployed Lambda, where neither the table nor
 * the permission to write it exists.
 *
 * It is NOT restricted to a designated test account. `context.accountId` — the Lambda's own
 * account, read from its ARN — is stamped as `testAccountId` for provenance only, and
 * `assertVersionPassedTest` says outright that it is not matched against any configured
 * account: "the runbook is proven wherever the MCP server ran it". So a pass records
 * where it was earned; it does not constrain where it may be earned.
 *
 * Failures to record are reported rather than thrown: the test itself already
 * ran, and the caller needs its result plus an explanation of why the version is
 * still not deployable.
 */
async function recordTestOutcome(
  context: ExecutionContext,
  runbookId: string,
  version: number,
  result: RunbookTestResult,
): Promise<TestRecordingOutcome> {
  if (!context.customRunbookTableName) {
    return {
      recorded: false,
      reason:
        'No custom runbook table is available, so this run is not attributable to a registered ' +
        'version. Test results are only recorded by the deployed ASR MCP server.',
    };
  }

  try {
    await customRunbookTestResultRepository(context).recordTestResult(runbookId, version, result);
    return { recorded: true };
  } catch (err) {
    return { recorded: false, reason: describeRecordingFailure(err, runbookId, version) };
  }
}

/**
 * Turn a failed `recordTestOutcome` write into a reason the caller can act on.
 * A conditional failure means either the version is not registered or the tested
 * YAML is not the registered YAML; `ALL_OLD` on the error distinguishes them.
 */
function describeRecordingFailure(err: unknown, runbookId: string, version: number): string {
  if (!(err instanceof Error) || err.name !== 'ConditionalCheckFailedException') {
    return `Failed to record the test result: ${err instanceof Error ? err.message : String(err)}`;
  }

  // The SDK attaches the pre-write item to the error when ALL_OLD is requested.
  const existingItem = (err as { Item?: Record<string, unknown> }).Item;
  if (!existingItem) {
    return `No registered runbook ${runbookId} version ${version} to record against — register it first.`;
  }

  return (
    `The YAML tested is not the YAML registered for runbook ${runbookId} version ${version}, so no pass was ` +
    'recorded. Test the exact content that was registered — even a whitespace or indentation difference counts — ' +
    'or register the changed YAML as a new version and test that.'
  );
}

interface ExecutionOutcome {
  readonly execution: AutomationExecution | undefined;
  readonly executionId: string | undefined;
  readonly failureMessage: string | undefined;
  readonly durationSeconds: number;
}

/** Starts the automation execution and polls it to a terminal state, capturing failures as a message rather than throwing. */
async function runExecution(
  ssm: SSMClient,
  documentName: string,
  args: TestRunbookYamlParams,
  testRoleArn: string | undefined,
  timeoutSeconds: number,
  clock: Clock,
  sleeper: Sleeper,
): Promise<ExecutionOutcome> {
  const startedAt = clock.now().getTime();
  let execution: AutomationExecution | undefined;
  let executionId: string | undefined;
  let failureMessage: string | undefined;

  try {
    const startResp = await ssm.send(
      new StartAutomationExecutionCommand({
        DocumentName: documentName,
        Parameters: buildParameters(args.input_parameters, testRoleArn),
      }),
    );
    executionId = startResp.AutomationExecutionId;
    if (!executionId) {
      throw new Error('StartAutomationExecution returned no AutomationExecutionId');
    }

    execution = await waitForTerminalStatus(ssm, executionId, timeoutSeconds, clock, sleeper, 'test_runbook_yaml');
    // Use the shared helper, not `!== 'Success'`: SSM reports `CompletedWithSuccess`
    // for rate-controlled and multi-account executions. Setting a failureMessage here
    // for that status made `recordIfRequested` compute passed=false — its check is
    // `isSuccessful(status) && failureMessage === undefined` — so a clean run was
    // recorded FAILED and then blocked deploy_runbook at the test gate.
    if (!isSuccessful(execution.AutomationExecutionStatus)) {
      failureMessage = execution.FailureMessage ?? execution.AutomationExecutionStatus;
    }
  } catch (err) {
    failureMessage = err instanceof Error ? err.message : String(err);
  }

  const durationSeconds = (clock.now().getTime() - startedAt) / 1000;
  return { execution, executionId, failureMessage, durationSeconds };
}

/** Records the test outcome against a registered version, when the caller asked to. */
async function recordIfRequested(
  context: ExecutionContext,
  args: TestRunbookYamlParams,
  outcome: ExecutionOutcome,
  clock: Clock,
  testRole: ProvisionedCustomRunbookTestRole | undefined,
): Promise<TestRecordingOutcome> {
  if (!args.runbook_id || args.version === undefined) {
    return {
      recorded: false,
      reason: 'No runbook_id/version supplied, so this was a throwaway run and no version was updated.',
    };
  }

  // A transient or infrastructure failure (throttling, a network error, or
  // StartAutomationExecution never returning an execution ID) never reaches a terminal SSM
  // status at all, so `outcome.execution` stays undefined. That is a different fact from the
  // runbook itself failing — recording it as FAILED would block deploy_runbook on an error the
  // runbook's own logic never caused.
  if (!outcome.execution) {
    return {
      recorded: false,
      reason:
        `The execution never reached a terminal SSM status (${outcome.failureMessage ?? 'unknown error'}), so no ` +
        'test verdict was recorded. This looks like a transient or infrastructure failure rather than a runbook ' +
        'defect — resolve it and re-run test_runbook_yaml.',
    };
  }
  if (!testRole) {
    throw new ValidationError(
      'test_runbook_yaml: a recorded test must execute with the version-scoped test role provisioned from ' +
        'required_iam_actions.',
    );
  }

  // Judged before cleanup so that failing to delete the transient document —
  // housekeeping, not a remediation defect — cannot turn a good run into a FAILED
  // test result.
  const passed = isSuccessful(outcome.execution.AutomationExecutionStatus) && outcome.failureMessage === undefined;
  const error = passed
    ? undefined
    : (outcome.failureMessage ??
      `Automation did not succeed (status: ${outcome.execution.AutomationExecutionStatus ?? 'unknown'})`);

  return recordTestOutcome(context, args.runbook_id, args.version, {
    testStatus: passed ? 'PASSED' : 'FAILED',
    testedAt: clock.now().toISOString(),
    testAccountId: context.accountId ?? '',
    testedContentDigest: createHash('sha256').update(args.runbook_yaml, 'utf8').digest('hex'),
    testedIamActions: [...testRole.requiredIamActions],
    testRoleArn: testRole.roleArn,
    testError: error,
  });
}

async function buildSkipExecutionResult(
  ssm: SSMClient,
  documentName: string,
  cleanup: boolean,
): Promise<TestRunbookYamlResult> {
  const cleanupResult = cleanup
    ? await tryDeleteDocument(ssm, documentName)
    : { cleanedUp: false, deleteError: undefined };
  return {
    documentName,
    executionId: undefined,
    status: 'Registered',
    durationSeconds: 0,
    failureMessage: undefined,
    cleanupError: cleanupResult.deleteError,
    outputs: {},
    steps: [],
    cleanedUp: cleanupResult.cleanedUp,
    skippedExecution: true,
    // A schema check is not a test. Recording a pass here would let a runbook
    // reach production having never executed once.
    testResultRecorded: false,
    testRoleArn: undefined,
    testRecordingSkippedReason:
      'skip_execution only verified that SSM accepts the document. Nothing ran, so no test result ' +
      'was recorded and the version is not yet deployable.',
  };
}

/** Combine the transient document- and role-cleanup errors into one caller-facing message. */
function combineCleanupErrors(documentError: string | undefined, roleError: string | undefined): string | undefined {
  const parts = [
    documentError ? `document: ${documentError}` : undefined,
    roleError ? `test role: ${roleError}` : undefined,
  ].filter((part): part is string => part !== undefined);
  return parts.length > 0 ? parts.join('; ') : undefined;
}

/** Creates an executor with an injectable clock and sleeper for deterministic tests. */
export function createTestRunbookYaml(
  clock: Clock = getClock(),
  sleeper: Sleeper = getSleeper(),
  // Defaulted from `sleeper` so the executor's injected sleeper also governs the role
  // service's IAM-propagation settle delay — a test passing a no-op sleeper does not
  // pay the real 10s wait.
  testRoleService: CustomRunbookTestRoleService = new CustomRunbookTestRoleService(undefined, sleeper),
  idGenerator: IdGenerator = getIdGenerator(),
): Executor<TestRunbookYamlParams, TestRunbookYamlResult> {
  return async (args, context) => {
    const ssm = new SSMClient({ region: context.region });
    const documentName = generateDocumentName(
      DOCUMENT_NAME_PREFIX,
      args.document_name,
      args.control_id,
      clock,
      idGenerator,
    );
    const documentFormat = args.document_format ?? 'YAML';
    const cleanup = args.cleanup ?? true;
    const timeoutSeconds = args.timeout_seconds ?? DEFAULT_TIMEOUT_SECONDS;
    const skipExecution = args.skip_execution ?? false;

    const documentBytes = Buffer.byteLength(args.runbook_yaml, 'utf8');
    if (documentBytes > MAX_DOCUMENT_BYTES) {
      throw new ValidationError(
        `test_runbook_yaml: runbook_yaml is ${documentBytes} bytes, exceeding SSM's ${MAX_DOCUMENT_BYTES}-byte ` +
          'CreateDocument quota.',
      );
    }

    const registeredTest =
      skipExecution || (!args.runbook_id && args.version === undefined && !args.required_iam_actions)
        ? undefined
        : await prepareRegisteredTest(args, context);

    // Step 1 — register the document. This is where SSM does its own schema
    // validation; if the runbook is malformed, CreateDocument throws here and
    // we never start an execution.
    await ssm.send(
      new CreateDocumentCommand({
        Name: documentName,
        DocumentType: 'Automation',
        DocumentFormat: documentFormat,
        Content: args.runbook_yaml,
        TargetType: '/',
        Tags: [TRANSIENT_DOCUMENT_TAG],
      }),
    );

    if (skipExecution) {
      return buildSkipExecutionResult(ssm, documentName, cleanup);
    }

    let testRole: ProvisionedCustomRunbookTestRole | undefined;
    if (registeredTest) {
      try {
        testRole = await testRoleService.provisionRole({
          ...registeredTest,
          region: context.region,
          // The transient document name is unique per execution, so it gives each test run
          // its own role and prevents a concurrent identical test from deleting it mid-run.
          executionId: documentName,
        });
      } catch (error) {
        // The document was valid but the execution role could not be prepared.
        // Do not strand a transient document merely because IAM failed.
        if (cleanup) await tryDeleteDocument(ssm, documentName);
        throw error;
      }
    }

    const outcome = await runExecution(ssm, documentName, args, testRole?.roleArn, timeoutSeconds, clock, sleeper);
    const recording = await recordIfRequested(context, args, outcome, clock, testRole);

    const cleanupResult = cleanup
      ? await tryDeleteDocument(ssm, documentName)
      : { cleanedUp: false, deleteError: undefined };

    // Reap the version-scoped test role too, so it does not accumulate against the
    // account's IAM role quota. Best-effort and after the run/record, exactly like the
    // document cleanup — a failure here is surfaced but never fails the test.
    const roleCleanup =
      cleanup && testRole
        ? await testRoleService.tryDeleteRole(testRole.roleArn, context.region)
        : { deleted: false, deleteError: undefined };

    return {
      documentName,
      executionId: outcome.executionId,
      status: outcome.execution?.AutomationExecutionStatus,
      durationSeconds: outcome.durationSeconds,
      failureMessage: outcome.failureMessage,
      outputs: outcome.execution?.Outputs ?? {},
      steps: outcome.execution ? summariseSteps(outcome.execution) : [],
      cleanedUp: cleanupResult.cleanedUp,
      cleanupError: combineCleanupErrors(cleanupResult.deleteError, roleCleanup.deleteError),
      skippedExecution: false,
      testResultRecorded: recording.recorded,
      testRecordingSkippedReason: recording.reason,
      testRoleArn: testRole?.roleArn,
    };
  };
}

interface PreparedRegisteredTest {
  readonly runbookId: string;
  readonly version: number;
  readonly requiredIamActions: readonly string[];
  readonly accountId: string;
  readonly partition: string;
  readonly permissionsBoundaryArn: string;
}

async function prepareRegisteredTest(
  args: TestRunbookYamlParams,
  context: ExecutionContext,
): Promise<PreparedRegisteredTest> {
  if (!args.runbook_id || args.version === undefined || !args.required_iam_actions) {
    throw new ValidationError(
      'test_runbook_yaml: runbook_id, version, and required_iam_actions are all required for a recorded test.',
    );
  }
  if (
    !context.accountId ||
    !context.partition ||
    !context.customRunbookTestBoundaryArn ||
    !context.customRunbookTableName
  ) {
    throw new ValidationError(
      'test_runbook_yaml: recorded tests require the deployed ASR MCP server with custom-runbook storage and ' +
        'the test-role permissions boundary configured.',
    );
  }

  await assertRegisteredTestTarget(context, args.runbook_id, args.version, args.runbook_yaml);

  return {
    runbookId: args.runbook_id,
    version: args.version,
    requiredIamActions: args.required_iam_actions,
    accountId: context.accountId,
    partition: context.partition,
    permissionsBoundaryArn: context.customRunbookTestBoundaryArn,
  };
}

export const testRunbookYaml: Executor<TestRunbookYamlParams, TestRunbookYamlResult> = createTestRunbookYaml();
