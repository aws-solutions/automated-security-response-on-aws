// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import {
  CreateDocumentCommand,
  DeleteDocumentCommand,
  GetAutomationExecutionCommand,
  SSMClient,
  StartAutomationExecutionCommand,
} from '@aws-sdk/client-ssm';
import { DynamoDBDocumentClient, GetCommand, UpdateCommand } from '@aws-sdk/lib-dynamodb';
import {
  CreateRoleCommand,
  DeleteRoleCommand,
  DeleteRolePolicyCommand,
  GetRoleCommand,
  IAMClient,
  PutRolePolicyCommand,
  TagRoleCommand,
} from '@aws-sdk/client-iam';
import { createHash } from 'node:crypto';
import { mockClient } from 'aws-sdk-client-mock';
import { createTestRunbookYaml, type ExecutionContext, type TestRunbookYamlParams } from '../index';
import type { RunbookId } from '@asr/data-models';

// SSM and DynamoDB are system boundaries; the executor's own recording logic runs for real.
const ssmMock = mockClient(SSMClient);
const dynamoMock = mockClient(DynamoDBDocumentClient);
const iamMock = mockClient(IAMClient);

// Real clock, but a no-op sleeper so the test role's IAM-propagation settle delay does not
// make the recorded-test path (which creates a role) wait for real. The sleeper is passed
// on, so the default CustomRunbookTestRoleService inherits it (see createTestRunbookYaml).
const testRunbookYaml = createTestRunbookYaml(undefined, { sleep: () => Promise.resolve() });

const TABLE_NAME = 'test-custom-runbook-table';
const TEST_ACCOUNT = '123456789012';
const TEST_BOUNDARY_ARN = `arn:aws:iam::${TEST_ACCOUNT}:policy/SO0111-ASR-Custom-Runbook-Test-Boundary`;
const REQUIRED_IAM_ACTIONS = ['s3:GetBucketLogging', 's3:PutBucketLogging'];

const params: TestRunbookYamlParams = {
  runbook_yaml: 'schemaVersion: "0.3"\nmainSteps: []',
  runbook_id: 'rb-1' as RunbookId,
  version: 3,
  required_iam_actions: REQUIRED_IAM_ACTIONS,
};

/** Context as the deployed Lambda builds it when it is running in its account. */
function context(overrides: Partial<ExecutionContext> = {}): ExecutionContext {
  return {
    region: 'us-east-1',
    requestId: 'request-1',
    customRunbookTableName: TABLE_NAME,
    accountId: TEST_ACCOUNT,
    partition: 'aws',
    customRunbookTestBoundaryArn: TEST_BOUNDARY_ARN,
    ...overrides,
  };
}

/** Make the automation reach a terminal state on the first poll, so nothing sleeps. */
function stubExecution(status: 'Success' | 'Failed' | 'CompletedWithSuccess', failureMessage?: string): void {
  ssmMock.on(StartAutomationExecutionCommand).resolves({ AutomationExecutionId: 'execution-1' });
  ssmMock.on(GetAutomationExecutionCommand).resolves({
    AutomationExecution: {
      AutomationExecutionId: 'execution-1',
      AutomationExecutionStatus: status,
      FailureMessage: failureMessage,
      StepExecutions: [],
    },
  });
}

/** The single UpdateCommand the executor is allowed to issue. */
function recordedUpdate(): UpdateCommand['input'] {
  const calls = dynamoMock.commandCalls(UpdateCommand);
  expect(calls).toHaveLength(1);
  return calls[0].args[0].input;
}

describe('test_runbook_yaml — recording a version’s test outcome', () => {
  beforeEach(() => {
    ssmMock.reset();
    dynamoMock.reset();
    iamMock.reset();
    ssmMock.on(CreateDocumentCommand).resolves({});
    ssmMock.on(DeleteDocumentCommand).resolves({});
    dynamoMock.on(GetCommand).resolves({
      Item: {
        runbookId: 'rb-1',
        version: 3,
        registeredContentDigest: createHash('sha256').update(params.runbook_yaml, 'utf8').digest('hex'),
      },
    });
    dynamoMock.on(UpdateCommand).resolves({});
    iamMock.on(GetRoleCommand).rejects(Object.assign(new Error('not found'), { name: 'NoSuchEntityException' }));
    iamMock.on(CreateRoleCommand).resolves({});
    iamMock.on(PutRolePolicyCommand).resolves({});
    iamMock.on(TagRoleCommand).resolves({});
    // The test role is reaped after the run (best-effort cleanup); stub the deletes so the
    // cleanup succeeds cleanly rather than hitting the mock default and reporting a spurious
    // cleanupError.
    iamMock.on(DeleteRolePolicyCommand).resolves({});
    iamMock.on(DeleteRoleCommand).resolves({});
  });

  afterAll(() => {
    ssmMock.restore();
    dynamoMock.restore();
    iamMock.restore();
  });

  it('stamps PASSED on the named version when the automation succeeds', async () => {
    stubExecution('Success');

    const result = await testRunbookYaml(params, context());

    expect(result.testResultRecorded).toBe(true);
    expect(result.testRecordingSkippedReason).toBeUndefined();
    const input = recordedUpdate();
    expect(input.TableName).toBe(TABLE_NAME);
    expect(input.Key).toEqual({ runbookId: 'rb-1', version: 3 });
    expect(input.ExpressionAttributeValues).toMatchObject({
      ':status': 'PASSED',
      ':accountId': TEST_ACCOUNT,
      ':iamActions': REQUIRED_IAM_ACTIONS,
      ':testRoleArn': expect.stringMatching(/role\/SO0111-Remediate-Custom-Test-/),
    });
    // A pass REMOVEs testError (rather than writing null), clearing any prior failure
    // reason without leaving a stale one beside a PASSED status.
    expect(input.ExpressionAttributeValues?.[':error']).toBeUndefined();
    expect(input.UpdateExpression).toContain('REMOVE testError');
    expect(input.UpdateExpression).not.toContain('testError = :error');
    expect(input.ExpressionAttributeValues?.[':testedAt']).toEqual(expect.any(String));
  });

  // SSM reports CompletedWithSuccess rather than Success for rate-controlled and
  // multi-account executions. `runExecution` used to compare against 'Success'
  // literally, which set a failureMessage for this status; `recordIfRequested` then
  // computed passed=false even though `isSuccessful()` accepts it. The result was a
  // clean run recorded FAILED, which then blocked deploy_runbook at the test gate.
  it('stamps PASSED for CompletedWithSuccess, the status a multi-account run returns', async () => {
    stubExecution('CompletedWithSuccess');

    const result = await testRunbookYaml(params, context());

    expect(result.testResultRecorded).toBe(true);
    const input = recordedUpdate();
    expect(input.ExpressionAttributeValues).toMatchObject({ ':status': 'PASSED' });
    expect(input.ExpressionAttributeValues?.[':error']).toBeUndefined();
  });

  // The digest binds a recorded pass to exactly the YAML that was tested;
  // deploy_runbook rejects an S3 object whose hash disagrees. If the digest
  // never lands in DDB, the gate has nothing to compare against and drifted
  // bytes can ride the pass into production.
  it('persists testedContentDigest as the hash of exactly the YAML it was given', async () => {
    stubExecution('Success');

    await testRunbookYaml(params, context());

    const input = recordedUpdate();
    expect(input.UpdateExpression).toContain('testedContentDigest = :digest');
    // Pinned to the actual value, not just "some 64-hex string": hashing the
    // wrong thing (the document name, a normalized YAML, a constant) would still
    // satisfy a shape-only assertion while making every deploy fail its gate.
    const expected = createHash('sha256').update(params.runbook_yaml, 'utf8').digest('hex');
    expect(input.ExpressionAttributeValues?.[':digest']).toBe(expected);
  });

  it('overrides a caller-supplied AutomationAssumeRole with the version-scoped test role', async () => {
    stubExecution('Success');

    await testRunbookYaml(
      {
        ...params,
        input_parameters: {
          AutomationAssumeRole: 'arn:aws:iam::123456789012:role/CallerSelectedRole',
        },
      },
      context(),
    );

    const executionParameters = ssmMock.commandCalls(StartAutomationExecutionCommand)[0].args[0].input.Parameters;
    expect(executionParameters?.AutomationAssumeRole).toEqual([
      expect.stringMatching(/role\/SO0111-Remediate-Custom-Test-/),
    ]);
    expect(executionParameters?.AutomationAssumeRole).not.toContain(
      'arn:aws:iam::123456789012:role/CallerSelectedRole',
    );
  });

  it('refuses mismatched YAML before provisioning the test role or creating a document', async () => {
    dynamoMock.on(GetCommand).resolves({
      Item: { runbookId: 'rb-1', version: 3, registeredContentDigest: 'a'.repeat(64) },
    });

    await expect(testRunbookYaml(params, context())).rejects.toThrow(/supplied YAML is not the content registered/);

    expect(iamMock.commandCalls(CreateRoleCommand)).toHaveLength(0);
    expect(ssmMock.commandCalls(CreateDocumentCommand)).toHaveLength(0);
  });

  it('checks the registered digest in the same atomic write as the registration guard', async () => {
    stubExecution('Success');

    await testRunbookYaml(params, context());

    const input = recordedUpdate();
    expect(input.ConditionExpression).toContain('registeredContentDigest = :digest');
    expect(input.ConditionExpression).not.toContain('attribute_not_exists(registeredContentDigest)');
    // Needed to attribute a failed condition to the right guard.
    expect(input.ReturnValuesOnConditionCheckFailure).toBe('ALL_OLD');
  });

  // Without the condition, an update on an unregistered key would create a bare
  // record whose only content is a passing test.
  it('records only against an already registered version', async () => {
    stubExecution('Success');

    await testRunbookYaml(params, context());

    const input = recordedUpdate();
    // `version` is a DynamoDB reserved word, so the condition refers to it through
    // an ExpressionAttributeNames alias rather than by name.
    // Asserts this test's own concern — the registration guard — rather than the
    // whole expression, which also carries the registered-digest guard covered below.
    expect(input.ConditionExpression).toContain('attribute_exists(runbookId) AND attribute_exists(#v)');
    expect(input.ExpressionAttributeNames).toMatchObject({ '#v': 'version' });
  });

  it('rejects an unregistered version before IAM or SSM work', async () => {
    dynamoMock.on(GetCommand).resolves({});

    await expect(testRunbookYaml(params, context())).rejects.toThrow(/no registered runbook rb-1 version 3 exists/);
    expect(iamMock.commandCalls(CreateRoleCommand)).toHaveLength(0);
    expect(ssmMock.commandCalls(CreateDocumentCommand)).toHaveLength(0);
  });

  it('surfaces any other write failure instead of silently reporting a recorded pass', async () => {
    stubExecution('Success');
    dynamoMock.on(UpdateCommand).rejects(new Error('AccessDeniedException: not authorized'));

    const result = await testRunbookYaml(params, context());

    expect(result.testResultRecorded).toBe(false);
    expect(result.testRecordingSkippedReason).toContain('AccessDeniedException: not authorized');
  });

  it('stamps FAILED with the automation’s own failure reason', async () => {
    stubExecution('Failed', 'step verifyBucket returned Failed');

    const result = await testRunbookYaml(params, context());

    expect(result.testResultRecorded).toBe(true);
    expect(recordedUpdate().ExpressionAttributeValues).toMatchObject({
      ':status': 'FAILED',
      ':error': 'step verifyBucket returned Failed',
    });
  });

  it('records nothing when the automation never started (no execution id)', async () => {
    // A failure to *start* the automation is a transient/infrastructure failure, not a
    // runbook defect, so the shipped executor records no verdict and writes nothing —
    // deploy_runbook stays gated rather than marking the version FAILED on an infra hiccup.
    ssmMock.on(StartAutomationExecutionCommand).resolves({ AutomationExecutionId: undefined });

    const result = await testRunbookYaml(params, context());

    expect(result.testResultRecorded).toBe(false);
    expect(dynamoMock.commandCalls(UpdateCommand)).toHaveLength(0);
  });

  // A cleanup failure is housekeeping, not a defect in the remediation being tested.
  it('keeps a successful run PASSED even when the transient document cannot be deleted', async () => {
    stubExecution('Success');
    ssmMock.on(DeleteDocumentCommand).rejects(new Error('throttled'));

    const result = await testRunbookYaml(params, context());

    expect(result.cleanedUp).toBe(false);
    // Still a pass: testError is REMOVEd, clearing any prior failure.
    const passUpdate = recordedUpdate();
    expect(passUpdate.ExpressionAttributeValues).toMatchObject({ ':status': 'PASSED' });
    expect(passUpdate.ExpressionAttributeValues?.[':error']).toBeUndefined();
    expect(passUpdate.UpdateExpression).toContain('REMOVE testError');
  });

  it('writes nothing for a throwaway run that names no version', async () => {
    stubExecution('Success');

    const result = await testRunbookYaml({ runbook_yaml: params.runbook_yaml }, context());

    expect(dynamoMock.commandCalls(UpdateCommand)).toHaveLength(0);
    expect(result.testResultRecorded).toBe(false);
    expect(result.testRecordingSkippedReason).toContain('throwaway run');
  });

  // skip_execution only asks SSM whether it accepts the document. Recording a pass
  // for that would let a runbook reach production having never executed once.
  it('records nothing when the run only validated the document schema', async () => {
    const result = await testRunbookYaml({ ...params, skip_execution: true }, context());

    expect(ssmMock.commandCalls(StartAutomationExecutionCommand)).toHaveLength(0);
    expect(dynamoMock.commandCalls(UpdateCommand)).toHaveLength(0);
    expect(result.testResultRecorded).toBe(false);
    expect(result.testRecordingSkippedReason).toContain('Nothing ran');
  });

  // A host running these tools locally has neither the test boundary nor permission
  // to create the version-scoped role.
  it('rejects a recorded test when running outside the deployed MCP server', async () => {
    await expect(
      testRunbookYaml(params, context({ customRunbookTableName: undefined, customRunbookTestBoundaryArn: undefined })),
    ).rejects.toThrow(/require the deployed ASR MCP server/);

    expect(ssmMock.commandCalls(CreateDocumentCommand)).toHaveLength(0);
    expect(dynamoMock.commandCalls(UpdateCommand)).toHaveLength(0);
  });
});
