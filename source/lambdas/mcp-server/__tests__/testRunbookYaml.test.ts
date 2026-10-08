// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { mockClient } from 'aws-sdk-client-mock';
import {
  SSMClient,
  CreateDocumentCommand,
  StartAutomationExecutionCommand,
  GetAutomationExecutionCommand,
  DeleteDocumentCommand,
} from '@aws-sdk/client-ssm';
import { DynamoDBClient } from '@aws-sdk/client-dynamodb';
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
import { createTestRunbookYaml } from '../backends/common/testRunbookYaml';
import { CustomRunbookTestRoleService } from '../backends/common/customRunbookTestRoleService';
import type { Clock } from '../../common/utils/clock';
import type { Sleeper } from '../../common/utils/sleeper';
import type { ExecutionContext } from '../backends/common/../types';

const ssmMock = mockClient(SSMClient);
const ddbMock = mockClient(DynamoDBDocumentClient);
const iamMock = mockClient(IAMClient);

const FIXED_NOW = new Date('2024-01-01T00:00:00.000Z');
const fixedClock: Clock = { now: () => FIXED_NOW };
const noopSleeper: Sleeper = { sleep: () => Promise.resolve() };

const RUNBOOK_YAML = 'schemaVersion: "0.3"\nmainSteps:\n  - name: Step1\n    action: aws:executeAwsApi\n';
const RUNBOOK_DIGEST = createHash('sha256').update(RUNBOOK_YAML, 'utf8').digest('hex');
const REQUIRED_IAM_ACTIONS = ['s3:GetBucketLogging', 's3:PutBucketLogging'];
const TEST_BOUNDARY_ARN = 'arn:aws:iam::111111111111:policy/SO0111-ASR-Custom-Runbook-Test-Boundary';
const RECORDED_TEST_PARAMS = {
  runbook_yaml: RUNBOOK_YAML,
  runbook_id: 'rb-1',
  version: 1,
  required_iam_actions: REQUIRED_IAM_ACTIONS,
} as const;

function context(overrides: Partial<ExecutionContext> = {}): ExecutionContext {
  return {
    region: 'us-east-1',
    requestId: 'test-request',
    accountId: '111111111111',
    partition: 'aws',
    customRunbookTestBoundaryArn: TEST_BOUNDARY_ARN,
    ...overrides,
  };
}

function mockSuccessfulExecution(): void {
  ssmMock.on(CreateDocumentCommand).resolves({});
  ssmMock.on(StartAutomationExecutionCommand).resolves({ AutomationExecutionId: 'exec-1' });
  ssmMock.on(GetAutomationExecutionCommand).resolves({
    AutomationExecution: { AutomationExecutionStatus: 'Success', StepExecutions: [] },
  });
  ssmMock.on(DeleteDocumentCommand).resolves({});
}

beforeEach(() => {
  ssmMock.reset();
  ddbMock.reset();
  iamMock.reset();
  iamMock.on(GetRoleCommand).rejects(Object.assign(new Error('not found'), { name: 'NoSuchEntityException' }));
  iamMock.on(CreateRoleCommand).resolves({});
  iamMock.on(PutRolePolicyCommand).resolves({});
  iamMock.on(TagRoleCommand).resolves({});
  iamMock.on(DeleteRolePolicyCommand).resolves({});
  iamMock.on(DeleteRoleCommand).resolves({});
  ddbMock.on(GetCommand).resolves({
    Item: { runbookId: 'rb-1', version: 1, registeredContentDigest: RUNBOOK_DIGEST },
  });
});

describe('recordTestOutcome via testRunbookYaml', () => {
  const testRunbookYaml = createTestRunbookYaml(fixedClock, noopSleeper);

  test('no runbook_id/version: declines to record, does not touch DynamoDB', async () => {
    mockSuccessfulExecution();

    const result = await testRunbookYaml(
      { runbook_yaml: RUNBOOK_YAML },
      context({ customRunbookTableName: 'table', accountId: '111111111111' }),
    );

    expect(result.testResultRecorded).toBe(false);
    expect(result.testRecordingSkippedReason).toMatch(/throwaway run/);
    expect(ddbMock.calls()).toHaveLength(0);
  });

  test('registered-version test outside the deployed MCP server is rejected before creating a document', async () => {
    await expect(testRunbookYaml(RECORDED_TEST_PARAMS, context())).rejects.toThrow(
      /require the deployed ASR MCP server/,
    );
    expect(ssmMock.commandCalls(CreateDocumentCommand)).toHaveLength(0);
  });

  test('running in the designated test account with a successful test: recorded as PASSED', async () => {
    mockSuccessfulExecution();
    ddbMock.on(UpdateCommand).resolves({});

    const result = await testRunbookYaml(
      RECORDED_TEST_PARAMS,
      context({ customRunbookTableName: 'table', accountId: '111111111111' }),
    );

    expect(result.testResultRecorded).toBe(true);
    expect(result.testRecordingSkippedReason).toBeUndefined();

    const updateCall = ddbMock.commandCalls(UpdateCommand)[0];
    expect(updateCall.args[0].input.ExpressionAttributeValues?.[':status']).toBe('PASSED');
    expect(updateCall.args[0].input.Key).toEqual({ runbookId: 'rb-1', version: 1 });
    expect(ssmMock.commandCalls(StartAutomationExecutionCommand)[0].args[0].input.Parameters).toMatchObject({
      AutomationAssumeRole: [expect.stringMatching(/role\/SO0111-Remediate-Custom-Test-/)],
    });
  });

  test('a failed execution in the test account is recorded as FAILED, not PASSED', async () => {
    ssmMock.on(CreateDocumentCommand).resolves({});
    ssmMock.on(StartAutomationExecutionCommand).resolves({ AutomationExecutionId: 'exec-1' });
    ssmMock.on(GetAutomationExecutionCommand).resolves({
      AutomationExecution: {
        AutomationExecutionStatus: 'Failed',
        FailureMessage: 'step failed',
        StepExecutions: [],
      },
    });
    ssmMock.on(DeleteDocumentCommand).resolves({});
    ddbMock.on(UpdateCommand).resolves({});

    const result = await testRunbookYaml(
      RECORDED_TEST_PARAMS,
      context({ customRunbookTableName: 'table', accountId: '111111111111' }),
    );

    expect(result.testResultRecorded).toBe(true);
    const updateCall = ddbMock.commandCalls(UpdateCommand)[0];
    expect(updateCall.args[0].input.ExpressionAttributeValues?.[':status']).toBe('FAILED');
    expect(updateCall.args[0].input.ExpressionAttributeValues?.[':error']).toBe('step failed');
  });

  test('an unregistered runbook/version is rejected before creating a role or document', async () => {
    ddbMock.on(GetCommand).resolves({});

    await expect(
      testRunbookYaml(
        { ...RECORDED_TEST_PARAMS, runbook_id: 'rb-unregistered', version: 5 },
        context({ customRunbookTableName: 'table', accountId: '111111111111' }),
      ),
    ).rejects.toThrow(/no registered runbook rb-unregistered version 5/);

    expect(iamMock.commandCalls(CreateRoleCommand)).toHaveLength(0);
    expect(ssmMock.commandCalls(CreateDocumentCommand)).toHaveLength(0);
  });

  test('a legacy version without a registration digest cannot earn a deployable pass', async () => {
    ddbMock.on(GetCommand).resolves({ Item: { runbookId: 'rb-1', version: 1 } });

    await expect(
      testRunbookYaml(RECORDED_TEST_PARAMS, context({ customRunbookTableName: 'table', accountId: '111111111111' })),
    ).rejects.toThrow(/predates content-bound testing/);

    expect(iamMock.commandCalls(CreateRoleCommand)).toHaveLength(0);
    expect(ssmMock.commandCalls(CreateDocumentCommand)).toHaveLength(0);
  });

  test('different YAML is rejected before creating a role or document', async () => {
    ddbMock.on(GetCommand).resolves({
      Item: { runbookId: 'rb-1', version: 1, registeredContentDigest: 'a'.repeat(64) },
    });

    await expect(
      testRunbookYaml(RECORDED_TEST_PARAMS, context({ customRunbookTableName: 'table', accountId: '111111111111' })),
    ).rejects.toThrow(/supplied YAML is not the content registered/);

    expect(iamMock.commandCalls(CreateRoleCommand)).toHaveLength(0);
    expect(ssmMock.commandCalls(CreateDocumentCommand)).toHaveLength(0);
  });

  test('SSM schema rejection happens before the test role is created', async () => {
    ssmMock.on(CreateDocumentCommand).rejects(new Error('InvalidDocumentContent'));

    await expect(
      testRunbookYaml(RECORDED_TEST_PARAMS, context({ customRunbookTableName: 'table', accountId: '111111111111' })),
    ).rejects.toThrow(/InvalidDocumentContent/);

    expect(iamMock.commandCalls(CreateRoleCommand)).toHaveLength(0);
  });

  test('an IAM provisioning failure cleans up the transient document', async () => {
    ssmMock.on(CreateDocumentCommand).resolves({});
    ssmMock.on(DeleteDocumentCommand).resolves({});
    iamMock.on(CreateRoleCommand).rejects(new Error('AccessDeniedException'));

    await expect(
      testRunbookYaml(RECORDED_TEST_PARAMS, context({ customRunbookTableName: 'table', accountId: '111111111111' })),
    ).rejects.toThrow(/AccessDeniedException/);

    expect(ssmMock.commandCalls(DeleteDocumentCommand)).toHaveLength(1);
    expect(ssmMock.commandCalls(StartAutomationExecutionCommand)).toHaveLength(0);
  });

  test('a preflight read failure is surfaced before IAM or SSM work', async () => {
    ddbMock.on(GetCommand).rejects(new Error('AccessDeniedException'));

    await expect(
      testRunbookYaml(RECORDED_TEST_PARAMS, context({ customRunbookTableName: 'table', accountId: '111111111111' })),
    ).rejects.toThrow(/AccessDeniedException/);

    expect(iamMock.commandCalls(CreateRoleCommand)).toHaveLength(0);
    expect(ssmMock.commandCalls(CreateDocumentCommand)).toHaveLength(0);
  });

  test('the preflight uses a consistent, projected read of the named version', async () => {
    mockSuccessfulExecution();
    ddbMock.on(UpdateCommand).resolves({});

    await testRunbookYaml(
      RECORDED_TEST_PARAMS,
      context({ customRunbookTableName: 'table', accountId: '111111111111' }),
    );

    expect(ddbMock.commandCalls(GetCommand)[0].args[0].input).toMatchObject({
      TableName: 'table',
      Key: { runbookId: 'rb-1', version: 1 },
      ConsistentRead: true,
      ProjectionExpression: 'runbookId, #v, registeredContentDigest',
      ExpressionAttributeNames: { '#v': 'version' },
    });
  });

  test('skip_execution=true never records a pass, even in the correct test account', async () => {
    ssmMock.on(CreateDocumentCommand).resolves({});
    ssmMock.on(DeleteDocumentCommand).resolves({});

    const result = await testRunbookYaml(
      { ...RECORDED_TEST_PARAMS, skip_execution: true },
      context({ customRunbookTableName: 'table', accountId: '111111111111' }),
    );

    expect(result.skippedExecution).toBe(true);
    expect(result.testResultRecorded).toBe(false);
    expect(result.testRecordingSkippedReason).toMatch(/Nothing ran/);
    expect(ddbMock.calls()).toHaveLength(0);
    expect(ssmMock.commandCalls(StartAutomationExecutionCommand)).toHaveLength(0);
  });

  test('StartAutomationExecution never returning an execution ID is a transient failure, not a FAILED verdict', async () => {
    ssmMock.on(CreateDocumentCommand).resolves({});
    ssmMock.on(StartAutomationExecutionCommand).resolves({}); // no AutomationExecutionId
    ssmMock.on(DeleteDocumentCommand).resolves({});

    const result = await testRunbookYaml(
      RECORDED_TEST_PARAMS,
      context({ customRunbookTableName: 'table', accountId: '111111111111' }),
    );

    expect(result.testResultRecorded).toBe(false);
    expect(result.testRecordingSkippedReason).toMatch(/transient or infrastructure failure/);
    expect(ddbMock.commandCalls(UpdateCommand)).toHaveLength(0);
  });

  test('StartAutomationExecution itself throwing (e.g. throttling) is a transient failure, not a FAILED verdict', async () => {
    ssmMock.on(CreateDocumentCommand).resolves({});
    ssmMock.on(StartAutomationExecutionCommand).rejects(new Error('ThrottlingException'));
    ssmMock.on(DeleteDocumentCommand).resolves({});

    const result = await testRunbookYaml(
      RECORDED_TEST_PARAMS,
      context({ customRunbookTableName: 'table', accountId: '111111111111' }),
    );

    expect(result.testResultRecorded).toBe(false);
    expect(result.testRecordingSkippedReason).toMatch(/transient or infrastructure failure/);
    expect(result.testRecordingSkippedReason).toMatch(/ThrottlingException/);
    expect(ddbMock.commandCalls(UpdateCommand)).toHaveLength(0);
  });
});

describe('testRunbookYaml — document size guard', () => {
  const testRunbookYaml = createTestRunbookYaml(fixedClock, noopSleeper);

  test('rejects a runbook_yaml over the 64 KB SSM CreateDocument quota, before calling CreateDocument', async () => {
    const oversized = `schemaVersion: "0.3"\nmainSteps:\n  - name: Step1\n    action: aws:executeAwsApi\n    inputs:\n      comment: "${'x'.repeat(70_000)}"\n`;

    await expect(testRunbookYaml({ runbook_yaml: oversized }, context())).rejects.toThrow(
      /exceeding SSM's 65536-byte CreateDocument quota/,
    );

    expect(ssmMock.commandCalls(CreateDocumentCommand)).toHaveLength(0);
  });
});

describe('testRunbookYaml — input_parameters normalisation', () => {
  const testRunbookYaml = createTestRunbookYaml(fixedClock, noopSleeper);

  test('omits a null input_parameters value rather than sending the literal string "null"', async () => {
    ssmMock.on(CreateDocumentCommand).resolves({});
    ssmMock.on(StartAutomationExecutionCommand).resolves({ AutomationExecutionId: 'exec-1' });
    ssmMock.on(GetAutomationExecutionCommand).resolves({
      AutomationExecution: { AutomationExecutionStatus: 'Success', StepExecutions: [] },
    });
    ssmMock.on(DeleteDocumentCommand).resolves({});

    await testRunbookYaml(
      { runbook_yaml: RUNBOOK_YAML, input_parameters: { BucketName: 'my-bucket', Foo: null } },
      context(),
    );

    const call = ssmMock.commandCalls(StartAutomationExecutionCommand)[0];
    const parameters = call.args[0].input.Parameters as Record<string, string[]>;
    expect(parameters).toEqual({ BucketName: ['my-bucket'] });
    expect(parameters.Foo).toBeUndefined();
  });
});

describe('testRunbookYaml — injectable IdGenerator (ADR 0004)', () => {
  test('an injected IdGenerator pins the generated document name', async () => {
    // generateDocumentName already accepted an idGenerator, but the factory never threaded
    // one, so the random suffix came from the real generator and no test could assert the
    // document name — the wrapper was ceremony rather than an injection point.
    ssmMock.on(CreateDocumentCommand).resolves({});
    ssmMock.on(DeleteDocumentCommand).resolves({});

    const testRunbookYamlWithPinnedId = createTestRunbookYaml(
      { now: () => new Date(1_700_000_000_000) },
      { sleep: () => Promise.resolve() },
      new CustomRunbookTestRoleService(),
      { randomUUID: () => 'feedface-0000-0000-0000-000000000000' },
    );

    const result = await testRunbookYamlWithPinnedId(
      { runbook_yaml: RUNBOOK_YAML, control_id: 'S3.9', skip_execution: true },
      context(),
    );

    expect(result.documentName).toBe('ASR-Custom-TestRunbook-S3-9-loyw3v28-feedface');
  });
});
