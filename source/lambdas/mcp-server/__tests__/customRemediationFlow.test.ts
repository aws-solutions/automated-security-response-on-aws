// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { AdminGetUserCommand, CognitoIdentityProviderClient } from '@aws-sdk/client-cognito-identity-provider';
import { InvokeCommand, LambdaClient } from '@aws-sdk/client-lambda';
import {
  GetFindingHistoryCommand,
  GetFindingsCommand,
  SecurityHubClient,
  type AwsSecurityFinding,
} from '@aws-sdk/client-securityhub';
import {
  CreateDocumentCommand,
  DeleteDocumentCommand,
  DescribeDocumentCommand,
  GetAutomationExecutionCommand,
  GetDocumentCommand,
  ListDocumentsCommand,
  SSMClient,
  StartAutomationExecutionCommand,
} from '@aws-sdk/client-ssm';
import {
  DeleteRoleCommand,
  DeleteRolePolicyCommand,
  GetRoleCommand,
  IAMClient,
  PutRolePermissionsBoundaryCommand,
  PutRolePolicyCommand,
  TagRoleCommand,
  UpdateAssumeRolePolicyCommand,
} from '@aws-sdk/client-iam';
import { mockClient } from 'aws-sdk-client-mock';
import { createHash } from 'node:crypto';
import { userPoolId } from '../../common/__tests__/envSetup';
import { DynamoDBTestSetup } from '../../common/__tests__/dynamodbSetup';
import { CustomRunbookRepository } from '../../common/repositories/customRunbookRepository';
import { UserAccountMappingRepository } from '../../common/repositories/userAccountMappingRepository';
import { RunbookIdSchema, type RunbookMetadata } from '@asr/data-models';
import {
  createAgentCoreContext,
  createAgentCoreEvent,
  createLambdaPayload,
  forwardedApiRequest,
  stubCognitoJwks,
  toolCallResult,
  type ForwardedApiRequest,
  type ToolCallResult,
} from './mcpAuthorizationTestFactories';

const MCP_ACCOUNT_ID = '123456789012';
const MEMBER_ACCOUNT_ID = '210987654321';
const CONTROL_ID = 'S3.9';
// A UUID because both `deploy_runbook` and `test_runbook_yaml` validate runbook_id with
// z.uuid() — the two tools have to agree on what an id is, or a version could earn a
// recorded test pass under an id the deploy would then reject as malformed. toolContract's
// "rejects a runbook_id that is not a UUID" test is the other half of that.
const RUNBOOK_ID = '33333333-3333-4333-8333-333333333333';
const REQUIRED_IAM_ACTIONS = ['s3:PutBucketLogging'];
const TEST_BOUNDARY_ARN = `arn:aws:iam::${MCP_ACCOUNT_ID}:policy/SO0111-ASR-Custom-Runbook-Test-Boundary`;
const CUSTOM_RUNBOOK_TABLE = 'test-flow-custom-runbook';
const MAPPING_TABLE = 'test-flow-user-account-mapping';
const REMEDIATION_HISTORY_TABLE = 'test-flow-remediation-history';

// The real verifyAccessToken runs here: tokens carry genuine RS256 signatures and only the
// Cognito JWKS endpoint is stubbed (see stubCognitoJwks). Mocking our own verifier would be
// the `jest.mock` on our own module that unit-testing.md rules out, and would leave the
// token-verification path these dispatch and authorization tests depend on unexercised.

process.env.API_FUNCTION_NAME = 'SO0111-ASR-APIs';
process.env.COGNITO_USER_POOL_ID = userPoolId;
process.env.MCP_GATEWAY_CLIENT_ID = 'gateway-client-1';
process.env.USER_ACCOUNT_MAPPING_TABLE_NAME = MAPPING_TABLE;
process.env.CUSTOM_RUNBOOK_TABLE_NAME = CUSTOM_RUNBOOK_TABLE;
process.env.CUSTOM_RUNBOOK_TEST_BOUNDARY_ARN = TEST_BOUNDARY_ARN;
process.env.REMEDIATION_HISTORY_TABLE_NAME = REMEDIATION_HISTORY_TABLE;

// The custom remediation lifecycle, driven through the MCP Lambda entry point as ONE
// sequence: discover a gap → author → validate → test → deploy → execute → observe.
//
// Every existing MCP suite calls a single executor, or the handler for a single tool.
// The guarantees this feature rests on are not properties of any one call — they are
// properties BETWEEN calls:
//
//   * the control id a customer discovers is the control id they author against
//     (nothing normalizes or re-cases it on the way through — ADR 0010);
//   * the version `test_runbook_yaml` stamps is the version `deploy_runbook` later
//     gates on, bound to the same content digest and the same IAM action set;
//   * the two privileged steps (test and deploy) are refused for a caller below the
//     Admin/Delegated Admin tier even mid-flow, when everything before them succeeded.
//
// State that must survive between calls (the custom runbook version and its recorded test
// outcome) lives in the real runbook table in DynamoDB Local, written and read through
// CustomRunbookRepository (unit-testing.md). That is the point of the suite: the guarded
// recording write, its key schema and the consistent read the test pre-check makes are the
// hand-off between calls, and a stub would re-implement exactly the thing being asserted.
// AWS calls with no bearing on those invariants (SSM, IAM, Security Hub) are stubbed at the
// SDK boundary.

const cognitoMock = mockClient(CognitoIdentityProviderClient);
const lambdaMock = mockClient(LambdaClient);
const ssmMock = mockClient(SSMClient);
const iamMock = mockClient(IAMClient);
const securityHubMock = mockClient(SecurityHubClient);

import { handler } from '../mcpServerHandler';
import { resetMcpServerEnvironmentCache } from '../mcpServerEnvironment';
import { resetTokenVerifierCache } from '../tokenVerifier';

let customRunbookRepository: CustomRunbookRepository;
let userAuthorizationRepository: UserAccountMappingRepository;

const clientId = 'gateway-client-1';
const operatorUsername = 'flow.operator';
const operatorEmail = 'flow.operator@example.com';

const RUNBOOK_YAML = [
  'schemaVersion: "0.3"',
  'description: enable S3 access logging',
  'assumeRole: "{{ AutomationAssumeRole }}"',
  'parameters:',
  '  AutomationAssumeRole:',
  '    type: String',
  'mainSteps:',
  '  - name: EnableLogging',
  "    action: 'aws:executeScript'",
  '    inputs:',
  '      Runtime: python3.11',
  '      Handler: handler',
  '      Script: |-',
  '        def handler(event, _context):',
  '            return {"ok": True}',
].join('\n');

function sha256(content: string): string {
  return createHash('sha256').update(content, 'utf8').digest('hex');
}

/**
 * Register a version the way the ASR API's register action does: a DRAFT record whose
 * `registeredContentDigest` fingerprints the exact YAML bytes. Written through the real
 * repository so the record the MCP-side test tool reads back has the real key schema.
 */
async function registerVersion(runbookId: string, version: number, runbookYaml: string): Promise<void> {
  await customRunbookRepository.createVersion({
    runbookId: RunbookIdSchema.parse(runbookId),
    version,
    controlId: CONTROL_ID,
    serviceName: 's3',
    description: 'enable S3 access logging',
    remediationAction: 'EnableLogging',
    status: 'DRAFT',
    s3Key: `runbooks/${runbookId}/v${version}/runbook.yaml`,
    createdBy: 'flow-test',
    createdAt: '2026-01-01T00:00:00.000Z',
    registeredContentDigest: sha256(runbookYaml),
  });
}

/** The stored record for one version, read back through the repository. */
async function storedVersion(runbookId: string, version: number): Promise<RunbookMetadata | undefined> {
  return customRunbookRepository.findVersion(RunbookIdSchema.parse(runbookId), version);
}

/** Every ASR API request the handler proxied, in call order. */
function forwardedApiCalls(): ForwardedApiRequest[] {
  return lambdaMock.commandCalls(InvokeCommand).map((call) => forwardedApiRequest(call.args[0].input));
}

function lastForwardedCall(path: string): ForwardedApiRequest {
  const calls = forwardedApiCalls().filter((call) => call.path === path);
  expect(calls.length).toBeGreaterThan(0);
  return calls[calls.length - 1];
}

/**
 * Stand in for the ASR API Lambda.
 *
 * Responses are per route, and `/runbooks/deploy` also mutates the shared version
 * store — register writes the DRAFT version the MCP-side test tool then reads, which
 * is the hand-off this suite exists to exercise.
 */
function stubApiLambda(): void {
  lambdaMock.on(InvokeCommand).callsFake(async (input) => {
    const { path, body } = forwardedApiRequest(input);
    const respond = (payload: object): { Payload: Uint8Array } => ({
      Payload: createLambdaPayload(JSON.stringify({ statusCode: 200, body: JSON.stringify(payload) })),
    });

    switch (path) {
      case '/runbooks/generate':
        return respond({ rules: 'authoring rules', description: body.description });
      case '/runbooks/validate':
        return respond({ valid: true, findings: [] });
      case '/runbooks/deploy': {
        if (body.action === 'register') {
          const version = (await storedVersion(RUNBOOK_ID, 1)) ? 2 : 1;
          await registerVersion(RUNBOOK_ID, version, String(body.runbook_yaml));
          return respond({
            action: 'register',
            runbook_id: RUNBOOK_ID,
            version,
            status: 'DRAFT',
            control_id: body.control_id,
            s3_key: `runbooks/${RUNBOOK_ID}/v${version}/runbook.yaml`,
          });
        }
        return respond({
          action: 'deploy',
          runbook_id: body.runbook_id,
          version: body.version ?? 1,
          status: 'DEPLOYED',
          document_name: `ASR-Custom-${body.security_standard}_${body.standard_version}_${body.control_id}`,
          role_provisioning: { succeeded: body.member_account_ids, failed: [] },
          document_deployment: { succeeded: body.member_account_ids, failed: [] },
        });
      }
      case '/runbooks/execute':
        return respond({ execution_id: 'execution-1', status: 'IN_PROGRESS' });
      case '/runbooks/execution-status':
        return respond({ execution_id: 'execution-1', status: 'SUCCESS' });
      default:
        return respond({ ok: true });
    }
  });
}

/** Automation outcome the transient test document reports on its first poll. */
function stubAutomationOutcome(status: 'Success' | 'Failed', failureMessage?: string): void {
  ssmMock.on(StartAutomationExecutionCommand).resolves({ AutomationExecutionId: 'execution-1' });
  ssmMock.on(GetAutomationExecutionCommand).resolves({
    AutomationExecution: {
      AutomationExecutionId: 'execution-1',
      AutomationExecutionStatus: status,
      FailureMessage: failureMessage,
      StepExecutions: [
        {
          StepName: 'EnableLogging',
          StepStatus: status === 'Success' ? 'Success' : 'Failed',
        },
      ],
    },
  });
}

const CONSOLIDATED_FINDING_ID = `arn:aws:securityhub:us-east-1:${MCP_ACCOUNT_ID}:security-control/S3.9/finding/11111111-1111-1111-1111-111111111111`;

beforeAll(async () => {
  // One JWKS response serves the whole suite: the pool's signing key does not change, so the
  // verifier fetches it once and caches it. The cache is cleared first so module state cannot
  // leak in from another suite.
  resetTokenVerifierCache();
  stubCognitoJwks();
  await DynamoDBTestSetup.createCustomRunbookTable(CUSTOM_RUNBOOK_TABLE);
  await DynamoDBTestSetup.createUserAccountMappingTable(MAPPING_TABLE);
  // Read by get_execution_status further along the flow; empty is the genuine state here.
  await DynamoDBTestSetup.createRemediationHistoryTable(REMEDIATION_HISTORY_TABLE);
  customRunbookRepository = new CustomRunbookRepository(CUSTOM_RUNBOOK_TABLE, DynamoDBTestSetup.getDocClient());
  userAuthorizationRepository = new UserAccountMappingRepository(
    'test-principal',
    MAPPING_TABLE,
    DynamoDBTestSetup.getDocClient(),
  );
});

beforeEach(async () => {
  cognitoMock.reset();
  lambdaMock.reset();
  ssmMock.reset();
  iamMock.reset();
  securityHubMock.reset();
  await DynamoDBTestSetup.clearTable(CUSTOM_RUNBOOK_TABLE, 'customRunbook');
  await DynamoDBTestSetup.clearTable(MAPPING_TABLE, 'userAccountMapping');
  resetMcpServerEnvironmentCache();

  stubApiLambda();
  stubAutomationOutcome('Success');
  ssmMock.on(CreateDocumentCommand).resolves({ DocumentDescription: { DocumentVersion: '1' } });
  ssmMock.on(DeleteDocumentCommand).resolves({});
  // No ASR runbook documents exist yet, so every control with findings is a gap.
  ssmMock.on(ListDocumentsCommand).resolves({ DocumentIdentifiers: [] });

  // The test role already exists, so provisioning reuses it. A freshly created role
  // takes a bounded IAM-propagation settle delay that no test needs to sit through.
  iamMock.on(GetRoleCommand).resolves({
    Role: {
      Path: '/',
      RoleName: 'SO0111-Remediate-Custom-Test-existing',
      RoleId: 'AROAEXAMPLE',
      Arn: `arn:aws:iam::${MCP_ACCOUNT_ID}:role/SO0111-Remediate-Custom-Test-existing`,
      CreateDate: new Date('2026-01-01T00:00:00.000Z'),
    },
  });
  iamMock.on(PutRolePermissionsBoundaryCommand).resolves({});
  iamMock.on(UpdateAssumeRolePolicyCommand).resolves({});
  iamMock.on(PutRolePolicyCommand).resolves({});
  iamMock.on(TagRoleCommand).resolves({});
  iamMock.on(DeleteRolePolicyCommand).resolves({});
  iamMock.on(DeleteRoleCommand).resolves({});

  securityHubMock.on(GetFindingHistoryCommand).resolves({ Records: [] });
});

afterAll(() => {
  cognitoMock.restore();
  lambdaMock.restore();
  ssmMock.restore();
  iamMock.restore();
  securityHubMock.restore();
});

/** Invoke one tool as an Admin, the tier that may run every step of the lifecycle. */
async function callAsAdmin(toolName: string, args: Record<string, unknown>): Promise<ToolCallResult> {
  return toolCallResult(
    await handler(createAgentCoreEvent({ groups: ['AdminGroup'], clientId }, args), createAgentCoreContext(toolName)),
  );
}

/** Invoke one tool as an Account Operator holding the widest possible grant. */
async function callAsAccountOperator(toolName: string, args: Record<string, unknown>): Promise<ToolCallResult> {
  cognitoMock
    .on(AdminGetUserCommand, { UserPoolId: userPoolId, Username: operatorUsername })
    .resolves({ UserAttributes: [{ Name: 'email', Value: operatorEmail }] });
  await userAuthorizationRepository.create({
    userId: operatorEmail,
    accountIds: [MCP_ACCOUNT_ID],
    allowedMcpTools: ['*'],
  });

  return toolCallResult(
    await handler(
      createAgentCoreEvent({ groups: ['AccountOperatorGroup'], clientId, username: operatorUsername }, args),
      createAgentCoreContext(toolName),
    ),
  );
}

/**
 * A minimal but correctly-typed Security Hub finding. Only the fields the discovery step
 * reads are set, and the single `as` narrows the partial to `AwsSecurityFinding` in one
 * place — rather than casting the whole stubbed response to `never`, which switches off
 * checking for the entire `GetFindingsCommandOutput` (ADR 0001, no scattered casts). Mirrors
 * the `finding` helper in findingsWithoutRunbook.test.ts.
 */
function consolidatedControlFinding(): AwsSecurityFinding {
  return {
    Id: CONSOLIDATED_FINDING_ID,
    AwsAccountId: MCP_ACCOUNT_ID,
    Title: 'S3 general purpose buckets should have server access logging enabled',
    Compliance: { SecurityControlId: CONTROL_ID },
  } as AwsSecurityFinding;
}

/** Findings for the discovery step: one consolidated control finding. */
function stubFindings(): void {
  securityHubMock.on(GetFindingsCommand).resolves({ Findings: [consolidatedControlFinding()] });
}

describe('custom remediation lifecycle through the MCP handler', () => {
  it('carries one control from discovery through test, deploy, and execution', async () => {
    // GIVEN a control with findings and no runbook of any kind
    stubFindings();

    // WHEN — step 1: the customer asks which findings have no remediation
    const gaps = await callAsAdmin('list_findings_without_runbook', {});

    // THEN the control is reported as a gap, with its id exactly as Security Hub
    // gave it. ADR 0010 warns that control ids are case-sensitive and that the
    // consolidated-prefix strip silently no-ops, so a re-cased or trimmed id here
    // would have the customer author against a control that never matches.
    expect(gaps.status).toBe(200);
    const discoveredControlIds = (gaps.body.controls as { controlId: string }[]).map((control) => control.controlId);
    expect(discoveredControlIds).toEqual([CONTROL_ID]);

    // WHEN — step 2: history for the finding that motivated the work
    const history = await callAsAdmin('get_finding_history', { finding_id: CONSOLIDATED_FINDING_ID });
    expect(history.status).toBe(200);

    // WHEN — step 3: authoring guidance for exactly the discovered control
    const generated = await callAsAdmin('generate_runbook', {
      description: 'enable S3 access logging',
      control_id: discoveredControlIds[0],
    });

    // THEN the id the customer discovered is the id the API is asked about
    expect(generated.status).toBe(200);
    expect(lastForwardedCall('/runbooks/generate').body.control_id).toBe(CONTROL_ID);

    // WHEN — step 4: validation of the authored YAML
    const validated = await callAsAdmin('validate_runbook', { runbook_yaml: RUNBOOK_YAML });
    expect(validated.status).toBe(200);

    // WHEN — step 5: the version is registered as a DRAFT
    const registered = await callAsAdmin('deploy_runbook', {
      action: 'register',
      runbook_yaml: RUNBOOK_YAML,
      control_id: CONTROL_ID,
    });

    // THEN
    expect(registered.body.status).toBe('DRAFT');
    expect(registered.body.version).toBe(1);

    // WHEN — step 6: the registered version is tested for real
    const tested = await callAsAdmin('test_runbook_yaml', {
      runbook_yaml: RUNBOOK_YAML,
      runbook_id: registered.body.runbook_id,
      version: registered.body.version,
      required_iam_actions: REQUIRED_IAM_ACTIONS,
      timeout_seconds: 60,
    });

    // THEN the outcome is recorded against that version, and the transient document
    // is gone — a document left behind counts against the account's SSM quota.
    expect(tested.status).toBe(200);
    expect(tested.body.testResultRecorded).toBe(true);
    expect(ssmMock.commandCalls(DeleteDocumentCommand)).toHaveLength(1);

    // THEN the recorded row satisfies exactly the three conditions the deploy gate
    // checks (runbookDeploymentService.assertVersionPassedTest): a PASSED status, a
    // tested digest equal to the registered one, and the same IAM action set the
    // deploy will request. Asserting them here proves the MCP side produces what the
    // gate consumes; that the gate enforces them is covered api-side.
    const row = await storedVersion(RUNBOOK_ID, 1);
    expect(row?.testStatus).toBe('PASSED');
    expect(row?.testedContentDigest).toBe(row?.registeredContentDigest);
    expect(row?.testedIamActions).toEqual(REQUIRED_IAM_ACTIONS);

    // WHEN — step 7: the proven version is deployed to a member account
    const deployed = await callAsAdmin('deploy_runbook', {
      action: 'deploy',
      runbook_id: RUNBOOK_ID,
      control_id: CONTROL_ID,
      security_standard: 'SC',
      standard_version: '2.0.0',
      required_iam_actions: REQUIRED_IAM_ACTIONS,
      member_account_ids: [MEMBER_ACCOUNT_ID],
      version: 1,
    });

    // THEN the deploy names the same version and the same permission set that were
    // tested. Forwarding a different action set is how a version proven under one
    // permission set would deploy under another.
    expect(deployed.body.status).toBe('DEPLOYED');
    const deployRequest = lastForwardedCall('/runbooks/deploy');
    expect(deployRequest.body).toMatchObject({
      action: 'deploy',
      runbook_id: RUNBOOK_ID,
      version: 1,
      required_iam_actions: REQUIRED_IAM_ACTIONS,
      member_account_ids: [MEMBER_ACCOUNT_ID],
    });

    // WHEN — step 8: the remediation is run against the finding and observed
    const executed = await callAsAdmin('execute_runbook', { finding_id: CONSOLIDATED_FINDING_ID });
    const status = await callAsAdmin('get_execution_status', { finding_id: CONSOLIDATED_FINDING_ID });

    // THEN
    expect(executed.status).toBe(200);
    expect(status.body.status).toBe('SUCCESS');
    expect(lastForwardedCall('/runbooks/execute').body.finding_id).toBe(CONSOLIDATED_FINDING_ID);
  });

  it('records FAILED for a version whose automation fails, leaving nothing for a deploy to pass on', async () => {
    // GIVEN a registered version whose test execution fails
    await registerVersion(RUNBOOK_ID, 1, RUNBOOK_YAML);
    stubAutomationOutcome('Failed', 'step EnableLogging failed');

    // WHEN
    const tested = await callAsAdmin('test_runbook_yaml', {
      runbook_yaml: RUNBOOK_YAML,
      runbook_id: RUNBOOK_ID,
      version: 1,
      required_iam_actions: REQUIRED_IAM_ACTIONS,
      timeout_seconds: 60,
    });

    // THEN the failure is recorded on the version, not swallowed, so the deploy gate
    // has a FAILED status to refuse rather than an absent one to interpret.
    expect(tested.status).toBe(200);
    expect((await storedVersion(RUNBOOK_ID, 1))?.testStatus).toBe('FAILED');
    // The transient document is still cleaned up on the failure path.
    expect(ssmMock.commandCalls(DeleteDocumentCommand)).toHaveLength(1);
  });

  it('does not record a pass for a registration-only run that executed nothing', async () => {
    // GIVEN a registered version
    await registerVersion(RUNBOOK_ID, 1, RUNBOOK_YAML);

    // WHEN the caller only checks that SSM accepts the document
    const tested = await callAsAdmin('test_runbook_yaml', {
      runbook_yaml: RUNBOOK_YAML,
      runbook_id: RUNBOOK_ID,
      version: 1,
      required_iam_actions: REQUIRED_IAM_ACTIONS,
      skip_execution: true,
    });

    // THEN nothing ran, so nothing may be recorded — otherwise skip_execution would
    // be a way to earn a passing gate without executing the runbook at all.
    expect(tested.status).toBe(200);
    expect(ssmMock.commandCalls(StartAutomationExecutionCommand)).toHaveLength(0);
    expect((await storedVersion(RUNBOOK_ID, 1))?.testStatus).toBeUndefined();
  });

  it('binds the recorded pass to the tested bytes with the guard the gate depends on', async () => {
    // GIVEN a registered version
    await registerVersion(RUNBOOK_ID, 1, RUNBOOK_YAML);

    // WHEN it is tested
    await callAsAdmin('test_runbook_yaml', {
      runbook_yaml: RUNBOOK_YAML,
      runbook_id: RUNBOOK_ID,
      version: 1,
      required_iam_actions: REQUIRED_IAM_ACTIONS,
      timeout_seconds: 60,
    });

    // THEN the pass is stamped on the version with the digest of the bytes that were
    // actually tested, and that digest is the registered one — the pair the deploy gate
    // compares. The conditional write that produces this is guarded on the version
    // existing and on the two digests matching; the refusals those conditions cause are
    // covered by "refuses to test a version that was never registered" and "refuses to
    // test a version against content other than what was registered for it".
    const row = await storedVersion(RUNBOOK_ID, 1);
    expect(row?.testStatus).toBe('PASSED');
    expect(row?.testedContentDigest).toBe(sha256(RUNBOOK_YAML));
    expect(row?.registeredContentDigest).toBe(sha256(RUNBOOK_YAML));
  });

  it('reports drift after the deployed document is edited out of band', async () => {
    // The failure this covers: someone edits the live SSM document (console, CLI, another
    // pipeline), so what runs in the account is no longer the reviewed and tested content.
    // Nothing else in the lifecycle notices — deploy already succeeded and the runbook
    // record still points at the registered version.
    const documentName = 'ASR-Custom-SC_2.0.0_MCPProbe.1';
    // A real content change: the step's script now returns something else entirely.
    const editedYaml = RUNBOOK_YAML.replace('return {"ok": True}', 'return {"tampered": True}');
    ssmMock.on(DescribeDocumentCommand).resolves({
      Document: { Name: documentName, Status: 'Active', DocumentVersion: '2', DocumentFormat: 'YAML' },
    });
    ssmMock.on(GetDocumentCommand).resolves({ Content: editedYaml, DocumentFormat: 'YAML', DocumentVersion: '2' });

    const drift = await callAsAdmin('check_runbook_drift', {
      document_name: documentName,
      runbook_yaml: RUNBOOK_YAML,
    });

    expect(drift.status).toBe(200);
    expect(drift.body.isInSync).toBe(false);
    expect(drift.body.reason).toBe('differs');
    expect((drift.body.structuralDiff as unknown[]).length).toBeGreaterThan(0);
  });

  it('reports no drift when the live document is reformatted but structurally identical', async () => {
    // Reformatting is not drift. If it were, every legitimate deployment would look
    // tampered with and the signal would be ignored.
    const documentName = 'ASR-Custom-SC_2.0.0_MCPProbe.1';
    // A genuine reformat: quote style flipped on three scalars, the mainSteps list
    // de-indented to column 0, `type: String` re-indented, and the script block scalar
    // re-indented — all of which parse to the same document. A whitespace-only variant
    // would not exercise this case at all: the comparator compares trimmed text first and
    // returns `identical-text`, so the structural path this test is about never runs. That
    // is why the reason is asserted and not just `isInSync`.
    const reformattedYaml = [
      "schemaVersion: '0.3'",
      'description: enable S3 access logging',
      "assumeRole: '{{ AutomationAssumeRole }}'",
      'parameters:',
      '  AutomationAssumeRole:',
      '      type: String',
      'mainSteps:',
      '- name: EnableLogging',
      '  action: "aws:executeScript"',
      '  inputs:',
      '    Runtime: python3.11',
      '    Handler: handler',
      '    Script: |-',
      '      def handler(event, _context):',
      '          return {"ok": True}',
    ].join('\n');
    // Guards the setup itself: if the two ever became the same text, the assertions below
    // would pass through the identical-text short-circuit and prove nothing.
    expect(reformattedYaml.trim()).not.toBe(RUNBOOK_YAML.trim());
    ssmMock.on(DescribeDocumentCommand).resolves({
      Document: { Name: documentName, Status: 'Active', DocumentVersion: '1', DocumentFormat: 'YAML' },
    });
    ssmMock.on(GetDocumentCommand).resolves({ Content: reformattedYaml, DocumentFormat: 'YAML', DocumentVersion: '1' });

    const drift = await callAsAdmin('check_runbook_drift', {
      document_name: documentName,
      runbook_yaml: RUNBOOK_YAML,
    });

    expect(drift.body.isInSync).toBe(true);
    expect(drift.body.reason).toBe('identical-structure');
    expect(drift.body.structuralDiff).toEqual([]);
  });

  it('refuses to test a version that was never registered', async () => {
    // GIVEN an empty table — no version was registered first

    // WHEN
    const tested = await callAsAdmin('test_runbook_yaml', {
      runbook_yaml: RUNBOOK_YAML,
      runbook_id: RUNBOOK_ID,
      version: 1,
      required_iam_actions: REQUIRED_IAM_ACTIONS,
      timeout_seconds: 60,
    });

    // THEN the caller is told to register first, and no automation is started: an
    // unregistered (runbookId, version) must not gain a record consisting of nothing
    // but a passing test.
    expect(tested.status).toBe(400);
    expect(ssmMock.commandCalls(StartAutomationExecutionCommand)).toHaveLength(0);
    // The guarded write is what keeps this true: an unconditional one would create the
    // record it was supposed to require.
    expect(await storedVersion(RUNBOOK_ID, 1)).toBeUndefined();
  });

  it('refuses the two privileged lifecycle steps for an Account Operator mid-flow', async () => {
    // GIVEN an Account Operator granted every tool their tier allows, and a version
    // already registered and proven by an Admin
    await registerVersion(RUNBOOK_ID, 1, RUNBOOK_YAML);

    // WHEN they attempt the two steps that write customer-authored code into an
    // account and run it under an elevated role
    const tested = await callAsAccountOperator('test_runbook_yaml', {
      runbook_yaml: RUNBOOK_YAML,
      runbook_id: RUNBOOK_ID,
      version: 1,
      required_iam_actions: REQUIRED_IAM_ACTIONS,
    });
    const deployed = await callAsAccountOperator('deploy_runbook', {
      action: 'deploy',
      runbook_id: RUNBOOK_ID,
      control_id: CONTROL_ID,
      security_standard: 'SC',
      standard_version: '2.0.0',
      required_iam_actions: REQUIRED_IAM_ACTIONS,
      member_account_ids: [MEMBER_ACCOUNT_ID],
    });

    // THEN both are refused for the tier, and neither reached AWS or the ASR API
    expect(tested.status).toBe(403);
    expect(deployed.status).toBe(403);
    expect(ssmMock.commandCalls(CreateDocumentCommand)).toHaveLength(0);
    expect(forwardedApiCalls().filter((call) => call.path === '/runbooks/deploy')).toHaveLength(0);
  });

  it('lets the same Account Operator run the read-only steps of the flow', async () => {
    // GIVEN the same operator and the same findings
    stubFindings();

    // WHEN they perform discovery and validation rather than test or deploy
    const gaps = await callAsAccountOperator('list_findings_without_runbook', {});
    const validated = await callAsAccountOperator('validate_runbook', { runbook_yaml: RUNBOOK_YAML });

    // THEN the tier that cannot deploy can still find gaps and check YAML, which is
    // what makes the ceiling a useful boundary rather than a blanket denial.
    expect(gaps.status).toBe(200);
    expect(validated.status).toBe(200);
  });

  it('refuses to test a version against content other than what was registered for it', async () => {
    // GIVEN v1 registered and proven, then v2 registered with revised content —
    // the "fix it and ship v2" step of the journey
    const revisedYaml = `${RUNBOOK_YAML}\n# revised: also enable logging on new buckets\n`;
    await callAsAdmin('deploy_runbook', { action: 'register', runbook_yaml: RUNBOOK_YAML, control_id: CONTROL_ID });
    await callAsAdmin('test_runbook_yaml', {
      runbook_yaml: RUNBOOK_YAML,
      runbook_id: RUNBOOK_ID,
      version: 1,
      required_iam_actions: REQUIRED_IAM_ACTIONS,
      timeout_seconds: 60,
    });
    const secondRegister = await callAsAdmin('deploy_runbook', {
      action: 'register',
      runbook_yaml: revisedYaml,
      control_id: CONTROL_ID,
    });
    expect(secondRegister.body.version).toBe(2);
    // Forget the v1 test's own SSM calls so what follows is attributable to the v2 attempt.
    ssmMock.resetHistory();

    // WHEN the caller tests v2 but supplies v1's YAML — the substitution that would
    // earn v2 a pass for bytes it does not contain
    const tested = await callAsAdmin('test_runbook_yaml', {
      runbook_yaml: RUNBOOK_YAML,
      runbook_id: RUNBOOK_ID,
      version: 2,
      required_iam_actions: REQUIRED_IAM_ACTIONS,
      timeout_seconds: 60,
    });

    // THEN it is refused before any IAM role is created or any automation starts,
    // v2 stays untested, and v1's pass stays on v1 rather than covering v2.
    expect(tested.status).toBe(400);
    expect(tested.body.error).toMatch(/not the content registered/);
    expect(ssmMock.commandCalls(StartAutomationExecutionCommand)).toHaveLength(0);
    expect((await storedVersion(RUNBOOK_ID, 2))?.testStatus).toBeUndefined();
    expect((await storedVersion(RUNBOOK_ID, 1))?.testStatus).toBe('PASSED');
    expect((await storedVersion(RUNBOOK_ID, 2))?.registeredContentDigest).toBe(sha256(revisedYaml));
  });
});
