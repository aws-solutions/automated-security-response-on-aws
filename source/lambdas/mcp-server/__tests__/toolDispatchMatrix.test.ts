// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { AdminGetUserCommand, CognitoIdentityProviderClient } from '@aws-sdk/client-cognito-identity-provider';
import { InvokeCommand, LambdaClient } from '@aws-sdk/client-lambda';
import { GetFindingHistoryCommand, GetFindingsCommand, SecurityHubClient } from '@aws-sdk/client-securityhub';
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
import { GetRoleCommand, IAMClient } from '@aws-sdk/client-iam';
import { mockClient } from 'aws-sdk-client-mock';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { userPoolId } from '../../common/__tests__/envSetup';
import { DynamoDBTestSetup } from '../../common/__tests__/dynamodbSetup';
import { UserAccountMappingRepository } from '../../common/repositories/userAccountMappingRepository';
import {
  createAgentCoreContext,
  createAgentCoreEvent,
  createLambdaPayload,
  forwardedApiRequest,
  stubCognitoJwks,
  type ForwardedApiRequest,
} from './mcpAuthorizationTestFactories';

// Suite-private table names, created in DynamoDB Local. The grant read drives tier and
// account enforcement for every tool below, so it runs through the real repository against
// a real table (unit-testing.md): a stub would leave the key schema and the lowercase-key
// fallback unexercised for exactly the 28 tools this matrix claims to cover. The names are
// suite-private so the file does not share state with another test file.
const dispatchUserAccountMappingTableName = 'test-dispatch-matrix-user-account-mapping';
const dispatchRemediationHistoryTableName = 'test-dispatch-matrix-remediation-history';
const dispatchCustomRunbookTableName = 'test-dispatch-matrix-custom-runbook';

// The real verifyAccessToken runs here: tokens carry genuine RS256 signatures and only the
// Cognito JWKS endpoint is stubbed (see stubCognitoJwks). Mocking our own verifier would be
// the `jest.mock` on our own module that unit-testing.md rules out, and would leave the
// token-verification path these dispatch and authorization tests depend on unexercised.

process.env.API_FUNCTION_NAME = 'SO0111-ASR-APIs';
process.env.COGNITO_USER_POOL_ID = userPoolId;
process.env.MCP_GATEWAY_CLIENT_ID = 'gateway-client-1';
process.env.USER_ACCOUNT_MAPPING_TABLE_NAME = dispatchUserAccountMappingTableName;
process.env.REMEDIATION_HISTORY_TABLE_NAME = dispatchRemediationHistoryTableName;
process.env.CUSTOM_RUNBOOK_TABLE_NAME = dispatchCustomRunbookTableName;

// Every advertised tool, driven through the Lambda entry point.
//
// The per-tool executor suites already cover each backend in depth. What none of
// them covers is the entry point itself: before this suite, 3 of the 28 advertised
// tools were ever invoked through `handler`, so for the other 25 nothing proved the
// tool name resolves, the arguments survive validation, the caller's tier is
// enforced, or — for a proxied tool — that the ASR API is asked for the right path
// and method. A route typo or a schema/route mismatch was invisible until a client
// called it.
//
// Two properties are asserted for all 28 tools at once, so a tool added to
// `toolSchema.json` without a fixture fails the parity test rather than shipping
// unexercised:
//   1. Dispatch — a proxied tool reaches the API Lambda at its declared path and
//      method (path params substituted into the URL, not left in the body); a
//      direct tool executes in-process and invokes no API Lambda at all.
//   2. Authorization — the Account Operator ceiling is enforced per tool, with a
//      tier refusal distinguishable from a missing grant.

const cognitoMock = mockClient(CognitoIdentityProviderClient);
const lambdaMock = mockClient(LambdaClient);
const ssmMock = mockClient(SSMClient);
const iamMock = mockClient(IAMClient);
const securityHubMock = mockClient(SecurityHubClient);

import { handler } from '../mcpServerHandler';
import { resetMcpServerEnvironmentCache } from '../mcpServerEnvironment';
import { resetTokenVerifierCache } from '../tokenVerifier';
import { ACCOUNT_OPERATOR_TOOLS } from '../contract/toolContract';

let userAuthorizationRepository: UserAccountMappingRepository;

const clientId = 'gateway-client-1';
const username = 'dispatch.matrix.user';
const userEmail = 'dispatch.matrix@example.com';
const ACCOUNT_ID = '123456789012';
const TEST_ASSUME_ROLE = `arn:aws:iam::${ACCOUNT_ID}:role/SO0111-ASR-Custom-Runbook-Test`;
// test_remediation_script validates the role name against the only prefix the MCP server is
// permitted to iam:PassRole to SSM, so its fixture cannot reuse TEST_ASSUME_ROLE above.
const TEST_REMEDIATION_ASSUME_ROLE = `arn:aws:iam::${ACCOUNT_ID}:role/SO0111-Remediate-Custom-Test-dispatch`;

/** How a tool is expected to be served, and the arguments to serve it with. */
interface ToolFixture {
  readonly args: Record<string, unknown>;
  /** Proxied: the ASR API path and method the handler must invoke. */
  readonly proxy?: { readonly path: string; readonly method: string };
  /** Direct: executes in this Lambda, so no API Lambda invocation may happen. */
  readonly direct?: true;
  /**
   * Argument that fills a `{param}` token in the route path. It must appear in the
   * concrete path and must NOT remain in the forwarded body — leaving it in the
   * body is how a parameterized route silently posts to the collection endpoint.
   */
  readonly pathParam?: { readonly name: string; readonly value: string };
}

const VALID_YAML = 'schemaVersion: "0.3"\ndescription: probe\nmainSteps: []\n';
const FILTER_ID = '11111111-1111-4111-8111-111111111111';
const NOTIFICATION_ID = '22222222-2222-4222-8222-222222222222';

const notificationBody = {
  name: 'Probe config',
  enabled: true,
  notificationType: 'finding' as const,
  deliveryChannels: [{ type: 'sns' as const, enabled: true, topicArn: `arn:aws:sns:us-east-1:${ACCOUNT_ID}:probe` }],
  batchWindow: { enabled: false },
  contentOptions: {
    includeManualRemediationLink: true,
    includeRemediationDeadline: false,
    includeIaCSnippet: false,
    includeEnableAutomationLink: true,
  },
};

const filterBody = {
  name: 'Probe filter',
  accountIds: [ACCOUNT_ID],
  organizationalUnits: [],
  tags: [],
  arnPatterns: [],
};

const TOOL_FIXTURES: Readonly<Record<string, ToolFixture>> = {
  // --- Custom runbook lifecycle (proxied to the ASR API) ---
  generate_runbook: {
    args: { description: 'enable access logging' },
    proxy: { path: '/runbooks/generate', method: 'POST' },
  },
  validate_runbook: { args: { runbook_yaml: VALID_YAML }, proxy: { path: '/runbooks/validate', method: 'POST' } },
  deploy_runbook: {
    args: { action: 'register', runbook_yaml: VALID_YAML, control_id: 'S3.9' },
    proxy: { path: '/runbooks/deploy', method: 'POST' },
  },
  execute_runbook: { args: { finding_id: 'finding-1' }, proxy: { path: '/runbooks/execute', method: 'POST' } },
  get_execution_status: {
    args: { finding_id: 'finding-1' },
    proxy: { path: '/runbooks/execution-status', method: 'POST' },
  },
  list_runbooks: { args: {}, proxy: { path: '/runbooks/list', method: 'POST' } },
  get_runbook: { args: { runbook_id: 'rb-1' }, proxy: { path: '/runbooks/get', method: 'POST' } },
  drift_detection: {
    args: { action: 'status', execution_id: 'execution-1', account_id: ACCOUNT_ID },
    proxy: { path: '/runbooks/drift-detection', method: 'POST' },
  },

  // --- Controls, filters, findings, reporting ---
  list_controls: { args: {}, proxy: { path: '/controls', method: 'GET' } },
  update_controls: {
    args: {
      operation: 'update',
      data: [
        {
          controlId: 'S3.9',
          description: 'S3 bucket logging',
          automatedRemediationEnabled: true,
          filters: [],
          filterMode: 'exclude',
          version: 1,
          lastModified: '2026-01-01T00:00:00.000Z',
          modifiedBy: userEmail,
        },
      ],
    },
    proxy: { path: '/controls/bulk-edit', method: 'POST' },
  },
  list_filters: { args: {}, proxy: { path: '/filters', method: 'GET' } },
  create_filter: { args: filterBody, proxy: { path: '/filters', method: 'POST' } },
  update_filter: {
    args: { ...filterBody, version: 1, filterId: FILTER_ID },
    proxy: { path: `/filters/${FILTER_ID}`, method: 'PUT' },
    pathParam: { name: 'filterId', value: FILTER_ID },
  },
  delete_filter: {
    args: { filterId: FILTER_ID },
    proxy: { path: `/filters/${FILTER_ID}`, method: 'DELETE' },
    pathParam: { name: 'filterId', value: FILTER_ID },
  },
  findings: { args: {}, proxy: { path: '/findings', method: 'POST' } },
  remediations: { args: {}, proxy: { path: '/remediations', method: 'POST' } },
  execute_finding_action: {
    args: { actionType: 'Remediate', findingIds: ['finding-1'] },
    proxy: { path: '/findings/action', method: 'POST' },
  },

  // --- Notifications ---
  list_notifications: { args: {}, proxy: { path: '/notifications', method: 'GET' } },
  create_notification: { args: notificationBody, proxy: { path: '/notifications', method: 'POST' } },
  update_notification: {
    args: { ...notificationBody, version: 1, id: NOTIFICATION_ID },
    proxy: { path: `/notifications/${NOTIFICATION_ID}`, method: 'PUT' },
    pathParam: { name: 'id', value: NOTIFICATION_ID },
  },
  delete_notification: {
    args: { id: NOTIFICATION_ID },
    proxy: { path: `/notifications/${NOTIFICATION_ID}`, method: 'DELETE' },
    pathParam: { name: 'id', value: NOTIFICATION_ID },
  },
  test_notification: {
    args: { id: NOTIFICATION_ID },
    proxy: { path: `/notifications/${NOTIFICATION_ID}/test`, method: 'POST' },
    pathParam: { name: 'id', value: NOTIFICATION_ID },
  },

  // --- Direct execution (AWS SDK calls inside this Lambda) ---
  // An ARN-form finding id: this tool derives the finding's account from the id and
  // fails closed when it cannot, so an Account Operator can only be authorized for
  // an id that actually encodes one of their accounts (ADR 0010).
  get_finding_history: {
    args: {
      finding_id: `arn:aws:securityhub:us-east-1:${ACCOUNT_ID}:subscription/aws-foundational-security-best-practices/v/1.0.0/S3.9/finding/11111111-1111-1111-1111-111111111111`,
    },
    direct: true,
  },
  list_findings_without_runbook: { args: {}, direct: true },
  check_runbook_drift: { args: { document_name: 'ASR-Custom-SC_2.0.0_S3.9', runbook_yaml: VALID_YAML }, direct: true },
  check_deploy_readiness: {
    args: { control_id: 'S3.9', remediation_name: 'EnableS3Logging', namespace: 'test' },
    direct: true,
  },
  test_remediation_script: {
    args: {
      python_script: 'def handler(event, _context):\n    return {"ok": True}\n',
      // SSM needs a role to run the transient document under; the tool refuses
      // rather than guessing one.
      automation_assume_role: TEST_REMEDIATION_ASSUME_ROLE,
      timeout_seconds: 30,
    },
    direct: true,
  },
  test_runbook_yaml: {
    args: {
      runbook_yaml: VALID_YAML,
      input_parameters: { AutomationAssumeRole: TEST_ASSUME_ROLE },
      timeout_seconds: 30,
    },
    direct: true,
  },
};

/** Tool names the gateway actually advertises — the set clients can call. */
const ADVERTISED_TOOL_NAMES: readonly string[] = (
  JSON.parse(readFileSync(join(__dirname, '..', 'toolSchema.json'), 'utf8')) as readonly { name: string }[]
).map((tool) => tool.name);

function stubApiLambda(responseBody: object = { ok: true }, statusCode = 200): void {
  lambdaMock.on(InvokeCommand).resolves({
    Payload: createLambdaPayload(JSON.stringify({ statusCode, body: JSON.stringify(responseBody) })),
  });
}

/** The single API Gateway event the handler forwarded to the ASR API Lambda. */
function forwardedApiEvent(): ForwardedApiRequest {
  const calls = lambdaMock.commandCalls(InvokeCommand);
  expect(calls).toHaveLength(1);
  return forwardedApiRequest(calls[0].args[0].input);
}

function stubCognitoEmail(email: string = userEmail): void {
  cognitoMock
    .on(AdminGetUserCommand, { UserPoolId: userPoolId, Username: username })
    .resolves({ UserAttributes: [{ Name: 'email', Value: email }] });
}

/**
 * Seed the caller's authorization record as the Users panel would write it.
 *
 * `undefined` seeds nothing, modelling a user with no record at all — the state of a
 * Delegated Admin or Account Operator whose administrator has granted nothing, which must
 * deny rather than fall back to the group tier.
 */
async function seedUserGrant(
  allowedTools: readonly string[] | undefined,
  accountIds: readonly string[] = [],
): Promise<void> {
  if (!allowedTools) return;
  await userAuthorizationRepository.create({
    userId: userEmail,
    accountIds: [...accountIds],
    allowedMcpTools: [...allowedTools],
  });
}

/**
 * Make every AWS boundary a direct executor touches answer benignly.
 *
 * The point of this suite is dispatch and authorization, not executor behavior —
 * each executor has its own suite for that — so the stubs only need to let a call
 * complete without reaching real AWS.
 */
function stubDirectExecutionBoundaries(): void {
  ssmMock.on(CreateDocumentCommand).resolves({ DocumentDescription: { DocumentVersion: '1' } });
  ssmMock.on(DeleteDocumentCommand).resolves({});
  ssmMock.on(StartAutomationExecutionCommand).resolves({ AutomationExecutionId: 'execution-1' });
  ssmMock.on(GetAutomationExecutionCommand).resolves({
    AutomationExecution: {
      AutomationExecutionId: 'execution-1',
      AutomationExecutionStatus: 'Success',
      StepExecutions: [],
    },
  });
  ssmMock.on(DescribeDocumentCommand).resolves({
    Document: { Name: 'ASR-Custom-SC_2.0.0_S3.9', Status: 'Active', DocumentVersion: '1', DocumentFormat: 'YAML' },
  });
  ssmMock.on(GetDocumentCommand).resolves({ Content: VALID_YAML, DocumentFormat: 'YAML', DocumentVersion: '1' });
  ssmMock.on(ListDocumentsCommand).resolves({ DocumentIdentifiers: [] });
  iamMock.on(GetRoleCommand).resolves({
    Role: {
      Path: '/',
      RoleName: 'SO0111-EnableS3Logging-test',
      RoleId: 'AROAEXAMPLE',
      Arn: `arn:aws:iam::${ACCOUNT_ID}:role/SO0111-EnableS3Logging-test`,
      CreateDate: new Date('2026-01-01T00:00:00.000Z'),
    },
  });
  securityHubMock.on(GetFindingHistoryCommand).resolves({ Records: [] });
  securityHubMock.on(GetFindingsCommand).resolves({ Findings: [] });
}

beforeAll(async () => {
  // One JWKS response serves the whole suite: the pool's signing key does not change, so the
  // verifier fetches it once and caches it. The cache is cleared first so module state cannot
  // leak in from another suite.
  resetTokenVerifierCache();
  stubCognitoJwks();
  await DynamoDBTestSetup.createUserAccountMappingTable(dispatchUserAccountMappingTableName);
  // The history and custom-runbook tables the direct executors read. Empty real tables, so
  // "no history" and "no custom coverage" are the tables' answer rather than a stub's.
  await DynamoDBTestSetup.createRemediationHistoryTable(dispatchRemediationHistoryTableName);
  await DynamoDBTestSetup.createCustomRunbookTable(dispatchCustomRunbookTableName);
  userAuthorizationRepository = new UserAccountMappingRepository(
    'test-principal',
    dispatchUserAccountMappingTableName,
    DynamoDBTestSetup.getDocClient(),
  );
});

beforeEach(async () => {
  cognitoMock.reset();
  lambdaMock.reset();
  ssmMock.reset();
  iamMock.reset();
  securityHubMock.reset();
  resetMcpServerEnvironmentCache();
  stubApiLambda();
  stubDirectExecutionBoundaries();
  // No grant record unless a test seeds one, so an ungranted caller is genuinely ungranted.
  await DynamoDBTestSetup.clearTable(dispatchUserAccountMappingTableName, 'userAccountMapping');
});

afterAll(() => {
  cognitoMock.restore();
  lambdaMock.restore();
  ssmMock.restore();
  iamMock.restore();
  securityHubMock.restore();
});

describe('advertised tool catalog', () => {
  it('has an entry-point fixture for every advertised tool', () => {
    // Guards the suite against silently going stale: advertising a tool without a
    // fixture would leave it with no entry-point coverage at all, which is the
    // condition this suite exists to end.
    expect(Object.keys(TOOL_FIXTURES).sort()).toEqual([...ADVERTISED_TOOL_NAMES].sort());
  });

  it('fixtures every advertised tool as either proxied or direct, never both', () => {
    for (const [toolName, fixture] of Object.entries(TOOL_FIXTURES)) {
      expect(Boolean(fixture.proxy) !== Boolean(fixture.direct)).toBe(true);
      expect(toolName).toBe(toolName.toLowerCase());
    }
  });
});

describe('proxied tool dispatch through the handler', () => {
  const proxiedFixtures = Object.entries(TOOL_FIXTURES).filter(([, fixture]) => fixture.proxy);

  it.each(proxiedFixtures)('routes %s to its declared ASR API path and method', async (toolName, fixture) => {
    // GIVEN an Admin caller and valid arguments for the tool
    const event = createAgentCoreEvent({ groups: ['AdminGroup'], clientId }, fixture.args);

    // WHEN the gateway invokes the Lambda for that tool
    const response = await handler(event, createAgentCoreContext(toolName));

    // THEN the API Lambda is asked for exactly the declared route
    expect(response.statusCode).toBe(200);
    const forwarded = forwardedApiEvent();
    expect(forwarded.path).toBe(fixture.proxy?.path);
    expect(forwarded.httpMethod).toBe(fixture.proxy?.method);
  });

  it.each(proxiedFixtures.filter(([, fixture]) => fixture.pathParam))(
    'substitutes the %s path parameter into the URL and drops it from the body',
    async (toolName, fixture) => {
      // GIVEN
      const event = createAgentCoreEvent({ groups: ['AdminGroup'], clientId }, fixture.args);

      // WHEN
      await handler(event, createAgentCoreContext(toolName));

      // THEN the id identifies the resource in the path only. A body that still
      // carries it means the API router matched the collection route instead.
      const forwarded = forwardedApiEvent();
      expect(forwarded.path).toContain(fixture.pathParam?.value);
      expect(forwarded.body).not.toHaveProperty(fixture.pathParam?.name as string);
    },
  );

  it('never forwards the interceptor-injected authorization header into the request body', async () => {
    // GIVEN a caller who also supplies the transport field explicitly
    const event = createAgentCoreEvent({ groups: ['AdminGroup'], clientId }, { finding_id: 'finding-1' });

    // WHEN
    await handler(event, createAgentCoreContext('execute_runbook'));

    // THEN the header stays in the transport envelope, never in the tool payload
    expect(forwardedApiEvent().body).not.toHaveProperty('__authorizationHeader');
  });
});

describe('direct tool dispatch through the handler', () => {
  const directFixtures = Object.entries(TOOL_FIXTURES).filter(([, fixture]) => fixture.direct);

  it.each(directFixtures)('executes %s in-process without invoking the ASR API', async (toolName, fixture) => {
    // GIVEN
    const event = createAgentCoreEvent({ groups: ['AdminGroup'], clientId }, fixture.args);

    // WHEN
    const response = await handler(event, createAgentCoreContext(toolName));

    // THEN the executor ran here: a 200 with no API Lambda invocation at all.
    // A tool that silently fell through to the proxy table would invoke it.
    expect(response.statusCode).toBe(200);
    expect(lambdaMock.commandCalls(InvokeCommand)).toHaveLength(0);
  });
});

const everyTool = Object.entries(TOOL_FIXTURES);
const operatorTools = everyTool.filter(([toolName]) => ACCOUNT_OPERATOR_TOOLS.includes(toolName));
const beyondOperatorTools = everyTool.filter(([toolName]) => !ACCOUNT_OPERATOR_TOOLS.includes(toolName));

describe('Account Operator granted every tool', () => {
  beforeEach(async () => {
    stubCognitoEmail();
    // The widest grant an administrator can give.
    await seedUserGrant(['*'], [ACCOUNT_ID]);
  });

  it.each(beyondOperatorTools)('refuses %s, which is outside the tier ceiling', async (toolName, fixture) => {
    // GIVEN an Account Operator whose grant is as wide as a grant can be
    const event = createAgentCoreEvent({ groups: ['AccountOperatorGroup'], clientId, username }, fixture.args);

    // WHEN
    const response = await handler(event, createAgentCoreContext(toolName));

    // THEN the tier ceiling holds: a grant narrows a ceiling, it never widens one.
    // The message must name the tier, not a missing grant, or the caller is sent
    // to an administrator for a grant that would change nothing.
    expect(response.statusCode).toBe(403);
    expect(JSON.parse(response.body).error).toMatch(/not permitted for the 'AccountOperator' access tier/);
    expect(lambdaMock.commandCalls(InvokeCommand)).toHaveLength(0);
  });

  it.each(operatorTools)('allows %s, which is inside the tier ceiling', async (toolName, fixture) => {
    // GIVEN
    const event = createAgentCoreEvent({ groups: ['AccountOperatorGroup'], clientId, username }, fixture.args);

    // WHEN
    const response = await handler(event, createAgentCoreContext(toolName));

    // THEN
    expect(response.statusCode).toBe(200);
  });
});

describe('Account Operator with no grant', () => {
  beforeEach(async () => {
    stubCognitoEmail();
    // No authorization record at all — the state of a user an administrator has
    // not granted anything to.
    await seedUserGrant(undefined);
  });

  it.each(operatorTools)('refuses %s until an administrator grants it', async (toolName, fixture) => {
    // GIVEN a caller inside the ceiling but with nothing granted
    const event = createAgentCoreEvent({ groups: ['AccountOperatorGroup'], clientId, username }, fixture.args);

    // WHEN
    const response = await handler(event, createAgentCoreContext(toolName));

    // THEN the refusal points at the grant, not the tier — the actionable fix
    expect(response.statusCode).toBe(403);
    expect(JSON.parse(response.body).error).toMatch(/is not granted to user/);
  });
});

describe('Admin', () => {
  it.each(everyTool)('allows %s with no grant record at all', async (toolName, fixture) => {
    // GIVEN no seeded grant: Admin must not depend on one
    const event = createAgentCoreEvent({ groups: ['AdminGroup'], clientId }, fixture.args);

    // WHEN
    const response = await handler(event, createAgentCoreContext(toolName));

    // THEN
    expect(response.statusCode).toBe(200);
    expect(cognitoMock.commandCalls(AdminGetUserCommand)).toHaveLength(0);
  });
});
