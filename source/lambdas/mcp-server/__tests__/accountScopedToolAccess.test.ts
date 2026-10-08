// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { AdminGetUserCommand, CognitoIdentityProviderClient } from '@aws-sdk/client-cognito-identity-provider';
import { InvokeCommand, LambdaClient } from '@aws-sdk/client-lambda';
import { GetFindingHistoryCommand, GetFindingsCommand, SecurityHubClient } from '@aws-sdk/client-securityhub';
import { ListDocumentsCommand, SSMClient } from '@aws-sdk/client-ssm';
import { mockClient } from 'aws-sdk-client-mock';
import { userPoolId } from '../../common/__tests__/envSetup';
import { DynamoDBTestSetup } from '../../common/__tests__/dynamodbSetup';
import { UserAccountMappingRepository } from '../../common/repositories/userAccountMappingRepository';
import {
  createAgentCoreContext,
  createAgentCoreEvent,
  createLambdaPayload,
  forwardedApiRequest,
  stubCognitoJwks,
  toolCallResult,
  type ToolCallResult,
} from './mcpAuthorizationTestFactories';

const MAPPING_TABLE = 'test-scoping-user-account-mapping';
const REMEDIATION_HISTORY_TABLE = 'test-scoping-remediation-history';
const CUSTOM_RUNBOOK_TABLE = 'test-scoping-custom-runbook';
const OWN_ACCOUNT = '111111111111';
const OTHER_ACCOUNT = '222222222222';

// The real verifyAccessToken runs here: tokens carry genuine RS256 signatures and only the
// Cognito JWKS endpoint is stubbed (see stubCognitoJwks). Mocking our own verifier would be
// the `jest.mock` on our own module that unit-testing.md rules out, and would leave the
// token-verification path these dispatch and authorization tests depend on unexercised.

process.env.API_FUNCTION_NAME = 'SO0111-ASR-APIs';
process.env.COGNITO_USER_POOL_ID = userPoolId;
process.env.MCP_GATEWAY_CLIENT_ID = 'gateway-client-1';
process.env.USER_ACCOUNT_MAPPING_TABLE_NAME = MAPPING_TABLE;
process.env.REMEDIATION_HISTORY_TABLE_NAME = REMEDIATION_HISTORY_TABLE;
process.env.CUSTOM_RUNBOOK_TABLE_NAME = CUSTOM_RUNBOOK_TABLE;

// Per-account scoping for the direct-execution tools.
//
// The direct tools bypass the REST API, so the per-account rules `createAccessRules`
// applies there never run for them — the handler's `authorizedAccountIds` is the only
// thing standing between an Account Operator and organization-wide finding data. That
// makes these the security-relevant cases: a scope that silently widens, or a
// transient table failure that falls through to "no restriction", both leak findings
// from accounts the caller was never granted.
//
// Asserted at the Security Hub boundary rather than on the tool's output, because a
// server-side filter is the claim being made: findings from an unauthorized account
// must never be fetched into this Lambda in the first place.

// The DynamoDB client is deliberately NOT mocked: the grant and account-assignment reads
// this suite is about run through the real UserAccountMappingRepository against DynamoDB
// Local (unit-testing.md), so the key schema and the lowercase-key fallback the handler
// depends on are genuinely exercised rather than re-implemented in a stub.
const cognitoMock = mockClient(CognitoIdentityProviderClient);
const lambdaMock = mockClient(LambdaClient);
const ssmMock = mockClient(SSMClient);
const securityHubMock = mockClient(SecurityHubClient);

import { handler } from '../mcpServerHandler';
import { resetMcpServerEnvironmentCache } from '../mcpServerEnvironment';
import { resetTokenVerifierCache } from '../tokenVerifier';

let userAuthorizationRepository: UserAccountMappingRepository;

const clientId = 'gateway-client-1';
const operatorUsername = 'scoped.operator';
const operatorEmail = 'scoped.operator@example.com';
const delegatedAdminUsername = 'scoped.delegated.admin';
const delegatedAdminEmail = 'scoped.delegated.admin@example.com';

/** Account criteria the tool sent to Security Hub, or undefined for unrestricted. */
function requestedAccountFilters(): (string | undefined)[] {
  return securityHubMock
    .commandCalls(GetFindingsCommand)
    .flatMap((call) => call.args[0].input.Filters?.AwsAccountId?.map((criterion) => criterion.Value) ?? [undefined]);
}

function stubOperatorIdentity(): void {
  cognitoMock
    .on(AdminGetUserCommand, { UserPoolId: userPoolId, Username: operatorUsername })
    .resolves({ UserAttributes: [{ Name: 'email', Value: operatorEmail }] });
}

function stubDelegatedAdminIdentity(): void {
  cognitoMock
    .on(AdminGetUserCommand, { UserPoolId: userPoolId, Username: delegatedAdminUsername })
    .resolves({ UserAttributes: [{ Name: 'email', Value: delegatedAdminEmail }] });
}

/** Seed the operator's authorization record: their MCP grant and their accounts. */
async function seedOperatorMapping(accountIds: readonly string[]): Promise<void> {
  await userAuthorizationRepository.create({
    userId: operatorEmail,
    accountIds: [...accountIds],
    allowedMcpTools: ['*'],
  });
}

/**
 * Seed a Delegated Admin's MCP grant. The record carries an empty `accountIds` on purpose:
 * the tier is unrestricted by account, so an assignment list would be ignored — and leaving
 * it empty proves the unrestricted scope comes from the tier rather than from a conveniently
 * broad mapping.
 */
async function seedDelegatedAdminGrant(allowedMcpTools: readonly string[]): Promise<void> {
  await userAuthorizationRepository.create({
    userId: delegatedAdminEmail,
    accountIds: [],
    allowedMcpTools: [...allowedMcpTools],
  });
}

async function callTool(
  toolName: string,
  args: Record<string, unknown>,
  caller: 'operator' | 'admin' | 'delegatedAdmin',
): Promise<ToolCallResult> {
  const eventForCaller = {
    admin: () => createAgentCoreEvent({ groups: ['AdminGroup'], clientId }, args),
    delegatedAdmin: () =>
      createAgentCoreEvent({ groups: ['DelegatedAdminGroup'], clientId, username: delegatedAdminUsername }, args),
    operator: () =>
      createAgentCoreEvent({ groups: ['AccountOperatorGroup'], clientId, username: operatorUsername }, args),
  };
  return toolCallResult(await handler(eventForCaller[caller](), createAgentCoreContext(toolName)));
}

const findingIdIn = (accountId: string): string =>
  `arn:aws:securityhub:us-east-1:${accountId}:security-control/S3.9/finding/11111111-1111-1111-1111-111111111111`;

beforeAll(async () => {
  // One JWKS response serves the whole suite: the pool's signing key does not change, so the
  // verifier fetches it once and caches it. The cache is cleared first so module state cannot
  // leak in from another suite.
  resetTokenVerifierCache();
  stubCognitoJwks();
  await DynamoDBTestSetup.createUserAccountMappingTable(MAPPING_TABLE);
  // The direct tools read these two as well — an empty real table is what makes "no
  // custom coverage" and "no remediation history" the genuine state rather than a stub's
  // answer.
  await DynamoDBTestSetup.createCustomRunbookTable(CUSTOM_RUNBOOK_TABLE);
  await DynamoDBTestSetup.createRemediationHistoryTable(REMEDIATION_HISTORY_TABLE);
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
  securityHubMock.reset();
  resetMcpServerEnvironmentCache();

  lambdaMock.on(InvokeCommand).resolves({
    Payload: createLambdaPayload(JSON.stringify({ statusCode: 200, body: JSON.stringify({ ok: true }) })),
  });
  ssmMock.on(ListDocumentsCommand).resolves({ DocumentIdentifiers: [] });
  securityHubMock.on(GetFindingsCommand).resolves({ Findings: [] });
  securityHubMock.on(GetFindingHistoryCommand).resolves({ Records: [] });
  // Each test starts with no authorization records, so a test that seeds none is genuinely
  // exercising the "no mapping" path.
  await DynamoDBTestSetup.clearTable(MAPPING_TABLE, 'userAccountMapping');
  stubOperatorIdentity();
  stubDelegatedAdminIdentity();
});

afterAll(() => {
  cognitoMock.restore();
  lambdaMock.restore();
  ssmMock.restore();
  securityHubMock.restore();
});

describe('account scoping for direct-execution tools', () => {
  it('restricts an Account Operator’s finding search to their mapped accounts', async () => {
    // GIVEN an operator mapped to one account
    await seedOperatorMapping([OWN_ACCOUNT]);

    // WHEN they list findings without a runbook
    const response = await callTool('list_findings_without_runbook', {}, 'operator');

    // THEN the account restriction is applied server-side, in the query itself
    expect(response.status).toBe(200);
    expect(requestedAccountFilters()).toEqual([OWN_ACCOUNT]);
  });

  it('returns nothing for an Account Operator mapped to no accounts, rather than everything', async () => {
    // GIVEN an operator with an empty account list — the state of an unmapped user
    await seedOperatorMapping([]);

    // WHEN
    const response = await callTool('list_findings_without_runbook', {}, 'operator');

    // THEN no findings request is made at all. Security Hub treats an absent account
    // criterion as unrestricted, so sending an empty criterion — or skipping the
    // filter — would turn "authorized for zero accounts" into "authorized for all".
    expect(response.status).toBe(200);
    expect(response.body.count).toBe(0);
    expect(securityHubMock.commandCalls(GetFindingsCommand)).toHaveLength(0);
  });

  it('does not restrict an Admin, who may see every account', async () => {
    // GIVEN no mapping record for the caller at all

    // WHEN an Admin runs the same tool
    const response = await callTool('list_findings_without_runbook', {}, 'admin');

    // THEN the query carries no account criterion
    expect(response.status).toBe(200);
    expect(requestedAccountFilters()).toEqual([undefined]);
  });

  it('does not restrict a Delegated Admin, whose grant is checked but whose accounts are not', async () => {
    // GIVEN a Delegated Admin granted this specific tool. Unlike an Admin, this tier
    // goes through the per-user grant read — so this is the one path where the grant
    // gate and direct dispatch both run for the same call.
    await seedDelegatedAdminGrant(['list_findings_without_runbook']);

    // WHEN
    const response = await callTool('list_findings_without_runbook', {}, 'delegatedAdmin');

    // THEN the executor runs with no account criterion. The scope decision keys off the
    // tier, so narrowing it to Admin only would silently reduce a Delegated Admin to
    // "no accounts" — a denial dressed as an empty result.
    expect(response.status).toBe(200);
    expect(requestedAccountFilters()).toEqual([undefined]);
    // The grant path really ran, rather than the call being waved through as Admin.
    expect(cognitoMock.commandCalls(AdminGetUserCommand)).toHaveLength(1);
  });

  it('denies a Delegated Admin a direct tool their grant omits, before Security Hub is queried', async () => {
    // GIVEN a Delegated Admin whose grant covers a different tool
    await seedDelegatedAdminGrant(['list_runbooks']);

    // WHEN they call a direct-execution tool
    const response = await callTool('list_findings_without_runbook', {}, 'delegatedAdmin');

    // THEN it is refused before dispatch. The grant gate is shared with the proxied
    // tools, but only the direct tools reach AWS under this Lambda's own org-wide
    // Security Hub permissions, so an ungranted call must not get that far.
    expect(response.status).toBe(403);
    expect(securityHubMock.commandCalls(GetFindingsCommand)).toHaveLength(0);
  });

  it('denies retryably when the account mapping cannot be read, instead of running unscoped', async () => {
    // GIVEN the mapping table is unreadable. Removing the table is how a read failure is
    // produced against DynamoDB Local; the grant read and the account read share one
    // GetItem on one record, so a failure isolated to the account read is not a state the
    // real repository can be in — only a stub could stage it.
    await seedOperatorMapping([OWN_ACCOUNT]);
    await DynamoDBTestSetup.deleteTable(MAPPING_TABLE);

    // WHEN
    const response = await callTool('list_findings_without_runbook', {}, 'operator');

    // Restore the table for the tests that follow, before any assertion can fail out.
    await DynamoDBTestSetup.createUserAccountMappingTable(MAPPING_TABLE);

    // THEN the call is refused as retryable and the executor never ran. Falling back
    // to "unrestricted" here would widen scope on a blip; falling back to an empty
    // list would turn a blip into a hard authorization failure.
    expect(response.status).toBe(503);
    expect(response.body.error).toMatch(/retry the request/i);
    expect(securityHubMock.commandCalls(GetFindingsCommand)).toHaveLength(0);
  });

  it('refuses finding history for an account the Account Operator is not mapped to', async () => {
    // GIVEN an operator mapped to one account
    await seedOperatorMapping([OWN_ACCOUNT]);

    // WHEN they ask for the history of a finding in a different account
    const response = await callTool('get_finding_history', { finding_id: findingIdIn(OTHER_ACCOUNT) }, 'operator');

    // THEN it is refused, and Security Hub is never asked. This tool runs under the
    // MCP Lambda's own organization-wide Security Hub permissions, so without this
    // check the lowest tier could read any account's history.
    expect(response.status).toBe(403);
    expect(securityHubMock.commandCalls(GetFindingHistoryCommand)).toHaveLength(0);
  });

  it('allows finding history for an account the Account Operator is mapped to', async () => {
    // GIVEN
    await seedOperatorMapping([OWN_ACCOUNT]);

    // WHEN
    const response = await callTool('get_finding_history', { finding_id: findingIdIn(OWN_ACCOUNT) }, 'operator');

    // THEN
    expect(response.status).toBe(200);
    expect(securityHubMock.commandCalls(GetFindingHistoryCommand)).toHaveLength(1);
  });

  it('refuses finding history for an id that encodes no account', async () => {
    // GIVEN an operator and a finding id that is not an ARN (ADR 0010: not every
    // finding id is one)
    await seedOperatorMapping([OWN_ACCOUNT]);

    // WHEN
    const response = await callTool('get_finding_history', { finding_id: 'finding-1' }, 'operator');

    // THEN it fails closed: an id whose account cannot be derived cannot be proven to
    // belong to the caller, and allowing it would make an unparseable id the way
    // around the restriction.
    expect(response.status).toBe(403);
    expect(securityHubMock.commandCalls(GetFindingHistoryCommand)).toHaveLength(0);
  });
});

describe('privileged finding actions through the proxy', () => {
  /** The action type the ASR API was asked to perform. */
  const forwardedAction = (): { path: string; actionType: unknown } => {
    const calls = lambdaMock.commandCalls(InvokeCommand);
    expect(calls).toHaveLength(1);
    const { path, body } = forwardedApiRequest(calls[0].args[0].input);
    return { path, actionType: body.actionType };
  };

  it('forwards a Rollback request unchanged for an Admin', async () => {
    // GIVEN an Admin rolling a remediation back — the "it made things worse, undo it"
    // step of the lifecycle
    const response = await callTool(
      'execute_finding_action',
      { actionType: 'Rollback', findingIds: [findingIdIn(OWN_ACCOUNT)] },
      'admin',
    );

    // THEN the action type reaches the API verbatim. The MCP layer must not downgrade
    // or rewrite it — Rollback and Remediate are different operations on a resource.
    expect(response.status).toBe(200);
    expect(forwardedAction()).toEqual({ path: '/findings/action', actionType: 'Rollback' });
  });

  it('forwards Rollback for a granted Account Operator, leaving the action-type decision to the API', async () => {
    // GIVEN an Account Operator granted execute_finding_action, which is inside their
    // tier ceiling
    await seedOperatorMapping([OWN_ACCOUNT]);

    // WHEN they request a Rollback
    const response = await callTool(
      'execute_finding_action',
      { actionType: 'Rollback', findingIds: [findingIdIn(OWN_ACCOUNT)] },
      'operator',
    );

    // THEN the MCP tier check does not stop them: grants are per TOOL, not per action
    // type, so `Rollback` is reachable by any caller granted this tool. Per ADR 0011
    // rollback is restricted to administrator roles, and this asserts where that
    // restriction has to live — the ASR API, which sees the action type — rather than
    // assuming the MCP tier covers it.
    expect(response.status).toBe(200);
    expect(forwardedAction()).toEqual({ path: '/findings/action', actionType: 'Rollback' });
  });
});
