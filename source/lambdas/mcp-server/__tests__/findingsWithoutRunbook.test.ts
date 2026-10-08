// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { mockClient } from 'aws-sdk-client-mock';
import { SecurityHubClient, GetFindingsCommand, type AwsSecurityFinding } from '@aws-sdk/client-securityhub';
import { SSMClient, ListDocumentsCommand, GetParametersByPathCommand } from '@aws-sdk/client-ssm';
import { DynamoDBDocumentClient, QueryCommand } from '@aws-sdk/lib-dynamodb';
import { listFindingsWithoutRunbook } from '../backends/common/findingsWithoutRunbook';
import type { ExecutionContext } from '../backends/common/../types';

const securityHubMock = mockClient(SecurityHubClient);
const ssmMock = mockClient(SSMClient);
const dynamoDBMock = mockClient(DynamoDBDocumentClient);

const customRunbookTableName = 'test-custom-runbook-table';

/** A Custom Runbook table record, only the fields the coverage check reads. */
function runbookRecord(
  controlId: string,
  status: 'DRAFT' | 'DEPLOYED',
  memberStatuses: readonly ('DEPLOYED' | 'PENDING' | 'FAILED')[],
): Record<string, unknown> {
  return {
    runbookId: `rb-${controlId}`,
    version: 1,
    controlId,
    status,
    deployedAccounts: Object.fromEntries(
      memberStatuses.map((memberStatus, index) => [`10000000000${index}`, { status: memberStatus }]),
    ),
  };
}

function context(overrides: Partial<ExecutionContext> = {}): ExecutionContext {
  return { region: 'us-east-1', requestId: 'test-request', ...overrides };
}

/**
 * A minimal but correctly-typed Security Hub finding for these tests. Only the
 * two fields the tool reads (Compliance.SecurityControlId, Title) are set; the
 * single `as` narrows the partial to AwsSecurityFinding in one place instead of
 * an `as never` at every call site (ADR 0001 / naming.md — no scattered casts).
 */
function finding(controlId: string, title = controlId): AwsSecurityFinding {
  return { Compliance: { SecurityControlId: controlId }, Title: title } as AwsSecurityFinding;
}

beforeEach(() => {
  securityHubMock.reset();
  ssmMock.reset();
  dynamoDBMock.reset();
  // No control remaps unless a test says otherwise. The tool reads these to find controls
  // ASR remediates through another control's runbook.
  ssmMock.on(GetParametersByPathCommand).resolves({ Parameters: [] });
});

describe('listFindingsWithoutRunbook — basic cross-reference', () => {
  test('a control with findings and no deployed runbook is reported as a gap', async () => {
    securityHubMock.on(GetFindingsCommand).resolves({
      Findings: [finding('S3.1', 'S3 bucket should have logging')],
    });
    ssmMock.on(ListDocumentsCommand).resolves({ DocumentIdentifiers: [] });

    const result = await listFindingsWithoutRunbook({}, context());

    expect(result.controls).toEqual([{ controlId: 'S3.1', title: 'S3 bucket should have logging', resourceCount: 1 }]);
    expect(result.truncated).toBe(false);
  });

  test('a control with a deployed runbook is not reported as a gap', async () => {
    securityHubMock.on(GetFindingsCommand).resolves({
      Findings: [finding('S3.1', 'S3 bucket should have logging')],
    });
    ssmMock.on(ListDocumentsCommand).resolves({ DocumentIdentifiers: [{ Name: 'ASR-SC_2.0.0_S3.1' }] });

    const result = await listFindingsWithoutRunbook({}, context());

    expect(result.controls).toEqual([]);
  });

  // ListDocuments is filtered only to self-owned Automation documents, so a
  // customer's own document can end in _Something.N. Treating that as coverage
  // would hide a genuine gap — the failure this tool exists to report.
  test('an unrelated customer document does not count as runbook coverage', async () => {
    securityHubMock.on(GetFindingsCommand).resolves({
      Findings: [finding('S3.1', 'S3 bucket should have logging')],
    });
    ssmMock.on(ListDocumentsCommand).resolves({
      DocumentIdentifiers: [{ Name: 'MyTeam_Nightly_Backup_S3.1' }, { Name: 'internal_deploy_v1.2' }],
    });

    const result = await listFindingsWithoutRunbook({}, context());

    expect(result.controls).toEqual([{ controlId: 'S3.1', title: 'S3 bucket should have logging', resourceCount: 1 }]);
  });

  // ASR ships controls whose IDs are not numeric, so a digits-only suffix match
  // reported them as gaps even with a runbook deployed.
  test.each(['Inspector.InstanceVulnerability', 'GuardDuty.IAMUser', 'Macie.SensitiveDataS3Object'])(
    'recognizes coverage for the non-numeric control ID %s',
    async (controlId) => {
      securityHubMock.on(GetFindingsCommand).resolves({
        Findings: [finding(controlId, 'x')],
      });
      ssmMock
        .on(ListDocumentsCommand)
        .resolves({ DocumentIdentifiers: [{ Name: `ASR-Custom-SC_2.0.0_${controlId}` }] });
      // A confirmed deployment so the claim counts as coverage; this test verifies the
      // non-numeric control-ID pattern is recognized, independent of the unverified-table policy.
      dynamoDBMock.on(QueryCommand).resolves({ Items: [runbookRecord(controlId, 'DEPLOYED', ['DEPLOYED'])] });

      const result = await listFindingsWithoutRunbook({}, context({ customRunbookTableName }));

      expect(result.controls).toEqual([]);
    },
  );
});

describe('listFindingsWithoutRunbook — pagination ceiling', () => {
  test('stops after MAX_PAGES and reports truncated=true rather than looping forever', async () => {
    // Every page returns a NextToken, so an unbounded loop would never terminate.
    securityHubMock.on(GetFindingsCommand).resolves({
      Findings: [finding('S3.1', 'x')],
      NextToken: 'always-more',
    });
    ssmMock.on(ListDocumentsCommand).resolves({ DocumentIdentifiers: [] });

    const result = await listFindingsWithoutRunbook({}, context());

    expect(result.truncated).toBe(true);
    // Bounded: the test completing at all (within jest's default timeout)
    // proves the ceiling was applied; also assert the exact call count.
    expect(securityHubMock.commandCalls(GetFindingsCommand)).toHaveLength(50);
  });

  test('a normally-paginated, terminating query is not marked truncated', async () => {
    securityHubMock
      .on(GetFindingsCommand)
      .resolvesOnce({
        Findings: [finding('S3.1', 'x')],
        NextToken: 'page-2',
      })
      .resolves({ Findings: [finding('S3.2', 'y')] });
    ssmMock.on(ListDocumentsCommand).resolves({ DocumentIdentifiers: [] });

    const result = await listFindingsWithoutRunbook({}, context());

    expect(result.truncated).toBe(false);
    expect(result.controls).toHaveLength(2);
  });

  test('a truncated ListDocuments page also sets truncated=true', async () => {
    securityHubMock.on(GetFindingsCommand).resolves({ Findings: [] });
    ssmMock.on(ListDocumentsCommand).resolves({ DocumentIdentifiers: [], NextToken: 'always-more' });

    const result = await listFindingsWithoutRunbook({}, context());

    expect(result.truncated).toBe(true);
  });

  test('a gap reported while the runbook scan was truncated is flagged as unconfirmed, not a definite gap', async () => {
    // The document scan never reaches a page that could contain S3.1's runbook, so this
    // "gap" might not be one — the top-level truncated flag alone does not tell the caller
    // WHICH entries are affected; every entry must carry the caveat since the scan gives
    // no way to know which control's runbook would have been on the unread page.
    securityHubMock.on(GetFindingsCommand).resolves({
      Findings: [finding('S3.1', 'x')],
    });
    ssmMock.on(ListDocumentsCommand).resolves({ DocumentIdentifiers: [], NextToken: 'always-more' });

    const result = await listFindingsWithoutRunbook({}, context());

    expect(result.truncated).toBe(true);
    expect(result.controls).toEqual([
      { controlId: 'S3.1', title: 'x', resourceCount: 1, runbookCoverageUnconfirmed: true },
    ]);
  });

  test('a gap reported when only the findings scan was truncated (not the runbook scan) is not flagged', async () => {
    securityHubMock.on(GetFindingsCommand).resolves({
      Findings: [finding('S3.1', 'x')],
      NextToken: 'always-more',
    });
    ssmMock.on(ListDocumentsCommand).resolves({ DocumentIdentifiers: [] });

    const result = await listFindingsWithoutRunbook({}, context());

    expect(result.truncated).toBe(true);
    expect(result.controls[0].runbookCoverageUnconfirmed).toBeUndefined();
  });
});

// This tool runs directly in the MCP Lambda under its own organization-wide
// securityhub:GetFindings, with no API hop applying the per-account rules the REST API
// enforces. Without the filter below, an Account Operator — the lowest tier — saw
// findings aggregated across every account in the organization.
describe('listFindingsWithoutRunbook — per-account scoping', () => {
  beforeEach(() => {
    securityHubMock.reset();
    ssmMock.reset();
    securityHubMock.on(GetFindingsCommand).resolves({ Findings: [] });
    ssmMock.on(ListDocumentsCommand).resolves({ DocumentIdentifiers: [] });
  });

  it('restricts the Security Hub query to the accounts the caller may see', async () => {
    await listFindingsWithoutRunbook({}, context({ authorizedAccountIds: ['111111111111', '222222222222'] }));

    const filters = securityHubMock.commandCalls(GetFindingsCommand)[0].args[0].input.Filters;
    // Applied server-side, so an unauthorized account's findings never reach this
    // Lambda — and the page budget is not spent on records that would be discarded.
    expect(filters?.AwsAccountId).toEqual([
      { Value: '111111111111', Comparison: 'EQUALS' },
      { Value: '222222222222', Comparison: 'EQUALS' },
    ]);
  });

  it('sends no account filter for an unrestricted caller', async () => {
    // undefined means Admin tier or a machine principal, both of which see every
    // account through the REST API too.
    await listFindingsWithoutRunbook({}, context({ authorizedAccountIds: undefined }));

    const filters = securityHubMock.commandCalls(GetFindingsCommand)[0].args[0].input.Filters;
    expect(filters?.AwsAccountId).toBeUndefined();
  });

  it('returns nothing for a caller mapped to no accounts, rather than everything', async () => {
    const result = await listFindingsWithoutRunbook({}, context({ authorizedAccountIds: [] }));

    expect(result).toEqual({
      count: 0,
      controls: [],
      truncated: false,
      runbookCoverageScope: 'server-account-only',
      runbookCoverageCaveat: expect.stringContaining('only in the account this MCP server runs in'),
    });
    expect(securityHubMock.commandCalls(GetFindingsCommand)).toHaveLength(0);
    expect(ssmMock.commandCalls(ListDocumentsCommand)).toHaveLength(0);
  });

  // The absence of a gap is not authoritative per member: runbook coverage is
  // checked only in the server's own account, so the result must say so rather
  // than let the caller read "no gap" as "covered everywhere".
  it('always carries the server-account-only runbook-coverage caveat', async () => {
    securityHubMock.on(GetFindingsCommand).resolves({
      Findings: [finding('S3.1', 'x')],
    });
    ssmMock.on(ListDocumentsCommand).resolves({ DocumentIdentifiers: [{ Name: 'ASR-SC_2.0.0_S3.1' }] });

    const result = await listFindingsWithoutRunbook({}, context());

    // Even when this specific control is covered in the server account, the
    // result cannot claim it is covered per-member.
    expect(result.controls).toEqual([]);
    expect(result.runbookCoverageScope).toBe('server-account-only');
    expect(result.runbookCoverageCaveat).toMatch(/deployed per member account/);
    expect(result.runbookCoverageCaveat).toMatch(/absence of a gap is not authoritative per-member/);
  });
  test('splits more than 20 authorized accounts across requests, since Security Hub caps a filter at 20 values', async () => {
    // 45 accounts must become 3 requests (20 + 20 + 5). Sending all 45 in one
    // AwsAccountId filter is rejected outright by Security Hub, so an operator
    // authorized for a large estate got an error instead of their findings.
    const accountIds = Array.from({ length: 45 }, (_, i) => String(100000000000 + i));
    securityHubMock.on(GetFindingsCommand).resolves({ Findings: [] });
    ssmMock.on(ListDocumentsCommand).resolves({ DocumentIdentifiers: [] });

    await listFindingsWithoutRunbook({}, context({ authorizedAccountIds: accountIds }));

    const calls = securityHubMock.commandCalls(GetFindingsCommand);
    expect(calls).toHaveLength(3);
    const batches = calls.map((call) => call.args[0].input.Filters?.AwsAccountId ?? []);
    expect(batches.map((b) => b.length)).toEqual([20, 20, 5]);
    // Every authorized account is queried exactly once — no drops, no duplicates.
    const queried = batches.flat().map((criterion) => criterion.Value);
    expect(queried).toHaveLength(45);
    expect(new Set(queried)).toEqual(new Set(accountIds));
  });

  test('merges per-control counts across account chunks', async () => {
    const accountIds = Array.from({ length: 25 }, (_, i) => String(200000000000 + i));
    ssmMock.on(ListDocumentsCommand).resolves({ DocumentIdentifiers: [] });
    // One S3.1 finding in each of the two chunks must total 2, not overwrite to 1.
    securityHubMock.on(GetFindingsCommand).resolves({ Findings: [finding('S3.1', 'x')] });

    const result = await listFindingsWithoutRunbook({}, context({ authorizedAccountIds: accountIds }));

    expect(result.controls).toEqual([{ controlId: 'S3.1', title: 'x', resourceCount: 2 }]);
  });

  test('an unrestricted caller sends a single request with no account filter', async () => {
    securityHubMock.on(GetFindingsCommand).resolves({ Findings: [] });
    ssmMock.on(ListDocumentsCommand).resolves({ DocumentIdentifiers: [] });

    await listFindingsWithoutRunbook({}, context({ authorizedAccountIds: undefined }));

    const calls = securityHubMock.commandCalls(GetFindingsCommand);
    expect(calls).toHaveLength(1);
    expect(calls[0].args[0].input.Filters?.AwsAccountId).toBeUndefined();
  });

  test('a caller authorized for no accounts queries nothing', async () => {
    securityHubMock.on(GetFindingsCommand).resolves({ Findings: [finding('S3.1', 'x')] });
    ssmMock.on(ListDocumentsCommand).resolves({ DocumentIdentifiers: [] });

    const result = await listFindingsWithoutRunbook({}, context({ authorizedAccountIds: [] }));

    expect(securityHubMock.commandCalls(GetFindingsCommand)).toHaveLength(0);
    expect(result.controls).toEqual([]);
  });
});

describe('listFindingsWithoutRunbook — custom runbook deployment confirmation', () => {
  const ORPHAN_DOCUMENT = 'ASR-Custom-SC_2.0.0_Inspector.InstanceVulnerability';
  const CONTROL_ID = 'Inspector.InstanceVulnerability';

  function findingForControl(): void {
    securityHubMock.on(GetFindingsCommand).resolves({ Findings: [finding(CONTROL_ID, 'vuln')] });
    ssmMock.on(ListDocumentsCommand).resolves({ DocumentIdentifiers: [{ Name: ORPHAN_DOCUMENT }] });
  }

  test('still reports a gap when the admin document exists but the record is DRAFT', async () => {
    // The deploy creates the admin-account document BEFORE any member deployment and
    // leaves it behind when every member fails, so document presence alone marked a
    // control covered that nothing anywhere can remediate.
    findingForControl();
    dynamoDBMock.on(QueryCommand).resolves({ Items: [runbookRecord(CONTROL_ID, 'DRAFT', ['FAILED'])] });

    const result = await listFindingsWithoutRunbook({}, context({ customRunbookTableName }));

    expect(result.controls.map((c) => c.controlId)).toEqual([CONTROL_ID]);
  });

  test('still reports a gap when the record is DEPLOYED but no member account holds it', async () => {
    findingForControl();
    dynamoDBMock.on(QueryCommand).resolves({
      Items: [runbookRecord(CONTROL_ID, 'DEPLOYED', ['FAILED', 'PENDING'])],
    });

    const result = await listFindingsWithoutRunbook({}, context({ customRunbookTableName }));

    expect(result.controls.map((c) => c.controlId)).toEqual([CONTROL_ID]);
  });

  test('treats the control as covered once a member account reports DEPLOYED', async () => {
    findingForControl();
    dynamoDBMock.on(QueryCommand).resolves({
      Items: [runbookRecord(CONTROL_ID, 'DEPLOYED', ['FAILED', 'DEPLOYED'])],
    });

    const result = await listFindingsWithoutRunbook({}, context({ customRunbookTableName }));

    expect(result.controls).toEqual([]);
  });

  test('lists the control as an unconfirmed gap when deployment state cannot be read', async () => {
    // Querying by control ID uses a GSI whose grant is provisioned separately, so an
    // AccessDenied here must not silently hide the control on an unverified custom-document
    // claim: the control stays a gap, marked unconfirmed, plus the global caveat.
    findingForControl();
    dynamoDBMock.on(QueryCommand).rejects(Object.assign(new Error('denied'), { name: 'AccessDeniedException' }));

    const result = await listFindingsWithoutRunbook({}, context({ customRunbookTableName }));

    expect(result.controls.map((c) => c.controlId)).toEqual([CONTROL_ID]);
    expect(result.controls[0].runbookCoverageUnconfirmed).toBe(true);
    expect(result.runbookCoverageCaveat).toMatch(/could not be verified/);
  });

  test('lists the control as an unconfirmed gap when no custom runbook table is configured', async () => {
    findingForControl();

    const result = await listFindingsWithoutRunbook({}, context({ customRunbookTableName: undefined }));

    expect(result.controls.map((c) => c.controlId)).toEqual([CONTROL_ID]);
    expect(result.controls[0].runbookCoverageUnconfirmed).toBe(true);
    expect(result.runbookCoverageCaveat).toMatch(/could not be verified/);
  });

  test('never counts a transient test document as coverage', async () => {
    // An explicitly-named test document can match the control-ID pattern
    // (`ASR-Custom-Test_S3.9` does), and these documents are deleted after the run,
    // so they must never hide a control.
    securityHubMock.on(GetFindingsCommand).resolves({ Findings: [finding('S3.9', 'bucket')] });
    ssmMock.on(ListDocumentsCommand).resolves({
      DocumentIdentifiers: [{ Name: 'ASR-Custom-TestRunbook-S3.9-abc123' }, { Name: 'ASR-Custom-Test_S3.9' }],
    });

    const result = await listFindingsWithoutRunbook({}, context({ customRunbookTableName }));

    expect(result.controls.map((c) => c.controlId)).toEqual(['S3.9']);
    // No table read is needed: the documents were rejected by name before any claim existed.
    expect(dynamoDBMock.commandCalls(QueryCommand)).toHaveLength(0);
  });

  test('a built-in wrapper document needs no table confirmation', async () => {
    securityHubMock.on(GetFindingsCommand).resolves({ Findings: [finding('S3.9', 'bucket')] });
    ssmMock.on(ListDocumentsCommand).resolves({ DocumentIdentifiers: [{ Name: 'ASR-SC_2.0.0_S3.9' }] });

    const result = await listFindingsWithoutRunbook({}, context({ customRunbookTableName }));

    expect(result.controls).toEqual([]);
    expect(dynamoDBMock.commandCalls(QueryCommand)).toHaveLength(0);
    expect(result.runbookCoverageCaveat).not.toMatch(/could not be verified/);
  });
});

describe('listFindingsWithoutRunbook — controls remediated by another control’s runbook', () => {
  // ASR ships some remediations once and points several controls at them: S3.9 executes
  // CloudTrail.7's runbook (playbooks/SC/lib/sc_remediations.ts), so the deployed document
  // is ASR-SC_2.0.0_CloudTrail.7 and nothing names S3.9. Reporting S3.9 as a gap sent
  // customers to author a custom runbook that a built-in then always outranks in
  // resolution — verified against a live deployment, where exactly that happened.
  const remapParameter = (control: string, executes: string) => ({
    Name: `/Solutions/SO0111/SC/2.0.0/${control}/remap`,
    Value: executes,
  });

  test('a control whose remediation is another control’s deployed runbook is not a gap', async () => {
    securityHubMock.on(GetFindingsCommand).resolves({ Findings: [finding('S3.9', 'bucket logging')] });
    ssmMock.on(ListDocumentsCommand).resolves({ DocumentIdentifiers: [{ Name: 'ASR-SC_2.0.0_CloudTrail.7' }] });
    ssmMock.on(GetParametersByPathCommand).resolves({ Parameters: [remapParameter('S3.9', 'CloudTrail.7')] });

    const result = await listFindingsWithoutRunbook({}, context());

    expect(result.controls).toEqual([]);
    expect(result.count).toBe(0);
  });

  test('reads remaps only for standards that have a deployed document', async () => {
    securityHubMock.on(GetFindingsCommand).resolves({ Findings: [finding('S3.9', 'bucket logging')] });
    ssmMock.on(ListDocumentsCommand).resolves({ DocumentIdentifiers: [{ Name: 'ASR-SC_2.0.0_CloudTrail.7' }] });
    ssmMock.on(GetParametersByPathCommand).resolves({ Parameters: [remapParameter('S3.9', 'CloudTrail.7')] });

    await listFindingsWithoutRunbook({}, context());

    // Scoped to the standard actually deployed here rather than guessing standard names.
    const calls = ssmMock.commandCalls(GetParametersByPathCommand);
    expect(calls).toHaveLength(1);
    expect(calls[0].args[0].input.Path).toBe('/Solutions/SO0111/SC/2.0.0/');
    expect(calls[0].args[0].input.Recursive).toBe(true);
  });

  test('still reports a gap when the control it maps to has no deployed runbook', async () => {
    // The mapping alone is not coverage: if the target control's document is absent,
    // nothing remediates this control and the gap is real.
    securityHubMock.on(GetFindingsCommand).resolves({ Findings: [finding('S3.9', 'bucket logging')] });
    ssmMock.on(ListDocumentsCommand).resolves({ DocumentIdentifiers: [{ Name: 'ASR-SC_2.0.0_S3.1' }] });
    ssmMock.on(GetParametersByPathCommand).resolves({ Parameters: [remapParameter('S3.9', 'CloudTrail.7')] });

    const result = await listFindingsWithoutRunbook({}, context());

    expect(result.controls.map((control) => control.controlId)).toEqual(['S3.9']);
  });

  test('reports the gap and flags the answer when remaps cannot be read', async () => {
    // Fails toward reporting rather than hiding: an unreadable mapping must not make a
    // control disappear, but the caller has to know the gap may be a mapped one.
    securityHubMock.on(GetFindingsCommand).resolves({ Findings: [finding('S3.9', 'bucket logging')] });
    ssmMock.on(ListDocumentsCommand).resolves({ DocumentIdentifiers: [{ Name: 'ASR-SC_2.0.0_CloudTrail.7' }] });
    ssmMock.on(GetParametersByPathCommand).rejects(new Error('AccessDeniedException'));

    const result = await listFindingsWithoutRunbook({}, context());

    expect(result.controls.map((control) => control.controlId)).toEqual(['S3.9']);
    expect(result.runbookCoverageCaveat).toMatch(/remaps could not be read/i);
  });

  test('reports the gap and flags the answer when the remap scan hits the page cap', async () => {
    // Every remap page returns a NextToken, so the loop stops on the page ceiling with a
    // token still in hand. That is a partial read: S3.9's remap may sit on an unread page,
    // so the control must still be reported and the answer flagged — same degradation as a
    // failed read, not a silent drop that presents a possibly-false gap as certain.
    securityHubMock.on(GetFindingsCommand).resolves({ Findings: [finding('S3.9', 'bucket logging')] });
    ssmMock.on(ListDocumentsCommand).resolves({ DocumentIdentifiers: [{ Name: 'ASR-SC_2.0.0_CloudTrail.7' }] });
    ssmMock.on(GetParametersByPathCommand).resolves({ Parameters: [], NextToken: 'always-more' });

    const result = await listFindingsWithoutRunbook({}, context());

    expect(result.controls.map((control) => control.controlId)).toEqual(['S3.9']);
    expect(result.runbookCoverageCaveat).toMatch(/remaps could not be read/i);
  });
});
