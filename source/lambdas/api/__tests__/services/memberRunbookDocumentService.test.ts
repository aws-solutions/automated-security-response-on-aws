// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { Logger } from '@aws-lambda-powertools/logger';
import {
  CreateDocumentCommand,
  DescribeDocumentCommand,
  DocumentAlreadyExists,
  DuplicateDocumentContent,
  GetParameterCommand,
  ListDocumentsCommand,
  ParameterNotFound,
  SSMClient,
  UpdateDocumentCommand,
  UpdateDocumentDefaultVersionCommand,
} from '@aws-sdk/client-ssm';
import { STSClient, AssumeRoleCommand } from '@aws-sdk/client-sts';
import { mockClient } from 'aws-sdk-client-mock';
import { MemberRunbookDocumentService } from '../../services/memberRunbookDocumentService';
import { MemberAccountCredentialsProvider } from '../../services/memberAccountCredentials';

const ssmMock = mockClient(SSMClient);
const stsMock = mockClient(STSClient);

const DOCUMENT_NAME = 'ASR-Custom-SC_2.0.0_S3.9';
const BUILT_IN_DOCUMENT_NAME = 'ASR-SC_2.0.0_S3.9';
const REMAPPED_BUILT_IN_DOCUMENT_NAME = 'ASR-SC_2.0.0_CloudTrail.7';
const REMAP_PARAMETER_NAME = '/Solutions/SO0111/SC/2.0.0/S3.9/remap';
const YAML = 'schemaVersion: "0.3"';

function service(): MemberRunbookDocumentService {
  // The factory ignores the credentials because mockClient intercepts every
  // SSMClient — what matters is that a client is built per member account.
  return new MemberRunbookDocumentService(
    new Logger({ serviceName: 'test' }),
    new MemberAccountCredentialsProvider(),
    () => new SSMClient({}),
  );
}

const alreadyExists = () => new DocumentAlreadyExists({ message: 'exists', $metadata: {} });
const duplicateContent = () => new DuplicateDocumentContent({ message: 'identical', $metadata: {} });
const parameterNotFound = () => new ParameterNotFound({ message: 'not found', $metadata: {} });

/** ListDocuments response listing the given ASR document names as self-owned Automation docs. */
function listedDocuments(
  names: string[],
  nextToken?: string,
): { DocumentIdentifiers: { Name: string }[]; NextToken: string | undefined } {
  return { DocumentIdentifiers: names.map((Name) => ({ Name })), NextToken: nextToken };
}

describe('MemberRunbookDocumentService — copy-per-member document install', () => {
  beforeEach(() => {
    ssmMock.reset();
    stsMock.reset();
    stsMock.on(AssumeRoleCommand).resolves({
      Credentials: {
        AccessKeyId: 'access-key',
        SecretAccessKey: 'secret-key',
        SessionToken: 'session-token',
        Expiration: new Date(),
      },
    });
  });

  it('creates the document in the member account and promotes the new version to default', async () => {
    ssmMock.on(CreateDocumentCommand).resolves({ DocumentDescription: { DocumentVersion: '1' } });
    ssmMock.on(UpdateDocumentDefaultVersionCommand).resolves({});

    const version = await service().deployDocumentToAccount({
      memberAccountId: '111111111111',
      documentName: DOCUMENT_NAME,
      content: YAML,
      controlId: 'S3.9',
    });

    expect(version).toBe('1');
    // The member-account hop must target the named account AND carry the
    // operation-specific session name for CloudTrail attribution.
    const memberHop = stsMock
      .commandCalls(AssumeRoleCommand)
      .map((call) => call.args[0].input)
      .find((input) => input.RoleArn?.includes('111111111111'));
    expect(memberHop?.RoleArn).toBe('arn:aws:iam::111111111111:role/SO0111-ASR-Orchestrator-Member');
    expect(memberHop?.RoleSessionName).toBe('asr-cr-document-deploy');

    const created = ssmMock.commandCalls(CreateDocumentCommand)[0].args[0].input;
    expect(created.Name).toBe(DOCUMENT_NAME);
    expect(created.Content).toBe(YAML);
    expect(created.DocumentType).toBe('Automation');
    expect(created.Tags).toEqual([
      { Key: 'aws-solutions:solution-id', Value: 'SO0111' },
      { Key: 'aws-solutions:custom-runbook', Value: 'S3.9' },
    ]);

    expect(ssmMock.commandCalls(UpdateDocumentDefaultVersionCommand)[0].args[0].input).toEqual({
      Name: DOCUMENT_NAME,
      DocumentVersion: '1',
    });
  });

  it('updates $LATEST when the account already holds the document, then promotes that version', async () => {
    ssmMock.on(CreateDocumentCommand).rejects(alreadyExists());
    ssmMock.on(UpdateDocumentCommand).resolves({ DocumentDescription: { DocumentVersion: '3' } });
    ssmMock.on(UpdateDocumentDefaultVersionCommand).resolves({});

    const version = await service().deployDocumentToAccount({
      memberAccountId: '111111111111',
      documentName: DOCUMENT_NAME,
      content: YAML,
      controlId: 'S3.9',
    });

    expect(version).toBe('3');
    expect(ssmMock.commandCalls(UpdateDocumentCommand)[0].args[0].input.DocumentVersion).toBe('$LATEST');
    expect(ssmMock.commandCalls(UpdateDocumentCommand)[0].args[0].input.DocumentFormat).toBe('YAML');
    // Promotion is what makes the update take effect — an unqualified execution
    // runs the default version, which UpdateDocument leaves pointing at the old one.
    expect(ssmMock.commandCalls(UpdateDocumentDefaultVersionCommand)[0].args[0].input.DocumentVersion).toBe('3');
  });

  it('treats identical content as installed and still promotes the existing version', async () => {
    ssmMock.on(CreateDocumentCommand).rejects(alreadyExists());
    ssmMock.on(UpdateDocumentCommand).rejects(duplicateContent());
    ssmMock.on(DescribeDocumentCommand).resolves({ Document: { DocumentVersion: '2' } });
    ssmMock.on(UpdateDocumentDefaultVersionCommand).resolves({});

    const version = await service().deployDocumentToAccount({
      memberAccountId: '111111111111',
      documentName: DOCUMENT_NAME,
      content: YAML,
      controlId: 'S3.9',
    });

    expect(version).toBe('2');
    expect(ssmMock.commandCalls(UpdateDocumentDefaultVersionCommand)[0].args[0].input.DocumentVersion).toBe('2');
  });

  it('surfaces non-conflict SSM errors instead of reporting a successful install', async () => {
    ssmMock.on(CreateDocumentCommand).rejects(new Error('AccessDenied'));

    await expect(
      service().deployDocumentToAccount({
        memberAccountId: '111111111111',
        documentName: DOCUMENT_NAME,
        content: YAML,
        controlId: 'S3.9',
      }),
    ).rejects.toThrow('AccessDenied');
    expect(ssmMock.commandCalls(UpdateDocumentDefaultVersionCommand)).toHaveLength(0);
  });

  it('detects a direct built-in document before a custom document is installed', async () => {
    ssmMock.on(ListDocumentsCommand).resolves(listedDocuments([BUILT_IN_DOCUMENT_NAME]));

    const result = await service().prepareDeploymentTargets(['111111111111'], 'S3.9', 'S3.9');

    expect(result.ready).toHaveLength(0);
    expect(result.failed).toEqual([]);
    expect(result.collisions).toEqual([{ accountId: '111111111111', documentName: BUILT_IN_DOCUMENT_NAME }]);
  });

  it('detects a built-in from a non-SC playbook by control id, even when SC is not loaded', async () => {
    // With LoadSCAdminStack=no but e.g. CIS300 loaded, the built-in is named ASR-CIS_3.0.0_S3.9.
    // The guard matches at the control-id level, so it still blocks a custom runbook for S3.9.
    ssmMock.on(ListDocumentsCommand).resolves(listedDocuments(['ASR-CIS_3.0.0_S3.9']));

    const result = await service().prepareDeploymentTargets(['111111111111'], 'S3.9', 'S3.9');

    expect(result.ready).toHaveLength(0);
    expect(result.collisions).toEqual([{ accountId: '111111111111', documentName: 'ASR-CIS_3.0.0_S3.9' }]);
  });

  // Binds the guard's breadth to the coverage detector's: the security invariant is that this
  // guard must collide on every built-in name the gap tool (findingsWithoutRunbook) recognizes
  // as covering a control, so a future narrowing of this guard's regex fails here rather than
  // silently letting a custom runbook install over a built-in. Each name below is a shape the
  // gap tool's `ASR-.*_(control)` extraction matches — every shipped standard, numeric and
  // non-numeric control ids, and a remapped target.
  it.each([
    'ASR-SC_2.0.0_S3.9',
    'ASR-CIS_3.0.0_S3.9',
    'ASR-CIS_1.2.0_S3.9',
    'ASR-AFSBP_1.0.0_S3.9',
    'ASR-NIST80053_5.0.0_S3.9',
    'ASR-PCI_3.2.1_S3.9',
  ])('collides on built-in document name %s regardless of standard prefix', async (documentName) => {
    ssmMock.on(ListDocumentsCommand).resolves(listedDocuments([documentName]));

    const result = await service().prepareDeploymentTargets(['111111111111'], 'S3.9', 'S3.9');

    expect(result.collisions).toEqual([{ accountId: '111111111111', documentName }]);
  });

  it('collides on a non-numeric control id built-in the coverage detector also matches', async () => {
    ssmMock.on(ListDocumentsCommand).resolves(listedDocuments(['ASR-SC_2.0.0_Inspector.InstanceVulnerability']));

    const result = await service().prepareDeploymentTargets(
      ['111111111111'],
      'Inspector.InstanceVulnerability',
      'Inspector.InstanceVulnerability',
    );

    expect(result.collisions).toEqual([
      { accountId: '111111111111', documentName: 'ASR-SC_2.0.0_Inspector.InstanceVulnerability' },
    ]);
  });

  it('does not treat an existing custom runbook document as a built-in collision', async () => {
    // The account already holds this control's own custom document (a redeploy). ASR-Custom-*
    // must not count as a built-in, or a custom runbook could never be updated.
    ssmMock.on(ListDocumentsCommand).resolves(listedDocuments([DOCUMENT_NAME]));

    const result = await service().prepareDeploymentTargets(['111111111111'], 'S3.9', 'S3.9');

    expect(result.collisions).toEqual([]);
    expect(result.ready).toHaveLength(1);
  });

  it('checks the remapped control document that the Orchestrator would execute', async () => {
    // The caller resolved S3.9 → CloudTrail.7 in the admin account; a built-in named after the
    // remap target (ASR-SC_2.0.0_CloudTrail.7) is a collision for a custom S3.9 runbook.
    ssmMock.on(ListDocumentsCommand).resolves(listedDocuments([REMAPPED_BUILT_IN_DOCUMENT_NAME]));

    const result = await service().prepareDeploymentTargets(['111111111111'], 'S3.9', 'CloudTrail.7');

    expect(result.ready).toHaveLength(0);
    expect(result.collisions).toEqual([{ accountId: '111111111111', documentName: REMAPPED_BUILT_IN_DOCUMENT_NAME }]);
    // The preflight must NOT read remap parameters itself — those live only in the admin
    // account, so a member-credentialled read would always miss and defeat the guard.
    expect(ssmMock.commandCalls(GetParameterCommand)).toHaveLength(0);
  });

  it('excludes an account whose document list is truncated before a collision is found', async () => {
    // A truncated list could still hide a built-in on an unread page, so the account must be
    // failed closed rather than assumed safe.
    ssmMock.on(ListDocumentsCommand).resolves(listedDocuments(['ASR-SC_2.0.0_EC2.1'], 'more-pages'));

    const result = await service().prepareDeploymentTargets(['111111111111'], 'S3.9', 'S3.9');

    expect(result.ready).toEqual([]);
    expect(result.collisions).toEqual([]);
    expect(result.failed).toHaveLength(1);
    expect(result.failed[0].accountId).toBe('111111111111');
  });

  it('reuses the preflight SSM client for installation when no built-in exists', async () => {
    ssmMock.on(ListDocumentsCommand).resolves(listedDocuments([]));
    ssmMock.on(CreateDocumentCommand).resolves({ DocumentDescription: { DocumentVersion: '1' } });
    ssmMock.on(UpdateDocumentDefaultVersionCommand).resolves({});

    const prepared = await service().prepareDeploymentTargets(['111111111111'], 'S3.9', 'S3.9');
    const deployed = await service().deployToPreparedAccounts(prepared.ready, DOCUMENT_NAME, YAML, 'S3.9');

    expect(prepared.collisions).toEqual([]);
    expect(prepared.failed).toEqual([]);
    expect(deployed.succeeded).toEqual([{ accountId: '111111111111', ssmDocumentVersion: '1' }]);
    // One member-account hop serves both the read-only preflight and the later
    // document write; role provisioning uses its own separate service and hop.
    const memberRoleArns = stsMock
      .commandCalls(AssumeRoleCommand)
      .map((call) => call.args[0].input.RoleArn)
      .filter((arn) => arn?.includes('SO0111-ASR-Orchestrator-Member'));
    expect(memberRoleArns).toEqual(['arn:aws:iam::111111111111:role/SO0111-ASR-Orchestrator-Member']);
  });

  it('installs its own copy in every named account, using that account’s credentials', async () => {
    ssmMock.on(CreateDocumentCommand).resolves({ DocumentDescription: { DocumentVersion: '1' } });
    ssmMock.on(UpdateDocumentDefaultVersionCommand).resolves({});

    const result = await service().deployToAccounts(['111111111111', '222222222222'], DOCUMENT_NAME, YAML, 'S3.9');

    expect(result.succeeded).toEqual([
      { accountId: '111111111111', ssmDocumentVersion: '1' },
      { accountId: '222222222222', ssmDocumentVersion: '1' },
    ]);
    expect(result.failed).toEqual([]);
    // Verify the member-role hop targeted each named account exactly once.
    const memberRoleArns = stsMock
      .commandCalls(AssumeRoleCommand)
      .map((call) => call.args[0].input.RoleArn)
      .filter((arn) => arn?.includes('SO0111-ASR-Orchestrator-Member'));
    expect(memberRoleArns).toEqual([
      'arn:aws:iam::111111111111:role/SO0111-ASR-Orchestrator-Member',
      'arn:aws:iam::222222222222:role/SO0111-ASR-Orchestrator-Member',
    ]);
    expect(ssmMock.commandCalls(CreateDocumentCommand)).toHaveLength(2);
  });

  it('keeps releasing to the remaining accounts after one account fails', async () => {
    ssmMock
      .on(CreateDocumentCommand)
      .rejectsOnce(new Error('AccessDenied'))
      .resolves({ DocumentDescription: { DocumentVersion: '1' } });
    ssmMock.on(UpdateDocumentDefaultVersionCommand).resolves({});

    const result = await service().deployToAccounts(['111111111111', '222222222222'], DOCUMENT_NAME, YAML, 'S3.9');

    expect(result.failed).toEqual([{ accountId: '111111111111', error: 'AccessDenied' }]);
    expect(result.succeeded).toEqual([{ accountId: '222222222222', ssmDocumentVersion: '1' }]);
  });

  describe('resolveRemediationControlId — reads the admin-account remap', () => {
    it('returns the remap target when a remap parameter exists', async () => {
      ssmMock.on(GetParameterCommand, { Name: REMAP_PARAMETER_NAME }).resolves({
        Parameter: { Value: 'CloudTrail.7' },
      });

      const resolved = await service().resolveRemediationControlId(new SSMClient({}), 'S3.9');

      expect(resolved).toBe('CloudTrail.7');
      expect(ssmMock.commandCalls(GetParameterCommand)[0].args[0].input.Name).toBe(REMAP_PARAMETER_NAME);
    });

    it('falls back to the control id when no remap parameter exists', async () => {
      ssmMock.on(GetParameterCommand).rejects(parameterNotFound());

      const resolved = await service().resolveRemediationControlId(new SSMClient({}), 'S3.9');

      expect(resolved).toBe('S3.9');
    });
  });
});
