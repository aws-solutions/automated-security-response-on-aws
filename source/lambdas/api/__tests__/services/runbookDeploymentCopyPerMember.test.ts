// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { Logger } from '@aws-lambda-powertools/logger';
import { createHash } from 'node:crypto';
import { GetObjectCommand, GetObjectCommandOutput, S3Client } from '@aws-sdk/client-s3';
import {
  CreateRoleCommand,
  GetRoleCommand,
  IAMClient,
  NoSuchEntityException,
  PutRolePolicyCommand,
  TagRoleCommand,
} from '@aws-sdk/client-iam';
import { AssumeRoleCommand, STSClient } from '@aws-sdk/client-sts';
import {
  CreateDocumentCommand,
  DescribeDocumentCommand,
  DocumentAlreadyExists,
  DuplicateDocumentContent,
  GetParameterCommand,
  ListDocumentsCommand,
  ModifyDocumentPermissionCommand,
  ParameterNotFound,
  SSMClient,
  UpdateDocumentCommand,
  UpdateDocumentDefaultVersionCommand,
} from '@aws-sdk/client-ssm';
import { DynamoDBDocumentClient, PutCommand, QueryCommand, UpdateCommand } from '@aws-sdk/lib-dynamodb';
import { MemberDeploymentState, RunbookId, RunbookMetadata } from '@asr/data-models';
import { mockClient } from 'aws-sdk-client-mock';
import { RunbookDeploymentService } from '../../services/runbookDeploymentService';
import { resetApiLambdaEnvironmentCache } from '../../apiLambdaEnvironment';
import type { Clock } from '../../../common/utils/clock';
import type { IdGenerator } from '../../../common/utils/idGenerator';
import { remediationConfigTableName } from '../../../common/__tests__/envSetup';

// This suite mocks at the AWS SDK boundary (STS/IAM/SSM/S3/DynamoDB) and drives
// the REAL CrossAccountRoleService and MemberRunbookDocumentService, per
// unit-testing.md — rather than stubbing those collaborators. Per-account
// outcomes are expressed at the natural seam: the member-account STS hop
// (RoleArn carries the account) for a role-provisioning failure, and the member
// SSM CreateDocument for a document-install failure.

const stsMock = mockClient(STSClient);
const iamMock = mockClient(IAMClient);
const ssmMock = mockClient(SSMClient);
const s3Mock = mockClient(S3Client);
const dynamoMock = mockClient(DynamoDBDocumentClient);

const NOW = '2026-01-01T00:00:00.000Z';
const fixedClock: Clock = { now: () => new Date(NOW) };
const fakeIdGenerator: IdGenerator = { randomUUID: () => 'uuid-1' };

const DOCUMENT_NAME = 'ASR-Custom-SC_2.0.0_S3.9';
const BUILT_IN_DOCUMENT_NAME = 'ASR-SC_2.0.0_S3.9';
const ROLE_NAME = 'SO0111-Remediate-Custom-SC-2.0.0-S3.9';
const YAML = 'schemaVersion: "0.3"';
const YAML_DIGEST = createHash('sha256').update(YAML, 'utf8').digest('hex');
const ADMIN_DOC_VERSION = '4';
const MEMBER_DOC_VERSION = '1';

const ACCOUNT_A = '111111111111';
const ACCOUNT_B = '222222222222';

/** The Orchestrator Member role ARN a member-account hop assumes for `accountId`. */
function memberRoleArn(accountId: string): string {
  return `arn:aws:iam::${accountId}:role/SO0111-ASR-Orchestrator-Member`;
}

function metadata(version: number, deployedAccounts?: Record<string, MemberDeploymentState>): RunbookMetadata {
  return {
    runbookId: 'rb-1',
    version,
    controlId: 'S3.9',
    serviceName: 'S3',
    description: 'test',
    remediationAction: 'test',
    status: 'DRAFT',
    s3Key: `runbooks/rb-1/v${version}/runbook.yaml`,
    createdBy: 'test',
    createdAt: NOW,
    deployedAccounts,
    // A version is deployable only after test_runbook_yaml records a PASSED
    // outcome bound to the registered content and the exact requested IAM actions
    // (see assertVersionPassedTest). The digests match each other and the tested
    // action set equals deployParams.required_iam_actions.
    testStatus: 'PASSED',
    testedAt: NOW,
    // Bound to the actual fixture bytes, not a placeholder: deploy re-hashes the
    // YAML it fetches from S3 and refuses to install an artifact that does not
    // match its registration, so a stand-in string would fail that check.
    registeredContentDigest: YAML_DIGEST,
    testedContentDigest: YAML_DIGEST,
    testedIamActions: ['s3:PutBucketLogging'],
  } as RunbookMetadata;
}

function yamlBody(): GetObjectCommandOutput['Body'] {
  return { transformToString: () => Promise.resolve(YAML) } as unknown as GetObjectCommandOutput['Body'];
}

/** Deploy params shared by every test — only the account list varies. */
const deployParams = {
  action: 'deploy' as const,
  runbook_id: 'rb-1' as RunbookId,
  control_id: 'S3.9',
  security_standard: 'SC',
  standard_version: '2.0.0',
  required_iam_actions: ['s3:PutBucketLogging'],
};

function service(): RunbookDeploymentService {
  // No collaborators injected — the service builds the real CrossAccountRoleService
  // and MemberRunbookDocumentService, which reach the mocked AWS clients.
  return new RunbookDeploymentService(new Logger({ serviceName: 'test' }), fixedClock, fakeIdGenerator);
}

const parameterNotFound = () => new ParameterNotFound({ message: 'not found', $metadata: {} });

/** Default preflight: no control remap (admin) and no built-in documents in member accounts. */
function setupBuiltInPreflightMisses(): void {
  ssmMock.on(GetParameterCommand).rejects(parameterNotFound());
  ssmMock.on(ListDocumentsCommand).resolves({ DocumentIdentifiers: [] });
}

/**
 * (Re)configures the SSM mock. `memberCreate` decides what each member-account
 * CreateDocument returns (or throws); the admin-account CreateDocument (no Tags)
 * always returns the admin version. Callers pass a custom `memberCreate` to make
 * a specific member install fail.
 */
function setupSsmMock(memberCreate: (callIndex: number) => { DocumentDescription: { DocumentVersion: string } }): void {
  ssmMock.reset();
  setupBuiltInPreflightMisses();
  ssmMock.on(UpdateDocumentDefaultVersionCommand).resolves({});
  let memberCreateCount = 0;
  ssmMock.on(CreateDocumentCommand).callsFake((input) => {
    // The admin-account document create carries no Tags; member-account copies do.
    if (!input.Tags) {
      return { DocumentDescription: { DocumentVersion: ADMIN_DOC_VERSION } };
    }
    memberCreateCount += 1;
    return memberCreate(memberCreateCount);
  });
}

/** deployedAccounts entries written back to DynamoDB, keyed by account ID. */
function recordedMemberStates(): Record<string, MemberDeploymentState> {
  const states: Record<string, MemberDeploymentState> = {};
  for (const call of dynamoMock.commandCalls(UpdateCommand)) {
    const input = call.args[0].input;
    const accountId = input.ExpressionAttributeNames?.['#account'];
    if (accountId) states[accountId] = input.ExpressionAttributeValues?.[':state'] as MemberDeploymentState;
  }
  return states;
}

/** Member-account role ARNs assumed across all STS hops, in call order. */
function memberHopArns(): string[] {
  return stsMock
    .commandCalls(AssumeRoleCommand)
    .map((call) => call.args[0].input.RoleArn)
    .filter((arn): arn is string => !!arn && arn.includes('SO0111-ASR-Orchestrator-Member'));
}

function resetAllMocks(): void {
  stsMock.reset();
  iamMock.reset();
  s3Mock.reset();
  dynamoMock.reset();
}

describe('RunbookDeploymentService — copy-per-member release', () => {
  beforeEach(() => {
    resetAllMocks();

    // Cross-account chain: admin hop + every member hop assume successfully.
    stsMock.on(AssumeRoleCommand).resolves({
      Credentials: { AccessKeyId: 'ak', SecretAccessKey: 'sk', SessionToken: 'st', Expiration: new Date() },
    });

    // Remediation role does not exist yet → CreateRole path succeeds.
    iamMock.on(GetRoleCommand).rejects(new NoSuchEntityException({ message: 'not found', $metadata: {} }));
    iamMock.on(CreateRoleCommand).resolves({});
    iamMock.on(PutRolePolicyCommand).resolves({});
    iamMock.on(TagRoleCommand).resolves({});

    setupSsmMock(() => ({ DocumentDescription: { DocumentVersion: MEMBER_DOC_VERSION } }));

    s3Mock.on(GetObjectCommand).resolves({ Body: yamlBody() });

    dynamoMock.on(QueryCommand).resolves({ Items: [metadata(2)], Count: 1 });
    dynamoMock.on(UpdateCommand).resolves({});
    dynamoMock.on(PutCommand).resolves({});

    process.env.CUSTOM_RUNBOOK_BUCKET_NAME = 'test-bucket';
    process.env.CUSTOM_RUNBOOK_TABLE_NAME = 'test-table';
    resetApiLambdaEnvironmentCache();
  });

  it('never shares the admin document out of the admin account', async () => {
    await service().execute({ ...deployParams, member_account_ids: [ACCOUNT_A] });

    expect(ssmMock.commandCalls(ModifyDocumentPermissionCommand)).toHaveLength(0);
  });

  it('promotes the admin document version to default so an unqualified execution runs it', async () => {
    const result = await service().execute({ ...deployParams, member_account_ids: [ACCOUNT_A] });

    expect(result.document_version).toBe(ADMIN_DOC_VERSION);
    // The admin document is created and promoted before any member release, so the
    // first default-version promotion is the admin document's.
    expect(ssmMock.commandCalls(UpdateDocumentDefaultVersionCommand)[0].args[0].input).toEqual({
      Name: DOCUMENT_NAME,
      DocumentVersion: ADMIN_DOC_VERSION,
    });
  });

  it('re-deploying byte-identical YAML still promotes and deploys (admin DuplicateDocumentContent)', async () => {
    // The admin document already exists and the re-sent YAML is byte-identical, so
    // SSM rejects the create with DocumentAlreadyExists and the follow-up update
    // with DuplicateDocumentContent. This is the documented multi-call rollout /
    // retry path — the deploy must resolve the current version and carry on, not
    // 500 before role provisioning and the member release.
    ssmMock.reset();
    setupBuiltInPreflightMisses();
    ssmMock.on(UpdateDocumentDefaultVersionCommand).resolves({});
    ssmMock.on(CreateDocumentCommand).callsFake((input) => {
      // Admin create (no Tags) hits the already-exists path; member copies (Tags) succeed.
      if (!input.Tags) throw new DocumentAlreadyExists({ message: 'exists', $metadata: {} });
      return { DocumentDescription: { DocumentVersion: MEMBER_DOC_VERSION } };
    });
    ssmMock.on(UpdateDocumentCommand).rejects(new DuplicateDocumentContent({ message: 'identical', $metadata: {} }));
    ssmMock
      .on(DescribeDocumentCommand, { Name: DOCUMENT_NAME, DocumentVersion: '$LATEST' })
      .resolves({ Document: { DocumentVersion: ADMIN_DOC_VERSION } });

    const result = await service().execute({ ...deployParams, member_account_ids: [ACCOUNT_A] });

    expect(result.status).toBe('DEPLOYED');
    // The current admin version is resolved via DescribeDocument and still promoted.
    expect(result.document_version).toBe(ADMIN_DOC_VERSION);
    expect(ssmMock.commandCalls(UpdateDocumentDefaultVersionCommand)[0].args[0].input).toEqual({
      Name: DOCUMENT_NAME,
      DocumentVersion: ADMIN_DOC_VERSION,
    });
    // The member account was still released to.
    expect(result.document_deployment?.succeeded).toEqual([ACCOUNT_A]);
  });

  it('installs the document only in the accounts named in member_account_ids', async () => {
    const result = await service().execute({ ...deployParams, member_account_ids: [ACCOUNT_A] });

    // Exactly one member-account copy is created (the named account), carrying the runbook YAML.
    const memberCreates = ssmMock.commandCalls(CreateDocumentCommand).filter((call) => call.args[0].input.Tags);
    expect(memberCreates).toHaveLength(1);
    expect(memberCreates[0].args[0].input).toMatchObject({
      Name: DOCUMENT_NAME,
      Content: YAML,
      DocumentType: 'Automation',
    });
    // Only ACCOUNT_A was ever assumed into (document preflight/install hop +
    // role-provision hop).
    expect(memberHopArns()).toEqual([memberRoleArn(ACCOUNT_A), memberRoleArn(ACCOUNT_A)]);
    expect(result.document_deployment).toEqual({ succeeded: [ACCOUNT_A], failed: [] });
  });

  it('derives the install document name from the SC standard, ignoring caller-supplied standard/version', async () => {
    // The install must use the trusted SC standard and version, not the caller's params, so a
    // caller sending a bogus standard/version cannot install under a non-SC name the runtime
    // resolver would never look up.
    const result = await service().execute({
      ...deployParams,
      security_standard: 'AFSBP',
      standard_version: '9.9.9',
      member_account_ids: [ACCOUNT_A],
    });

    // The installed member document uses the SC-derived custom name, not ASR-Custom-AFSBP_9.9.9_S3.9.
    const memberCreates = ssmMock.commandCalls(CreateDocumentCommand).filter((call) => call.args[0].input.Tags);
    expect(memberCreates[0].args[0].input.Name).toBe(DOCUMENT_NAME);
    expect(result.document_deployment).toEqual({ succeeded: [ACCOUNT_A], failed: [] });
  });

  it('rejects the whole release when a requested account has a built-in runbook', async () => {
    // ACCOUNT_A has no built-in (empty list); ACCOUNT_B has the SC built-in for this control.
    // The preflight lists each account's ASR-* documents, so the collision is by control id.
    ssmMock
      .on(ListDocumentsCommand)
      .resolvesOnce({ DocumentIdentifiers: [] })
      .resolves({ DocumentIdentifiers: [{ Name: BUILT_IN_DOCUMENT_NAME }] });

    await expect(
      service().execute({ ...deployParams, member_account_ids: [ACCOUNT_A, ACCOUNT_B] }),
    ).rejects.toMatchObject({
      statusCode: 400,
      message: expect.stringMatching(/already provides a built-in remediation/i),
    });

    // The collision is detected before stored content is read or any IAM/SSM
    // document/status write begins.
    expect(s3Mock.commandCalls(GetObjectCommand)).toHaveLength(0);
    expect(ssmMock.commandCalls(CreateDocumentCommand)).toHaveLength(0);
    expect(iamMock.calls()).toHaveLength(0);
    expect(dynamoMock.commandCalls(UpdateCommand)).toHaveLength(0);
  });

  it('makes no deployment writes when built-in coverage cannot be checked in any account', async () => {
    stsMock.on(AssumeRoleCommand, { RoleArn: memberRoleArn(ACCOUNT_A) }).rejects(new Error('AccessDenied'));
    stsMock.on(AssumeRoleCommand, { RoleArn: memberRoleArn(ACCOUNT_B) }).rejects(new Error('AccessDenied'));

    await expect(
      service().execute({ ...deployParams, member_account_ids: [ACCOUNT_A, ACCOUNT_B] }),
    ).rejects.toMatchObject({
      statusCode: 502,
      message: expect.stringMatching(/No runbook resources were changed/i),
    });

    expect(s3Mock.commandCalls(GetObjectCommand)).toHaveLength(0);
    expect(ssmMock.commandCalls(CreateDocumentCommand)).toHaveLength(0);
    expect(iamMock.calls()).toHaveLength(0);
    expect(dynamoMock.commandCalls(UpdateCommand)).toHaveLength(0);
  });

  it('rejects a deploy whose control differs from the runbook registration', async () => {
    dynamoMock.on(QueryCommand).resolves({
      Items: [{ ...metadata(2), controlId: 'EC2.1' }],
      Count: 1,
    });

    await expect(service().execute({ ...deployParams, member_account_ids: [ACCOUNT_A] })).rejects.toMatchObject({
      statusCode: 400,
      message: expect.stringMatching(/registered under control EC2\.1, not S3\.9/i),
    });

    expect(stsMock.commandCalls(AssumeRoleCommand)).toHaveLength(0);
    expect(s3Mock.commandCalls(GetObjectCommand)).toHaveLength(0);
    expect(ssmMock.commandCalls(CreateDocumentCommand)).toHaveLength(0);
    expect(iamMock.calls()).toHaveLength(0);
  });

  it('publishes a successfully deployed custom control as disabled configuration', async () => {
    await service().execute({ ...deployParams, member_account_ids: [ACCOUNT_A] }, 'deployer@example.com');

    const configurationWrites = dynamoMock
      .commandCalls(PutCommand)
      .filter((call) => call.args[0].input.TableName === remediationConfigTableName);
    expect(configurationWrites).toHaveLength(1);
    expect(configurationWrites[0].args[0].input).toEqual({
      TableName: remediationConfigTableName,
      Item: {
        controlId: 'S3.9',
        description: 'test',
        automatedRemediationEnabled: false,
        filterMode: 'include',
        version: 0,
        lastModified: NOW,
        modifiedBy: 'deployer@example.com',
        source: 'custom',
      },
      ConditionExpression: 'attribute_not_exists(controlId)',
    });
  });

  it('does not overwrite an existing control configuration during redeploy', async () => {
    const alreadyExists = new Error('control already exists');
    alreadyExists.name = 'ConditionalCheckFailedException';
    dynamoMock.on(PutCommand).callsFake((input) => {
      if (input.TableName === remediationConfigTableName) throw alreadyExists;
      return {};
    });

    const result = await service().execute({ ...deployParams, member_account_ids: [ACCOUNT_A] });

    expect(result.status).toBe('DEPLOYED');
    // Prove the code actually attempted the conditional write (and swallowed its
    // ConditionalCheckFailedException) rather than merely not crashing: the guarded
    // PutCommand to the controls table must have been issued exactly once.
    expect(
      dynamoMock.commandCalls(PutCommand).filter((call) => call.args[0].input.TableName === remediationConfigTableName),
    ).toHaveLength(1);
  });

  it('still reports DEPLOYED when writing the control-config entry fails for a non-conditional reason', async () => {
    // The Controls entry is a convenience record secondary to the DEPLOYED status; the
    // runbook is already installed in the member account, so a throttle/5xx on that write
    // must be logged and swallowed rather than surfacing a 500 for a deploy that succeeded.
    const throttled = new Error('Rate exceeded');
    throttled.name = 'ProvisionedThroughputExceededException';
    dynamoMock.on(PutCommand).callsFake((input) => {
      if (input.TableName === remediationConfigTableName) throw throttled;
      return {};
    });

    const result = await service().execute({ ...deployParams, member_account_ids: [ACCOUNT_A] });

    expect(result.status).toBe('DEPLOYED');
  });

  it('provisions the remediation role before installing the document', async () => {
    const order: string[] = [];
    iamMock.on(CreateRoleCommand).callsFake(() => {
      order.push('role');
      return {};
    });
    setupSsmMock(() => {
      order.push('document');
      return { DocumentDescription: { DocumentVersion: MEMBER_DOC_VERSION } };
    });

    await service().execute({ ...deployParams, member_account_ids: [ACCOUNT_A] });

    expect(order).toEqual(['role', 'document']);
    // The role is the scoped custom-runbook remediation role, granted the requested action.
    expect(iamMock.commandCalls(CreateRoleCommand)[0].args[0].input.RoleName).toBe(ROLE_NAME);
    const policyDocuments = iamMock.commandCalls(PutRolePolicyCommand).map((call) => call.args[0].input.PolicyDocument);
    expect(policyDocuments.some((document) => document?.includes('s3:PutBucketLogging'))).toBe(true);
  });

  it('skips role provisioning and document installation when an account preflight fails', async () => {
    // ACCOUNT_B is unreachable during the read-only built-in preflight, so it
    // is excluded before role provisioning or document installation.
    stsMock.on(AssumeRoleCommand, { RoleArn: memberRoleArn(ACCOUNT_B) }).rejects(new Error('AccessDenied'));

    const result = await service().execute({
      ...deployParams,
      member_account_ids: [ACCOUNT_A, ACCOUNT_B],
    });

    // The document is installed only in ACCOUNT_A.
    const memberCreates = ssmMock.commandCalls(CreateDocumentCommand).filter((call) => call.args[0].input.Tags);
    expect(memberCreates).toHaveLength(1);
    expect(result.document_deployment?.succeeded).toEqual([ACCOUNT_A]);
    expect(result.document_deployment?.failed).toEqual([
      { accountId: ACCOUNT_B, error: 'Built-in runbook preflight failed: AccessDenied' },
    ]);
  });

  it('does NOT mark the version DEPLOYED when every named account failed', async () => {
    // Roles fail in every account, so the document step targets nothing and the
    // runbook is installed nowhere. The version must not flip to DEPLOYED (which
    // would publish a runbook that can execute nowhere); deploy fails 502 instead.
    iamMock.on(GetRoleCommand).rejects(new Error('AccessDenied'));

    await expect(
      service().execute({ ...deployParams, member_account_ids: [ACCOUNT_A, ACCOUNT_B] }),
    ).rejects.toMatchObject({ statusCode: 502 });

    // No document was installed anywhere...
    const memberCreates = ssmMock.commandCalls(CreateDocumentCommand).filter((call) => call.args[0].input.Tags);
    expect(memberCreates).toHaveLength(0);
    // ...and no status write flipped the record to DEPLOYED.
    const statusWrites = dynamoMock
      .commandCalls(UpdateCommand)
      .filter((call) => call.args[0].input.ExpressionAttributeValues?.[':status'] === 'DEPLOYED');
    expect(statusWrites).toHaveLength(0);
    expect(
      dynamoMock.commandCalls(PutCommand).filter((call) => call.args[0].input.TableName === remediationConfigTableName),
    ).toHaveLength(0);
    // The per-account failures were still recorded for diagnosis.
    expect(recordedMemberStates()[ACCOUNT_A].status).toBe('FAILED');
    expect(recordedMemberStates()[ACCOUNT_B].status).toBe('FAILED');
  });

  it('records each released account’s installed version on the runbook record', async () => {
    // Roles succeed everywhere; ACCOUNT_A's document install returns v7, ACCOUNT_B's throttles.
    setupSsmMock((callIndex) => {
      if (callIndex === 1) return { DocumentDescription: { DocumentVersion: '7' } };
      throw new Error('throttled');
    });

    await service().execute({ ...deployParams, member_account_ids: [ACCOUNT_A, ACCOUNT_B] });

    expect(recordedMemberStates()).toEqual({
      [ACCOUNT_A]: { runbookVersion: 2, ssmDocumentVersion: '7', status: 'DEPLOYED', attemptedAt: NOW },
      [ACCOUNT_B]: {
        runbookVersion: 2,
        ssmDocumentVersion: ADMIN_DOC_VERSION,
        status: 'FAILED',
        attemptedAt: NOW,
        error: 'throttled',
      },
    });
  });

  it('keeps a failed account on the version it was last known to run', async () => {
    // ACCOUNT_B previously ran v1; ACCOUNT_A succeeds so the deploy isn't an all-fail,
    // and ACCOUNT_B's install throttles — its recorded state must keep v1, not the target.
    dynamoMock.on(QueryCommand).resolves({
      Items: [
        metadata(2, {
          [ACCOUNT_B]: {
            runbookVersion: 1,
            ssmDocumentVersion: '1',
            status: 'PENDING',
            attemptedAt: '2025-12-01T00:00:00.000Z',
          },
        }),
      ],
      Count: 1,
    });
    setupSsmMock((callIndex) => {
      if (callIndex === 1) return { DocumentDescription: { DocumentVersion: '2' } };
      throw new Error('throttled');
    });

    await service().execute({ ...deployParams, member_account_ids: [ACCOUNT_A, ACCOUNT_B] });

    expect(recordedMemberStates()[ACCOUNT_B]).toEqual({
      runbookVersion: 1,
      ssmDocumentVersion: '1',
      status: 'FAILED',
      attemptedAt: NOW,
      error: 'throttled',
    });
  });

  it('reports the fleet as inconsistent while an account is still pending release', async () => {
    dynamoMock.on(QueryCommand).resolves({
      Items: [
        metadata(2, {
          [ACCOUNT_A]: { runbookVersion: 1, ssmDocumentVersion: '1', status: 'PENDING', attemptedAt: NOW },
          [ACCOUNT_B]: { runbookVersion: 1, ssmDocumentVersion: '1', status: 'PENDING', attemptedAt: NOW },
        }),
      ],
      Count: 1,
    });

    const result = await service().execute({ ...deployParams, member_account_ids: [ACCOUNT_A] });

    expect(result.version_consistency).toEqual({
      consistent: false,
      target_version: 2,
      accounts_on_target: [ACCOUNT_A],
      accounts_pending_release: [{ accountId: ACCOUNT_B, runbookVersion: 1 }],
      accounts_failed: [],
    });
  });

  it('reports the fleet as consistent once every known account runs the target version', async () => {
    dynamoMock.on(QueryCommand).resolves({
      Items: [
        metadata(2, {
          [ACCOUNT_A]: { runbookVersion: 1, ssmDocumentVersion: '1', status: 'PENDING', attemptedAt: NOW },
        }),
      ],
      Count: 1,
    });

    const result = await service().execute({ ...deployParams, member_account_ids: [ACCOUNT_A] });

    expect(result.version_consistency).toEqual({
      consistent: true,
      target_version: 2,
      accounts_on_target: [ACCOUNT_A],
      accounts_pending_release: [],
      accounts_failed: [],
    });
  });

  it('rejects a deploy that names no member accounts, before any AWS-side writes', async () => {
    // A deploy releases the runbook copy-per-member; naming no account cannot
    // produce a working remediation, so it must be rejected rather than writing a
    // DEPLOYED record that can run nowhere. The Zod schema rejects an empty array
    // upstream; passing [] here exercises the service's own defense-in-depth guard
    // on the direct-caller path.
    await expect(service().execute({ ...deployParams, member_account_ids: [] })).rejects.toMatchObject({
      statusCode: 400,
    });

    // Nothing was created or assumed into: no admin document, no member hops, no
    // remediation role, no recorded state.
    expect(ssmMock.commandCalls(CreateDocumentCommand)).toHaveLength(0);
    expect(memberHopArns()).toHaveLength(0);
    expect(iamMock.calls()).toHaveLength(0);
    expect(recordedMemberStates()).toEqual({});
  });

  // The test-before-deploy gate (assertVersionPassedTest). A version reaches deploy
  // only after test_runbook_yaml records a PASSED result bound to the registered
  // content and the exact requested IAM actions; each case below is a way that
  // binding is absent or broken, and must be refused before any AWS side effect.
  describe('test-before-deploy gate', () => {
    /** Seed findLatestVersion with a metadata whose test fields are overridden. */
    function seedMetadata(overrides: Partial<RunbookMetadata>): void {
      dynamoMock.on(QueryCommand).resolves({ Items: [{ ...metadata(2), ...overrides }], Count: 1 });
    }

    async function expectDeployRejected(): Promise<void> {
      await expect(service().execute({ ...deployParams, member_account_ids: [ACCOUNT_A] })).rejects.toMatchObject({
        statusCode: 400,
      });
      // Rejected before any SSM/IAM side effect.
      expect(ssmMock.commandCalls(CreateDocumentCommand)).toHaveLength(0);
      expect(iamMock.calls()).toHaveLength(0);
      expect(recordedMemberStates()).toEqual({});
    }

    it('refuses a version that was never tested (testStatus undefined)', async () => {
      seedMetadata({ testStatus: undefined });
      await expectDeployRejected();
    });

    it('refuses a version whose recorded test FAILED', async () => {
      seedMetadata({ testStatus: 'FAILED' });
      await expectDeployRejected();
    });

    it('refuses a version whose tested content is not the registered content', async () => {
      // A re-register after testing leaves registeredContentDigest ahead of the
      // digest the pass was recorded against, so the bytes about to deploy were
      // never the bytes proven.
      seedMetadata({ registeredContentDigest: 'new-content', testedContentDigest: 'old-content' });
      await expectDeployRejected();
    });

    it('refuses a version tested with a different IAM action set than requested', async () => {
      // Proven with only GetBucketLogging, but the deploy requests PutBucketLogging
      // — the remediation would run with a permission its test never exercised.
      seedMetadata({ testedIamActions: ['s3:GetBucketLogging'] });
      await expectDeployRejected();
    });

    it('refuses a version requesting a superset of the tested IAM actions', async () => {
      // deployParams requests exactly [s3:PutBucketLogging]; a version tested with
      // that plus an extra action is not a match either — the sets must be equal.
      seedMetadata({ testedIamActions: ['s3:PutBucketLogging', 's3:GetBucketLogging'] });
      await expectDeployRejected();
    });
  });
});
