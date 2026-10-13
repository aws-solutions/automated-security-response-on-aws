// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { Logger } from '@aws-lambda-powertools/logger';
import {
  CreateRoleCommand,
  DeleteRolePolicyCommand,
  GetRoleCommand,
  IAMClient,
  NoSuchEntityException,
  PutRolePermissionsBoundaryCommand,
  PutRolePolicyCommand,
  TagRoleCommand,
  UpdateAssumeRolePolicyCommand,
} from '@aws-sdk/client-iam';
import { STSClient, AssumeRoleCommand } from '@aws-sdk/client-sts';
import { mockClient } from 'aws-sdk-client-mock';
import { CrossAccountRoleService } from '../../services/crossAccountRoleService';
import { BadRequestError } from '../../../common/utils/httpErrors';
import { MemberAccountCredentialsProvider } from '../../services/memberAccountCredentials';

const iamMock = mockClient(IAMClient);
const stsMock = mockClient(STSClient);

const MEMBER_ACCOUNT_ID = '111111111111';
const ROLE_NAME = 'SO0111-Remediate-Custom-SC-2.0.0-S3.9';

function service(): CrossAccountRoleService {
  // The factory ignores the credentials because mockClient intercepts every IAMClient.
  return new CrossAccountRoleService(
    new Logger({ logLevel: 'SILENT' }),
    new MemberAccountCredentialsProvider(),
    () => new IAMClient({}),
  );
}

describe('CrossAccountRoleService — required_iam_actions validation', () => {
  beforeEach(() => {
    iamMock.reset();
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

  it.each(['iam:CreateRole', 'iam:AttachRolePolicy', 'sts:AssumeRole', 'organizations:LeaveOrganization'])(
    'rejects %s before making any IAM call in any account',
    async (forbiddenAction) => {
      await expect(
        service().provisionRolesInAccounts(
          [MEMBER_ACCOUNT_ID],
          ROLE_NAME,
          ['s3:PutBucketLogging', forbiddenAction],
          'ASR-Custom-SC_2.0.0_S3.9',
          'S3.9',
        ),
      ).rejects.toThrow(BadRequestError);

      expect(iamMock.calls()).toHaveLength(0);
    },
  );

  it('rejects an uppercase service segment as malformed, not as a namespace match', async () => {
    // IAM_ACTION_SHAPE requires a lowercase service segment, so this fails the shape check
    // before FORBIDDEN_IAM_ACTION_NAMESPACES is ever consulted — it throws for being
    // malformed, not because 'IAM' matched the (lowercase) 'iam' namespace entry.
    // Real AWS IAM action strings are always lowercase-service, so this only rejects
    // input that could never have been a legitimate action in the first place.
    await expect(
      service().provisionRolesInAccounts([MEMBER_ACCOUNT_ID], ROLE_NAME, ['IAM:PutRolePolicy'], 'doc', 'S3.9'),
    ).rejects.toThrow(BadRequestError);
  });

  it('rejects a lowercase forbidden namespace regardless of the action name casing', async () => {
    // The namespace match itself IS case-insensitive (via .toLowerCase()), so the action
    // name's casing is irrelevant once the service segment matches a forbidden namespace.
    await expect(
      service().provisionRolesInAccounts([MEMBER_ACCOUNT_ID], ROLE_NAME, ['iam:PutRolePolicy'], 'doc', 'S3.9'),
    ).rejects.toThrow(BadRequestError);
  });

  it.each(['*', 'iam*', 'i*', 'sts*', 'organizations*'])(
    'rejects the wildcard/malformed action "%s" that has no well-formed service:Action shape',
    async (bypassAction) => {
      // Granted on Resource: '*', none of these match a startsWith('iam:')-style prefix
      // check, yet each can still resolve to full IAM/STS/Organizations access once IAM
      // evaluates the policy — the exact bypass this shape check exists to close.
      await expect(
        service().provisionRolesInAccounts([MEMBER_ACCOUNT_ID], ROLE_NAME, [bypassAction], 'doc', 'S3.9'),
      ).rejects.toThrow(BadRequestError);

      expect(iamMock.calls()).toHaveLength(0);
    },
  );

  it('rejects an action with no colon at all as malformed', async () => {
    await expect(
      service().provisionRolesInAccounts([MEMBER_ACCOUNT_ID], ROLE_NAME, ['PutBucketLogging'], 'doc', 'S3.9'),
    ).rejects.toThrow(/^required_iam_actions entry/);
  });

  it('rejects an action with a wildcard in the service segment even when a colon is present', async () => {
    // 'ia*:CreateRole' has a colon, so a startsWith check on the literal string 'iam:'
    // would miss it — but it could still expand to match the iam: namespace under IAM's
    // wildcard evaluation, so the shape check rejects any wildcard in the service segment.
    await expect(
      service().provisionRolesInAccounts([MEMBER_ACCOUNT_ID], ROLE_NAME, ['ia*:CreateRole'], 'doc', 'S3.9'),
    ).rejects.toThrow(BadRequestError);
  });

  it.each(['s3:*', 'ec2:*'])('rejects the wildcard in the action name action "%s"', async (serviceWildcard) => {
    await expect(
      service().provisionRolesInAccounts([MEMBER_ACCOUNT_ID], ROLE_NAME, [serviceWildcard], 'doc', 'S3.9'),
    ).rejects.toThrow(/wildcard in the action name/);

    expect(iamMock.calls()).toHaveLength(0);
  });

  it('rejects a partial wildcard in the action name', async () => {
    await expect(
      service().provisionRolesInAccounts([MEMBER_ACCOUNT_ID], ROLE_NAME, ['s3:Put*'], 'doc', 'S3.9'),
    ).rejects.toThrow(/wildcard in the action name/);

    expect(iamMock.commandCalls(CreateRoleCommand)).toHaveLength(0);
  });

  it('allows a hyphenated real AWS service namespace', async () => {
    // execute-api, iot-data, resource-groups, application-autoscaling, etc. are all real
    // AWS service prefixes with hyphens — rejecting them as malformed would be a
    // functional gap, since the hyphen can never spell a forbidden namespace differently.
    iamMock.on(GetRoleCommand).rejects(new NoSuchEntityException({ message: 'not found', $metadata: {} }));
    iamMock.on(CreateRoleCommand).resolves({});
    iamMock.on(PutRolePolicyCommand).resolves({});
    iamMock.on(TagRoleCommand).resolves({});

    const result = await service().provisionRolesInAccounts(
      [MEMBER_ACCOUNT_ID],
      ROLE_NAME,
      ['execute-api:Invoke'],
      'doc',
      'S3.9',
    );

    expect(result.succeeded).toEqual([MEMBER_ACCOUNT_ID]);
    expect(result.failed).toEqual([]);
  });

  it('rejects a single-character ? wildcard in the action name', async () => {
    await expect(
      service().provisionRolesInAccounts([MEMBER_ACCOUNT_ID], ROLE_NAME, ['s3:Get?bjectTagging'], 'doc', 'S3.9'),
    ).rejects.toThrow(/wildcard in the action name/);

    expect(iamMock.commandCalls(CreateRoleCommand)).toHaveLength(0);
  });

  it('does not reject actions that merely contain a forbidden namespace as a substring', async () => {
    iamMock.on(GetRoleCommand).rejects(new NoSuchEntityException({ message: 'not found', $metadata: {} }));
    iamMock.on(CreateRoleCommand).resolves({});
    iamMock.on(PutRolePolicyCommand).resolves({});
    iamMock.on(TagRoleCommand).resolves({});

    // 's3:GetBucketPolicyStatus' contains no forbidden action namespace prefix —
    // confirms the check is a startsWith on the namespace, not a substring scan.
    const result = await service().provisionRolesInAccounts(
      [MEMBER_ACCOUNT_ID],
      ROLE_NAME,
      ['s3:GetBucketPolicyStatus'],
      'doc',
      'S3.9',
    );

    expect(result.succeeded).toEqual([MEMBER_ACCOUNT_ID]);
    expect(result.failed).toEqual([]);
  });

  it('allows a normal deploy through to IAM when no forbidden action is present', async () => {
    iamMock.on(GetRoleCommand).rejects(new NoSuchEntityException({ message: 'not found', $metadata: {} }));
    iamMock.on(CreateRoleCommand).resolves({});
    iamMock.on(PutRolePolicyCommand).resolves({});
    iamMock.on(TagRoleCommand).resolves({});

    const result = await service().provisionRolesInAccounts(
      [MEMBER_ACCOUNT_ID],
      ROLE_NAME,
      ['s3:PutBucketLogging'],
      'ASR-Custom-SC_2.0.0_S3.9',
      'S3.9',
    );

    expect(result.succeeded).toEqual([MEMBER_ACCOUNT_ID]);
    expect(result.failed).toEqual([]);
    expect(iamMock.commandCalls(CreateRoleCommand)).toHaveLength(1);
  });

  it('re-asserts the permissions boundary (and trust policy) when the role already exists', async () => {
    // GetRole succeeds → existing-role path. The boundary must be re-applied here,
    // not only on CreateRole, so a role pre-created without a boundary cannot
    // receive the caller-controlled inline policy on an unbounded role.
    iamMock.on(GetRoleCommand).resolves({});
    iamMock.on(UpdateAssumeRolePolicyCommand).resolves({});
    iamMock.on(PutRolePermissionsBoundaryCommand).resolves({});
    iamMock.on(PutRolePolicyCommand).resolves({});
    iamMock.on(TagRoleCommand).resolves({});

    const result = await service().provisionRolesInAccounts(
      [MEMBER_ACCOUNT_ID],
      ROLE_NAME,
      ['s3:PutBucketLogging'],
      'ASR-Custom-SC_2.0.0_S3.9',
      'S3.9',
    );

    expect(result.succeeded).toEqual([MEMBER_ACCOUNT_ID]);
    expect(iamMock.commandCalls(CreateRoleCommand)).toHaveLength(0);
    const boundaryCalls = iamMock.commandCalls(PutRolePermissionsBoundaryCommand);
    expect(boundaryCalls).toHaveLength(1);
    expect(boundaryCalls[0].args[0].input).toMatchObject({
      RoleName: ROLE_NAME,
      PermissionsBoundary: `arn:aws:iam::${MEMBER_ACCOUNT_ID}:policy/SO0111-ASR-Remediation-Boundary`,
    });
  });

  /**
   * Ordering is the security property, not an implementation detail. Widening trust before
   * the boundary is attached makes the role assumable by SSM and the Orchestrator while it is
   * still unbounded; if the boundary call then fails — throttle, AccessDenied, or the
   * member-roles stack not yet updated so the policy ARN does not resolve — an
   * IAM-privileged actor who pre-created this deterministic role name keeps whatever
   * policies it already carried, now reachable through the ASR automation path.
   *
   * Asserted on the adopt-existing-role path, which is the only one where a pre-existing
   * role can carry pre-existing policies. CreateRole attaches the boundary atomically.
   */
  it('attaches the permissions boundary before widening trust on an existing role', async () => {
    iamMock.on(GetRoleCommand).resolves({});
    iamMock.on(UpdateAssumeRolePolicyCommand).resolves({});
    iamMock.on(PutRolePermissionsBoundaryCommand).resolves({});
    iamMock.on(PutRolePolicyCommand).resolves({});
    iamMock.on(TagRoleCommand).resolves({});

    await service().provisionRolesInAccounts(
      [MEMBER_ACCOUNT_ID],
      ROLE_NAME,
      ['s3:PutBucketLogging'],
      'ASR-Custom-SC_2.0.0_S3.9',
      'S3.9',
    );

    const ordered = iamMock
      .calls()
      .map((call) => call.args[0].constructor.name)
      .filter((name) => name === 'PutRolePermissionsBoundaryCommand' || name === 'UpdateAssumeRolePolicyCommand');
    expect(ordered).toEqual(['PutRolePermissionsBoundaryCommand', 'UpdateAssumeRolePolicyCommand']);
  });

  it('removes a stale remediation policy when a re-deploy narrows to zero actions', async () => {
    // Existing role, empty iamActions → the broad ASR-Custom-Runbook-Remediation
    // policy from a prior deploy must be deleted so the effective grant matches
    // the current (empty) request rather than persisting stale permissions.
    iamMock.on(GetRoleCommand).resolves({});
    iamMock.on(UpdateAssumeRolePolicyCommand).resolves({});
    iamMock.on(PutRolePermissionsBoundaryCommand).resolves({});
    iamMock.on(PutRolePolicyCommand).resolves({});
    iamMock.on(DeleteRolePolicyCommand).resolves({});
    iamMock.on(TagRoleCommand).resolves({});

    const result = await service().provisionRolesInAccounts([MEMBER_ACCOUNT_ID], ROLE_NAME, [], 'doc', 'S3.9');

    expect(result.succeeded).toEqual([MEMBER_ACCOUNT_ID]);
    const deleteCalls = iamMock.commandCalls(DeleteRolePolicyCommand);
    expect(deleteCalls).toHaveLength(1);
    expect(deleteCalls[0].args[0].input).toMatchObject({
      RoleName: ROLE_NAME,
      PolicyName: 'ASR-Custom-Runbook-Remediation',
    });
  });
});
