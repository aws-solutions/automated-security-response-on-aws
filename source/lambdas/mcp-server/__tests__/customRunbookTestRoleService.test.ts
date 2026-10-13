// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import {
  CreateRoleCommand,
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
import {
  CUSTOM_RUNBOOK_TEST_ROLE_PREFIX,
  CustomRunbookTestRoleService,
} from '../backends/common/customRunbookTestRoleService';

const iamMock = mockClient(IAMClient);
const BOUNDARY_ARN = 'arn:aws:iam::123456789012:policy/SO0111-ASR-Custom-Runbook-Test-Boundary';

function service(): CustomRunbookTestRoleService {
  // No-op sleeper so the IAM-propagation settle delay on the new-role path does not
  // make these tests wait for real; the default IAM client factory still reaches the mock.
  return new CustomRunbookTestRoleService(undefined, { sleep: () => Promise.resolve() });
}

function params(requiredIamActions: readonly string[] = ['s3:PutBucketLogging'], executionId = 'exec-fixed') {
  return {
    runbookId: 'runbook-1',
    version: 7,
    requiredIamActions,
    accountId: '123456789012',
    partition: 'aws',
    region: 'us-east-1',
    permissionsBoundaryArn: BOUNDARY_ARN,
    executionId,
  };
}

describe('CustomRunbookTestRoleService', () => {
  beforeEach(() => {
    iamMock.reset();
    iamMock.on(GetRoleCommand).rejects(Object.assign(new Error('not found'), { name: 'NoSuchEntityException' }));
    iamMock.on(CreateRoleCommand).resolves({});
    iamMock.on(PutRolePolicyCommand).resolves({});
    iamMock.on(TagRoleCommand).resolves({});
    iamMock.on(PutRolePermissionsBoundaryCommand).resolves({});
    iamMock.on(UpdateAssumeRolePolicyCommand).resolves({});
  });

  afterAll(() => iamMock.restore());

  it('creates a bounded role and canonicalizes the exact remediation actions it grants', async () => {
    const result = await service().provisionRole(
      params(['s3:PutBucketLogging', 's3:GetBucketLogging', 's3:PutBucketLogging']),
    );

    const createInput = iamMock.commandCalls(CreateRoleCommand)[0].args[0].input;
    expect(createInput.RoleName).toMatch(new RegExp(`^${CUSTOM_RUNBOOK_TEST_ROLE_PREFIX}`));
    expect(createInput.RoleName?.length).toBeLessThanOrEqual(64);
    expect(createInput.PermissionsBoundary).toBe(BOUNDARY_ARN);
    expect(result.roleArn).toBe(`arn:aws:iam::123456789012:role/${createInput.RoleName}`);
    expect(result.requiredIamActions).toEqual(['s3:GetBucketLogging', 's3:PutBucketLogging']);

    const policy = JSON.parse(iamMock.commandCalls(PutRolePolicyCommand)[0].args[0].input.PolicyDocument ?? '{}') as {
      Statement: Array<{ Action: string | string[]; Resource: unknown; Condition?: unknown }>;
    };
    expect(policy.Statement).toContainEqual(
      expect.objectContaining({
        Effect: 'Allow',
        Action: ['s3:GetBucketLogging', 's3:PutBucketLogging'],
        Resource: '*',
      }),
    );
    expect(policy.Statement).toContainEqual(
      expect.objectContaining({
        Action: 'iam:PassRole',
        Resource: result.roleArn,
        Condition: { StringEquals: { 'iam:PassedToService': 'ssm.amazonaws.com' } },
      }),
    );
  });

  it('uses different role names for different permission sets on the same version', async () => {
    const first = await service().provisionRole(params(['s3:GetBucketLogging']));
    iamMock.reset();
    iamMock.on(GetRoleCommand).rejects(Object.assign(new Error('not found'), { name: 'NoSuchEntityException' }));
    iamMock.on(CreateRoleCommand).resolves({});
    iamMock.on(PutRolePolicyCommand).resolves({});
    iamMock.on(TagRoleCommand).resolves({});

    const second = await service().provisionRole(params(['s3:PutBucketLogging']));

    expect(first.roleArn).not.toBe(second.roleArn);
  });

  it('uses a unique role per execution so a concurrent identical test cannot delete its role', async () => {
    // Same runbook, version, and permission set — only the execution id differs. The role
    // names must still differ, so one execution's post-run cleanup never tears down a role
    // another execution's SSM automation is still assuming.
    const first = await service().provisionRole(params(['s3:PutBucketLogging'], 'exec-A'));
    iamMock.reset();
    iamMock.on(GetRoleCommand).rejects(Object.assign(new Error('not found'), { name: 'NoSuchEntityException' }));
    iamMock.on(CreateRoleCommand).resolves({});
    iamMock.on(PutRolePolicyCommand).resolves({});
    iamMock.on(TagRoleCommand).resolves({});

    const second = await service().provisionRole(params(['s3:PutBucketLogging'], 'exec-B'));

    expect(first.roleArn).not.toBe(second.roleArn);
  });

  it('attaches the boundary before making an existing role assumable or updating its policy', async () => {
    iamMock.on(GetRoleCommand).resolves({
      Role: {
        Path: '/',
        RoleName: 'existing',
        RoleId: 'role-id',
        Arn: 'arn:aws:iam::123456789012:role/existing',
        CreateDate: new Date('2026-01-01T00:00:00.000Z'),
      },
    });

    await service().provisionRole(params());

    expect(iamMock.calls().map((call) => call.args[0].constructor.name)).toEqual([
      'GetRoleCommand',
      'PutRolePermissionsBoundaryCommand',
      'UpdateAssumeRolePolicyCommand',
      'PutRolePolicyCommand',
      'TagRoleCommand',
    ]);
  });

  it('repairs a create race by enforcing the boundary before updating the role', async () => {
    iamMock
      .on(CreateRoleCommand)
      .rejects(Object.assign(new Error('already exists'), { name: 'EntityAlreadyExistsException' }));

    await service().provisionRole(params());

    const commands = iamMock.calls().map((call) => call.args[0].constructor.name);
    expect(commands.indexOf('PutRolePermissionsBoundaryCommand')).toBeLessThan(
      commands.indexOf('UpdateAssumeRolePolicyCommand'),
    );
    expect(commands.indexOf('UpdateAssumeRolePolicyCommand')).toBeLessThan(commands.indexOf('PutRolePolicyCommand'));
  });

  it('rejects unsafe IAM actions before making any IAM call', async () => {
    await expect(service().provisionRole(params(['iam:CreateRole']))).rejects.toThrow(/required_iam_actions/);
    expect(iamMock.calls()).toHaveLength(0);
  });

  describe('tryDeleteRole', () => {
    const ROLE_ARN = 'arn:aws:iam::123456789012:role/SO0111-ASR-Custom-Runbook-Test-abc123';
    const ROLE_NAME = 'SO0111-ASR-Custom-Runbook-Test-abc123';

    const noSuchEntity = () => Object.assign(new Error('not found'), { name: 'NoSuchEntityException' });

    it('deletes the inline policy before the role and reports success', async () => {
      iamMock.on(DeleteRolePolicyCommand).resolves({});
      iamMock.on(DeleteRoleCommand).resolves({});

      const result = await service().tryDeleteRole(ROLE_ARN, 'us-east-1');

      expect(result).toEqual({ deleted: true, deleteError: undefined });
      const commands = iamMock.calls().map((call) => call.args[0].constructor.name);
      expect(commands.indexOf('DeleteRolePolicyCommand')).toBeLessThan(commands.indexOf('DeleteRoleCommand'));
      expect(iamMock.commandCalls(DeleteRoleCommand)[0].args[0].input.RoleName).toBe(ROLE_NAME);
    });

    it('still deletes the role when the inline policy is already gone, so a retry cannot leak it', async () => {
      // A prior partial cleanup (or a concurrent identical test) removed the inline policy
      // but not the role. The missing policy must be tolerated per-call so DeleteRole is
      // still attempted — otherwise the role this method exists to reap would leak.
      iamMock.on(DeleteRolePolicyCommand).rejects(noSuchEntity());
      iamMock.on(DeleteRoleCommand).resolves({});

      const result = await service().tryDeleteRole(ROLE_ARN, 'us-east-1');

      expect(result).toEqual({ deleted: true, deleteError: undefined });
      expect(iamMock.commandCalls(DeleteRoleCommand)).toHaveLength(1);
    });

    it('treats an already-deleted role as success', async () => {
      iamMock.on(DeleteRolePolicyCommand).resolves({});
      iamMock.on(DeleteRoleCommand).rejects(noSuchEntity());

      const result = await service().tryDeleteRole(ROLE_ARN, 'us-east-1');

      expect(result).toEqual({ deleted: true, deleteError: undefined });
    });

    it('returns the error rather than throwing when the role cannot be deleted', async () => {
      iamMock.on(DeleteRolePolicyCommand).resolves({});
      iamMock.on(DeleteRoleCommand).rejects(new Error('DeleteConflict: role still attached'));

      const result = await service().tryDeleteRole(ROLE_ARN, 'us-east-1');

      expect(result.deleted).toBe(false);
      expect(result.deleteError).toContain('DeleteConflict');
    });

    it('propagates a non-NoSuchEntity failure on the policy delete instead of swallowing it', async () => {
      // A throttle on the policy delete is not "already gone" — it must surface as a
      // failed cleanup, not be mistaken for a tolerated missing policy.
      iamMock.on(DeleteRolePolicyCommand).rejects(new Error('ThrottlingException'));

      const result = await service().tryDeleteRole(ROLE_ARN, 'us-east-1');

      expect(result.deleted).toBe(false);
      expect(result.deleteError).toContain('ThrottlingException');
      expect(iamMock.commandCalls(DeleteRoleCommand)).toHaveLength(0);
    });

    it('reports failure when a role name cannot be derived from the ARN', async () => {
      // A trailing slash yields an empty final segment, so no role name can be derived.
      const result = await service().tryDeleteRole('arn:aws:iam::123456789012:role/', 'us-east-1');

      expect(result.deleted).toBe(false);
      expect(result.deleteError).toContain('Could not derive a role name');
      expect(iamMock.calls()).toHaveLength(0);
    });
  });
});
