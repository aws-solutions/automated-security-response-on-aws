// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import {
  CreateRoleCommand,
  DeleteRoleCommand,
  DeleteRolePolicyCommand,
  EntityAlreadyExistsException,
  GetRoleCommand,
  IAMClient,
  NoSuchEntityException,
  PutRolePermissionsBoundaryCommand,
  PutRolePolicyCommand,
  TagRoleCommand,
  UpdateAssumeRolePolicyCommand,
} from '@aws-sdk/client-iam';
import { checkIamAction } from '@asr/data-models';
import { createHash } from 'node:crypto';
import { getSleeper, type Sleeper } from '../../../common/utils/sleeper';
import { ValidationError } from './errors';

const SOLUTION_PREFIX = 'SO0111';
export const CUSTOM_RUNBOOK_TEST_ROLE_PREFIX = `${SOLUTION_PREFIX}-Remediate-Custom-Test-`;

/**
 * Settle delay after creating a new test role, before its ARN is handed to
 * StartAutomationExecution. IAM role creation is eventually consistent and there is no
 * waiter for assumability, so SSM can otherwise fail to assume a role that has not yet
 * propagated. Ten seconds is the common guidance for IAM propagation and stays well
 * within the tool's overall poll budget; it is only paid once per newly created role.
 */
const ROLE_PROPAGATION_DELAY_MS = 10_000;
const TEST_ROLE_POLICY_NAME = 'ASR-Custom-Runbook-Test';

export interface ProvisionCustomRunbookTestRoleParams {
  readonly runbookId: string;
  readonly version: number;
  readonly requiredIamActions: readonly string[];
  readonly accountId: string;
  readonly partition: string;
  readonly region: string;
  readonly permissionsBoundaryArn: string;
  /**
   * A token unique to this test execution. It is folded into the role name so two
   * concurrent tests never share a role — otherwise one test's post-run cleanup could
   * delete a role while another execution's SSM automation is still assuming it. The
   * caller supplies its per-execution id (e.g. the transient document name).
   */
  readonly executionId: string;
}

export interface ProvisionedCustomRunbookTestRole {
  readonly roleArn: string;
  readonly requiredIamActions: readonly string[];
}

/** Provisions the version-and-permission-set-scoped role used by a recorded runbook test. */
export class CustomRunbookTestRoleService {
  constructor(
    private readonly iamClientFactory: (region: string) => IAMClient = (region) => new IAMClient({ region }),
    private readonly sleeper: Sleeper = getSleeper(),
  ) {}

  async provisionRole(params: ProvisionCustomRunbookTestRoleParams): Promise<ProvisionedCustomRunbookTestRole> {
    const requiredIamActions = canonicalizeRequiredIamActions(params.requiredIamActions);
    const roleName = buildTestRoleName(params.runbookId, params.version, requiredIamActions, params.executionId);
    const roleArn = `arn:${params.partition}:iam::${params.accountId}:role/${roleName}`;
    const iamClient = this.iamClientFactory(params.region);
    const trustPolicy = JSON.stringify({
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Allow',
          Principal: { Service: 'ssm.amazonaws.com' },
          Action: 'sts:AssumeRole',
        },
      ],
    });

    // A pre-existing role has already propagated and is assumable, so its reuse
    // needs no settle delay. Only a freshly created role does.
    let roleWasCreated = false;
    if (await this.roleExists(iamClient, roleName)) {
      await this.enforceBoundaryThenTrust(iamClient, roleName, trustPolicy, params.permissionsBoundaryArn);
    } else {
      try {
        await iamClient.send(
          new CreateRoleCommand({
            RoleName: roleName,
            AssumeRolePolicyDocument: trustPolicy,
            PermissionsBoundary: params.permissionsBoundaryArn,
            Description: `ASR Custom Runbook test role for version ${params.version}`,
            Tags: [
              { Key: 'aws-solutions:solution-id', Value: SOLUTION_PREFIX },
              { Key: 'aws-solutions:custom-runbook-test', Value: params.runbookId },
            ],
          }),
        );
        roleWasCreated = true;
      } catch (error) {
        if (isEntityAlreadyExists(error)) {
          await this.enforceBoundaryThenTrust(iamClient, roleName, trustPolicy, params.permissionsBoundaryArn);
        } else {
          throw error;
        }
      }
    }

    await iamClient.send(
      new PutRolePolicyCommand({
        RoleName: roleName,
        PolicyName: TEST_ROLE_POLICY_NAME,
        PolicyDocument: buildTestRolePolicy(params, roleArn, requiredIamActions),
      }),
    );
    await iamClient.send(
      new TagRoleCommand({
        RoleName: roleName,
        Tags: [
          { Key: 'aws-solutions:solution-id', Value: SOLUTION_PREFIX },
          { Key: 'aws-solutions:custom-runbook-test', Value: params.runbookId },
        ],
      }),
    );

    // IAM role creation is eventually consistent: the caller passes this ARN straight
    // to StartAutomationExecution, and SSM assuming a role that has not yet propagated
    // fails with an opaque "cannot assume role" error on the first attempt. There is no
    // IAM waiter for assumability (waitUntilRoleExists only confirms GetRole succeeds,
    // not that the trust policy has propagated), so a newly created role is given a
    // bounded settle delay before it is used. A reused role has already propagated.
    if (roleWasCreated) {
      await this.sleeper.sleep(ROLE_PROPAGATION_DELAY_MS);
    }

    return { roleArn, requiredIamActions };
  }

  /**
   * Best-effort deletion of a test role provisioned by {@link provisionRole}.
   *
   * The role is created per (runbookId, version, requiredIamActions) and reused across
   * identical test runs, but nothing else reaps it, so a test that does not clean up leaks
   * an IAM role against the account's role quota. Deletion mirrors the transient-document
   * cleanup: it runs after the execution and is best-effort — a failure is returned, never
   * thrown, because failing to delete housekeeping state must not fail the test itself. The
   * inline policy is removed before the role (DeleteRole rejects a role that still has one).
   */
  async tryDeleteRole(
    roleArn: string,
    region: string,
  ): Promise<{ readonly deleted: boolean; readonly deleteError: string | undefined }> {
    const roleName = roleArn.split('/').pop();
    if (!roleName) {
      return { deleted: false, deleteError: `Could not derive a role name from ARN "${roleArn}"` };
    }
    const iamClient = this.iamClientFactory(region);
    const isNoSuchEntity = (error: unknown): boolean =>
      error instanceof NoSuchEntityException || (error instanceof Error && error.name === 'NoSuchEntityException');
    try {
      // The inline policy must go first; a permissions boundary does not block DeleteRole.
      // Tolerate a missing policy per-call: a prior partial cleanup (or a concurrent
      // identical test) may already have removed it, and that must not stop us from
      // deleting the role itself — otherwise a retry would leak the very role this method
      // exists to reap.
      try {
        await iamClient.send(new DeleteRolePolicyCommand({ RoleName: roleName, PolicyName: TEST_ROLE_POLICY_NAME }));
      } catch (error) {
        if (!isNoSuchEntity(error)) throw error;
      }
      await iamClient.send(new DeleteRoleCommand({ RoleName: roleName }));
      return { deleted: true, deleteError: undefined };
    } catch (error) {
      // A NoSuchEntity on the role means someone already removed it (or a concurrent
      // identical test did) — treat that as success rather than a leak to worry about.
      if (isNoSuchEntity(error)) {
        return { deleted: true, deleteError: undefined };
      }
      return { deleted: false, deleteError: error instanceof Error ? error.message : String(error) };
    }
  }

  private async roleExists(iamClient: IAMClient, roleName: string): Promise<boolean> {
    try {
      await iamClient.send(new GetRoleCommand({ RoleName: roleName }));
      return true;
    } catch (error) {
      if (
        error instanceof NoSuchEntityException ||
        (error instanceof Error && error.name === 'NoSuchEntityException')
      ) {
        return false;
      }
      throw error;
    }
  }

  private async enforceBoundaryThenTrust(
    iamClient: IAMClient,
    roleName: string,
    trustPolicy: string,
    permissionsBoundaryArn: string,
  ): Promise<void> {
    // Boundary first: a partial update must never make an existing unbounded role
    // newly assumable by SSM.
    await iamClient.send(
      new PutRolePermissionsBoundaryCommand({ RoleName: roleName, PermissionsBoundary: permissionsBoundaryArn }),
    );
    await iamClient.send(new UpdateAssumeRolePolicyCommand({ RoleName: roleName, PolicyDocument: trustPolicy }));
  }
}

function buildTestRoleName(
  runbookId: string,
  version: number,
  requiredIamActions: readonly string[],
  executionId: string,
): string {
  // Fold an execution-unique token into the identity so every test run gets its own
  // role. Two concurrent tests — even for the same version and permission set — must not
  // share a role: cleanup deletes the role after each run, so a shared role could be
  // torn down while another execution's SSM automation is still assuming it.
  const roleDigest = createHash('sha256')
    .update(JSON.stringify({ runbookId, version, requiredIamActions, executionId }), 'utf8')
    .digest('hex')
    .slice(0, 32);
  return `${CUSTOM_RUNBOOK_TEST_ROLE_PREFIX}${roleDigest}`;
}

function canonicalizeRequiredIamActions(requiredIamActions: readonly string[]): readonly string[] {
  if (requiredIamActions.length === 0) {
    throw new ValidationError(
      'test_runbook_yaml: required_iam_actions must name the permissions the registered runbook needs.',
    );
  }

  for (const action of requiredIamActions) {
    const validationMessage = checkIamAction(action, 'required_iam_actions');
    if (validationMessage) throw new ValidationError(`test_runbook_yaml: ${validationMessage}`);
  }
  return [...new Set(requiredIamActions)].sort((a, b) => a.localeCompare(b));
}

function buildTestRolePolicy(
  params: ProvisionCustomRunbookTestRoleParams,
  roleArn: string,
  requiredIamActions: readonly string[],
): string {
  return JSON.stringify({
    Version: '2012-10-17',
    Statement: [
      {
        Effect: 'Allow',
        Action: ['ssm:GetParameters', 'ssm:GetParameter', 'ssm:PutParameter'],
        Resource: `arn:${params.partition}:ssm:*:${params.accountId}:parameter/Solutions/${SOLUTION_PREFIX}/*`,
      },
      {
        Effect: 'Allow',
        Action: 'iam:PassRole',
        Resource: roleArn,
        Condition: { StringEquals: { 'iam:PassedToService': 'ssm.amazonaws.com' } },
      },
      {
        Effect: 'Allow',
        Action: ['ssm:StartAutomationExecution', 'ssm:GetAutomationExecution', 'ssm:DescribeAutomationStepExecutions'],
        Resource: [
          `arn:${params.partition}:ssm:*:${params.accountId}:document/ASR-Custom-*`,
          `arn:${params.partition}:ssm:*:${params.accountId}:automation-definition/*`,
          `arn:${params.partition}:ssm:*::automation-definition/*`,
          `arn:${params.partition}:ssm:*:${params.accountId}:automation-execution/*`,
        ],
      },
      {
        Effect: 'Allow',
        Action: requiredIamActions,
        Resource: '*',
      },
    ],
  });
}

function isEntityAlreadyExists(error: unknown): boolean {
  return (
    error instanceof EntityAlreadyExistsException ||
    (error instanceof Error && error.name === 'EntityAlreadyExistsException')
  );
}
