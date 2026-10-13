// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { Logger } from '@aws-lambda-powertools/logger';
import {
  IAMClient,
  CreateRoleCommand,
  PutRolePolicyCommand,
  DeleteRolePolicyCommand,
  GetRoleCommand,
  UpdateAssumeRolePolicyCommand,
  PutRolePermissionsBoundaryCommand,
  NoSuchEntityException,
  EntityAlreadyExistsException,
  TagRoleCommand,
} from '@aws-sdk/client-iam';
import {
  MemberAccountCredentialsProvider,
  MemberCredentials,
  buildMemberSessionName,
} from './memberAccountCredentials';
import { BadRequestError } from '../../common/utils/httpErrors';
import { checkIamAction } from '@asr/data-models';
import { apiLambdaEnvironment } from '../apiLambdaEnvironment';

const SOLUTION_PREFIX = 'SO0111';

export function validateIamActions(iamActions: readonly string[]): readonly string[] {
  for (const action of iamActions) {
    const message = checkIamAction(action, 'required_iam_actions');
    if (message) throw new BadRequestError(message);
  }
  return iamActions;
}

interface ProvisionRoleParams {
  memberAccountId: string;
  roleName: string;
  iamActions: readonly string[];
  ssmDocumentName: string;
  controlId: string;
  actor?: string;
}

/**
 * Provisions scoped remediation roles in member accounts for custom runbooks.
 *
 * Uses the existing cross-account trust chain:
 *   API Lambda → Orchestrator Admin Role (same account) → Orchestrator Member Role (member account)
 *
 * The remediation role created in each member account follows the same pattern as
 * built-in roles (SsmRole in ssmplaybook.ts): trusted by the Orchestrator Member Role
 * and the SSM service principal, with a scoped inline policy for the runbook's API calls.
 */
export class CrossAccountRoleService {
  constructor(
    private readonly logger: Logger,
    private readonly credentialsProvider: MemberAccountCredentialsProvider = new MemberAccountCredentialsProvider(),
    private readonly iamClientFactory: (credentials: MemberCredentials) => IAMClient = (credentials) =>
      new IAMClient({ credentials, maxAttempts: 3 }),
  ) {}

  /**
   * Get an IAM client for a member account by assuming through the orchestrator role chain.
   */
  private async getMemberIamClient(memberAccountId: string, actor?: string): Promise<IAMClient> {
    const credentials = await this.credentialsProvider.getCredentials(
      memberAccountId,
      buildMemberSessionName('role-provision', actor),
    );
    return this.iamClientFactory(credentials);
  }

  /**
   * Check if a role already exists in a member account.
   */
  private async roleExists(iamClient: IAMClient, roleName: string): Promise<boolean> {
    try {
      await iamClient.send(new GetRoleCommand({ RoleName: roleName }));
      return true;
    } catch (error) {
      if (error instanceof NoSuchEntityException) return false;
      throw error;
    }
  }

  /**
   * Re-assert the expected trust policy AND the permissions boundary on an
   * already-existing role. The boundary matters most here: an IAM-privileged
   * actor in the member account could pre-create the deterministic role name
   * WITHOUT a boundary, and this service would otherwise attach the
   * caller-controlled inline remediation policy (on `Resource: '*'`) to an
   * unbounded role. Setting the boundary on every existing-role deploy closes
   * that escalation path, matching the boundary the CreateRole path sets.
   */
  private async enforceBoundaryThenTrust(
    iamClient: IAMClient,
    roleName: string,
    trustPolicy: string,
    permissionsBoundaryArn: string,
  ): Promise<void> {
    // Boundary FIRST, trust second, and the order is the security property. Widening trust
    // first makes the role assumable by SSM and the Orchestrator at a moment when it still
    // has no boundary; if the boundary call then fails — throttle, AccessDenied, or the
    // member-roles stack not yet updated so the policy ARN does not resolve — we would have
    // left a role that is newly reachable through the ASR automation path and unbounded,
    // with whatever pre-existing policies it already carried now usable through it. In this
    // order a partial failure leaves the role no more assumable than it was before.
    await iamClient.send(
      new PutRolePermissionsBoundaryCommand({ RoleName: roleName, PermissionsBoundary: permissionsBoundaryArn }),
    );
    await iamClient.send(new UpdateAssumeRolePolicyCommand({ RoleName: roleName, PolicyDocument: trustPolicy }));
  }

  /**
   * Provision a remediation role in a single member account.
   * Creates the role with a trust policy matching the built-in SsmRole pattern
   * and an inline policy scoped to the required IAM actions.
   */
  async provisionRole(params: ProvisionRoleParams): Promise<void> {
    const { memberAccountId, roleName, iamActions, ssmDocumentName, controlId, actor } = params;
    const iamClient = await this.getMemberIamClient(memberAccountId, actor);
    const { AWS_PARTITION } = apiLambdaEnvironment();

    const trustPolicy = JSON.stringify({
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Allow',
          Principal: {
            AWS: `arn:${AWS_PARTITION}:iam::${memberAccountId}:role/${SOLUTION_PREFIX}-ASR-Orchestrator-Member`,
            Service: 'ssm.amazonaws.com',
          },
          Action: 'sts:AssumeRole',
        },
      ],
    });

    // Create the role or update its trust policy if it already exists.
    // Updating the trust policy on existing roles prevents a stale trust from an
    // older deployment and closes the pre-creation attack (an IAM-privileged actor
    // in the member account could pre-create the deterministic role name with a
    // trust policy naming themselves; overwriting it here neutralises that).
    //
    // A PermissionsBoundary is attached so that no inline policy (which the caller
    // controls via required_iam_actions) can exceed what the boundary allows —
    // even if the deny-list misses an escalation primitive, the boundary caps
    // effective permissions. The boundary policy is NOT created by this API
    // package: it is provisioned in each member account by the member-roles
    // infrastructure that also creates the custom-runbook table and bucket. Deploy
    // therefore requires that infrastructure to be present — the whole
    // custom-runbook feature is gated on it — and IAM rejects a role create with a
    // boundary ARN that does not resolve.
    const permissionsBoundaryArn = `arn:${AWS_PARTITION}:iam::${memberAccountId}:policy/${SOLUTION_PREFIX}-ASR-Remediation-Boundary`;

    const isExisting = await this.roleExists(iamClient, roleName);
    if (isExisting) {
      // Role exists — enforce the expected trust policy on every deploy.
      await this.enforceBoundaryThenTrust(iamClient, roleName, trustPolicy, permissionsBoundaryArn);
    } else {
      try {
        await iamClient.send(
          new CreateRoleCommand({
            RoleName: roleName,
            AssumeRolePolicyDocument: trustPolicy,
            PermissionsBoundary: permissionsBoundaryArn,
            Description: `ASR Custom Runbook remediation role for ${controlId}`,
            Tags: [
              { Key: 'aws-solutions:solution-id', Value: SOLUTION_PREFIX },
              { Key: 'aws-solutions:custom-runbook', Value: controlId },
            ],
          }),
        );
      } catch (error) {
        if (error instanceof EntityAlreadyExistsException) {
          // Race: role appeared between GetRole and CreateRole — update trust below.
          await this.enforceBoundaryThenTrust(iamClient, roleName, trustPolicy, permissionsBoundaryArn);
        } else throw error;
      }
    }

    // Base policy: SSM parameter access + PassRole + StartAutomationExecution
    const basePolicy = {
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Allow',
          Action: ['ssm:GetParameters', 'ssm:GetParameter', 'ssm:PutParameter'],
          Resource: `arn:${AWS_PARTITION}:ssm:*:${memberAccountId}:parameter/Solutions/${SOLUTION_PREFIX}/*`,
        },
        {
          Effect: 'Allow',
          Action: ['iam:PassRole'],
          Resource: `arn:${AWS_PARTITION}:iam::${memberAccountId}:role/${roleName}`,
        },
        {
          Effect: 'Allow',
          Action: [
            'ssm:StartAutomationExecution',
            'ssm:GetAutomationExecution',
            'ssm:DescribeAutomationStepExecutions',
          ],
          Resource: [
            `arn:${AWS_PARTITION}:ssm:*:${memberAccountId}:document/${ssmDocumentName}`,
            `arn:${AWS_PARTITION}:ssm:*:${memberAccountId}:document/ASR-Custom-*`,
            `arn:${AWS_PARTITION}:ssm:*:${memberAccountId}:automation-definition/*`,
            `arn:${AWS_PARTITION}:ssm:*::automation-definition/*`,
            `arn:${AWS_PARTITION}:ssm:*:${memberAccountId}:automation-execution/*`,
          ],
        },
        // No sts:AssumeRole on the role's own ARN — SSM Automation's
        // AutomationAssumeRole mechanism handles the assume internally via
        // iam:PassRole, which is already granted above.
      ],
    };

    await iamClient.send(
      new PutRolePolicyCommand({
        RoleName: roleName,
        PolicyName: 'ASR-Custom-Runbook-Base',
        PolicyDocument: JSON.stringify(basePolicy),
      }),
    );

    // Remediation-specific policy with the required IAM actions
    if (iamActions.length > 0) {
      const remediationPolicy = {
        Version: '2012-10-17',
        Statement: [
          {
            Effect: 'Allow',
            Action: iamActions,
            Resource: '*',
          },
        ],
      };

      await iamClient.send(
        new PutRolePolicyCommand({
          RoleName: roleName,
          PolicyName: 'ASR-Custom-Runbook-Remediation',
          PolicyDocument: JSON.stringify(remediationPolicy),
        }),
      );
    } else {
      // Re-deploy narrowed to zero actions: remove any remediation policy left by
      // a prior deploy so the effective grant matches the current (empty) request
      // rather than leaving stale broad permissions on the role.
      try {
        await iamClient.send(
          new DeleteRolePolicyCommand({ RoleName: roleName, PolicyName: 'ASR-Custom-Runbook-Remediation' }),
        );
      } catch (error) {
        // No policy to remove (first-time provision, or none previously set) is fine.
        if (!(error instanceof NoSuchEntityException)) throw error;
      }
    }

    await iamClient.send(
      new TagRoleCommand({
        RoleName: roleName,
        Tags: [
          { Key: 'aws-solutions:solution-id', Value: SOLUTION_PREFIX },
          { Key: 'aws-solutions:custom-runbook', Value: controlId },
        ],
      }),
    );

    this.logger.info('Provisioned remediation role', {
      roleName,
      memberAccountId,
      controlId,
    });
  }

  /**
   * Provision remediation roles across all specified member accounts.
   * Failures in individual accounts are logged but don't block other accounts.
   */
  async provisionRolesInAccounts(
    memberAccountIds: string[],
    roleName: string,
    iamActions: string[],
    ssmDocumentName: string,
    controlId: string,
    actor?: string,
  ): Promise<{
    succeeded: string[];
    failed: Array<{ accountId: string; error: string }>;
  }> {
    const validatedIamActions = validateIamActions(iamActions);

    const succeeded: string[] = [];
    const failed: Array<{ accountId: string; error: string }> = [];

    for (const accountId of memberAccountIds) {
      try {
        await this.provisionRole({
          memberAccountId: accountId,
          roleName,
          iamActions: validatedIamActions,
          ssmDocumentName,
          controlId,
          actor,
        });
        succeeded.push(accountId);
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        this.logger.error('Failed to provision role in member account', {
          accountId,
          roleName,
          error: message,
        });
        failed.push({ accountId, error: message });
      }
    }

    return { succeeded, failed };
  }
}
