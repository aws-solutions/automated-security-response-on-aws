// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { Stack, ArnFormat } from 'aws-cdk-lib';
import {
  PolicyStatement,
  Effect,
  Role,
  PolicyDocument,
  ArnPrincipal,
  ServicePrincipal,
  CompositePrincipal,
  CfnRole,
} from 'aws-cdk-lib/aws-iam';
import { Construct } from 'constructs';
import { addCfnGuardSuppression } from './cdk-helper/add-cfn-guard-suppression';
import { stripDevelopmentPrefix } from './config/cdk-config';

export interface OrchRoleProps {
  solutionId: string;
  adminAccountId: string;
  adminRoleName: string;
}

export class OrchestratorMemberRole extends Construct {
  constructor(scope: Construct, id: string, props: OrchRoleProps) {
    super(scope, id);
    const RESOURCE_PREFIX = stripDevelopmentPrefix(props.solutionId); // prefix on every resource name
    const stack = Stack.of(this);
    const memberPolicy = new PolicyDocument();

    /**
     * @description Cross-account permissions for Orchestration role
     * @type {PolicyStatement}
     */
    const iamPerms = new PolicyStatement();
    iamPerms.addActions('iam:PassRole', 'iam:GetRole');
    iamPerms.effect = Effect.ALLOW;
    iamPerms.addResources(`arn:${stack.partition}:iam::${stack.account}:role/${RESOURCE_PREFIX}-*`);
    memberPolicy.addStatements(iamPerms);

    // sts:AssumeRole into per-control roles (SO0111-{control}-{namespace})
    // for multi-service runbooks. Scoped to SO0111-* in the same account;
    // each per-control role's trust policy independently restricts which
    // principal may assume it.
    const stsAssumePerms = new PolicyStatement();
    stsAssumePerms.addActions('sts:AssumeRole');
    stsAssumePerms.effect = Effect.ALLOW;
    stsAssumePerms.addResources(`arn:${stack.partition}:iam::${stack.account}:role/${RESOURCE_PREFIX}-*`);
    memberPolicy.addStatements(stsAssumePerms);

    // iam:GetAccessKeyLastUsed is used by SC_GuardDuty.IAMUser to resolve the
    // owning IAM user from a bare access-key id. Scoped to user/* since IAM
    // evaluates the action against the user that owns the key.
    const iamGetAccessKeyLastUsedPerms = new PolicyStatement();
    iamGetAccessKeyLastUsedPerms.addActions('iam:GetAccessKeyLastUsed');
    iamGetAccessKeyLastUsedPerms.effect = Effect.ALLOW;
    iamGetAccessKeyLastUsedPerms.addResources(`arn:${stack.partition}:iam::${stack.account}:user/*`);
    memberPolicy.addStatements(iamGetAccessKeyLastUsedPerms);

    const ssmRWPerms = new PolicyStatement();
    ssmRWPerms.addActions('ssm:StartAutomationExecution');
    ssmRWPerms.addResources(
      stack.formatArn({
        service: 'ssm',
        region: '*',
        resource: 'document',
        resourceName: 'ASR-*',
        arnFormat: ArnFormat.SLASH_RESOURCE_NAME,
      }),
      stack.formatArn({
        service: 'ssm',
        region: '*',
        resource: 'document',
        account: '',
        resourceName: '*',
        arnFormat: ArnFormat.SLASH_RESOURCE_NAME,
      }),
      stack.formatArn({
        service: 'ssm',
        region: '*',
        resource: 'automation-execution',
        resourceName: '*',
        arnFormat: ArnFormat.SLASH_RESOURCE_NAME,
      }),
    );
    memberPolicy.addStatements(ssmRWPerms);

    memberPolicy.addStatements(
      // ssm:DescribeAutomationExecutions does not support resource-level
      // permissions and requires Resource '*'.
      new PolicyStatement({
        actions: ['ssm:DescribeAutomationExecutions'],
        resources: ['*'],
        effect: Effect.ALLOW,
      }),
      // ssm:GetAutomationExecution and ssm:DescribeAutomationStepExecutions both
      // support the automation-execution resource type, so scope them to that
      // type rather than '*'.
      // DescribeAutomationStepExecutions lets the GuardDuty.IAMUser control
      // runbook read the ReportContain step of the TargetLocations child
      // execution to capture the backup S3 key needed for a later Restore.
      // The child execution runs in the finding's account/region (from
      // TargetLocations, untrusted and unknown at deploy time), so the account
      // and region segments are wildcarded.
      new PolicyStatement({
        actions: ['ssm:GetAutomationExecution', 'ssm:DescribeAutomationStepExecutions'],
        resources: [
          stack.formatArn({
            service: 'ssm',
            region: '*',
            account: '*',
            resource: 'automation-execution',
            resourceName: '*',
            arnFormat: ArnFormat.SLASH_RESOURCE_NAME,
          }),
        ],
        effect: Effect.ALLOW,
      }),
      new PolicyStatement({
        actions: ['ssm:DescribeDocument'],
        resources: [`arn:${stack.partition}:ssm:*:*:document/*`],
        effect: Effect.ALLOW,
      }),
      // The custom-runbook deploy preflight lists this account's ASR-* built-in documents to
      // block a custom runbook for any control ASR already ships a built-in for, under ANY
      // loaded playbook standard (not just SC). ListDocuments has no resource-level scoping;
      // the deploy service filters the results to ASR-* Automation documents.
      new PolicyStatement({
        actions: ['ssm:ListDocuments'],
        resources: ['*'],
        effect: Effect.ALLOW,
      }),
      new PolicyStatement({
        actions: ['ssm:GetParameters', 'ssm:GetParameter'],
        resources: [`arn:${stack.partition}:ssm:*:*:parameter/Solutions/SO0111/*`],
        effect: Effect.ALLOW,
      }),
      new PolicyStatement({
        actions: ['config:DescribeConfigRules'],
        resources: ['*'],
        effect: Effect.ALLOW,
      }),
    );

    const sechubPerms = new PolicyStatement();
    sechubPerms.addActions('cloudwatch:PutMetricData');
    sechubPerms.addActions('securityhub:BatchUpdateFindings');
    sechubPerms.effect = Effect.ALLOW;
    sechubPerms.addResources('*');

    memberPolicy.addStatements(sechubPerms);

    // Custom Runbook role provisioning — allows the deploy service to create
    // scoped remediation roles in member accounts for custom runbooks.
    memberPolicy.addStatements(
      new PolicyStatement({
        actions: [
          'iam:CreateRole',
          'iam:PutRolePolicy',
          'iam:UpdateAssumeRolePolicy',
          'iam:DeleteRole',
          'iam:DeleteRolePolicy',
          'iam:TagRole',
          // Needed for a role that ALREADY exists: CrossAccountRoleService attaches the
          // boundary with CreateRole for a new role, but reasserts it with
          // PutRolePermissionsBoundary when the role is already there — a redeploy, a
          // retry, or a role left by an earlier attempt. Without this Allow that path
          // fails with an implicit deny and the deploy reports zero accounts installed,
          // permanently, which is how a custom runbook whose role predates the deploy
          // becomes undeployable. The DENY below still constrains WHICH boundary may be
          // set, so this widens reachability, not privilege.
          'iam:PutRolePermissionsBoundary',
        ],
        effect: Effect.ALLOW,
        resources: [`arn:${stack.partition}:iam::${stack.account}:role/${RESOURCE_PREFIX}-Remediate-Custom-*`],
      }),
    );

    // Force the ASR remediation permissions boundary on any role created in that name
    // space. Without this, the Allow above is a privilege-escalation primitive: a
    // compromised orchestrator-member role could mint a Remediate-Custom-* role with an
    // arbitrary trust and inline policy and assume it unbounded. The DENY (which overrides
    // any Allow) requires iam:PermissionsBoundary to equal the boundary the member-roles
    // stack deploys, matching the admin-side guard in mcp-gateway-construct.ts. The boundary
    // ARN is reconstructed by the same fixed-name convention CrossAccountRoleService uses to
    // attach it.
    const remediationBoundaryArn = `arn:${stack.partition}:iam::${stack.account}:policy/${RESOURCE_PREFIX}-ASR-Remediation-Boundary`;
    memberPolicy.addStatements(
      new PolicyStatement({
        sid: 'RequireBoundaryOnCustomRemediationRoles',
        effect: Effect.DENY,
        actions: ['iam:CreateRole', 'iam:PutRolePermissionsBoundary'],
        resources: [`arn:${stack.partition}:iam::${stack.account}:role/${RESOURCE_PREFIX}-Remediate-Custom-*`],
        conditions: {
          StringNotEquals: { 'iam:PermissionsBoundary': remediationBoundaryArn },
        },
      }),
    );

    // The statement above only constrains which boundary may be SET, which makes the
    // escalation-safety of iam:PutRolePolicy and iam:UpdateAssumeRolePolicy depend on the
    // boundary being impossible to remove. Nothing grants DeleteRolePermissionsBoundary
    // today, so this denies an action that is already implicitly denied — stated
    // explicitly so that a later Allow broadening this name space cannot silently turn
    // those two actions into escalation primitives. Unconditional because there is no
    // legitimate reason to strip the boundary from a role in this name space, and because
    // the delete API carries no iam:PermissionsBoundary key for a condition to test.
    memberPolicy.addStatements(
      new PolicyStatement({
        sid: 'DenyBoundaryRemovalOnCustomRemediationRoles',
        effect: Effect.DENY,
        actions: ['iam:DeleteRolePermissionsBoundary'],
        resources: [`arn:${stack.partition}:iam::${stack.account}:role/${RESOURCE_PREFIX}-Remediate-Custom-*`],
      }),
    );

    // Custom Runbook document deployment — every member account holds its own
    // copy of a custom runbook's Automation document instead of running one
    // shared from the admin account, so the deploy service creates and updates
    // documents here. Scoped to the ASR-Custom-* name space, which only custom
    // runbooks use, so built-in ASR documents cannot be rewritten through it.
    // UpdateDocumentDefaultVersion is required because UpdateDocument leaves the
    // previous version as the one an unqualified execution would run.
    memberPolicy.addStatements(
      new PolicyStatement({
        actions: [
          'ssm:CreateDocument',
          'ssm:UpdateDocument',
          'ssm:UpdateDocumentDefaultVersion',
          'ssm:DeleteDocument',
          'ssm:AddTagsToResource',
        ],
        effect: Effect.ALLOW,
        resources: [
          stack.formatArn({
            service: 'ssm',
            region: '*',
            resource: 'document',
            resourceName: 'ASR-Custom-*',
            arnFormat: ArnFormat.SLASH_RESOURCE_NAME,
          }),
        ],
      }),
    );

    const principalPolicyStatement = new PolicyStatement();

    principalPolicyStatement.addActions('sts:AssumeRole');
    principalPolicyStatement.effect = Effect.ALLOW;

    const roleprincipal = new ArnPrincipal(
      `arn:${stack.partition}:iam::${props.adminAccountId}:role/${props.adminRoleName}`,
    );

    const principals = new CompositePrincipal(roleprincipal);
    principals.addToPolicy(principalPolicyStatement);

    const serviceprincipal = new ServicePrincipal('ssm.amazonaws.com');
    principals.addPrincipals(serviceprincipal);

    const memberRole = new Role(this, `MemberAccountRole`, {
      assumedBy: principals,
      inlinePolicies: {
        member_orchestrator: memberPolicy,
      },
      roleName: `${RESOURCE_PREFIX}-ASR-Orchestrator-Member`,
    });

    const memberRoleResource = memberRole.node.findChild('Resource') as CfnRole;

    memberRoleResource.cfnOptions.metadata = {
      cfn_nag: {
        rules_to_suppress: [
          {
            id: 'W11',
            reason: 'Resource * is required due to the administrative nature of the solution.',
          },
          {
            id: 'W28',
            reason: 'Static names chosen intentionally to provide integration in cross-account permissions',
          },
        ],
      },
    };
    addCfnGuardSuppression(memberRole, 'IAM_NO_INLINE_POLICY_CHECK');
  }
}
