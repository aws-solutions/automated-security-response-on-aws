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

export interface InspectorAutomationRoleProps {
  solutionId: string;
  adminAccountId: string;
  adminRoleName: string;
  namespace: string;
}

/**
 * Dedicated, Inspector-scoped SSM Automation role.
 *
 * The Inspector.InstanceVulnerability control runbook uses a native
 * aws:waitForAwsResourceProperty step to wait for AWS-RunPatchBaseline to
 * finish. Native document steps run under the runbook's AutomationAssumeRole,
 * so the waiter needs ssm:GetCommandInvocation. That action does not support
 * resource-level permissions, so it can only be granted on Resource: '*'.
 *
 * To avoid putting that wildcard read on the shared SO0111-ASR-Orchestrator-Member
 * role (which every multi-service control runbook uses), this role is a
 * purpose-built AutomationAssumeRole used ONLY by the Inspector runbook. The
 * orchestrator (resolve_ssm_doc_for_finding.py) resolves Inspector findings to
 * this role instead of Orchestrator-Member, so the GetCommandInvocation
 * wildcard is confined to Inspector remediations. All other multi-service
 * controls remain on Orchestrator-Member, unchanged.
 *
 * The privileged remediation work (SendCommand, IAM, S3, Security Hub) still
 * runs one layer deeper under the per-control RemediationRole, which the
 * runbook scripts assume via STS — this role only grants what the runbook needs
 * to start, assume that role, and read the patch command status.
 */
export class InspectorAutomationRole extends Construct {
  constructor(scope: Construct, id: string, props: InspectorAutomationRoleProps) {
    super(scope, id);
    const resourcePrefix = props.solutionId.replace(/^DEV-/, '');
    const stack = Stack.of(this);
    const roleName = `${resourcePrefix}-ASR-Inspector-Automation`;
    const perControlRoleArn = `arn:${stack.partition}:iam::${stack.account}:role/${resourcePrefix}-Inspector.InstanceVulnerability-${props.namespace}`;

    const role = new Role(this, 'InspectorAutomationMemberRole', {
      assumedBy: this.buildTrustPrincipal(stack, props),
      inlinePolicies: {
        inspector_automation: this.buildInlinePolicy(stack, roleName, perControlRoleArn),
      },
      roleName: roleName,
    });

    // Use defaultChild (the documented CDK accessor for the underlying L1) with
    // an instanceof guard rather than an unchecked `as CfnRole` cast.
    const roleResource = role.node.defaultChild;
    if (!(roleResource instanceof CfnRole)) {
      throw new TypeError('Expected InspectorAutomationRole default child to be a CfnRole');
    }
    roleResource.cfnOptions.metadata = {
      cfn_nag: {
        rules_to_suppress: [
          {
            id: 'W11',
            reason:
              'ssm:GetCommandInvocation does not support resource-level permissions and requires Resource *. ' +
              'It is intentionally isolated to this Inspector-only automation role rather than the shared Orchestrator-Member role.',
          },
          {
            id: 'W28',
            reason:
              'Static name chosen intentionally so the admin orchestrator can resolve it without knowing the member namespace.',
          },
        ],
      },
    };
    addCfnGuardSuppression(role, 'IAM_NO_INLINE_POLICY_CHECK');
  }

  /**
   * Least-privilege inline policy: read the patch command status, start the
   * Inspector runbook, pass itself as the AutomationAssumeRole, assume the
   * per-control RemediationRole, and read the ASR config bucket parameter.
   */
  private buildInlinePolicy(stack: Stack, roleName: string, perControlRoleArn: string): PolicyDocument {
    const policy = new PolicyDocument();

    // The native aws:waitForAwsResourceProperty waiter reads the patch command
    // status. ssm:GetCommandInvocation supports no resource-level permissions,
    // so it must be granted on '*'. This wildcard read is intentionally
    // confined to this single-purpose Inspector-only role rather than the
    // shared Orchestrator-Member role, and should not be migrated to a shared
    // role.
    const getCommandInvocationStatement = new PolicyStatement();
    getCommandInvocationStatement.addActions('ssm:GetCommandInvocation');
    getCommandInvocationStatement.effect = Effect.ALLOW;
    getCommandInvocationStatement.addResources('*');
    policy.addStatements(getCommandInvocationStatement);

    // Start the Inspector control runbook and read its own execution status.
    const automationExecutionStatement = new PolicyStatement();
    automationExecutionStatement.addActions('ssm:StartAutomationExecution', 'ssm:GetAutomationExecution');
    automationExecutionStatement.effect = Effect.ALLOW;
    automationExecutionStatement.addResources(
      stack.formatArn({
        service: 'ssm',
        region: '*',
        resource: 'document',
        resourceName: 'ASR-Inspector.InstanceVulnerability',
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
    policy.addStatements(automationExecutionStatement);

    // Pass itself as the AutomationAssumeRole when starting the runbook.
    const passRoleStatement = new PolicyStatement();
    passRoleStatement.addActions('iam:PassRole');
    passRoleStatement.effect = Effect.ALLOW;
    passRoleStatement.addResources(`arn:${stack.partition}:iam::${stack.account}:role/${roleName}`);
    policy.addStatements(passRoleStatement);

    // Assume the per-control RemediationRole, which the SendPatch/Finalize
    // scripts use for the privileged SSM/EC2/IAM/S3/Security Hub calls. Scoped
    // to exactly the Inspector per-control role.
    const assumePerControlRoleStatement = new PolicyStatement();
    assumePerControlRoleStatement.addActions('sts:AssumeRole');
    assumePerControlRoleStatement.effect = Effect.ALLOW;
    assumePerControlRoleStatement.addResources(perControlRoleArn);
    policy.addStatements(assumePerControlRoleStatement);

    // Read the ASR remediation configuration bucket name (used by the scripts
    // before assuming the per-control role, mirroring Orchestrator-Member).
    const parameterReadStatement = new PolicyStatement();
    parameterReadStatement.addActions('ssm:GetParameters', 'ssm:GetParameter');
    parameterReadStatement.effect = Effect.ALLOW;
    parameterReadStatement.addResources(`arn:${stack.partition}:ssm:*:${stack.account}:parameter/Solutions/SO0111/*`);
    policy.addStatements(parameterReadStatement);

    return policy;
  }

  /**
   * Trust policy: assumable by the admin orchestrator (to start the runbook
   * cross-account) and by SSM Automation (to serve as the runbook's
   * AutomationAssumeRole).
   */
  private buildTrustPrincipal(stack: Stack, props: InspectorAutomationRoleProps): CompositePrincipal {
    const adminPrincipal = new ArnPrincipal(
      `arn:${stack.partition}:iam::${props.adminAccountId}:role/${props.adminRoleName}`,
    );
    const principals = new CompositePrincipal(adminPrincipal);
    const assumeRoleStatement = new PolicyStatement();
    assumeRoleStatement.addActions('sts:AssumeRole');
    assumeRoleStatement.effect = Effect.ALLOW;
    principals.addToPolicy(assumeRoleStatement);
    principals.addPrincipals(new ServicePrincipal('ssm.amazonaws.com'));
    return principals;
  }
}
