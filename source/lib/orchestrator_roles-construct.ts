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
import { addCfnGuardSuppression } from './cdk-helper/add-cfn-nag-suppression';

export interface OrchRoleProps {
  solutionId: string;
  adminAccountId: string;
  adminRoleName: string;
}

export class OrchestratorMemberRole extends Construct {
  constructor(scope: Construct, id: string, props: OrchRoleProps) {
    super(scope, id);
    const RESOURCE_PREFIX = props.solutionId.replace(/^DEV-/, ''); // prefix on every resource name
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
        resource: 'automation-definition',
        resourceName: '*',
        arnFormat: ArnFormat.SLASH_RESOURCE_NAME,
      }),
      stack.formatArn({
        service: 'ssm',
        region: '*',
        resource: 'automation-definition',
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
      // The actions in your policy do not support resource-level permissions and require you to choose All resources
      new PolicyStatement({
        actions: ['ssm:DescribeAutomationExecutions', 'ssm:GetAutomationExecution'],
        resources: ['*'],
        effect: Effect.ALLOW,
      }),
      new PolicyStatement({
        actions: ['ssm:DescribeDocument'],
        resources: [`arn:${stack.partition}:ssm:*:*:document/*`],
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

    const memberRole = new Role(this, 'MemberAccountRole', {
      assumedBy: principals,
      inlinePolicies: {
        member_orchestrator: memberPolicy,
      },
      roleName: `${RESOURCE_PREFIX}-SHARR-Orchestrator-Member`,
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
