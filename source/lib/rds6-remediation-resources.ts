// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import * as cdk from 'aws-cdk-lib';
import { Effect, Policy, PolicyStatement, Role, ServicePrincipal, CfnRole } from 'aws-cdk-lib/aws-iam';
import { Construct } from 'constructs';

export interface IRds6EnhancedMonitoringRole {
  roleName: string;
}

export class Rds6EnhancedMonitoringRole extends Construct {
  constructor(scope: Construct, id: string, props: IRds6EnhancedMonitoringRole) {
    super(scope, id);
    const stack = cdk.Stack.of(this);

    const rds6Policy = new Policy(this, 'RDS6-Enhanced-Monitoring-Policy');

    const logs1Perms = new PolicyStatement({
      effect: Effect.ALLOW,
      sid: 'EnableCreationAndManagementOfRDSCloudwatchLogGroups',
    });
    logs1Perms.addActions('logs:CreateLogGroup');
    logs1Perms.addActions('logs:PutRetentionPolicy');
    logs1Perms.addResources(`arn:${stack.partition}:logs:*:${stack.account}:log-group:RDS*`);
    rds6Policy.addStatements(logs1Perms);

    const logs2Perms = new PolicyStatement({
      effect: Effect.ALLOW,
      sid: 'EnableCreationAndManagementOfRDSCloudwatchLogStreams',
    });
    logs2Perms.addActions('logs:CreateLogStream');
    logs2Perms.addActions('logs:PutLogEvents');
    logs2Perms.addActions('logs:DescribeLogStreams');
    logs2Perms.addActions('logs:GetLogEvents');
    logs2Perms.addResources(`arn:${stack.partition}:logs:*:${stack.account}:log-group:RDS*:log-stream:*`);
    rds6Policy.addStatements(logs2Perms);

    // AssumeRole Policy
    const principalPolicyStatement = new PolicyStatement();
    principalPolicyStatement.addActions('sts:AssumeRole');
    principalPolicyStatement.effect = Effect.ALLOW;

    const serviceprincipal = new ServicePrincipal('monitoring.rds.amazonaws.com');
    serviceprincipal.addToPolicy(principalPolicyStatement);

    const rds6Role = new Role(this, 'Rds6EnhancedMonitoringRole', {
      assumedBy: serviceprincipal,
      roleName: props.roleName,
    });

    rds6Role.attachInlinePolicy(rds6Policy);
    rds6Role.applyRemovalPolicy(cdk.RemovalPolicy.RETAIN);

    const roleResource = rds6Role.node.findChild('Resource') as CfnRole;
    roleResource.cfnOptions.metadata = {
      cfn_nag: {
        rules_to_suppress: [
          {
            id: 'W28',
            reason: 'Static names required to allow use in automated remediation runbooks.',
          },
        ],
      },
    };
  }
}
