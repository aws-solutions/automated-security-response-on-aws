// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import * as cdk_nag from 'cdk-nag';
import * as cdk from 'aws-cdk-lib';
import { Effect, Policy, PolicyStatement, Role, ServicePrincipal, CfnRole } from 'aws-cdk-lib/aws-iam';
import { Construct } from 'constructs';
import { addCfnGuardSuppression } from './cdk-helper/add-cfn-nag-suppression';

export interface ISNS2DeliveryStatusLoggingRole {
  roleName: string;
}

export class SNS2DeliveryStatusLoggingRole extends Construct {
  roleArn: string;
  constructor(scope: Construct, id: string, props: ISNS2DeliveryStatusLoggingRole) {
    super(scope, id);

    const deliveryStatusLoggingPolicy = new Policy(this, 'Delivery-Status-Logging-Policy');
    cdk_nag.NagSuppressions.addResourceSuppressions(deliveryStatusLoggingPolicy, [
      { id: 'AwsSolutions-IAM5', reason: 'Resource * is required to allow delivery status logging for any topic.' },
    ]);

    const perms = new PolicyStatement({
      effect: Effect.ALLOW,
      sid: 'EnableDeliveryStatusLoggingForSNSTopic',
    });
    perms.addActions('logs:CreateLogGroup');
    perms.addActions('logs:CreateLogStream');
    perms.addActions('logs:PutLogEvents');
    perms.addActions('logs:PutMetricFilter');
    perms.addActions('logs:PutRetentionPolicy');
    perms.addResources('*');
    deliveryStatusLoggingPolicy.addStatements(perms);

    // AssumeRole Policy
    const principalPolicyStatement = new PolicyStatement();
    principalPolicyStatement.addActions('sts:AssumeRole');
    principalPolicyStatement.effect = Effect.ALLOW;

    const serviceprincipal = new ServicePrincipal('sns.amazonaws.com');
    serviceprincipal.addToPolicy(principalPolicyStatement);

    const deliveryStatusLoggingRole = new Role(this, 'DeliveryStatusLoggingRole', {
      assumedBy: serviceprincipal,
      description: `Role automatically created by ASR for remediation of SNS.2 findings. 
      This role is retained after the solution is deleted to support continuing function 
      of SNS delivery status logging enabled by this remediation. Before removing this 
      role, use IAM access analyzer for confirming it's safe`,
      roleName: props.roleName,
    });

    this.roleArn = deliveryStatusLoggingRole.roleArn;

    deliveryStatusLoggingRole.attachInlinePolicy(deliveryStatusLoggingPolicy);
    deliveryStatusLoggingRole.applyRemovalPolicy(cdk.RemovalPolicy.RETAIN);

    cdk.Tags.of(deliveryStatusLoggingRole).add('SO0111', 'RetainedRole');

    const roleResource = deliveryStatusLoggingRole.node.findChild('Resource') as CfnRole;
    roleResource.cfnOptions.metadata = {
      cfn_nag: {
        rules_to_suppress: [
          {
            id: 'W12',
            reason: 'Resource * is required to allow delivery status logging for any topic.',
          },
        ],
      },
    };
    addCfnGuardSuppression(deliveryStatusLoggingRole, 'CFN_NO_EXPLICIT_RESOURCE_NAMES');
  }
}
