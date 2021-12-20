#!/usr/bin/env node
/*****************************************************************************
 *  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.   *
 *                                                                            *
 *  Licensed under the Apache License, Version 2.0 (the "License"). You may   *
 *  not use this file except in compliance with the License. A copy of the    *
 *  License is located at                                                     *
 *                                                                            *
 *      http://www.apache.org/licenses/LICENSE-2.0                            *
 *                                                                            *
 *  or in the 'license' file accompanying this file. This file is distributed *
 *  on an 'AS IS' BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,        *
 *  express or implied. See the License for the specific language governing   *
 *  permissions and limitations under the License.                            *
 *****************************************************************************/

import * as cdk from '@aws-cdk/core';
import { 
    Effect, 
    Policy, 
    PolicyStatement, 
    Role,
    ServicePrincipal,
    CfnRole
} from '@aws-cdk/aws-iam';

export interface IRds6EnhancedMonitoringRole {
    roleName: string;
}

export class Rds6EnhancedMonitoringRole extends cdk.Construct {

  constructor(scope: cdk.Construct, id: string, props: IRds6EnhancedMonitoringRole) {
    super(scope, id);
    const stack = cdk.Stack.of(this)

    const rds6Policy = new Policy(this, 'RDS6-Enhanced-Monitoring-Policy')
     
    const logs1Perms = new PolicyStatement({
        effect: Effect.ALLOW,
        sid: 'EnableCreationAndManagementOfRDSCloudwatchLogGroups'
    });
    logs1Perms.addActions("logs:CreateLogGroup")
    logs1Perms.addActions("logs:PutRetentionPolicy")
    logs1Perms.addResources(
        `arn:${stack.partition}:logs:*:${stack.account}:log-group:RDS*`
    );
    rds6Policy.addStatements(logs1Perms)

    const logs2Perms = new PolicyStatement({
        effect: Effect.ALLOW,
        sid: 'EnableCreationAndManagementOfRDSCloudwatchLogStreams'
    });
    logs2Perms.addActions("logs:CreateLogStream")
    logs2Perms.addActions("logs:PutLogEvents")
    logs2Perms.addActions("logs:DescribeLogStreams")
    logs2Perms.addActions("logs:GetLogEvents")
    logs2Perms.addResources(
        `arn:${stack.partition}:logs:*:${stack.account}:log-group:RDS*:log-stream:*`
    );
    rds6Policy.addStatements(logs2Perms)

    // AssumeRole Policy
    let principalPolicyStatement = new PolicyStatement();
    principalPolicyStatement.addActions("sts:AssumeRole");
    principalPolicyStatement.effect = Effect.ALLOW;

    let serviceprincipal = new ServicePrincipal('monitoring.rds.amazonaws.com')
    serviceprincipal.addToPolicy(principalPolicyStatement);

    let rds6Role = new Role(this, 'Rds6EnhancedMonitoringRole', {
        assumedBy: serviceprincipal,
        roleName: props.roleName
    });

    rds6Role.attachInlinePolicy(rds6Policy)
    rds6Role.applyRemovalPolicy(cdk.RemovalPolicy.RETAIN)

    let roleResource = rds6Role.node.findChild('Resource') as CfnRole;
    roleResource.cfnOptions.metadata = {
        cfn_nag: {
            rules_to_suppress: [{
                id: 'W28',
                reason: 'Static names required to allow use in automated remediation runbooks.'
            }]
        }
    };
  }
}