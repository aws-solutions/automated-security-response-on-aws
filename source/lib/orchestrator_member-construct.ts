#!/usr/bin/env node
/*****************************************************************************
 *  Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.   *
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

// Create a new stack to deploy a Playbook in a member account
// Orchestrator member role
// Remediation role(s)
// SSM Automation Documents

import * as cdk from '@aws-cdk/core';
import { 
    PolicyStatement, 
    Effect, 
    Role, 
    PolicyDocument, 
    ArnPrincipal, 
    CompositePrincipal, 
    CfnRole 
} from '@aws-cdk/aws-iam';

export interface SHARRStackProps extends cdk.StackProps  {
    solutionId: string;
    solutionVersion: string;
    solutionDistBucket: string;
    solutionDistName: string;
    solutionName: string;
    securityStandard: string;
}

export class MemberStack extends cdk.Stack {

  SEND_ANONYMOUS_DATA = 'Yes'
  public readonly adminAccountNumber: cdk.CfnParameter;

  constructor(scope: cdk.App, id: string, props: SHARRStackProps) {
    super(scope, id, props);

    const validAwsAccount = "\\d{12}"
    const adminRoleName = props.solutionId + '-SHARR-Orchestrator-Admin_' + this.region

    this.adminAccountNumber = new cdk.CfnParameter(this, 'Admin Account Number', {
        description: "Admin account number",
        type: "String",
        allowedPattern: validAwsAccount
    });

    const memberPolicy = new PolicyDocument();
    /**
     * @description Cross-account permissions for Orchestration role
     * @type {PolicyStatement}
     */
    const ssmROPerms = new PolicyStatement()
    ssmROPerms.addActions("ssm:DescribeAutomationExecutions")
    ssmROPerms.addActions("ssm:DescribeDocument")
    ssmROPerms.effect = Effect.ALLOW;
    ssmROPerms.addResources(
        "arn:" + this.partition + ":ssm:" + this.region + ":*:*"
    )
    memberPolicy.addStatements(ssmROPerms)

    let principalPolicyStatement = new PolicyStatement();

    principalPolicyStatement.addActions("sts:AssumeRole");
    principalPolicyStatement.effect = Effect.ALLOW;

    let roleprincipal = new ArnPrincipal(
        'arn:' + this.partition + ':iam::' + this.adminAccountNumber.value + ':role/' +
        adminRoleName
    );

    let principals = new CompositePrincipal(roleprincipal);
    principals.addToPolicy(principalPolicyStatement);

    let memberRole = new Role(this, 'MemberAccountRole', {
        assumedBy: principals,
        inlinePolicies: {
            'default_lambdaPolicy': memberPolicy
        },
        roleName: props.solutionId + '-SHARR-Orchestrator-Member-' + props.securityStandard + '_' + this.region
    });

    const memberRoleResource = memberRole.node.findChild('Resource') as CfnRole;

    memberRoleResource.cfnOptions.metadata = {
        cfn_nag: {
            rules_to_suppress: [{
                id: 'W11',
                reason: 'Resource * is required due to the administrative nature of the solution.'
            },{
                id: 'W28',
                reason: 'Static names chosen intentionally to provide integration in cross-account permissions'
            }]
        }
    };
  }
}


