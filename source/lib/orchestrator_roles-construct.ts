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
    PolicyStatement, 
    Effect, 
    Role, 
    PolicyDocument, 
    ArnPrincipal,
    ServicePrincipal,
    CompositePrincipal, 
    CfnRole 
} from '@aws-cdk/aws-iam';

export interface OrchRoleProps {
    solutionId: string;
    adminAccountId: string;
    adminRoleName: string;
}

export class OrchestratorMemberRole extends cdk.Construct {
  constructor(scope: cdk.Construct, id: string, props: OrchRoleProps) {
    super(scope, id);
    const RESOURCE_PREFIX = props.solutionId.replace(/^DEV-/,''); // prefix on every resource name
    const stack = cdk.Stack.of(this);
    const memberPolicy = new PolicyDocument();

    /**
     * @description Cross-account permissions for Orchestration role
     * @type {PolicyStatement}
     */
    const iamPerms = new PolicyStatement();
    iamPerms.addActions(
        "iam:PassRole",
        "iam:GetRole"
    )
    iamPerms.effect = Effect.ALLOW
    iamPerms.addResources(
        `arn:${stack.partition}:iam::${stack.account}:role/${RESOURCE_PREFIX}-*`
    );
    memberPolicy.addStatements(iamPerms)
    const ssmROPerms = new PolicyStatement()
    ssmROPerms.addActions(
        "ssm:DescribeAutomationExecutions",
        "ssm:DescribeDocument",
        "ssm:GetParameters"
    )
    ssmROPerms.effect = Effect.ALLOW;
    ssmROPerms.addResources(
        "arn:" + stack.partition + ":ssm:*:*:*"
    )
    memberPolicy.addStatements(ssmROPerms)

    const ssmRWPerms = new PolicyStatement()
    ssmRWPerms.addActions(
        "ssm:StartAutomationExecution",
        "ssm:GetAutomationExecution"
    )
    ssmRWPerms.addResources(
        // `arn:${stack.partition}:ssm:*:${stack.account}:document/SHARR-*`,
        // `arn:${stack.partition}:ssm:*:${stack.account}:automation-definition/*`,
        // `arn:${stack.partition}:ssm:*:${stack.account}:document/SHARR-*`,
        stack.formatArn({
            service: 'ssm',
            region: '*',
            resource: 'document',
            resourceName: 'SHARR-*',
            sep: '/'
        }),
        stack.formatArn({
            service: 'ssm',
            region: '*',
            resource: 'automation-definition',
            resourceName: '*',
            sep: '/'
        }),
        stack.formatArn({
            service: 'ssm',
            region: '*',
            resource: 'automation-definition',
            account:'',
            resourceName: '*',
            sep: '/'
        }),
        stack.formatArn({
            service: 'ssm',
            region: '*',
            resource: 'automation-execution',
            resourceName: '*',
            sep: '/'
        })
    );
    memberPolicy.addStatements(ssmRWPerms)

    const sechubPerms = new PolicyStatement();
    sechubPerms.addActions("cloudwatch:PutMetricData")
    sechubPerms.addActions("securityhub:BatchUpdateFindings")
    sechubPerms.effect = Effect.ALLOW
    sechubPerms.addResources("*")

    memberPolicy.addStatements(sechubPerms)

    let principalPolicyStatement = new PolicyStatement();

    principalPolicyStatement.addActions("sts:AssumeRole");
    principalPolicyStatement.effect = Effect.ALLOW;

    let roleprincipal = new ArnPrincipal(
        `arn:${stack.partition}:iam::${props.adminAccountId}:role/${props.adminRoleName}`
    );

    let principals = new CompositePrincipal(roleprincipal);
    principals.addToPolicy(principalPolicyStatement);

    let serviceprincipal = new ServicePrincipal('ssm.amazonaws.com')
    principals.addPrincipals(serviceprincipal);

    let memberRole = new Role(this, 'MemberAccountRole', {
        assumedBy: principals,
        inlinePolicies: {
            'member_orchestrator': memberPolicy
        },
        roleName: `${RESOURCE_PREFIX}-SHARR-Orchestrator-Member`
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
    }
  }
}