/*****************************************************************************
 *  Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.   *
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
import { PolicyStatement, Effect, Role, PolicyDocument, ArnPrincipal, ServicePrincipal, CompositePrincipal, CfnRole } from '@aws-cdk/aws-iam';

export interface AssumeRoleConstructProps {
    masterAccountNumber: cdk.CfnParameter,
    solutionId: string,
    lambdaPolicy: PolicyDocument,
    lambdaHandlerName: string
    service?: string
}

export class AssumeRoleConstruct extends cdk.Construct {

    constructor(scope: cdk.Construct, id: string, props: AssumeRoleConstructProps) {
        super(scope, id);

        //DEFINE PRINCIPLE RESOURCE WHICH WILL ASSUME THE ROLE.

        let principalPolicyStatement = new PolicyStatement();
        principalPolicyStatement.addActions("sts:AssumeRole");
        principalPolicyStatement.effect = Effect.ALLOW;

        let roleprincipal = new ArnPrincipal('arn:aws:iam::' + props.masterAccountNumber.value + ':role/' +
            props.solutionId + '_' + props.lambdaHandlerName +  '_lambdaRole');

        let principals = new CompositePrincipal(roleprincipal);
        principals.addToPolicy(principalPolicyStatement);

        if (props.service) {
            let serviceprincipal = new ServicePrincipal(props.service)
            principals.addPrincipals(serviceprincipal);
        }

        let lambdaRole = new Role(this, 'MemberAccountRole', {
            assumedBy: principals,
            inlinePolicies: {
                'default_lambdaPolicy': props.lambdaPolicy
            },
            roleName: props.solutionId + '_' + props.lambdaHandlerName + '_memberRole'
        });

        const lambdaRoleResource = lambdaRole.node.findChild('Resource') as CfnRole;

        lambdaRoleResource.cfnOptions.metadata = {
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