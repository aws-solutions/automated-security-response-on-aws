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
import * as fs from 'fs';
import { AdminAccountParm } from '../../lib/admin_account_parm-construct';
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
import { Key } from '@aws-cdk/aws-kms';
import { StringParameter } from '@aws-cdk/aws-ssm';

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

    //--------------------------
    // KMS Customer Managed Key

    // Key Policy
    const kmsKeyPolicy:PolicyDocument = new PolicyDocument()
    const kmsPerms:PolicyStatement = new PolicyStatement();
    kmsPerms.addActions(
        'kms:GenerateDataKey',
        'kms:GenerateDataKeyPair',
        'kms:GenerateDataKeyPairWithoutPlaintext',
        'kms:GenerateDataKeyWithoutPlaintext',
        'kms:Decrypt',
        'kms:Encrypt',
        'kms:ReEncryptFrom',
        'kms:ReEncryptTo',
        'kms:DescribeKey',
        'kms:DescribeCustomKeyStores'
        )
    kmsPerms.effect = Effect.ALLOW
    kmsPerms.addResources("*") // Only the key the policydocument is attached to
    kmsPerms.addPrincipals(new ServicePrincipal('sns.amazonaws.com'))
    kmsPerms.addPrincipals(new ServicePrincipal('s3.amazonaws.com'))
    kmsPerms.addPrincipals(new ServicePrincipal(`logs.${stack.region}.${stack.urlSuffix}`))
    kmsPerms.addPrincipals(new ServicePrincipal(`cloudtrail.${stack.urlSuffix}`))
    kmsKeyPolicy.addStatements(kmsPerms)

    const kmsKey:Key = new Key(this, 'SHARR Remediation Key', {
        enableKeyRotation: true,
        alias: `${RESOURCE_PREFIX}-SHARR-Remediation-Key`,
        trustAccountIdentities: true,
        policy: kmsKeyPolicy
    });

    new StringParameter(this, 'SHARR Key Alias', {
        description: 'KMS Customer Managed Key that will encrypt data for remediations',
        parameterName: `/Solutions/${RESOURCE_PREFIX}/CMK_REMEDIATION_ARN`,
        stringValue: kmsKey.keyArn
    });

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
        "arn:" + stack.partition + ":ssm:" + stack.region + ":*:*"
    )
    memberPolicy.addStatements(ssmROPerms)

    const ssmRWPerms = new PolicyStatement()
    ssmRWPerms.addActions(
        "ssm:StartAutomationExecution",
        "ssm:GetAutomationExecution"
    )
    ssmRWPerms.addResources(
        stack.formatArn({
            service: 'ssm',
            resource: 'document',
            resourceName: 'SHARR-*',
            sep: '/'
        }),
        stack.formatArn({
            service: 'ssm',
            resource: 'automation-definition',
            resourceName: '*',
            sep: '/'
        }),
        stack.formatArn({
            service: 'ssm',
            resource: 'automation-definition',
            account:'',
            resourceName: '*',
            sep: '/'
        }),
        stack.formatArn({
            service: 'ssm',
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
        'arn:' + stack.partition + ':iam::' + props.adminAccountId + ':role/' +
        props.adminRoleName
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
        roleName: RESOURCE_PREFIX + '-SHARR-Orchestrator-Member_' + stack.region
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

export interface SolutionProps {
	description: string;
    solutionId: string;
    solutionDistBucket: string;
    solutionTMN: string;
    solutionVersion: string;
}

export class MemberStack extends cdk.Stack {

  constructor(scope: cdk.App, id: string, props: SolutionProps) {
    super(scope, id, props);

    const stack = cdk.Stack.of(this);
    const RESOURCE_PREFIX = props.solutionId.replace(/^DEV-/,''); // prefix on every resource name
    const adminRoleName = RESOURCE_PREFIX + '-SHARR-Orchestrator-Admin_' + stack.region

    const adminAccount = new AdminAccountParm(this, 'AdminAccountParameter', {
    	solutionId: props.solutionId
    })

    /********************
    ** Parameters
    ********************/

    const logGroupName = new cdk.CfnParameter(this, "LogGroupName",
    {
        type: "String",
        description: "Name of the log group to be used to create metric filters and cloudwatch alarms. You must use a Log Group that is the the logging destination of a multi-region CloudTrail"
    });

    /********************
    ** Metadata
    ********************/

    stack.templateOptions.metadata = {
    "AWS::CloudFormation::Interface": {
        ParameterGroups: [
            {
                Label: {default: "LogGroup Configuration"},
                Parameters: [logGroupName.logicalId]
            }
        ],
        ParameterLabels: {
            [logGroupName.logicalId]: {
                default: "Provide the name of the LogGroup to be used to create Metric Filters and Alarms",
            }
        },
    },
    };

    /*********************************************
    ** Create SSM Parameter to store log group name
    *********************************************/
    new StringParameter(stack, 'SSMParameterLogGroupName', {
        description: 'Parameter to store log group name',
        parameterName: '/Solutions/SO0111/Metrics_LogGroupName',
        stringValue: logGroupName.valueAsString
    })

    new OrchestratorMemberRole(this, 'OrchestratorMemberRole', {
        solutionId: props.solutionId,
        adminAccountId: adminAccount.adminAccountNumber.valueAsString,
        adminRoleName: adminRoleName
    })

    new cdk.CfnMapping(this, 'SourceCode', {
        mapping: { "General": { 
            "S3Bucket": props.solutionDistBucket,
            "KeyPrefix": props.solutionTMN + '/' + props.solutionVersion
        } }
    })

    //-------------------------------------------------------------------------
    // Runbooks - shared automations
    //
    new cdk.CfnStack(this, `RunbookStack`, {
        parameters: {
            'SecHubAdminAccount': adminAccount.adminAccountNumber.valueAsString
        },
        templateUrl: "https://" + cdk.Fn.findInMap("SourceCode", "General", "S3Bucket") +
        "-reference.s3.amazonaws.com/" + cdk.Fn.findInMap("SourceCode", "General", "KeyPrefix") +
        "/aws-sharr-remediations.template"
    })
  	//-------------------------------------------------------------------------
    // Loop through all of the Playbooks and create a Product for each SET of playbooks
    //
    const PB_DIR = `${__dirname}/../../playbooks`
    var ignore = ['.DS_Store', 'core', 'python_lib', 'python_tests', '.pytest_cache', 'NEWPLAYBOOK'];
    let illegalChars = /[\._]/g;

    fs.readdir(PB_DIR, (err, items) => {
        items.forEach(file => {
            if (!ignore.includes(file)) {
                var template_file = `${file}MemberStack.template`

                //---------------------------------------------------------------------
                // Playbook Member Template Nested Stack
                //
                let parmname = file.replace(illegalChars, '')
                let memberStackOption = new cdk.CfnParameter(this, `LoadMemberStack${parmname}`, {
                    type: "String",
                    description: `Load Playbook member stack for ${file}?`,
                    default: "no",
                    allowedValues: ["yes", "no"],
                })
                memberStackOption.overrideLogicalId(`Load${parmname}MemberStack`)

                let memberStack = new cdk.CfnStack(this, `PlaybookMemberStack${file}`, {
                    parameters: {
                        'SecHubAdminAccount': adminAccount.adminAccountNumber.valueAsString
                    },
                    templateUrl: "https://" + cdk.Fn.findInMap("SourceCode", "General", "S3Bucket") +
                    "-reference.s3.amazonaws.com/" + cdk.Fn.findInMap("SourceCode", "General", "KeyPrefix") +
                    "/playbooks/" + template_file
                })

                memberStack.cfnOptions.condition = new cdk.CfnCondition(this, `load${file}Cond`, {
                    expression: 
                        cdk.Fn.conditionEquals(memberStackOption, "yes")
                });
            }
        });
    })
  }
}
