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
import * as lambda from '@aws-cdk/aws-lambda';
import * as events from '@aws-cdk/aws-events';
import * as eventstarget from '@aws-cdk/aws-events-targets';
import {Effect, PolicyDocument, PolicyStatement, ServicePrincipal, Policy, Role, CfnRole} from '@aws-cdk/aws-iam';
import { Bucket, IBucket } from '@aws-cdk/aws-s3';
import * as e2l from '@aws-solutions-constructs/aws-events-rule-lambda';

export interface IPlaybookConstructProps {
    name: string;
    description: string;
    lambda_env?: any;
    aws_region: string;
    aws_accountid: string;
    lambda_handler?: string;
    lambda_memsize?: number;
    lambda_maxtime?: number;
    custom_action_name: string;
    findings: object;
    solutionId: string;
    solutionVersion: string;
    solutionName: string;
    distName: string;
    distBucket: string;
}

export class PlaybookConstruct extends cdk.Construct {
    
    constructor(scope: cdk.Construct, id: string, props: IPlaybookConstructProps) {
        super(scope, id);
        let workflowStatusFilter = {
            "Status": [ "NEW" ]
        }
        let complianceStatusFilter = {
            "Status": [ "FAILED", "WARNING" ]
        }

        let RESOURCE_PREFIX = props.solutionId;

        let lambdaRole = undefined

        const basePolicy = new PolicyStatement();
        basePolicy.addActions("cloudwatch:PutMetricData")
        basePolicy.addActions("securityhub:BatchUpdateFindings")
        basePolicy.effect = Effect.ALLOW
        basePolicy.addResources("*")

        const logsPolicy = new PolicyStatement();
        logsPolicy.addActions("logs:CreateLogGroup")
        logsPolicy.addActions("logs:CreateLogStream")
        logsPolicy.addActions("logs:PutLogEvents")
        logsPolicy.effect = Effect.ALLOW
        logsPolicy.addResources("*")

        const kmsPolicy = new PolicyStatement();
        kmsPolicy.addActions("kms:Encrypt")
        kmsPolicy.addActions("kms:Decrypt")
        kmsPolicy.addActions("kms:GenerateDataKey")
        kmsPolicy.effect = Effect.ALLOW
        kmsPolicy.addResources('{{resolve:ssm:/Solutions/' + props.solutionId + '/CMK_ARN:1}}')

        const snsPolicy = new PolicyStatement();
        snsPolicy.addActions("sns:Publish")
        snsPolicy.effect = Effect.ALLOW
        snsPolicy.addResources('arn:aws:sns:' + props.aws_region + ':' +
            props.aws_accountid + ':' + props.solutionId + '-SHARR_Topic')

        const stsPolicy = new PolicyStatement();
        stsPolicy.addActions("sts:AssumeRole")
        stsPolicy.effect = Effect.ALLOW
        stsPolicy.addResources('arn:aws:iam::*:role/' +
            RESOURCE_PREFIX + '_' + props.name + '_memberRole_' + props.aws_region)

        const lambdaPolicy = new PolicyDocument();
        lambdaPolicy.addStatements(logsPolicy)
        lambdaPolicy.addStatements(basePolicy)
        lambdaPolicy.addStatements(snsPolicy)
        lambdaPolicy.addStatements(kmsPolicy)
        lambdaPolicy.addStatements(stsPolicy)

        const principal = new ServicePrincipal('lambda.amazonaws.com');
        const principalPolicyStatement = new PolicyStatement();
        principalPolicyStatement.addActions("sts:AssumeRole");
        principalPolicyStatement.effect = Effect.ALLOW;
        principal.addToPolicy(principalPolicyStatement);

        let roleName: string = RESOURCE_PREFIX + '_' + props.name + '_lambdaRole_' + props.aws_region;
        lambdaRole = new Role(this, 'Role', {
            assumedBy: principal,
            inlinePolicies: {
                'default_lambdaPolicy': lambdaPolicy
            },
            roleName: roleName
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

        let lambdaName: string = props.name + '_lambda';

        let s3BucketForLambda: IBucket = Bucket.fromBucketAttributes(this, "s3BucketForLambda", {
            bucketName: props.distBucket + '-' + props.aws_region
        })

        let lambda_src = props.distName + '/'
            + props.solutionVersion + '/playbooks/CIS/' 
            + props.name.toLowerCase() + '.py.zip';

        let lambda_handler = undefined
        if (props.lambda_handler) {
            lambda_handler = props.lambda_handler
        } else {
            lambda_handler = props.name.toLowerCase() + '.lambda_handler';
        }

        let lambda_memsize = 256
        if (props.lambda_memsize) {
            lambda_memsize = props.lambda_memsize
        }

        let lambda_maxtime = 60
        if (props.lambda_maxtime) {
            lambda_maxtime = props.lambda_maxtime
        }

        // Event to Lambda
        // ---------------
        let eventRuleName: string = props.name + '_eventRule'

        let customActionName: string = props.name + '_customAction';
        const customAction = new cdk.CustomResource(this, 'CustomAction', {
            serviceToken: 'arn:aws:lambda:' + props.aws_region + ':' + 
                props.aws_accountid + ':function:' + RESOURCE_PREFIX + '-SHARR-CustomAction',
            resourceType: 'Custom::ActionTarget',
            properties: {
                Name: props.custom_action_name,
                Description: props.description,
                Id: props.name,
            }
        });

        const e2lprops = {
            deployLambda: true,
            lambdaFunctionProps: {
                functionName: lambdaName,
                description: 'SHARR-' + props.description,
                runtime: lambda.Runtime.PYTHON_3_8,
                code: lambda.Code.fromBucket(s3BucketForLambda, lambda_src),
                handler: lambda_handler,
                memorySize: lambda_memsize,
                role: lambdaRole,
                timeout: cdk.Duration.seconds(lambda_maxtime),
                environment: {
                    log_level: 'info',
                    sendAnonymousMetrics: '{{resolve:ssm:/Solutions/' + props.solutionId + '/sendAnonymousMetrics:1}}',
                    metricsId: '{{resolve:ssm:/Solutions/' + props.solutionId + '/metricsId:1}}'
                }
            },
            eventRuleProps: {
                description: props.description + ' event rule.',
                ruleName: eventRuleName,
                enabled: true,
                eventPattern: {
                    source: ["aws.securityhub"],
                    detailType: ["Security Hub Findings - Custom Action"],
                    resources: [customAction.getAttString('Arn')],
                    detail: {
                        findings: { 
                            Title: props.findings,
                            Workflow: workflowStatusFilter,
                            Compliance: complianceStatusFilter
                        }
                    }
                }
            }
        }

        let eventToLambda = new e2l.EventsRuleToLambda(this, 'eventToPlaybook', e2lprops)

        if (props.lambda_env) {
            let envs = Object.keys(props.lambda_env);
            for (let env of envs) {
                eventToLambda.lambdaFunction.addEnvironment(env, props.lambda_env[env])
            }
        }

        const eventTarget = new eventstarget.LambdaFunction(eventToLambda.lambdaFunction);

        const enable_auto_remediation_param = new cdk.CfnParameter(this, 'AutoEnable', {
            description: "This will fully enable automated remediation for "+ props.description.slice(11),
            type: "String",
            allowedValues: ["ENABLED", "DISABLED"],
            default: "DISABLED"
        });

        enable_auto_remediation_param.overrideLogicalId(props.name + "AutoRemediation")

        // Adding an automated even rule for the playbook
        const eventRule_auto = new events.Rule(this, 'AutoEventRule', {
            description: props.description + ' automatic remediation event rule.',
            ruleName: eventRuleName + '_automated',
            targets: [eventTarget]
        });

        const cfnEventRule_auto = eventRule_auto.node.defaultChild as events.CfnRule;
        cfnEventRule_auto.addPropertyOverride('State', enable_auto_remediation_param.valueAsString);

        eventRule_auto.addEventPattern({
            source: ["aws.securityhub"],
            detailType: ["Security Hub Findings - Imported"],
            detail: {
                findings: { 
                    Title: props.findings,
                    Workflow: workflowStatusFilter,
                    Compliance: complianceStatusFilter
                }
            }
        });
    }
}