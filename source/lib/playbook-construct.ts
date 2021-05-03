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

import * as cdk from '@aws-cdk/core';
import * as lambda from '@aws-cdk/aws-lambda';
import * as events from '@aws-cdk/aws-events';
import * as eventstarget from '@aws-cdk/aws-events-targets';
import {
    Effect, 
    PolicyDocument, 
    PolicyStatement, 
    ServicePrincipal, 
    Policy, 
    Role, 
    CfnRole,
    ArnPrincipal,
    CompositePrincipal,
    CfnPolicy
} from '@aws-cdk/aws-iam';
import { Bucket, IBucket } from '@aws-cdk/aws-s3';
import * as e2l from '@aws-solutions-constructs/aws-events-rule-lambda';
import * as sfn from '@aws-cdk/aws-stepfunctions';
import * as iam from '@aws-cdk/aws-iam';

export interface IPlaybookConstructProps {
    name: string;
    description: string;
    lambda_env?: any;
    aws_region: string;
    aws_accountid: string;
    aws_partition: string;
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
    public readonly lambdaRole: Role;
    
    constructor(scope: cdk.Construct, id: string, props: IPlaybookConstructProps) {
        super(scope, id);

        let workflowStatusFilter = {
            "Status": [ "NEW" ]
        }
        let complianceStatusFilter = {
            "Status": [ "FAILED", "WARNING" ]
        }

        let RESOURCE_PREFIX = props.solutionId;

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

        const ssmPolicy = new PolicyStatement({
            actions: [
                'ssm:GetParameter',
                'ssm:GetParameters',
                'ssm:PutParameter'
            ],
            resources: [`arn:${props.aws_partition}:ssm:*:${props.aws_accountid}:parameter/Solutions/SO0111/*`]
        })

        const snsPolicy = new PolicyStatement();
        snsPolicy.addActions("sns:Publish")
        snsPolicy.effect = Effect.ALLOW
        snsPolicy.addResources('arn:' + props.aws_partition + ':sns:' + props.aws_region + ':' +
            props.aws_accountid + ':' + props.solutionId + '-SHARR_Topic')

        const stsPolicy = new PolicyStatement();
        stsPolicy.addActions("sts:AssumeRole")
        stsPolicy.effect = Effect.ALLOW
        stsPolicy.addResources('arn:' + props.aws_partition + ':iam::*:role/' +
            RESOURCE_PREFIX + '_' + props.name + '_memberRole_' + props.aws_region)

        const lambdaPolicy = new PolicyDocument();
        lambdaPolicy.addStatements(logsPolicy)
        lambdaPolicy.addStatements(basePolicy)
        lambdaPolicy.addStatements(snsPolicy)
        lambdaPolicy.addStatements(kmsPolicy)
        lambdaPolicy.addStatements(stsPolicy)
        lambdaPolicy.addStatements(ssmPolicy)

        const principal = new ServicePrincipal('lambda.amazonaws.com');
        const principalPolicyStatement = new PolicyStatement();
        principalPolicyStatement.addActions("sts:AssumeRole");
        principalPolicyStatement.effect = Effect.ALLOW;
        principal.addToPolicy(principalPolicyStatement);

        let roleName: string = RESOURCE_PREFIX + '_' + props.name + '_lambdaRole_' + props.aws_region;
        this.lambdaRole = new Role(this, 'Role', {
            assumedBy: principal,
            inlinePolicies: {
                'default_lambdaPolicy': lambdaPolicy
            },
            roleName: roleName
        });

        const lambdaRoleResource = this.lambdaRole.node.findChild('Resource') as CfnRole;

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

        let lambda_src = `${props.distName}/${props.solutionVersion}/playbooks/CIS/${props.name.toLowerCase()}.py.zip`;

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
        const customAction = new cdk.CustomResource(this, 'CustomAction', {
            serviceToken: 'arn:' + props.aws_partition + ':lambda:' + props.aws_region + ':' + 
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
                role: this.lambdaRole,
                timeout: cdk.Duration.seconds(lambda_maxtime),
                environment: {
                    AWS_PARTITION: props.aws_partition,
                    log_level: 'info',
                    sendAnonymousMetrics: '{{resolve:ssm:/Solutions/' + props.solutionId + '/sendAnonymousMetrics:1}}'
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
            description: `Enable/Disable automatically triggered remediation for ${props.description.slice(11)}. If enabled, findings for this control will be immediately remediated by the solution.`,
            type: "String",
            allowedValues: ["ENABLED", "DISABLED"],
            default: "DISABLED"
        });

        enable_auto_remediation_param.overrideLogicalId(`${props.name}AutoRemediation`)

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

        {
            // let lambdaFunc = eventToLambda.lambdaFunction
            const childToMod =  eventToLambda.lambdaFunction.node.findChild('Resource') as lambda.CfnFunction;
            childToMod.cfnOptions.metadata = {
                cfn_nag: {
                    rules_to_suppress: [
                        {
                            id: 'W89',
                            reason: 'There is no need to run this lambda in a VPC'
                        },
                        {
                            id: 'W92',
                            reason: 'There is no need for Reserved Concurrency'
                        }
                    ]
                }
            };
        }
    }
}

/*
 * @author AWS Solutions Development
 * @description SSM-based remediation parameters
 * @type {playbookConstruct}
 */
import * as ssm from '@aws-cdk/aws-ssm';
import * as fs from 'fs';
import * as yaml from 'js-yaml';

export interface IssmPlaybookProps {
    securityStandard: string;     // ex. AFSBP
    controlId: string;
    ssmDocPath: string;
    ssmDocFileName: string;
}

export class SsmPlaybook extends cdk.Construct {
    
  constructor(scope: cdk.Construct, id: string, props: IssmPlaybookProps) {
    super(scope, id);
    let illegalChars = /[\.]/g;

    const enableParam = new cdk.CfnParameter(this, 'Enable ' + props.controlId, {
        type: "String",
        description: `Enable/disable availability of remediation for AFSBP Control ${props.controlId} in Security Hub Console Custom Actions. If NOT Available the remediation cannot be triggered from the Security Hub console in the Security Hub Admin account.`,
        default: "Available",
        allowedValues: ["Available", "NOT Available"]
    })
    enableParam.overrideLogicalId(`${props.securityStandard}${props.controlId.replace(illegalChars, '')}Active`)

    const installSsmDoc = new cdk.CfnCondition(this, 'Enable ' + props.controlId + ' Condition', {
        expression: cdk.Fn.conditionEquals(enableParam, "Available")
    })

    let ssmDocName = `SHARR_Remediation_${props.securityStandard}_${props.controlId}`
    let ssmDocFQFileName = `${props.ssmDocPath}${props.ssmDocFileName}`
    let ssmDocType = props.ssmDocFileName.substr(props.ssmDocFileName.length - 4).toLowerCase()

    let ssmDocSource = undefined
    if (ssmDocType == 'json') {
        ssmDocSource = JSON.parse(fs.readFileSync(ssmDocFQFileName, 'utf8'))
    } else if (ssmDocType == 'yaml') {
        ssmDocSource = yaml.safeLoad(fs.readFileSync(ssmDocFQFileName, 'utf8'))
    }

    const AutoDoc = new ssm.CfnDocument(this, 'Automation Document', {
        content: ssmDocSource,
        documentType: 'Automation',
        name: ssmDocName
    })
    AutoDoc.cfnOptions.condition = installSsmDoc
  }
}

export interface ISsmRemediationRoleProps {
    // adminAccountNumber: string;
    solutionId: string;
    controlId: string;
    adminAccountNumber: string;
    remediationPolicy: Policy;
    adminRoleName: string;
    remediationRoleName: string;
}

export class SsmRemediationRole extends cdk.Construct {

  constructor(scope: cdk.Construct, id: string, props: ISsmRemediationRoleProps) {
    super(scope, id);
    const stack = cdk.Stack.of(this)
    const ssmDocPrefix = props.solutionId + '_Remediation_AFSBP_'

    const basePolicy = new Policy(this, 'SHARR-AFSBP-Member-Base-Policy')
    // Global Permissions       
    const iamPerms = new PolicyStatement();
    iamPerms.addActions("iam:PassRole")
    iamPerms.effect = Effect.ALLOW
    iamPerms.addResources(
        'arn:' + stack.partition + ':iam::' + stack.account +
        ':role/' + props.remediationRoleName
    );
    basePolicy.addStatements(iamPerms)

    const ssmPerms = new PolicyStatement();
    ssmPerms.addActions("ssm:StartAutomationExecution")
    ssmPerms.addActions("ssm:GetAutomationExecution")
    ssmPerms.effect = Effect.ALLOW
    ssmPerms.addResources(
        'arn:' + stack.partition + ':ssm:' + stack.region + ':' +
        stack.account + ':document/' + ssmDocPrefix + props.controlId
    );
    ssmPerms.addResources(
        'arn:' + stack.partition + ':ssm:' + stack.region + ':' +
        ':automation-definition/*'
    );
    ssmPerms.addResources(
        'arn:' + stack.partition + ':ssm:' + stack.region + ':' +
        stack.account + ':automation-execution/*'
    );
    basePolicy.addStatements(ssmPerms)

    const ssmParmPerms = new PolicyStatement();
    ssmParmPerms.addActions("ssm:GetParameters")
    ssmParmPerms.addActions("ssm:GetParameter")
    ssmParmPerms.addActions("ssm:PutParameter")
    ssmParmPerms.effect = Effect.ALLOW
    ssmParmPerms.addResources(
        `arn:${stack.partition}:ssm:${stack.region}:${stack.account}:parameter/Solutions/SO0111/*`
    );
    basePolicy.addStatements(ssmParmPerms)

    const sechubPerms = new PolicyStatement();
    sechubPerms.addActions("cloudwatch:PutMetricData")
    sechubPerms.addActions("securityhub:BatchUpdateFindings")
    sechubPerms.effect = Effect.ALLOW
    sechubPerms.addResources("*")

    basePolicy.addStatements(sechubPerms)

    {    
        let resourceForException = basePolicy.node.defaultChild as CfnPolicy;
        resourceForException.cfnOptions.metadata = {
            cfn_nag: {
                rules_to_suppress: [{
                    id: 'W12',
                    reason: 'Resource * is required as the resource names are not predictable (randomly assigned).'
                }]
            }
        };
    }

    // AssumeRole Policy
    let principalPolicyStatement = new PolicyStatement();
    principalPolicyStatement.addActions("sts:AssumeRole");
    principalPolicyStatement.effect = Effect.ALLOW;

    let roleprincipal = new ArnPrincipal(
        'arn:' + stack.partition + ':iam::' + props.adminAccountNumber + 
        ':role/' + props.adminRoleName
    );

    let principals = new CompositePrincipal(roleprincipal);
    principals.addToPolicy(principalPolicyStatement);

    let serviceprincipal = new ServicePrincipal('ssm.amazonaws.com')
    principals.addPrincipals(serviceprincipal);

    let memberRole = new Role(this, 'MemberAccountRole', {
        assumedBy: principals,
        roleName: props.remediationRoleName
    });

    memberRole.attachInlinePolicy(basePolicy)
    memberRole.attachInlinePolicy(props.remediationPolicy)

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

/*
 * @author AWS Solutions Development
 * @description SSM-based remediation trigger
 * @type {trigger}
 */
export interface ITriggerProps {
    description?: string,
    securityStandard: string;     // ex. AFSBP
    securityStandardArn: string;   // ex. arn:aws:securityhub:::standards/aws-foundational-security-best-practices/v/1.0.0
    controlId: string;
    targetArn: string;
}

export class Trigger extends cdk.Construct {
    
  constructor(scope: cdk.Construct, id: string, props: ITriggerProps) {
    super(scope, id);
    const stack = cdk.Stack.of(this)
    let illegalChars = /[\.]/g;

    // Event to Step Function
    // ----------------------
    // Create CWE rule
    // Create custom action

    const enableRemediation = new cdk.CfnParameter(this, 'Enable ' + props.controlId, {
        type: "String",
        description: `Enable/disable remediation for AFSBP Control ${props.controlId}. Note 
        that remediations can be disabled on a per-account basis in the Member template.`,
        default: "Install",
        allowedValues: ["Install", "DO NOT Install"],
    })
    enableRemediation.overrideLogicalId(`${props.securityStandard}${props.controlId.replace(illegalChars, '')}Installation`)

    const installTrigger = new cdk.CfnCondition(this, `Enable ${props.controlId} Condition`, {
        expression: cdk.Fn.conditionEquals(enableRemediation, "Install")
    })

    let description = 'Remediate AFSBP ' + props.controlId
    if (props.description) {
        description = props.description
    }

    let workflowStatusFilter = {
        "Status": [ "NEW" ]
    }
    let complianceStatusFilter = {
        "Status": [ "FAILED", "WARNING" ]
    }

    let customActionName: string = `${props.securityStandard} ${props.controlId}`

    let stateMachine = sfn.StateMachine.fromStateMachineArn(this, 'orchestrator', props.targetArn);

    // Note: Id is max 20 characters
    const customAction = new cdk.CustomResource(this, 'Custom Action', {
        serviceToken: `arn:${stack.partition}:lambda:${stack.region}:${stack.account}:function:SO0111-SHARR-CustomAction`,
        resourceType: 'Custom::ActionTarget',
        properties: {
            Name: customActionName,
            Description: description,
            Id: props.securityStandard + props.controlId.replace(illegalChars, '')
        }
    });
    {
        const childToMod = customAction.node.defaultChild as cdk.CfnCustomResource;
        childToMod.cfnOptions.condition = installTrigger
    }

    // Create an IAM role for Events to start the State Machine
    const eventsRole = new iam.Role(this, 'EventsRuleRole', {
      assumedBy: new iam.ServicePrincipal('events.amazonaws.com')
    });

    // Grant the start execution permission to the Events service
    stateMachine.grantStartExecution(eventsRole);

    // Create an event rule to trigger the step function
    const stateMachineTarget: events.IRuleTarget = {
      bind: () => ({
        id: '',
        arn: props.targetArn,
        role: eventsRole
      })
    };

    const eventPattern: events.EventPattern = {
        source: ["aws.securityhub"],
        detailType: ["Security Hub Findings - Custom Action"],
        resources: [ customAction.getAttString('Arn') ],
        detail: {
            findings: { 
                ProductFields: {
                    StandardsArn: [ props.securityStandardArn ],
                    ControlId: [ props.controlId ],
                },
                Compliance: complianceStatusFilter
            }
        }
    }

    const custom_action_rule = new events.Rule(this, props.securityStandard + ' ' + props.controlId + ' Custom Action', {
        description: description,
        enabled: true,
        eventPattern: eventPattern,
        ruleName: `${props.securityStandard}_${props.controlId}_CustomAction`,
        targets: [stateMachineTarget]
    })
    {
        let childToMod = custom_action_rule.node.defaultChild as events.CfnRule;
        childToMod.cfnOptions.condition = installTrigger
    }

    const enable_auto_remediation_param = new cdk.CfnParameter(this, 'AutoEnable', {
        description: "This will fully enable automated remediation for "+ props.securityStandard + ' ' + props.controlId,
        type: "String",
        allowedValues: ["ENABLED", "DISABLED"],
        default: "DISABLED"
    });

    enable_auto_remediation_param.overrideLogicalId(`${props.securityStandard}${props.controlId.replace(illegalChars, '')}AutoTrigger`)
    
    const triggerPattern: events.EventPattern = {
        source: ["aws.securityhub"],
        detailType: ["Security Hub Findings - Imported"],
        detail: {
            findings: { 
                ProductFields: {
                    StandardsArn: [ props.securityStandardArn ],
                    ControlId: [ props.controlId ]
                },
                Workflow: workflowStatusFilter,
                Compliance: complianceStatusFilter
            }
        }
    }

    // Adding an automated even rule for the playbook
    const eventRule_auto = new events.Rule(this, 'AutoEventRule', {
        description: description + ' automatic remediation trigger event rule.',
        ruleName: `${props.securityStandard}_${props.controlId}_AutoTrigger`,
        targets: [stateMachineTarget],
        eventPattern: triggerPattern
    });

    const cfnEventRule_auto = eventRule_auto.node.defaultChild as events.CfnRule;
    cfnEventRule_auto.addPropertyOverride('State', enable_auto_remediation_param.valueAsString);
    cfnEventRule_auto.cfnOptions.condition = installTrigger

  }
}
