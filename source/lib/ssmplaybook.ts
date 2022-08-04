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
import * as ssm from '@aws-cdk/aws-ssm';
import * as fs from 'fs';
import * as yaml from 'js-yaml';
import * as sfn from '@aws-cdk/aws-stepfunctions';
import * as events from '@aws-cdk/aws-events';
import {
    Effect,
    PolicyStatement,
    ServicePrincipal,
    Policy,
    Role,
    CfnRole,
    ArnPrincipal,
    CompositePrincipal,
    AccountPrincipal
} from '@aws-cdk/aws-iam';
import { StateMachine } from '@aws-cdk/aws-stepfunctions';
import { IRuleTarget, EventPattern, Rule } from '@aws-cdk/aws-events';
import { MemberRoleStack } from '../solution_deploy/lib/remediation_runbook-stack';

/*
 * @author AWS Solutions Development
 * @description SSM-based remediation parameters
 * @type {playbookConstruct}
 */

export interface IssmPlaybookProps {
  securityStandard: string; // ex. AFSBP
  securityStandardVersion: string;
  controlId: string;
  ssmDocPath: string;
  ssmDocFileName: string;
  solutionVersion: string;
  solutionDistBucket: string;
  adminRoleName?: string;
  remediationPolicy?: Policy;
  adminAccountNumber?: string;
  solutionId: string;
  scriptPath?: string;
  commonScripts?: string;
}

export class SsmPlaybook extends cdk.Construct {

  constructor(scope: cdk.Construct, id: string, props: IssmPlaybookProps) {
    super(scope, id);

    let scriptPath = ''
    if (props.scriptPath == undefined ) {
        scriptPath = `${props.ssmDocPath}/scripts`
    } else {
        scriptPath = props.scriptPath
    }

    let commonScripts = ''
    if (props.commonScripts == undefined ) {
        commonScripts = '../common'
    } else {
        commonScripts = props.commonScripts
    }

    const enableParam = new cdk.CfnParameter(this, 'Enable ' + props.controlId, {
        type: "String",
        description: `Enable/disable availability of remediation for ${props.securityStandard} version ${props.securityStandardVersion} Control ${props.controlId} in Security Hub Console Custom Actions. If NOT Available the remediation cannot be triggered from the Security Hub console in the Security Hub Admin account.`,
        default: "Available",
        allowedValues: ["Available", "NOT Available"]
    })

    const installSsmDoc = new cdk.CfnCondition(this, 'Enable ' + props.controlId + ' Condition', {
        expression: cdk.Fn.conditionEquals(enableParam, "Available")
    })

    let ssmDocName = `SHARR-${props.securityStandard}_${props.securityStandardVersion}_${props.controlId}`
    let ssmDocFQFileName = `${props.ssmDocPath}/${props.ssmDocFileName}`
    let ssmDocType = props.ssmDocFileName.substring(props.ssmDocFileName.length - 4).toLowerCase()

    let ssmDocIn = fs.readFileSync(ssmDocFQFileName, 'utf8')

    let ssmDocOut: string = ''
    const re = /^(?<padding>\s+)%%SCRIPT=(?<script>.*)%%/

    for (let line of ssmDocIn.split('\n')) {
        let foundMatch = re.exec(line)
        if (foundMatch && foundMatch.groups && foundMatch.groups.script) {
            let pathAndFileToInsert = foundMatch.groups.script
            // If a relative path is provided then use it
            if (pathAndFileToInsert.substring(0,7) === 'common/') {
                pathAndFileToInsert = `${commonScripts}/${pathAndFileToInsert.substring(7)}`
            } else {
                pathAndFileToInsert = `${scriptPath}/${pathAndFileToInsert}`
            }
            let scriptIn = fs.readFileSync(pathAndFileToInsert, 'utf8')
            for (let scriptLine of scriptIn.split('\n')) {
                ssmDocOut += foundMatch.groups.padding + scriptLine + '\n'
            }
        } else {
            ssmDocOut += line + '\n'
        }
    }

    let ssmDocSource = undefined
    if (ssmDocType == 'json') {
        ssmDocSource = JSON.parse(ssmDocOut)
    } else if (ssmDocType == 'yaml') {
        ssmDocSource = yaml.load(ssmDocOut)
    }

    const AutoDoc = new ssm.CfnDocument(this, 'Automation Document', {
        content: ssmDocSource,
        documentType: 'Automation',
        name: ssmDocName,
        versionName: props.solutionVersion
    })
    AutoDoc.cfnOptions.condition = installSsmDoc
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
    generatorId: string;    // ex. "arn:aws-cn:securityhub:::ruleset/cis-aws-foundations-benchmark/v/1.2.0"
    controlId: string;
    targetArn: string;
}

export class Trigger extends cdk.Construct {

  constructor(scope: cdk.Construct, id: string, props: ITriggerProps) {
    super(scope, id);
    let illegalChars = /[\.]/g;

    // Event to Step Function
    // ----------------------
    // Create CWE rule
    // Create custom action

    let description = `Remediate ${props.securityStandard} ${props.controlId}`
    if (props.description) {
        description = props.description
    }

    let workflowStatusFilter = {
        "Status": [ "NEW" ]
    }
    let complianceStatusFilter = {
        "Status": [ "FAILED", "WARNING" ]
    }
    const recordStateFilter: string[] = [
        'ACTIVE'
    ];

    const stateMachine = sfn.StateMachine.fromStateMachineArn(this, 'orchestrator', props.targetArn);

    // Create an IAM role for Events to start the State Machine
    const eventsRole = new Role(this, 'EventsRuleRole', {
      assumedBy: new ServicePrincipal('events.amazonaws.com')
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

    const enable_auto_remediation_param = new cdk.CfnParameter(this, 'AutoEnable', {
        description: "This will fully enable automated remediation for "+ props.securityStandard + ' ' + props.controlId,
        type: "String",
        allowedValues: ["ENABLED", "DISABLED"],
        default: "DISABLED"
    });

    enable_auto_remediation_param.overrideLogicalId(`${props.securityStandard}${props.controlId.replace(illegalChars, '')}AutoTrigger`)

    interface IPattern {
        source: any,
        detailType: any
        detail: any
    }
    let eventPattern: IPattern = {
        source: ["aws.securityhub"],
        detailType: ["Security Hub Findings - Imported"],
        detail: {
            findings: {
                // GeneratorId includes both standard and control/rule ID
                GeneratorId: [props.generatorId],
                Workflow: workflowStatusFilter,
                Compliance: complianceStatusFilter,
                RecordState: recordStateFilter
            }
        }
    }

    let triggerPattern: events.EventPattern = eventPattern

    // Adding an automated even rule for the playbook
    const eventRule_auto = new events.Rule(this, 'AutoEventRule', {
        description: description + ' automatic remediation trigger event rule.',
        ruleName: `${props.securityStandard}_${props.controlId}_AutoTrigger`,
        targets: [stateMachineTarget],
        eventPattern: triggerPattern
    });

    const cfnEventRule_auto = eventRule_auto.node.defaultChild as events.CfnRule;
    cfnEventRule_auto.addPropertyOverride('State', enable_auto_remediation_param.valueAsString);
  }
}

export interface IOneTriggerProps {
    description?: string,
    targetArn: string;
    serviceToken: string;
    prereq: cdk.CfnResource[];
}
export class OneTrigger extends cdk.Construct {
// used in place of Trigger. Sends all finding events for which the
// SHARR custom action is initiated to the Step Function

  constructor(scope: cdk.Construct, id: string, props: IOneTriggerProps) {
    super(scope, id);
    const stack = cdk.Stack.of(this)

    // Event to Step Function
    // ----------------------
    // Create CWE rule
    // Create custom action

    let description = `Remediate with SHARR`
    if (props.description) {
        description = props.description
    }

    let complianceStatusFilter = {
        "Status": [ "FAILED", "WARNING" ]
    }

    const stateMachine = StateMachine.fromStateMachineArn(this, 'orchestrator', props.targetArn);

    // Note: Id is max 20 characters
    const customAction = new cdk.CustomResource(this, 'Custom Action', {
        serviceToken: props.serviceToken,
        resourceType: 'Custom::ActionTarget',
        properties: {
            Name: 'Remediate with SHARR',
            Description: 'Submit the finding to AWS Security Hub Automated Response and Remediation',
            Id: 'SHARRRemediation'
        }
    });
    {
        let child = customAction.node.defaultChild as cdk.CfnCustomResource
        for (var prereq of props.prereq) {
            child.addDependsOn(prereq)
        }
    }

    // Create an IAM role for Events to start the State Machine
    const eventsRole = new Role(this, 'EventsRuleRole', {
    assumedBy: new ServicePrincipal('events.amazonaws.com')
    });

    // Grant the start execution permission to the Events service
    stateMachine.grantStartExecution(eventsRole);

    // Create an event rule to trigger the step function
    const stateMachineTarget: IRuleTarget = {
        bind: () => ({
            id: '',
            arn: props.targetArn,
            role: eventsRole
        })
    };

    let eventPattern: EventPattern = {
        source: ["aws.securityhub"],
        detailType: ["Security Hub Findings - Custom Action"],
        resources: [ customAction.getAttString('Arn') ],
        detail: {
            findings: {
                Compliance: complianceStatusFilter
            }
        }
    }

    new Rule(this, 'Remediate Custom Action', {
        description: description,
        enabled: true,
        eventPattern: eventPattern,
        ruleName: `Remediate_with_SHARR_CustomAction`,
        targets: [stateMachineTarget]
    })
  }
}

export interface RoleProps {
    readonly solutionId: string;
    readonly ssmDocName: string;
    readonly remediationPolicy: Policy;
    readonly remediationRoleName: string;
};

export class SsmRole extends cdk.Construct {

  constructor(scope: cdk.Construct, id: string, props: RoleProps) {
    super(scope, id);
    const stack = cdk.Stack.of(this)
    const roleStack = MemberRoleStack.of(this) as MemberRoleStack;
    const basePolicy = new Policy(this, 'SHARR-Member-Base-Policy')
    const adminAccount = roleStack.node.findChild('AdminAccountParameter').node.findChild('Admin Account Number') as cdk.CfnParameter;

    basePolicy.addStatements(
        new PolicyStatement({
            actions: [
                "ssm:GetParameters",
                "ssm:GetParameter",
                "ssm:PutParameter"
            ],
            resources: [
                `arn:${stack.partition}:ssm:*:${stack.account}:parameter/Solutions/SO0111/*`
            ],
            effect: Effect.ALLOW
        }),
        new PolicyStatement({
            actions: [
                "iam:PassRole"
            ],
            resources: [
                `arn:${stack.partition}:iam::${stack.account}:role/${props.remediationRoleName}`
            ],
            effect: Effect.ALLOW
        }),
        new PolicyStatement({
            actions: [
                "ssm:StartAutomationExecution",
                "ssm:GetAutomationExecution",
                "ssm:DescribeAutomationStepExecutions"
            ],
            resources: [
                `arn:${stack.partition}:ssm:*:${stack.account}:document/Solutions/SHARR-${props.remediationRoleName}`,
                `arn:${stack.partition}:ssm:*:${stack.account}:automation-definition/*`,
                `arn:${stack.partition}:ssm:*::automation-definition/*`,
                `arn:${stack.partition}:ssm:*:${stack.account}:automation-execution/*`
            ],
            effect: Effect.ALLOW
        }),
        new PolicyStatement({
            actions: [
                "sts:AssumeRole"
            ],
            resources: [
                `arn:${stack.partition}:iam::${stack.account}:role/${props.remediationRoleName}`
            ],
            effect: Effect.ALLOW
        })
    )

    // AssumeRole Policy
    let principalPolicyStatement = new PolicyStatement();
    principalPolicyStatement.addActions("sts:AssumeRole");
    principalPolicyStatement.effect = Effect.ALLOW;

    const RESOURCE_PREFIX = props.solutionId.replace(/^DEV-/,'');
    let roleprincipal = new ArnPrincipal(
        `arn:${stack.partition}:iam::${stack.account}:role/${RESOURCE_PREFIX}-SHARR-Orchestrator-Member`
    );

    let principals = new CompositePrincipal(roleprincipal);
    principals.addToPolicy(principalPolicyStatement);

    let serviceprincipal = new ServicePrincipal('ssm.amazonaws.com')
    principals.addPrincipals(serviceprincipal);

    // Multi-account/region automations must be able to assume the remediation role
    const accountPrincipal = new AccountPrincipal(stack.account);
    principals.addPrincipals(accountPrincipal);

    let memberRole = new Role(this, 'MemberAccountRole', {
        assumedBy: principals,
        roleName: props.remediationRoleName
    });

    memberRole.attachInlinePolicy(basePolicy)
    memberRole.attachInlinePolicy(props.remediationPolicy)
    memberRole.applyRemovalPolicy(cdk.RemovalPolicy.RETAIN)
    memberRole.node.addDependency(roleStack.getOrchestratorMemberRole());

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

export interface RemediationRunbookProps {
  ssmDocName: string;
  ssmDocPath: string;
  ssmDocFileName: string;
  solutionVersion: string;
  solutionDistBucket: string;
  remediationPolicy?: Policy;
  solutionId: string;
  scriptPath?: string;
}

export class SsmRemediationRunbook extends cdk.Construct {

  constructor(scope: cdk.Construct, id: string, props: RemediationRunbookProps) {
    super(scope, id);

    // Add prefix to ssmDocName
    let ssmDocName = `SHARR-${props.ssmDocName}`

    let scriptPath = ''
    if (props.scriptPath == undefined) {
        scriptPath = 'ssmdocs/scripts'
    } else {
        scriptPath = props.scriptPath
    }

    let ssmDocFQFileName = `${props.ssmDocPath}/${props.ssmDocFileName}`
    let ssmDocType = props.ssmDocFileName.substr(props.ssmDocFileName.length - 4).toLowerCase()

    let ssmDocIn = fs.readFileSync(ssmDocFQFileName, 'utf8')

    let ssmDocOut: string = ''
    const re = /^(?<padding>\s+)%%SCRIPT=(?<script>.*)%%/

    for (let line of ssmDocIn.split('\n')) {
        let foundMatch = re.exec(line)
        if (foundMatch && foundMatch.groups && foundMatch.groups.script) {
            let scriptIn = fs.readFileSync(`${scriptPath}/${foundMatch.groups.script}`, 'utf8')
            for (let scriptLine of scriptIn.split('\n')) {
                ssmDocOut += foundMatch.groups.padding + scriptLine + '\n'
            }
        } else {
            ssmDocOut += line + '\n'
        }
    }

    let ssmDocSource = undefined
    if (ssmDocType == 'json') {
        ssmDocSource = JSON.parse(ssmDocOut)
    } else if (ssmDocType == 'yaml') {
        ssmDocSource = yaml.load(ssmDocOut)
    }

    new ssm.CfnDocument(this, 'Automation Document', {
        content: ssmDocSource,
        documentType: 'Automation',
        name: ssmDocName
    })
  }
}
