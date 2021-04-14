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
import * as sfn from '@aws-cdk/aws-stepfunctions';
import * as tasks from '@aws-cdk/aws-stepfunctions-tasks';
import * as lambda from '@aws-cdk/aws-lambda';
import { PolicyDocument, PolicyStatement, Policy, Role, Effect, ServicePrincipal, CfnPolicy, CfnRole } from '@aws-cdk/aws-iam';
import { LogGroup, CfnLogGroup, RetentionDays } from '@aws-cdk/aws-logs';
import { LambdaInvokeRS, LambdaInvokeRSProps } from '../../../lib/lambda_invoke_extended';
import { Key, IKey } from '@aws-cdk/aws-kms';

export interface ConstructProps {
    roleArn: string;
    ssmDocStateLambda: string;
    ssmExecDocLambda: string;
    ssmExecMonitorLambda: string;
    notifyLambda: string;
    solutionId: string;
}

export class OrchestratorConstruct extends cdk.Construct {
  public readonly orchestratorArn: string;
  constructor(scope: cdk.Construct, id: string, props: ConstructProps) {
    super(scope, id);

    const stack = cdk.Stack.of(this);
    const extractFindings = new sfn.Pass(this, 'Get Finding Data from Input', {
        comment: 'Extract top-level data needed for remediation',
        parameters: {
            "EventType.$": "$.detail-type",
            "Findings.$": "$.detail.findings",
            "Metrics": {
                "sendAnonymousMetrics.$": "States.Format('{{resolve:ssm:/Solutions/SO0111/sendAnonymousMetrics:1}}')"
            }
        }
    })

    let getDocStateFunc: lambda.IFunction = lambda.Function.fromFunctionAttributes(this, 'getDocStateFunc',{
        functionArn: props.ssmDocStateLambda
    })

    let execRemediationFunc: lambda.IFunction = lambda.Function.fromFunctionAttributes(this, 'execRemediationFunc',{
        functionArn: props.ssmExecDocLambda
    })
    let execMonFunc: lambda.IFunction = lambda.Function.fromFunctionAttributes(this, 'getExecStatusFunc',{
        functionArn: props.ssmExecMonitorLambda
    })
    let notifyFunc: lambda.IFunction = lambda.Function.fromFunctionAttributes(this, 'notifyFunc',{
        functionArn: props.notifyLambda
    })

    const orchestratorFailed = new sfn.Pass(this, 'Orchestrator Failed', {
        parameters: {
            "Notification": {
                "Message.$": "States.Format('Orchestrator failed: {}', $.Error)",
                "State.$": "States.Format('LAMBDAERROR')",
                "Details.$": "States.Format('Cause: {}', $.Cause)"
            },
            "SecurityStandard.$": "States.Format('AFSBP')",
            "Payload.$": "$"
        }
    })

    const getDocState = new LambdaInvokeRS(this, 'Get Automation Document State', {
        comment:  "Get the status of the remediation automation document in the target account",
        lambdaFunction: getDocStateFunc,
        timeout: cdk.Duration.minutes(1),
        resultSelector: {
            "DocState.$": "$.Payload.status",
            "Message.$": "$.Payload.message"
        },
        resultPath: "$.AutomationDocument"
    })
    getDocState.addCatch(orchestratorFailed)

    const remediateAFSBP = new LambdaInvokeRS(this, 'Execute Remediation', {
        comment: "Execute the SSM Automation Document in the target account",
        lambdaFunction: execRemediationFunc,
        heartbeat: cdk.Duration.seconds(60),
        timeout: cdk.Duration.minutes(5),
        resultSelector: {
            "ExecState.$": "$.Payload.status",
            "Message.$": "$.Payload.message",
            "ExecId.$": "$.Payload.executionid"
        },
        resultPath: "$.SSMExecution"
    })
    remediateAFSBP.addCatch(orchestratorFailed)

    const execMonitor = new LambdaInvokeRS(this, 'execMonitor', {
        comment: "Monitor the remediation execution until done",
        lambdaFunction: execMonFunc,
        heartbeat: cdk.Duration.seconds(60),
        timeout: cdk.Duration.minutes(5),
        resultSelector: {
            "ExecState.$": "$.Payload.status",
            "ExecId.$": "$.Payload.executionid",
            "RemediationState.$": "$.Payload.remediation_status",
            "Message.$": "$.Payload.message",
            "LogData.$": "$.Payload.logdata",
            "AffectedObject.$": "$.Payload.affected_object",
        },
        resultPath: "$.Remediation"
    })
    execMonitor.addCatch(orchestratorFailed)

    const notify = new tasks.LambdaInvoke(this, 'notify', {
        comment: "Send notifications",
        lambdaFunction: notifyFunc,
        heartbeat: cdk.Duration.seconds(60),
        timeout: cdk.Duration.minutes(5)
    })

    new sfn.Fail(this, 'Job Failed', {
        cause: 'AWS Batch Job Failed',
        error: 'DescribeJob returned FAILED',
    });

    const eoj = new sfn.Pass(this, 'EOJ', {
        comment: 'END-OF-JOB'
    })

    const processFindings = new sfn.Map(this, 'Process Findings', {
        comment: 'Process all findings in CloudWatch Event',
        parameters: {
            "Metrics.$": "$.Metrics",
            "Finding.$": "$$.Map.Item.Value",
            "EventType.$": "$.EventType"
        },
        itemsPath: '$.Findings'
    })

    new sfn.Choice(this, 'checkStandard', {
        comment:'Validate that standard is AFSBP (will be a Choice)',
    })

    const extractParameters = new sfn.Pass(this, 'extractParameters', {
        comment: 'Extract parameters needed for remediation',
        parameters: {
            "SecurityStandard.$": "States.Format('AFSBP')",
            "ControlId.$": "$.Finding.ProductFields.ControlId",
            "AccountId.$": "$.Finding.AwsAccountId",
            "Finding.$": "$.Finding",
            "RemediationRole.$": "States.Format('SO0111-SHARR-Remediation-AFSBP-{}', $.Finding.ProductFields.ControlId)",
            "AutomationDocId.$": "States.Format('SHARR_Remediation_AFSBP_{}', $.Finding.ProductFields.ControlId)",
            "Metrics.$": "$.Metrics",
            "EventType.$": "$.EventType"
        }
    })

    // Set notification. If the when is not matched then this will be the notification sent
    const checkWorkflowNew = new sfn.Choice(this, 'Finding Workflow State NEW?')

    const docNotNew = new sfn.Pass(this, 'Finding Workflow State is not NEW', {
        parameters: {
            "Notification": {
                "Message.$": "States.Format('Finding Workflow State is not NEW ({}).', $.Finding.Workflow.Status)",
                "State.$": "States.Format('NOTNEW')"
            },
            "Metrics.$": "$.Metrics",
            "EventType.$": "$.EventType",
            "Finding.$": "$.Finding"
        }
    })

    // Set notification. If the when is not matched then this will be the notification sent
    const checkDocStandard = new sfn.Choice(this, 'Correct Security Standard?')

    const wrongStandard = new sfn.Pass(this, 'Wrong Security Standard', {
        parameters: {
            "Notification": {
                "Message.$": "States.Format('Finding Security Standard is not AFSBP ({}). Verify that the correct remediation was selected.', $.Finding.GeneratorId)",
                "State.$": "States.Format('WRONGSTANDARD')"
            },
            "Metrics.$": "$.Metrics",
            "EventType.$": "$.EventType",
            "Finding.$": "$.Finding"
        }
    })

    const checkDocState = new sfn.Choice(this, 'Automation Doc Active?')

    const docStateNotActive = new sfn.Pass(this, 'Automation Document is not Active', {
        parameters: {
            "Notification": {
                "Message.$": "States.Format('Automation Document ({}) is not active ({}) in the member account({}).', $.AutomationDocId, $.AutomationDocument.DocState, $.Finding.AwsAccountId)",
                "State.$": "States.Format('REMEDIATIONNOTACTIVE')",
                "updateSecHub": "yes"
            },
            "Metrics.$": "$.Metrics",
            "EventType.$": "$.EventType",
            "Finding.$": "$.Finding",
            "AccountId.$": "$.AccountId",
            "AutomationDocId.$": "$.AutomationDocId",
            "RemediationRole.$": "$.RemediationRole",
            "ControlId.$": "$.ControlId",
            "SecurityStandard.$": "$.SecurityStandard"
        }
    })

    new sfn.Pass(this, 'check_ssm_doc_state Error', {
        parameters: {
            "Notification": {
                "Message.$": "States.Format('check_ssm_doc_state returned an error: {}', $.AutomationDocument.Message)",
                "State.$": "States.Format('LAMBDAERROR')"
            },
            "Metrics.$": "$.Metrics",
            "EventType.$": "$.EventType",
            "Finding.$": "$.Finding"
        }
    })

    const isdone = new sfn.Choice(this, 'Remediation completed?')

    const waitForRemediation = new sfn.Wait(this, 'Wait for Remediation', {
        time: sfn.WaitTime.duration(cdk.Duration.seconds(15))
    })

    const remediationFailed = new sfn.Pass(this, 'Remediation Failed', {
        comment: 'Set parameters for notification',
        parameters: {
            "Metrics.$": "$.Metrics",
            "EventType.$": "$.EventType",
            "Finding.$": "$.Finding",
            "AccountId.$": "$.AccountId",
            "AutomationDocId.$": "$.AutomationDocId",
            "RemediationRole.$": "$.RemediationRole",
            "ControlId.$": "$.ControlId",
            "SecurityStandard.$": "$.SecurityStandard",
            "Notification": {
                "Message.$": "States.Format('Remediation failed for {} control {} in account {}: {}', $.SecurityStandard, $.ControlId, $.AccountId, $.Remediation.Message)",
                "State.$": "$.Remediation.ExecState",
                "Details.$": "$.Remediation.LogData",
                "ExecId.$": "$.Remediation.ExecId",
                "AffectedObject.$": "$.Remediation.AffectedObject",
            }
        }
    })

    const remediationSucceeded = new sfn.Pass(this, 'Remediation Succeeded', {
        comment: 'Set parameters for notification',
        parameters: {
            "Metrics.$": "$.Metrics",
            "EventType.$": "$.EventType",
            "Finding.$": "$.Finding",
            "AccountId.$": "$.AccountId",
            "AutomationDocId.$": "$.AutomationDocId",
            "RemediationRole.$": "$.RemediationRole",
            "ControlId.$": "$.ControlId",
            "SecurityStandard.$": "$.SecurityStandard",
            "Notification": {
                "Message.$": "States.Format('Remediation succeeded for {} control {} in account {}: {}', $.SecurityStandard, $.ControlId, $.AccountId, $.Remediation.Message)",
                "State.$": "States.Format('SUCCESS')",
                "Details.$": "$.Remediation.LogData",
                "ExecId.$": "$.Remediation.ExecId",
                "AffectedObject.$": "$.Remediation.AffectedObject",
            }
        }
    })

    //-----------------------------------------------------------------
    // State Machine
    //
    extractFindings.next(processFindings)

    checkWorkflowNew.when(
        sfn.Condition.or(
            sfn.Condition.stringEquals(
                '$.EventType', 
                'Security Hub Findings - Custom Action'
            ),     
            sfn.Condition.and(
                sfn.Condition.stringEquals(
                    '$.Finding.Workflow.Status', 
                    'NEW'
                ),
                sfn.Condition.stringEquals(
                    '$.EventType', 
                    'Security Hub Findings - Imported'
                ),     
            )
        ),
        checkDocStandard
    )
    checkWorkflowNew.otherwise(docNotNew)

    docNotNew.next(notify)

    // Verify that the security standard matches this playbook
    checkDocStandard.when(
        sfn.Condition.stringMatches(
            '$.Finding.GeneratorId', 
            'aws-foundational-security-best-practices/v/1.0.0/*'), 
        extractParameters
    )
    checkDocStandard.otherwise(wrongStandard)

    wrongStandard.next(notify)

    // Normalize/extract parameters
    extractParameters.next(getDocState)

    // Call Lambda to get status of the automation document in the target account
    getDocState.next(checkDocState)

    checkDocState.when(
        sfn.Condition.stringEquals(
            '$.AutomationDocument.DocState',
            'ACTIVE'),
        remediateAFSBP
    )
    checkDocState.otherwise(docStateNotActive)

    docStateNotActive.next(notify)

    // Execute the remediation
    remediateAFSBP.next(execMonitor)

    execMonitor.next(isdone)

    isdone.when(
        sfn.Condition.stringEquals(
            '$.Remediation.RemediationState',
            'Failed'
            ),
        remediationFailed
    )
    isdone.when(
        sfn.Condition.stringEquals(
            '$.Remediation.ExecState',
            'Success'),
        remediationSucceeded
    )
    isdone.when(
        sfn.Condition.stringEquals(
            '$.Remediation.ExecState',
            'TimedOut'),
        remediationFailed
    )
    isdone.when(
        sfn.Condition.stringEquals(
            '$.Remediation.ExecState',
            'Cancelling'),
        remediationFailed
    )
    isdone.when(
        sfn.Condition.stringEquals(
            '$.Remediation.ExecState',
            'Cancelled'),
        remediationFailed
    )
    isdone.when(
        sfn.Condition.stringEquals(
            '$.Remediation.ExecState',
            'Failed'),
        remediationFailed
    )
    isdone.otherwise(waitForRemediation)

    waitForRemediation.next(execMonitor)

    orchestratorFailed.next(notify)

    remediationFailed.next(notify)

    remediationSucceeded.next(notify)

    processFindings.iterator(checkWorkflowNew).next(eoj);

    const sharrKmsKey: IKey = Key.fromKeyArn(this, "kmsKey", `arn:${stack.partition}:kms:${stack.region}:${stack.account}:alias/SO0111-SHARR-Key`)

    const orchestratorPolicy = new PolicyDocument();
    orchestratorPolicy.addStatements(
        new PolicyStatement({
            actions: [
                "logs:CreateLogDelivery",
                "logs:GetLogDelivery",
                "logs:UpdateLogDelivery",
                "logs:DeleteLogDelivery",
                "logs:ListLogDeliveries",
                "logs:PutResourcePolicy",
                "logs:DescribeResourcePolicies",
                "logs:DescribeLogGroups"
            ],
            effect: Effect.ALLOW,
            resources: [ '*' ]
        })
    )
    orchestratorPolicy.addStatements(
        new PolicyStatement({
            actions: [ "lambda:InvokeFunction" ],
            effect: Effect.ALLOW,
            resources: [
                `arn:${stack.partition}:lambda:${stack.region}:${stack.account}:function:${getDocStateFunc.functionName}`,
                `arn:${stack.partition}:lambda:${stack.region}:${stack.account}:function:${execRemediationFunc.functionName}`,
                `arn:${stack.partition}:lambda:${stack.region}:${stack.account}:function:${execMonFunc.functionName}`,
                `arn:${stack.partition}:lambda:${stack.region}:${stack.account}:function:${notifyFunc.functionName}`
            ]
        })
    )
    orchestratorPolicy.addStatements(
        new PolicyStatement({
            actions: [ 
                "kms:Encrypt",
                "kms:Decrypt",
                "kms:GenerateDataKey"
            ],
            effect: Effect.ALLOW,
            resources: [
                `arn:${stack.partition}:kms:${stack.region}:${stack.account}:alias/SO0111-SHARR-Key`
            ]
        })
    )
 
    const principal = new ServicePrincipal('states.amazonaws.com');
    const orchestratorRole = new Role(this, 'Role', {
        assumedBy: principal,
        inlinePolicies: {
            'BasePolicy': orchestratorPolicy
        }
    });

    {
        let childToMod = orchestratorRole.node.defaultChild as CfnRole
        childToMod.cfnOptions.metadata = {
            cfn_nag: {
                rules_to_suppress: [{
                    id: 'W11',
                    reason: 'CloudWatch Logs permissions require resource * except for DescribeLogGroups, except for GovCloud, which only works with resource *'
                }]
            }
        };
    }

    // As of March 2021, CWLogs encryption is not yet supported in GovCloud
    // Choose based on partition
    const orchestratorLogGroupEncrypted: LogGroup = new LogGroup(this, 'SO0111-SHARR-Orchestrator-AFSBP-Encrypted', {
        logGroupName: 'SO0111-SHARR-Orchestrator-AFSBP',
        removalPolicy: cdk.RemovalPolicy.RETAIN,
        retention: RetentionDays.ONE_YEAR,
        encryptionKey: sharrKmsKey
    });
    const isNotGovCloud = new cdk.CfnCondition(this, "isNotGovCloud", {
        expression: cdk.Fn.conditionNot(cdk.Fn.conditionEquals(stack.partition, "aws-us-gov"))
    });

    {
        let childToMod = orchestratorLogGroupEncrypted.node.defaultChild as CfnLogGroup;
        childToMod.cfnOptions.condition = isNotGovCloud
    }

    const orchestratorLogGroupNOTEncrypted: LogGroup = new LogGroup(this, 'SO0111-SHARR-Orchestrator-AFSBP', {
        logGroupName: 'SO0111-SHARR-Orchestrator-AFSBP',
        removalPolicy: cdk.RemovalPolicy.RETAIN,
        retention: RetentionDays.ONE_YEAR
    });

    {
        let childToMod = orchestratorLogGroupNOTEncrypted.node.defaultChild as CfnLogGroup;
        childToMod.cfnOptions.condition = new cdk.CfnCondition(this, "isGovCloud", {
            expression: cdk.Fn.conditionNot(isNotGovCloud)
        })
        childToMod.cfnOptions.metadata = {
            cfn_nag: {
                rules_to_suppress: [{
                    id: 'W84',
                    reason: 'KmsKeyId is not supported in GovCloud.'
                }]
            }
        }
    }

    const orchestratorStateMachine = new sfn.StateMachine(this, 'StateMachine', {
        definition: extractFindings,
        stateMachineName: 'SO0111-SHARR-Orchestrator-AFSBP',
        timeout: cdk.Duration.minutes(15),
        role: orchestratorRole
    });

    // Use an escape hatch to handle conditionally using the encryped or unencrypted CW LogsGroup
    const stateMachineConstruct = orchestratorStateMachine.node.defaultChild as sfn.CfnStateMachine
    stateMachineConstruct.addOverride('Properties.LoggingConfiguration', {
        "Destinations": [
            {
                "CloudWatchLogsLogGroup": {
                    "LogGroupArn": {
                        "Fn::If": [
                            isNotGovCloud.logicalId,
                            orchestratorLogGroupEncrypted.logGroupArn,
                            orchestratorLogGroupNOTEncrypted.logGroupArn
                        ]
                    }
                }
            }
        ],
        "IncludeExecutionData": true,
        "Level": "ALL"
    })

    // Remove the unnecessary Policy created by the L2 StateMachine construct
    let roleToModify = this.node.findChild('Role') as CfnRole;
    if (roleToModify) {
        roleToModify.node.tryRemoveChild('DefaultPolicy')
    }

    this.orchestratorArn = orchestratorStateMachine.stateMachineArn
  }
}