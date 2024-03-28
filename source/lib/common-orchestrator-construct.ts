// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { Stack, Duration, RemovalPolicy, CfnParameter, CfnResource, Fn, NestedStack } from 'aws-cdk-lib';
import { PolicyDocument, PolicyStatement, Role, Effect, ServicePrincipal, CfnRole } from 'aws-cdk-lib/aws-iam';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as sfn from 'aws-cdk-lib/aws-stepfunctions';
import { LambdaInvoke, SqsSendMessage } from 'aws-cdk-lib/aws-stepfunctions-tasks';
import { StringParameter } from 'aws-cdk-lib/aws-ssm';
import { Construct } from 'constructs';
import * as cdk_nag from 'cdk-nag';
import { Timeout } from 'aws-cdk-lib/aws-stepfunctions';
import { IQueue } from 'aws-cdk-lib/aws-sqs';

export interface ConstructProps {
  roleArn: string;
  ssmDocStateLambda: string;
  ssmExecDocLambda: string;
  ssmExecMonitorLambda: string;
  notifyLambda: string;
  getApprovalRequirementLambda: string;
  solutionId: string;
  solutionName: string;
  solutionVersion: string;
  orchLogGroup: string;
  kmsKeyParm: StringParameter; // to force dependency
  sqsQueue: IQueue;
}

export class OrchestratorConstruct extends Construct {
  nestedStack: NestedStack;
  constructor(scope: Construct, id: string, props: ConstructProps) {
    super(scope, id);

    const stack = Stack.of(this);
    const RESOURCE_PREFIX = props.solutionId.replace(/^DEV-/, ''); // prefix on every resource name

    const extractFindings = new sfn.Pass(this, 'Get Finding Data from Input', {
      comment: 'Extract top-level data needed for remediation',
      parameters: {
        'EventType.$': '$.detail-type',
        'Findings.$': '$.detail.findings',
      },
    });

    const nestedLogStack = this.createLogStack(props.kmsKeyParm);
    this.nestedStack = nestedLogStack;

    const getDocStateFunc: lambda.IFunction = lambda.Function.fromFunctionAttributes(this, 'getDocStateFunc', {
      functionArn: props.ssmDocStateLambda,
    });

    const execRemediationFunc: lambda.IFunction = lambda.Function.fromFunctionAttributes(this, 'execRemediationFunc', {
      functionArn: props.ssmExecDocLambda,
    });

    const execMonFunc: lambda.IFunction = lambda.Function.fromFunctionAttributes(this, 'getExecStatusFunc', {
      functionArn: props.ssmExecMonitorLambda,
    });

    const notifyFunc: lambda.IFunction = lambda.Function.fromFunctionAttributes(this, 'notifyFunc', {
      functionArn: props.notifyLambda,
    });

    const getApprovalRequirementFunc: lambda.IFunction = lambda.Function.fromFunctionAttributes(
      this,
      'getRequirementFunc',
      {
        functionArn: props.getApprovalRequirementLambda,
      },
    );

    const orchestratorFailed = new sfn.Pass(this, 'Orchestrator Failed', {
      parameters: {
        Notification: {
          'Message.$': "States.Format('Orchestrator failed: {}', $.Error)",
          'State.$': "States.Format('LAMBDAERROR')",
          'Details.$': "States.Format('Cause: {}', $.Cause)",
        },
        'Payload.$': '$',
      },
    });

    const getDocState = new LambdaInvoke(this, 'Get Automation Document State', {
      comment: 'Get the status of the remediation automation document in the target account',
      lambdaFunction: getDocStateFunc,
      taskTimeout: Timeout.duration(Duration.minutes(1)),
      resultSelector: {
        'DocState.$': '$.Payload.status',
        'Message.$': '$.Payload.message',
        'SecurityStandard.$': '$.Payload.securitystandard',
        'SecurityStandardVersion.$': '$.Payload.securitystandardversion',
        'SecurityStandardSupported.$': '$.Payload.standardsupported',
        'ControlId.$': '$.Payload.controlid',
        'AccountId.$': '$.Payload.accountid',
        'RemediationRole.$': '$.Payload.remediationrole',
        'AutomationDocId.$': '$.Payload.automationdocid',
        'ResourceRegion.$': '$.Payload.resourceregion',
      },
      resultPath: '$.AutomationDocument',
    });
    getDocState.addCatch(orchestratorFailed);

    const getApprovalRequirement = new LambdaInvoke(this, 'Get Remediation Approval Requirement', {
      comment: 'Determine whether the selected remediation requires manual approval',
      lambdaFunction: getApprovalRequirementFunc,
      taskTimeout: Timeout.duration(Duration.minutes(5)),
      resultSelector: {
        'WorkflowDocument.$': '$.Payload.workflowdoc',
        'WorkflowAccount.$': '$.Payload.workflowaccount',
        'WorkflowRole.$': '$.Payload.workflowrole',
        'WorkflowConfig.$': '$.Payload.workflow_data',
      },
      resultPath: '$.Workflow',
    });
    getApprovalRequirement.addCatch(orchestratorFailed);

    const remediationWait = new sfn.Wait(this, 'Remediation Wait', {
      comment: 'Waiting for remediation',
      time: sfn.WaitTime.timestampPath('$.PlannedTimestamp'),
    });

    const sendTaskToken = new SqsSendMessage(this, 'Send Task Token', {
      comment: 'Send Task Token to SQS Queue for Remediation Scheduling',
      integrationPattern: sfn.IntegrationPattern.WAIT_FOR_TASK_TOKEN,
      queue: props.sqsQueue,
      messageBody: sfn.TaskInput.fromObject({
        RemediationDetails: sfn.JsonPath.stringAt('$'),
        TaskToken: sfn.JsonPath.taskToken,
        AccountId: sfn.JsonPath.stringAt('$.AutomationDocument.AccountId'),
        ResourceRegion: sfn.JsonPath.stringAt('$.AutomationDocument.ResourceRegion'),
        executionId: sfn.JsonPath.stringAt('$$.Execution.Id'),
      }),
    });
    sendTaskToken.addCatch(orchestratorFailed);

    const remediateFinding = new LambdaInvoke(this, 'Execute Remediation', {
      comment: 'Execute the SSM Automation Document in the target account',
      lambdaFunction: execRemediationFunc,
      heartbeatTimeout: Timeout.duration(Duration.seconds(60)),
      taskTimeout: Timeout.duration(Duration.minutes(5)),
      resultSelector: {
        'ExecState.$': '$.Payload.status',
        'Message.$': '$.Payload.message',
        'ExecId.$': '$.Payload.executionid',
        'Account.$': '$.Payload.executionaccount',
        'Region.$': '$.Payload.executionregion',
      },
      resultPath: '$.SSMExecution',
    });
    remediateFinding.addCatch(orchestratorFailed);

    const execMonitor = new LambdaInvoke(this, 'execMonitor', {
      comment: 'Monitor the remediation execution until done',
      lambdaFunction: execMonFunc,
      heartbeatTimeout: Timeout.duration(Duration.seconds(60)),
      taskTimeout: Timeout.duration(Duration.minutes(5)),
      resultSelector: {
        'ExecState.$': '$.Payload.status',
        'ExecId.$': '$.Payload.executionid',
        'RemediationState.$': '$.Payload.remediation_status',
        'Message.$': '$.Payload.message',
        'LogData.$': '$.Payload.logdata',
        'AffectedObject.$': '$.Payload.affected_object',
      },
      resultPath: '$.Remediation',
    });
    execMonitor.addCatch(orchestratorFailed);

    const notify = new LambdaInvoke(this, 'notify', {
      comment: 'Send notifications',
      lambdaFunction: notifyFunc,
      heartbeatTimeout: Timeout.duration(Duration.seconds(60)),
      taskTimeout: Timeout.duration(Duration.minutes(5)),
    });

    const notifyQueued = new LambdaInvoke(this, 'Queued Notification', {
      comment: 'Send notification that a remediation has queued',
      lambdaFunction: notifyFunc,
      heartbeatTimeout: Timeout.duration(Duration.seconds(60)),
      taskTimeout: Timeout.duration(Duration.minutes(5)),
      resultPath: '$.notificationResult',
    });

    new sfn.Fail(this, 'Job Failed', {
      cause: 'AWS Batch Job Failed',
      error: 'DescribeJob returned FAILED',
    });

    const eoj = new sfn.Pass(this, 'EOJ', {
      comment: 'END-OF-JOB',
    });

    const processFindings = new sfn.Map(this, 'Process Findings', {
      comment: 'Process all findings in CloudWatch Event',
      parameters: {
        'Finding.$': '$$.Map.Item.Value',
        'EventType.$': '$.EventType',
      },
      itemsPath: '$.Findings',
    });

    // Set notification. If the when is not matched then this will be the notification sent
    const checkWorkflowNew = new sfn.Choice(this, 'Finding Workflow State NEW?');

    const docNotNew = new sfn.Pass(this, 'Finding Workflow State is not NEW', {
      parameters: {
        Notification: {
          'Message.$': "States.Format('Finding Workflow State is not NEW ({}).', $.Finding.Workflow.Status)",
          'State.$': "States.Format('NOTNEW')",
        },
        'EventType.$': '$.EventType',
        'Finding.$': '$.Finding',
      },
    });

    const checkDocState = new sfn.Choice(this, 'Automation Doc Active?');

    const docStateNotActive = new sfn.Pass(this, 'Automation Document is not Active', {
      parameters: {
        Notification: {
          'Message.$':
            "States.Format('Automation Document ({}) is not active ({}) in the member account({}).', $.AutomationDocId, $.AutomationDocument.DocState, $.Finding.AwsAccountId)",
          'State.$': "States.Format('REMEDIATIONNOTACTIVE')",
          updateSecHub: 'yes',
        },
        'EventType.$': '$.EventType',
        'Finding.$': '$.Finding',
        'AccountId.$': '$.AutomationDocument.AccountId',
        'AutomationDocId.$': '$.AutomationDocument.AutomationDocId',
        'RemediationRole.$': '$.AutomationDocument.RemediationRole',
        'ControlId.$': '$.AutomationDocument.ControlId',
        'SecurityStandard.$': '$.AutomationDocument.SecurityStandard',
        'SecurityStandardVersion.$': '$.AutomationDocument.SecurityStandardVersion',
      },
    });

    const controlNoRemediation = new sfn.Pass(this, 'No Remediation for Control', {
      parameters: {
        Notification: {
          'Message.$':
            "States.Format('Security Standard {} v{} control {} has no automated remediation.', $.AutomationDocument.SecurityStandard, $.AutomationDocument.SecurityStandardVersion, $.AutomationDocument.ControlId)",
          'State.$': "States.Format('NOREMEDIATION')",
          updateSecHub: 'yes',
        },
        'EventType.$': '$.EventType',
        'Finding.$': '$.Finding',
        'AccountId.$': '$.AutomationDocument.AccountId',
        'AutomationDocId.$': '$.AutomationDocument.AutomationDocId',
        'RemediationRole.$': '$.AutomationDocument.RemediationRole',
        'ControlId.$': '$.AutomationDocument.ControlId',
        'SecurityStandard.$': '$.AutomationDocument.SecurityStandard',
        'SecurityStandardVersion.$': '$.AutomationDocument.SecurityStandardVersion',
      },
    });

    const standardNotEnabled = new sfn.Pass(this, 'Security Standard is not enabled', {
      parameters: {
        Notification: {
          'Message.$':
            "States.Format('Security Standard ({}) v{} is not enabled.', $.AutomationDocument.SecurityStandard, $.AutomationDocument.SecurityStandardVersion)",
          'State.$': "States.Format('STANDARDNOTENABLED')",
          updateSecHub: 'yes',
        },
        'EventType.$': '$.EventType',
        'Finding.$': '$.Finding',
        'AccountId.$': '$.AutomationDocument.AccountId',
        'AutomationDocId.$': '$.AutomationDocument.AutomationDocId',
        'RemediationRole.$': '$.AutomationDocument.RemediationRole',
        'ControlId.$': '$.AutomationDocument.ControlId',
        'SecurityStandard.$': '$.AutomationDocument.SecurityStandard',
        'SecurityStandardVersion.$': '$.AutomationDocument.SecurityStandardVersion',
      },
    });

    const docStateError = new sfn.Pass(this, 'check_ssm_doc_state Error', {
      parameters: {
        Notification: {
          'Message.$': "States.Format('check_ssm_doc_state returned an error: {}', $.AutomationDocument.Message)",
          'State.$': "States.Format('LAMBDAERROR')",
        },
        'EventType.$': '$.EventType',
        'Finding.$': '$.Finding',
      },
    });

    const isdone = new sfn.Choice(this, 'Remediation completed?');

    const waitForRemediation = new sfn.Wait(this, 'Wait for Remediation', {
      time: sfn.WaitTime.duration(Duration.seconds(15)),
    });

    const remediationFailed = new sfn.Pass(this, 'Remediation Failed', {
      comment: 'Set parameters for notification',
      parameters: {
        'EventType.$': '$.EventType',
        'Finding.$': '$.Finding',
        'SSMExecution.$': '$.SSMExecution',
        'AutomationDocument.$': '$.AutomationDocument',
        Notification: {
          'Message.$':
            "States.Format('Remediation failed for {} control {} in account {}: {}', $.AutomationDocument.SecurityStandard, $.AutomationDocument.ControlId, $.AutomationDocument.AccountId, $.Remediation.Message)",
          'State.$': '$.Remediation.ExecState',
          'Details.$': '$.Remediation.LogData',
          'ExecId.$': '$.Remediation.ExecId',
          'AffectedObject.$': '$.Remediation.AffectedObject',
        },
      },
    });

    const remediationSucceeded = new sfn.Pass(this, 'Remediation Succeeded', {
      comment: 'Set parameters for notification',
      parameters: {
        'EventType.$': '$.EventType',
        'Finding.$': '$.Finding',
        'AccountId.$': '$.AutomationDocument.AccountId',
        'AutomationDocId.$': '$.AutomationDocument.AutomationDocId',
        'RemediationRole.$': '$.AutomationDocument.RemediationRole',
        'ControlId.$': '$.AutomationDocument.ControlId',
        'SecurityStandard.$': '$.AutomationDocument.SecurityStandard',
        'SecurityStandardVersion.$': '$.AutomationDocument.SecurityStandardVersion',
        Notification: {
          'Message.$':
            "States.Format('Remediation succeeded for {} control {} in account {}: {}', $.AutomationDocument.SecurityStandard, $.AutomationDocument.ControlId, $.AutomationDocument.AccountId, $.Remediation.Message)",
          'State.$': "States.Format('SUCCESS')",
          'Details.$': '$.Remediation.LogData',
          'ExecId.$': '$.Remediation.ExecId',
          'AffectedObject.$': '$.Remediation.AffectedObject',
        },
      },
    });

    const remediationQueued = new sfn.Pass(this, 'Remediation Queued', {
      comment: 'Set parameters for notification',
      parameters: {
        'EventType.$': '$.EventType',
        'Finding.$': '$.Finding',
        'AutomationDocument.$': '$.AutomationDocument',
        'SSMExecution.$': '$.SSMExecution',
        Notification: {
          'Message.$':
            "States.Format('Remediation queued for {} control {} in account {}', $.AutomationDocument.SecurityStandard, $.AutomationDocument.ControlId, $.AutomationDocument.AccountId)",
          'State.$': "States.Format('QUEUED')",
          'ExecId.$': '$.SSMExecution.ExecId',
        },
      },
    });

    //-----------------------------------------------------------------
    // State Machine
    //
    extractFindings.next(processFindings);

    checkWorkflowNew.when(
      sfn.Condition.or(
        sfn.Condition.stringEquals('$.EventType', 'Security Hub Findings - Custom Action'),
        sfn.Condition.and(
          sfn.Condition.stringEquals('$.Finding.Workflow.Status', 'NEW'),
          sfn.Condition.stringEquals('$.EventType', 'Security Hub Findings - Imported'),
        ),
      ),
      getApprovalRequirement,
    );
    checkWorkflowNew.otherwise(docNotNew);

    docNotNew.next(notify);

    // Call Lambda to get status of the automation document in the target account
    getDocState.next(checkDocState);

    getApprovalRequirement.next(getDocState);

    checkDocState.when(sfn.Condition.stringEquals('$.AutomationDocument.DocState', 'ACTIVE'), sendTaskToken);
    checkDocState.when(sfn.Condition.stringEquals('$.AutomationDocument.DocState', 'NOTACTIVE'), docStateNotActive);
    checkDocState.when(sfn.Condition.stringEquals('$.AutomationDocument.DocState', 'NOTENABLED'), standardNotEnabled);
    checkDocState.when(sfn.Condition.stringEquals('$.AutomationDocument.DocState', 'NOTFOUND'), controlNoRemediation);
    checkDocState.otherwise(docStateError);

    docStateNotActive.next(notify);

    standardNotEnabled.next(notify);

    controlNoRemediation.next(notify);

    docStateError.next(notify);

    // Execute the remediation
    // remediateFinding.next(execMonitor)

    sendTaskToken.next(remediationWait);

    remediationWait.next(remediateFinding);
    // Send a notification
    remediateFinding.next(remediationQueued);

    remediationQueued.next(notifyQueued);

    notifyQueued.next(execMonitor);

    execMonitor.next(isdone);

    isdone.when(sfn.Condition.stringEquals('$.Remediation.RemediationState', 'Failed'), remediationFailed);
    isdone.when(sfn.Condition.stringEquals('$.Remediation.ExecState', 'Success'), remediationSucceeded);
    isdone.when(sfn.Condition.stringEquals('$.Remediation.ExecState', 'TimedOut'), remediationFailed);
    isdone.when(sfn.Condition.stringEquals('$.Remediation.ExecState', 'Cancelling'), remediationFailed);
    isdone.when(sfn.Condition.stringEquals('$.Remediation.ExecState', 'Cancelled'), remediationFailed);
    isdone.when(sfn.Condition.stringEquals('$.Remediation.ExecState', 'Failed'), remediationFailed);
    isdone.otherwise(waitForRemediation);

    waitForRemediation.next(execMonitor);

    orchestratorFailed.next(notify);

    remediationFailed.next(notify);

    remediationSucceeded.next(notify);

    processFindings.iterator(checkWorkflowNew).next(eoj);

    const orchestratorPolicy = new PolicyDocument();
    orchestratorPolicy.addStatements(
      new PolicyStatement({
        actions: [
          'logs:CreateLogDelivery',
          'logs:GetLogDelivery',
          'logs:UpdateLogDelivery',
          'logs:DeleteLogDelivery',
          'logs:ListLogDeliveries',
          'logs:PutResourcePolicy',
          'logs:DescribeResourcePolicies',
          'logs:DescribeLogGroups',
        ],
        effect: Effect.ALLOW,
        resources: ['*'],
      }),
    );
    orchestratorPolicy.addStatements(
      new PolicyStatement({
        actions: ['lambda:InvokeFunction'],
        effect: Effect.ALLOW,
        resources: [
          `arn:${stack.partition}:lambda:${stack.region}:${stack.account}:function:${getDocStateFunc.functionName}`,
          `arn:${stack.partition}:lambda:${stack.region}:${stack.account}:function:${execRemediationFunc.functionName}`,
          `arn:${stack.partition}:lambda:${stack.region}:${stack.account}:function:${execMonFunc.functionName}`,
          `arn:${stack.partition}:lambda:${stack.region}:${stack.account}:function:${notifyFunc.functionName}`,
          `arn:${stack.partition}:lambda:${stack.region}:${stack.account}:function:${getApprovalRequirementFunc.functionName}`,
        ],
      }),
    );
    orchestratorPolicy.addStatements(
      new PolicyStatement({
        actions: ['kms:Encrypt', 'kms:Decrypt', 'kms:GenerateDataKey'],
        effect: Effect.ALLOW,
        resources: [
          `arn:${stack.partition}:kms:${stack.region}:${stack.account}:alias/${RESOURCE_PREFIX}-SHARR-Key`,
          props.kmsKeyParm.stringValue,
        ],
      }),
    );
    orchestratorPolicy.addStatements(
      new PolicyStatement({
        actions: ['sqs:SendMessage'],
        effect: Effect.ALLOW,
        resources: [props.sqsQueue.queueArn],
      }),
    );

    const principal = new ServicePrincipal(`states.amazonaws.com`);
    const orchestratorRole = new Role(this, 'Role', {
      assumedBy: principal,
      inlinePolicies: {
        BasePolicy: orchestratorPolicy,
      },
    });
    orchestratorRole.applyRemovalPolicy(RemovalPolicy.RETAIN);
    {
      const childToMod = orchestratorRole.node.defaultChild as CfnRole;
      childToMod.cfnOptions.metadata = {
        cfn_nag: {
          rules_to_suppress: [
            {
              id: 'W11',
              reason:
                'CloudWatch Logs permissions require resource * except for DescribeLogGroups, except for GovCloud, which only works with resource *',
            },
          ],
        },
      };
    }

    cdk_nag.NagSuppressions.addResourceSuppressions(orchestratorRole, [
      {
        id: 'AwsSolutions-IAM5',
        reason:
          'CloudWatch Logs permissions require resource * except for DescribeLogGroups, except for GovCloud, which only works with resource *',
      },
    ]);

    const orchestratorStateMachine = new sfn.StateMachine(this, 'StateMachine', {
      definitionBody: sfn.DefinitionBody.fromChainable(extractFindings),
      stateMachineName: `${RESOURCE_PREFIX}-SHARR-Orchestrator`,
      timeout: Duration.minutes(90),
      role: orchestratorRole,
    });

    new StringParameter(this, 'SHARR_Orchestrator_Arn', {
      description:
        'Arn of the SHARR Orchestrator Step Function. This step function routes findings to remediation runbooks.',
      parameterName: '/Solutions/' + RESOURCE_PREFIX + '/OrchestratorArn',
      stringValue: orchestratorStateMachine.stateMachineArn,
    });

    // The arn for the CloudWatch logs group will be the same, regardless of encryption or not,
    // regardless of reuse or not. Set it here:
    const orchestratorLogGroupArn = `arn:${stack.partition}:logs:${stack.region}:${stack.account}:log-group:${props.orchLogGroup}:*`;

    // Use an escape hatch to handle conditionally using the encrypted or unencrypted CW LogsGroup
    const stateMachineConstruct = orchestratorStateMachine.node.defaultChild as sfn.CfnStateMachine;
    stateMachineConstruct.addOverride('Properties.LoggingConfiguration', {
      Destinations: [
        {
          CloudWatchLogsLogGroup: {
            LogGroupArn: orchestratorLogGroupArn,
          },
        },
      ],
      IncludeExecutionData: true,
      Level: 'ALL',
    });
    stateMachineConstruct.addDependency(nestedLogStack.nestedStackResource as CfnResource);

    // Remove the unnecessary Policy created by the L2 StateMachine construct
    const roleToModify = this.node.findChild('Role') as CfnRole;
    if (roleToModify) {
      roleToModify.node.tryRemoveChild('DefaultPolicy');
    }

    cdk_nag.NagSuppressions.addResourceSuppressions(orchestratorStateMachine, [
      { id: 'AwsSolutions-SF1', reason: 'False alarm. Logging configuration is overridden to log ALL.' },
      { id: 'AwsSolutions-SF2', reason: 'X-Ray is not needed for this use case.' },
    ]);
  }

  private createLogStack(kmsKeyParm: StringParameter): NestedStack {
    const reuseOrchLogGroup = new CfnParameter(this, 'Reuse Log Group', {
      type: 'String',
      description: `Reuse existing Orchestrator Log Group? Choose "yes" if the log group already exists, else "no"`,
      default: 'no',
      allowedValues: ['yes', 'no'],
    });

    reuseOrchLogGroup.overrideLogicalId(`ReuseOrchestratorLogGroup`);

    const logStack = new NestedStack(this, 'NestedLogStack', {
      parameters: {
        KmsKeyArn: kmsKeyParm.stringValue,
        ReuseOrchestratorLogGroup: reuseOrchLogGroup.valueAsString,
      },
    });
    const cfnStack = logStack.nestedStackResource as CfnResource;

    cfnStack.addPropertyOverride(
      'TemplateURL',
      'https://' +
        Fn.findInMap('SourceCode', 'General', 'S3Bucket') +
        '-reference.s3.amazonaws.com/' +
        Fn.findInMap('SourceCode', 'General', 'KeyPrefix') +
        '/aws-sharr-orchestrator-log.template',
    );
    return logStack;
  }
}
