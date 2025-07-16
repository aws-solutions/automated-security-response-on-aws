// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import * as cdk from 'aws-cdk-lib';
import { App, CfnOutput, Fn } from 'aws-cdk-lib';
import * as s3 from 'aws-cdk-lib/aws-s3';
import * as sns from 'aws-cdk-lib/aws-sns';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import { Tracing } from 'aws-cdk-lib/aws-lambda';
import * as dynamodb from 'aws-cdk-lib/aws-dynamodb';
import * as sqs from 'aws-cdk-lib/aws-sqs';
import { CfnParameter, StringParameter } from 'aws-cdk-lib/aws-ssm';
import * as kms from 'aws-cdk-lib/aws-kms';
import * as lambdaEventSources from 'aws-cdk-lib/aws-lambda-event-sources';
import {
  AccountRootPrincipal,
  CfnPolicy,
  CfnRole,
  Policy,
  PolicyDocument,
  PolicyStatement,
  Role,
  ServicePrincipal,
} from 'aws-cdk-lib/aws-iam';
import { OrchestratorConstruct } from './common-orchestrator-construct';
import { CfnStateMachine, StateMachine } from 'aws-cdk-lib/aws-stepfunctions';
import { OneTrigger } from './ssmplaybook';
import { CloudWatchMetrics } from './cloudwatch_metrics';
import { AdminPlaybook } from './admin-playbook';
import { scPlaybookProps, standardPlaybookProps } from '../playbooks/playbook-index';
import { ActionLog } from './action-log';
import { addCfnGuardSuppression } from './cdk-helper/add-cfn-guard-suppression';
import AccountTargetParam from './parameters/account-target-param';
import MetricResources from './cdk-helper/metric-resources';

export interface ASRStackProps extends cdk.StackProps {
  solutionId: string;
  solutionVersion: string;
  solutionDistBucket: string;
  solutionTMN: string;
  solutionName: string;
  runtimePython: lambda.Runtime;
  orchestratorLogGroup: string;
  SNSTopicName: string;
  cloudTrailLogGroupName: string;
}

export class AdministratorStack extends cdk.Stack {
  private static readonly sendAnonymizedData: string = 'Yes';
  private readonly primarySolutionSNSTopicARN: string;

  constructor(scope: App, id: string, props: ASRStackProps) {
    super(scope, id, props);
    const stack = cdk.Stack.of(this);
    const RESOURCE_NAME_PREFIX = props.solutionId.replace(/^DEV-/, ''); // prefix on every resource name

    //=============================================================================================
    // Parameters
    //=============================================================================================
    const accountTargetParam = new AccountTargetParam(this, 'AccountTargetParams');

    //-------------------------------------------------------------------------
    // Solutions Bucket - Source Code
    //
    const solutionsBucket = s3.Bucket.fromBucketAttributes(this, 'SolutionsBucket', {
      bucketName: props.solutionDistBucket + '-' + this.region,
    });

    //=========================================================================
    // MAPPINGS
    //=========================================================================
    new cdk.CfnMapping(this, 'SourceCode', {
      mapping: {
        General: {
          S3Bucket: props.solutionDistBucket,
          KeyPrefix: props.solutionTMN + '/' + props.solutionVersion,
        },
      },
    });

    //-------------------------------------------------------------------------
    // KMS Key for solution encryption
    //

    // Key Policy
    const kmsKeyPolicy: PolicyDocument = new PolicyDocument();

    const kmsServicePolicy = new PolicyStatement({
      principals: [new ServicePrincipal('sns.amazonaws.com'), new ServicePrincipal(`logs.${this.urlSuffix}`)],
      actions: ['kms:Encrypt*', 'kms:Decrypt*', 'kms:ReEncrypt*', 'kms:GenerateDataKey*', 'kms:Describe*'],
      resources: ['*'],
      conditions: {
        ArnEquals: {
          'kms:EncryptionContext:aws:logs:arn': this.formatArn({
            service: 'logs',
            resource: 'log-group:SO0111-ASR-*',
          }),
        },
      },
    });
    kmsKeyPolicy.addStatements(kmsServicePolicy);

    const kmsRootPolicy = new PolicyStatement({
      principals: [new AccountRootPrincipal()],
      actions: ['kms:*'],
      resources: ['*'],
    });
    kmsKeyPolicy.addStatements(kmsRootPolicy);

    const kmsKey = new kms.Key(this, 'SHARR-key', {
      enableKeyRotation: true,
      alias: `${RESOURCE_NAME_PREFIX}-SHARR-Key`,
      policy: kmsKeyPolicy,
    });

    const kmsKeyParm = new StringParameter(this, 'SHARR_Key', {
      description: 'KMS Customer Managed Key that SHARR will use to encrypt data',
      parameterName: `/Solutions/${RESOURCE_NAME_PREFIX}/CMK_ARN`,
      stringValue: kmsKey.keyArn,
    });

    //-------------------------------------------------------------------------
    // SNS Topic for notification fanout on Playbook completion
    //
    const primarySolutionTopic = new sns.Topic(this, 'SHARR-Topic', {
      displayName: `Automated Security Response on AWS (${RESOURCE_NAME_PREFIX}) Status Topic`,
      topicName: props.SNSTopicName,
      masterKey: kmsKey,
    });
    this.primarySolutionSNSTopicARN = `arn:${stack.partition}:sns:${stack.region}:${stack.account}:${props.SNSTopicName}`;

    new StringParameter(this, 'SHARR_SNS_Topic', {
      description:
        'SNS Topic ARN where ASR will send status messages. This topic can be useful for driving additional actions, such as email notifications, trouble ticket updates.',
      parameterName: '/Solutions/' + RESOURCE_NAME_PREFIX + '/SNS_Topic_ARN',
      stringValue: primarySolutionTopic.topicArn,
    });

    const mapping = new cdk.CfnMapping(this, 'mappings');
    mapping.setValue('sendAnonymizedMetrics', 'data', AdministratorStack.sendAnonymizedData);

    new StringParameter(this, 'SHARR_SendAnonymousMetrics', {
      description: 'Flag to enable or disable sending anonymous metrics.',
      parameterName: '/Solutions/' + RESOURCE_NAME_PREFIX + '/sendAnonymizedMetrics',
      stringValue: mapping.findInMap('sendAnonymizedMetrics', 'data'),
    });

    new StringParameter(this, 'SHARR_version', {
      description: 'Solution version for metrics.',
      parameterName: '/Solutions/' + RESOURCE_NAME_PREFIX + '/version',
      stringValue: props.solutionVersion,
    });

    const asrLambdaLayer = new lambda.LayerVersion(this, 'ASRLambdaLayer', {
      compatibleRuntimes: [props.runtimePython],
      description: 'SO0111 ASR Common functions used by the solution',
      license: 'https://www.apache.org/licenses/LICENSE-2.0',
      code: lambda.Code.fromBucket(
        solutionsBucket,
        props.solutionTMN + '/' + props.solutionVersion + '/lambda/layer.zip',
      ),
    });

    /**
     * @description Policy for role used by common Orchestrator Lambdas
     * @type {Policy}
     */
    const orchestratorPolicy = new Policy(this, 'orchestratorPolicy', {
      policyName: RESOURCE_NAME_PREFIX + '-ASR_Orchestrator',
      statements: [
        new PolicyStatement({
          actions: ['logs:CreateLogStream', 'logs:PutLogEvents'],
          resources: [`arn:${this.partition}:logs:*:${this.account}:log-group:*:log-stream:*`],
        }),
        new PolicyStatement({
          actions: ['logs:CreateLogGroup'],
          resources: [`arn:${this.partition}:logs:*:${this.account}:log-group:*`],
        }),
        new PolicyStatement({
          actions: ['ssm:GetParameter', 'ssm:GetParameters', 'ssm:PutParameter'],
          resources: [`arn:${this.partition}:ssm:*:${this.account}:parameter/Solutions/SO0111/*`],
        }),
        new PolicyStatement({
          actions: ['sts:AssumeRole'],
          resources: [
            `arn:${this.partition}:iam::*:role/${RESOURCE_NAME_PREFIX}-ASR-Orchestrator-Member`,
            //'arn:' + this.partition + ':iam::*:role/' + RESOURCE_NAME_PREFIX +
            //'-Remediate-*',
          ],
        }),
        // Supports https://gitlab.aws.dev/dangibbo/sharr-remediation-framework
        new PolicyStatement({
          actions: ['organizations:ListTagsForResource'],
          resources: ['*'],
        }),
      ],
    });

    {
      const childToMod = orchestratorPolicy.node.findChild('Resource') as CfnPolicy;
      childToMod.cfnOptions.metadata = {
        cfn_nag: {
          rules_to_suppress: [
            {
              id: 'W12',
              reason: 'Resource * is required for read-only policies used by orchestrator Lambda functions.',
            },
          ],
        },
      };
    }

    /**
     * @description Role used by common Orchestrator Lambdas
     * @type {Role}
     */

    const orchestratorRole: Role = new Role(this, 'orchestratorRole', {
      assumedBy: new ServicePrincipal('lambda.amazonaws.com'),
      description: 'Lambda role to allow cross account read-only ASR orchestrator functions',
      roleName: `${RESOURCE_NAME_PREFIX}-ASR-Orchestrator-Admin`,
    });

    orchestratorRole.attachInlinePolicy(orchestratorPolicy);

    {
      const childToMod = orchestratorRole.node.findChild('Resource') as CfnRole;
      childToMod.cfnOptions.metadata = {
        cfn_nag: {
          rules_to_suppress: [
            {
              id: 'W28',
              reason:
                'Static names chosen intentionally to provide easy integration with playbook orchestrator step functions.',
            },
          ],
        },
      };
    }
    addCfnGuardSuppression(orchestratorRole, 'IAM_NO_INLINE_POLICY_CHECK');

    const checkSSMDocumentState = new lambda.Function(this, 'checkSSMDocumentState', {
      functionName: RESOURCE_NAME_PREFIX + '-ASR-checkSSMDocumentState',
      handler: 'check_ssm_doc_state.lambda_handler',
      runtime: props.runtimePython,
      description: 'Checks the status of an SSM Automation Document in the target account',
      code: lambda.Code.fromBucket(
        solutionsBucket,
        props.solutionTMN + '/' + props.solutionVersion + '/lambda/check_ssm_doc_state.py.zip',
      ),
      environment: {
        log_level: 'info',
        AWS_PARTITION: this.partition,
        SOLUTION_ID: props.solutionId,
        SOLUTION_VERSION: props.solutionVersion,
        SOLUTION_TMN: props.solutionTMN,
      },
      memorySize: 256,
      timeout: cdk.Duration.seconds(600),
      role: orchestratorRole,
      tracing: Tracing.ACTIVE,
      layers: [asrLambdaLayer],
    });

    {
      const childToMod = checkSSMDocumentState.node.findChild('Resource') as lambda.CfnFunction;

      childToMod.cfnOptions.metadata = {
        cfn_nag: {
          rules_to_suppress: [
            {
              id: 'W58',
              reason: 'False positive. Access is provided via a policy',
            },
            {
              id: 'W89',
              reason: 'There is no need to run this lambda in a VPC',
            },
            {
              id: 'W92',
              reason: 'There is no need for Reserved Concurrency',
            },
          ],
        },
      };
    }

    /**
     * @description getApprovalRequirement - determine whether manual approval is required
     * @type {lambda.Function}
     */
    const getApprovalRequirement = new lambda.Function(this, 'getApprovalRequirement', {
      functionName: RESOURCE_NAME_PREFIX + '-ASR-getApprovalRequirement',
      handler: 'get_approval_requirement.lambda_handler',
      runtime: props.runtimePython,
      description: 'Determines if a manual approval is required for remediation',
      code: lambda.Code.fromBucket(
        solutionsBucket,
        props.solutionTMN + '/' + props.solutionVersion + '/lambda/get_approval_requirement.py.zip',
      ),
      environment: {
        log_level: 'info',
        AWS_PARTITION: this.partition,
        SOLUTION_ID: props.solutionId,
        SOLUTION_VERSION: props.solutionVersion,
        WORKFLOW_RUNBOOK: '',
        SOLUTION_TMN: props.solutionTMN,
      },
      memorySize: 256,
      timeout: cdk.Duration.seconds(600),
      role: orchestratorRole,
      tracing: Tracing.ACTIVE,
      layers: [asrLambdaLayer],
    });

    {
      const childToMod = getApprovalRequirement.node.findChild('Resource') as lambda.CfnFunction;

      childToMod.cfnOptions.metadata = {
        cfn_nag: {
          rules_to_suppress: [
            {
              id: 'W58',
              reason: 'False positive. Access is provided via a policy',
            },
            {
              id: 'W89',
              reason: 'There is no need to run this lambda in a VPC',
            },
            {
              id: 'W92',
              reason: 'There is no need for Reserved Concurrency',
            },
          ],
        },
      };
    }

    /**
     * @description execAutomation - initiate an SSM automation document in a target account
     * @type {lambda.Function}
     */
    const execAutomation = new lambda.Function(this, 'execAutomation', {
      functionName: RESOURCE_NAME_PREFIX + '-ASR-execAutomation',
      handler: 'exec_ssm_doc.lambda_handler',
      runtime: props.runtimePython,
      description: 'Executes an SSM Automation Document in a target account',
      code: lambda.Code.fromBucket(
        solutionsBucket,
        props.solutionTMN + '/' + props.solutionVersion + '/lambda/exec_ssm_doc.py.zip',
      ),
      environment: {
        log_level: 'info',
        AWS_PARTITION: this.partition,
        SOLUTION_ID: props.solutionId,
        SOLUTION_VERSION: props.solutionVersion,
        SOLUTION_TMN: props.solutionTMN,
      },
      memorySize: 256,
      timeout: cdk.Duration.seconds(600),
      role: orchestratorRole,
      tracing: Tracing.ACTIVE,
      layers: [asrLambdaLayer],
    });

    {
      const childToMod = execAutomation.node.findChild('Resource') as lambda.CfnFunction;

      childToMod.cfnOptions.metadata = {
        cfn_nag: {
          rules_to_suppress: [
            {
              id: 'W58',
              reason: 'False positive. Access is provided via a policy',
            },
            {
              id: 'W89',
              reason: 'There is no need to run this lambda in a VPC',
            },
            {
              id: 'W92',
              reason: 'There is no need for Reserved Concurrency',
            },
          ],
        },
      };
    }

    /**
     * @description monitorSSMExecState - get the status of an ssm execution
     * @type {lambda.Function}
     */
    const monitorSSMExecState = new lambda.Function(this, 'monitorSSMExecState', {
      functionName: RESOURCE_NAME_PREFIX + '-ASR-monitorSSMExecState',
      handler: 'check_ssm_execution.lambda_handler',
      runtime: props.runtimePython,
      description: 'Checks the status of an SSM automation document execution',
      code: lambda.Code.fromBucket(
        solutionsBucket,
        props.solutionTMN + '/' + props.solutionVersion + '/lambda/check_ssm_execution.py.zip',
      ),
      environment: {
        log_level: 'info',
        AWS_PARTITION: this.partition,
        SOLUTION_ID: props.solutionId,
        SOLUTION_VERSION: props.solutionVersion,
        SOLUTION_TMN: props.solutionTMN,
      },
      memorySize: 256,
      timeout: cdk.Duration.seconds(600),
      role: orchestratorRole,
      tracing: Tracing.ACTIVE,
      layers: [asrLambdaLayer],
    });

    {
      const childToMod = monitorSSMExecState.node.findChild('Resource') as lambda.CfnFunction;

      childToMod.cfnOptions.metadata = {
        cfn_nag: {
          rules_to_suppress: [
            {
              id: 'W58',
              reason: 'False positive. Access is provided via a policy',
            },
            {
              id: 'W89',
              reason: 'There is no need to run this lambda in a VPC',
            },
            {
              id: 'W92',
              reason: 'There is no need for Reserved Concurrency',
            },
          ],
        },
      };
    }

    /**
     * @description Policy for role used by common Orchestrator notification lambda
     * @type {Policy}
     */
    const notifyPolicy = new Policy(this, 'notifyPolicy', {
      policyName: RESOURCE_NAME_PREFIX + '-ASR_Orchestrator_Notifier',
      statements: [
        new PolicyStatement({
          actions: ['logs:CreateLogGroup', 'logs:CreateLogStream', 'logs:PutLogEvents'],
          resources: ['*'],
        }),
        new PolicyStatement({
          actions: ['securityhub:BatchUpdateFindings'],
          resources: ['*'],
        }),
        new PolicyStatement({
          actions: ['ssm:GetParameter', 'ssm:PutParameter'],
          resources: [`arn:${this.partition}:ssm:${this.region}:${this.account}:parameter/Solutions/SO0111/*`],
        }),
        new PolicyStatement({
          actions: ['kms:Encrypt', 'kms:Decrypt', 'kms:GenerateDataKey'],
          resources: [kmsKey.keyArn],
        }),
        new PolicyStatement({
          actions: ['sns:Publish'],
          resources: [`arn:${this.partition}:sns:${this.region}:${this.account}:${RESOURCE_NAME_PREFIX}-ASR_Topic`],
        }),
        new PolicyStatement({
          actions: ['cloudwatch:PutMetricData'],
          resources: ['*'],
        }),
        new PolicyStatement({
          actions: ['organizations:ListAccounts'],
          resources: ['*'],
        }),
      ],
    });

    {
      const childToMod = notifyPolicy.node.findChild('Resource') as CfnPolicy;
      childToMod.cfnOptions.metadata = {
        cfn_nag: {
          rules_to_suppress: [
            {
              id: 'W12',
              reason:
                'Resource * is required for CloudWatch Logs and Security Hub policies used by core solution Lambda function for notifications.',
            },
            {
              id: 'W58',
              reason: 'False positive. Access is provided via a policy',
            },
          ],
        },
      };
    }

    notifyPolicy.attachToRole(orchestratorRole); // Any Orchestrator Lambda can send to sns

    /**
     * @description Role used by common Orchestrator Lambdas
     * @type {Role}
     */

    const notifyRole: Role = new Role(this, 'notifyRole', {
      assumedBy: new ServicePrincipal('lambda.amazonaws.com'),
      description: 'Lambda role to perform notification and logging from orchestrator step function',
    });

    notifyRole.attachInlinePolicy(notifyPolicy);

    {
      const childToMod = notifyRole.node.findChild('Resource') as CfnRole;
      childToMod.cfnOptions.metadata = {
        cfn_nag: {
          rules_to_suppress: [
            {
              id: 'W28',
              reason:
                'Static names chosen intentionally to provide easy integration with playbook orchestrator step functions.',
            },
          ],
        },
      };
    }

    // Defined outside cloudwatch_metrics.ts to avoid dependency loop between cloudWatchMetrics and orchStateMachine
    const enableEnhancedCloudWatchMetrics = new cdk.CfnParameter(this, 'EnableEnhancedCloudWatchMetrics', {
      type: 'String',
      description: `Enable collection of metrics per Control ID in addition to standard metrics. You must also select 'yes' for UseCloudWatchMetrics to enable enhanced metric collection. The added cost of these additional custom metrics could be up to $67.20/month.`,
      default: 'no',
      allowedValues: ['yes', 'no'],
    });

    const enhancedMetricsEnabled = new cdk.CfnCondition(this, 'enhancedMetricsEnabled', {
      expression: Fn.conditionEquals(enableEnhancedCloudWatchMetrics.valueAsString, 'yes'),
    });

    /**
     * @description sendNotifications - send notifications and log messages from Orchestrator step function
     * @type {lambda.Function}
     */
    const sendNotifications = new lambda.Function(this, 'sendNotifications', {
      functionName: RESOURCE_NAME_PREFIX + '-ASR-sendNotifications',
      handler: 'send_notifications.lambda_handler',
      runtime: props.runtimePython,
      description: 'Sends notifications and log messages',
      code: lambda.Code.fromBucket(
        solutionsBucket,
        props.solutionTMN + '/' + props.solutionVersion + '/lambda/send_notifications.py.zip',
      ),
      environment: {
        log_level: 'info',
        AWS_PARTITION: this.partition,
        SOLUTION_ID: props.solutionId,
        SOLUTION_VERSION: props.solutionVersion,
        SOLUTION_TMN: props.solutionTMN,
        ENHANCED_METRICS: enableEnhancedCloudWatchMetrics.valueAsString,
      },
      memorySize: 256,
      timeout: cdk.Duration.seconds(600),
      role: notifyRole,
      tracing: Tracing.ACTIVE,
      layers: [asrLambdaLayer],
    });

    {
      const childToMod = sendNotifications.node.findChild('Resource') as lambda.CfnFunction;

      childToMod.cfnOptions.metadata = {
        cfn_nag: {
          rules_to_suppress: [
            {
              id: 'W58',
              reason: 'False positive. Access is provided via a policy',
            },
            {
              id: 'W89',
              reason: 'There is no need to run this lambda in a VPC',
            },
            {
              id: 'W92',
              reason: 'There is no need for Reserved Concurrency due to low request rate',
            },
          ],
        },
      };
    }

    //-------------------------------------------------------------------------
    // Custom Lambda Policy
    //
    const createCustomActionPolicy = new Policy(this, 'createCustomActionPolicy', {
      policyName: RESOURCE_NAME_PREFIX + '-ASR_Custom_Action',
      statements: [
        new PolicyStatement({
          actions: ['cloudwatch:PutMetricData'],
          resources: ['*'],
        }),
        new PolicyStatement({
          actions: ['logs:CreateLogStream', 'logs:PutLogEvents'],
          resources: [`arn:${this.partition}:logs:*:${this.account}:log-group:*:log-stream:*`],
        }),
        new PolicyStatement({
          actions: ['logs:CreateLogGroup'],
          resources: [`arn:${this.partition}:logs:*:${this.account}:log-group:*`],
        }),
        new PolicyStatement({
          actions: [
            'securityhub:CreateActionTarget',
            'securityhub:DescribeActionTargets',
            'securityhub:DeleteActionTarget',
          ],
          resources: ['*'],
        }),
        new PolicyStatement({
          actions: ['ssm:GetParameter', 'ssm:GetParameters', 'ssm:PutParameter'],
          resources: [`arn:${this.partition}:ssm:*:${this.account}:parameter/Solutions/SO0111/*`],
        }),
      ],
    });

    const createCAPolicyResource = createCustomActionPolicy.node.findChild('Resource') as CfnPolicy;

    createCAPolicyResource.cfnOptions.metadata = {
      cfn_nag: {
        rules_to_suppress: [
          {
            id: 'W12',
            reason: 'Resource * is required for CloudWatch Logs policies used on Lambda functions.',
          },
        ],
      },
    };

    //-------------------------------------------------------------------------
    // Custom Lambda Role
    //
    const createCustomActionRole = new Role(this, 'createCustomActionRole', {
      assumedBy: new ServicePrincipal('lambda.amazonaws.com'),
      description: 'Lambda role to allow creation of Security Hub Custom Actions',
    });

    createCustomActionRole.attachInlinePolicy(createCustomActionPolicy);

    const createCARoleResource = createCustomActionRole.node.findChild('Resource') as CfnRole;

    createCARoleResource.cfnOptions.metadata = {
      cfn_nag: {
        rules_to_suppress: [
          {
            id: 'W28',
            reason: 'Static names chosen intentionally to provide easy integration with playbook templates',
          },
        ],
      },
    };

    //-------------------------------------------------------------------------
    // Custom Lambda - Create Custom Action
    //
    const createCustomAction = new lambda.Function(this, 'CreateCustomAction', {
      functionName: RESOURCE_NAME_PREFIX + '-SHARR-CustomAction',
      handler: 'action_target_provider.lambda_handler',
      runtime: props.runtimePython,
      description: 'Custom resource to create or retrieve an action target in Security Hub',
      code: lambda.Code.fromBucket(
        solutionsBucket,
        props.solutionTMN + '/' + props.solutionVersion + '/lambda/action_target_provider.zip',
      ),
      environment: {
        log_level: 'info',
        AWS_PARTITION: this.partition,
        sendAnonymizedMetrics: mapping.findInMap('sendAnonymizedMetrics', 'data'),
        SOLUTION_ID: props.solutionId,
        SOLUTION_VERSION: props.solutionVersion,
      },
      memorySize: 256,
      timeout: cdk.Duration.seconds(600),
      role: createCustomActionRole,
      layers: [asrLambdaLayer],
    });

    const createCAFuncResource = createCustomAction.node.findChild('Resource') as lambda.CfnFunction;

    createCAFuncResource.cfnOptions.metadata = {
      cfn_nag: {
        rules_to_suppress: [
          {
            id: 'W58',
            reason: 'False positive. the lambda role allows write to CW Logs',
          },
          {
            id: 'W89',
            reason: 'There is no need to run this lambda in a VPC',
          },
          {
            id: 'W92',
            reason: 'There is no need for Reserved Concurrency due to low request rate',
          },
        ],
      },
    };

    //---------------------------------------------------------------------
    // Scheduling Queue for SQS Remediation Throttling
    //
    const deadLetterQueue = new sqs.Queue(this, 'deadLetterSchedulingQueue', {
      encryption: sqs.QueueEncryption.KMS,
      enforceSSL: true,
      encryptionMasterKey: kmsKey,
    });

    const deadLetterQueueDeclaration: sqs.DeadLetterQueue = {
      maxReceiveCount: 10,
      queue: deadLetterQueue,
    };

    const schedulingQueue = new sqs.Queue(this, 'SchedulingQueue', {
      encryption: sqs.QueueEncryption.KMS,
      enforceSSL: true,
      deadLetterQueue: deadLetterQueueDeclaration,
      encryptionMasterKey: kmsKey,
    });

    const eventSource = new lambdaEventSources.SqsEventSource(schedulingQueue, {
      batchSize: 1,
    });

    const orchestrator = new OrchestratorConstruct(this, 'orchestrator', {
      roleArn: orchestratorRole.roleArn,
      ssmDocStateLambda: checkSSMDocumentState.functionArn,
      ssmExecDocLambda: execAutomation.functionArn,
      ssmExecMonitorLambda: monitorSSMExecState.functionArn,
      notifyLambda: sendNotifications.functionArn,
      getApprovalRequirementLambda: getApprovalRequirement.functionArn,
      solutionId: RESOURCE_NAME_PREFIX,
      solutionName: props.solutionName,
      solutionVersion: props.solutionVersion,
      orchLogGroup: props.orchestratorLogGroup,
      kmsKeyParm: kmsKeyParm,
      sqsQueue: schedulingQueue,
    });

    const orchStateMachine = orchestrator.node.findChild('StateMachine') as StateMachine;
    const stateMachineConstruct = orchStateMachine.node.defaultChild as CfnStateMachine;
    const orchArnParm = orchestrator.node.findChild('SHARR_Orchestrator_Arn') as StringParameter;
    const orchestratorArn = orchArnParm.node.defaultChild as CfnParameter;

    // Role used by custom action EventBridge rules
    const customActionEventsRuleRole = new Role(this, 'EventsRuleRole', {
      assumedBy: new ServicePrincipal('events.amazonaws.com'),
    });

    //---------------------------------------------------------------------
    // OneTrigger - Remediate with ASR custom action
    //
    // Create an IAM role for Events to start the State Machine

    new OneTrigger(this, 'RemediateWithSharr', {
      targetArn: orchStateMachine.stateMachineArn,
      serviceToken: createCustomAction.functionArn,
      ruleId: 'Remediate Custom Action',
      ruleName: 'Remediate_with_ASR_CustomAction',
      eventsRole: customActionEventsRuleRole,
      customActionName: 'Remediate with ASR', // must be <= 20 chars in length
      customActionId: 'ASRRemediation', // must be <= 20 chars in length
      customActionDescription: 'Submit the finding to Automated Response and Remediation (ASR) for remediation.',
      prereq: [createCAFuncResource, createCAPolicyResource],
    });

    //---------------------------------------------------------------------
    // OneTrigger - Remediate & Generate Ticket custom action
    //
    new OneTrigger(this, 'RemediateAndTicket', {
      targetArn: orchStateMachine.stateMachineArn,
      serviceToken: createCustomAction.functionArn,
      condition: orchestrator.ticketingEnabled,
      ruleId: 'Ticketing Custom Action',
      description: 'Remediate with ASR and generate a ticket.',
      ruleName: 'ASR_Remediate_and_Ticket_CustomAction',
      eventsRole: customActionEventsRuleRole,
      customActionName: 'ASR:Remediate&Ticket', // must be <= 20 chars in length
      customActionId: 'ASRTicketing', // must be <= 20 chars in length
      customActionDescription:
        'Submit the finding to Automated Response and Remediation (ASR) for remediation and generate a ticket.',
      prereq: [createCAFuncResource, createCAPolicyResource],
    });

    //-------------------------------------------------------------------------
    // Loop through all of the Playbooks and create an option to load each
    //
    const securityStandardPlaybookNames: string[] = [];
    standardPlaybookProps.forEach((playbookProps) => {
      const playbook = new AdminPlaybook(this, {
        name: playbookProps.name,
        stackDependencies: [stateMachineConstruct, orchestratorArn],
        defaultState: playbookProps.defaultParameterValue,
        description: playbookProps.description,
        targetAccountIDs: accountTargetParam.targetAccountIDs,
        targetAccountIDsStrategy: accountTargetParam.targetAccountIDsStrategy,
      });
      securityStandardPlaybookNames.push(playbook.parameterName);
    });

    const scPlaybook = new AdminPlaybook(this, {
      name: scPlaybookProps.name,
      stackDependencies: [stateMachineConstruct, orchestratorArn],
      defaultState: scPlaybookProps.defaultParameterValue,
      description: scPlaybookProps.description,
      targetAccountIDs: accountTargetParam.targetAccountIDs,
      targetAccountIDsStrategy: accountTargetParam.targetAccountIDsStrategy,
    });

    //---------------------------------------------------------------------
    // Scheduling Table for SQS Remediation Throttling
    //
    const schedulingTable = new dynamodb.Table(this, 'SchedulingTable', {
      partitionKey: { name: 'AccountID-Region', type: dynamodb.AttributeType.STRING },
      encryption: dynamodb.TableEncryption.AWS_MANAGED,
      pointInTimeRecoverySpecification: {
        pointInTimeRecoveryEnabled: true,
      },
      timeToLiveAttribute: 'TTL',
      deletionProtection: true,
    });
    const readScaling = schedulingTable.autoScaleReadCapacity({ minCapacity: 1, maxCapacity: 10 });
    readScaling.scaleOnUtilization({
      targetUtilizationPercent: 70,
    });
    const writeScaling = schedulingTable.autoScaleWriteCapacity({ minCapacity: 1, maxCapacity: 10 });
    writeScaling.scaleOnUtilization({
      targetUtilizationPercent: 70,
    });

    addCfnGuardSuppression(schedulingTable, 'DYNAMODB_BILLING_MODE_RULE');
    addCfnGuardSuppression(schedulingTable, 'DYNAMODB_TABLE_ENCRYPTED_KMS');

    const schedulingLamdbdaPolicy = new Policy(this, 'SchedulingLambdaPolicy', {
      policyName: RESOURCE_NAME_PREFIX + '-ASR_Scheduling_Lambda',
      statements: [
        new PolicyStatement({
          actions: ['logs:CreateLogStream', 'logs:PutLogEvents'],
          resources: [`arn:${this.partition}:logs:*:${this.account}:log-group:*:log-stream:*`],
        }),
        new PolicyStatement({
          actions: ['logs:CreateLogGroup'],
          resources: [`arn:${this.partition}:logs:*:${this.account}:log-group:*`],
        }),
        new PolicyStatement({
          actions: ['ssm:GetParameter', 'ssm:PutParameter'],
          resources: [`arn:${this.partition}:ssm:${this.region}:${this.account}:parameter/Solutions/SO0111/*`],
        }),
        new PolicyStatement({
          actions: ['cloudwatch:PutMetricData'],
          resources: ['*'],
        }),
      ],
    });

    const schedulingLambdaRole = new Role(this, 'SchedulingLambdaRole', {
      assumedBy: new ServicePrincipal('lambda.amazonaws.com'),
      description: 'Lambda role to schedule remediations that are sent to SQS through the orchestrator',
    });

    schedulingLambdaRole.attachInlinePolicy(schedulingLamdbdaPolicy);
    /**
     * @description schedulingLambdaTrigger - Lambda trigger for SQS Queue
     * @type {lambda.Function}
     */
    const schedulingLambdaTrigger = new lambda.Function(this, 'schedulingLambdaTrigger', {
      functionName: RESOURCE_NAME_PREFIX + '-ASR-schedulingLambdaTrigger',
      handler: 'schedule_remediation.lambda_handler',
      runtime: props.runtimePython,
      description: 'SO0111 ASR function that schedules remediations in member accounts',
      code: lambda.Code.fromBucket(
        solutionsBucket,
        props.solutionTMN + '/' + props.solutionVersion + '/lambda/schedule_remediation.py.zip',
      ),
      environment: {
        SchedulingTableName: schedulingTable.tableName,
        RemediationWaitTime: '3',
      },
      memorySize: 128,
      timeout: cdk.Duration.seconds(10),
      role: schedulingLambdaRole,
      reservedConcurrentExecutions: 1,
      tracing: Tracing.ACTIVE,
      layers: [asrLambdaLayer],
    });
    orchStateMachine.grantTaskResponse(schedulingLambdaTrigger);
    schedulingTable.grantReadWriteData(schedulingLambdaTrigger);

    addCfnGuardSuppression(schedulingLambdaTrigger, 'LAMBDA_INSIDE_VPC');

    schedulingLambdaTrigger.addEventSource(eventSource);

    new ActionLog(this, 'ActionLog', {
      logGroupName: props.cloudTrailLogGroupName,
    });

    const cloudWatchMetrics = new CloudWatchMetrics(this, {
      solutionId: props.solutionId,
      schedulingQueueName: schedulingQueue.queueName,
      orchStateMachineArn: orchStateMachine.stateMachineArn,
      kmsKey: kmsKey,
      actionLogLogGroupName: props.cloudTrailLogGroupName,
      enhancedMetricsEnabled: enhancedMetricsEnabled,
    });

    new MetricResources(this, 'MetricResources', {
      solutionTMN: props.solutionTMN,
      solutionVersion: props.solutionVersion,
      solutionId: props.solutionId,
      runtimePython: props.runtimePython,
      solutionsBucket: solutionsBucket,
      lambdaLayer: asrLambdaLayer,
    });

    const sortedPlaybookNames = [...securityStandardPlaybookNames].sort();

    stack.templateOptions.metadata = {
      'AWS::CloudFormation::Interface': {
        ParameterGroups: [
          {
            Label: { default: 'Consolidated Control Findings Playbook' },
            Parameters: [scPlaybook.parameterName],
          },
          {
            Label: { default: 'Security Standard Playbooks' },
            Parameters: sortedPlaybookNames,
          },
          {
            Label: { default: 'Orchestrator Configuration' },
            Parameters: ['ReuseOrchestratorLogGroup'],
          },
          {
            Label: { default: 'CloudWatch Metrics' },
            Parameters: [...cloudWatchMetrics.getStandardParameterIds()],
          },
          {
            Label: { default: '(Optional) Enhanced CloudWatch Metrics' },
            Parameters: [enableEnhancedCloudWatchMetrics.logicalId, ...cloudWatchMetrics.getEnhancedParameterIds()],
          },
          {
            Label: { default: '(Optional) Ticketing Service Integration' },
            Parameters: [orchestrator.ticketGenFunctionNameParamId],
          },
          {
            Label: { default: '(Optional) Target accounts' },
            Parameters: [
              accountTargetParam.targetAccountIDs.logicalId,
              accountTargetParam.targetAccountIDsStrategy.logicalId,
            ],
          },
        ],
        ParameterLabels: {
          SecurityStandardPlaybooks: {
            default:
              'For more details see: https://docs.aws.amazon.com/solutions/latest/automated-security-response-on-aws/enable-fully-automated-remediations.html',
          },
        },
      },
    };

    new CfnOutput(this, 'Generated Ticketing Lambda function ARN', {
      description:
        'The Lambda ARN constructed from the Ticket Generator Function Name you have provided as input to the stack. ' +
        'This ARN is used by the solution to plug your ticketing function into the Orchestrator step function. ' +
        'This field will be empty if you did not provide a ticketing Lambda Function name.',
      value: orchestrator.ticketGenFunctionARN,
    });
  }

  getPrimarySolutionSNSTopicARN(): string {
    return this.primarySolutionSNSTopicARN;
  }
}
