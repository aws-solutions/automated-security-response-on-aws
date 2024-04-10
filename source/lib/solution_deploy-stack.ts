// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import * as cdk_nag from 'cdk-nag';
import * as cdk from 'aws-cdk-lib';
import * as s3 from 'aws-cdk-lib/aws-s3';
import * as sns from 'aws-cdk-lib/aws-sns';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as dynamodb from 'aws-cdk-lib/aws-dynamodb';
import * as sqs from 'aws-cdk-lib/aws-sqs';
import { StringParameter, CfnParameter } from 'aws-cdk-lib/aws-ssm';
import * as kms from 'aws-cdk-lib/aws-kms';
import * as lambdaEventSources from 'aws-cdk-lib/aws-lambda-event-sources';
import * as fs from 'fs';
import {
  Role,
  CfnRole,
  Policy,
  CfnPolicy,
  PolicyStatement,
  PolicyDocument,
  ServicePrincipal,
  AccountRootPrincipal,
} from 'aws-cdk-lib/aws-iam';
import { OrchestratorConstruct } from './common-orchestrator-construct';
import { CfnStateMachine, StateMachine } from 'aws-cdk-lib/aws-stepfunctions';
import { OneTrigger } from './ssmplaybook';
import { CloudWatchMetrics } from './cloudwatch_metrics';
import { AdminPlaybook } from './admin-playbook';

export interface SHARRStackProps extends cdk.StackProps {
  solutionId: string;
  solutionVersion: string;
  solutionDistBucket: string;
  solutionTMN: string;
  solutionName: string;
  runtimePython: lambda.Runtime;
  orchLogGroup: string;
}

export class SolutionDeployStack extends cdk.Stack {
  SEND_ANONYMIZED_DATA = 'Yes';
  nestedStacks: cdk.Stack[];

  constructor(scope: cdk.App, id: string, props: SHARRStackProps) {
    super(scope, id, props);
    this.nestedStacks = [];
    const stack = cdk.Stack.of(this);
    const RESOURCE_PREFIX = props.solutionId.replace(/^DEV-/, ''); // prefix on every resource name

    //-------------------------------------------------------------------------
    // Solutions Bucket - Source Code
    //
    const SolutionsBucket = s3.Bucket.fromBucketAttributes(this, 'SolutionsBucket', {
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
            resource: 'log-group:SO0111-SHARR-*',
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
      alias: `${RESOURCE_PREFIX}-SHARR-Key`,
      policy: kmsKeyPolicy,
    });

    const kmsKeyParm = new StringParameter(this, 'SHARR_Key', {
      description: 'KMS Customer Managed Key that SHARR will use to encrypt data',
      parameterName: `/Solutions/${RESOURCE_PREFIX}/CMK_ARN`,
      stringValue: kmsKey.keyArn,
    });

    //-------------------------------------------------------------------------
    // SNS Topic for notification fanout on Playbook completion
    //
    const snsTopic = new sns.Topic(this, 'SHARR-Topic', {
      displayName: 'SHARR Playbook Topic (' + RESOURCE_PREFIX + ')',
      topicName: RESOURCE_PREFIX + '-SHARR_Topic',
      masterKey: kmsKey,
    });

    new StringParameter(this, 'SHARR_SNS_Topic', {
      description:
        'SNS Topic ARN where SHARR will send status messages. This topic can be useful for driving additional actions, such as email notifications, trouble ticket updates.',
      parameterName: '/Solutions/' + RESOURCE_PREFIX + '/SNS_Topic_ARN',
      stringValue: snsTopic.topicArn,
    });

    const mapping = new cdk.CfnMapping(this, 'mappings');
    mapping.setValue('sendAnonymizedMetrics', 'data', this.SEND_ANONYMIZED_DATA);

    new StringParameter(this, 'SHARR_SendAnonymousMetrics', {
      description: 'Flag to enable or disable sending anonymous metrics.',
      parameterName: '/Solutions/' + RESOURCE_PREFIX + '/sendAnonymizedMetrics',
      stringValue: mapping.findInMap('sendAnonymizedMetrics', 'data'),
    });

    new StringParameter(this, 'SHARR_version', {
      description: 'Solution version for metrics.',
      parameterName: '/Solutions/' + RESOURCE_PREFIX + '/version',
      stringValue: props.solutionVersion,
    });

    /**
     * @description Lambda Layer for common solution functions
     * @type {lambda.LayerVersion}
     */
    const sharrLambdaLayer = new lambda.LayerVersion(this, 'SharrLambdaLayer', {
      compatibleRuntimes: [props.runtimePython],
      description: 'SO0111 SHARR Common functions used by the solution',
      license: 'https://www.apache.org/licenses/LICENSE-2.0',
      code: lambda.Code.fromBucket(
        SolutionsBucket,
        props.solutionTMN + '/' + props.solutionVersion + '/lambda/layer.zip',
      ),
    });

    /**
     * @description Policy for role used by common Orchestrator Lambdas
     * @type {Policy}
     */
    const orchestratorPolicy = new Policy(this, 'orchestratorPolicy', {
      policyName: RESOURCE_PREFIX + '-SHARR_Orchestrator',
      statements: [
        new PolicyStatement({
          actions: ['logs:CreateLogGroup', 'logs:CreateLogStream', 'logs:PutLogEvents'],
          resources: ['*'],
        }),
        new PolicyStatement({
          actions: ['ssm:GetParameter', 'ssm:GetParameters', 'ssm:PutParameter'],
          resources: [`arn:${this.partition}:ssm:*:${this.account}:parameter/Solutions/SO0111/*`],
        }),
        new PolicyStatement({
          actions: ['sts:AssumeRole'],
          resources: [
            `arn:${this.partition}:iam::*:role/${RESOURCE_PREFIX}-SHARR-Orchestrator-Member`,
            //'arn:' + this.partition + ':iam::*:role/' + RESOURCE_PREFIX +
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

    cdk_nag.NagSuppressions.addResourceSuppressions(orchestratorPolicy, [
      {
        id: 'AwsSolutions-IAM5',
        reason: 'Resource * is required for read-only policies used by orchestrator Lambda functions.',
      },
    ]);

    /**
     * @description Role used by common Orchestrator Lambdas
     * @type {Role}
     */

    const orchestratorRole = new Role(this, 'orchestratorRole', {
      assumedBy: new ServicePrincipal('lambda.amazonaws.com'),
      description: 'Lambda role to allow cross account read-only SHARR orchestrator functions',
      roleName: `${RESOURCE_PREFIX}-SHARR-Orchestrator-Admin`,
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

    /**
     * @description checkSSMDocState - get the status of an ssm document
     * @type {lambda.Function}
     */
    const checkSSMDocState = new lambda.Function(this, 'checkSSMDocState', {
      functionName: RESOURCE_PREFIX + '-SHARR-checkSSMDocState',
      handler: 'check_ssm_doc_state.lambda_handler',
      runtime: props.runtimePython,
      description: 'Checks the status of an SSM Automation Document in the target account',
      code: lambda.Code.fromBucket(
        SolutionsBucket,
        props.solutionTMN + '/' + props.solutionVersion + '/lambda/check_ssm_doc_state.py.zip',
      ),
      environment: {
        log_level: 'info',
        AWS_PARTITION: this.partition,
        SOLUTION_ID: props.solutionId,
        SOLUTION_VERSION: props.solutionVersion,
      },
      memorySize: 256,
      timeout: cdk.Duration.seconds(600),
      role: orchestratorRole,
      layers: [sharrLambdaLayer],
    });

    {
      const childToMod = checkSSMDocState.node.findChild('Resource') as lambda.CfnFunction;

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
      functionName: RESOURCE_PREFIX + '-SHARR-getApprovalRequirement',
      handler: 'get_approval_requirement.lambda_handler',
      runtime: props.runtimePython,
      description: 'Determines if a manual approval is required for remediation',
      code: lambda.Code.fromBucket(
        SolutionsBucket,
        props.solutionTMN + '/' + props.solutionVersion + '/lambda/get_approval_requirement.py.zip',
      ),
      environment: {
        log_level: 'info',
        AWS_PARTITION: this.partition,
        SOLUTION_ID: props.solutionId,
        SOLUTION_VERSION: props.solutionVersion,
        WORKFLOW_RUNBOOK: '',
      },
      memorySize: 256,
      timeout: cdk.Duration.seconds(600),
      role: orchestratorRole,
      layers: [sharrLambdaLayer],
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
      functionName: RESOURCE_PREFIX + '-SHARR-execAutomation',
      handler: 'exec_ssm_doc.lambda_handler',
      runtime: props.runtimePython,
      description: 'Executes an SSM Automation Document in a target account',
      code: lambda.Code.fromBucket(
        SolutionsBucket,
        props.solutionTMN + '/' + props.solutionVersion + '/lambda/exec_ssm_doc.py.zip',
      ),
      environment: {
        log_level: 'info',
        AWS_PARTITION: this.partition,
        SOLUTION_ID: props.solutionId,
        SOLUTION_VERSION: props.solutionVersion,
      },
      memorySize: 256,
      timeout: cdk.Duration.seconds(600),
      role: orchestratorRole,
      layers: [sharrLambdaLayer],
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
      functionName: RESOURCE_PREFIX + '-SHARR-monitorSSMExecState',
      handler: 'check_ssm_execution.lambda_handler',
      runtime: props.runtimePython,
      description: 'Checks the status of an SSM automation document execution',
      code: lambda.Code.fromBucket(
        SolutionsBucket,
        props.solutionTMN + '/' + props.solutionVersion + '/lambda/check_ssm_execution.py.zip',
      ),
      environment: {
        log_level: 'info',
        AWS_PARTITION: this.partition,
        SOLUTION_ID: props.solutionId,
        SOLUTION_VERSION: props.solutionVersion,
      },
      memorySize: 256,
      timeout: cdk.Duration.seconds(600),
      role: orchestratorRole,
      layers: [sharrLambdaLayer],
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
      policyName: RESOURCE_PREFIX + '-SHARR_Orchestrator_Notifier',
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
          resources: [`arn:${this.partition}:sns:${this.region}:${this.account}:${RESOURCE_PREFIX}-SHARR_Topic`],
        }),
        new PolicyStatement({
          actions: ['cloudwatch:PutMetricData'],
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

    cdk_nag.NagSuppressions.addResourceSuppressions(notifyPolicy, [
      {
        id: 'AwsSolutions-IAM5',
        reason:
          'Resource * is required for CloudWatch Logs and Security Hub policies used by core solution Lambda function for notifications.',
      },
    ]);

    notifyPolicy.attachToRole(orchestratorRole); // Any Orchestrator Lambda can send to sns

    /**
     * @description Role used by common Orchestrator Lambdas
     * @type {Role}
     */

    const notifyRole = new Role(this, 'notifyRole', {
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

    /**
     * @description sendNotifications - send notifications and log messages from Orchestrator step function
     * @type {lambda.Function}
     */
    const sendNotifications = new lambda.Function(this, 'sendNotifications', {
      functionName: RESOURCE_PREFIX + '-SHARR-sendNotifications',
      handler: 'send_notifications.lambda_handler',
      runtime: props.runtimePython,
      description: 'Sends notifications and log messages',
      code: lambda.Code.fromBucket(
        SolutionsBucket,
        props.solutionTMN + '/' + props.solutionVersion + '/lambda/send_notifications.py.zip',
      ),
      environment: {
        log_level: 'info',
        AWS_PARTITION: this.partition,
        SOLUTION_ID: props.solutionId,
        SOLUTION_VERSION: props.solutionVersion,
      },
      memorySize: 256,
      timeout: cdk.Duration.seconds(600),
      role: notifyRole,
      layers: [sharrLambdaLayer],
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
      policyName: RESOURCE_PREFIX + '-SHARR_Custom_Action',
      statements: [
        new PolicyStatement({
          actions: ['cloudwatch:PutMetricData'],
          resources: ['*'],
        }),
        new PolicyStatement({
          actions: ['logs:CreateLogGroup', 'logs:CreateLogStream', 'logs:PutLogEvents'],
          resources: ['*'],
        }),
        new PolicyStatement({
          actions: ['securityhub:CreateActionTarget', 'securityhub:DeleteActionTarget'],
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

    cdk_nag.NagSuppressions.addResourceSuppressions(createCustomActionPolicy, [
      {
        id: 'AwsSolutions-IAM5',
        reason: 'Resource * is required for CloudWatch Logs policies used on Lambda functions.',
      },
    ]);

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
      functionName: RESOURCE_PREFIX + '-SHARR-CustomAction',
      handler: 'action_target_provider.lambda_handler',
      runtime: props.runtimePython,
      description: 'Custom resource to create an action target in Security Hub',
      code: lambda.Code.fromBucket(
        SolutionsBucket,
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
      layers: [sharrLambdaLayer],
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
      ssmDocStateLambda: checkSSMDocState.functionArn,
      ssmExecDocLambda: execAutomation.functionArn,
      ssmExecMonitorLambda: monitorSSMExecState.functionArn,
      notifyLambda: sendNotifications.functionArn,
      getApprovalRequirementLambda: getApprovalRequirement.functionArn,
      solutionId: RESOURCE_PREFIX,
      solutionName: props.solutionName,
      solutionVersion: props.solutionVersion,
      orchLogGroup: props.orchLogGroup,
      kmsKeyParm: kmsKeyParm,
      sqsQueue: schedulingQueue,
    });

    this.nestedStacks.push(orchestrator.nestedStack as cdk.Stack);

    const orchStateMachine = orchestrator.node.findChild('StateMachine') as StateMachine;
    const stateMachineConstruct = orchStateMachine.node.defaultChild as CfnStateMachine;
    const orchArnParm = orchestrator.node.findChild('SHARR_Orchestrator_Arn') as StringParameter;
    const orchestratorArn = orchArnParm.node.defaultChild as CfnParameter;

    //---------------------------------------------------------------------
    // OneTrigger - Remediate with ASR custom action
    //
    new OneTrigger(this, 'RemediateWithSharr', {
      targetArn: orchStateMachine.stateMachineArn,
      serviceToken: createCustomAction.functionArn,
      prereq: [createCAFuncResource, createCAPolicyResource],
    });

    //-------------------------------------------------------------------------
    // Loop through all of the Playbooks and create an option to load each
    //
    const PB_DIR = `${__dirname}/../playbooks`;
    const ignore = [
      '.DS_Store',
      'common',
      'python_lib',
      'python_tests',
      '.pytest_cache',
      'NEWPLAYBOOK',
      '.coverage',
      'SC',
    ];

    const standardLogicalNames: string[] = [];
    const items = fs.readdirSync(PB_DIR);
    items.forEach((file) => {
      if (!ignore.includes(file)) {
        const playbook = new AdminPlaybook(this, {
          name: file,
          stackDependencies: [stateMachineConstruct, orchestratorArn],
          defaultState: 'no',
        });
        standardLogicalNames.push(playbook.parameterName);
        this.nestedStacks.push(playbook.playbookStack);
      }
    });

    const scPlaybook = new AdminPlaybook(this, {
      name: 'SC',
      stackDependencies: [stateMachineConstruct, orchestratorArn],
      defaultState: 'yes',
      description:
        'If the consolidated control findings feature is turned on in Security Hub, only enable the Security Control (SC) playbook. If the feature is not turned on, enable the playbooks for the security standards that are enabled in Security Hub. Enabling additional playbooks can result in reaching the quota for EventBridge Rules.',
    });
    this.nestedStacks.push(scPlaybook.playbookStack);

    //---------------------------------------------------------------------
    // Scheduling Table for SQS Remediation Throttling
    //
    const schedulingTable = new dynamodb.Table(this, 'SchedulingTable', {
      partitionKey: { name: 'AccountID-Region', type: dynamodb.AttributeType.STRING },
      encryption: dynamodb.TableEncryption.AWS_MANAGED,
      pointInTimeRecovery: true,
      timeToLiveAttribute: 'TTL',
    });

    const schedulingLamdbdaPolicy = new Policy(this, 'SchedulingLambdaPolicy', {
      policyName: RESOURCE_PREFIX + '-SHARR_Scheduling_Lambda',
      statements: [
        new PolicyStatement({
          actions: ['logs:CreateLogGroup', 'logs:CreateLogStream', 'logs:PutLogEvents'],
          resources: ['*'],
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

    cdk_nag.NagSuppressions.addResourceSuppressions(schedulingLamdbdaPolicy, [
      {
        id: 'AwsSolutions-IAM5',
        reason: 'Resource * is required for CloudWatch Logs used by the Scheduling Lambda function.',
      },
    ]);

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
      functionName: RESOURCE_PREFIX + '-SHARR-schedulingLambdaTrigger',
      handler: 'schedule_remediation.lambda_handler',
      runtime: props.runtimePython,
      description: 'SO0111 ASR function that schedules remediations in member accounts',
      code: lambda.Code.fromBucket(
        SolutionsBucket,
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
      layers: [sharrLambdaLayer],
    });
    orchStateMachine.grantTaskResponse(schedulingLambdaTrigger);
    schedulingTable.grantReadWriteData(schedulingLambdaTrigger);

    schedulingLambdaTrigger.addEventSource(eventSource);

    const cloudWatchMetrics = new CloudWatchMetrics(this, {
      solutionId: props.solutionId,
      schedulingQueueName: schedulingQueue.queueName,
      orchStateMachineArn: orchStateMachine.stateMachineArn,
      kmsKey: kmsKey,
    });

    const customResourceLambdaPolicyDocument = new PolicyDocument({
      statements: [
        new PolicyStatement({ actions: ['cloudwatch:PutMetricData'], resources: ['*'] }),
        new PolicyStatement({
          actions: ['logs:CreateLogGroup', 'logs:CreateLogStream', 'logs:PutLogEvents'],
          resources: ['*'],
        }),
        new PolicyStatement({
          actions: ['ssm:GetParameter', 'ssm:GetParameters', 'ssm:PutParameter'],
          resources: [`arn:${this.partition}:ssm:*:${this.account}:parameter/Solutions/SO0111/*`],
        }),
      ],
    });

    const customResourceLambdaRole = new Role(this, `${id}Role`, {
      assumedBy: new ServicePrincipal('lambda.amazonaws.com'),
      inlinePolicies: { LambdaPolicy: customResourceLambdaPolicyDocument },
    });

    const customResourceFunction = new lambda.Function(this, 'ASR-DeploymentCustomResource-Lambda', {
      code: lambda.Code.fromBucket(
        SolutionsBucket,
        props.solutionTMN + '/' + props.solutionVersion + '/lambda/deployment_metrics_custom_resource.zip',
      ),
      handler: 'deployment_metrics_custom_resource.lambda_handler',
      runtime: props.runtimePython,
      description: 'ASR - Handles deployment related custom actions',
      environment: {
        LOG_LEVEL: 'INFO',
        AWS_PARTITION: this.partition,
        SOLUTION_ID: props.solutionId,
        SOLUTION_VERSION: props.solutionVersion,
      },
      memorySize: 256,
      timeout: cdk.Duration.seconds(5),
      role: customResourceLambdaRole,
      layers: [sharrLambdaLayer],
    });

    new cdk.CustomResource(this, `ASR-DeploymentMetricsCustomResource`, {
      resourceType: 'Custom::DeploymentMetrics',
      serviceToken: customResourceFunction.functionArn,
      properties: {
        CloudWatchMetricsDashboardEnabled: cloudWatchMetrics.getCloudWatchMetricsParameterValue(),
      },
    });

    cdk_nag.NagSuppressions.addResourceSuppressions(
      customResourceLambdaRole,
      [
        {
          id: 'AwsSolutions-IAM5',
          reason: 'Resource * is needed for CloudWatch Logs policies used on Lambda functions.',
        },
      ],
      true,
    );

    stack.templateOptions.metadata = {
      'AWS::CloudFormation::Interface': {
        ParameterGroups: [
          {
            Label: { default: 'Consolidated Control Findings Playbook' },
            Parameters: [scPlaybook.parameterName],
          },
          {
            Label: { default: 'Security Standard Playbooks' },
            Parameters: standardLogicalNames,
          },
          {
            Label: { default: 'Orchestrator Configuration' },
            Parameters: ['ReuseOrchestratorLogGroup'],
          },
          {
            Label: { default: 'CloudWatch Metrics' },
            Parameters: cloudWatchMetrics.getParameterIds(),
          },
        ],
        ParameterLabels: {
          ...cloudWatchMetrics.getParameterIdsAndLabels(),
        },
      },
    };
  }
}
