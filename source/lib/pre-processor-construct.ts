// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import * as cdk from 'aws-cdk-lib';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as sqs from 'aws-cdk-lib/aws-sqs';
import { QueueEncryption } from 'aws-cdk-lib/aws-sqs';
import { SqsEventSource } from 'aws-cdk-lib/aws-lambda-event-sources';
import { Construct } from 'constructs';
import { IBucket } from 'aws-cdk-lib/aws-s3';
import { Key } from 'aws-cdk-lib/aws-kms';
import { addCfnGuardSuppression } from './cdk-helper/add-cfn-guard-suppression';
import { Effect, PolicyStatement, ServicePrincipal } from 'aws-cdk-lib/aws-iam';
import { Table } from 'aws-cdk-lib/aws-dynamodb';
import { getLambdaCode } from './cdk-helper/lambda-code-manifest';

export interface PreProcessorStackProps {
  readonly solutionId: string;
  readonly solutionVersion: string;
  readonly resourceNamePrefix: string;
  readonly solutionsBucket: IBucket;
  readonly solutionTMN: string;
  readonly findingsTable: string;
  readonly remediationHistoryTable: string;
  readonly functionName: string;
  readonly remediationConfigTable: string;
  readonly orchestratorArn: string;
  readonly findingsTTL: string;
  readonly historyTTL: string;
  readonly kmsKey: Key;
}

export class PreProcessorConstruct extends Construct {
  readonly preProcessorFunction: lambda.Function;
  readonly queue: sqs.Queue;
  readonly deadLetterQueue: sqs.Queue;

  constructor(scope: Construct, id: string, props: PreProcessorStackProps) {
    super(scope, id);
    const stack = cdk.Stack.of(this);

    this.deadLetterQueue = new sqs.Queue(this, 'PreProcessorDLQ', {
      retentionPeriod: cdk.Duration.days(14),
      encryption: QueueEncryption.KMS,
      encryptionMasterKey: props.kmsKey,
      enforceSSL: true,
    });

    this.queue = new sqs.Queue(this, 'PreProcessorQueue', {
      visibilityTimeout: cdk.Duration.minutes(15),
      enforceSSL: true,
      encryption: QueueEncryption.KMS,
      encryptionMasterKey: props.kmsKey,
      deadLetterQueue: {
        queue: this.deadLetterQueue,
        maxReceiveCount: 10, // Messages can be retried 10 times before being sent to DLQ
      },
    });

    this.queue.addToResourcePolicy(
      new PolicyStatement({
        effect: Effect.ALLOW,
        principals: [new ServicePrincipal('events.amazonaws.com')],
        actions: ['sqs:SendMessage'],
        resources: ['*'],
      }),
    );

    this.preProcessorFunction = new lambda.Function(this, 'PreProcessorFunction', {
      functionName: props.functionName,
      runtime: lambda.Runtime.NODEJS_22_X,
      handler: 'pre-processor/preProcessor.handler',
      code: getLambdaCode(props.solutionsBucket, props.solutionTMN, props.solutionVersion, 'asr_lambdas.zip'),
      timeout: cdk.Duration.minutes(15),
      memorySize: 512,
      environment: {
        SOLUTION_TRADEMARKEDNAME: props.solutionTMN,
        POWERTOOLS_LOG_LEVEL: 'INFO',
        FINDINGS_TABLE_ARN: props.findingsTable,
        REMEDIATION_HISTORY_TABLE_ARN: props.remediationHistoryTable,
        REMEDIATION_CONFIG_TABLE_ARN: props.remediationConfigTable,
        ORCHESTRATOR_ARN: props.orchestratorArn,
        FINDINGS_TTL_DAYS: props.findingsTTL,
        HISTORY_TTL_DAYS: props.historyTTL,
        AWS_ACCOUNT_ID: stack.account,
        STACK_ID: stack.stackId,
      },
      tracing: lambda.Tracing.ACTIVE,
      reservedConcurrentExecutions: 5,
    });

    addCfnGuardSuppression(this.preProcessorFunction, 'LAMBDA_INSIDE_VPC');
    addCfnGuardSuppression(this.preProcessorFunction, 'CFN_NO_EXPLICIT_RESOURCE_NAMES');

    // Grant DynamoDB table read/write permissions to PreProcessor Lambda
    const findingsTable = Table.fromTableArn(this, 'FindingsTable', props.findingsTable);
    findingsTable.grantReadWriteData(this.preProcessorFunction);

    const remediationConfigTable = Table.fromTableArn(this, 'RemediationConfigTable', props.remediationConfigTable);
    remediationConfigTable.grantReadWriteData(this.preProcessorFunction);

    const remediationHistoryTable = Table.fromTableArn(this, 'RemediationHistoryTable', props.remediationHistoryTable);
    remediationHistoryTable.grantReadWriteData(this.preProcessorFunction);

    // Grant SSM parameter access for metrics and filter configuration
    this.preProcessorFunction.addToRolePolicy(
      new PolicyStatement({
        actions: [
          'ssm:GetParameters',
          'ssm:GetParameter',
          'ssm:GetParametersByPath',
          'ssm:PutParameter',
          'ssm:PutParameters',
          'ssm:DeleteParameter',
        ],
        resources: [
          `arn:${cdk.Stack.of(this).partition}:ssm:*:*:parameter/Solutions/SO0111/*`,
          `arn:${cdk.Stack.of(this).partition}:ssm:*:*:parameter/ASR/Filters`,
          `arn:${cdk.Stack.of(this).partition}:ssm:*:*:parameter/ASR/Filters/*`,
        ],
        effect: Effect.ALLOW,
      }),
    );

    // Grant Step Functions execution permission for orchestrator
    this.preProcessorFunction.addToRolePolicy(
      new PolicyStatement({
        actions: ['states:StartExecution'],
        resources: [props.orchestratorArn],
        effect: Effect.ALLOW,
      }),
    );

    this.preProcessorFunction.addToRolePolicy(
      new PolicyStatement({
        actions: ['organizations:ListParents', 'organizations:DescribeAccount'],
        resources: ['*'],
        effect: Effect.ALLOW,
      }),
    );

    const eventSource = new SqsEventSource(this.queue, {
      batchSize: 10, // Reduced from 50 to prevent connection exhaustion
      maxBatchingWindow: cdk.Duration.seconds(5), // Reduced batching window for faster processing
      reportBatchItemFailures: true,
    });

    this.preProcessorFunction.addEventSource(eventSource);
  }
}
