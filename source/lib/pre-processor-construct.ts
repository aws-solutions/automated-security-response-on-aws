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
import { createLogGroup } from './cdk-helper/log-group';
import { Effect, PolicyStatement, ServicePrincipal } from 'aws-cdk-lib/aws-iam';
import { ITable } from 'aws-cdk-lib/aws-dynamodb';
import { getLambdaCode } from './cdk-helper/lambda-code-manifest';
import { getConfig } from './config/cdk-config';
import { PreProcessorEnvironmentConfig } from '@asr/data-models';

export interface PreProcessorStackProps {
  readonly solutionId: string;
  readonly solutionVersion: string;
  readonly resourceNamePrefix: string;
  readonly solutionsBucket: IBucket;
  readonly solutionTMN: string;
  readonly findingsTable: ITable;
  readonly remediationHistoryTable: ITable;
  readonly functionName: string;
  readonly remediationConfigTable: ITable;
  readonly resourceFiltersTable: ITable;
  readonly notificationConfigTable: ITable;
  readonly orchestratorArn: string;
  readonly findingsTTL: string;
  readonly historyTTL: string;
  readonly kmsKey: Key;
  readonly notificationQueueUrl: string;
}

export class PreProcessorConstruct extends Construct {
  readonly preProcessorFunction: lambda.Function;
  readonly queue: sqs.Queue;
  readonly deadLetterQueue: sqs.Queue;

  constructor(scope: Construct, id: string, props: PreProcessorStackProps) {
    super(scope, id);
    const stack = cdk.Stack.of(this);
    const config = getConfig();

    const processingTimeout = cdk.Duration.minutes(15);
    const sqsBatchSize = 10;
    const sqsBatchingWindow = cdk.Duration.seconds(5);
    const lambdaConcurrency = 5;
    const sqsRetentionPeriod = cdk.Duration.days(config.sqs.retentionPeriodDays);
    const sqsDataKeyReuse = cdk.Duration.minutes(config.sqs.dataKeyReuseMinutes);

    this.deadLetterQueue = new sqs.Queue(this, 'PreProcessorDLQ', {
      retentionPeriod: sqsRetentionPeriod,
      encryption: QueueEncryption.KMS,
      encryptionMasterKey: props.kmsKey,
      enforceSSL: true,
      dataKeyReuse: sqsDataKeyReuse,
    });

    this.queue = new sqs.Queue(this, 'PreProcessorQueue', {
      visibilityTimeout: processingTimeout,
      enforceSSL: true,
      encryption: QueueEncryption.KMS,
      encryptionMasterKey: props.kmsKey,
      deadLetterQueue: {
        queue: this.deadLetterQueue,
        maxReceiveCount: 10, // Messages can be retried 10 times before being sent to DLQ
      },
      dataKeyReuse: sqsDataKeyReuse,
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
      logGroup: createLogGroup(this, 'PreProcessorFunctionLogGroup'),
      runtime: lambda.Runtime.NODEJS_24_X,
      handler: 'pre-processor/preProcessor.handler',
      code: getLambdaCode(props.solutionsBucket, props.solutionTMN, props.solutionVersion, 'asr_lambdas.zip'),
      timeout: processingTimeout,
      memorySize: 512,
      environment: {
        SOLUTION_TRADEMARKEDNAME: props.solutionTMN,
        POWERTOOLS_LOG_LEVEL: 'INFO',
        FINDINGS_TABLE_NAME: props.findingsTable.tableName,
        REMEDIATION_HISTORY_TABLE_NAME: props.remediationHistoryTable.tableName,
        REMEDIATION_CONFIG_TABLE_NAME: props.remediationConfigTable.tableName,
        RESOURCE_FILTERS_TABLE_NAME: props.resourceFiltersTable.tableName,
        NOTIFICATION_CONFIG_TABLE_NAME: props.notificationConfigTable.tableName,
        ORCHESTRATOR_ARN: props.orchestratorArn,
        FINDINGS_TTL_DAYS: props.findingsTTL,
        HISTORY_TTL_DAYS: props.historyTTL,
        AWS_ACCOUNT_ID: stack.account,
        STACK_ID: stack.stackId,
        NOTIFICATION_QUEUE_URL: props.notificationQueueUrl,
      } satisfies PreProcessorEnvironmentConfig,
      tracing: lambda.Tracing.ACTIVE,
      reservedConcurrentExecutions: lambdaConcurrency,
    });

    addCfnGuardSuppression(this.preProcessorFunction, 'LAMBDA_INSIDE_VPC');
    addCfnGuardSuppression(this.preProcessorFunction, 'CFN_NO_EXPLICIT_RESOURCE_NAMES');

    // Grant DynamoDB table read/write permissions to PreProcessor Lambda
    props.findingsTable.grantReadWriteData(this.preProcessorFunction);
    props.remediationConfigTable.grantReadWriteData(this.preProcessorFunction);
    props.remediationHistoryTable.grantReadWriteData(this.preProcessorFunction);
    props.resourceFiltersTable.grantReadData(this.preProcessorFunction);
    props.notificationConfigTable.grantReadData(this.preProcessorFunction);

    // Grant SSM parameter access for metrics
    this.preProcessorFunction.addToRolePolicy(
      new PolicyStatement({
        actions: [
          'ssm:GetParameters',
          'ssm:GetParameter',
          'ssm:GetParametersByPath',
          'ssm:PutParameter',
          'ssm:DeleteParameter',
        ],
        resources: [`arn:${cdk.Stack.of(this).partition}:ssm:*:*:parameter/Solutions/SO0111/*`],
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
      batchSize: sqsBatchSize,
      maxBatchingWindow: sqsBatchingWindow,
      reportBatchItemFailures: true,
    });

    this.preProcessorFunction.addEventSource(eventSource);
  }
}
