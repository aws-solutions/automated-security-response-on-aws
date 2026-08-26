// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import * as cdk from 'aws-cdk-lib';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as sqs from 'aws-cdk-lib/aws-sqs';
import * as sns from 'aws-cdk-lib/aws-sns';
import { QueueEncryption } from 'aws-cdk-lib/aws-sqs';
import { SqsEventSource } from 'aws-cdk-lib/aws-lambda-event-sources';
import { Construct } from 'constructs';
import { IBucket } from 'aws-cdk-lib/aws-s3';
import { Key } from 'aws-cdk-lib/aws-kms';
import { ITable } from 'aws-cdk-lib/aws-dynamodb';
import { Grant } from 'aws-cdk-lib/aws-iam';
import { addCfnGuardSuppression } from './cdk-helper/add-cfn-guard-suppression';
import { createLogGroup } from './cdk-helper/log-group';
import { addMetricsSsmPermissions } from './cdk-helper/add-metrics-permissions';
import { getLambdaCode } from './cdk-helper/lambda-code-manifest';
import { getConfig } from './config/cdk-config';
import { NotificationDispatcherEnvironmentConfig } from '@asr/data-models';

export interface NotificationDispatcherProps {
  readonly solutionId: string;
  readonly solutionVersion: string;
  readonly solutionsBucket: IBucket;
  readonly solutionTMN: string;
  readonly notificationConfigTable: ITable;
  readonly notificationBatchesTable: ITable;
  readonly resourceFiltersTable: ITable;
  readonly kmsKey: Key;
  readonly resourceNamePrefix: string;
}

export class NotificationDispatcherConstruct extends Construct {
  readonly queue: sqs.Queue;
  readonly deadLetterQueue: sqs.Queue;
  readonly dispatcherFunction: lambda.Function;
  readonly channelFanoutTopic: sns.Topic;

  constructor(scope: Construct, id: string, props: NotificationDispatcherProps) {
    super(scope, id);
    const stack = cdk.Stack.of(this);
    const config = getConfig();

    const processingTimeout = cdk.Duration.minutes(5);
    const sqsBatchSize = 10;
    const sqsBatchingWindow = cdk.Duration.seconds(5);
    const lambdaConcurrency = 5;
    const sqsRetentionPeriod = cdk.Duration.days(config.sqs.retentionPeriodDays);
    const sqsDataKeyReuse = cdk.Duration.minutes(config.sqs.dataKeyReuseMinutes);

    this.deadLetterQueue = new sqs.Queue(this, 'NotificationDLQ', {
      retentionPeriod: sqsRetentionPeriod,
      encryption: QueueEncryption.KMS,
      encryptionMasterKey: props.kmsKey,
      enforceSSL: true,
      dataKeyReuse: sqsDataKeyReuse,
    });

    this.queue = new sqs.Queue(this, 'NotificationQueue', {
      visibilityTimeout: processingTimeout,
      encryption: QueueEncryption.KMS,
      encryptionMasterKey: props.kmsKey,
      enforceSSL: true,
      deadLetterQueue: {
        queue: this.deadLetterQueue,
        maxReceiveCount: 3,
      },
      dataKeyReuse: sqsDataKeyReuse,
    });

    this.channelFanoutTopic = new sns.Topic(this, 'ChannelFanoutTopic', {
      masterKey: props.kmsKey,
      enforceSSL: true,
    });

    const environment = {
      SOLUTION_TRADEMARKEDNAME: props.solutionTMN,
      POWERTOOLS_SERVICE_NAME: 'notification_dispatcher',
      POWERTOOLS_LOG_LEVEL: 'INFO',
      NOTIFICATION_CONFIG_TABLE_NAME: props.notificationConfigTable.tableName,
      NOTIFICATION_BATCHES_TABLE_NAME: props.notificationBatchesTable.tableName,
      RESOURCE_FILTERS_TABLE_NAME: props.resourceFiltersTable.tableName,
      AWS_ACCOUNT_ID: stack.account,
      STACK_ID: stack.stackId,
      CHANNEL_FANOUT_TOPIC_ARN: this.channelFanoutTopic.topicArn,
      LAMBDA_TIMEOUT_SECONDS: processingTimeout.toSeconds().toString(),
    } satisfies NotificationDispatcherEnvironmentConfig;

    const dispatcherFunctionLogGroup = createLogGroup(this, 'DispatcherFunctionLogGroup');

    this.dispatcherFunction = new lambda.Function(this, 'DispatcherFunction', {
      functionName: `${props.resourceNamePrefix}-ASR-NotificationDispatcher`,
      runtime: lambda.Runtime.NODEJS_24_X,
      handler: 'notification-dispatcher/notificationDispatcher.handler',
      code: getLambdaCode(props.solutionsBucket, props.solutionTMN, props.solutionVersion, 'asr_lambdas.zip'),
      timeout: processingTimeout,
      memorySize: 512,
      environment,
      tracing: lambda.Tracing.ACTIVE,
      reservedConcurrentExecutions: lambdaConcurrency,
      logGroup: dispatcherFunctionLogGroup,
    });

    addCfnGuardSuppression(this.dispatcherFunction, 'LAMBDA_INSIDE_VPC');
    addCfnGuardSuppression(this.dispatcherFunction, 'CFN_NO_EXPLICIT_RESOURCE_NAMES');

    // Grant DynamoDB read on config table, read/write on batches table
    props.notificationConfigTable.grantReadData(this.dispatcherFunction);
    // grantReadData on an imported table does not cover GSI indexes — grant Query explicitly
    Grant.addToPrincipal({
      grantee: this.dispatcherFunction,
      actions: ['dynamodb:Query'],
      resourceArns: [`${props.notificationConfigTable.tableArn}/index/*`],
    });

    props.notificationBatchesTable.grantReadWriteData(this.dispatcherFunction);

    props.resourceFiltersTable.grantReadData(this.dispatcherFunction);

    // SSM access for publishing anonymous usage metrics via sendMetrics()
    addMetricsSsmPermissions(this.dispatcherFunction, props.solutionId);

    this.channelFanoutTopic.grantPublish(this.dispatcherFunction);

    this.dispatcherFunction.addEventSource(
      new SqsEventSource(this.queue, {
        batchSize: sqsBatchSize,
        maxBatchingWindow: sqsBatchingWindow,
        reportBatchItemFailures: true,
      }),
    );
  }

  grantSendMessages(grantee: lambda.IFunction): void {
    this.queue.grantSendMessages(grantee);
  }
}
