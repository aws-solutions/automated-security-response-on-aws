// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import * as cdk from 'aws-cdk-lib';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as events from 'aws-cdk-lib/aws-events';
import * as targets from 'aws-cdk-lib/aws-events-targets';
import * as sns from 'aws-cdk-lib/aws-sns';
import { ITable } from 'aws-cdk-lib/aws-dynamodb';
import { Grant, Effect, PolicyStatement } from 'aws-cdk-lib/aws-iam';
import { Key } from 'aws-cdk-lib/aws-kms';
import { IBucket } from 'aws-cdk-lib/aws-s3';
import { Construct } from 'constructs';
import { addCfnGuardSuppression } from './cdk-helper/add-cfn-guard-suppression';
import { createLogGroup } from './cdk-helper/log-group';
import { addMetricsSsmPermissions } from './cdk-helper/add-metrics-permissions';
import { getLambdaCode } from './cdk-helper/lambda-code-manifest';
import { BatchProcessorEnvironmentConfig } from '@asr/data-models';

export interface BatchProcessorProps {
  readonly solutionId: string;
  readonly solutionVersion: string;
  readonly solutionsBucket: IBucket;
  readonly solutionTMN: string;
  readonly resourceNamePrefix: string;
  readonly kmsKey: Key;
  readonly notificationConfigTable: ITable;
  readonly notificationBatchesTable: ITable;
  readonly resourceFiltersTable: ITable;
  readonly findingsTable: ITable;
  readonly remediationHistoryTable: ITable;
  readonly channelFanoutTopic: sns.ITopic;
  readonly csvExportBucket: IBucket;
  readonly webUiUrl: string;
  readonly orchestratorArn: string;
}

export class BatchProcessorConstruct extends Construct {
  readonly batchProcessorFunction: lambda.Function;

  constructor(scope: Construct, id: string, props: BatchProcessorProps) {
    super(scope, id);
    const stack = cdk.Stack.of(this);

    const processingTimeout = cdk.Duration.minutes(5);

    const environment = {
      SOLUTION_TRADEMARKEDNAME: props.solutionTMN,
      POWERTOOLS_SERVICE_NAME: 'batch_processor',
      POWERTOOLS_LOG_LEVEL: 'INFO',
      NOTIFICATION_CONFIG_TABLE_NAME: props.notificationConfigTable.tableName,
      NOTIFICATION_BATCHES_TABLE_NAME: props.notificationBatchesTable.tableName,
      RESOURCE_FILTERS_TABLE_NAME: props.resourceFiltersTable.tableName,
      FINDINGS_TABLE_NAME: props.findingsTable.tableName,
      REMEDIATION_HISTORY_TABLE_NAME: props.remediationHistoryTable.tableName,
      AWS_ACCOUNT_ID: stack.account,
      STACK_ID: stack.stackId,
      CHANNEL_FANOUT_TOPIC_ARN: props.channelFanoutTopic.topicArn,
      CSV_EXPORT_BUCKET_NAME: props.csvExportBucket.bucketName,
      LAMBDA_TIMEOUT_SECONDS: processingTimeout.toSeconds().toString(),
      WEB_UI_URL: props.webUiUrl,
      ORCHESTRATOR_ARN: props.orchestratorArn,
    } satisfies BatchProcessorEnvironmentConfig;

    const batchProcessorFunctionLogGroup = createLogGroup(this, 'BatchProcessorFunctionLogGroup');

    this.batchProcessorFunction = new lambda.Function(this, 'BatchProcessorFunction', {
      functionName: `${props.resourceNamePrefix}-ASR-BatchProcessor`,
      runtime: lambda.Runtime.NODEJS_24_X,
      handler: 'batch-processor/batchProcessor.handler',
      code: getLambdaCode(props.solutionsBucket, props.solutionTMN, props.solutionVersion, 'asr_lambdas.zip'),
      timeout: processingTimeout,
      memorySize: 1024,
      environment,
      environmentEncryption: props.kmsKey,
      tracing: lambda.Tracing.ACTIVE,
      reservedConcurrentExecutions: 1,
      logGroup: batchProcessorFunctionLogGroup,
    });

    addCfnGuardSuppression(this.batchProcessorFunction, 'LAMBDA_INSIDE_VPC');
    addCfnGuardSuppression(this.batchProcessorFunction, 'CFN_NO_EXPLICIT_RESOURCE_NAMES');

    // KMS decrypt for encrypted DynamoDB tables and SNS topic
    props.kmsKey.grantDecrypt(this.batchProcessorFunction);

    // DynamoDB permissions
    props.notificationConfigTable.grantReadData(this.batchProcessorFunction);
    Grant.addToPrincipal({
      grantee: this.batchProcessorFunction,
      actions: ['dynamodb:Query'],
      resourceArns: [`${props.notificationConfigTable.tableArn}/index/*`],
    });

    props.notificationBatchesTable.grantReadWriteData(this.batchProcessorFunction);

    props.resourceFiltersTable.grantReadData(this.batchProcessorFunction);

    props.findingsTable.grantReadWriteData(this.batchProcessorFunction);
    Grant.addToPrincipal({
      grantee: this.batchProcessorFunction,
      actions: ['dynamodb:Query'],
      resourceArns: [`${props.findingsTable.tableArn}/index/*`],
    });

    props.remediationHistoryTable.grantReadWriteData(this.batchProcessorFunction);
    Grant.addToPrincipal({
      grantee: this.batchProcessorFunction,
      actions: ['dynamodb:Query'],
      resourceArns: [`${props.remediationHistoryTable.tableArn}/index/*`],
    });

    // Trigger the Orchestrator step function for overdue finding remediation
    this.batchProcessorFunction.addToRolePolicy(
      new PolicyStatement({
        effect: Effect.ALLOW,
        actions: ['states:StartExecution'],
        resources: [props.orchestratorArn],
      }),
    );

    // SNS publish to channel fanout
    props.channelFanoutTopic.grantPublish(this.batchProcessorFunction);

    // SSM access for publishing anonymous usage metrics via sendMetrics()
    addMetricsSsmPermissions(this.batchProcessorFunction, props.solutionId);

    // S3 put for batch CSV upload, read for pre-signed download URLs. Avoid grantReadWrite
    // so the Lambda does not receive s3:DeleteObject permissions it never exercises.
    props.csvExportBucket.grantPut(this.batchProcessorFunction);
    props.csvExportBucket.grantRead(this.batchProcessorFunction);

    // EventBridge scheduled rule — every 5 minutes
    const scheduledRule = new events.Rule(this, 'BatchProcessorSchedule', {
      ruleName: `${props.resourceNamePrefix}-ASR-BatchProcessorSchedule`,
      schedule: events.Schedule.rate(cdk.Duration.minutes(5)),
      description: 'Triggers the ASR Batch Processor Lambda every 5 minutes to process ready notification batches',
    });

    scheduledRule.addTarget(new targets.LambdaFunction(this.batchProcessorFunction));
  }
}
