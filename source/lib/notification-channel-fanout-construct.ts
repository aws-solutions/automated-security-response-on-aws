// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import * as cdk from 'aws-cdk-lib';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as sns from 'aws-cdk-lib/aws-sns';
import * as snsSubscriptions from 'aws-cdk-lib/aws-sns-subscriptions';
import * as sqs from 'aws-cdk-lib/aws-sqs';
import * as cloudwatch from 'aws-cdk-lib/aws-cloudwatch';
import { QueueEncryption } from 'aws-cdk-lib/aws-sqs';
import { Effect, PolicyStatement } from 'aws-cdk-lib/aws-iam';
import { Key } from 'aws-cdk-lib/aws-kms';
import { IBucket } from 'aws-cdk-lib/aws-s3';
import { Construct } from 'constructs';
import { addCfnGuardSuppression } from './cdk-helper/add-cfn-guard-suppression';
import { createLogGroup } from './cdk-helper/log-group';
import { addMetricsSsmPermissions } from './cdk-helper/add-metrics-permissions';
import { getLambdaCode } from './cdk-helper/lambda-code-manifest';
import { getConfig } from './config/cdk-config';
import { ChannelLambdaEnvironmentConfig } from '@asr/data-models';

export interface NotificationChannelFanoutProps {
  readonly solutionId: string;
  readonly solutionVersion: string;
  readonly solutionsBucket: IBucket;
  readonly solutionTMN: string;
  readonly resourceNamePrefix: string;
  readonly kmsKey: Key;
  readonly channelFanoutTopic: sns.ITopic;
  readonly webUiUrl: string;
  readonly iacTemplatesBucket: IBucket;
}

export interface ChannelFunctionOptions {
  readonly channelType: string;
  readonly constructIdPrefix: string;
  readonly handlerPath: string;
  readonly serviceName: string;
  readonly timeoutSeconds: number;
  readonly extraEnvironment?: Record<string, string>;
  readonly iamPolicy: PolicyStatement | PolicyStatement[];
}

export class NotificationChannelFanoutConstruct extends Construct {
  private readonly channelFunctions: Map<string, lambda.Function> = new Map();
  readonly emailNotificationsTopic: sns.Topic;

  /** Returns a read-only view of channel type → Lambda function mappings. */
  getChannelFunctions(): ReadonlyMap<string, lambda.Function> {
    return this.channelFunctions;
  }

  constructor(scope: Construct, id: string, props: NotificationChannelFanoutProps) {
    super(scope, id);
    const stack = cdk.Stack.of(this);
    const config = getConfig();
    const channelConfig = config.notificationChannels;
    const sqsRetentionPeriod = cdk.Duration.days(config.sqs.retentionPeriodDays);
    const sqsDataKeyReuse = cdk.Duration.minutes(config.sqs.dataKeyReuseMinutes);
    const lambdaCode = getLambdaCode(
      props.solutionsBucket,
      props.solutionTMN,
      props.solutionVersion,
      'asr_lambdas.zip',
    );

    const baseEnv = {
      SOLUTION_TRADEMARKEDNAME: props.solutionTMN,
      POWERTOOLS_LOG_LEVEL: channelConfig.logLevel,
      AWS_ACCOUNT_ID: stack.account,
      AWS_PARTITION: stack.partition,
      STACK_ID: stack.stackId,
      RESOURCE_NAME_PREFIX: props.resourceNamePrefix,
      WEB_UI_URL: props.webUiUrl,
      IAC_TEMPLATES_BUCKET: props.iacTemplatesBucket.bucketName,
    } satisfies Record<keyof ChannelLambdaEnvironmentConfig, string>;

    const secretsManagerResources = [
      `arn:${stack.partition}:secretsmanager:${stack.region}:${stack.account}:secret:${channelConfig.secretsResourcePattern}*`,
    ];

    const createChannelFunction = (options: ChannelFunctionOptions): lambda.Function => {
      const dlq = new sqs.Queue(this, `${options.constructIdPrefix}ChannelDLQ`, {
        retentionPeriod: sqsRetentionPeriod,
        encryption: QueueEncryption.KMS,
        encryptionMasterKey: props.kmsKey,
        enforceSSL: true,
        dataKeyReuse: sqsDataKeyReuse,
      });

      const channelLogGroup = createLogGroup(this, `${options.constructIdPrefix}ChannelFunctionLogGroup`);

      const fn = new lambda.Function(this, `${options.constructIdPrefix}ChannelFunction`, {
        functionName: `${props.resourceNamePrefix}-ASR-${options.constructIdPrefix}Channel`,
        runtime: lambda.Runtime.NODEJS_24_X,
        handler: options.handlerPath,
        code: lambdaCode,
        timeout: cdk.Duration.seconds(options.timeoutSeconds),
        memorySize: channelConfig.lambdaMemorySize,
        environment: {
          ...baseEnv,
          POWERTOOLS_SERVICE_NAME: options.serviceName,
          ...options.extraEnvironment,
        },
        tracing: lambda.Tracing.ACTIVE,
        reservedConcurrentExecutions: channelConfig.lambdaReservedConcurrency,
        logGroup: channelLogGroup,
      });
      addCfnGuardSuppression(fn, 'LAMBDA_INSIDE_VPC');
      addCfnGuardSuppression(fn, 'CFN_NO_EXPLICIT_RESOURCE_NAMES');
      props.kmsKey.grantDecrypt(fn);
      const iamPolicies = Array.isArray(options.iamPolicy) ? options.iamPolicy : [options.iamPolicy];
      iamPolicies.forEach((policy) => fn.addToRolePolicy(policy));
      // SSM access for publishing anonymous usage metrics via sendMetrics()
      addMetricsSsmPermissions(fn, props.solutionId);
      props.channelFanoutTopic.addSubscription(
        new snsSubscriptions.LambdaSubscription(fn, {
          filterPolicy: { channelType: sns.SubscriptionFilter.stringFilter({ allowlist: [options.channelType] }) },
          deadLetterQueue: dlq,
        }),
      );

      const dlqAlarm = new cloudwatch.Alarm(this, `${options.constructIdPrefix}ChannelDLQAlarm`, {
        alarmName: `${props.resourceNamePrefix}-ASR-${options.constructIdPrefix}ChannelDLQ`,
        alarmDescription: `Automated Security Response on AWS: Messages in the ${options.channelType} notification channel DLQ. The channel Lambda failed to deliver notifications after SNS retries. Inspect the DLQ and CloudWatch logs for the ${options.constructIdPrefix}Channel Lambda.`,
        metric: new cloudwatch.Metric({
          namespace: 'AWS/SQS',
          metricName: 'ApproximateNumberOfMessagesVisible',
          dimensionsMap: { QueueName: dlq.queueName },
        }).with({
          statistic: 'Sum',
          period: cdk.Duration.minutes(1),
        }),
        threshold: 1,
        evaluationPeriods: 1,
        datapointsToAlarm: 1,
        comparisonOperator: cloudwatch.ComparisonOperator.GREATER_THAN_OR_EQUAL_TO_THRESHOLD,
        treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
        actionsEnabled: true,
      });
      addCfnGuardSuppression(dlqAlarm, 'CFN_NO_EXPLICIT_RESOURCE_NAMES');

      this.channelFunctions.set(options.channelType, fn);
      props.iacTemplatesBucket.grantRead(fn);
      return fn;
    };

    // ── Email Channel ──────────────────────────────────────────────────

    this.emailNotificationsTopic = new sns.Topic(this, 'EmailNotificationsTopic', {
      topicName: `${props.resourceNamePrefix}-ASR-EmailNotifications`,
      masterKey: props.kmsKey,
    });

    createChannelFunction({
      channelType: 'email',
      constructIdPrefix: 'Email',
      handlerPath: 'notification-channels/email-channel.handler',
      serviceName: 'notification_email_channel',
      timeoutSeconds: channelConfig.lambdaTimeoutSeconds,
      iamPolicy: new PolicyStatement({
        effect: Effect.ALLOW,
        actions: ['sns:Publish'],
        resources: [`arn:${stack.partition}:sns:${stack.region}:${stack.account}:asr-notifications-*`],
      }),
    });

    // ── Slack Channel ──────────────────────────────────────────────────

    const secretsManagerPolicy = new PolicyStatement({
      effect: Effect.ALLOW,
      actions: ['secretsmanager:GetSecretValue'],
      resources: secretsManagerResources,
    });

    createChannelFunction({
      channelType: 'slack',
      constructIdPrefix: 'Slack',
      handlerPath: 'notification-channels/slack-channel.handler',
      serviceName: 'notification_slack_channel',
      timeoutSeconds: channelConfig.webhookLambdaTimeoutSeconds,
      iamPolicy: secretsManagerPolicy,
    });

    // ── JIRA Channel ───────────────────────────────────────────────────

    createChannelFunction({
      channelType: 'jira',
      constructIdPrefix: 'Jira',
      handlerPath: 'notification-channels/jira-channel.handler',
      serviceName: 'notification_jira_channel',
      timeoutSeconds: channelConfig.webhookLambdaTimeoutSeconds,
      iamPolicy: secretsManagerPolicy,
    });

    // ── ServiceNow Channel ─────────────────────────────────────────────

    createChannelFunction({
      channelType: 'servicenow',
      constructIdPrefix: 'ServiceNow',
      handlerPath: 'notification-channels/servicenow-channel.handler',
      serviceName: 'notification_servicenow_channel',
      timeoutSeconds: channelConfig.webhookLambdaTimeoutSeconds,
      iamPolicy: secretsManagerPolicy,
    });

    // ── SNS Channel ────────────────────────────────────────────────────

    createChannelFunction({
      channelType: 'sns',
      constructIdPrefix: 'Sns',
      handlerPath: 'notification-channels/sns-channel.handler',
      serviceName: 'notification_sns_channel',
      timeoutSeconds: channelConfig.lambdaTimeoutSeconds,
      iamPolicy: [
        new PolicyStatement({
          effect: Effect.ALLOW,
          actions: ['sns:Publish'],
          resources: [`arn:${stack.partition}:sns:${stack.region}:${stack.account}:*`],
        }),
        // Publishing to a KMS-encrypted (SSE) customer SNS topic also requires kms:GenerateDataKey +
        // kms:Decrypt on the topic's key. Customer topics can use arbitrary customer-managed keys
        // unknown at deploy time, so the grant is scoped to same-account + same-region keys and
        // constrained to use through SNS only via the kms:ViaService condition.
        new PolicyStatement({
          effect: Effect.ALLOW,
          actions: ['kms:GenerateDataKey', 'kms:Decrypt'],
          resources: [`arn:${stack.partition}:kms:${stack.region}:${stack.account}:key/*`],
          conditions: {
            StringEquals: { 'kms:ViaService': `sns.${stack.region}.amazonaws.com` },
          },
        }),
      ],
    });
  }
}
