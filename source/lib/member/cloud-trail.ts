// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { Construct } from 'constructs';
import * as s3 from 'aws-cdk-lib/aws-s3';
import { BlockPublicAccess, Bucket, BucketEncryption } from 'aws-cdk-lib/aws-s3';
import * as cdk from 'aws-cdk-lib';
import { CfnOutput, CfnParameter, Duration, Fn, RemovalPolicy, Stack, StackProps } from 'aws-cdk-lib';
import { ReadWriteType, Trail } from 'aws-cdk-lib/aws-cloudtrail';
import * as s3n from 'aws-cdk-lib/aws-s3-notifications';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import { Architecture } from 'aws-cdk-lib/aws-lambda';
import { Effect, PolicyStatement, Role, ServicePrincipal } from 'aws-cdk-lib/aws-iam';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { addCfnGuardSuppression } from '../cdk-helper/add-cfn-guard-suppression';

export const EVENT_FILTER_FUNCTION_NAME = `ASR-EventProcessor`;
const SOLUTION_ID = process.env['SOLUTION_ID'] || 'unknown';

export class MemberCloudTrailStack extends Stack {
  constructor(scope: Construct, id: string, props: StackProps) {
    super(scope, id, props);

    const resourceNamePrefix = SOLUTION_ID.replace(/^DEV-/, '');

    const namespace = new CfnParameter(this, 'Namespace');
    const cloudTrailLogGroupName = new CfnParameter(this, 'CloudTrailLogGroupName');
    const logWriterRoleArn = new CfnParameter(this, 'LogWriterRoleArn');

    // prettier-ignore
    const trailLoggingBucket = new Bucket(this, `ManagementEventsBucket`, {//NOSONAR No need to version because of lifecycleRules (1-day retention).
      bucketName: Fn.join('-', ['so0111-asr', namespace.valueAsString, 'management-events', this.account]),
      encryption: BucketEncryption.S3_MANAGED,
      publicReadAccess: false,
      blockPublicAccess: BlockPublicAccess.BLOCK_ALL,
      enforceSSL: true,
      lifecycleRules: [
        {
          enabled: true,
          // events are processed by lambda, no need to store longer
          expiration: Duration.days(1),
        },
      ],
      removalPolicy: RemovalPolicy.RETAIN_ON_UPDATE_OR_DELETE,
    });
    addCfnGuardSuppression(trailLoggingBucket, 'S3_BUCKET_LOGGING_ENABLED');

    const trail = new Trail(this, 'ManagementEventsTrail', {
      bucket: trailLoggingBucket,
      s3KeyPrefix: 'cloudtrail-logs',
      isMultiRegionTrail: true,
      includeGlobalServiceEvents: true,
      enableFileValidation: true,
      managementEvents: ReadWriteType.WRITE_ONLY,
    });

    // Read JavaScript code directly from file, no build/package required.
    const eventProcessorJsFilePath = path.join(__dirname, 'cloud-trail-event-processor', 'event-processor.js');
    const inlineCode = lambda.Code.fromInline(fs.readFileSync(eventProcessorJsFilePath, 'utf8'));

    // Add S3 notification to trigger the EventProcessor Lambda function
    const eventProcessorFunction = new lambda.Function(this, EVENT_FILTER_FUNCTION_NAME, {
      functionName: resourceNamePrefix + '-' + EVENT_FILTER_FUNCTION_NAME,
      runtime: lambda.Runtime.NODEJS_22_X,
      architecture: Architecture.ARM_64,
      timeout: Duration.seconds(15),
      handler: 'index.handler',
      code: inlineCode,
      environment: {
        CLOUD_TRAIL_INVOKED_BY: 'NAME',
        LOG_GROUP_NAME: cloudTrailLogGroupName.valueAsString,
        LOG_WRITER_ROLE_ARN: logWriterRoleArn.valueAsString,
      },
    });
    eventProcessorFunction.addToRolePolicy(
      new PolicyStatement({
        effect: Effect.ALLOW,
        actions: ['sts:AssumeRole'],
        resources: [logWriterRoleArn.valueAsString],
      }),
    );
    trailLoggingBucket.grantRead(eventProcessorFunction);
    addCfnGuardSuppression(eventProcessorFunction, 'LAMBDA_INSIDE_VPC');
    addCfnGuardSuppression(eventProcessorFunction, 'LAMBDA_CONCURRENCY_CHECK');

    // Role that allows S3 to trigger the EventProcessor function
    const s3TriggerRole = new Role(this, 'S3TriggerRole', {
      assumedBy: new ServicePrincipal('s3.amazonaws.com'),
      roleName: 'CloudTrailS3EventTriggerLambdaRole',
    });
    eventProcessorFunction.grantInvoke(s3TriggerRole);
    addCfnGuardSuppression(s3TriggerRole, 'CFN_NO_EXPLICIT_RESOURCE_NAMES');

    const lambdaDestination = new s3n.LambdaDestination(eventProcessorFunction);
    trailLoggingBucket.addEventNotification(s3.EventType.OBJECT_CREATED, lambdaDestination, {
      prefix: 'cloudtrail-logs',
      suffix: '.json.gz',
    });

    // Find the BucketNotificationsHandler Lambda function created by .addEventNotification()
    const bucketNotificationsHandlers = this.node
      .findAll()
      .filter((node) => node.node.id.includes('BucketNotificationsHandler')) as lambda.Function[];

    if (bucketNotificationsHandlers.length !== 1) {
      throw new Error(
        `Expected exactly one BucketNotificationsHandler function, got ${bucketNotificationsHandlers.length}`,
      );
    }

    const bucketNotificationsHandler = bucketNotificationsHandlers[0];

    addCfnGuardSuppression(bucketNotificationsHandler, 'CFN_NO_EXPLICIT_RESOURCE_NAMES');
    addCfnGuardSuppression(bucketNotificationsHandler, 'LAMBDA_CONCURRENCY_CHECK');
    addCfnGuardSuppression(bucketNotificationsHandler, 'LAMBDA_INSIDE_VPC');

    new CfnOutput(this, 'TrailArn', {
      value: trail.trailArn,
      description: 'The ARN of the CloudTrail trail',
    });

    new CfnOutput(this, 'BucketName', {
      value: trailLoggingBucket.bucketName,
      description: 'The name of the S3 bucket storing CloudTrail logs',
    });

    new cdk.CfnOutput(this, 'LambdaFunctionArn', {
      value: eventProcessorFunction.functionArn,
      description: 'The ARN of the Lambda function',
    });
  }
}
