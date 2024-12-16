// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { Construct } from 'constructs';
import * as s3 from 'aws-cdk-lib/aws-s3';
import { BlockPublicAccess, Bucket, BucketEncryption } from 'aws-cdk-lib/aws-s3';
import * as cdk from 'aws-cdk-lib';
import { CfnOutput, Duration, Fn, NestedStack, RemovalPolicy } from 'aws-cdk-lib';
import { ReadWriteType, Trail } from 'aws-cdk-lib/aws-cloudtrail';
import * as s3n from 'aws-cdk-lib/aws-s3-notifications';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import { Architecture } from 'aws-cdk-lib/aws-lambda';
import * as cdk_nag from 'cdk-nag';
import { NagSuppressions } from 'cdk-nag';
import { Effect, PolicyStatement, Role, ServicePrincipal } from 'aws-cdk-lib/aws-iam';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { addCfnGuardSuppression } from '../cdk-helper/add-cfn-nag-suppression';

export const EVENT_FILTER_FUNCTION_NAME = `ASR-EventProcessor`;

interface MemberCloudTrailProps {
  secHubAdminAccount: string;
  region: string;
  solutionId: string;
  solutionName: string;
  namespace: string;
  cloudTrailLogGroupName: string;
  logWriterRoleArn: string;
}

export class MemberCloudTrail extends NestedStack {
  constructor(scope: Construct, id: string, props: MemberCloudTrailProps) {
    super(scope, id);

    const resourceNamePrefix = props.solutionId.replace(/^DEV-/, '');

    // Create a new S3 bucket to store CloudTrail logs
    const trailLoggingBucket = new Bucket(this, `ManagementEventsBucket`, {
      bucketName: Fn.join('-', ['so0111-asr-', props.namespace, '-management-events']),
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
    NagSuppressions.addResourceSuppressions(trailLoggingBucket, [
      { id: 'AwsSolutions-S1', reason: 'This is a logging bucket.' },
    ]);
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
      runtime: lambda.Runtime.NODEJS_20_X,
      architecture: Architecture.ARM_64,
      timeout: Duration.seconds(15),
      handler: 'index.handler',
      code: inlineCode,
      environment: {
        CLOUD_TRAIL_INVOKED_BY: props.solutionName,
        LOG_GROUP_NAME: props.cloudTrailLogGroupName,
        LOG_WRITER_ROLE_ARN: props.logWriterRoleArn,
      },
    });
    eventProcessorFunction.addToRolePolicy(
      new PolicyStatement({
        effect: Effect.ALLOW,
        actions: ['sts:AssumeRole'],
        resources: [props.logWriterRoleArn],
      }),
    );
    trailLoggingBucket.grantRead(eventProcessorFunction);
    addCfnGuardSuppression(eventProcessorFunction, 'LAMBDA_INSIDE_VPC');
    addCfnGuardSuppression(eventProcessorFunction, 'LAMBDA_CONCURRENCY_CHECK');

    if (eventProcessorFunction.role) {
      NagSuppressions.addResourceSuppressions(eventProcessorFunction.role, [
        {
          id: 'AwsSolutions-IAM4',
          reason: 'AWSLambdaBasicExecutionRole is sufficiently restrictive',
        },
      ]);
      NagSuppressions.addResourceSuppressions(
        eventProcessorFunction.role,
        [
          {
            id: 'AwsSolutions-IAM5',
            reason: 'Read permissions for all objects in the bucket are required',
          },
        ],
        true, // apply to children
      );
    }

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

    if (bucketNotificationsHandler.role)
      cdk_nag.NagSuppressions.addResourceSuppressions(bucketNotificationsHandler.role, [
        {
          id: 'AwsSolutions-IAM4',
          reason: 'AWSLambdaBasicExecutionRole is sufficiently restrictive',
        },
      ]);
    const defaultPolicy = bucketNotificationsHandler.role?.node?.findChild('DefaultPolicy');
    if (defaultPolicy)
      cdk_nag.NagSuppressions.addResourceSuppressions(defaultPolicy, [
        {
          id: 'AwsSolutions-IAM5',
          reason:
            'The IAM Role associated with the Lambda function destination for the S3 bucket event notification requires wildcard permissions to allow the S3 bucket to invoke the Lambda function. This is a necessary permission for the functionality of the solution.',
        },
      ]);
    addCfnGuardSuppression(bucketNotificationsHandler, 'CFN_NO_EXPLICIT_RESOURCE_NAMES');
    addCfnGuardSuppression(bucketNotificationsHandler, 'LAMBDA_CONCURRENCY_CHECK');

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
