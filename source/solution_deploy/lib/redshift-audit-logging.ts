// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { CfnCondition, CfnParameter, Fn, RemovalPolicy, Stack } from 'aws-cdk-lib';
import { Effect, PolicyStatement, ServicePrincipal, StarPrincipal } from 'aws-cdk-lib/aws-iam';
import {
  BlockPublicAccess,
  Bucket,
  BucketEncryption,
  BucketPolicy,
  CfnBucket,
  CfnBucketPolicy,
} from 'aws-cdk-lib/aws-s3';
import { CfnParameter as CfnSsmParameter, StringParameter } from 'aws-cdk-lib/aws-ssm';
import { Construct } from 'constructs';
import { NagSuppressions } from 'cdk-nag';
import setCondition from './set-condition';
import { addCfnNagSuppression } from './add-cfn-nag-suppression';

export interface RedshiftAuditLoggingProps {
  readonly solutionId: string;
}

enum ChoiceParam {
  Yes = 'yes',
  No = 'no',
}

export class RedshiftAuditLogging extends Construct {
  constructor(scope: Construct, id: string, props: RedshiftAuditLoggingProps) {
    super(scope, id);

    // Add template param at stack scope to keep logical ID consistent
    const templateParam = new CfnParameter(Stack.of(this), 'CreateS3BucketForRedshiftAuditLogging', {
      default: ChoiceParam.No,
      allowedValues: [ChoiceParam.Yes, ChoiceParam.No],
      description: 'Create S3 Bucket For Redshift Cluster Audit Logging.',
    });

    const condition = new CfnCondition(this, 'Condition', {
      expression: Fn.conditionEquals(templateParam.valueAsString, ChoiceParam.Yes),
    });

    const bucket = new Bucket(this, 'Bucket', {
      encryption: BucketEncryption.S3_MANAGED,
      publicReadAccess: false,
      blockPublicAccess: BlockPublicAccess.BLOCK_ALL,
    });
    (bucket.node.defaultChild as CfnBucket).overrideLogicalId('S3BucketForRedShiftAuditLogging652E7355');

    setCondition(bucket, condition);

    NagSuppressions.addResourceSuppressions(bucket, [{ id: 'AwsSolutions-S1', reason: 'This is a logging bucket.' }]);
    addCfnNagSuppression(bucket, {
      id: 'W35',
      reason: 'Logs bucket does not require logging configuration',
    });

    const bucketPolicy = new BucketPolicy(this, 'Policy', {
      bucket: bucket,
      removalPolicy: RemovalPolicy.RETAIN,
    });
    bucketPolicy.document.addStatements(
      new PolicyStatement({
        sid: 'Put bucket policy needed for audit logging',
        effect: Effect.ALLOW,
        actions: ['s3:GetBucketAcl', 's3:PutObject'],
        principals: [new ServicePrincipal('redshift.amazonaws.com')],
        resources: [
          bucket.bucketArn,
          Fn.sub('arn:${AWS::Partition}:s3:::${BucketName}/*', {
            BucketName: `${bucket.bucketName}`,
          }),
        ],
      }),
      new PolicyStatement({
        sid: 'EnforceSSL',
        effect: Effect.DENY,
        actions: ['s3:*'],
        principals: [new StarPrincipal()],
        resources: [bucket.bucketArn, bucket.arnForObjects('*')],
        conditions: { Bool: { ['aws:SecureTransport']: 'false' } },
      })
    );

    const cfnBucketPolicy = bucketPolicy.node.defaultChild as CfnBucketPolicy;
    cfnBucketPolicy.cfnOptions.condition = condition;

    NagSuppressions.addResourceSuppressions(bucket, [
      { id: 'AwsSolutions-S1', reason: 'Logs bucket does not require logging configuration' },
    ]);

    cfnBucketPolicy.addDependency(bucket.node.defaultChild as CfnBucket);

    const ssmParameterForRedshift4BucketName = new StringParameter(this, 'SSMParameterForS3BucketNameForREDSHIFT4', {
      description:
        'Parameter to store the S3 bucket name for the remediation AFSBP.REDSHIFT.4, the default value is bucket-name which has to be updated by the user before using the remediation.',
      parameterName: `/Solutions/${props.solutionId}/afsbp/1.0.0/REDSHIFT.4/S3BucketNameForAuditLogging`,
      stringValue: bucket.bucketName,
    });
    (ssmParameterForRedshift4BucketName.node.defaultChild as CfnSsmParameter).overrideLogicalId(
      'SSMParameterForS3BucketNameForREDSHIFT441DD36B1'
    );

    setCondition(ssmParameterForRedshift4BucketName, condition);

    ssmParameterForRedshift4BucketName.node.addDependency(bucket.node.defaultChild as CfnBucket);
  }
}
