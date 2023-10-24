// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { CfnCondition, CfnParameter, Fn, RemovalPolicy } from 'aws-cdk-lib';
import { Effect, PolicyStatement, ServicePrincipal, StarPrincipal } from 'aws-cdk-lib/aws-iam';
import { BlockPublicAccess, Bucket, BucketEncryption, BucketPolicy, CfnBucket } from 'aws-cdk-lib/aws-s3';
import { StringParameter } from 'aws-cdk-lib/aws-ssm';
import { Construct } from 'constructs';
import { NagSuppressions } from 'cdk-nag';
import setCondition from '../cdk-helper/set-condition';
import { addCfnNagSuppression } from '../cdk-helper/add-cfn-nag-suppression';
import ChoiceParam from '../cdk-helper/choice-param';

export interface RedshiftAuditLoggingProps {
  readonly solutionId: string;
}

export class RedshiftAuditLogging extends Construct {
  constructor(scope: Construct, id: string, props: RedshiftAuditLoggingProps) {
    super(scope, id);

    // Create all resource at `scope` scope rather than `this` to maintain logical IDs

    const templateParam = new CfnParameter(scope, 'CreateS3BucketForRedshiftAuditLogging', {
      default: ChoiceParam.No,
      allowedValues: [ChoiceParam.Yes, ChoiceParam.No],
      description: 'Create S3 Bucket For Redshift Cluster Audit Logging.',
    });

    const condition = new CfnCondition(scope, 'EnableS3BucketForRedShift4', {
      expression: Fn.conditionEquals(templateParam.valueAsString, ChoiceParam.Yes),
    });

    const bucket = new Bucket(scope, 'S3BucketForRedShiftAuditLogging', { //NOSONAR The policy attached to this bucket enforces SSL.
      encryption: BucketEncryption.S3_MANAGED,
      publicReadAccess: false,
      blockPublicAccess: BlockPublicAccess.BLOCK_ALL,
    });
    setCondition(bucket, condition);

    NagSuppressions.addResourceSuppressions(bucket, [{ id: 'AwsSolutions-S1', reason: 'This is a logging bucket.' }]);
    addCfnNagSuppression(bucket, {
      id: 'W35',
      reason: 'Logs bucket does not require logging configuration',
    });

    const bucketPolicy = new BucketPolicy(scope, 'S3BucketForRedShiftAuditLoggingBucketPolicy', {
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
    setCondition(bucketPolicy, condition);
    bucketPolicy.node.addDependency(bucket.node.defaultChild as CfnBucket);

    NagSuppressions.addResourceSuppressions(bucket, [
      { id: 'AwsSolutions-S1', reason: 'Logs bucket does not require logging configuration' },
    ]);

    const ssmParam = new StringParameter(scope, 'SSMParameterForS3BucketNameForREDSHIFT4', {
      description:
        'Parameter to store the S3 bucket name for the remediation AFSBP.REDSHIFT.4, the default value is bucket-name which has to be updated by the user before using the remediation.',
      parameterName: `/Solutions/${props.solutionId}/afsbp/1.0.0/REDSHIFT.4/S3BucketNameForAuditLogging`,
      stringValue: bucket.bucketName,
    });
    setCondition(ssmParam, condition);
    ssmParam.node.addDependency(bucket.node.defaultChild as CfnBucket);
  }
}
