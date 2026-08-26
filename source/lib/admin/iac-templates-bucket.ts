// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import * as cdk from 'aws-cdk-lib';
import { Effect, PolicyStatement, AnyPrincipal } from 'aws-cdk-lib/aws-iam';
import { IKey } from 'aws-cdk-lib/aws-kms';
import { BlockPublicAccess, Bucket, BucketEncryption } from 'aws-cdk-lib/aws-s3';
import { Construct } from 'constructs';
import { addCfnGuardSuppression } from '../cdk-helper/add-cfn-guard-suppression';

export interface IaCTemplatesBucketProps {
  readonly solutionId: string;
  readonly namespace: string;
  readonly encryptionKey: IKey;
}

export class IaCTemplatesBucketConstruct extends Construct {
  public readonly bucket: Bucket;
  /**
   * Bucket ARN built from the deterministic bucket name rather than the
   * resource's `Fn::GetAtt`/`Ref`. Consumers that must reference this bucket
   * inside the same KMS CMK's key policy (e.g. the deletion-monitoring S3
   * source-ARN condition) use this to avoid a key<->bucket dependency cycle,
   * since the CMK also encrypts the bucket.
   */
  public readonly deterministicBucketArn: string;

  constructor(scope: Construct, id: string, props: IaCTemplatesBucketProps) {
    super(scope, id);

    const stack = cdk.Stack.of(scope);

    // S3 folder structure (populated by IaC Template Sync custom resource):
    //   {controlId}/{format}/              - Solution-managed templates (overwritten on upgrade)
    //   .customized/{controlId}/{format}/  - Customer customizations (never touched by sync)
    //   .metadata/manifest.json            - Deployment manifest
    //   .deprecated/                       - Archived templates for removed controls

    const bucketName = cdk.Fn.join('', [
      'so0111-asr-iac-templates-',
      props.namespace,
      '-',
      stack.region,
      '-',
      stack.account,
    ]);

    const bucket = new Bucket(scope, 'IaCTemplatesBucketResource', {
      bucketName,
      versioned: true,
      encryption: BucketEncryption.KMS,
      encryptionKey: props.encryptionKey,
      bucketKeyEnabled: true,
      enforceSSL: true,
      publicReadAccess: false,
      blockPublicAccess: BlockPublicAccess.BLOCK_ALL,
      removalPolicy: cdk.RemovalPolicy.RETAIN,
      lifecycleRules: [
        {
          noncurrentVersionExpiration: cdk.Duration.days(90),
        },
      ],
    });
    this.bucket = bucket;
    this.deterministicBucketArn = stack.formatArn({
      service: 's3',
      region: '',
      account: '',
      resource: bucketName,
    });

    bucket.addToResourcePolicy(
      new PolicyStatement({
        sid: 'AllowAccountAccess',
        effect: Effect.ALLOW,
        principals: [new AnyPrincipal()],
        actions: ['s3:GetObject', 's3:PutObject', 's3:DeleteObject'],
        resources: [`${bucket.bucketArn}/*`],
        conditions: {
          StringEquals: {
            'aws:PrincipalAccount': stack.account,
          },
        },
      }),
    );

    bucket.addToResourcePolicy(
      new PolicyStatement({
        sid: 'AllowAccountListBucket',
        effect: Effect.ALLOW,
        principals: [new AnyPrincipal()],
        actions: ['s3:ListBucket'],
        resources: [bucket.bucketArn],
        conditions: {
          StringEquals: {
            'aws:PrincipalAccount': stack.account,
          },
        },
      }),
    );

    addCfnGuardSuppression(bucket, 'S3_BUCKET_LOGGING_ENABLED');
  }
}
