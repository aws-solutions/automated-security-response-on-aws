// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { App, CfnParameter, DefaultStackSynthesizer, Stack } from 'aws-cdk-lib';
import { Match, Template } from 'aws-cdk-lib/assertions';
import { Role, ServicePrincipal } from 'aws-cdk-lib/aws-iam';
import { Key } from 'aws-cdk-lib/aws-kms';
import { IaCTemplatesBucketConstruct } from './iac-templates-bucket';

const solutionId = 'SO0111';

const expectedBucketName = {
  ['Fn::Join']: [
    '',
    ['so0111-asr-iac-templates-', { Ref: 'Namespace' }, '-', { Ref: 'AWS::Region' }, '-', { Ref: 'AWS::AccountId' }],
  ],
};

function getStack(): Stack {
  const app = new App();
  const stack = new Stack(app, 'TestStack', {
    analyticsReporting: false,
    synthesizer: new DefaultStackSynthesizer({ generateBootstrapVersionRule: false }),
  });

  const namespaceParam = new CfnParameter(stack, 'Namespace', { type: 'String', default: 'default' });

  new IaCTemplatesBucketConstruct(stack, 'IaCTemplatesBucket', {
    solutionId,
    namespace: namespaceParam.valueAsString,
    encryptionKey: new Key(stack, 'TestKey'),
  });

  return stack;
}

function findBucketLogicalId(template: Template): string {
  const buckets = template.findResources('AWS::S3::Bucket', {
    Properties: { BucketName: expectedBucketName },
  });
  const ids = Object.keys(buckets);
  expect(ids).toHaveLength(1);
  return ids[0];
}

describe('IaC Templates bucket', function () {
  let template: Template;
  let bucketLogicalId: string;

  beforeAll(() => {
    template = Template.fromStack(getStack());
    bucketLogicalId = findBucketLogicalId(template);
  });

  it('is present with correct configuration', function () {
    template.hasResource('AWS::S3::Bucket', {
      DeletionPolicy: 'Retain',
      Properties: {
        BucketName: expectedBucketName,
        BucketEncryption: {
          ServerSideEncryptionConfiguration: [
            {
              BucketKeyEnabled: true,
              ServerSideEncryptionByDefault: {
                SSEAlgorithm: 'aws:kms',
                KMSMasterKeyID: Match.anyValue(),
              },
            },
          ],
        },
        PublicAccessBlockConfiguration: {
          BlockPublicAcls: true,
          BlockPublicPolicy: true,
          IgnorePublicAcls: true,
          RestrictPublicBuckets: true,
        },
        VersioningConfiguration: {
          Status: 'Enabled',
        },
      },
      UpdateReplacePolicy: 'Retain',
    });
  });

  it('has lifecycle rules with noncurrent version expiration at 90 days', function () {
    template.hasResourceProperties('AWS::S3::Bucket', {
      BucketName: expectedBucketName,
      LifecycleConfiguration: {
        Rules: [
          Match.objectLike({
            NoncurrentVersionExpiration: { NoncurrentDays: 90 },
            Status: 'Enabled',
          }),
        ],
      },
    });
  });

  it('bucket policy enforces SSL and account-scoped access', function () {
    template.hasResourceProperties('AWS::S3::BucketPolicy', {
      Bucket: { Ref: bucketLogicalId },
      PolicyDocument: {
        Statement: Match.arrayWith([
          Match.objectLike({
            Action: 's3:*',
            Condition: { Bool: { 'aws:SecureTransport': 'false' } },
            Effect: 'Deny',
            Principal: { AWS: '*' },
          }),
          Match.objectLike({
            Sid: 'AllowAccountAccess',
            Action: ['s3:GetObject', 's3:PutObject', 's3:DeleteObject'],
            Effect: 'Allow',
            Principal: { AWS: '*' },
            Condition: { StringEquals: { 'aws:PrincipalAccount': { Ref: 'AWS::AccountId' } } },
          }),
          Match.objectLike({
            Sid: 'AllowAccountListBucket',
            Action: 's3:ListBucket',
            Effect: 'Allow',
            Principal: { AWS: '*' },
            Condition: { StringEquals: { 'aws:PrincipalAccount': { Ref: 'AWS::AccountId' } } },
          }),
        ]),
      },
    });
  });

  it('has cfn-guard suppression for S3_BUCKET_LOGGING_ENABLED', function () {
    template.hasResource('AWS::S3::Bucket', {
      Properties: { BucketName: expectedBucketName },
      Metadata: {
        guard: { SuppressedRules: Match.arrayWith(['S3_BUCKET_LOGGING_ENABLED']) },
      },
    });
  });

  it('grantRead produces correct IAM policy statements', function () {
    const app = new App();
    const grantStack = new Stack(app, 'GrantTestStack');

    const construct = new IaCTemplatesBucketConstruct(grantStack, 'TestIaCTemplatesBucket', {
      solutionId,
      namespace: 'testns',
      encryptionKey: new Key(grantStack, 'GrantTestKey'),
    });

    const role = new Role(grantStack, 'TestRole', {
      assumedBy: new ServicePrincipal('lambda.amazonaws.com'),
    });

    construct.bucket.grantRead(role);

    const grantTemplate = Template.fromStack(grantStack);

    grantTemplate.hasResourceProperties('AWS::IAM::Policy', {
      PolicyDocument: {
        Statement: Match.arrayWith([
          Match.objectLike({
            Action: Match.arrayWith(['s3:GetObject*', 's3:GetBucket*', 's3:List*']),
            Effect: 'Allow',
          }),
          // grantRead on a CMK-encrypted bucket also grants decrypt on the key.
          Match.objectLike({
            Action: Match.arrayWith(['kms:Decrypt']),
            Effect: 'Allow',
          }),
        ]),
      },
    });
  });
});
