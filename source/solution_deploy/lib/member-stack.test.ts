// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { App, Aspects, DefaultStackSynthesizer, Stack } from 'aws-cdk-lib';
import { Runtime } from 'aws-cdk-lib/aws-lambda';
import { Template } from 'aws-cdk-lib/assertions';
import { AwsSolutionsChecks } from 'cdk-nag';
import { MemberStack } from './member-stack';

function getMemberStack(): Stack {
  const app = new App();
  const stack = new MemberStack(app, 'MemberStack', {
    analyticsReporting: false,
    synthesizer: new DefaultStackSynthesizer({ generateBootstrapVersionRule: false }),
    description: 'ASR Member Stack',
    solutionId: 'SO0111',
    solutionTMN: 'aws-security-hub-automated-response-and-remediation',
    solutionVersion: 'v1.1.1',
    solutionDistBucket: 'sharrbukkit',
    runtimePython: Runtime.PYTHON_3_9,
  });
  Aspects.of(app).add(new AwsSolutionsChecks({ verbose: true }));
  return stack;
}

describe('Member stack', function () {
  const template = Template.fromStack(getMemberStack());

  it('matches snapshot', function () {
    expect(template).toMatchSnapshot();
  });

  it('has admin account parameter', function () {
    template.hasParameter('SecHubAdminAccount', {
      AllowedPattern: RegExp(/\d{12}/).source,
      Type: 'String',
    });
  });

  it('has log group name parameter', function () {
    template.hasParameter('LogGroupName', {
      Type: 'String',
    });
  });

  it('has parameter for S3 bucket for Redshift audit logging', function () {
    template.hasParameter('CreateS3BucketForRedshiftAuditLogging', {
      AllowedValues: ['yes', 'no'],
      Default: 'no',
      Type: 'String',
    });
  });

  it('has condition for creating S3 bucket for Redshift audit logging', function () {
    template.hasCondition('EnableS3BucketForRedShift4', {
      ['Fn::Equals']: [{ Ref: 'CreateS3BucketForRedshiftAuditLogging' }, 'yes'],
    });
  });

  it('has S3 bucket and policy for Redshift audit logging', function () {
    template.hasResource('AWS::S3::Bucket', {
      Condition: 'EnableS3BucketForRedShift4',
      DeletionPolicy: 'Retain',
      Properties: {
        BucketEncryption: {
          ServerSideEncryptionConfiguration: [
            {
              ServerSideEncryptionByDefault: {
                SSEAlgorithm: 'AES256',
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
      },
      UpdateReplacePolicy: 'Retain',
    });

    template.hasResource('AWS::S3::BucketPolicy', {
      Condition: 'EnableS3BucketForRedShift4',
      DeletionPolicy: 'Retain',
      DependsOn: ['S3BucketForRedShiftAuditLogging652E7355'],
      Properties: {
        Bucket: { Ref: 'S3BucketForRedShiftAuditLogging652E7355' },
        PolicyDocument: {
          Statement: [
            {
              Action: ['s3:GetBucketAcl', 's3:PutObject'],
              Effect: 'Allow',
              Principal: {
                Service: 'redshift.amazonaws.com',
              },
              Resource: [
                {
                  ['Fn::GetAtt']: ['S3BucketForRedShiftAuditLogging652E7355', 'Arn'],
                },
                {
                  ['Fn::Sub']: [
                    'arn:${AWS::Partition}:s3:::${BucketName}/*',
                    {
                      BucketName: {
                        Ref: 'S3BucketForRedShiftAuditLogging652E7355',
                      },
                    },
                  ],
                },
              ],
            },
            {
              Action: 's3:*',
              Condition: {
                Bool: {
                  ['aws:SecureTransport']: 'false',
                },
              },
              Effect: 'Deny',
              Principal: '*',
              Resource: [
                {
                  ['Fn::GetAtt']: ['S3BucketForRedShiftAuditLogging652E7355', 'Arn'],
                },
                {
                  ['Fn::Join']: [
                    '',
                    [
                      {
                        ['Fn::GetAtt']: ['S3BucketForRedShiftAuditLogging652E7355', 'Arn'],
                      },
                      '/*',
                    ],
                  ],
                },
              ],
            },
          ],
        },
      },
      UpdateReplacePolicy: 'Retain',
    });
  });
});
