// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { App, DefaultStackSynthesizer, Stack } from 'aws-cdk-lib';
import { Match, Template } from 'aws-cdk-lib/assertions';
import { Bucket } from 'aws-cdk-lib/aws-s3';
import { Key } from 'aws-cdk-lib/aws-kms';
import { IaCTemplateSyncConstruct } from './iac-template-sync-construct';

const solutionId = 'SO0111';
const solutionTMN = 'automated-security-response-on-aws';
const solutionVersion = 'v4.0.0';
const namespace = 'test-ns';

function getStack(): Stack {
  const app = new App();
  const stack = new Stack(app, 'TestStack', {
    analyticsReporting: false,
    synthesizer: new DefaultStackSynthesizer({ generateBootstrapVersionRule: false }),
  });

  const sourceCodeBucket = Bucket.fromBucketAttributes(stack, 'SourceBucket', {
    bucketName: 'test-solutions-bucket-us-east-1',
  });

  const customerBucket = new Bucket(stack, 'CustomerBucket', {
    bucketName: 'test-customer-bucket',
  });

  new IaCTemplateSyncConstruct(stack, 'IaCTemplateSyncConstruct', {
    solutionId,
    solutionTMN,
    solutionVersion,
    sourceCodeBucket,
    customerBucket,
    customerBucketEncryptionKey: new Key(stack, 'CustomerBucketKey'),
    namespace,
  });

  return stack;
}

describe('IaCTemplateSyncConstruct', function () {
  let template: Template;

  beforeAll(() => {
    jest.useFakeTimers();
    jest.setSystemTime(new Date('2025-01-01T00:00:00.000Z'));
    template = Template.fromStack(getStack());
  });

  afterAll(() => {
    jest.useRealTimers();
  });

  it('snapshot matches', function () {
    expect(template).toMatchSnapshot();
  });

  describe('GIVEN the IaC template sync IAM policy', function () {
    it('THEN it grants S3 read on the solutions bucket', function () {
      template.hasResourceProperties('AWS::IAM::Policy', {
        PolicyDocument: {
          Statement: Match.arrayWith([
            Match.objectLike({
              Action: 's3:GetObject',
              Resource: Match.objectLike({
                'Fn::Join': Match.arrayWith([
                  Match.arrayWith([Match.stringLikeRegexp('test-solutions-bucket-us-east-1')]),
                ]),
              }),
            }),
          ]),
        },
      });
    });

    it('THEN it grants S3 read/write/delete on the customer bucket', function () {
      template.hasResourceProperties('AWS::IAM::Policy', {
        PolicyDocument: {
          Statement: Match.arrayWith([
            Match.objectLike({
              Action: ['s3:GetObject', 's3:PutObject', 's3:DeleteObject'],
            }),
          ]),
        },
      });
    });

    it('THEN it grants KMS decrypt/generate on the customer bucket key', function () {
      template.hasResourceProperties('AWS::IAM::Policy', {
        PolicyDocument: {
          Statement: Match.arrayWith([
            Match.objectLike({
              Action: ['kms:Decrypt', 'kms:GenerateDataKey'],
              Resource: Match.objectLike({ 'Fn::GetAtt': Match.arrayWith(['Arn']) }),
            }),
          ]),
        },
      });
    });

    it('THEN it grants CloudWatch Logs permissions', function () {
      template.hasResourceProperties('AWS::IAM::Policy', {
        PolicyDocument: {
          Statement: Match.arrayWith([
            Match.objectLike({
              Action: ['logs:CreateLogGroup', 'logs:CreateLogStream', 'logs:PutLogEvents'],
            }),
          ]),
        },
      });
    });

    it('THEN it has cfn_nag W12 suppression', function () {
      template.hasResource('AWS::IAM::Policy', {
        Metadata: {
          cfn_nag: {
            rules_to_suppress: Match.arrayWith([Match.objectLike({ id: 'W12' })]),
          },
        },
      });
    });
  });

  describe('GIVEN the IaC template sync IAM role', function () {
    it('THEN it has cfn_nag W28 suppression', function () {
      template.hasResource('AWS::IAM::Role', {
        Metadata: {
          cfn_nag: {
            rules_to_suppress: Match.arrayWith([Match.objectLike({ id: 'W28' })]),
          },
          guard: {
            SuppressedRules: Match.arrayWith(['IAM_NO_INLINE_POLICY_CHECK']),
          },
        },
      });
    });
  });

  describe('GIVEN the IaC template sync Lambda function', function () {
    it('THEN it uses nodejs24.x runtime', function () {
      template.hasResourceProperties('AWS::Lambda::Function', {
        Runtime: 'nodejs24.x',
      });
    });

    it('THEN it has a 300-second timeout', function () {
      template.hasResourceProperties('AWS::Lambda::Function', {
        Timeout: 300,
      });
    });

    it('THEN it uses the correct handler', function () {
      template.hasResourceProperties('AWS::Lambda::Function', {
        Handler: 'iac-template-sync/iacTemplateSyncHandler.handler',
      });
    });

    it('THEN it has the expected environment variables', function () {
      template.hasResourceProperties('AWS::Lambda::Function', {
        Environment: {
          Variables: Match.objectLike({
            SOLUTION_TRADEMARKEDNAME: solutionTMN,
            POWERTOOLS_SERVICE_NAME: 'iac_template_sync',
            POWERTOOLS_LOG_LEVEL: 'INFO',
          }),
        },
      });
    });

    it('THEN it has cfn_nag W58, W89, W92 suppressions', function () {
      template.hasResource('AWS::Lambda::Function', {
        Metadata: Match.objectLike({
          cfn_nag: {
            rules_to_suppress: Match.arrayWith([
              Match.objectLike({ id: 'W58' }),
              Match.objectLike({ id: 'W89' }),
              Match.objectLike({ id: 'W92' }),
            ]),
          },
        }),
      });
    });

    it('THEN it has cfn-guard LAMBDA_INSIDE_VPC and LAMBDA_CONCURRENCY_CHECK suppressions', function () {
      template.hasResource('AWS::Lambda::Function', {
        Metadata: Match.objectLike({
          guard: {
            SuppressedRules: Match.arrayWith(['LAMBDA_INSIDE_VPC', 'LAMBDA_CONCURRENCY_CHECK']),
          },
        }),
      });
    });
  });

  describe('GIVEN the IaC template sync CustomResource', function () {
    it('THEN it has the correct resource type', function () {
      template.hasResource('Custom::IaCTemplateSync', {});
    });

    it('THEN it passes the expected resource properties', function () {
      template.hasResourceProperties('Custom::IaCTemplateSync', {
        SolutionsBucketName: 'test-solutions-bucket-us-east-1',
        CustomerBucketName: Match.objectLike({ Ref: Match.anyValue() }),
        ManifestKey: `${solutionTMN}/${solutionVersion}/iac-templates/.metadata/manifest.json`,
        SolutionVersion: solutionVersion,
        TemplatePrefix: `${solutionTMN}/${solutionVersion}/iac-templates/`,
      });
    });
  });
});
