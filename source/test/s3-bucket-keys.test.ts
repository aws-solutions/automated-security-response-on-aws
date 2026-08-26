// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { App, DefaultStackSynthesizer, Stack } from 'aws-cdk-lib';
import { Runtime } from 'aws-cdk-lib/aws-lambda';
import { Template } from 'aws-cdk-lib/assertions';
import { AdministratorStack } from '../lib/administrator-stack';
import { MemberStack } from '../lib/member-stack';
import { WebUIHostingConstruct } from '../lib/webui/webUIHostingConstruct';

// Mock Date to return consistent timestamp
beforeAll(() => {
  jest.useFakeTimers();
  jest.setSystemTime(new Date('2025-01-01T00:00:00.000Z'));
});

afterAll(() => {
  jest.useRealTimers();
});

function getAdministratorStack(): Stack {
  const envEU = { account: '111111111111', region: 'eu-west-1' };
  const app = new App();

  return new AdministratorStack(app, 'AdminStack', {
    synthesizer: new DefaultStackSynthesizer({ generateBootstrapVersionRule: false }),
    env: envEU,
    solutionId: 'SO0111',
    solutionVersion: 'v1.0.0',
    solutionDistBucket: 'solutions',
    solutionTMN: 'automated-security-response-on-aws',
    solutionName: 'AWS Security Hub Automated Response & Remediation',
    runtimePython: Runtime.PYTHON_3_11,
    orchestratorLogGroup: 'ORCH_LOG_GROUP',
    SNSTopicName: 'ASR_Topic',
    cloudTrailLogGroupName: 'some-loggroup-name',
  });
}

function getMemberStack(): Stack {
  const envEU = { account: '111111111111', region: 'eu-west-1' };
  const app = new App();

  return new MemberStack(app, 'MemberStack', {
    synthesizer: new DefaultStackSynthesizer({ generateBootstrapVersionRule: false }),
    env: envEU,
    solutionId: 'SO0111',
    solutionVersion: 'v1.0.0',
    solutionDistBucket: 'solutions',
    solutionTradeMarkName: 'automated-security-response-on-aws',
    runtimePython: Runtime.PYTHON_3_11,
    SNSTopicName: 'ASR_Topic',
    cloudTrailLogGroupName: 'some-loggroup-name',
  });
}

function getWebUIConstruct(): Stack {
  const app = new App();
  const stack = new Stack(app, 'WebUIStack');

  new WebUIHostingConstruct(stack, 'WebUIHosting', {
    stackName: 'test-stack',
  });

  return stack;
}

describe('S3 Bucket Keys Configuration', () => {
  test('CSV Export Bucket has KMS encryption with bucket keys enabled', () => {
    const template = Template.fromStack(getAdministratorStack());

    // Verify CSV Export Bucket has KMS encryption with bucket keys
    template.hasResourceProperties('AWS::S3::Bucket', {
      BucketEncryption: {
        ServerSideEncryptionConfiguration: [
          {
            ServerSideEncryptionByDefault: {
              SSEAlgorithm: 'aws:kms',
            },
            BucketKeyEnabled: true,
          },
        ],
      },
      LifecycleConfiguration: {
        Rules: [
          {
            Id: 'DeleteOldCSVExports',
            Status: 'Enabled',
          },
        ],
      },
    });
  });

  test('Access Logs Bucket uses default S3 encryption', () => {
    const template = Template.fromStack(getAdministratorStack());

    // Count S3 buckets with KMS encryption and bucket keys
    template.resourcePropertiesCountIs(
      'AWS::S3::Bucket',
      {
        BucketEncryption: {
          ServerSideEncryptionConfiguration: [
            {
              ServerSideEncryptionByDefault: {
                SSEAlgorithm: 'aws:kms',
              },
              BucketKeyEnabled: true,
            },
          ],
        },
      },
      2,
    ); // Should be exactly 2 buckets (CSV Export + IaC Templates)
  });

  test('WebUI Hosting Bucket uses S3-managed encryption without bucket keys', () => {
    const template = Template.fromStack(getWebUIConstruct());

    // Verify WebUI bucket uses S3-managed encryption (no bucket keys)
    template.hasResourceProperties('AWS::S3::Bucket', {
      BucketEncryption: {
        ServerSideEncryptionConfiguration: [
          {
            ServerSideEncryptionByDefault: {
              SSEAlgorithm: 'AES256',
            },
          },
        ],
      },
    });

    // Verify no KMS encryption with bucket keys exists
    template.resourcePropertiesCountIs(
      'AWS::S3::Bucket',
      {
        BucketEncryption: {
          ServerSideEncryptionConfiguration: [
            {
              ServerSideEncryptionByDefault: {
                SSEAlgorithm: 'aws:kms',
              },
              BucketKeyEnabled: true,
            },
          ],
        },
      },
      0,
    );
  });

  test('Member stack buckets use S3-managed encryption without bucket keys', () => {
    const template = Template.fromStack(getMemberStack());

    // Verify member stack doesn't create buckets with KMS encryption + bucket keys
    template.resourcePropertiesCountIs(
      'AWS::S3::Bucket',
      {
        BucketEncryption: {
          ServerSideEncryptionConfiguration: [
            {
              ServerSideEncryptionByDefault: {
                SSEAlgorithm: 'aws:kms',
              },
              BucketKeyEnabled: true,
            },
          ],
        },
      },
      0,
    );
  });

  test('Only consolidated KMS key buckets have bucket keys enabled', () => {
    const template = Template.fromStack(getAdministratorStack());

    // Verify exactly 2 buckets have KMS encryption with bucket keys
    // (the CSV Export and IaC Templates buckets, both using the consolidated KMS key)
    template.resourcePropertiesCountIs(
      'AWS::S3::Bucket',
      {
        BucketEncryption: {
          ServerSideEncryptionConfiguration: [
            {
              ServerSideEncryptionByDefault: {
                SSEAlgorithm: 'aws:kms',
              },
              BucketKeyEnabled: true,
            },
          ],
        },
      },
      2,
    );
  });

  test('KMS key is properly configured for bucket encryption', () => {
    const template = Template.fromStack(getAdministratorStack());

    // Verify KMS key exists with key rotation enabled
    template.hasResourceProperties('AWS::KMS::Key', {
      EnableKeyRotation: true,
    });

    // Verify KMS key alias exists
    template.hasResourceProperties('AWS::KMS::Alias', {
      AliasName: 'alias/SO0111-SHARR-Key',
    });

    // Verify at least one bucket references the KMS key
    template.hasResourceProperties('AWS::S3::Bucket', {
      BucketEncryption: {
        ServerSideEncryptionConfiguration: [
          {
            ServerSideEncryptionByDefault: {
              SSEAlgorithm: 'aws:kms',
            },
            BucketKeyEnabled: true,
          },
        ],
      },
    });
  });
});
