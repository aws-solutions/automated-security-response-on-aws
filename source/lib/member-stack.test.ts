// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { App, DefaultStackSynthesizer, Stack } from 'aws-cdk-lib';
import { Runtime } from 'aws-cdk-lib/aws-lambda';
import { Template } from 'aws-cdk-lib/assertions';
import { MemberStack } from './member-stack';
import { SC_REMEDIATIONS } from '../playbooks/SC/lib/sc_remediations';
import { NIST80053_REMEDIATIONS } from '../playbooks/NIST80053/lib/nist80053_remediations';
import { AFSBP_REMEDIATIONS } from '../playbooks/AFSBP/lib/afsbp_remediations';
import { getConfig } from './config/cdk-config';

const config = getConfig();
const SC_MEMBER_STACK_LIMIT = config.memberStackLimits.sc;
const NIST_MEMBER_STACK_LIMIT = config.memberStackLimits.nist;
const AFSBP_MEMBER_STACK_LIMIT = config.memberStackLimits.afsbp;
const description = 'ASR Member Stack';
const solutionId = 'SO9999';
const solutionTradeMarkName = 'my-solution-tmn';
const solutionVersion = 'v9.9.9';
const solutionDistBucket = 'sharrbukkit';

const memberStackLimitsRecord: Record<string, number> = {
  SC: SC_MEMBER_STACK_LIMIT,
  NIST80053: NIST_MEMBER_STACK_LIMIT,
  AFSBP: AFSBP_MEMBER_STACK_LIMIT,
};

const totalRemediationsRecord: Record<string, number> = {
  SC: SC_REMEDIATIONS.length,
  NIST80053: NIST80053_REMEDIATIONS.length,
  AFSBP: AFSBP_REMEDIATIONS.length,
};

function getMemberStack(): Stack {
  const app = new App();
  const stack = new MemberStack(app, 'MemberStack', {
    analyticsReporting: false,
    synthesizer: new DefaultStackSynthesizer({ generateBootstrapVersionRule: false }),
    description,
    solutionId,
    solutionTradeMarkName,
    solutionVersion,
    solutionDistBucket,
    runtimePython: Runtime.PYTHON_3_11,
    SNSTopicName: 'ASR_Topic',
    cloudTrailLogGroupName: 'SO0111-ASR-CloudTrailEvents',
  });
  return stack;
}

describe('member stack', function () {
  let template: Template;
  beforeAll(() => {
    jest.useFakeTimers();
    jest.setSystemTime(new Date('2025-01-01T00:00:00.000Z'));
    template = Template.fromStack(getMemberStack());
  });

  afterAll(() => {
    jest.useRealTimers();
  });

  it('snapshot matches', function () {
    expect(template).toMatchSnapshot();
  });

  it('description is present', function () {
    expect(template.toJSON().Description).toEqual(description);
  });

  it('admin account template parameter is present', function () {
    template.hasParameter('SecHubAdminAccount', {});
  });

  describe('log group name', function () {
    const templateParameterName = 'LogGroupName';

    it('template parameter is present', function () {
      template.hasParameter(templateParameterName, {
        Type: 'String',
      });
    });

    it('SSM parameter is present', function () {
      template.hasResourceProperties('AWS::SSM::Parameter', {
        Name: `/Solutions/${solutionId}/Metrics_LogGroupName`,
        Type: 'String',
        Value: { Ref: templateParameterName },
      });
    });
  });

  describe('Redshift audit logging bucket', function () {
    const templateParameterName = 'CreateS3BucketForRedshiftAuditLogging';
    const conditionName = 'EnableS3BucketForRedShift4';
    const bucketLogicalId = 'S3BucketForRedShiftAuditLogging652E7355';

    it('template parameter is present', function () {
      template.hasParameter(templateParameterName, {
        AllowedValues: ['yes', 'no'],
        Default: 'no',
        Type: 'String',
      });
    });

    it('condition is present', function () {
      template.hasCondition(conditionName, {
        ['Fn::Equals']: [{ Ref: templateParameterName }, 'yes'],
      });
    });

    it('is present', function () {
      template.hasResource('AWS::S3::Bucket', {
        Condition: conditionName,
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
    });

    it('policy is present', function () {
      template.hasResource('AWS::S3::BucketPolicy', {
        Condition: conditionName,
        DeletionPolicy: 'Retain',
        DependsOn: [bucketLogicalId],
        Properties: {
          Bucket: { Ref: bucketLogicalId },
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
                    ['Fn::GetAtt']: [bucketLogicalId, 'Arn'],
                  },
                  {
                    ['Fn::Sub']: [
                      'arn:${AWS::Partition}:s3:::${BucketName}/*',
                      {
                        BucketName: {
                          Ref: bucketLogicalId,
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
                    ['Fn::GetAtt']: [bucketLogicalId, 'Arn'],
                  },
                  {
                    ['Fn::Join']: [
                      '',
                      [
                        {
                          ['Fn::GetAtt']: [bucketLogicalId, 'Arn'],
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

    it('encryption key alias SSM parameter is present', function () {
      template.hasResourceProperties('AWS::SSM::Parameter', {
        Name: `/Solutions/${solutionId}/afsbp/1.0.0/S3.4/KmsKeyAlias`,
        Type: 'String',
        Value: 'default-s3-encryption',
      });
    });
  });

  describe('Remediation Configuration bucket', function () {
    const bucketLogicalId = 'RemediationConfigurationBucketF5FA3D12';

    it('is present with correct configuration', function () {
      template.hasResource('AWS::S3::Bucket', {
        DeletionPolicy: 'Retain',
        Properties: {
          BucketName: {
            ['Fn::Join']: ['', ['so0111-asr-remediation-', { Ref: 'AWS::Region' }, '-', { Ref: 'AWS::AccountId' }]],
          },
          BucketEncryption: {
            ServerSideEncryptionConfiguration: [
              {
                ServerSideEncryptionByDefault: {
                  SSEAlgorithm: 'AES256',
                },
              },
            ],
          },
          LifecycleConfiguration: {
            Rules: [
              {
                ExpirationInDays: 90,
                Id: 'GuardDutyBackupRetention',
                Prefix: 'guardduty-backups/',
                Status: 'Enabled',
              },
              {
                ExpirationInDays: 7,
                Id: 'InstallOverrideListExpiration',
                Prefix: 'install-overrides/',
                Status: 'Enabled',
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

    it('bucket policy enforces SSL and grants EC2 read access', function () {
      const accountPrincipalArn = {
        ['Fn::Join']: ['', ['arn:', { Ref: 'AWS::Partition' }, ':iam::', { Ref: 'AWS::AccountId' }, ':root']],
      };

      template.hasResourceProperties('AWS::S3::BucketPolicy', {
        Bucket: { Ref: bucketLogicalId },
        PolicyDocument: {
          Statement: [
            {
              Action: 's3:*',
              Condition: {
                Bool: { 'aws:SecureTransport': 'false' },
              },
              Effect: 'Deny',
              Principal: { AWS: '*' },
              Resource: [
                { ['Fn::GetAtt']: [bucketLogicalId, 'Arn'] },
                {
                  ['Fn::Join']: ['', [{ ['Fn::GetAtt']: [bucketLogicalId, 'Arn'] }, '/*']],
                },
              ],
            },
            {
              Sid: 'AllowEC2ReadForPatching',
              Action: 's3:GetObject',
              Effect: 'Allow',
              Principal: { AWS: accountPrincipalArn },
              Resource: [
                {
                  ['Fn::Join']: ['', [{ ['Fn::GetAtt']: [bucketLogicalId, 'Arn'] }, '/install-overrides/*']],
                },
                {
                  ['Fn::Join']: ['', [{ ['Fn::GetAtt']: [bucketLogicalId, 'Arn'] }, '/baseline-overrides/*']],
                },
              ],
              Condition: {
                StringEquals: {
                  'aws:PrincipalAccount': { Ref: 'AWS::AccountId' },
                },
              },
            },
            {
              Sid: 'AllowListBucket',
              Action: 's3:ListBucket',
              Effect: 'Allow',
              Principal: { AWS: accountPrincipalArn },
              Resource: { ['Fn::GetAtt']: [bucketLogicalId, 'Arn'] },
              Condition: {
                StringLike: {
                  's3:prefix': ['install-overrides/*', 'baseline-overrides/*'],
                },
              },
            },
          ],
        },
      });
    });

    it('SSM parameter for bucket name is present', function () {
      template.hasResourceProperties('AWS::SSM::Parameter', {
        Name: `/Solutions/${solutionId}/RemediationConfigurationBucket`,
        Type: 'String',
        Value: {
          Ref: bucketLogicalId,
        },
      });
    });

    it('remediation config bucket-access managed policy is present and scoped to the bucket', function () {
      template.hasResourceProperties('AWS::IAM::ManagedPolicy', {
        ManagedPolicyName: 'ASR-RemediationConfigBucketAccess',
        PolicyDocument: {
          Statement: [
            {
              Action: 's3:GetObject',
              Effect: 'Allow',
              Resource: [
                {
                  ['Fn::Join']: ['', [{ ['Fn::GetAtt']: [bucketLogicalId, 'Arn'] }, '/install-overrides/*']],
                },
                {
                  ['Fn::Join']: ['', [{ ['Fn::GetAtt']: [bucketLogicalId, 'Arn'] }, '/baseline-overrides/*']],
                },
              ],
            },
            {
              Action: 's3:ListBucket',
              Effect: 'Allow',
              Resource: { ['Fn::GetAtt']: [bucketLogicalId, 'Arn'] },
            },
          ],
        },
      });
    });

    it('baseline configuration Lambda function is present', function () {
      template.hasResourceProperties('AWS::Lambda::Function', {
        Handler: 'baseline-configuration/baselineConfigurationHandler.handler',
        Runtime: 'nodejs22.x',
        Description: 'Uploads Windows security baseline configuration to the Remediation Configuration bucket',
        Timeout: 300,
      });
    });

    it('baseline configuration Lambda role has S3 PutObject permission', function () {
      template.hasResourceProperties('AWS::IAM::Role', {
        AssumeRolePolicyDocument: {
          Statement: [
            {
              Action: 'sts:AssumeRole',
              Effect: 'Allow',
              Principal: { Service: 'lambda.amazonaws.com' },
            },
          ],
        },
        Policies: [
          {
            PolicyName: 'BaselineConfigPolicy',
            PolicyDocument: {
              Statement: [
                {
                  Action: 's3:PutObject',
                  Effect: 'Allow',
                  Resource: {
                    ['Fn::Join']: ['', [{ ['Fn::GetAtt']: [bucketLogicalId, 'Arn'] }, '/baseline-overrides/*']],
                  },
                },
                {
                  Action: ['logs:CreateLogGroup', 'logs:CreateLogStream', 'logs:PutLogEvents'],
                  Effect: 'Allow',
                  Resource: '*',
                },
              ],
            },
          },
        ],
      });
    });

    it('baseline configuration custom resource is present with bucket name', function () {
      template.hasResourceProperties('Custom::BaselineConfiguration', {
        BucketName: { Ref: bucketLogicalId },
      });
    });
  });

  describe('remediation key', function () {
    const keyLogicalId = 'SHARRRemediationKeyE744743D';

    it('is present', function () {
      template.hasResource('AWS::KMS::Key', {
        DeletionPolicy: 'Retain',
        Properties: {
          EnableKeyRotation: true,
          KeyPolicy: {
            Statement: [
              {
                Action: [
                  'kms:GenerateDataKey',
                  'kms:GenerateDataKeyPair',
                  'kms:GenerateDataKeyPairWithoutPlaintext',
                  'kms:GenerateDataKeyWithoutPlaintext',
                  'kms:Decrypt',
                  'kms:Encrypt',
                  'kms:ReEncryptFrom',
                  'kms:ReEncryptTo',
                  'kms:DescribeKey',
                  'kms:DescribeCustomKeyStores',
                ],
                Effect: 'Allow',
                Principal: {
                  Service: [
                    'sns.amazonaws.com',
                    's3.amazonaws.com',
                    {
                      ['Fn::Join']: [
                        '',
                        [
                          'logs.',
                          {
                            Ref: 'AWS::URLSuffix',
                          },
                        ],
                      ],
                    },
                    {
                      ['Fn::Join']: [
                        '',
                        [
                          'logs.',
                          {
                            Ref: 'AWS::Region',
                          },
                          '.',
                          {
                            Ref: 'AWS::URLSuffix',
                          },
                        ],
                      ],
                    },
                    {
                      ['Fn::Join']: [
                        '',
                        [
                          'cloudtrail.',
                          {
                            Ref: 'AWS::URLSuffix',
                          },
                        ],
                      ],
                    },
                    'cloudwatch.amazonaws.com',
                  ],
                },
                Resource: '*',
              },
              {
                Action: 'kms:*',
                Effect: 'Allow',
                Principal: {
                  AWS: {
                    ['Fn::Join']: [
                      '',
                      [
                        'arn:',
                        {
                          Ref: 'AWS::Partition',
                        },
                        ':iam::',
                        {
                          Ref: 'AWS::AccountId',
                        },
                        ':root',
                      ],
                    ],
                  },
                },
                Resource: '*',
              },
            ],
          },
        },
        UpdateReplacePolicy: 'Retain',
      });
    });

    it('alias is present', function () {
      template.hasResourceProperties('AWS::KMS::Alias', {
        AliasName: `alias/${solutionId}-SHARR-Remediation-Key`,
        TargetKeyId: { ['Fn::GetAtt']: [keyLogicalId, 'Arn'] },
      });
    });

    it('alias SSM parameter is present', function () {
      template.hasResourceProperties('AWS::SSM::Parameter', {
        Name: `/Solutions/${solutionId}/CMK_REMEDIATION_ARN`,
        Type: 'String',
        Value: { ['Fn::GetAtt']: [keyLogicalId, 'Arn'] },
      });
    });
  });

  describe('nested stack', function () {
    const mappingName = 'NestedStackFactorySourceCodeA11A36A7';
    const mappingKeyName = 'General';
    const keyPrefixKeyName = 'KeyPrefix';
    const bucketKeyName = 'S3Bucket';

    it('source code mapping is present', function () {
      template.hasMapping(mappingName, {
        [mappingKeyName]: {
          [keyPrefixKeyName]: `${solutionTradeMarkName}/${solutionVersion}`,
          [bucketKeyName]: solutionDistBucket,
        },
      });
    });

    function getExpectedTemplateURL(templatePath: string) {
      return {
        ['Fn::Join']: [
          '',
          [
            'https://',
            {
              ['Fn::FindInMap']: [mappingName, mappingKeyName, bucketKeyName],
            },
            `-reference.s3.amazonaws.com/`,
            {
              ['Fn::FindInMap']: [mappingName, mappingKeyName, keyPrefixKeyName],
            },
            `/${templatePath}`,
          ],
        ],
      };
    }

    it('for runbooks is present', function () {
      template.hasResourceProperties('AWS::CloudFormation::Stack', {
        TemplateURL: getExpectedTemplateURL('automated-security-response-remediation-runbooks.template'),
      });
    });

    const expectedPlaybooks = ['AFSBP', 'CIS120', 'CIS140', 'PCI321', 'SC'];

    const expectedTemplateParameterProperties = {
      AllowedValues: ['yes', 'no'],
      Type: 'String',
    };

    expectedPlaybooks.forEach(function (playbook: string) {
      describe(`for playbook ${playbook}`, function () {
        const templateParameterName = `Load${playbook}MemberStack`;
        const conditionName = `load${playbook}Cond`;

        it('template parameter is present', function () {
          template.hasParameter(templateParameterName, expectedTemplateParameterProperties);
        });

        it('condition is present', function () {
          template.hasCondition(conditionName, {
            ['Fn::Equals']: [{ Ref: templateParameterName }, 'yes'],
          });
        });

        it('is present', function () {
          template.hasResource('AWS::CloudFormation::Stack', {
            Condition: conditionName,
            Properties: {
              Parameters: {
                SecHubAdminAccount: { Ref: 'SecHubAdminAccount' },
              },
              TemplateURL: getExpectedTemplateURL(`playbooks/${playbook}MemberStack.template`),
            },
          });
        });
      });
    });

    expectedPlaybooks.forEach(function (playbook: string) {
      describe('for split member stacks', function () {
        if (memberStackLimitsRecord[playbook]) {
          const numDivisions = Math.ceil(totalRemediationsRecord[playbook] / memberStackLimitsRecord[playbook]);
          for (let stackIndex = 1; stackIndex < numDivisions; stackIndex++) {
            const templateParameterName = 'LoadSCMemberStack';
            const conditionName = `loadSC${stackIndex}Cond`;

            it('has a template parameter', function () {
              template.hasParameter(templateParameterName, expectedTemplateParameterProperties);
            });

            it('has a condition', function () {
              template.hasCondition(conditionName, {
                ['Fn::Equals']: [{ Ref: templateParameterName }, 'yes'],
              });
            });

            it('is present', function () {
              template.hasResource('AWS::CloudFormation::Stack', {
                Condition: conditionName,
                Properties: {
                  Parameters: {
                    SecHubAdminAccount: { Ref: 'SecHubAdminAccount' },
                  },
                  TemplateURL: getExpectedTemplateURL(`playbooks/SCMemberStack${stackIndex}.template`),
                },
              });
            });
          }
        }
      });
    });
  });

  it('solution version SSM parameter is present', function () {
    template.hasResourceProperties('AWS::SSM::Parameter', {
      Name: `/Solutions/${solutionId}/member-version`,
      Type: 'String',
      Value: solutionVersion,
    });
  });
});
