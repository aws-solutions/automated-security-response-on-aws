// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { App, Aspects, DefaultStackSynthesizer, Stack } from 'aws-cdk-lib';
import { Runtime } from 'aws-cdk-lib/aws-lambda';
import { Template } from 'aws-cdk-lib/assertions';
import { AwsSolutionsChecks } from 'cdk-nag';
import { MemberStack } from './member-stack';
import { AppRegister } from './appregistry/applyAppRegistry';

const description = 'ASR Member Stack';
const solutionId = 'SO9999';
const solutionTMN = 'my-solution-tmn';
const solutionVersion = 'v9.9.9';
const solutionDistBucket = 'sharrbukkit';

function getMemberStack(): Stack {
  const app = new App();
  const appName = 'automated-security-response-on-aws';
  const appregistry = new AppRegister({
    solutionId: 'SO0111',
    solutionName: appName,
    solutionVersion: 'v1.0.0',
    appRegistryApplicationName: appName,
    applicationType: 'AWS-Solutions',
  });
  const stack = new MemberStack(app, 'MemberStack', {
    analyticsReporting: false,
    synthesizer: new DefaultStackSynthesizer({ generateBootstrapVersionRule: false }),
    description,
    solutionId,
    solutionTMN,
    solutionVersion,
    solutionDistBucket,
    runtimePython: Runtime.PYTHON_3_9,
  });
  appregistry.applyAppRegistryToStacks(stack, stack.nestedStacksWithAppRegistry);
  Aspects.of(app).add(new AwsSolutionsChecks({ verbose: true }));
  return stack;
}

describe('member stack', function () {
  const template = Template.fromStack(getMemberStack());

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
          [keyPrefixKeyName]: `${solutionTMN}/${solutionVersion}`,
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
        TemplateURL: getExpectedTemplateURL('aws-sharr-remediations.template'),
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
  });

  it('solution version SSM parameter is present', function () {
    template.hasResourceProperties('AWS::SSM::Parameter', {
      Name: `/Solutions/${solutionId}/member-version`,
      Type: 'String',
      Value: solutionVersion,
    });
  });

  interface Resource {
    [_: string]: any; // eslint-disable-line @typescript-eslint/no-explicit-any
  }

  interface GraphNode {
    readonly logicalId: string;
    dependencies: string[]; // _outgoing_ dependencies, _incoming_ edges
  }

  interface NodeTypes {
    readonly startingNodes: { [_: string]: Resource };
    readonly remainingNodes: { [_: string]: GraphNode };
  }

  function getNodeTypes(gates: { [_: string]: Resource }, stacks: { [_: string]: Resource }): NodeTypes {
    // make a list of all nodes with no incoming edges
    const startingNodes: { [_: string]: Resource } = {};
    const remainingNodes: { [_: string]: GraphNode } = {};
    for (const [logicalId, stack] of Object.entries(stacks)) {
      const node: GraphNode = { logicalId, dependencies: [] };
      remainingNodes[logicalId] = node;
      stack.DependsOn?.forEach(function (dependencyLogicalId: string) {
        // add the dependency if it's a stack
        if (dependencyLogicalId in stacks) {
          node.dependencies.push(dependencyLogicalId);
        }
        // also add all conditional dependencies created through a gate
        if (dependencyLogicalId in gates) {
          const gate = gates[dependencyLogicalId];
          const conditionalDependencies = getConditionalDependencyLogicalIds(gate, stacks);
          node.dependencies.push(...conditionalDependencies);
        }
      });

      // if this node has no incoming edges (outgoing dependencies), it's a candidate starter node
      if (node.dependencies.length === 0) {
        startingNodes[logicalId] = node;
      }
    }

    return { startingNodes, remainingNodes };
  }

  function getConditionalDependencyLogicalIds(gate: Resource, stacks: { [_: string]: Resource }): string[] {
    const result: string[] = [];
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    for (const [_, value] of Object.entries(gate.Metadata)) {
      const metadata = value as any; // eslint-disable-line @typescript-eslint/no-explicit-any
      const conditionalDependencyLogicalId: string = metadata['Fn::If'][1].Ref;
      if (conditionalDependencyLogicalId in stacks) {
        result.push(conditionalDependencyLogicalId);
      }
    }
    return result;
  }

  it('creates stacks serially', function () {
    const stacks = template.findResources('AWS::CloudFormation::Stack');
    const gates = template.findResources('AWS::CloudFormation::WaitConditionHandle');

    const { startingNodes, remainingNodes } = getNodeTypes(gates, stacks);

    // create a deep copy to check edges later
    const allNodes: { [_: string]: GraphNode } = JSON.parse(JSON.stringify(remainingNodes));

    // if stacks are serial, there should be only one starting node
    expect(Object.getOwnPropertyNames(startingNodes)).toHaveLength(1);

    const sortedNodes: GraphNode[] = [];

    // topological sort - Kahn's algorithm
    while (Object.getOwnPropertyNames(startingNodes).length > 0) {
      const logicalId = Object.getOwnPropertyNames(startingNodes)[0];
      delete startingNodes[logicalId];
      const node = remainingNodes[logicalId];
      sortedNodes.push(node);
      delete remainingNodes[logicalId];
      for (const [otherLogicalId, otherNode] of Object.entries(remainingNodes)) {
        // remove this node from other nodes' dependencies
        const index = otherNode.dependencies.indexOf(logicalId);
        if (index > -1) {
          otherNode.dependencies.splice(index, 1);
        }
        // if this node has no incoming edges, add it as a candidate next node
        if (otherNode.dependencies.length === 0) {
          startingNodes[otherLogicalId] = otherNode;
        }
      }
    }

    // no remaining stacks
    expect(Object.getOwnPropertyNames(remainingNodes)).toHaveLength(0);
    // no remaining edges
    sortedNodes.forEach(function (node) {
      expect(node.dependencies).toHaveLength(0);
    });

    // in a serial dependency structure, a node must depend on all nodes before itself
    sortedNodes.forEach(function (node: GraphNode, i: number) {
      // use the deep copy from before, since we removed edges from the graph
      const dependencies = allNodes[node.logicalId].dependencies;
      if (i === 0) {
        expect(dependencies).toHaveLength(0);
      } else {
        for (let j = 0; j < i; ++j) {
          expect(dependencies).toContain(sortedNodes[j].logicalId);
        }
      }
    });
  });
});
