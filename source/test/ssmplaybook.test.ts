// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { expect as expectCDK, haveResourceLike, ResourcePart } from '@aws-cdk/assert';
import { App, Aspects, Stack } from 'aws-cdk-lib';
import { Policy, PolicyStatement, Effect } from 'aws-cdk-lib/aws-iam';
import { SsmRole } from '../lib/ssmplaybook';
import { MemberRoleStack } from '../solution_deploy/lib/remediation_runbook-stack';
import { AwsSolutionsChecks } from 'cdk-nag';
import { RunbookFactory } from '../solution_deploy/lib/runbook_factory';

function getSsmPlaybook(): Stack {
  const app = new App();
  const stack = new Stack(app, 'MyTestStack', {
    stackName: 'testStack',
  });
  new RunbookFactory(stack, 'RunbookFactory');
  RunbookFactory.createControlRunbook(stack, 'Playbook', {
    securityStandard: 'SECTEST',
    securityStandardVersion: '1.2.3',
    controlId: 'TEST.1',
    ssmDocPath: 'test/test_data/',
    ssmDocFileName: 'tstest-rds1.yaml',
    solutionVersion: 'v1.1.1',
    solutionDistBucket: 'solutionstest',
    solutionId: 'SO0111',
  });
  Aspects.of(app).add(new AwsSolutionsChecks({ verbose: true }));
  return stack;
}

test('Test SsmPlaybook Generation', () => {
  expectCDK(getSsmPlaybook()).to(
    haveResourceLike(
      'AWS::SSM::Document',
      {
        Content: {
          description: '### Document Name - ASR-SECTEST_1.2.3_TEST.1\n',
          schemaVersion: '0.3',
          assumeRole: '{{ AutomationAssumeRole }}',
          outputs: ['VerifySGRules.Response'],
          parameters: {
            Finding: {
              type: 'StringMap',
              description: 'The input from Step function for TEST1 finding',
            },
            AutomationAssumeRole: {
              type: 'String',
              description:
                '(Optional) The ARN of the role that allows Automation to perform the actions on your behalf.',
              default: '',
            },
          },
        },
        DocumentType: 'Automation',
        Name: 'ASR-SECTEST_1.2.3_TEST.1',
        DocumentFormat: 'YAML',
        UpdateMethod: 'NewVersion',
      },
      ResourcePart.Properties
    )
  );
});

// ---------------------
// SsmRemediationRunbook
// ---------------------
function getSsmRemediationRunbook(): Stack {
  const app = new App();
  const stack = new Stack(app, 'MyTestStack', {
    stackName: 'testStack',
  });
  new MemberRoleStack(app, 'roles', {
    description: 'test;',
    solutionId: 'SO0111',
    solutionVersion: 'v1.1.1',
    solutionDistBucket: 'sharrbukkit',
  });
  new RunbookFactory(stack, 'RunbookFactory');
  RunbookFactory.createRemediationRunbook(stack, 'Playbook', {
    ssmDocName: 'blahblahblah',
    ssmDocPath: 'test/test_data/',
    ssmDocFileName: 'tstest-cis29.yaml',
    solutionVersion: 'v1.1.1',
    solutionDistBucket: 'solutionstest',
    solutionId: 'SO0111',
  });
  return stack;
}

test('Test Shared Remediation Generation', () => {
  expectCDK(getSsmRemediationRunbook()).to(
    haveResourceLike(
      'AWS::SSM::Document',
      {
        Content: {
          description: '### Document Name - ASR-CIS_1.2.0_2.9\n',
          schemaVersion: '0.3',
          assumeRole: '{{ AutomationAssumeRole }}',
          outputs: ['VerifySGRules.Response'],
          parameters: {
            Finding: {
              type: 'StringMap',
              description: 'The input from Step function for 2.9 finding',
            },
            AutomationAssumeRole: {
              type: 'String',
              description:
                '(Optional) The ARN of the role that allows Automation to perform the actions on your behalf.',
              default: '',
            },
          },
        },
        DocumentType: 'Automation',
        Name: 'ASR-blahblahblah',
        DocumentFormat: 'YAML',
        UpdateMethod: 'NewVersion',
      },
      ResourcePart.Properties
    )
  );
});

// ------------------
// SsmRole
// ------------------
function getSsmRemediationRoleCis(): Stack {
  const app = new App();
  const stack = new MemberRoleStack(app, 'MyTestStack', {
    description: 'test-description',
    solutionId: 'SO0111',
    solutionVersion: 'v1.0.0',
    solutionDistBucket: 'test-bucket',
  });
  const inlinePolicy = new Policy(stack, 'Policy');
  const rdsPerms = new PolicyStatement();
  rdsPerms.addActions('rds:ModifyDBSnapshotAttribute');
  rdsPerms.effect = Effect.ALLOW;
  rdsPerms.addResources('*');
  inlinePolicy.addStatements(rdsPerms);
  new SsmRole(stack, 'Role', {
    solutionId: 'SO0111',
    ssmDocName: 'foobar',
    remediationPolicy: inlinePolicy,
    remediationRoleName: 'SHARR-RemediationRoleName',
  });
  return stack;
}

test('Test SsmRole Generation', () => {
  expectCDK(getSsmRemediationRoleCis()).to(
    haveResourceLike(
      'AWS::IAM::Role',
      {
        AssumeRolePolicyDocument: {
          Statement: [
            {
              Action: 'sts:AssumeRole',
              Effect: 'Allow',
              Principal: {
                AWS: {
                  'Fn::Join': [
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
                      ':role/SO0111-SHARR-Orchestrator-Member',
                    ],
                  ],
                },
              },
            },
          ],
          Version: '2012-10-17',
        },
        RoleName: 'SHARR-RemediationRoleName',
      },
      ResourcePart.Properties
    )
  );
});
