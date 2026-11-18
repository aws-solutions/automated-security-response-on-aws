// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { App, DefaultStackSynthesizer } from 'aws-cdk-lib';
import { Match, Template } from 'aws-cdk-lib/assertions';
import { Runtime } from 'aws-cdk-lib/aws-lambda';
import { MemberRolesStack } from '../lib/member-roles-stack';

function synthesizeMemberRolesTemplate(): Template {
  const stack = new MemberRolesStack(new App(), 'roles', {
    synthesizer: new DefaultStackSynthesizer({ generateBootstrapVersionRule: false }),
    solutionId: 'SO0111',
    solutionVersion: 'v1.1.1',
    solutionDistBucket: 'sharrbukkit',
    solutionTradeMarkName: 'automated-security-response-on-aws',
    runtimePython: Runtime.PYTHON_3_11,
  });
  return Template.fromStack(stack);
}

function logicalIdOf(template: Template, type: string, properties: object): string {
  const ids = Object.keys(template.findResources(type, { Properties: properties }));
  expect(ids).toHaveLength(1);
  return ids[0];
}

describe('Custom Runbook role cleanup in the Member Roles stack', () => {
  const template = synthesizeMemberRolesTemplate();
  const boundaryPolicyId = logicalIdOf(template, 'AWS::IAM::ManagedPolicy', {
    ManagedPolicyName: 'SO0111-ASR-Remediation-Boundary',
  });

  it('passes the role name prefix and boundary ARN, so it is deleted before the boundary policy', () => {
    // The Ref makes the custom resource depend on the policy; CloudFormation deletes dependents first.
    template.hasResourceProperties('Custom::CustomRunbookRoleCleanup', {
      RoleNamePrefix: 'SO0111-Remediate-Custom-',
      PermissionsBoundaryArn: { Ref: boundaryPolicyId },
    });
  });

  it('can only delete tagged ASR Custom Runbook roles', () => {
    const cleanupRole = logicalIdOf(template, 'AWS::IAM::Role', {
      Description: 'Deletes the ASR Custom Runbook remediation roles when the Member Roles stack is deleted',
    });
    const roleArnPattern = {
      'Fn::Join': [
        '',
        ['arn:', { Ref: 'AWS::Partition' }, ':iam::', { Ref: 'AWS::AccountId' }, ':role/SO0111-Remediate-Custom-*'],
      ],
    };
    template.hasResourceProperties('AWS::IAM::Role', {
      Description: Match.stringLikeRegexp('Deletes the ASR Custom Runbook'),
      Policies: [
        {
          PolicyDocument: {
            Statement: Match.arrayWith([
              Match.objectLike({
                Action: ['iam:DeleteRolePolicy', 'iam:DetachRolePolicy', 'iam:DeleteRole'],
                Resource: roleArnPattern,
                Condition: { Null: { 'iam:ResourceTag/aws-solutions:custom-runbook': 'false' } },
              }),
            ]),
          },
        },
      ],
    });
    // The role's permissions are inline, so no separate Policy resource can be deleted before the cleanup runs.
    expect(
      Object.values(template.findResources('AWS::IAM::Policy')).filter((policy) =>
        JSON.stringify(policy.Properties.Roles).includes(cleanupRole),
      ),
    ).toHaveLength(0);
  });

  it('runs the packaged cleanup Lambda from the regional solutions bucket', () => {
    template.hasResourceProperties('AWS::Lambda::Function', {
      Handler: 'custom_runbook_role_cleanup.lambda_handler',
      Runtime: 'python3.11',
      Code: {
        S3Bucket: { 'Fn::Join': ['', ['sharrbukkit-', { Ref: 'AWS::Region' }]] },
        S3Key: Match.stringLikeRegexp('^automated-security-response-on-aws/v1.1.1/lambda/custom_runbook_role_cleanup'),
      },
    });
  });
});
