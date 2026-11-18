// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { App } from 'aws-cdk-lib';
import { Match, Template } from 'aws-cdk-lib/assertions';
import { MemberCloudTrailStack } from './cloud-trail';

function getTemplate(): Template {
  const app = new App();
  const stack = new MemberCloudTrailStack(app, 'MemberCloudTrailStack', {});
  return Template.fromStack(stack);
}

/** Reloads the stack module so its module-level config reads the current environment. */
function synthesizeWithFreshConfig(): Template {
  const templates: Template[] = [];
  jest.isolateModules(() => {
    const isolatedModule: typeof import('./cloud-trail') = require('./cloud-trail');
    templates.push(Template.fromStack(new isolatedModule.MemberCloudTrailStack(new App(), 'FreshConfigStack', {})));
  });
  return templates[0];
}

const EVENT_PROCESSOR_ROLE_NAME = { 'Fn::Join': ['', ['SO0111-ASR-EventProcessor-', { Ref: 'AWS::Region' }]] };

describe('member CloudTrail stack', () => {
  it('does not give the S3 trigger role an explicit name', () => {
    const template = getTemplate();

    const roles = Object.values(template.findResources('AWS::IAM::Role'));
    const s3AssumableRoles = roles.filter((role) => {
      const statements = role.Properties?.AssumeRolePolicyDocument?.Statement ?? [];
      return statements.some(
        (statement: { Principal?: { Service?: unknown } }) => statement.Principal?.Service === 's3.amazonaws.com',
      );
    });

    expect(s3AssumableRoles).toHaveLength(1);
    // This stack is nested in the per-region member stack, but an IAM role is
    // account-global. A hardcoded name makes a second regional deployment into the
    // same account fail with "role already exists". Nothing looks this role up by
    // name, so CloudFormation must generate it.
    expect(s3AssumableRoles[0].Properties).not.toHaveProperty('RoleName');
  });

  it('gives the EventProcessor a per-Region role that the hub log writer trust can name', () => {
    // ARRANGE
    const template = getTemplate();

    // ACT
    const eventProcessorRoles = template.findResources('AWS::IAM::Role', {
      Properties: { RoleName: EVENT_PROCESSOR_ROLE_NAME },
    });
    const [eventProcessorRoleId] = Object.keys(eventProcessorRoles);

    // ASSERT
    expect(Object.keys(eventProcessorRoles)).toHaveLength(1);
    expect(eventProcessorRoles[eventProcessorRoleId].Metadata.guard.SuppressedRules).toContain(
      'CFN_NO_EXPLICIT_RESOURCE_NAMES',
    );
    template.hasResourceProperties('AWS::Lambda::Function', {
      FunctionName: 'SO0111-ASR-EventProcessor',
      Role: { 'Fn::GetAtt': [eventProcessorRoleId, 'Arn'] },
      Environment: { Variables: Match.not(Match.objectLike({ LOG_WRITER_EXTERNAL_ID: Match.anyValue() })) },
    });
    template.hasResourceProperties('AWS::IAM::Role', {
      RoleName: EVENT_PROCESSOR_ROLE_NAME,
      ManagedPolicyArns: [
        Match.objectLike({
          'Fn::Join': ['', Match.arrayWith([Match.stringLikeRegexp('AWSLambdaBasicExecutionRole')])],
        }),
      ],
    });
    template.hasResourceProperties('AWS::IAM::Policy', {
      Roles: [{ Ref: eventProcessorRoleId }],
      PolicyDocument: {
        Statement: Match.arrayWith([
          {
            Effect: 'Allow',
            Action: ['sts:AssumeRole', 'sts:SetSourceIdentity'],
            Resource: { Ref: 'LogWriterRoleArn' },
          },
          Match.objectLike({ Action: Match.arrayWith(['s3:GetObject*']) }),
        ]),
      },
    });
  });

  it('keeps the EventProcessor role name free of the DEV- prefix in a pre-prod build', () => {
    // ARRANGE
    process.env.SOLUTION_ID = 'DEV-SO0111';

    try {
      // ACT
      const template = synthesizeWithFreshConfig();

      // ASSERT
      template.hasResourceProperties('AWS::IAM::Role', { RoleName: EVENT_PROCESSOR_ROLE_NAME });
    } finally {
      delete process.env.SOLUTION_ID;
    }
  });
});
