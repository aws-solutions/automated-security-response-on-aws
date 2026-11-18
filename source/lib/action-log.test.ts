// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { App, Stack } from 'aws-cdk-lib';
import { Template } from 'aws-cdk-lib/assertions';
import { ActionLog } from './action-log';
import { actionsOf, PolicyStatementJson } from '../test/iam-policy-documents';

const LOG_GROUP_NAME = '/aws/lambda/SO0111-ASR-CloudTrailEvents';

function getWriterRoleStatements(): {
  trustStatements: PolicyStatementJson[];
  permissionStatements: PolicyStatementJson[];
} {
  const stack = new Stack(new App(), 'ActionLogStack', { env: { account: '111111111111', region: 'us-east-1' } });
  new ActionLog(stack, 'ActionLog', { logGroupName: LOG_GROUP_NAME, resourceNamePrefix: 'SO0111' });
  const template = Template.fromStack(stack);

  const [writerRoleId, writerRole] = Object.entries(
    template.findResources('AWS::IAM::Role', { Properties: { RoleName: 'CrossAccountLogWriterRole' } }),
  )[0];
  const writerPolicies = Object.values(template.findResources('AWS::IAM::Policy')).filter((policy) =>
    JSON.stringify(policy.Properties.Roles).includes(writerRoleId),
  );

  return {
    trustStatements: writerRole.Properties.AssumeRolePolicyDocument.Statement,
    permissionStatements: writerPolicies.flatMap((policy) => policy.Properties.PolicyDocument.Statement),
  };
}

describe('Action Log writer role', () => {
  it('admits only the member EventProcessor role naming its own account as the source identity', () => {
    // ARRANGE
    const { trustStatements } = getWriterRoleStatements();

    // ACT
    const grantedActions = trustStatements.flatMap(actionsOf).sort((left, right) => left.localeCompare(right));

    // ASSERT
    expect(grantedActions).toEqual(['sts:AssumeRole', 'sts:SetSourceIdentity']);
    for (const statement of trustStatements) {
      expect(statement.Condition).toEqual({
        StringEquals: {
          'aws:PrincipalOrgID': expect.anything(),
          'sts:SourceIdentity': '${aws:PrincipalAccount}',
        },
        ArnLike: {
          'aws:PrincipalArn': {
            'Fn::Join': ['', ['arn:', { Ref: 'AWS::Partition' }, ':iam::*:role/SO0111-ASR-EventProcessor-*']],
          },
        },
      });
    }
  });

  it('lets a session write only to log streams prefixed with its source identity', () => {
    // ARRANGE
    const { permissionStatements } = getWriterRoleStatements();

    // ACT
    const resources = permissionStatements.flatMap((statement) =>
      Array.isArray(statement.Resource) ? statement.Resource : [statement.Resource],
    );

    // ASSERT
    expect(permissionStatements.flatMap(actionsOf).sort((left, right) => left.localeCompare(right))).toEqual([
      'logs:CreateLogStream',
      'logs:PutLogEvents',
    ]);
    expect(resources).toEqual([
      {
        'Fn::Join': [
          '',
          [
            'arn:',
            { Ref: 'AWS::Partition' },
            `:logs:us-east-1:111111111111:log-group:${LOG_GROUP_NAME}:log-stream:\${aws:SourceIdentity}-*`,
          ],
        ],
      },
    ]);
  });
});
