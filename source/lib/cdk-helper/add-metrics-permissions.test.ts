// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { Stack } from 'aws-cdk-lib';
import { Template } from 'aws-cdk-lib/assertions';
import { Code, Function as LambdaFunction, Runtime } from 'aws-cdk-lib/aws-lambda';
import { addMetricsSsmPermissions } from './add-metrics-permissions';

interface PolicyStatementJson {
  Action: string | string[];
  Resource: unknown;
}

describe('addMetricsSsmPermissions', function () {
  it('grants least-privilege SSM access scoped per parameter', function () {
    // ARRANGE
    const stack = new Stack(undefined, 'TestStack', { env: { account: '111111111111', region: 'us-east-1' } });
    const fn = new LambdaFunction(stack, 'Fn', {
      runtime: Runtime.NODEJS_24_X,
      handler: 'index.handler',
      code: Code.fromInline('exports.handler = async () => {};'),
    });

    // ACT
    addMetricsSsmPermissions(fn, 'SO0111');

    // ASSERT
    const template = Template.fromStack(stack);
    const policies = template.findResources('AWS::IAM::Policy');
    const statements: PolicyStatementJson[] = Object.values(policies).flatMap(
      (policy) => policy.Properties.PolicyDocument.Statement as PolicyStatementJson[],
    );

    const serializeStatementForAction = (action: string): string => {
      const statement = statements.find((candidate) => {
        const actions = Array.isArray(candidate.Action) ? candidate.Action : [candidate.Action];
        return actions.includes(action);
      });
      return JSON.stringify(statement);
    };

    // Read is required on all three parameters.
    const getStatement = serializeStatementForAction('ssm:GetParameter');
    expect(getStatement).toContain('/Solutions/SO0111/version');
    expect(getStatement).toContain('/Solutions/SO0111/metrics_uuid');
    expect(getStatement).toContain('/Solutions/SO0111/anonymous_metrics_uuid');

    // Write is scoped to the current UUID parameter only.
    const putStatement = serializeStatementForAction('ssm:PutParameter');
    expect(putStatement).toContain('/Solutions/SO0111/metrics_uuid');
    expect(putStatement).not.toContain('/Solutions/SO0111/version');
    expect(putStatement).not.toContain('/Solutions/SO0111/anonymous_metrics_uuid');

    // Delete is scoped to the deprecated UUID parameter only.
    const deleteStatement = serializeStatementForAction('ssm:DeleteParameter');
    expect(deleteStatement).toContain('/Solutions/SO0111/anonymous_metrics_uuid');
    expect(deleteStatement).not.toContain('/Solutions/SO0111/version');
    expect(deleteStatement).not.toContain('/Solutions/SO0111/metrics_uuid');
  });
});
