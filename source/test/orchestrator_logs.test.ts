// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { SynthUtils } from '@aws-cdk/assert';
import * as cdk from 'aws-cdk-lib';
import { OrchLogStack } from '../solution_deploy/lib/orchestrator-log-stack';
import { AwsSolutionsChecks } from 'cdk-nag';
import { Aspects } from 'aws-cdk-lib';

function getTestStack(): cdk.Stack {
  const app = new cdk.App();
  const stack = new OrchLogStack(app, 'roles', {
    description: 'test;',
    solutionId: 'SO0111',
    logGroupName: 'TestLogGroup',
  });
  Aspects.of(app).add(new AwsSolutionsChecks({ verbose: true }));
  return stack;
}
test('Global Roles Stack', () => {
  expect(SynthUtils.toCloudFormation(getTestStack())).toMatchSnapshot();
});
