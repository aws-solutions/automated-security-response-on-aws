// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import * as cdk from 'aws-cdk-lib';
import { OrchLogStack } from '../lib/orchestrator-log-stack';
import { DefaultStackSynthesizer } from 'aws-cdk-lib';
import { Template } from 'aws-cdk-lib/assertions';

function getTestStack(): cdk.Stack {
  const app = new cdk.App();
  const stack = new OrchLogStack(app, 'roles', {
    synthesizer: new DefaultStackSynthesizer({ generateBootstrapVersionRule: false }),
    description: 'test;',
    solutionId: 'SO0111',
    logGroupName: 'TestLogGroup',
  });
  return stack;
}
test('Global Roles Stack', () => {
  expect(Template.fromStack(getTestStack())).toMatchSnapshot();
});
