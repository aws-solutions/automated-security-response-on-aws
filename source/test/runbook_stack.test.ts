// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { App, Aspects, DefaultStackSynthesizer, Stack } from 'aws-cdk-lib';
import { Template } from 'aws-cdk-lib/assertions';
import { AwsSolutionsChecks } from 'cdk-nag';
import { MemberRoleStack, RemediationRunbookStack } from '../lib/remediation_runbook-stack';

function getRoleTestStack(): MemberRoleStack {
  const app = new App();
  const stack = new MemberRoleStack(app, 'roles', {
    synthesizer: new DefaultStackSynthesizer({ generateBootstrapVersionRule: false }),
    description: 'test;',
    solutionId: 'SO0111',
    solutionVersion: 'v1.1.1',
    solutionDistBucket: 'sharrbukkit',
  });
  return stack;
}
test('Global Roles Stack', () => {
  expect(Template.fromStack(getRoleTestStack())).toMatchSnapshot();
});

function getSsmTestStack(): Stack {
  const app = new App();
  const stack = new RemediationRunbookStack(app, 'stack', {
    synthesizer: new DefaultStackSynthesizer({ generateBootstrapVersionRule: false }),
    description: 'test;',
    solutionId: 'SO0111',
    solutionVersion: 'v1.1.1',
    solutionDistBucket: 'sharrbukkit',
    ssmdocs: 'remediation_runbooks',
    roleStack: getRoleTestStack(),
  });
  Aspects.of(app).add(new AwsSolutionsChecks({ verbose: true }));
  return stack;
}

test('Regional Documents', () => {
  expect(Template.fromStack(getSsmTestStack())).toMatchSnapshot();
});
