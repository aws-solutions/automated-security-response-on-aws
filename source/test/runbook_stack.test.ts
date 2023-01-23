// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { SynthUtils } from '@aws-cdk/assert';
import * as cdk from 'aws-cdk-lib';
import { MemberRoleStack, RemediationRunbookStack } from '../solution_deploy/lib/remediation_runbook-stack';
import { AwsSolutionsChecks } from 'cdk-nag';
import { Aspects } from 'aws-cdk-lib';

function getRoleTestStack(): MemberRoleStack {
  const app = new cdk.App();
  const stack = new MemberRoleStack(app, 'roles', {
    description: 'test;',
    solutionId: 'SO0111',
    solutionVersion: 'v1.1.1',
    solutionDistBucket: 'sharrbukkit',
  });
  return stack;
}
test('Global Roles Stack', () => {
  expect(SynthUtils.toCloudFormation(getRoleTestStack())).toMatchSnapshot();
});

function getSsmTestStack(): cdk.Stack {
  const app = new cdk.App();
  const stack = new RemediationRunbookStack(app, 'stack', {
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
  expect(SynthUtils.toCloudFormation(getSsmTestStack())).toMatchSnapshot();
});
