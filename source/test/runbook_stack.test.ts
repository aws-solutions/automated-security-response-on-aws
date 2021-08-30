import { expect as expectCDK, matchTemplate, SynthUtils } from '@aws-cdk/assert';
import * as cdk from '@aws-cdk/core';
import { RemediationRunbookStack } from '../solution_deploy/lib/remediation_runbook-stack';

function getTestStack(): cdk.Stack {
  const app = new cdk.App();
  const stack = new RemediationRunbookStack(app, 'stack', {
  	description: 'test;',
    solutionId: 'SO0111',
    solutionVersion: 'v1.1.1',
    solutionDistBucket: 'sharrbukkit',
    ssmdocs: 'remediation_runbooks'
  })
  return stack;
}

test('default stack', () => {
  expect(SynthUtils.toCloudFormation(getTestStack())).toMatchSnapshot();
});