import { expect as expectCDK, matchTemplate, SynthUtils } from '@aws-cdk/assert';
import * as cdk from '@aws-cdk/core';
import * as afsbp from '../lib/afsbp-primary-stack';

function getTestStack(): cdk.Stack {
  const app = new cdk.App();
  const stack = new afsbp.AfsbpPrimaryStack(app, 'stack', {
  	description: 'test;',
    solutionId: 'SO0111',
    solutionVersion: 'v1.1.1',
    solutionDistBucket: 'sharrbukkit',
    solutionDistName: 'aws-security-hub-automated-response-and-remediation',
    solutionName: 'Security Hub Automated Response and Remediation',
  })
  return stack;
}

test('default stack', () => {
  expect(SynthUtils.toCloudFormation(getTestStack())).toMatchSnapshot();
});