import { expect as expectCDK, matchTemplate, SynthUtils } from '@aws-cdk/assert';
import * as cdk from '@aws-cdk/core';
import * as Cis from '../lib/cis-stack';

function getTestStack(): cdk.Stack {
  const app = new cdk.App();
  const stack = new Cis.CisStack(app, 'stack', {
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
  process.env.DIST_OUTPUT_BUCKET = 'solutions'
  process.env.DIST_SOLUTION_NAME = 'aws-security-hub-automated-response-and-remediation'
  process.env.DIST_VERSION = 'v1.0.0'
  process.env.SOLUTION_ID='SO0111'
  process.env.SOLUTION_NAME='Security Hub Automated Response and Remdiation'
  expect(SynthUtils.toCloudFormation(getTestStack())).toMatchSnapshot();
});
