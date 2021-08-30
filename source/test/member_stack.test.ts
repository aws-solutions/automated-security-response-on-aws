import { expect as expectCDK, matchTemplate, SynthUtils } from '@aws-cdk/assert';
import * as cdk from '@aws-cdk/core';
import { MemberStack } from '../solution_deploy/lib/sharr_member-stack';

function getCatStack(): cdk.Stack {
  const app = new cdk.App();
  const stack = new MemberStack(app, 'CatalogStack', {
  	description: 'test;',
    solutionId: 'SO0111',
    solutionVersion: 'v1.1.1',
    solutionDistBucket: 'sharrbukkit',
    solutionTMN: 'aws-security-hub-automated-response-and-remediation'
  })
  return stack;
}

test('default stack', () => {
  expect(SynthUtils.toCloudFormation(getCatStack())).toMatchSnapshot();
});
