import { expect as expectCDK, matchTemplate, SynthUtils } from '@aws-cdk/assert';
import * as cdk from '@aws-cdk/core';
import { PlaybookPrimaryStack, PlaybookMemberStack } from '../../../lib/sharrplaybook-construct';

function getPrimaryStack(): cdk.Stack {
  const app = new cdk.App();
  const stack = new PlaybookPrimaryStack(app, 'primaryStack', {
  	description: 'test;',
    solutionId: 'SO0111',
    solutionVersion: 'v1.1.1',
    solutionDistBucket: 'sharrbukkit',
    solutionDistName: 'aws-security-hub-automated-response-and-remediation',
    remediations: [ 
      {"control": 'Example.3'}, {"control":'Example.5'}, {"control":'Example.1'} 
    ],
    securityStandard: 'AFSBP',
    securityStandardLongName: 'aws-foundational-security-best-practices',
    securityStandardVersion: '1.0.0'
  })
  return stack;
}

test('Primary Stack - AFSBP', () => {
  expect(SynthUtils.toCloudFormation(getPrimaryStack())).toMatchSnapshot();
});

function getMemberStack(): cdk.Stack {
  const app = new cdk.App();
  const stack = new PlaybookMemberStack(app, 'memberStack', {
    description: 'test;',
    solutionId: 'SO0111',
    solutionVersion: 'v1.1.1',
    solutionDistBucket: 'sharrbukkit',
    securityStandard: 'AFSBP',
    securityStandardLongName: 'aws-foundational-security-best-practices',
    securityStandardVersion: '1.0.0',
    ssmdocs: 'playbooks/AFSBP/ssmdocs',
    commonScripts: 'playbooks/common',
    remediations: [ { "control": 'EC2.1'}, {"control": 'RDS.1'}, {"control":'Lambda.1'} ]
  })
  return stack;
}

test('Member Stack - AFSBP', () => {
  expect(SynthUtils.toCloudFormation(getMemberStack())).toMatchSnapshot();
});