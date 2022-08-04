import { SynthUtils } from '@aws-cdk/assert';
import * as cdk from '@aws-cdk/core';
import { StringParameter } from '@aws-cdk/aws-ssm';
import { PlaybookPrimaryStack, PlaybookMemberStack } from '../../../lib/sharrplaybook-construct';

const RESOURCE_PREFIX = 'SO0111'

function getPrimaryStack(): cdk.Stack {
  const app = new cdk.App();
  const stack = new PlaybookPrimaryStack(app, 'primaryStack', {
  	description: 'test;',
    solutionId: 'SO0111',
    solutionVersion: 'v1.1.1',
    solutionDistBucket: 'sharrbukkit',
    solutionDistName: 'aws-security-hub-automated-response-and-remediation',
    remediations: [ {"control":'1.1'}, {"control":'1.2'}, {"control":'1.3'} ],
    securityStandard: 'CIS',
    securityStandardLongName: 'cis-aws-foundations-benchmark',
    securityStandardVersion: '1.2.0'
  })
  return stack;
}

test('default stack', () => {
  expect(SynthUtils.toCloudFormation(getPrimaryStack())).toMatchSnapshot();
});

function getMemberStack(): cdk.Stack {
  const app = new cdk.App();
  const stack = new PlaybookMemberStack(app, 'memberStack', {
    description: 'test;',
    solutionId: 'SO0111',
    solutionVersion: 'v1.1.1',
    solutionDistBucket: 'sharrbukkit',
    securityStandard: 'CIS',
    securityStandardVersion: '1.2.0',
    securityStandardLongName: 'cis-aws-foundations-benchmark',
    ssmdocs: 'playbooks/CIS120/ssmdocs',
    commonScripts: 'playbooks/common',
    remediations: [ {"control":'1.3'}, {"control":'1.5'}, {"control":'2.1'} ]
  })

  new StringParameter(stack, `Remap CIS 4.2`, {
    description: `Remap the CIS 4.2 finding to CIS 4.1 remediation`,
    parameterName: `/Solutions/${RESOURCE_PREFIX}/cis-aws-foundations-benchmark/1.2.0-4.2`,
    stringValue: '4.1'
  });
  return stack;
}

test('default stack', () => {
  expect(SynthUtils.toCloudFormation(getMemberStack())).toMatchSnapshot();
});
