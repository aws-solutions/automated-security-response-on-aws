import { SynthUtils } from '@aws-cdk/assert';
import * as cdk from '@aws-cdk/core';
import { PlaybookPrimaryStack, PlaybookMemberStack } from '../../../lib/sharrplaybook-construct';

function getTestStack(): cdk.Stack {
  const app = new cdk.App();
  const stack = new PlaybookPrimaryStack(app, 'stack', {
    description: 'test;',
    solutionId: 'SO0111',
    solutionVersion: 'v1.1.1',
    solutionDistBucket: 'sharrbukkit',
    solutionDistName: 'aws-security-hub-automated-response-and-remediation',
    remediations: [ {"control":'PCI.AutoScaling.1'}, {"control":'PCI.EC2.6'}, {"control":'PCI.IAM.8'} ],
    securityStandard: 'PCI',
    securityStandardLongName: 'pci-dss',
    securityStandardVersion: '3.2.1'
  })
  return stack;
}

test('default stack', () => {
  expect(SynthUtils.toCloudFormation(getTestStack())).toMatchSnapshot();
});

function getMemberStack(): cdk.Stack {
  const app = new cdk.App();
  const stack = new PlaybookMemberStack(app, 'memberStack', {
    description: 'test;',
    solutionId: 'SO0111',
    solutionVersion: 'v1.1.1',
    solutionDistBucket: 'sharrbukkit',
    securityStandard: 'PCI',
    securityStandardVersion: '3.2.1',
    securityStandardLongName: 'pci-dss',
    ssmdocs: 'playbooks/PCI321/ssmdocs',
    commonScripts: 'playbooks/common',
    remediations: [ {"control":'PCI.AutoScaling.1'}, {"control":'PCI.EC2.6'}, {"control":'PCI.IAM.8'} ]
  })
  return stack;
}

test('default stack', () => {
  expect(SynthUtils.toCloudFormation(getMemberStack())).toMatchSnapshot();
});