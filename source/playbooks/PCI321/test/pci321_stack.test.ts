// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { App, DefaultStackSynthesizer, Stack } from 'aws-cdk-lib';
import { Template } from 'aws-cdk-lib/assertions';
import { PlaybookPrimaryStack, PlaybookMemberStack } from '../../../lib/sharrplaybook-construct';

function getTestStack(): Stack {
  const app = new App();
  const stack = new PlaybookPrimaryStack(app, 'stack', {
    synthesizer: new DefaultStackSynthesizer({ generateBootstrapVersionRule: false }),
    description: 'test;',
    solutionId: 'SO0111',
    solutionVersion: 'v1.1.1',
    solutionDistBucket: 'sharrbukkit',
    solutionDistName: 'automated-security-response-on-aws',
    remediations: [{ control: 'PCI.AutoScaling.1' }, { control: 'PCI.EC2.6' }, { control: 'PCI.IAM.8' }],
    securityStandard: 'PCI',
    securityStandardLongName: 'pci-dss',
    securityStandardVersion: '3.2.1',
  });
  return stack;
}

test('default stack', () => {
  expect(Template.fromStack(getTestStack())).toMatchSnapshot();
});

function getMemberStack(): Stack {
  const app = new App();
  const stack = new PlaybookMemberStack(app, 'memberStack', {
    synthesizer: new DefaultStackSynthesizer({ generateBootstrapVersionRule: false }),
    description: 'test;',
    solutionId: 'SO0111',
    solutionVersion: 'v1.1.1',
    solutionDistBucket: 'sharrbukkit',
    securityStandard: 'PCI',
    securityStandardVersion: '3.2.1',
    securityStandardLongName: 'pci-dss',
    ssmdocs: 'playbooks/PCI321/ssmdocs',
    commonScripts: 'playbooks/common',
    remediations: [{ control: 'PCI.AutoScaling.1' }, { control: 'PCI.EC2.6' }, { control: 'PCI.IAM.8' }],
  });
  return stack;
}

test('default stack', () => {
  expect(Template.fromStack(getMemberStack())).toMatchSnapshot();
});
