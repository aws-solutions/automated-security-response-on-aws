// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { App, DefaultStackSynthesizer, Stack } from 'aws-cdk-lib';
import { Template } from 'aws-cdk-lib/assertions';
import { PlaybookPrimaryStack, PlaybookMemberStack } from '../../../lib/sharrplaybook-construct';

function getPrimaryStack(): Stack {
  const app = new App();
  const stack = new PlaybookPrimaryStack(app, 'primaryStack', {
    synthesizer: new DefaultStackSynthesizer({ generateBootstrapVersionRule: false }),
    description: 'test;',
    solutionId: 'SO0111',
    solutionVersion: 'v1.1.1',
    solutionDistBucket: 'sharrbukkit',
    solutionDistName: 'automated-security-response-on-aws',
    remediations: [{ control: 'Example.3' }, { control: 'Example.5' }, { control: 'Example.1' }],
    securityStandard: 'AFSBP',
    securityStandardLongName: 'aws-foundational-security-best-practices',
    securityStandardVersion: '1.0.0',
  });
  return stack;
}

test('Primary Stack - AFSBP', () => {
  expect(Template.fromStack(getPrimaryStack())).toMatchSnapshot();
});

function getMemberStack(): Stack {
  const app = new App();
  const stack = new PlaybookMemberStack(app, 'memberStack', {
    synthesizer: new DefaultStackSynthesizer({ generateBootstrapVersionRule: false }),
    description: 'test;',
    solutionId: 'SO0111',
    solutionVersion: 'v1.1.1',
    solutionDistBucket: 'sharrbukkit',
    securityStandard: 'AFSBP',
    securityStandardLongName: 'aws-foundational-security-best-practices',
    securityStandardVersion: '1.0.0',
    ssmdocs: 'playbooks/AFSBP/ssmdocs',
    commonScripts: 'playbooks/common',
    remediations: [{ control: 'EC2.1' }, { control: 'RDS.1' }, { control: 'Lambda.1' }],
  });
  return stack;
}

test('Member Stack - AFSBP', () => {
  expect(Template.fromStack(getMemberStack())).toMatchSnapshot();
});
