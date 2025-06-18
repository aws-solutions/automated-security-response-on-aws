// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { App, DefaultStackSynthesizer, Stack } from 'aws-cdk-lib';
import { Template } from 'aws-cdk-lib/assertions';
import { PlaybookPrimaryStack, PlaybookMemberStack } from '../../../lib/sharrplaybook-construct';
import { omitWaitResourceHash } from '../../../test/utils';

function getPrimaryStack(): Stack {
  const app = new App();
  const stack = new PlaybookPrimaryStack(app, 'primaryStack', {
    synthesizer: new DefaultStackSynthesizer({ generateBootstrapVersionRule: false }),
    description: 'test;',
    solutionId: 'SO0111',
    solutionVersion: 'v1.1.1',
    solutionDistBucket: 'sharrbukkit',
    solutionDistName: 'automated-security-response-on-aws',
    remediations: [
      { control: 'Example.3', versionAdded: '2.1.0' },
      { control: 'Example.5', versionAdded: '2.2.0' },
      { control: 'Example.1', versionAdded: '2.2.1' },
    ],
    securityStandard: 'AFSBP',
    securityStandardLongName: 'aws-foundational-security-best-practices',
    securityStandardVersion: '1.0.0',
  });
  return stack;
}

test('Primary Stack - AFSBP', () => {
  const stack = getPrimaryStack();
  const template = Template.fromStack(stack);

  const templateJSON = template.toJSON();
  omitWaitResourceHash(template, templateJSON);
  expect(templateJSON).toMatchSnapshot();
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
    remediations: [
      { control: 'EC2.1', versionAdded: '2.1.0' },
      { control: 'RDS.1', versionAdded: '2.2.0' },
      { control: 'Lambda.1', versionAdded: '2.2.1' },
    ],
  });
  return stack;
}

test('Member Stack - AFSBP', () => {
  const stack = getMemberStack();
  const template = Template.fromStack(stack);

  const templateJSON = template.toJSON();
  omitWaitResourceHash(template, templateJSON);
  expect(templateJSON).toMatchSnapshot();
});
