// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { App, DefaultStackSynthesizer, Stack } from 'aws-cdk-lib';
import { Template } from 'aws-cdk-lib/assertions';
import { PlaybookPrimaryStack, PlaybookMemberStack } from '../../../lib/sharrplaybook-construct';
import { omitWaitResourceHash } from '../../../test/utils';

function getPrimaryStack(): Stack {
  const app = new App();
  const stack = new PlaybookPrimaryStack(app, 'stack', {
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
    securityStandard: 'PCI',
    securityStandardLongName: 'pci-dss',
    securityStandardVersion: '3.2.1',
  });
  return stack;
}

test('admin stack', () => {
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
    ssmdocs: 'playbooks/NEWPLAYBOOK/ssmdocs',
    remediations: [{ control: 'RDS.6', versionAdded: '2.2.1' }],
    securityStandard: 'NPB',
    securityStandardLongName: 'newplaybook',
    securityStandardVersion: '3.2.1',
    commonScripts: 'playbooks/common',
  });
  return stack;
}

test('member stack', () => {
  const stack = getMemberStack();
  const template = Template.fromStack(stack);

  const templateJSON = template.toJSON();
  omitWaitResourceHash(template, templateJSON);
  expect(templateJSON).toMatchSnapshot();
});
