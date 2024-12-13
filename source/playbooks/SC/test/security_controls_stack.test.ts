// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { App, DefaultStackSynthesizer, Stack } from 'aws-cdk-lib';
import { Template } from 'aws-cdk-lib/assertions';
import {
  SecurityControlsPlaybookMemberStack,
  SecurityControlsPlaybookPrimaryStack,
} from '../lib/security_controls_playbook-construct';
import { omitWaitResourceHash } from '../../../test/utils';

function getPrimaryStack(): Stack {
  const app = new App();
  const stack = new SecurityControlsPlaybookPrimaryStack(app, 'stack', {
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
    securityStandard: 'SC',
    securityStandardLongName: 'security-control',
    securityStandardVersion: '2.0.0',
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
  const stack = new SecurityControlsPlaybookMemberStack(app, 'memberStack', {
    synthesizer: new DefaultStackSynthesizer({ generateBootstrapVersionRule: false }),
    description: 'test;',
    solutionId: 'SO0111',
    solutionVersion: 'v1.1.1',
    solutionDistBucket: 'sharrbukkit',
    ssmdocs: 'playbooks/NEWPLAYBOOK/ssmdocs',
    remediations: [
      { control: 'AutoScaling.1', versionAdded: '2.1.0' },
      { control: 'CloudTrail.5', versionAdded: '2.2.0' },
      { control: 'Config.1', versionAdded: '2.1.1' },
    ],
    securityStandard: 'PCI',
    securityStandardLongName: 'pci-dss',
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
