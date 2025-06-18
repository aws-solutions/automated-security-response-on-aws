// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { App, DefaultStackSynthesizer, Stack } from 'aws-cdk-lib';
import { Template } from 'aws-cdk-lib/assertions';
import { PlaybookPrimaryStack } from '../../../lib/sharrplaybook-construct';
import { NIST80053PlaybookMemberStack } from '../lib/NIST80053_playbook-construct';
import { omitWaitResourceHash } from '../../../test/utils';

function getPrimaryStack(): Stack {
  const app = new App();
  const stack = new PlaybookPrimaryStack(app, 'primaryStack', {
    synthesizer: new DefaultStackSynthesizer({ generateBootstrapVersionRule: false }),
    description: 'test;',
    solutionId: 'SO0111',
    solutionVersion: 'v2.1.0',
    solutionDistBucket: 'asrbukkit',
    solutionDistName: 'automated-security-response-on-aws',
    remediations: [
      { control: 'Example.3', versionAdded: '2.1.0' },
      { control: 'Example.5', versionAdded: '2.2.0' },
      { control: 'Example.1', versionAdded: '2.2.1' },
    ],
    securityStandard: 'NIST80053R5',
    securityStandardLongName: 'nist-800-53',
    securityStandardVersion: '5.0.0',
  });
  return stack;
}

test('Admin Stack - NIST', () => {
  const stack = getPrimaryStack();
  const template = Template.fromStack(stack);

  const templateJSON = template.toJSON();
  omitWaitResourceHash(template, templateJSON);
  expect(templateJSON).toMatchSnapshot();
});

function getMemberStack(): Stack {
  const app = new App();
  const stack = new NIST80053PlaybookMemberStack(app, 'memberStack', {
    synthesizer: new DefaultStackSynthesizer({ generateBootstrapVersionRule: false }),
    description: 'test;',
    solutionId: 'SO0111',
    solutionVersion: 'v1.1.1',
    solutionDistBucket: 'asrbukkit',
    securityStandard: 'NIST80053R5',
    securityStandardLongName: 'nist-800-53',
    securityStandardVersion: '5.0.0',
    ssmdocs: 'playbooks/NIST80053/ssmdocs',
    commonScripts: 'playbooks/common',
    remediations: [
      { control: 'EC2.1', versionAdded: '2.1.0' },
      { control: 'RDS.1', versionAdded: '2.2.0' },
      { control: 'Lambda.1', versionAdded: '2.2.1' },
    ],
  });

  return stack;
}

test('Member Stack - NIST', () => {
  const stack = getMemberStack();
  const template = Template.fromStack(stack);

  const templateJSON = template.toJSON();
  omitWaitResourceHash(template, templateJSON);
  expect(templateJSON).toMatchSnapshot();
});
