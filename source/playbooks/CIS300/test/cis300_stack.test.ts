// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { App, DefaultStackSynthesizer, Stack } from 'aws-cdk-lib';
import { Template } from 'aws-cdk-lib/assertions';
import { PlaybookPrimaryStack } from '../../../lib/sharrplaybook-construct';
import { CIS300PlaybookMemberStack } from '../lib/cis300_playbook-construct';
import { omitWaitResourceHash } from '../../../test/utils';

function getPrimaryStack(): Stack {
  const app = new App();
  return new PlaybookPrimaryStack(app, 'primaryStack', {
    synthesizer: new DefaultStackSynthesizer({ generateBootstrapVersionRule: false }),
    description: 'test',
    solutionId: 'SO0111',
    solutionVersion: 'v2.2.0',
    solutionDistBucket: 'sharrbukkit',
    solutionDistName: 'automated-security-response-on-aws',
    remediations: [
      { control: '2.1.4', versionAdded: '2.1.0' },
      { control: '2.1.1', versionAdded: '2.2.0' },
      { control: '1.8', versionAdded: '2.1.1' },
    ],
    securityStandard: 'CIS',
    securityStandardLongName: 'cis-aws-foundations-benchmark',
    securityStandardVersion: '3.0.0',
  });
}

describe('CISv3.0.0 primary stack', () => {
  const stack = getPrimaryStack();
  const template = Template.fromStack(stack);

  test('stack snapshot', () => {
    const templateJSON = template.toJSON();
    omitWaitResourceHash(template, templateJSON);
    expect(templateJSON).toMatchSnapshot();
  });

  test('stack has automatic remediation trigger event rules', () => {
    template.resourceCountIs('AWS::Events::Rule', 3);
  });

  test('stack has remediation parameters', () => {
    template.hasParameter('CIS300214AutoTrigger', {
      Type: 'String',
      Default: 'DISABLED',
      AllowedValues: ['ENABLED', 'DISABLED'],
      Description: 'This will fully enable automated remediation for CIS 3.0.0 2.1.4',
    });
    template.hasParameter('CIS300211AutoTrigger', {
      Type: 'String',
      Default: 'DISABLED',
      AllowedValues: ['ENABLED', 'DISABLED'],
      Description: 'This will fully enable automated remediation for CIS 3.0.0 2.1.1',
    });
    template.hasParameter('CIS30018AutoTrigger', {
      Type: 'String',
      Default: 'DISABLED',
      AllowedValues: ['ENABLED', 'DISABLED'],
      Description: 'This will fully enable automated remediation for CIS 3.0.0 1.8',
    });
  });
});

function getMemberStack(): Stack {
  const app = new App();
  return new CIS300PlaybookMemberStack(app, 'memberStack', {
    synthesizer: new DefaultStackSynthesizer({ generateBootstrapVersionRule: false }),
    description: 'test;',
    solutionId: 'SO0111',
    solutionVersion: 'v2.2.0',
    solutionDistBucket: 'sharrbukkit',
    securityStandard: 'CIS',
    securityStandardVersion: '3.0.0',
    securityStandardLongName: 'cis-aws-foundations-benchmark',
    ssmdocs: 'playbooks/CIS300/ssmdocs',
    commonScripts: 'playbooks/common',
    remediations: [
      { control: '2.1.4', versionAdded: '2.1.0' },
      { control: '2.1.1', versionAdded: '2.2.0' },
      { control: '1.8', versionAdded: '2.1.1' },
    ],
  });
}

describe('CISv3.0.0 member stack', () => {
  const stack = getMemberStack();
  const template = Template.fromStack(stack);

  test('snapshot', () => {
    const templateJSON = template.toJSON();
    omitWaitResourceHash(template, templateJSON);
    expect(templateJSON).toMatchSnapshot();
  });

  test('has remediation documents', () => {
    template.resourceCountIs('AWS::SSM::Document', 3);
  });

  test('has remediation documents', () => {
    template.resourceCountIs('AWS::SSM::Document', 3);
  });
});
