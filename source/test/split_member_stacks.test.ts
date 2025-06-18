// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { splitMemberStack } from '../playbooks/split_member_stacks';
import { App } from 'aws-cdk-lib';

const app = new App();

const mockMemberStack = jest.fn(() => {
  return { templateOptions: { templateFormatVersion: undefined } };
});

describe('split member stack', () => {
  it('handles unsplit stacks', () => {
    const result = splitMemberStack({
      scope: app,
      stackClass: mockMemberStack,
      stackLimit: 2,
      remediations: [{ control: '1.3', versionAdded: '2.1.0' }],
      baseStackName: 'MyMemberStack1',
      standardShortName: 'CIS',
      standardVersion: '1.2.0',
      standardLongName: 'cis-aws-foundations-benchmark',
    });

    expect(result.length).toEqual(1);
  });

  it('handles stacks with no limit', () => {
    const result = splitMemberStack({
      scope: app,
      stackClass: mockMemberStack,
      stackLimit: Infinity,
      remediations: [{ control: '1.3', versionAdded: '2.1.0' }],
      baseStackName: 'MyMemberStack2',
      standardShortName: 'CIS',
      standardVersion: '1.2.0',
      standardLongName: 'cis-aws-foundations-benchmark',
    });

    expect(result.length).toEqual(1);
  });

  it('handles stacks with limit', () => {
    const result = splitMemberStack({
      scope: app,
      stackClass: mockMemberStack,
      stackLimit: 1,
      remediations: [
        { control: '1.3', versionAdded: '2.1.0' },
        { control: '1.5', versionAdded: '2.2.0' },
        { control: '2.1', versionAdded: '2.1.1' },
      ],
      baseStackName: 'MyMemberStack3',
      standardShortName: 'CIS',
      standardVersion: '1.2.0',
      standardLongName: 'cis-aws-foundations-benchmark',
    });

    expect(result.length).toEqual(3);
  });
});
