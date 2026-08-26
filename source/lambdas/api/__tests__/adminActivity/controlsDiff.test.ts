// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { SecurityControl } from '@asr/data-models';
import { computeRemediationToggle } from '../../adminActivity/controlsDiff';

function control(controlId: string, automatedRemediationEnabled: boolean): SecurityControl {
  return {
    controlId,
    description: `Description for ${controlId}`,
    automatedRemediationEnabled,
    filters: [],
    filterMode: 'include',
    version: 1,
    lastModified: '2024-01-01T00:00:00Z',
    modifiedBy: 'admin',
  };
}

describe('computeRemediationToggle', () => {
  it('grades a disable as CONTROL_REMEDIATION_SET', () => {
    // ARRANGE
    const successfulControls = [control('S3.1', false)];
    const previous = new Map([['S3.1', true]]);

    // ACT
    const result = computeRemediationToggle(successfulControls, previous);

    // ASSERT
    expect(result).toEqual({ action: 'CONTROL_REMEDIATION_SET', affectedControlCount: 1 });
  });

  it('grades an enable as CONTROL_REMEDIATION_ENABLED', () => {
    // ARRANGE
    const successfulControls = [control('S3.1', true)];
    const previous = new Map([['S3.1', false]]);

    // ACT
    const result = computeRemediationToggle(successfulControls, previous);

    // ASSERT
    expect(result).toEqual({ action: 'CONTROL_REMEDIATION_ENABLED', affectedControlCount: 1 });
  });

  it('returns undefined when no control changed its remediation state', () => {
    // ARRANGE
    const successfulControls = [control('S3.1', false), control('EC2.6', true)];
    const previous = new Map([
      ['S3.1', false],
      ['EC2.6', true],
    ]);

    // ACT
    const result = computeRemediationToggle(successfulControls, previous);

    // ASSERT
    expect(result).toBeUndefined();
  });

  it('grades the set as a disable when both enables and disables occur, counting only toggled controls', () => {
    // ARRANGE
    const successfulControls = [control('S3.1', false), control('EC2.6', true), control('IAM.1', true)];
    const previous = new Map([
      ['S3.1', true], // disabled
      ['EC2.6', false], // enabled
      ['IAM.1', true], // unchanged
    ]);

    // ACT
    const result = computeRemediationToggle(successfulControls, previous);

    // ASSERT
    expect(result).toEqual({ action: 'CONTROL_REMEDIATION_SET', affectedControlCount: 2 });
  });
});
