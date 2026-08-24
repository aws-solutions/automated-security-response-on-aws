// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { SeverityFilter } from '@asr/data-models';
import { passesControlFilter, passesSeverityFilter } from '../notificationFilters';

describe('passesSeverityFilter', () => {
  it('matches everything when the filter is absent, empty, or contains All', () => {
    // ARRANGE / ACT / ASSERT
    expect(passesSeverityFilter(undefined, 'Critical')).toBe(true);
    expect(passesSeverityFilter([], 'Critical')).toBe(true);
    expect(passesSeverityFilter(['All'], 'Low')).toBe(true);
    expect(passesSeverityFilter(['Low', 'All'], 'Critical')).toBe(true);
  });

  it('matches only listed severities, case-insensitively', () => {
    // ARRANGE
    const filter: SeverityFilter = ['Critical', 'High'];

    // ACT / ASSERT
    expect(passesSeverityFilter(filter, 'Critical')).toBe(true);
    expect(passesSeverityFilter(filter, 'critical')).toBe(true);
    expect(passesSeverityFilter(filter, 'CRITICAL')).toBe(true);
    expect(passesSeverityFilter(filter, 'High')).toBe(true);
    expect(passesSeverityFilter(filter, 'Medium')).toBe(false);
    expect(passesSeverityFilter(filter, 'low')).toBe(false);
  });
});

describe('passesControlFilter', () => {
  it('matches every control when the control ID list is empty', () => {
    // ARRANGE / ACT / ASSERT
    expect(passesControlFilter([], 'S3.1')).toBe(true);
  });

  it('matches only control IDs present in the list', () => {
    // ARRANGE
    const controlIds = ['S3.1', 'EC2.2'];

    // ACT / ASSERT
    expect(passesControlFilter(controlIds, 'S3.1')).toBe(true);
    expect(passesControlFilter(controlIds, 'EC2.2')).toBe(true);
    expect(passesControlFilter(controlIds, 'IAM.1')).toBe(false);
  });
});
