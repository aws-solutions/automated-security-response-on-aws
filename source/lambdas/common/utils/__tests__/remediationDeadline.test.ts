// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import {
  MINIMUM_REMEDIATION_GRACE_HOURS,
  MINIMUM_REMEDIATION_GRACE_MS,
  computeRemediationDueBy,
} from '../remediationDeadline';

describe('computeRemediationDueBy', () => {
  // A fixed reference clock so the 24-hour grace floor (now + 24h) is deterministic.
  const now = new Date('2025-06-01T00:00:00.000Z');
  const graceFloor = '2025-06-02T00:00:00.000Z'; // now + 24h

  it('returns the deadline-based value when creationTime + deadlineDays is later than now + 24h', () => {
    // ARRANGE — a brand-new finding whose creation-time deadline is well beyond the grace floor.
    const creationTime = '2025-06-01T00:00:00.000Z';
    const deadlineDays = 10;

    // ACT
    const result = computeRemediationDueBy(creationTime, deadlineDays, now);

    // ASSERT — the later candidate (creationTime + 10 days) wins.
    expect(result).toBe('2025-06-11T00:00:00.000Z');
  });

  it('returns now + 24h when creationTime + deadlineDays is earlier than now + 24h', () => {
    // ARRANGE — a backlog finding whose creation-time deadline already lies in the past.
    const creationTime = '2025-01-01T00:00:00.000Z';
    const deadlineDays = 5;

    // ACT
    const result = computeRemediationDueBy(creationTime, deadlineDays, now);

    // ASSERT — the grace floor wins, guaranteeing at least 24 hours of notice.
    expect(result).toBe(graceFloor);
  });

  it('returns the shared value when creationTime + deadlineDays equals now + 24h', () => {
    // ARRANGE — boundary: creationTime + 1 day lands exactly on the grace floor.
    const creationTime = '2025-06-01T00:00:00.000Z';
    const deadlineDays = 1;

    // ACT
    const result = computeRemediationDueBy(creationTime, deadlineDays, now);

    // ASSERT — both candidates are equal, so that shared value is returned.
    expect(result).toBe(graceFloor);
  });

  it('exposes the fixed 24-hour grace-period constants', () => {
    // ASSERT — the floor is a fixed, non-configurable 24 hours expressed in hours and milliseconds.
    expect(MINIMUM_REMEDIATION_GRACE_HOURS).toBe(24);
    expect(MINIMUM_REMEDIATION_GRACE_MS).toBe(24 * 60 * 60 * 1000);
  });
});
