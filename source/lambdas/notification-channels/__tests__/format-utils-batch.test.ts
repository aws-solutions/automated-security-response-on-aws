// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { formatBatchDescription } from '../format-utils';

describe('formatBatchDescription', () => {
  it('should include labeled lines for notification type, count, and generation time', () => {
    // ARRANGE / ACT
    const result = formatBatchDescription({
      notificationType: 'finding',
      eventCount: 5,
      generationTime: '2024-06-15T10:30:00Z',
    });

    // ASSERT
    expect(result).toContain('Notification Type: Batch — 5 findings');
    expect(result).toContain('Generated: 2024-06-15T10:30:00Z');
  });

  it('should use singular noun when count is 1', () => {
    // ARRANGE / ACT
    const result = formatBatchDescription({
      notificationType: 'finding',
      eventCount: 1,
      generationTime: '2024-06-15T10:30:00Z',
    });

    // ASSERT
    expect(result).toContain('Notification Type: Batch — 1 finding');
  });

  it('should use "remediation(s)" for remediation type', () => {
    // ARRANGE / ACT
    const result = formatBatchDescription({
      notificationType: 'remediation',
      eventCount: 3,
      generationTime: '2024-06-15T10:30:00Z',
    });

    // ASSERT
    expect(result).toContain('Notification Type: Batch — 3 remediations');
  });

  it('should include export URL with expiration time when provided', () => {
    // ARRANGE
    const clock = { now: () => new Date('2024-06-15T10:00:00Z') };

    // ACT
    const result = formatBatchDescription({
      notificationType: 'finding',
      eventCount: 5,
      generationTime: '2024-06-15T10:30:00Z',
      exportUrl: 'https://s3.amazonaws.com/bucket/export.csv',
      linkAccessExpirationTime: '2024-06-16T10:00:00Z',
      clock,
    });

    // ASSERT
    expect(result).toContain('Export: https://s3.amazonaws.com/bucket/export.csv (expires: 2024-06-16T10:00:00Z)');
  });

  it('should append "(expired)" when linkAccessExpirationTime is in the past', () => {
    // ARRANGE
    const clock = { now: () => new Date('2024-06-17T10:00:00Z') };

    // ACT
    const result = formatBatchDescription({
      notificationType: 'finding',
      eventCount: 5,
      generationTime: '2024-06-15T10:30:00Z',
      exportUrl: 'https://s3.amazonaws.com/bucket/export.csv',
      linkAccessExpirationTime: '2024-06-16T10:00:00Z',
      clock,
    });

    // ASSERT
    expect(result).toContain('(expired)');
  });

  it('should not append "(expired)" when linkAccessExpirationTime is in the future', () => {
    // ARRANGE
    const clock = { now: () => new Date('2024-06-15T10:00:00Z') };

    // ACT
    const result = formatBatchDescription({
      notificationType: 'finding',
      eventCount: 5,
      generationTime: '2024-06-15T10:30:00Z',
      exportUrl: 'https://s3.amazonaws.com/bucket/export.csv',
      linkAccessExpirationTime: '2024-06-16T10:00:00Z',
      clock,
    });

    // ASSERT
    expect(result).not.toContain('(expired)');
  });

  it('should omit export line when exportUrl is undefined', () => {
    // ARRANGE / ACT
    const result = formatBatchDescription({
      notificationType: 'finding',
      eventCount: 5,
      generationTime: '2024-06-15T10:30:00Z',
    });

    // ASSERT
    expect(result).not.toContain('Export:');
  });
});
