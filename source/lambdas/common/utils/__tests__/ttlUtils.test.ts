// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { calculateTtlTimestamp, calculateHistoryTtlTimestamp } from '../ttlUtils';

describe('calculateTtlTimestamp', () => {
  it('should calculate TTL timestamp correctly with default 8 days', () => {
    const lastUpdatedTime = '2023-01-01T12:00:00.000Z';
    const result = calculateTtlTimestamp(lastUpdatedTime);

    const updatedAtDate = new Date('2023-01-01T12:00:00.000Z');
    const expectedDate = new Date(updatedAtDate.getTime() + 8 * 24 * 60 * 60 * 1000);
    const expectedTimestamp = Math.floor(expectedDate.getTime() / 1000);

    expect(result).toBe(expectedTimestamp);
  });

  it('should use environment variable when set', () => {
    process.env.FINDINGS_TTL_DAYS = '10';

    const lastUpdatedTime = '2023-01-01T12:00:00.000Z';
    const result = calculateTtlTimestamp(lastUpdatedTime);

    const updatedAtDate = new Date('2023-01-01T12:00:00.000Z');
    const expectedDate = new Date(updatedAtDate.getTime() + 10 * 24 * 60 * 60 * 1000);
    const expectedTimestamp = Math.floor(expectedDate.getTime() / 1000);

    expect(result).toBe(expectedTimestamp);

    delete process.env.FINDINGS_TTL_DAYS;
  });
});

describe('calculateHistoryTtlTimestamp', () => {
  it('should calculate history TTL timestamp correctly with default 365 days', () => {
    const lastUpdatedTime = '2023-01-01T12:00:00.000Z';
    const result = calculateHistoryTtlTimestamp(lastUpdatedTime);

    const updatedAtDate = new Date('2023-01-01T12:00:00.000Z');
    const expectedDate = new Date(updatedAtDate.getTime() + 365 * 24 * 60 * 60 * 1000);
    const expectedTimestamp = Math.floor(expectedDate.getTime() / 1000);

    expect(result).toBe(expectedTimestamp);
  });

  it('should use environment variable when set', () => {
    process.env.HISTORY_TTL_DAYS = '30';

    const lastUpdatedTime = '2023-01-01T12:00:00.000Z';
    const result = calculateHistoryTtlTimestamp(lastUpdatedTime);

    const updatedAtDate = new Date('2023-01-01T12:00:00.000Z');
    const expectedDate = new Date(updatedAtDate.getTime() + 30 * 24 * 60 * 60 * 1000);
    const expectedTimestamp = Math.floor(expectedDate.getTime() / 1000);

    expect(result).toBe(expectedTimestamp);

    delete process.env.HISTORY_TTL_DAYS;
  });

  it('should use custom ttlDays parameter when provided', () => {
    const lastUpdatedTime = '2023-01-01T12:00:00.000Z';
    const customDays = 90;
    const result = calculateHistoryTtlTimestamp(lastUpdatedTime, customDays);

    const updatedAtDate = new Date('2023-01-01T12:00:00.000Z');
    const expectedDate = new Date(updatedAtDate.getTime() + customDays * 24 * 60 * 60 * 1000);
    const expectedTimestamp = Math.floor(expectedDate.getTime() / 1000);

    expect(result).toBe(expectedTimestamp);
  });

  it('should fallback to 365 days for invalid environment variable', () => {
    process.env.HISTORY_TTL_DAYS = 'invalid';

    const lastUpdatedTime = '2023-01-01T12:00:00.000Z';
    const result = calculateHistoryTtlTimestamp(lastUpdatedTime);

    const updatedAtDate = new Date('2023-01-01T12:00:00.000Z');
    const expectedDate = new Date(updatedAtDate.getTime() + 365 * 24 * 60 * 60 * 1000);
    const expectedTimestamp = Math.floor(expectedDate.getTime() / 1000);

    expect(result).toBe(expectedTimestamp);

    delete process.env.HISTORY_TTL_DAYS;
  });

  it('should fallback to 365 days for negative ttlDays', () => {
    const lastUpdatedTime = '2023-01-01T12:00:00.000Z';
    const result = calculateHistoryTtlTimestamp(lastUpdatedTime, -5);

    const updatedAtDate = new Date('2023-01-01T12:00:00.000Z');
    const expectedDate = new Date(updatedAtDate.getTime() + 365 * 24 * 60 * 60 * 1000);
    const expectedTimestamp = Math.floor(expectedDate.getTime() / 1000);

    expect(result).toBe(expectedTimestamp);
  });
});
