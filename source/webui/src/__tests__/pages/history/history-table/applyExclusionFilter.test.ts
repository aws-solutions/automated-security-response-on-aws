// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { SecurityControl, BulkEditResponse } from '@data-models';
import { applyExclusionFilter } from '../../../../pages/history/history-table/applyExclusionFilter.ts';
import { generateTestRemediation } from '../../../test-data-factory.ts';

const RESOURCE_ARN = 'arn:aws:iam::111111111111:user/test-user';
const CONTROL_ID = 'GuardDuty.IAMUser';

const makeControl = (overrides: Partial<SecurityControl> = {}): SecurityControl => ({
  controlId: CONTROL_ID,
  description: 'GuardDuty IAM user control',
  automatedRemediationEnabled: true,
  filters: [],
  filterMode: 'exclude',
  version: 1,
  lastModified: '2025-01-01T00:00:00Z',
  modifiedBy: 'system',
  rollbackSupported: true,
  ...overrides,
});

const rollbackItem = (overrides = {}) =>
  generateTestRemediation({ findingType: CONTROL_ID, resourceId: RESOURCE_ARN, ...overrides });

const createFilter = vi.fn(
  async (): Promise<{ data: { filterId: string } } | { error: unknown }> => ({ data: { filterId: 'filter-1' } }),
);
const bulkEditControls = vi.fn(
  async (): Promise<{ data: BulkEditResponse } | { error: unknown }> => ({ data: { message: 'ok', updatedCount: 1 } }),
);
const deleteFilter = vi.fn(
  async (_filterId: string): Promise<{ data: unknown } | { error: unknown }> => ({
    data: undefined,
  }),
);

describe('applyExclusionFilter', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('returns a warning when the resourceId is missing', async () => {
    const warning = await applyExclusionFilter(
      rollbackItem({ resourceId: '' }),
      [makeControl()],
      createFilter,
      bulkEditControls,
      deleteFilter,
    );
    expect(warning).toMatch(/resource ID is missing/i);
    expect(createFilter).not.toHaveBeenCalled();
  });

  it('returns a warning when the resourceId is not an ARN', async () => {
    const warning = await applyExclusionFilter(
      rollbackItem({ resourceId: 'i-1234567890abcdef0' }),
      [makeControl()],
      createFilter,
      bulkEditControls,
      deleteFilter,
    );
    expect(warning).toMatch(/not identified by an ARN/i);
    expect(createFilter).not.toHaveBeenCalled();
  });

  it('returns a warning when the matching control cannot be found', async () => {
    const warning = await applyExclusionFilter(rollbackItem(), [], createFilter, bulkEditControls, deleteFilter);
    expect(warning).toMatch(/matching control could not be found/i);
  });

  it('returns a warning when the control uses include-mode filtering', async () => {
    const warning = await applyExclusionFilter(
      rollbackItem(),
      [makeControl({ filterMode: 'include', filters: ['existing-filter'] })],
      createFilter,
      bulkEditControls,
      deleteFilter,
    );
    expect(warning).toMatch(/include-mode filtering/i);
  });

  it('returns a warning and does not attach when the filter cannot be created', async () => {
    createFilter.mockResolvedValueOnce({ error: { status: 500 } });
    const warning = await applyExclusionFilter(
      rollbackItem(),
      [makeControl()],
      createFilter,
      bulkEditControls,
      deleteFilter,
    );
    expect(warning).toMatch(/could not be created/i);
    expect(bulkEditControls).not.toHaveBeenCalled();
  });

  it('returns an "already has an exclusion filter" warning (not a generic failure) on a duplicate-name error', async () => {
    // filtersService throws BadRequestError('...already exists'); RTK surfaces it as { data: { message } }.
    createFilter.mockResolvedValueOnce({
      error: {
        status: 400,
        data: { message: `A filter with the name "Rollback exclusion: ${RESOURCE_ARN}" already exists` },
      },
    });
    const warning = await applyExclusionFilter(
      rollbackItem(),
      [makeControl()],
      createFilter,
      bulkEditControls,
      deleteFilter,
    );
    expect(warning).toMatch(/already has an exclusion filter/i);
    expect(warning).not.toMatch(/could not be created/i);
    expect(bulkEditControls).not.toHaveBeenCalled();
  });

  it('deletes the created filter (orphan cleanup) when the attach returns an RTK error', async () => {
    bulkEditControls.mockResolvedValueOnce({ error: { status: 409 } });
    const warning = await applyExclusionFilter(
      rollbackItem(),
      [makeControl()],
      createFilter,
      bulkEditControls,
      deleteFilter,
    );
    expect(warning).toMatch(/could not be attached/i);
    expect(deleteFilter).toHaveBeenCalledWith('filter-1');
  });

  it('deletes the created filter when the attach returns a partial-success body (failedControlIds)', async () => {
    bulkEditControls.mockResolvedValueOnce({
      data: { message: 'partial', successCount: 0, failedControlIds: [CONTROL_ID] },
    });
    const warning = await applyExclusionFilter(
      rollbackItem(),
      [makeControl()],
      createFilter,
      bulkEditControls,
      deleteFilter,
    );
    expect(warning).toMatch(/could not be attached/i);
    expect(deleteFilter).toHaveBeenCalledWith('filter-1');
  });

  it('logs (best effort) but still returns the attach warning when the orphan cleanup delete also fails', async () => {
    bulkEditControls.mockResolvedValueOnce({ error: { status: 409 } });
    deleteFilter.mockResolvedValueOnce({ error: { status: 500 } });
    const consoleError = vi.spyOn(console, 'error').mockImplementation(() => {});
    const warning = await applyExclusionFilter(
      rollbackItem(),
      [makeControl()],
      createFilter,
      bulkEditControls,
      deleteFilter,
    );
    expect(warning).toMatch(/could not be attached/i);
    expect(deleteFilter).toHaveBeenCalledWith('filter-1');
    expect(consoleError).toHaveBeenCalledWith(expect.stringMatching(/orphaned exclusion filter filter-1/i), {
      status: 500,
    });
    consoleError.mockRestore();
  });

  it('returns null on full success, creating an ARN filter and attaching it in exclude mode', async () => {
    const warning = await applyExclusionFilter(
      rollbackItem(),
      [makeControl()],
      createFilter,
      bulkEditControls,
      deleteFilter,
    );

    expect(warning).toBeNull();
    expect(createFilter).toHaveBeenCalledWith(
      expect.objectContaining({ name: `Rollback exclusion: ${RESOURCE_ARN}`, arnPatterns: [RESOURCE_ARN] }),
    );
    expect(bulkEditControls).toHaveBeenCalledWith(
      expect.objectContaining({
        operation: 'update',
        data: [expect.objectContaining({ controlId: CONTROL_ID, filterMode: 'exclude', filters: ['filter-1'] })],
      }),
    );
    expect(deleteFilter).not.toHaveBeenCalled();
  });

  it('keeps the ARN tail (not the prefix) when the filter name exceeds the length limit', async () => {
    // Two ARNs sharing a long common prefix must not collide to the same name.
    const longArn = 'arn:aws:rds:us-east-1:111111111111:db:' + 'x'.repeat(90);
    const warning = await applyExclusionFilter(
      rollbackItem({ resourceId: longArn }),
      [makeControl()],
      createFilter,
      bulkEditControls,
      deleteFilter,
    );

    expect(warning).toBeNull();
    const prefix = 'Rollback exclusion: ';
    const expectedName = prefix + longArn.slice(-(100 - prefix.length));
    expect(expectedName).toHaveLength(100);
    expect(createFilter).toHaveBeenCalledWith(expect.objectContaining({ name: expectedName, arnPatterns: [longArn] }));
  });
});
