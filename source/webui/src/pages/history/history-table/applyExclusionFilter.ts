// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { RemediationHistoryApiResponse, SecurityControl, ResourceFilterInput, BulkEditResponse } from '@data-models';
import { extractControlId } from '../../../utils/controlUtils.ts';

// ResourceFilterSchema caps `name` at 100 characters.
const MAX_FILTER_NAME_LENGTH = 100;

// ResourceFilterSchema validates each arnPatterns entry against this shape. A
// remediation resourceId is only usually an ARN (bare ids like "i-1234..." are
// possible), so we check before creating the filter to give a clear reason.
const ARN_PATTERN = /^arn:[^:]+:[^:]*:[^:]*:[^:]*:.+$/;

/**
 * The subset of the createFilter mutation trigger required by applyExclusionFilter.
 * Using a structural type avoids importing the full RTK Query generated type.
 */
export type CreateFilterTrigger = (
  input: ResourceFilterInput,
) => Promise<{ data: { filterId: string } } | { error: unknown }>;

/**
 * The subset of the bulkEditControls mutation trigger required by applyExclusionFilter.
 * Resolves to BulkEditResponse, which may be a partial success (HTTP 200 with
 * failedControlIds) that must be treated as a failure.
 */
export type BulkEditControlsTrigger = (input: {
  operation: 'update';
  data: SecurityControl[];
}) => Promise<{ data: BulkEditResponse } | { error: unknown }>;

/**
 * The subset of the deleteFilter mutation trigger required for orphan cleanup.
 */
export type DeleteFilterTrigger = (filterId: string) => Promise<{ data: unknown } | { error: unknown }>;

// filtersService rejects a duplicate name with BadRequestError('...already
// exists'), surfaced by RTK as { data: { message } }. Not treated as success:
// the filter may exist but be detached from the control, so it isn't proof the
// resource is currently excluded.
function isDuplicateFilterNameError(error: unknown): boolean {
  if (typeof error !== 'object' || error === null) return false;
  const data = (error as { data?: unknown }).data;
  if (typeof data !== 'object' || data === null || !('message' in data)) return false;
  const message = (data as { message?: unknown }).message;
  return typeof message === 'string' && /already exists/i.test(message);
}

/**
 * Validates that the target control exists and can accept an exclude-mode filter,
 * then creates the filter and attaches it to the control.
 *
 * No orphan filters are left in the system:
 *  - validation runs before the filter is created (a missing/incompatible control
 *    fails without creating anything), and
 *  - if the attach step fails after the filter was created, the just-created
 *    filter is deleted before returning.
 *
 * Returns null on full success.
 * Returns a human-readable warning string when a partial failure occurs (the
 * rollback itself succeeded but the exclusion filter could not be fully applied).
 */
export async function applyExclusionFilter(
  rollbackItem: RemediationHistoryApiResponse,
  controlList: SecurityControl[] | undefined,
  createFilter: CreateFilterTrigger,
  bulkEditControls: BulkEditControlsTrigger,
  deleteFilter: DeleteFilterTrigger,
): Promise<string | null> {
  // Step 0: Validate inputs at the boundary and return a self-explaining error early.
  if (!rollbackItem.resourceId) {
    return 'the exclusion filter was not applied because the resource ID is missing.';
  }
  if (!ARN_PATTERN.test(rollbackItem.resourceId)) {
    return 'the exclusion filter was not applied because the resource is not identified by an ARN.';
  }

  // Step 1: Validate the control exists and is compatible before creating any resources.
  const controlId = extractControlId(rollbackItem.findingType ?? '');
  const control = controlList?.find((candidate) => candidate.controlId === controlId);
  if (!control) {
    return 'the exclusion filter was not applied because the matching control could not be found.';
  }
  if (control.filterMode === 'include' && control.filters.length > 0) {
    return 'the exclusion filter was not applied because the control uses include-mode filtering.';
  }

  // Step 2: Only create the filter after validation passes, preventing orphan filters.
  // Keep the ARN tail (the unique part) when truncating so prefix-sharing ARNs don't collide on the unique name.
  const namePrefix = 'Rollback exclusion: ';
  const nameBudget = MAX_FILTER_NAME_LENGTH - namePrefix.length;
  const filterName =
    namePrefix +
    (rollbackItem.resourceId.length > nameBudget
      ? rollbackItem.resourceId.slice(-nameBudget)
      : rollbackItem.resourceId);
  const filterResult = await createFilter({
    name: filterName,
    accountIds: [],
    organizationalUnits: [],
    tags: [],
    arnPatterns: [rollbackItem.resourceId],
  });
  if (!('data' in filterResult) || !filterResult.data?.filterId) {
    // Duplicate name = this resource already has an exclusion filter; report it
    // as such rather than a generic failure (but not as success).
    if ('error' in filterResult && isDuplicateFilterNameError(filterResult.error)) {
      return 'the exclusion filter was not created because this resource already has an exclusion filter.';
    }
    return 'the exclusion filter could not be created.';
  }
  const createdFilterId = filterResult.data.filterId;

  // Step 3: Attach the new filter to the control. A control-level failure comes
  // back as either an RTK error or an HTTP 200 partial-success body carrying
  // failedControlIds; both mean the attach did not take effect. In either case
  // delete the just-created filter (best effort) so it is not left orphaned.
  const editResult = await bulkEditControls({
    operation: 'update',
    data: [{ ...control, filters: [...control.filters, createdFilterId], filterMode: 'exclude' }],
  });
  const isAttachSuccessful =
    !('error' in editResult) && !('failedControlIds' in editResult.data && editResult.data.failedControlIds.length > 0);
  if (!isAttachSuccessful) {
    // Best-effort cleanup so the created filter is not orphaned. The RTK trigger
    // resolves to { data } | { error } and never rejects, so inspect the result
    // (a try/catch would never fire) and log if the delete itself failed.
    const deleteResult = await deleteFilter(createdFilterId);
    if ('error' in deleteResult) {
      console.error(`Failed to delete orphaned exclusion filter ${createdFilterId}`, deleteResult.error);
    }
    return 'the exclusion filter could not be attached to the control.';
  }

  return null;
}
