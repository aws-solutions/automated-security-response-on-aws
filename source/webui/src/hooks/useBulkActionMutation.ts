// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { useCallback, useMemo } from 'react';

import { useBulkActionConfirmation, BulkActionState } from './useBulkActionConfirmation.ts';
import { useBulkEditControlsMutation } from '../store/controlsApiSlice.ts';
import { NotificationPayload } from '../store/notificationsSlice.ts';
import { getErrorMessage } from '../utils/error.ts';
import {
  ResourceFilter,
  SecurityControl,
  BulkEditPartialSuccessResponse,
  BulkEditResponse,
  BulkFilterOperation,
} from '@data-models';

const isPartialSuccess = (result: BulkEditResponse): result is BulkEditPartialSuccessResponse =>
  'failedControlIds' in result;

interface UseBulkActionFlowParams {
  controls: SecurityControl[];
  notify: (type: NotificationPayload['type'], content: string) => void;
  withSubmitting: (fn: () => Promise<void>) => Promise<void>;
}

interface UseBulkActionMutationResult {
  bulkActionFilter: BulkActionState<ResourceFilter> | null;
  bulkActionAffectedCount: number;
  handleApplyToAll: (filter: ResourceFilter) => void;
  handleRemoveFromAll: (filter: ResourceFilter) => void;
  closeBulkAction: () => void;
  confirmBulkAction: () => Promise<void>;
}

const OPERATION_LABELS: Record<BulkFilterOperation, { verb: string }> = {
  applyFilterToAll: { verb: 'applied to' },
  removeFilterFromAll: { verb: 'removed from' },
};

export function useBulkActionMutation({
  controls,
  notify,
  withSubmitting,
}: UseBulkActionFlowParams): UseBulkActionMutationResult {
  const {
    bulkAction: bulkActionFilter,
    openApplyToAll: handleApplyToAll,
    openRemoveFromAll: handleRemoveFromAll,
    closeBulkAction,
  } = useBulkActionConfirmation<ResourceFilter>();

  const [bulkEditControls] = useBulkEditControlsMutation();

  const bulkActionAffectedCount = useMemo(() => {
    if (!bulkActionFilter) return 0;
    const filterId = bulkActionFilter.item.filterId;
    if (bulkActionFilter.operation === 'applyFilterToAll') {
      return controls.filter((control) => !control.filters.includes(filterId)).length;
    }
    return controls.filter((control) => control.filters.includes(filterId)).length;
  }, [bulkActionFilter, controls]);

  const confirmBulkAction = useCallback(async () => {
    if (!bulkActionFilter) return;
    const { item: filter, operation } = bulkActionFilter;
    await withSubmitting(async () => {
      try {
        const result = await bulkEditControls({ operation, data: filter.filterId }).unwrap();
        const failedIds = isPartialSuccess(result) ? result.failedControlIds : [];
        if (failedIds.length > 0) {
          notify('warning', `Some controls failed to update: ${failedIds.join(', ')}`);
        } else {
          notify('success', `Filter "${filter.name}" ${OPERATION_LABELS[operation].verb} all controls successfully.`);
        }
      } catch (error: unknown) {
        notify('error', `Bulk operation failed: ${getErrorMessage(error) || 'Unknown error'}`);
      } finally {
        closeBulkAction();
      }
    });
  }, [bulkActionFilter, bulkEditControls, notify, closeBulkAction, withSubmitting]);

  return {
    bulkActionFilter,
    bulkActionAffectedCount,
    handleApplyToAll,
    handleRemoveFromAll,
    closeBulkAction,
    confirmBulkAction,
  };
}
