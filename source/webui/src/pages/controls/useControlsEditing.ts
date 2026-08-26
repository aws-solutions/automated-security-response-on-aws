// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { useCallback, useEffect, useMemo, useState } from 'react';
import { useDispatch } from 'react-redux';

import { SecurityControl, FilterMode } from '@data-models';
import { useGetControlsQuery, useBulkEditControlsMutation } from '../../store/controlsApiSlice.ts';
import { isFetchBaseQueryError, getErrorMessage } from '../../utils/error.ts';
import { addNotification } from '../../store/notificationsSlice.ts';

interface ControlsEditingState {
  localControls: SecurityControl[];
  serverControls: SecurityControl[];
  isLoading: boolean;
  isSaving: boolean;
  hasUnsavedChanges: boolean;
  changedControlIds: string[];
  handleToggle: (controlId: string, isEnabled: boolean) => void;
  handleDisableAll: () => void;
  handleSave: () => Promise<void>;
  handleDiscard: () => void;
  handleRefresh: () => void;
  handleFilterModeChange: (controlId: string, filterMode: FilterMode) => void;
  handleAddFilter: (controlId: string, filterId: string) => void;
  handleRemoveFilter: (controlId: string, filterId: string) => void;
}

const EMPTY_CONTROLS: SecurityControl[] = [];
// WAF SizeRestrictions_BODY blocks requests > 8KB. Each control is ~300-500 bytes serialized.
// Batching at 15 keeps each request well under the limit.
const BATCH_SIZE = 15;

interface BulkEditResult {
  readonly updatedCount?: number;
  readonly successCount?: number;
  readonly failedControlIds?: string[];
  readonly message: string;
}

interface BatchAggregation {
  readonly totalSuccess: number;
  readonly allFailedControlIds: string[];
  readonly hasConflict: boolean;
  readonly lastErrorMessage: string | undefined;
}

function aggregateBatchOutcomes(
  outcomes: PromiseSettledResult<BulkEditResult>[],
  batches: SecurityControl[][],
): BatchAggregation {
  let totalSuccess = 0;
  const allFailedControlIds: string[] = [];
  let hasConflict = false;
  let lastErrorMessage: string | undefined;

  for (let i = 0; i < outcomes.length; i++) {
    const outcome = outcomes[i];
    if (outcome.status === 'fulfilled') {
      const result = outcome.value;
      if (result.failedControlIds) {
        totalSuccess += result.successCount ?? 0;
        allFailedControlIds.push(...result.failedControlIds);
      } else {
        totalSuccess += result.updatedCount ?? 0;
      }
    } else {
      allFailedControlIds.push(...batches[i].map((c) => c.controlId));
      if (isFetchBaseQueryError(outcome.reason) && outcome.reason.status === 409) {
        hasConflict = true;
      } else {
        lastErrorMessage = getErrorMessage(outcome.reason) || lastErrorMessage;
      }
    }
  }

  return { totalSuccess, allFailedControlIds, hasConflict, lastErrorMessage };
}

export const useControlsEditing = (isReadOnly: boolean): ControlsEditingState => {
  const dispatch = useDispatch();
  const { data: serverControls = EMPTY_CONTROLS, isLoading, refetch } = useGetControlsQuery();
  const [bulkEdit, { isLoading: isSaving }] = useBulkEditControlsMutation();

  const [localControls, setLocalControls] = useState<SecurityControl[]>([]);

  const changedControlIds = useMemo(() => {
    if (serverControls.length === 0) return [];
    const serverMap = new Map(serverControls.map((s) => [s.controlId, s]));
    return localControls
      .filter((local) => {
        const server = serverMap.get(local.controlId);
        if (!server) return false;
        if (local.automatedRemediationEnabled !== server.automatedRemediationEnabled) return true;
        if (local.filterMode !== server.filterMode) return true;
        if (local.filters.length !== server.filters.length) return true;
        return local.filters.some((f, i) => f !== server.filters[i]);
      })
      .map((c) => c.controlId);
  }, [localControls, serverControls]);

  const hasUnsavedChanges = changedControlIds.length > 0;

  useEffect(() => {
    if (changedControlIds.length === 0) {
      setLocalControls(serverControls);
    }
  }, [serverControls, changedControlIds]);

  useEffect(() => {
    const handleBeforeUnload = (e: BeforeUnloadEvent) => {
      if (hasUnsavedChanges) {
        e.preventDefault();
      }
    };
    window.addEventListener('beforeunload', handleBeforeUnload);
    return () => window.removeEventListener('beforeunload', handleBeforeUnload);
  }, [hasUnsavedChanges]);

  const handleToggle = useCallback(
    (controlId: string, isEnabled: boolean) => {
      if (isReadOnly) return;
      setLocalControls((prev) =>
        prev.map((c) => (c.controlId === controlId ? { ...c, automatedRemediationEnabled: isEnabled } : c)),
      );
    },
    [isReadOnly],
  );

  const handleDisableAll = useCallback(() => {
    if (isReadOnly) return;
    setLocalControls((prev) => prev.map((c) => ({ ...c, automatedRemediationEnabled: false })));
  }, [isReadOnly]);

  const handleSave = useCallback(async () => {
    const controlsToSave = localControls.filter((local) => changedControlIds.includes(local.controlId));
    if (controlsToSave.length === 0) return;

    const batches: SecurityControl[][] = [];
    for (let i = 0; i < controlsToSave.length; i += BATCH_SIZE) {
      batches.push(controlsToSave.slice(i, i + BATCH_SIZE));
    }

    const batchOutcomes = await Promise.allSettled(
      batches.map((batch) => bulkEdit({ operation: 'update', data: batch }).unwrap()),
    );

    const { totalSuccess, allFailedControlIds, hasConflict, lastErrorMessage } = aggregateBatchOutcomes(
      batchOutcomes,
      batches,
    );

    if (allFailedControlIds.length === 0) {
      dispatch(
        addNotification({
          type: 'success',
          content: 'Controls saved successfully.',
          id: `save-success-${Date.now()}`,
        }),
      );
      return;
    }

    if (hasConflict && totalSuccess === 0) {
      // If a non-conflict error ALSO happened in another batch, surface it so
      // the user knows refresh-and-retry isn't enough on its own.
      const conflictMessage = lastErrorMessage
        ? `Data was modified by another user, please refresh. Additionally: ${lastErrorMessage}`
        : 'Data was modified by another user, please refresh.';
      dispatch(
        addNotification({
          type: 'error',
          content: conflictMessage,
          id: `save-conflict-${Date.now()}`,
        }),
      );
      return;
    }

    if (totalSuccess > 0) {
      dispatch(
        addNotification({
          type: 'warning',
          content: `Saved ${totalSuccess} control${totalSuccess === 1 ? '' : 's'}. Failed: ${allFailedControlIds.join(', ')}. Please refresh and retry the failed controls.`,
          id: `save-partial-${Date.now()}`,
        }),
      );
      return;
    }

    dispatch(
      addNotification({
        type: 'error',
        content: `Save failed: ${lastErrorMessage ?? 'An unexpected error occurred.'}`,
        id: `save-error-${Date.now()}`,
      }),
    );
  }, [localControls, changedControlIds, bulkEdit, dispatch]);

  const handleDiscard = useCallback(() => {
    setLocalControls(serverControls);
    dispatch(
      addNotification({
        type: 'info',
        content: 'Changes discarded.',
        id: `discard-${Date.now()}`,
      }),
    );
  }, [serverControls, dispatch]);

  const handleRefresh = useCallback(() => {
    if (!hasUnsavedChanges) {
      refetch();
    }
  }, [hasUnsavedChanges, refetch]);

  const handleFilterModeChange = useCallback(
    (controlId: string, filterMode: FilterMode) => {
      if (isReadOnly) return;
      setLocalControls((prev) => prev.map((c) => (c.controlId === controlId ? { ...c, filterMode } : c)));
    },
    [isReadOnly],
  );

  const handleAddFilter = useCallback(
    (controlId: string, filterId: string) => {
      if (isReadOnly) return;
      setLocalControls((prev) =>
        prev.map((c) => {
          if (c.controlId !== controlId) return c;
          if (c.filters.includes(filterId)) return c;
          return { ...c, filters: [...c.filters, filterId] };
        }),
      );
    },
    [isReadOnly],
  );

  const removeFilterFromControl = useCallback(
    (controlId: string, filterId: string) =>
      (c: SecurityControl): SecurityControl => {
        if (c.controlId !== controlId) return c;
        return { ...c, filters: c.filters.filter((f) => f !== filterId) };
      },
    [],
  );

  const handleRemoveFilter = useCallback(
    (controlId: string, filterId: string) => {
      if (isReadOnly) return;
      setLocalControls((prev) => prev.map(removeFilterFromControl(controlId, filterId)));
    },
    [isReadOnly, removeFilterFromControl],
  );

  return {
    localControls,
    serverControls,
    isLoading,
    isSaving,
    hasUnsavedChanges,
    changedControlIds,
    handleToggle,
    handleDisableAll,
    handleSave,
    handleDiscard,
    handleRefresh,
    handleFilterModeChange,
    handleAddFilter,
    handleRemoveFilter,
  };
};
