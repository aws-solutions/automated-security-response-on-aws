// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { Dispatch, SetStateAction, useCallback, useMemo, useState } from 'react';
import { RemediationHistoryApiResponse } from '@data-models';
import { useExecuteActionMutation } from '../../../store/findingsApiSlice.ts';
import { useGetControlsQuery, useBulkEditControlsMutation } from '../../../store/controlsApiSlice.ts';
import { useCreateFilterMutation, useDeleteFilterMutation } from '../../../store/filtersApiSlice.ts';
import { getErrorMessage } from '../../../utils/error.ts';
import { extractControlId } from '../../../utils/controlUtils.ts';
import { applyExclusionFilter } from './applyExclusionFilter.ts';

/**
 * Return contract for {@link useRollbackConfirmation}.
 */
export interface UseRollbackConfirmationResult {
  pendingRollback: RemediationHistoryApiResponse | null;
  shouldExcludeFromAutoRemediation: boolean;
  setShouldExcludeFromAutoRemediation: Dispatch<SetStateAction<boolean>>;
  rollbackError: string | null;
  setRollbackError: Dispatch<SetStateAction<string | null>>;
  rollbackSuccess: string | null;
  setRollbackSuccess: Dispatch<SetStateAction<string | null>>;
  rollbackWarning: string | null;
  setRollbackWarning: Dispatch<SetStateAction<string | null>>;
  /** True for the whole submit (rollback call + exclusion-filter step) so the confirm button stays disabled. */
  isRollbackInProgress: boolean;
  isPendingControlAutoRemediationEnabled: boolean;
  reRemediationEligibleDate: string | null;
  pendingControlLabel: string;
  handleRollbackClick: (item: RemediationHistoryApiResponse) => void;
  executeRollback: (onComplete: () => void) => Promise<void>;
  closeModal: () => void;
}

/**
 * Encapsulates the rollback confirmation flow for the remediation history table:
 * the modal open/close state, the auto-remediation exclusion toggle, the derived
 * warning content (control label, re-remediation date, whether auto-remediation
 * is enabled), and the rollback execution + exclusion-filter side effects.
 *
 * Keeping this out of RemediationHistoryTable lets that component stay focused on
 * listing/filtering while this hook owns the rollback concern.
 */
export function useRollbackConfirmation(): UseRollbackConfirmationResult {
  // Controls drive the rollback warning: if auto-remediation is enabled for the
  // control behind the finding, a rolled-back finding can be picked up and
  // re-remediated automatically. The list is small and cached, so querying it
  // here is cheap.
  const { data: controls } = useGetControlsQuery();
  const [executeAction] = useExecuteActionMutation();
  const [createFilter] = useCreateFilterMutation();
  const [deleteFilter] = useDeleteFilterMutation();
  const [bulkEditControls] = useBulkEditControlsMutation();

  const [pendingRollback, setPendingRollback] = useState<RemediationHistoryApiResponse | null>(null);
  const [shouldExcludeFromAutoRemediation, setShouldExcludeFromAutoRemediation] = useState(false);
  const [rollbackError, setRollbackError] = useState<string | null>(null);
  const [rollbackSuccess, setRollbackSuccess] = useState<string | null>(null);
  const [rollbackWarning, setRollbackWarning] = useState<string | null>(null);
  // Covers the entire submit (rollback mutation + exclusion-filter step) so the
  // modal cannot be re-submitted while the filter calls are still running.
  const [isRollbackInProgress, setIsRollbackInProgress] = useState(false);

  // True when auto-remediation is enabled for the control of the finding being
  // rolled back. The history record's findingType is the control id (e.g.
  // "GuardDuty.IAMUser").
  const isPendingControlAutoRemediationEnabled = useMemo((): boolean => {
    if (!pendingRollback || !controls) return false;
    const controlId = extractControlId(pendingRollback.findingType ?? '');
    return controls.find((control) => control.controlId === controlId)?.automatedRemediationEnabled ?? false;
  }, [pendingRollback, controls]);

  const reRemediationEligibleDate = useMemo((): string | null => {
    const eligibleAtSeconds = pendingRollback?.reRemediationEligibleAt;
    if (typeof eligibleAtSeconds !== 'number') return null;
    const eligibleAtMs = eligibleAtSeconds * 1000;
    if (eligibleAtMs <= Date.now()) return null;
    return new Date(eligibleAtMs).toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' });
  }, [pendingRollback]);

  const pendingControlLabel = useMemo((): string => {
    if (!pendingRollback) return '';
    const controlId = extractControlId(pendingRollback.findingType ?? '');
    const control = controls?.find((candidate) => candidate.controlId === controlId);
    return control ? `${control.controlId} - ${control.description}` : controlId;
  }, [pendingRollback, controls]);

  const handleRollbackClick = useCallback((item: RemediationHistoryApiResponse): void => {
    setPendingRollback(item);
  }, []);

  // Single source of truth for clearing the modal state, reused by the dismiss
  // handlers and by every executeRollback exit path.
  const resetState = useCallback((): void => {
    setPendingRollback(null);
    setShouldExcludeFromAutoRemediation(false);
  }, []);

  // Runs the rollback, then optionally applies the auto-remediation exclusion
  // filter. `onComplete` refreshes the table after a successful rollback.
  const executeRollback = async (onComplete: () => void): Promise<void> => {
    if (!pendingRollback || isRollbackInProgress) return;
    const rollbackItem = pendingRollback;
    const findingId = rollbackItem.findingId;
    setRollbackError(null);
    setRollbackSuccess(null);
    setRollbackWarning(null);
    setIsRollbackInProgress(true);
    try {
      const result = await executeAction({
        actionType: 'Rollback',
        findingIds: [findingId],
        // Send the explicit key so the API never has to derive the partition key from the finding
        // id, which is impossible for ids that are not Security Hub ARNs. The history row's
        // findingType is the findings-table partition key. See ADR 0010.
        findingKeys: [{ findingId, findingType: rollbackItem.findingType }],
      });
      if (result.error) {
        resetState();
        setRollbackError(getErrorMessage(result.error) || 'Failed to initiate rollback. Please try again.');
        return;
      }
      // No resourceId guard here: applyExclusionFilter validates resourceId and
      // returns a descriptive warning, so a checked box on a resource-less finding
      // surfaces that warning instead of a misleading plain-success message.
      if (shouldExcludeFromAutoRemediation) {
        const exclusionWarning = await applyExclusionFilter(
          rollbackItem,
          controls,
          createFilter,
          bulkEditControls,
          deleteFilter,
        );
        if (exclusionWarning) {
          // The rollback succeeded but the exclusion filter did not fully apply —
          // a partial success, surfaced through the warning channel, not success.
          resetState();
          setRollbackWarning(`Rollback initiated for finding ${findingId}, but ${exclusionWarning}`);
          onComplete();
          return;
        }
      }
      resetState();
      setRollbackSuccess(`Rollback initiated for finding ${findingId}.`);
      onComplete();
    } finally {
      setIsRollbackInProgress(false);
    }
  };

  return {
    pendingRollback,
    shouldExcludeFromAutoRemediation,
    setShouldExcludeFromAutoRemediation,
    rollbackError,
    setRollbackError,
    rollbackSuccess,
    setRollbackSuccess,
    rollbackWarning,
    setRollbackWarning,
    isRollbackInProgress,
    isPendingControlAutoRemediationEnabled,
    reRemediationEligibleDate,
    pendingControlLabel,
    handleRollbackClick,
    executeRollback,
    closeModal: resetState,
  };
}
