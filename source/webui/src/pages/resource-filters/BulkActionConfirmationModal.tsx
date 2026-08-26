// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { Modal, Box, SpaceBetween, Button } from '@cloudscape-design/components';
import { ResourceFilter } from '@data-models';
import { BulkActionState } from '../../hooks/useBulkActionConfirmation.ts';

interface BulkActionConfirmationModalProps {
  bulkActionFilter: BulkActionState<ResourceFilter> | null;
  bulkActionAffectedCount: number;
  totalControlCount: number;
  onConfirm: () => void;
  onDismiss: () => void;
  isSubmitting: boolean;
}

export const BulkActionConfirmationModal = ({
  bulkActionFilter,
  bulkActionAffectedCount,
  totalControlCount,
  onConfirm,
  onDismiss,
  isSubmitting,
}: BulkActionConfirmationModalProps) => {
  const isApply = bulkActionFilter?.operation === 'applyFilterToAll';
  const alreadyAppliedCount = totalControlCount - bulkActionAffectedCount;

  return (
    <Modal
      visible={bulkActionFilter !== null}
      onDismiss={onDismiss}
      header={isApply ? 'Apply filter to all controls' : 'Remove filter from all controls'}
      footer={
        <Box float="right">
          <SpaceBetween direction="horizontal" size="xs">
            <Button variant="link" onClick={onDismiss}>
              Cancel
            </Button>
            <Button
              variant="primary"
              onClick={onConfirm}
              loading={isSubmitting}
              disabled={bulkActionAffectedCount === 0}
            >
              Confirm
            </Button>
          </SpaceBetween>
        </Box>
      }
    >
      {isApply ? (
        <Box variant="p">
          This will apply the filter <strong>{bulkActionFilter?.item.name}</strong> to {bulkActionAffectedCount} control
          {bulkActionAffectedCount === 1 ? '' : 's'} that don&apos;t already have it
          {alreadyAppliedCount > 0 ? ` (${alreadyAppliedCount} already applied)` : ''}. Continue?
        </Box>
      ) : (
        <Box variant="p">
          This will remove the filter <strong>{bulkActionFilter?.item.name}</strong> from {bulkActionAffectedCount}{' '}
          control
          {bulkActionAffectedCount === 1 ? '' : 's'}. Continue?
        </Box>
      )}
    </Modal>
  );
};
