// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { useCallback, useState, useMemo, useContext } from 'react';
import { Modal, Box, SpaceBetween, Button, Alert } from '@cloudscape-design/components';
import { useDispatch } from 'react-redux';

import ResourceFiltersTable from './resource-filters-table/ResourceFiltersTable.tsx';
import ResourceFilterForm from './resource-filter-form/ResourceFilterForm.tsx';
import { BulkActionConfirmationModal } from './BulkActionConfirmationModal.tsx';
import { ResourceFilter, ResourceFilterInput, UpdateFilterRequest } from '@data-models';
import { useFormModal } from '../../hooks/useFormModal.ts';
import { useDeleteConfirmation } from '../../hooks/useDeleteConfirmation.ts';
import { useBulkActionMutation } from '../../hooks/useBulkActionMutation.ts';
import {
  useGetFiltersQuery,
  useCreateFilterMutation,
  useUpdateFilterMutation,
  useDeleteFilterMutation,
} from '../../store/filtersApiSlice.ts';
import { useGetControlsQuery } from '../../store/controlsApiSlice.ts';
import { useGetNotificationConfigsQuery } from '../../store/notificationConfigApiSlice.ts';
import { UserContext } from '../../contexts/UserContext.tsx';
import { canEditControls } from '../../utils/userPermissions.ts';
import { isFetchBaseQueryError, getErrorMessage } from '../../utils/error.ts';
import { addNotification, NotificationPayload } from '../../store/notificationsSlice.ts';

export const ResourceFiltersOverviewPage = () => {
  const { groups } = useContext(UserContext);
  const isReadOnly = !canEditControls(groups);
  const dispatch = useDispatch();

  const notify = useCallback(
    (type: NotificationPayload['type'], content: string): void => {
      dispatch(addNotification({ type, content, id: `${type}-${crypto.randomUUID()}` }));
    },
    [dispatch],
  );

  const { data: filters = [], isLoading: filtersLoading, refetch: refetchFilters } = useGetFiltersQuery();
  const { data: controls = [], isLoading: controlsLoading } = useGetControlsQuery();
  const { data: notificationConfigs = [] } = useGetNotificationConfigsQuery();

  const [createFilter] = useCreateFilterMutation();
  const [updateFilter] = useUpdateFilterMutation();
  const [deleteFilterMutation] = useDeleteFilterMutation();

  const [isSubmitting, setIsSubmitting] = useState(false);

  const withSubmitting = useCallback(async (fn: () => Promise<void>): Promise<void> => {
    setIsSubmitting(true);
    try {
      await fn();
    } finally {
      setIsSubmitting(false);
    }
  }, []);

  const {
    formMode,
    editingItem: editingFilter,
    openCreateForm,
    openEditForm,
    closeForm,
  } = useFormModal<ResourceFilter>();
  const {
    deletingItem: deletingFilter,
    openDeleteConfirmation,
    cancelDelete,
    clearDeletingItem,
  } = useDeleteConfirmation<ResourceFilter>();
  const {
    bulkActionFilter,
    bulkActionAffectedCount,
    handleApplyToAll,
    handleRemoveFromAll,
    closeBulkAction,
    confirmBulkAction,
  } = useBulkActionMutation({ controls, notify, withSubmitting });

  const affectedControls = useMemo(() => {
    if (!deletingFilter) return [];
    return controls.filter((c) => c.filters.includes(deletingFilter.filterId));
  }, [deletingFilter, controls]);

  const affectedNotifications = useMemo(() => {
    if (!deletingFilter) return [];
    return notificationConfigs.filter((c) => (c.resourceFilterIds ?? []).includes(deletingFilter.filterId));
  }, [deletingFilter, notificationConfigs]);

  const handleCreate = useCallback(
    async (input: ResourceFilterInput): Promise<void> => {
      await createFilter(input).unwrap();
      notify('success', `Resource filter "${input.name}" created successfully.`);
    },
    [createFilter, notify],
  );

  const handleEdit = useCallback(
    async (input: ResourceFilterInput): Promise<void> => {
      if (!editingFilter) return;
      const updateBody: UpdateFilterRequest = { ...input, version: editingFilter.version };
      await updateFilter({ filterId: editingFilter.filterId, body: updateBody }).unwrap();
      notify('success', `Resource filter "${input.name}" updated successfully.`);
    },
    [editingFilter, updateFilter, notify],
  );

  const handleFormSubmit = useCallback(
    async (input: ResourceFilterInput): Promise<void> => {
      await withSubmitting(async () => {
        try {
          if (formMode === 'create') {
            await handleCreate(input);
          } else if (formMode === 'edit') {
            await handleEdit(input);
          }
          closeForm();
        } catch (error: unknown) {
          if (isFetchBaseQueryError(error) && error.status === 409) {
            refetchFilters();
            closeForm();
            notify('error', 'Data was modified by another user. Please reopen the filter and try again.');
          } else {
            notify('error', `Failed to ${formMode} filter: ${getErrorMessage(error) || 'Unknown error'}`);
          }
        }
      });
    },
    [formMode, handleCreate, handleEdit, notify, closeForm, refetchFilters, withSubmitting],
  );

  const confirmDelete = useCallback(async (): Promise<void> => {
    if (!deletingFilter) return;
    const filterName = deletingFilter.name;
    const filterId = deletingFilter.filterId;
    await withSubmitting(async () => {
      try {
        await deleteFilterMutation(filterId).unwrap();
        notify('success', `Resource filter "${filterName}" deleted successfully.`);
      } catch (error: unknown) {
        notify('error', `Failed to delete filter "${filterName}": ${getErrorMessage(error) || 'Unknown error'}`);
      } finally {
        clearDeletingItem();
      }
    });
  }, [deletingFilter, deleteFilterMutation, clearDeletingItem, notify, withSubmitting]);

  const [resetPagination, setResetPagination] = useState(false);
  const handleRefresh = useCallback((): void => {
    refetchFilters();
    setResetPagination(true);
    setTimeout(() => setResetPagination(false), 0);
  }, [refetchFilters]);

  return (
    <>
      <ResourceFiltersTable
        loading={filtersLoading || controlsLoading}
        filters={filters}
        controls={controls}
        notificationConfigs={notificationConfigs}
        onRefresh={handleRefresh}
        onCreateFilter={openCreateForm}
        onEditFilter={openEditForm}
        onDeleteFilter={openDeleteConfirmation}
        onApplyToAll={handleApplyToAll}
        onRemoveFromAll={handleRemoveFromAll}
        resetPagination={resetPagination}
        mutationInFlight={isSubmitting}
        isReadOnly={isReadOnly}
      />

      {formMode !== null && (
        <ResourceFilterForm
          mode={formMode}
          initialValues={formMode === 'edit' && editingFilter ? editingFilter : undefined}
          onSubmit={handleFormSubmit}
          onCancel={closeForm}
          isSubmitting={isSubmitting}
        />
      )}

      {/* Delete confirmation modal */}
      <Modal
        visible={deletingFilter !== null}
        onDismiss={cancelDelete}
        header="Delete resource filter"
        footer={
          <Box float="right">
            <SpaceBetween direction="horizontal" size="xs">
              <Button variant="link" onClick={cancelDelete}>
                Cancel
              </Button>
              <Button variant="primary" onClick={confirmDelete} loading={isSubmitting}>
                Delete
              </Button>
            </SpaceBetween>
          </Box>
        }
      >
        <SpaceBetween size="m">
          <Box variant="p">
            Are you sure you want to delete the resource filter <strong>{deletingFilter?.name}</strong>?
          </Box>

          {affectedControls.length > 0 && (
            <Alert type="warning" header="This filter is currently in use">
              <SpaceBetween size="s">
                <Box variant="p">
                  This resource filter is applied to {affectedControls.length} security control
                  {affectedControls.length === 1 ? '' : 's'}. Deleting it will remove the filter from the following
                  controls:
                </Box>
                <ul style={{ margin: 0, paddingLeft: '20px' }}>
                  {affectedControls.slice(0, 10).map((c) => (
                    <li key={c.controlId}>{c.controlId}</li>
                  ))}
                  {affectedControls.length > 10 && <li>...and {affectedControls.length - 10} more</li>}
                </ul>
              </SpaceBetween>
            </Alert>
          )}

          {affectedNotifications.length > 0 && (
            <Alert type="warning" header="This filter is used by notifications">
              <SpaceBetween size="s">
                <Box variant="p">
                  This resource filter is referenced by {affectedNotifications.length} notification configuration
                  {affectedNotifications.length === 1 ? '' : 's'}. Deleting it will remove the filter from the following
                  notifications:
                </Box>
                <ul style={{ margin: 0, paddingLeft: '20px' }}>
                  {affectedNotifications.slice(0, 10).map((n) => (
                    <li key={n.configId}>{n.name}</li>
                  ))}
                  {affectedNotifications.length > 10 && <li>...and {affectedNotifications.length - 10} more</li>}
                </ul>
              </SpaceBetween>
            </Alert>
          )}
        </SpaceBetween>
      </Modal>

      <BulkActionConfirmationModal
        bulkActionFilter={bulkActionFilter}
        bulkActionAffectedCount={bulkActionAffectedCount}
        totalControlCount={controls.length}
        onConfirm={confirmBulkAction}
        onDismiss={closeBulkAction}
        isSubmitting={isSubmitting}
      />
    </>
  );
};
