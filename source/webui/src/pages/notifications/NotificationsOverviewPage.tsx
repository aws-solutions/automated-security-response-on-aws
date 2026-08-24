// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { useCallback, useContext, useState, useMemo } from 'react';
import { Modal, Box, SpaceBetween, Button, Alert } from '@cloudscape-design/components';
import { useDispatch } from 'react-redux';

import NotificationsTable from './notifications-table/NotificationsTable.tsx';
import NotificationChannelForm from './notification-channel-form/NotificationChannelForm.tsx';
import EmailSubscriptionManagement from './EmailSubscriptionManagement.tsx';
import { TestNotificationDialog } from './test-notification-dialog/TestNotificationDialog.tsx';
import {
  NotificationConfigurationItem,
  CreateNotificationConfigurationRequest,
} from '../../store/controlPanelTypes.ts';
import { useFormModal } from '../../hooks/useFormModal.ts';
import { useDeleteConfirmation } from '../../hooks/useDeleteConfirmation.ts';
import {
  useGetNotificationConfigsQuery,
  useCreateNotificationConfigMutation,
  useUpdateNotificationConfigMutation,
  useDeleteNotificationConfigMutation,
  useToggleNotificationConfigMutation,
} from '../../store/notificationConfigApiSlice.ts';
import { useGetFiltersQuery } from '../../store/filtersApiSlice.ts';
import { useGetControlsQuery } from '../../store/controlsApiSlice.ts';
import { isFetchBaseQueryError, getErrorMessage } from '../../utils/error.ts';
import { addNotification, NotificationPayload } from '../../store/notificationsSlice.ts';
import { UserContext } from '../../contexts/UserContext.tsx';
import { canAccessControlPanel, canModifyNotificationConfig } from '../../utils/userPermissions.ts';

/**
 * Top-level page for the Notifications section.
 * Uses RTK Query for all CRUD operations.
 */
export const NotificationsOverviewPage = () => {
  const dispatch = useDispatch();
  const { groups: userGroups, email: userEmail } = useContext(UserContext);

  const canModifyConfig = useCallback(
    (config: NotificationConfigurationItem) => canModifyNotificationConfig(userGroups, userEmail, config),
    [userGroups, userEmail],
  );

  const notify = useCallback(
    (type: NotificationPayload['type'], content: string): void => {
      dispatch(addNotification({ type, content, id: `${type}-${crypto.randomUUID()}` }));
    },
    [dispatch],
  );

  const { data: configs = [], isLoading, refetch } = useGetNotificationConfigsQuery();
  const { data: resourceFilters = [] } = useGetFiltersQuery();
  const { data: controls = [] } = useGetControlsQuery();

  const [createConfig] = useCreateNotificationConfigMutation();
  const [updateConfig] = useUpdateNotificationConfigMutation();
  const [deleteConfig] = useDeleteNotificationConfigMutation();
  const [toggleConfig] = useToggleNotificationConfigMutation();

  const [isSubmitting, setIsSubmitting] = useState(false);

  const {
    formMode,
    editingItem: editingConfig,
    openCreateForm,
    openEditForm,
    closeForm,
  } = useFormModal<NotificationConfigurationItem>();
  const {
    deletingItem: deletingConfig,
    openDeleteConfirmation,
    cancelDelete,
    clearDeletingItem,
  } = useDeleteConfirmation<NotificationConfigurationItem>();

  const affectedControlIds = useMemo(() => {
    if (!deletingConfig) return [];
    return deletingConfig.controlIds ?? [];
  }, [deletingConfig]);

  const affectedResourceFilters = useMemo(() => {
    if (!deletingConfig) return [];
    const filterIds = deletingConfig.resourceFilterIds ?? [];
    if (filterIds.length === 0) return [];
    return resourceFilters.filter((f) => filterIds.includes(f.filterId));
  }, [deletingConfig, resourceFilters]);

  const [subscriptionConfig, setSubscriptionConfig] = useState<NotificationConfigurationItem | null>(null);
  const [testNotificationConfig, setTestNotificationConfig] = useState<NotificationConfigurationItem | null>(null);

  /* Toggle */
  const handleToggle = useCallback(
    async (configId: string, enabled: boolean) => {
      const config = configs.find((c) => c.configId === configId);
      if (!config) return;
      try {
        await toggleConfig({ configId, body: { enabled, version: config.version } }).unwrap();
        notify('success', `"${config.name}" ${enabled ? 'enabled' : 'disabled'} successfully.`);
      } catch {
        notify('error', `Failed to toggle "${config.name}".`);
      }
    },
    [configs, toggleConfig, notify],
  );

  /* Create / Edit */
  const handleFormSubmit = useCallback(
    async (input: CreateNotificationConfigurationRequest, version?: number) => {
      setIsSubmitting(true);
      try {
        if (formMode === 'create') {
          await createConfig(input).unwrap();
          notify('success', `"${input.name}" created successfully.`);
        } else if (formMode === 'edit' && editingConfig) {
          await updateConfig({
            configId: editingConfig.configId,
            body: { ...input, version: version ?? editingConfig.version },
          }).unwrap();
          notify('success', `"${input.name}" updated successfully.`);
        }
        closeForm();
      } catch (error: unknown) {
        if (isFetchBaseQueryError(error) && error.status === 409) {
          refetch();
          closeForm();
          notify('error', 'Data was modified by another user. Please reopen the configuration and try again.');
        } else {
          notify('error', `Failed to ${formMode} configuration: ${getErrorMessage(error) || 'Unknown error'}`);
        }
      } finally {
        setIsSubmitting(false);
      }
    },
    [formMode, editingConfig, createConfig, updateConfig, notify, closeForm, refetch],
  );

  /* Delete */
  const confirmDelete = async () => {
    if (!deletingConfig) return;
    const { name, configId } = deletingConfig;
    clearDeletingItem();
    try {
      await deleteConfig(configId).unwrap();
      notify('success', `"${name}" deleted successfully.`);
    } catch (error: unknown) {
      notify('error', `Failed to delete "${name}": ${getErrorMessage(error) || 'Unknown error'}`);
    }
  };

  /* Refresh */
  const [resetPagination, setResetPagination] = useState(false);
  const handleRefresh = useCallback(() => {
    refetch();
    setResetPagination(true);
    setTimeout(() => setResetPagination(false), 0);
  }, [refetch]);

  return (
    <>
      <NotificationsTable
        loading={isLoading}
        configs={configs}
        resourceFilters={resourceFilters}
        onRefresh={handleRefresh}
        onCreateConfig={openCreateForm}
        onEditConfig={openEditForm}
        onDeleteConfig={openDeleteConfirmation}
        onManageSubscriptions={setSubscriptionConfig}
        onSendTest={setTestNotificationConfig}
        onToggle={handleToggle}
        resetPagination={resetPagination}
        mutationInFlight={isSubmitting}
        canSendTest={canAccessControlPanel(userGroups)}
        canModifyConfig={canModifyConfig}
      />

      {testNotificationConfig && (
        <TestNotificationDialog
          config={testNotificationConfig}
          onClose={() => setTestNotificationConfig(null)}
          onEditConfig={(configId) => {
            setTestNotificationConfig(null);
            const config = configs.find((c) => c.configId === configId);
            if (config) openEditForm(config);
          }}
        />
      )}

      {formMode !== null && (
        <NotificationChannelForm
          mode={formMode}
          initialValues={formMode === 'edit' && editingConfig ? editingConfig : undefined}
          resourceFilters={resourceFilters}
          controls={controls}
          onSubmit={handleFormSubmit}
          onCancel={closeForm}
          isSubmitting={isSubmitting}
        />
      )}

      {subscriptionConfig && (
        <EmailSubscriptionManagement
          visible
          configId={subscriptionConfig.configId}
          configName={subscriptionConfig.name}
          onDismiss={() => setSubscriptionConfig(null)}
        />
      )}

      <Modal
        visible={deletingConfig !== null}
        onDismiss={cancelDelete}
        header="Delete notification configuration"
        footer={
          <Box float="right">
            <SpaceBetween direction="horizontal" size="xs">
              <Button variant="link" onClick={cancelDelete} data-testid="delete-cancel-button">
                Cancel
              </Button>
              <Button variant="primary" onClick={confirmDelete} data-testid="delete-confirm-button">
                Delete
              </Button>
            </SpaceBetween>
          </Box>
        }
      >
        <SpaceBetween size="m">
          <Box variant="p">
            Are you sure you want to delete <strong>{deletingConfig?.name}</strong>?
          </Box>

          {affectedControlIds.length > 0 && (
            <Alert type="warning" header="This notification is scoped to specific controls">
              <SpaceBetween size="s">
                <Box variant="p">
                  This notification configuration is applied to {affectedControlIds.length} security control
                  {affectedControlIds.length === 1 ? '' : 's'}. Deleting it will stop notifications for the following
                  controls:
                </Box>
                <ul style={{ margin: 0, paddingLeft: '20px' }}>
                  {affectedControlIds.slice(0, 10).map((id) => (
                    <li key={id}>{id}</li>
                  ))}
                  {affectedControlIds.length > 10 && <li>...and {affectedControlIds.length - 10} more</li>}
                </ul>
              </SpaceBetween>
            </Alert>
          )}

          {affectedResourceFilters.length > 0 && (
            <Alert type="warning" header="This notification uses resource filters">
              <SpaceBetween size="s">
                <Box variant="p">
                  This notification configuration references {affectedResourceFilters.length} resource filter
                  {affectedResourceFilters.length === 1 ? '' : 's'}:
                </Box>
                <ul style={{ margin: 0, paddingLeft: '20px' }}>
                  {affectedResourceFilters.slice(0, 10).map((f) => (
                    <li key={f.filterId}>{f.name}</li>
                  ))}
                  {affectedResourceFilters.length > 10 && <li>...and {affectedResourceFilters.length - 10} more</li>}
                </ul>
              </SpaceBetween>
            </Alert>
          )}
        </SpaceBetween>
      </Modal>
    </>
  );
};
