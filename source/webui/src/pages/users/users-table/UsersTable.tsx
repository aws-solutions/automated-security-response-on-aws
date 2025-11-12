// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { useState, useEffect, useMemo } from 'react';

import { useCollection } from '@cloudscape-design/collection-hooks';
import CollectionPreferences, {
  CollectionPreferencesProps,
} from '@cloudscape-design/components/collection-preferences';
import Header from '@cloudscape-design/components/header';
import Table from '@cloudscape-design/components/table';
import Button from '@cloudscape-design/components/button';
import { Pagination, TextFilter, Modal, FormField, Select, Textarea } from '@cloudscape-design/components';
import Box from '@cloudscape-design/components/box';
import SpaceBetween from '@cloudscape-design/components/space-between';

import { createColumnDefinitions } from './createColumnDefinitions.tsx';
import { EmptyTableState } from '../../../components/EmptyTableState.tsx';
import { User, AccountOperatorUser } from '@data-models';

import { useDispatch } from 'react-redux';
import { addNotification } from '../../../store/notificationsSlice.ts';
import { useUpdateUserMutation, useDeleteUserMutation } from '../../../store/usersApiSlice.ts';
import { getErrorMessage } from '../../../utils/error.ts';
import { parseAccountIds, validateAccountIds } from '../../../utils/validation.ts';

const getFilterCounterText = (count = 0) => `${count} ${count === 1 ? 'match' : 'matches'}`;
const getHeaderCounterText = (items: readonly User[] | null = [], selectedItems: readonly User[] = []) => {
  const itemsLength = items?.length || 0;
  return selectedItems && selectedItems.length > 0 ? `(${selectedItems.length}/${itemsLength})` : `(${itemsLength})`;
};

const createPagination = (
  currentPageIndex: number,
  totalPages: number,
  setCurrentPageIndex: (page: number) => void,
) => (
  <Pagination
    onChange={({ detail }) => setCurrentPageIndex(detail.currentPageIndex)}
    onNextPageClick={() => setCurrentPageIndex(Math.min(currentPageIndex + 1, totalPages))}
    onPreviousPageClick={() => setCurrentPageIndex(Math.max(currentPageIndex - 1, 1))}
    pagesCount={totalPages}
    currentPageIndex={currentPageIndex}
  />
);

export interface UsersTableProps {
  users: User[] | null;
  loading: boolean;
  onRefresh: () => void;
  resetPagination?: boolean;
}

export default function UsersTable({ users, loading, onRefresh, resetPagination }: UsersTableProps) {
  const [preferences, setPreferences] = useState<CollectionPreferencesProps['preferences']>({
    pageSize: 20,
    wrapLines: true,
  });
  const [isManageUserModalOpen, setIsManageUserModalOpen] = useState(false);
  const [isDeleteModalOpen, setIsDeleteModalOpen] = useState(false);
  const [accountIds, setAccountIds] = useState('');
  const dispatch = useDispatch();
  const [updateUser, { isLoading, error: updateUserError, reset: resetUpdateUser }] = useUpdateUserMutation();
  const [deleteUser, { isLoading: isDeleting, error: deleteError, reset: resetDelete }] = useDeleteUserMutation();
  const columnDefinitions = createColumnDefinitions();

  const { items, filterProps, actions, filteredItemsCount, collectionProps } = useCollection<User>(
    Array.isArray(users) ? users : [],
    {
      filtering: {
        filteringFunction: (item, filteringText) => {
          const searchText = filteringText.toLowerCase();
          return item.email.toLowerCase().includes(searchText);
        },
        noMatch: (
          <EmptyTableState
            title="No matches"
            subtitle="We can't find a match."
            action={
              <Button onClick={() => actions.setFiltering('')} data-testid="clear-filter-button">
                Clear filter
              </Button>
            }
          />
        ),
        empty: <EmptyTableState title="No users" subtitle="No users to display." />,
      },
      sorting: { defaultState: { sortingColumn: columnDefinitions[0] } },
      selection: { trackBy: 'email' },
    },
  );

  const [currentPageIndex, setCurrentPageIndex] = useState(1);
  const selectedUser = collectionProps.selectedItems?.[0];

  const originalAccountIds = useMemo(() => {
    if (!selectedUser?.email || selectedUser.type !== 'account-operator') return '';

    const currentUser = users?.find((user) => user.email === selectedUser.email);
    return currentUser?.type === 'account-operator'
      ? (currentUser as AccountOperatorUser).accountIds?.join(', ') || ''
      : '';
  }, [users, selectedUser?.email]);

  useEffect(() => {
    if (resetPagination) {
      setCurrentPageIndex(1);
    }
  }, [resetPagination]);

  useEffect(() => {
    if (isManageUserModalOpen && selectedUser?.type === 'account-operator') {
      setAccountIds(originalAccountIds);
    }
  }, [isManageUserModalOpen, originalAccountIds]);

  const pageSize = preferences?.pageSize ?? 20;
  const totalPages = Math.ceil(items.length / pageSize);
  const startIndex = (currentPageIndex - 1) * pageSize;
  const endIndex = startIndex + pageSize;
  const paginatedItems = items.slice(startIndex, endIndex);

  const pagination = createPagination(currentPageIndex, totalPages, setCurrentPageIndex);

  const handleManageUser = () => {
    if (selectedUser) {
      resetUpdateUser();
      resetDelete();
      setIsManageUserModalOpen(true);
    }
  };

  const handleDeleteUser = () => {
    setIsDeleteModalOpen(true);
  };

  const confirmDeleteUser = async () => {
    if (!selectedUser) return;

    const result = await deleteUser(selectedUser.email);

    if ('data' in result) {
      dispatch(
        addNotification({
          type: 'success',
          content: 'User deleted successfully',
          id: 'user-delete-success',
        }),
      );

      setIsDeleteModalOpen(false);
      setIsManageUserModalOpen(false);
      onRefresh();
    }
  };

  const arraysEqual = (a: string[], b: string[]) => {
    if (a.length !== b.length) return false;
    const setA = new Set(a);
    const setB = new Set(b);
    return setA.size === setB.size && [...setA].every((x) => setB.has(x));
  };

  const validationError = useMemo(() => {
    return validateAccountIds(accountIds);
  }, [accountIds]);

  const handleSave = async () => {
    if (!selectedUser || selectedUser.type !== 'account-operator') return;

    const parsedNewAccountIds = parseAccountIds(accountIds);
    const parsedOriginalAccountIds = parseAccountIds(originalAccountIds);

    if (arraysEqual(parsedNewAccountIds, parsedOriginalAccountIds)) {
      setIsManageUserModalOpen(false);
      return;
    }

    const result = await updateUser({
      type: selectedUser.type,
      email: selectedUser.email,
      accountIds: parsedNewAccountIds,
      status: selectedUser.status,
    });

    if ('data' in result) {
      dispatch(
        addNotification({
          type: 'success',
          content: 'User updated successfully',
          id: 'user-update-success',
        }),
      );

      setIsManageUserModalOpen(false);
      onRefresh();
    }
  };

  useEffect(() => {
    if (updateUserError) {
      dispatch(
        addNotification({
          type: 'error',
          content: `Failed to update user: ${getErrorMessage(updateUserError)}`,
          id: `user-update-error-${Date.now()}`,
        }),
      );
      setIsManageUserModalOpen(false);
    }
    if (deleteError) {
      dispatch(
        addNotification({
          type: 'error',
          content: `Failed to delete user: ${getErrorMessage(deleteError)}`,
          id: `user-delete-error-${Date.now()}`,
        }),
      );
      setIsDeleteModalOpen(false);
      setIsManageUserModalOpen(false);
    }
  }, [updateUserError, deleteError, dispatch]);

  const renderManageUserFormContent = () => {
    if (!selectedUser) return null;

    if (selectedUser.type === 'account-operator') {
      return (
        <SpaceBetween direction="vertical" size="xl">
          <FormField label="Permission Type" description="What level of access does this user have?">
            <Select
              selectedOption={{ label: 'Account Operator', value: 'account-operator' }}
              disabled
              options={[{ label: 'Account Operator', value: 'account-operator' }]}
            />
          </FormField>

          <FormField
            label="Owned Accounts"
            description="Modify the list of Account IDs for which the user should have remediation access."
            errorText={validationError}
          >
            <Textarea
              value={accountIds}
              onChange={({ detail }) => setAccountIds(detail.value)}
              rows={3}
              invalid={!!validationError}
              data-testid="owned-accounts-form-field"
            />
          </FormField>

          <FormField
            label="Remove User"
            description={`Revoke access for ${selectedUser.email}. This action cannot be undone.`}
          >
            <Button iconName="status-warning" variant="normal" onClick={handleDeleteUser}>
              Delete User
            </Button>
          </FormField>
        </SpaceBetween>
      );
    }

    if (selectedUser.type === 'delegated-admin') {
      return (
        <SpaceBetween direction="vertical" size="xl">
          <FormField label="Permission Type" description="What level of access does this user have?">
            <Select
              selectedOption={{ label: 'Delegated Admin', value: 'delegated-admin' }}
              disabled
              options={[{ label: 'Delegated Admin', value: 'delegated-admin' }]}
            />
          </FormField>

          <FormField
            label="Remove User"
            description={`Revoke access for ${selectedUser.email}. This action cannot be undone.`}
          >
            <Button iconName="status-warning" variant="normal" onClick={handleDeleteUser}>
              Delete User
            </Button>
          </FormField>
        </SpaceBetween>
      );
    }

    return null;
  };

  return (
    <>
      <Modal
        visible={isDeleteModalOpen}
        onDismiss={() => setIsDeleteModalOpen(false)}
        header="Delete User"
        closeAriaLabel="Close modal"
        footer={
          <Box float="right">
            <SpaceBetween direction="horizontal" size="xs">
              <Button variant="link" onClick={() => setIsDeleteModalOpen(false)}>
                Cancel
              </Button>
              <Button variant="primary" onClick={confirmDeleteUser} loading={isDeleting}>
                Delete
              </Button>
            </SpaceBetween>
          </Box>
        }
      >
        <SpaceBetween direction="vertical" size="m">
          <Box variant="p">
            Are you sure you want to delete user <strong>{selectedUser?.email}</strong>? This action cannot be undone.
          </Box>
        </SpaceBetween>
      </Modal>
      <Modal
        visible={isManageUserModalOpen && !isDeleteModalOpen}
        onDismiss={() => setIsManageUserModalOpen(false)}
        header={`Manage User ${selectedUser?.email || ''}`}
        data-testid="manage-user-modal"
        closeAriaLabel="Close modal"
        footer={
          <Box float="right">
            <SpaceBetween direction="horizontal" size="xs">
              {selectedUser?.type === 'account-operator' ? (
                <>
                  <Button
                    data-testid="cancel-manage-user-button"
                    variant="link"
                    onClick={() => setIsManageUserModalOpen(false)}
                  >
                    Cancel
                  </Button>
                  <Button
                    variant="primary"
                    onClick={handleSave}
                    loading={isLoading}
                    disabled={!!validationError}
                    data-testid="manage-user-save-button"
                  >
                    Save
                  </Button>
                </>
              ) : (
                <Button
                  variant="primary"
                  onClick={() => setIsManageUserModalOpen(false)}
                  data-testid="close-manage-user-button"
                >
                  Close
                </Button>
              )}
            </SpaceBetween>
          </Box>
        }
      >
        {renderManageUserFormContent()}
      </Modal>
      <Table<User>
        items={paginatedItems}
        loading={loading}
        loadingText="Loading users"
        columnDefinitions={columnDefinitions}
        stickyHeader
        stripedRows
        contentDensity={'comfortable'}
        variant="full-page"
        selectionType="single"
        isItemDisabled={(item) => item.type !== 'account-operator' && item.type !== 'delegated-admin'}
        ariaLabels={{
          selectionGroupLabel: 'Users selection',
          tableLabel: 'Users table',
        }}
        empty={<EmptyTableState title="No users" subtitle="No users to display." />}
        filter={
          <TextFilter
            {...filterProps}
            filteringPlaceholder="Search by User ID..."
            countText={getFilterCounterText(filteredItemsCount)}
          />
        }
        header={
          <Header
            variant="awsui-h1-sticky"
            counter={getHeaderCounterText(users, collectionProps.selectedItems)}
            actions={
              <SpaceBetween direction="horizontal" size="xs">
                <Button iconName="refresh" onClick={onRefresh} loading={loading} data-testid="refresh-button" />
                <Button
                  variant="primary"
                  disabled={!selectedUser}
                  onClick={handleManageUser}
                  data-testid="manage-user-button"
                >
                  Manage User
                </Button>
              </SpaceBetween>
            }
            description="View existing and invited users for the Automated Security Response on AWS UI. Note: Delegated Admin users can only view and manage Account Operator users."
          >
            Users
          </Header>
        }
        preferences={
          <CollectionPreferences
            preferences={preferences}
            pageSizePreference={{
              title: 'Select page size',
              options: [
                { value: 10, label: '10 users' },
                { value: 20, label: '20 users' },
                { value: 50, label: '50 users' },
                { value: 100, label: '100 users' },
              ],
            }}
            onConfirm={({ detail }) => {
              setPreferences(detail);
              setCurrentPageIndex(1); // Reset to first page when page size changes
            }}
            title="Preferences"
            confirmLabel="Confirm"
            cancelLabel="Cancel"
          />
        }
        pagination={pagination}
        {...collectionProps}
      />
    </>
  );
}
