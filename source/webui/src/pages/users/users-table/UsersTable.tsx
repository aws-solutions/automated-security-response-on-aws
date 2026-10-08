// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { useState, useEffect, useMemo, useContext } from 'react';

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
import { ToolPermissionsTable } from '../../../components/ToolPermissionsTable.tsx';
import { User, AccountOperatorUser } from '@data-models';

import { useDispatch } from 'react-redux';
import { addNotification } from '../../../store/notificationsSlice.ts';
import {
  useUpdateUserMutation,
  useDeleteUserMutation,
  useGetGrantableToolsQuery,
  usePutUserMcpToolsMutation,
} from '../../../store/usersApiSlice.ts';
import { UserContext } from '../../../contexts/UserContext.tsx';
import { isAdmin } from '../../../utils/userPermissions.ts';
import { getErrorMessage } from '../../../utils/error.ts';
import { parseAccountIds, validateAccountIds } from '../../../utils/validation.ts';

const getFilterCounterText = (count = 0) => `${count} ${count === 1 ? 'match' : 'matches'}`;

// Order-insensitive equality for string lists (account IDs, tool names).
const areArraysEqual = (a: string[], b: string[]): boolean => {
  if (a.length !== b.length) return false;
  const setA = new Set(a);
  const setB = new Set(b);
  return setA.size === setB.size && [...setA].every((x) => setB.has(x));
};

interface ManageUserSaveParams {
  selectedUser: User;
  hasAccountIdsChanged: boolean;
  hasToolsChanged: boolean;
  commitAccount: (user: AccountOperatorUser) => Promise<boolean>;
  commitTools: (user: User) => Promise<boolean>;
  onCommitted: () => void;
  onClose: () => void;
}

// Save orchestration for the manage-user modal, extracted from the component to keep the
// handler flat (Sonar S3776). Persists the two concerns the modal owns — an Account
// Operator's owned accounts and (Admin only) the MCP tool grant — writing each only when
// changed. The writes are sequential but independent: a committed account write still
// refreshes the table even if the tool write then fails. On a write failure the caller's
// per-mutation error effects surface the toast and close the modal, so the commit* fns
// only report whether the write committed.
const runManageUserSave = async ({
  selectedUser,
  hasAccountIdsChanged,
  hasToolsChanged,
  commitAccount,
  commitTools,
  onCommitted,
  onClose,
}: ManageUserSaveParams): Promise<void> => {
  if (!hasAccountIdsChanged && !hasToolsChanged) {
    onClose();
    return;
  }

  const isAccountCommitted =
    hasAccountIdsChanged && selectedUser.type === 'account-operator' ? await commitAccount(selectedUser) : false;
  if (hasAccountIdsChanged && !isAccountCommitted) return;

  const isToolsCommitted = hasToolsChanged ? await commitTools(selectedUser) : false;
  if (hasToolsChanged && !isToolsCommitted) {
    // A prior account write may already be committed; refresh so the table reflects it.
    if (isAccountCommitted) onCommitted();
    return;
  }

  onClose();
  onCommitted();
};
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

  // MCP tool permissions are Admin-only: the backend catalog endpoint (GET /mcp/tools)
  // is AdminGroup-only and 501s when MCP is disabled, so only fetch it — and only render
  // the table — for an Admin viewer. Firing the query for a non-Admin would just draw a
  // guaranteed 403/501.
  const { groups } = useContext(UserContext);
  const canEditToolPermissions = isAdmin(groups);
  const { data: grantableTools = [], isLoading: isLoadingTools } = useGetGrantableToolsQuery(undefined, {
    skip: !canEditToolPermissions,
  });
  const [putUserMcpTools, { isLoading: isSavingTools, error: putToolsError }] = usePutUserMcpToolsMutation();
  const [grantedTools, setGrantedTools] = useState<Set<string>>(new Set());

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

  // The catalog lists every tool an Admin can grant to anyone, tagged with the lowest tier
  // it reaches. PUT /users/{id}/mcp-tools rejects the whole grant if it names a tool above
  // the target's tier, so an Account Operator's table must not offer the Delegated
  // Admin-only tools at all: the "Minimum tier" column alone is advisory, and a category
  // holding both tiers would otherwise let one grant-all click build a set that cannot be
  // saved. Filtering here rather than inside ToolPermissionsTable keeps that component
  // presentational and keeps the tier rule next to the API contract it mirrors.
  const toolsGrantableToSelectedUser = useMemo(
    () =>
      selectedUser?.type === 'account-operator'
        ? grantableTools.filter((tool) => tool.tier === 'AccountOperator')
        : grantableTools,
    [grantableTools, selectedUser?.type],
  );

  // The tools currently granted to the selected user, read from the freshest copy in
  // the list. Only an Admin viewer sees the tool table (see renderToolPermissions); an
  // Admin *target* carries no stored grant since Admins receive every tool implicitly.
  const originalGrantedTools = useMemo(() => {
    if (!selectedUser?.email) return [];
    const currentUser = users?.find((user) => user.email === selectedUser.email);
    return currentUser?.allowedMcpTools ?? [];
  }, [users, selectedUser?.email]);

  // Whether the Account Operator's owned-accounts field differs from what is stored.
  // Lifted to render scope so both handleSave and the Save button's disabled gate use
  // the same signal: the button must block on a validation error only when the accounts
  // field is actually being written, not for a tools-only save.
  const hasAccountIdsChanged = useMemo(
    () =>
      selectedUser?.type === 'account-operator' &&
      !areArraysEqual(parseAccountIds(accountIds), parseAccountIds(originalAccountIds)),
    [selectedUser, accountIds, originalAccountIds],
  );

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

  // Seed the checkbox state when the modal opens, keyed by the selected user — not by
  // originalGrantedTools identity. That memo returns a fresh array on any `users`
  // reference change (e.g. a background refetch from an invalidatesTags), which would
  // otherwise re-fire this effect mid-edit and discard the user's in-progress toggles.
  // Matches how the sibling accountIds effect seeds from a primitive.
  useEffect(() => {
    if (isManageUserModalOpen) {
      setGrantedTools(new Set(originalGrantedTools));
    }
  }, [isManageUserModalOpen, selectedUser?.email]);

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

  const validationError = useMemo(() => {
    return validateAccountIds(accountIds);
  }, [accountIds]);

  // Applies one tool or a whole category in a single update, so granting a category
  // is one state transition rather than one per tool in it.
  const toggleToolGrant = (toolNames: readonly string[], granted: boolean) => {
    setGrantedTools((current) => {
      const next = new Set(current);
      toolNames.forEach((toolName) => {
        if (granted) {
          next.add(toolName);
        } else {
          next.delete(toolName);
        }
      });
      return next;
    });
  };

  // Write one Account Operator's owned accounts. Returns whether the write committed;
  // on failure the updateUserError effect surfaces the toast and closes the modal.
  const tryUpdateAccount = async (user: AccountOperatorUser): Promise<boolean> => {
    const result = await updateUser({
      type: user.type,
      email: user.email,
      accountIds: parseAccountIds(accountIds),
      status: user.status,
    });
    return 'data' in result;
  };

  // Write the user's MCP tool grant. Returns whether the write committed; on failure
  // the putToolsError effect surfaces the toast and closes the modal.
  //
  // The submitted set is intersected with the tools the target's tier can hold, mirroring
  // the same filter applied to the displayed catalog. A tool above the target's tier is
  // hidden from the table, so the Admin can neither see nor revoke it — without this
  // intersection such a tool would remain in grantedTools (seeded from the full stored
  // grant) and ride along on every save, which the PUT rejects for the whole grant.
  const tryUpdateTools = async (user: User): Promise<boolean> => {
    const grantableToolNames = new Set(toolsGrantableToSelectedUser.map((tool) => tool.name));
    const allowedTools = [...grantedTools].filter((toolName) => grantableToolNames.has(toolName));
    const result = await putUserMcpTools({ email: user.email, allowedTools });
    return 'data' in result;
  };

  // Persist the manage-user modal's edits via runManageUserSave, which keeps the branchy
  // orchestration out of the component. Success notification + table refresh happen once
  // any write commits; the per-mutation error effects handle failures.
  const handleSave = async () => {
    if (!selectedUser) return;

    const hasToolsChanged = canEditToolPermissions && !areArraysEqual([...grantedTools], originalGrantedTools);
    if (hasAccountIdsChanged && validationError) return;

    await runManageUserSave({
      selectedUser,
      hasAccountIdsChanged,
      hasToolsChanged,
      commitAccount: tryUpdateAccount,
      commitTools: tryUpdateTools,
      onCommitted: () => {
        dispatch(
          addNotification({
            type: 'success',
            content: 'User updated successfully',
            id: 'user-update-success',
          }),
        );
        onRefresh();
      },
      onClose: () => setIsManageUserModalOpen(false),
    });
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
    if (putToolsError) {
      dispatch(
        addNotification({
          type: 'error',
          content: `Failed to update tool permissions: ${getErrorMessage(putToolsError)}`,
          id: `tool-permissions-error-${Date.now()}`,
        }),
      );
      setIsManageUserModalOpen(false);
    }
  }, [updateUserError, deleteError, putToolsError, dispatch]);

  // The modal shows a Save button (rather than a plain Close) only when there is
  // something to persist: the target is not an Admin (Admins expose no editable
  // fields), AND either the viewer may edit tool permissions or the target is an
  // Account Operator whose owned accounts are editable.
  const isModalSaveable =
    !!selectedUser &&
    selectedUser.type !== 'admin' &&
    (canEditToolPermissions || selectedUser.type === 'account-operator');

  // The tool grant is Admin-managed and account-agnostic, so it applies to both
  // Account Operator and Delegated Admin targets. Managing grants is Admin-only, and the
  // catalog endpoint rejects non-Admins, so the table renders only for an Admin viewer;
  // for anyone else there is nothing to show or edit. Admins receive every tool
  // implicitly, so renderManageUser never reaches this for an Admin target.
  //
  // The label lives on the FormField rather than on the table, so this section's heading
  // renders in the same style as the form's other sections. The table itself carries no
  // header, so there is only one "Tool Permissions" heading.
  const renderToolPermissions = () => {
    if (!canEditToolPermissions) return null;
    return (
      <div className="form-section-divider">
        <FormField label="Tool Permissions">
          <ToolPermissionsTable
            tools={toolsGrantableToSelectedUser}
            grantedTools={grantedTools}
            onToggle={toggleToolGrant}
            loading={isLoadingTools}
          />
        </FormField>
      </div>
    );
  };

  const renderManageUserFormContent = () => {
    if (!selectedUser) return null;

    if (selectedUser.type === 'account-operator') {
      return (
        <SpaceBetween direction="vertical" size="xl">
          <FormField label="Permission Type">
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

          {renderToolPermissions()}

          <div className="form-section-divider">
            <FormField label="Remove User">
              <Button iconName="status-warning" variant="normal" onClick={handleDeleteUser}>
                Delete User
              </Button>
            </FormField>
          </div>
        </SpaceBetween>
      );
    }

    if (selectedUser.type === 'delegated-admin') {
      return (
        <SpaceBetween direction="vertical" size="xl">
          <FormField label="Permission Type">
            <Select
              selectedOption={{ label: 'Delegated Admin', value: 'delegated-admin' }}
              disabled
              options={[{ label: 'Delegated Admin', value: 'delegated-admin' }]}
            />
          </FormField>

          {renderToolPermissions()}

          <div className="form-section-divider">
            <FormField label="Remove User">
              <Button iconName="status-warning" variant="normal" onClick={handleDeleteUser}>
                Delete User
              </Button>
            </FormField>
          </div>
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
              {isModalSaveable ? (
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
                    loading={isLoading || isSavingTools}
                    disabled={hasAccountIdsChanged && !!validationError}
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
