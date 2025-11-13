// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { render } from '@testing-library/react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import createWrapper, { TableWrapper } from '@cloudscape-design/components/test-utils/dom';
import { Provider } from 'react-redux';
import { http } from 'msw';
import UsersTable from '../../pages/users/users-table/UsersTable';
import { User } from '@data-models';
import { generateTestUsers } from '../test-data-factory';
import { setupStore } from '../../store/store';
import { server, MOCK_SERVER_URL } from '../server';
import { ApiEndpoints } from '../../store/solutionApi';
import { ok } from '../../mocks/handlers';

const mockRefresh = vi.fn();

const findRowByUserType = (table: TableWrapper | null, userType: string): number => {
  const rows = table?.findRows();
  const index = rows?.findIndex((row: any) => row.getElement().textContent?.includes(userType));
  assert(
    index !== undefined && index !== -1,
    `could not find row for userType ${userType}, check that mock users are generated correctly.`,
  );

  return index + 1; // rows in cloudscape findRowSelectionArea are 1-indexed
};

const renderWithProvider = (component: React.ReactElement) => {
  const store = setupStore();
  return {
    store,
    ...render(<Provider store={store}>{component}</Provider>),
  };
};

describe('UsersTable', () => {
  beforeEach(() => {
    // ARRANGE - Reset mocks
    mockRefresh.mockClear();
  });

  it('should handle null users prop without crashing', () => {
    // ARRANGE
    const nullUsers = null as any;

    // ACT
    const renderResult = () =>
      renderWithProvider(<UsersTable users={nullUsers} loading={false} onRefresh={mockRefresh} />);

    // ASSERT
    expect(renderResult).not.toThrow();
  });

  it('should handle empty users array', () => {
    // ARRANGE
    const emptyUsers: User[] = [];

    // ACT
    renderWithProvider(<UsersTable users={emptyUsers} loading={false} onRefresh={mockRefresh} />);
    const wrapper = createWrapper(document.body);

    // ASSERT
    const header = wrapper.findHeader();
    expect(header?.getElement()).toHaveTextContent('Users');
    expect(header?.getElement()).toHaveTextContent('(0)');
    const table = wrapper.findTable();
    expect(table?.getElement()).toHaveTextContent('No users to display.');
  });

  it('should display correct counter for users array', () => {
    // ARRANGE
    const users = generateTestUsers(1);

    // ACT
    renderWithProvider(<UsersTable users={users} loading={false} onRefresh={mockRefresh} />);
    const wrapper = createWrapper(document.body);

    // ASSERT
    const header = wrapper.findHeader();
    expect(header?.getElement()).toHaveTextContent('Users');
    expect(header?.getElement()).toHaveTextContent('(1)');
  });

  it('should display loading state', () => {
    // ARRANGE
    const users = generateTestUsers(3);

    // ACT
    renderWithProvider(<UsersTable users={users} loading={true} onRefresh={mockRefresh} />);
    const wrapper = createWrapper(document.body);

    // ASSERT
    const table = wrapper.findTable();
    expect(table?.getElement()).toHaveTextContent('Loading users');
  });

  it('should display users in table', () => {
    // ARRANGE
    const users = generateTestUsers(2);

    // ACT
    renderWithProvider(<UsersTable users={users} loading={false} onRefresh={mockRefresh} />);
    const wrapper = createWrapper(document.body);

    // ASSERT
    const table = wrapper.findTable();
    expect(table).toBeTruthy();
    expect(table?.getElement()).toHaveTextContent(users[0].email);
    expect(table?.getElement()).toHaveTextContent(users[1].email);
    expect(table?.getElement()).toHaveTextContent('Confirmed');
    expect(table?.getElement()).toHaveTextContent('Invited');
  });

  it('should filter users by email', () => {
    // ARRANGE
    const users = generateTestUsers(3);

    // ACT
    renderWithProvider(<UsersTable users={users} loading={false} onRefresh={mockRefresh} />);
    const wrapper = createWrapper(document.body);

    const table = wrapper.findTable();
    const textFilter = table?.findTextFilter();
    textFilter?.findInput().setInputValue('user0');

    // ASSERT
    const rows = table?.findRows();
    expect(rows).toHaveLength(1); // 1 matching user
    expect(table?.getElement()).toHaveTextContent('user0@example.com');
    expect(table?.getElement()).not.toHaveTextContent('delegated1@example.com');
    expect(textFilter?.getElement()).toHaveTextContent('1 match');
  });

  it('should show no matches message when filter has no results & clear filter when button is clicked', () => {
    // ARRANGE
    const users = generateTestUsers(2);

    // ACT
    renderWithProvider(<UsersTable users={users} loading={false} onRefresh={mockRefresh} />);
    const wrapper = createWrapper(document.body);

    const table = wrapper.findTable();
    const textFilter = table?.findTextFilter();
    textFilter?.findInput().setInputValue('nonexistent');

    // ASSERT
    expect(table?.getElement()).toHaveTextContent('No matches');
    expect(table?.getElement()).toHaveTextContent("We can't find a match.");

    const clearButton = wrapper.findButton('[data-testid="clear-filter-button"]');
    expect(clearButton).toBeTruthy();

    // ACT
    clearButton?.click();

    // ASSERT
    const rows = table?.findRows();
    expect(rows).toHaveLength(2); // 2 users
  });

  it('should call onRefresh when refresh button is clicked', () => {
    // ARRANGE
    const users = generateTestUsers(1);

    // ACT
    renderWithProvider(<UsersTable users={users} loading={false} onRefresh={mockRefresh} />);
    const wrapper = createWrapper(document.body);

    const refreshButton = wrapper.findButton('[data-testid="refresh-button"]');
    refreshButton?.click();

    // ASSERT
    expect(mockRefresh).toHaveBeenCalledTimes(1);
  });

  it('should display manage user button', () => {
    // ARRANGE
    const users = generateTestUsers(1);

    // ACT
    renderWithProvider(<UsersTable users={users} loading={false} onRefresh={mockRefresh} />);
    const wrapper = createWrapper(document.body);

    // ASSERT
    const manageButton = wrapper.findButton('[data-testid="manage-user-button"]');
    expect(manageButton).toBeTruthy();
  });

  it('should display correct column headers', () => {
    // ARRANGE
    const users = generateTestUsers(1);

    // ACT
    renderWithProvider(<UsersTable users={users} loading={false} onRefresh={mockRefresh} />);
    const wrapper = createWrapper(document.body);

    // ASSERT
    const table = wrapper.findTable();
    expect(table?.getElement()).toHaveTextContent('User ID');
    expect(table?.getElement()).toHaveTextContent('Status');
    expect(table?.getElement()).toHaveTextContent('Permission Type');
    expect(table?.getElement()).toHaveTextContent('Invited By');
    expect(table?.getElement()).toHaveTextContent('Invitation Timestamp');
  });

  it('should format invitation timestamp correctly', () => {
    // ARRANGE
    const testDate = new Date('2023-01-01T12:00:00Z');
    const users: User[] = [
      {
        email: 'test@example.com',
        invitedBy: 'admin@example.com',
        invitationTimestamp: testDate.toISOString(),
        status: 'Confirmed',
        type: 'admin',
      },
    ];

    // ACT
    renderWithProvider(<UsersTable users={users} loading={false} onRefresh={mockRefresh} />);
    const wrapper = createWrapper(document.body);

    // ASSERT
    const table = wrapper.findTable();
    expect(table?.getElement()).toHaveTextContent(testDate.toLocaleString());
  });

  it('should paginate results with default page size of 20', () => {
    // ARRANGE
    const users = generateTestUsers(25);

    // ACT
    renderWithProvider(<UsersTable users={users} loading={false} onRefresh={mockRefresh} />);
    const wrapper = createWrapper(document.body);

    // ASSERT
    const table = wrapper.findTable();
    const rows = table!.findRows();
    expect(rows).toHaveLength(20);

    const pagination = wrapper.findPagination();
    expect(pagination).toBeTruthy();
  });

  it('should navigate to next page when next button is clicked', () => {
    // ARRANGE
    const users = generateTestUsers(25);

    // ACT
    renderWithProvider(<UsersTable users={users} loading={false} onRefresh={mockRefresh} />);
    const wrapper = createWrapper(document.body);

    const pagination = wrapper.findPagination();
    const nextButton = pagination!.findNextPageButton();
    nextButton!.click();

    // ASSERT
    const table = wrapper.findTable();
    const rows = table!.findRows();
    expect(rows).toHaveLength(5); // 5 remaining users on page 2
  });

  it('should respect page size preference changes', () => {
    // ARRANGE
    const users = generateTestUsers(15);

    // ACT
    renderWithProvider(<UsersTable users={users} loading={false} onRefresh={mockRefresh} />);
    const wrapper = createWrapper(document.body);

    const preferences = wrapper.findCollectionPreferences();
    preferences!.findTriggerButton().click();

    const modal = preferences!.findModal();
    const radioGroup = modal!.findContent()!.findRadioGroup();
    radioGroup!.findInputByValue('10')!.click();

    const buttons = modal!.findFooter()!.findAllButtons();
    const confirmButton = buttons.find((button) => button.getElement().textContent === 'Confirm');
    confirmButton!.click();

    // ASSERT
    const updatedWrapper = createWrapper(document.body);
    const table = updatedWrapper.findTable();
    const rows = table!.findRows();
    expect(rows).toHaveLength(10);
  });

  it('should show correct pagination info for multiple pages', () => {
    // ARRANGE
    const users = generateTestUsers(50);

    // ACT
    renderWithProvider(<UsersTable users={users} loading={false} onRefresh={mockRefresh} />);
    const wrapper = createWrapper(document.body);

    // ASSERT
    const pagination = wrapper.findPagination();
    expect(pagination!.findCurrentPage().getElement()).toHaveTextContent('1');
    expect(pagination!.findPageNumbers()).toHaveLength(3); // Pages 1, 2, 3
  });

  it('should disable previous button on first page', () => {
    // ARRANGE
    const users = generateTestUsers(25);

    // ACT
    renderWithProvider(<UsersTable users={users} loading={false} onRefresh={mockRefresh} />);
    const wrapper = createWrapper(document.body);

    // ASSERT
    const pagination = wrapper.findPagination();
    const prevButton = pagination!.findPreviousPageButton();
    expect(prevButton!.getElement()).toBeDisabled();
  });

  it('should disable next button on last page', () => {
    // ARRANGE
    const users = generateTestUsers(25);

    // ACT
    renderWithProvider(<UsersTable users={users} loading={false} onRefresh={mockRefresh} />);
    const wrapper = createWrapper(document.body);

    const pagination = wrapper.findPagination();
    const nextButton = pagination!.findNextPageButton();
    nextButton!.click(); // Go to page 2 (last page)

    // ASSERT
    expect(nextButton!.getElement()).toBeDisabled();
  });

  it('should disable manage user button when no user is selected', () => {
    // ARRANGE
    const users = generateTestUsers(2);

    // ACT
    renderWithProvider(<UsersTable users={users} loading={false} onRefresh={mockRefresh} />);
    const wrapper = createWrapper(document.body);

    // ASSERT
    const manageButton = wrapper.findButton('[data-testid="manage-user-button"]');
    expect(manageButton?.getElement()).toBeDisabled();
  });

  it('should enable manage user button when user is selected', () => {
    // ARRANGE
    const users = generateTestUsers(2);

    // ACT
    renderWithProvider(<UsersTable users={users} loading={false} onRefresh={mockRefresh} />);
    const wrapper = createWrapper(document.body);

    const table = wrapper.findTable();
    table!.findRowSelectionArea(1)!.click();

    // ASSERT
    const manageButton = wrapper.findButton('[data-testid="manage-user-button"]');
    expect(manageButton?.getElement()).not.toBeDisabled();
  });

  it('should open modal when manage user button is clicked', () => {
    // ARRANGE
    const users = generateTestUsers(1);

    // ACT
    renderWithProvider(<UsersTable users={users} loading={false} onRefresh={mockRefresh} />);
    const wrapper = createWrapper(document.body);

    const table = wrapper.findTable();
    table!.findRowSelectionArea(1)!.click();

    const manageButton = wrapper.findButton('[data-testid="manage-user-button"]');
    manageButton?.click();

    // ASSERT
    const modal = wrapper.findModal('[data-testid="manage-user-modal"]');
    expect(modal?.isVisible()).toBe(true);
  });

  it('should display account operator modal content correctly', () => {
    // ARRANGE
    const users = generateTestUsers(1);

    // ACT
    renderWithProvider(<UsersTable users={users} loading={false} onRefresh={mockRefresh} />);
    const wrapper = createWrapper(document.body);

    const table = wrapper.findTable();
    table!.findRowSelectionArea(1)!.click();

    const manageButton = wrapper.findButton('[data-testid="manage-user-button"]');
    manageButton?.click();

    // ASSERT
    const modal = wrapper.findModal('[data-testid="manage-user-modal"]');
    expect(modal?.getElement()).toHaveTextContent('Permission Type');
    expect(modal?.getElement()).toHaveTextContent('Account Operator');
    expect(modal?.getElement()).toHaveTextContent('Owned Accounts');
    expect(modal?.getElement()).toHaveTextContent('Remove User');
    const cancelButton = wrapper.findButton('[data-testid="cancel-manage-user-button"]');
    const saveButton = wrapper.findButton('[data-testid="manage-user-save-button"]');
    expect(cancelButton).toBeTruthy();
    expect(saveButton).toBeTruthy();
    const textarea = wrapper.findTextarea('[data-testid="owned-accounts-form-field"]');
    expect(textarea?.getTextareaValue()).toBe('123456789012, 123456789013');
  });

  it('should display delegated admin modal content correctly', () => {
    // ARRANGE
    const users = generateTestUsers(2);

    // ACT
    renderWithProvider(<UsersTable users={users} loading={false} onRefresh={mockRefresh} />);
    const wrapper = createWrapper(document.body);

    const table = wrapper.findTable();
    const rowIndex = findRowByUserType(table, 'delegated-admin');
    table!.findRowSelectionArea(rowIndex)!.click();

    const manageButton = wrapper.findButton('[data-testid="manage-user-button"]');
    manageButton?.click();

    // ASSERT
    const modal = wrapper.findModal('[data-testid="manage-user-modal"]');
    expect(modal?.getElement()).toHaveTextContent('Permission Type');
    expect(modal?.getElement()).toHaveTextContent('Delegated Admin');
    expect(modal?.getElement()).toHaveTextContent('Remove User');
    expect(modal?.getElement()).not.toHaveTextContent('Owned Accounts');
    const cancelButton = wrapper.findButton('[data-testid="cancel-manage-user-button"]');
    const saveButton = wrapper.findButton('[data-testid="manage-user-save-button"]');
    const closeButton = wrapper.findButton('[data-testid="close-manage-user-button"]');
    expect(cancelButton).toBeFalsy();
    expect(saveButton).toBeFalsy();
    expect(closeButton).toBeTruthy();
  });

  it('should close manage user modal when cancel button is clicked', async () => {
    // ARRANGE
    const users = generateTestUsers(1);

    // ACT
    renderWithProvider(<UsersTable users={users} loading={false} onRefresh={mockRefresh} />);
    const wrapper = createWrapper(document.body);

    const table = wrapper.findTable();
    const rowIndex = findRowByUserType(table, 'account-operator');
    table!.findRowSelectionArea(rowIndex)!.click();

    const manageButton = wrapper.findButton('[data-testid="manage-user-button"]');
    manageButton?.click();

    const modalWrapper = wrapper.findModal('[data-testid="manage-user-modal"]')!;

    const cancelManageUserButton = wrapper.findButton('[data-testid="cancel-manage-user-button"]');

    cancelManageUserButton?.click();

    expect(modalWrapper.isVisible()).toBe(false);
  });

  it('should close manage user modal when close button is clicked for delegated admin', async () => {
    // ARRANGE
    const users = generateTestUsers(2);

    // ACT
    renderWithProvider(<UsersTable users={users} loading={false} onRefresh={mockRefresh} />);
    const wrapper = createWrapper(document.body);

    const table = wrapper.findTable();
    const rowIndex = findRowByUserType(table, 'delegated-admin');
    table!.findRowSelectionArea(rowIndex)!.click();

    const manageButton = wrapper.findButton('[data-testid="manage-user-button"]');
    manageButton?.click();

    const modalWrapper = wrapper.findModal('[data-testid="manage-user-modal"]')!;

    const closeManageUserButton = wrapper.findButton('[data-testid="close-manage-user-button"]');

    closeManageUserButton?.click();

    // ASSERT
    expect(modalWrapper.isVisible()).toBe(false);
  });

  it('should validate account IDs and show error for invalid input', () => {
    // ARRANGE
    const users = generateTestUsers(1);

    // ACT
    renderWithProvider(<UsersTable users={users} loading={false} onRefresh={mockRefresh} />);
    const wrapper = createWrapper(document.body);

    const table = wrapper.findTable();
    table!.findRowSelectionArea(1)!.click();

    const manageButton = wrapper.findButton('[data-testid="manage-user-button"]');
    manageButton?.click();

    const textarea = wrapper.findTextarea('[data-testid="owned-accounts-form-field"]');
    const modal = wrapper.findModal('[data-testid="manage-user-modal"]');
    const saveButton = wrapper.findButton('[data-testid="manage-user-save-button"]');

    // ACT - Test empty account IDs
    textarea?.setTextareaValue('');

    // ASSERT - Validate error message for empty input
    expect(modal?.getElement()).toHaveTextContent('Please enter at least one account ID.');
    expect(saveButton?.getElement()).toBeDisabled();

    // ACT - invalid account ID
    textarea?.setTextareaValue('invalid-account-id');

    // ASSERT
    expect(modal?.getElement()).toHaveTextContent(
      'Invalid account IDs. Each account ID must be exactly 12 digits separated by commas.',
    );
    expect(saveButton?.getElement()).toBeDisabled();
  });

  it('should enable save button for valid account IDs', () => {
    // ARRANGE
    const users = generateTestUsers(1);

    // ACT
    renderWithProvider(<UsersTable users={users} loading={false} onRefresh={mockRefresh} />);
    const wrapper = createWrapper(document.body);

    const table = wrapper.findTable();
    table!.findRowSelectionArea(1)!.click();

    const manageButton = wrapper.findButton('[data-testid="manage-user-button"]');
    manageButton?.click();

    const textarea = wrapper.findTextarea('[data-testid="owned-accounts-form-field"]');
    textarea?.setTextareaValue('123456789012, 123456789013');

    // ASSERT
    const saveButton = wrapper.findButton('[data-testid="manage-user-save-button"]');
    expect(saveButton?.getElement()).not.toBeDisabled();
  });

  it('should close manage user modal without saving when account IDs are unchanged', async () => {
    // ARRANGE
    const users = generateTestUsers(1);

    // ACT
    renderWithProvider(<UsersTable users={users} loading={false} onRefresh={mockRefresh} />);
    const wrapper = createWrapper(document.body);

    const table = wrapper.findTable();
    const rowIndex = findRowByUserType(table, 'account-operator');
    table!.findRowSelectionArea(rowIndex)!.click();

    const manageButton = wrapper.findButton('[data-testid="manage-user-button"]');
    manageButton?.click();

    const modalWrapper = wrapper.findModal('[data-testid="manage-user-modal"]')!;

    const saveButton = wrapper.findButton('[data-testid="manage-user-save-button"]');
    saveButton?.click();

    expect(modalWrapper.isVisible()).toBe(false);
  });

  it('should send new account IDs from form field in API request when updating user', async () => {
    // ARRANGE
    const users = generateTestUsers(1);
    const newAccountIds = ['999999999999', '888888888888'];
    let capturedRequest: any = null;

    server.use(
      http.put(`${MOCK_SERVER_URL}${ApiEndpoints.USERS}/:email`, async ({ request }) => {
        capturedRequest = await request.json();
        return await ok({});
      }),
    );

    // ACT
    const { store } = renderWithProvider(<UsersTable users={users} loading={false} onRefresh={mockRefresh} />);
    const wrapper = createWrapper(document.body);

    const table = wrapper.findTable();
    table!.findRowSelectionArea(1)!.click();

    const manageButton = wrapper.findButton('[data-testid="manage-user-button"]');
    manageButton?.click();

    const textarea = wrapper.findTextarea('[data-testid="owned-accounts-form-field"]');
    textarea?.setTextareaValue(newAccountIds.join(', '));

    const saveButton = wrapper.findButton('[data-testid="manage-user-save-button"]');
    saveButton?.click();

    // ASSERT
    await vi.waitFor(() => {
      expect(capturedRequest).toBeDefined();
      expect(capturedRequest.accountIds).toEqual(newAccountIds);
    });
    await vi.waitFor(() => {
      const state = store.getState();
      const successNotification = state.notifications.notifications.find((n) => n.type === 'success');
      expect(successNotification).toBeDefined();
    });
  });

  it('should update account IDs form when user data changes', () => {
    // ARRANGE
    const initialUsers = generateTestUsers(1);
    const updatedUsers = [
      {
        ...initialUsers[0],
        accountIds: ['999999999999', '888888888888'],
      },
    ];

    // ACT
    const store = setupStore();
    const { rerender } = render(
      <Provider store={store}>
        <UsersTable users={initialUsers} loading={false} onRefresh={mockRefresh} />
      </Provider>,
    );
    const wrapper = createWrapper(document.body);

    const table = wrapper.findTable();
    table!.findRowSelectionArea(1)!.click();

    const manageButton = wrapper.findButton('[data-testid="manage-user-button"]');
    manageButton?.click();

    // Simulate data refresh
    rerender(
      <Provider store={store}>
        <UsersTable users={updatedUsers} loading={false} onRefresh={mockRefresh} />
      </Provider>,
    );

    // ASSERT
    const textarea = wrapper.findTextarea('[data-testid="owned-accounts-form-field"]');
    expect(textarea?.getTextareaValue()).toBe('999999999999, 888888888888');
  });

  it('should display error alert when user update fails', async () => {
    // ARRANGE
    const users = generateTestUsers(1);
    let capturedRequest: any = null;
    server.use(
      http.put(
        `${MOCK_SERVER_URL}${ApiEndpoints.USERS}/:email`,
        async ({ request }) => {
          capturedRequest = await request.json();
          return Response.json({ message: 'first failure' }, { status: 400 });
        },
        { once: true },
      ),
      http.put(
        `${MOCK_SERVER_URL}${ApiEndpoints.USERS}/:email`,
        async ({ request }) => {
          capturedRequest = await request.json();
          return Response.json({ message: 'second failure' }, { status: 400 });
        },
        { once: true },
      ),
    );

    // ACT
    const { store } = renderWithProvider(<UsersTable users={users} loading={false} onRefresh={mockRefresh} />);
    const wrapper = createWrapper(document.body);

    const table = wrapper.findTable();
    table!.findRowSelectionArea(1)!.click();

    let manageButton = wrapper.findButton('[data-testid="manage-user-button"]');
    manageButton?.click();

    const modal = wrapper.findModal('[data-testid="manage-user-modal"]')!;

    let textarea = wrapper.findTextarea('[data-testid="owned-accounts-form-field"]');
    textarea?.setTextareaValue('999999999999');

    let saveButton = wrapper.findButton('[data-testid="manage-user-save-button"]');
    saveButton?.click();

    // ASSERT
    await vi.waitFor(() => {
      expect(capturedRequest).toBeDefined();
      expect(capturedRequest.accountIds).toEqual(['999999999999']);
    });
    await vi.waitFor(() => {
      const state = store.getState();
      const notifications = state.notifications.notifications;
      expect(notifications).toHaveLength(1);
      expect(notifications[0]).toEqual(
        expect.objectContaining({
          type: 'error',
          content: 'Failed to update user: first failure',
        }),
      );
    });
    expect(modal.isVisible()).toBe(false);

    // ACT - second user update failure

    table!.findRowSelectionArea(1)!.click();

    manageButton = wrapper.findButton('[data-testid="manage-user-button"]');

    manageButton?.click();

    textarea = wrapper.findTextarea('[data-testid="owned-accounts-form-field"]');
    textarea?.setTextareaValue('123456789012,012345678901');

    saveButton = wrapper.findButton('[data-testid="manage-user-save-button"]');

    saveButton?.click();

    await vi.waitFor(() => {
      expect(capturedRequest).toBeDefined();
      expect(capturedRequest.accountIds).toEqual(['123456789012', '012345678901']);
    });

    // ASSERT - notification is re-rendered
    await vi.waitFor(() => {
      const state = store.getState();
      const notifications = state.notifications.notifications;

      expect(notifications).toHaveLength(2);
      expect(notifications[1]).toEqual(
        expect.objectContaining({
          type: 'error',
          content: 'Failed to update user: second failure',
        }),
      );
    });
  });

  it('should handle network error during user update', async () => {
    // ARRANGE
    const users = generateTestUsers(1);
    let capturedRequest: any = null;
    server.use(
      http.put(`${MOCK_SERVER_URL}${ApiEndpoints.USERS}/:email`, async ({ request }) => {
        capturedRequest = await request.json();
        return Response.error();
      }),
    );

    // ACT
    const { store } = renderWithProvider(<UsersTable users={users} loading={false} onRefresh={mockRefresh} />);
    const wrapper = createWrapper(document.body);

    const table = wrapper.findTable();
    table!.findRowSelectionArea(1)!.click();

    const manageButton = wrapper.findButton('[data-testid="manage-user-button"]');
    manageButton?.click();

    const modal = wrapper.findModal('[data-testid="manage-user-modal"]')!;

    const textarea = wrapper.findTextarea('[data-testid="owned-accounts-form-field"]');
    textarea?.setTextareaValue('999999999999');

    const saveButton = wrapper.findButton('[data-testid="manage-user-save-button"]');
    saveButton?.click();

    // ASSERT
    await vi.waitFor(() => {
      expect(capturedRequest).toBeDefined();
      expect(capturedRequest.accountIds).toEqual(['999999999999']);
    });
    await vi.waitFor(() => {
      const state = store.getState();
      const errorNotification = state.notifications.notifications.find((n) => n.type === 'error');
      expect(errorNotification).toBeDefined();
      expect(errorNotification?.content).toContain('Failed to update user');
    });
    expect(modal.isVisible()).toBe(false);
  });

  it('should open delete confirmation modal and hide manage user modal', () => {
    // ARRANGE
    const users = generateTestUsers(1);

    // ACT
    renderWithProvider(<UsersTable users={users} loading={false} onRefresh={mockRefresh} />);
    const wrapper = createWrapper(document.body);

    const table = wrapper.findTable();
    table!.findRowSelectionArea(1)!.click();

    const manageButton = wrapper.findButton('[data-testid="manage-user-button"]');
    manageButton?.click();

    const manageModal = wrapper.findModal('[data-testid="manage-user-modal"]');
    expect(manageModal?.isVisible()).toBe(true);

    const deleteButton = manageModal?.findContent()?.findButton();
    deleteButton?.click();

    // ASSERT
    const deleteModal = wrapper
      .findAllModals()
      .find(
        (modal) =>
          modal.getElement().textContent?.includes('Delete User') &&
          modal.getElement().textContent?.includes('Are you sure'),
      );
    expect(deleteModal?.isVisible()).toBe(true);
    expect(deleteModal?.getElement()).toHaveTextContent(
      'Are you sure you want to delete user user0@example.com? This action cannot be undone.',
    );
    expect(manageModal?.isVisible()).toBe(false);
  });

  it('should close delete confirmation modal when Cancel button is clicked', () => {
    // ARRANGE
    const users = generateTestUsers(1);

    // ACT
    renderWithProvider(<UsersTable users={users} loading={false} onRefresh={mockRefresh} />);
    const wrapper = createWrapper(document.body);

    const table = wrapper.findTable();
    table!.findRowSelectionArea(1)!.click();

    const manageButton = wrapper.findButton('[data-testid="manage-user-button"]');
    manageButton?.click();

    const manageModal = wrapper.findModal('[data-testid="manage-user-modal"]');
    const deleteButton = manageModal?.findContent()?.findButton();
    deleteButton?.click();

    const deleteModal = wrapper
      .findAllModals()
      .find(
        (modal) =>
          modal.getElement().textContent?.includes('Delete User') &&
          modal.getElement().textContent?.includes('Are you sure'),
      );
    const cancelButton = deleteModal
      ?.findFooter()
      ?.findAllButtons()
      .find((button) => button.getElement().textContent === 'Cancel');
    cancelButton?.click();

    // ASSERT
    expect(deleteModal?.isVisible()).toBe(false);
    expect(manageModal?.isVisible()).toBe(true);
  });

  it('should successfully delete user and close both modals', async () => {
    // ARRANGE
    const users = generateTestUsers(1);
    server.use(http.delete(`${MOCK_SERVER_URL}${ApiEndpoints.USERS}/:email`, async () => await ok({})));

    // ACT
    const { store } = renderWithProvider(<UsersTable users={users} loading={false} onRefresh={mockRefresh} />);
    const wrapper = createWrapper(document.body);

    const table = wrapper.findTable();
    table!.findRowSelectionArea(1)!.click();

    const manageButton = wrapper.findButton('[data-testid="manage-user-button"]');
    manageButton?.click();

    const manageModal = wrapper.findModal('[data-testid="manage-user-modal"]');
    const deleteButton = manageModal?.findContent()?.findButton();
    deleteButton?.click();

    const deleteModal = wrapper
      .findAllModals()
      .find(
        (modal) =>
          modal.getElement().textContent?.includes('Delete User') &&
          modal.getElement().textContent?.includes('Are you sure'),
      );
    const confirmDeleteButton = deleteModal
      ?.findFooter()
      ?.findAllButtons()
      .find((button) => button.getElement().textContent === 'Delete');
    confirmDeleteButton?.click();

    // ASSERT
    await vi.waitFor(() => {
      const state = store.getState();
      const successNotification = state.notifications.notifications.find((n) => n.type === 'success');
      expect(successNotification).toBeDefined();
      expect(successNotification?.id).toBe('user-delete-success');
    });
    expect(mockRefresh).toHaveBeenCalledTimes(1);
    expect(deleteModal?.isVisible()).toBe(false);
    expect(manageModal?.isVisible()).toBe(false);
  });

  it('should show loading state on delete button during deletion', () => {
    // ARRANGE
    const users = generateTestUsers(1);
    let resolveDelete: () => void;
    const deletePromise = new Promise<void>((resolve) => {
      resolveDelete = resolve;
    });
    server.use(
      http.delete(`${MOCK_SERVER_URL}${ApiEndpoints.USERS}/:email`, async () => {
        await deletePromise;
        return await ok({});
      }),
    );

    // ACT
    renderWithProvider(<UsersTable users={users} loading={false} onRefresh={mockRefresh} />);
    const wrapper = createWrapper(document.body);

    const table = wrapper.findTable();
    table!.findRowSelectionArea(1)!.click();

    const manageButton = wrapper.findButton('[data-testid="manage-user-button"]');
    manageButton?.click();

    const manageModal = wrapper.findModal('[data-testid="manage-user-modal"]');
    const deleteButton = manageModal?.findContent()?.findButton();
    deleteButton?.click();

    const deleteModal = wrapper
      .findAllModals()
      .find(
        (modal) =>
          modal.getElement().textContent?.includes('Delete User') &&
          modal.getElement().textContent?.includes('Are you sure'),
      );
    const confirmDeleteButton = deleteModal
      ?.findFooter()
      ?.findAllButtons()
      .find((button) => button.getElement().textContent === 'Delete');
    confirmDeleteButton?.click();

    // ASSERT
    expect(confirmDeleteButton?.getElement()).toHaveAttribute('aria-disabled', 'true');

    resolveDelete!();
  });

  it('should handle delete error and close both modals', async () => {
    // ARRANGE
    const users = generateTestUsers(1);
    server.use(
      http.delete(
        `${MOCK_SERVER_URL}${ApiEndpoints.USERS}/:email`,
        async () => {
          return Response.json({ message: 'first failure' }, { status: 400 });
        },
        { once: true },
      ),
      http.delete(
        `${MOCK_SERVER_URL}${ApiEndpoints.USERS}/:email`,
        async () => {
          return Response.json({ message: 'second failure' }, { status: 400 });
        },
        { once: true },
      ),
    );

    // ACT
    const { store } = renderWithProvider(<UsersTable users={users} loading={false} onRefresh={mockRefresh} />);
    const wrapper = createWrapper(document.body);

    const table = wrapper.findTable();
    table!.findRowSelectionArea(1)!.click();

    let manageButton = wrapper.findButton('[data-testid="manage-user-button"]');
    manageButton?.click();

    let manageModal = wrapper.findModal('[data-testid="manage-user-modal"]');
    let deleteButton = manageModal?.findContent()?.findButton();
    deleteButton?.click();

    let deleteModal = wrapper
      .findAllModals()
      .find(
        (modal) =>
          modal.getElement().textContent?.includes('Delete User') &&
          modal.getElement().textContent?.includes('Are you sure'),
      );
    let confirmDeleteButton = deleteModal
      ?.findFooter()
      ?.findAllButtons()
      .find((button) => button.getElement().textContent === 'Delete');
    confirmDeleteButton?.click();

    // ASSERT
    await vi.waitFor(() => {
      const state = store.getState();
      const notifications = state.notifications.notifications;
      expect(notifications).toHaveLength(1);
      expect(notifications[0]).toEqual(
        expect.objectContaining({
          type: 'error',
          content: 'Failed to delete user: first failure',
        }),
      );
    });
    expect(deleteModal?.isVisible()).toBe(false);
    expect(manageModal?.isVisible()).toBe(false);

    // ACT - second deletion attempt

    table!.findRowSelectionArea(1)!.click();

    manageButton = wrapper.findButton('[data-testid="manage-user-button"]');
    manageButton?.click();

    manageModal = wrapper.findModal('[data-testid="manage-user-modal"]');
    deleteButton = manageModal?.findContent()?.findButton();
    deleteButton?.click();

    deleteModal = wrapper
      .findAllModals()
      .find(
        (modal) =>
          modal.getElement().textContent?.includes('Delete User') &&
          modal.getElement().textContent?.includes('Are you sure'),
      );
    confirmDeleteButton = deleteModal
      ?.findFooter()
      ?.findAllButtons()
      .find((button) => button.getElement().textContent === 'Delete');
    confirmDeleteButton?.click();

    // ASSERT
    await vi.waitFor(() => {
      const state = store.getState();
      const notifications = state.notifications.notifications;
      expect(notifications).toHaveLength(2);
      expect(notifications[1]).toEqual(
        expect.objectContaining({
          type: 'error',
          content: 'Failed to delete user: second failure',
        }),
      );
    });
  });

  it('should handle delete network error and close both modals', async () => {
    // ARRANGE
    const users = generateTestUsers(1);
    server.use(
      http.delete(`${MOCK_SERVER_URL}${ApiEndpoints.USERS}/:email`, async () => {
        return Response.error();
      }),
    );

    // ACT
    const { store } = renderWithProvider(<UsersTable users={users} loading={false} onRefresh={mockRefresh} />);
    const wrapper = createWrapper(document.body);

    const table = wrapper.findTable();
    table!.findRowSelectionArea(1)!.click();

    const manageButton = wrapper.findButton('[data-testid="manage-user-button"]');
    manageButton?.click();

    const manageModal = wrapper.findModal('[data-testid="manage-user-modal"]');
    const deleteButton = manageModal?.findContent()?.findButton();
    deleteButton?.click();

    const deleteModal = wrapper
      .findAllModals()
      .find(
        (modal) =>
          modal.getElement().textContent?.includes('Delete User') &&
          modal.getElement().textContent?.includes('Are you sure'),
      );
    const confirmDeleteButton = deleteModal
      ?.findFooter()
      ?.findAllButtons()
      .find((button) => button.getElement().textContent === 'Delete');
    confirmDeleteButton?.click();

    // ASSERT
    await vi.waitFor(() => {
      const state = store.getState();
      const errorNotification = state.notifications.notifications.find((n) => n.type === 'error');
      expect(errorNotification).toBeDefined();
      expect(errorNotification?.content).toContain('Failed to delete user');
    });
    expect(deleteModal?.isVisible()).toBe(false);
    expect(manageModal?.isVisible()).toBe(false);
  });
});
