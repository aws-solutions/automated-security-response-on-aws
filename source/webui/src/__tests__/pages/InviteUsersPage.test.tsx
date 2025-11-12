// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { screen, within, act, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { http } from 'msw';
import { render } from '@testing-library/react';
import { Provider } from 'react-redux';
import { MemoryRouter } from 'react-router-dom';
import { configureStore } from '@reduxjs/toolkit';
import createWrapper from '@cloudscape-design/components/test-utils/dom';

import { MOCK_SERVER_URL, server } from '../server.ts';
import { ApiEndpoints } from '../../store/solutionApi.ts';
import { ok } from '../../mocks/handlers.ts';
import { mockUserContext } from '../test-data-factory.ts';
import { InviteUsersPage } from '../../pages/users/invite/InviteUsersPage.tsx';
import { UserContext } from '../../contexts/UserContext.tsx';
import { NotificationContextProvider } from '../../contexts/NotificationContext.tsx';
import { rootReducer } from '../../store/store.ts';
import { solutionApi } from '../../store/solutionApi.ts';

const renderInviteUsersPage = () => {
  const store = configureStore({
    reducer: rootReducer,
    middleware: (getDefaultMiddleware) => getDefaultMiddleware().concat(solutionApi.middleware),
  });

  const renderResult = render(
    <MemoryRouter>
      <Provider store={store}>
        <UserContext.Provider value={mockUserContext}>
          <NotificationContextProvider>
            <main>
              <InviteUsersPage />
            </main>
          </NotificationContextProvider>
        </UserContext.Provider>
      </Provider>
    </MemoryRouter>,
  );

  return {
    store,
    container: renderResult.container,
  };
};

describe('InviteUsersPage', () => {
  it('renders initial page state', () => {
    // ACT
    renderInviteUsersPage();

    // ASSERT
    // Form structure
    expect(screen.getByRole('heading', { name: 'Invite Users' })).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: 'Invitation Details' })).toBeInTheDocument();
    expect(screen.getByLabelText('Email')).toBeInTheDocument();
    expect(screen.getByLabelText('Permission Type')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Submit' })).toBeInTheDocument();

    // Description text
    expect(screen.getByText(/Send an access invitation for additional users/)).toBeInTheDocument();
    expect(screen.getByText(/Let us know who the invitation should be sent to/)).toBeInTheDocument();
    expect(screen.getByText(/What level of access should this user have/)).toBeInTheDocument();

    // Initial state
    expect(screen.getByRole('button', { name: 'Submit' })).toBeDisabled();
  });

  it('enables submit button when email and permission type are filled', async () => {
    // ARRANGE
    const user = userEvent.setup();

    // ACT
    const { container } = renderInviteUsersPage();
    const wrapper = createWrapper(container);

    const emailInput = screen.getByLabelText('Email');
    const selectWrapper = wrapper.findSelect();

    await user.type(emailInput, 'test@example.com');

    act(() => {
      selectWrapper!.openDropdown();
    });
    act(() => {
      selectWrapper!.selectOptionByValue('delegated-admin');
    });

    // ASSERT
    await waitFor(() => {
      expect(screen.getByRole('button', { name: 'Submit' })).toBeEnabled();
    });
  });

  it('shows owned accounts field when account operator is selected', async () => {
    // ACT
    const { container } = renderInviteUsersPage();
    const wrapper = createWrapper(container);

    const selectWrapper = wrapper.findSelect();

    act(() => {
      selectWrapper!.openDropdown();
    });
    act(() => {
      selectWrapper!.selectOptionByValue('account-operator');
    });

    // ASSERT
    await waitFor(() => {
      expect(screen.getByLabelText('Owned Accounts')).toBeInTheDocument();
    });
    expect(screen.getByText(/Enter a comma-separated list of Account IDs/)).toBeInTheDocument();
  });

  it('hides owned accounts field when delegated admin is selected', async () => {
    // ACT
    const { container } = renderInviteUsersPage();
    const wrapper = createWrapper(container);

    const selectWrapper = wrapper.findSelect();

    act(() => {
      selectWrapper!.openDropdown();
    });
    act(() => {
      selectWrapper!.selectOptionByValue('account-operator');
    });

    // Verify field appears
    await waitFor(() => {
      expect(screen.getByLabelText('Owned Accounts')).toBeInTheDocument();
    });

    // Switch to delegated admin
    act(() => {
      selectWrapper!.openDropdown();
    });
    act(() => {
      selectWrapper!.selectOptionByValue('delegated-admin');
    });

    // ASSERT
    await waitFor(() => {
      expect(screen.queryByLabelText('Owned Accounts')).not.toBeInTheDocument();
    });
  });

  it('validates account IDs and shows error for invalid format', async () => {
    // ARRANGE
    const user = userEvent.setup();

    // ACT
    const { container } = renderInviteUsersPage();
    const wrapper = createWrapper(container);

    const selectWrapper = wrapper.findSelect();

    act(() => {
      selectWrapper!.openDropdown();
    });
    act(() => {
      selectWrapper!.selectOptionByValue('account-operator');
    });

    const ownedAccountsField = screen.getByLabelText('Owned Accounts');
    await user.type(ownedAccountsField, 'invalid-account-id');

    // ASSERT
    await waitFor(() => {
      expect(screen.getByText(/Invalid account IDs/)).toBeInTheDocument();
    });
    expect(ownedAccountsField).toHaveAttribute('aria-invalid', 'true');
  });

  it('accepts valid account IDs', async () => {
    // ARRANGE
    const user = userEvent.setup();

    // ACT
    const { container } = renderInviteUsersPage();
    const wrapper = createWrapper(container);

    const selectWrapper = wrapper.findSelect();

    act(() => {
      selectWrapper!.openDropdown();
    });
    act(() => {
      selectWrapper!.selectOptionByValue('account-operator');
    });

    const ownedAccountsField = screen.getByLabelText('Owned Accounts');
    await user.type(ownedAccountsField, '123456789012, 012345678901');

    // ASSERT
    await waitFor(() => {
      expect(screen.queryByText(/Invalid account IDs/)).not.toBeInTheDocument();
    });
    expect(ownedAccountsField).not.toHaveAttribute('aria-invalid', 'true');
  });

  it('disables submit button when account operator has invalid account IDs', async () => {
    // ARRANGE
    const user = userEvent.setup();

    // ACT
    const { container } = renderInviteUsersPage();
    const wrapper = createWrapper(container);

    const emailInput = screen.getByLabelText('Email');
    const selectWrapper = wrapper.findSelect();

    await user.type(emailInput, 'test@example.com');
    act(() => {
      selectWrapper!.openDropdown();
    });
    act(() => {
      selectWrapper!.selectOptionByValue('account-operator');
    });

    const ownedAccountsField = screen.getByLabelText('Owned Accounts');
    await user.type(ownedAccountsField, 'invalid');

    // ASSERT
    await waitFor(() => {
      expect(screen.getByRole('button', { name: 'Submit' })).toBeDisabled();
    });
  });

  it('successfully invites delegated admin user', async () => {
    // ARRANGE
    const user = userEvent.setup();
    server.use(http.post(`${MOCK_SERVER_URL}${ApiEndpoints.USERS}`, async () => await ok({})));

    // ACT
    const { container, store } = renderInviteUsersPage();
    const wrapper = createWrapper(container);

    const emailInput = screen.getByLabelText('Email');
    const selectWrapper = wrapper.findSelect();

    await user.type(emailInput, 'test@example.com');
    act(() => {
      selectWrapper!.openDropdown();
    });
    act(() => {
      selectWrapper!.selectOptionByValue('delegated-admin');
    });

    const submitButton = screen.getByRole('button', { name: 'Submit' });
    await user.click(submitButton);

    // ASSERT
    await waitFor(() => {
      expect(emailInput).toHaveValue('');
    });

    await waitFor(() => {
      const state = store.getState();
      expect(state.notifications.notifications).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            type: 'success',
            content: 'User invitation sent successfully to test@example.com',
          }),
        ]),
      );
    });

    // ACT - second successful invitation
    await user.type(emailInput, 'test2@example.com');
    act(() => {
      selectWrapper!.openDropdown();
    });
    act(() => {
      selectWrapper!.selectOptionByValue('delegated-admin');
    });

    await user.click(submitButton);

    // ASSERT - notification should be re-rendered
    await waitFor(() => {
      expect(emailInput).toHaveValue('');
    });

    await waitFor(() => {
      const state = store.getState();
      expect(state.notifications.notifications).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            type: 'success',
            content: 'User invitation sent successfully to test2@example.com',
          }),
        ]),
      );
    });
  });

  it('successfully invites account operator user with account IDs', async () => {
    // ARRANGE
    const user = userEvent.setup();
    server.use(http.post(`${MOCK_SERVER_URL}${ApiEndpoints.USERS}`, async () => await ok({})));

    // ACT
    const { container, store } = renderInviteUsersPage();
    const wrapper = createWrapper(container);

    const emailInput = screen.getByLabelText('Email');
    const selectWrapper = wrapper.findSelect();

    await user.type(emailInput, 'operator@example.com');
    act(() => {
      selectWrapper!.openDropdown();
    });
    act(() => {
      selectWrapper!.selectOptionByValue('account-operator');
    });

    const ownedAccountsField = screen.getByLabelText('Owned Accounts');
    await user.type(ownedAccountsField, '123456789012, 012345678901');

    const submitButton = screen.getByRole('button', { name: 'Submit' });
    await user.click(submitButton);

    // ASSERT
    await waitFor(() => {
      expect(emailInput).toHaveValue('');
    });

    await waitFor(() => {
      const state = store.getState();
      expect(state.notifications.notifications).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            type: 'success',
            content: 'User invitation sent successfully to operator@example.com',
          }),
        ]),
      );
    });
  });

  it('shows loading state during submission', async () => {
    // ARRANGE
    const user = userEvent.setup();
    let resolveRequest: (value: Response) => void;
    const requestPromise = new Promise<Response>((resolve) => {
      resolveRequest = resolve;
    });

    server.use(http.post(`${MOCK_SERVER_URL}${ApiEndpoints.USERS}`, async () => requestPromise));

    // ACT
    const { container } = renderInviteUsersPage();
    const wrapper = createWrapper(container);

    const emailInput = screen.getByLabelText('Email');
    const selectWrapper = wrapper.findSelect();

    await user.type(emailInput, 'test@example.com');
    act(() => {
      selectWrapper!.openDropdown();
    });
    act(() => {
      selectWrapper!.selectOptionByValue('delegated-admin');
    });

    const submitButton = screen.getByRole('button', { name: 'Submit' });
    await user.click(submitButton);

    // ASSERT
    await waitFor(() => {
      expect(submitButton).toHaveAttribute('aria-disabled', 'true');
    });

    // Clean up
    resolveRequest!(await ok({}));
  });

  it('displays error notification when invitation fails', async () => {
    // ARRANGE
    const user = userEvent.setup();
    server.use(
      http.post(`${MOCK_SERVER_URL}${ApiEndpoints.USERS}`, async () => {
        return new Response(JSON.stringify({ message: 'User already exists' }), {
          status: 400,
          headers: { 'Content-Type': 'application/json' },
        });
      }),
    );

    // ACT
    const { container, store } = renderInviteUsersPage();
    const wrapper = createWrapper(container);

    const emailInput = screen.getByLabelText('Email');
    const selectWrapper = wrapper.findSelect();

    await user.type(emailInput, 'existing@example.com');
    act(() => {
      selectWrapper!.openDropdown();
    });
    act(() => {
      selectWrapper!.selectOptionByValue('delegated-admin');
    });

    const submitButton = screen.getByRole('button', { name: 'Submit' });
    await user.click(submitButton);

    // ASSERT
    await waitFor(() => {
      const state = store.getState();
      const errorNotification = state.notifications.notifications.find((n) => n.type === 'error');
      expect(errorNotification).toBeDefined();
      expect(errorNotification?.content).toContain('Failed to invite user');
    });
  });

  it('handles API error with unknown error message', async () => {
    // ARRANGE
    const user = userEvent.setup();
    server.use(
      http.post(`${MOCK_SERVER_URL}${ApiEndpoints.USERS}`, async () => {
        return new Response(null, {
          status: 400,
          headers: { 'Content-Type': 'application/json' },
        });
      }),
    );

    // ACT
    const { container, store } = renderInviteUsersPage();
    const wrapper = createWrapper(container);

    const emailInput = screen.getByLabelText('Email');
    const selectWrapper = wrapper.findSelect();

    await user.type(emailInput, 'test@example.com');
    act(() => {
      selectWrapper!.openDropdown();
    });
    act(() => {
      selectWrapper!.selectOptionByValue('delegated-admin');
    });

    const submitButton = screen.getByRole('button', { name: 'Submit' });
    await user.click(submitButton);

    // ASSERT
    await waitFor(() => {
      const state = store.getState();
      const errorNotification = state.notifications.notifications.find((n) => n.type === 'error');
      expect(errorNotification).toBeDefined();
      expect(errorNotification?.content).toContain('Failed to invite user');
    });
  });

  it('does not submit when form is incomplete', async () => {
    // ARRANGE
    const user = userEvent.setup();
    const mockPost = vi.fn();
    server.use(http.post(`${MOCK_SERVER_URL}${ApiEndpoints.USERS}`, mockPost));

    // ACT
    renderInviteUsersPage();

    const submitButton = screen.getByRole('button', { name: 'Submit' });

    // Try to submit with empty form
    await user.click(submitButton);

    // ASSERT
    expect(mockPost).not.toHaveBeenCalled();
    expect(submitButton).toBeDisabled();
  });

  it('enables submit for account operator without owned accounts', async () => {
    // ARRANGE
    const user = userEvent.setup();

    // ACT
    const { container } = renderInviteUsersPage();
    const wrapper = createWrapper(container);

    const emailInput = screen.getByLabelText('Email');
    const selectWrapper = wrapper.findSelect();

    await user.type(emailInput, 'test@example.com');
    act(() => {
      selectWrapper!.openDropdown();
    });
    act(() => {
      selectWrapper!.selectOptionByValue('account-operator');
    });

    // ASSERT
    await waitFor(() => {
      expect(screen.getByRole('button', { name: 'Submit' })).toBeEnabled();
    });
  });

  it('shows failed to invite user notification on API failure', async () => {
    // ARRANGE
    const user = userEvent.setup();
    server.use(
      http.post(
        `${MOCK_SERVER_URL}${ApiEndpoints.USERS}`,
        () => {
          return Response.json({ message: 'first failure' }, { status: 400 });
        },
        { once: true },
      ),
      http.post(
        `${MOCK_SERVER_URL}${ApiEndpoints.USERS}`,
        () => {
          return Response.json({ message: 'second failure' }, { status: 400 });
        },
        { once: true },
      ),
    );

    // ACT
    const { container, store } = renderInviteUsersPage();
    const wrapper = createWrapper(container);

    const emailInput = screen.getByLabelText('Email');
    const selectWrapper = wrapper.findSelect();

    await user.type(emailInput, 'test@example.com');
    act(() => {
      selectWrapper!.openDropdown();
    });
    act(() => {
      selectWrapper!.selectOptionByValue('delegated-admin');
    });

    const submitButton = screen.getByRole('button', { name: 'Submit' });
    await user.click(submitButton);

    // ASSERT
    await waitFor(() => {
      const state = store.getState();
      expect(state.notifications.notifications).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            type: 'error',
            content: 'Failed to invite user: first failure',
          }),
        ]),
      );
    });

    // ACT - second failed invitation
    await user.clear(emailInput);
    await user.type(emailInput, 'test2@example.com');
    act(() => {
      selectWrapper!.openDropdown();
    });
    act(() => {
      selectWrapper!.selectOptionByValue('delegated-admin');
    });

    await waitFor(() => {
      expect(submitButton).toBeEnabled();
    });
    
    await user.click(submitButton);

    // ASSERT
    await waitFor(() => {
      const state = store.getState();
      const notifications = state.notifications.notifications;
      expect(notifications).toHaveLength(2);
      expect(notifications[1]).toEqual(
        expect.objectContaining({
          type: 'error',
          content: 'Failed to invite user: second failure',
        })
      );
    });
  });

  it('shows appropriate description for delegated admin users', () => {
    // ARRANGE
    const delegatedAdminUserContext = {
      ...mockUserContext,
      groups: ['DelegatedAdminGroup'],
    };

    const store = configureStore({
      reducer: rootReducer,
      middleware: (getDefaultMiddleware) => getDefaultMiddleware().concat(solutionApi.middleware),
    });

    // ACT
    render(
      <MemoryRouter>
        <Provider store={store}>
          <UserContext.Provider value={delegatedAdminUserContext}>
            <NotificationContextProvider>
              <main>
                <InviteUsersPage />
              </main>
            </NotificationContextProvider>
          </UserContext.Provider>
        </Provider>
      </MemoryRouter>,
    );

    // ASSERT
    expect(screen.getByText('Delegated Admins can only invite Account Operators')).toBeInTheDocument();
  });
});
