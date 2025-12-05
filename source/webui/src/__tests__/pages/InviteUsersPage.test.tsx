// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { screen, within, act, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { http, HttpResponse } from 'msw';
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
    expect(screen.getByRole('heading', { name: 'Invite Users' })).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: 'Invitation Details' })).toBeInTheDocument();
    expect(screen.getByLabelText('Email(s)')).toBeInTheDocument();
    expect(screen.getByLabelText('Permission Type')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Submit' })).toBeInTheDocument();
    expect(screen.getByText(/Send an access invitation for additional users/)).toBeInTheDocument();
    expect(screen.getByText(/Enter one or more email addresses separated by commas/)).toBeInTheDocument();
    expect(screen.getByText(/What level of access should this user have/)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Submit' })).toBeDisabled();
  });

  it('enables submit button when email and permission type are filled', async () => {
    // ARRANGE
    const user = userEvent.setup();

    // ACT
    const { container } = renderInviteUsersPage();
    const wrapper = createWrapper(container);

    const emailInput = screen.getByLabelText('Email(s)');
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

    await waitFor(() => {
      expect(screen.getByLabelText('Owned Accounts')).toBeInTheDocument();
    });

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

    const emailInput = screen.getByLabelText('Email(s)');
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

  it('successfully invites single user', async () => {
    // ARRANGE
    const user = userEvent.setup();
    server.use(http.post(`${MOCK_SERVER_URL}${ApiEndpoints.USERS}`, async () => await ok({})));

    // ACT
    const { container, store } = renderInviteUsersPage();
    const wrapper = createWrapper(container);

    const emailInput = screen.getByLabelText('Email(s)');
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
    // When ALL succeed - form clears
    await waitFor(() => {
      expect(emailInput).toHaveValue('');
    });

    await waitFor(() => {
      const state = store.getState();
      expect(state.notifications.notifications).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            type: 'success',
            content: 'Successfully invited 1 user',
          }),
        ]),
      );
    });
  });

  it('successfully invites multiple users in batch', async () => {
    // ARRANGE
    const user = userEvent.setup();
    server.use(http.post(`${MOCK_SERVER_URL}${ApiEndpoints.USERS}`, async () => await ok({})));

    // ACT
    const { container, store } = renderInviteUsersPage();
    const wrapper = createWrapper(container);

    const emailInput = screen.getByLabelText('Email(s)');
    const selectWrapper = wrapper.findSelect();

    await user.type(emailInput, 'user1@example.com, user2@example.com, user3@example.com');
    act(() => {
      selectWrapper!.openDropdown();
    });
    act(() => {
      selectWrapper!.selectOptionByValue('delegated-admin');
    });

    const submitButton = screen.getByRole('button', { name: 'Submit' });
    await user.click(submitButton);

    // ASSERT
    // When ALL succeed - form clears
    await waitFor(() => {
      expect(emailInput).toHaveValue('');
    });

    await waitFor(() => {
      const state = store.getState();
      expect(state.notifications.notifications).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            type: 'success',
            content: 'Successfully invited 3 users',
          }),
        ]),
      );
    });
  });

  it('handles partial failures in batch invite and shows both success and error notifications', async () => {
    // ARRANGE
    const user = userEvent.setup();
    const failingEmail = 'fail@example.com';
    server.use(
      http.post(`${MOCK_SERVER_URL}${ApiEndpoints.USERS}`, async ({ request }) => {
        const body = (await request.json()) as { email: string };
        if (body.email === failingEmail) {
          return HttpResponse.json({ message: 'User already exists' }, { status: 400 });
        }
        return await ok({});
      }),
    );

    // ACT
    const { container, store } = renderInviteUsersPage();
    const wrapper = createWrapper(container);

    const emailInput = screen.getByLabelText('Email(s)');
    const selectWrapper = wrapper.findSelect();

    await user.type(emailInput, `success1@example.com, ${failingEmail}, success2@example.com`);
    act(() => {
      selectWrapper!.openDropdown();
    });
    act(() => {
      selectWrapper!.selectOptionByValue('delegated-admin');
    });

    const submitButton = screen.getByRole('button', { name: 'Submit' });
    await user.click(submitButton);

    // ASSERT
    await waitFor(
      () => {
        const state = store.getState();
        const notifications = state.notifications.notifications;
        const successNotif = notifications.find((n) => n.type === 'success');
        const errorNotif = notifications.find((n) => n.type === 'error');
        expect(successNotif).toBeDefined();
        expect(successNotif?.content).toBe('Successfully invited 2 users');
        expect(errorNotif).toBeDefined();
        expect(errorNotif?.content).toContain('Failed to invite 1 user');
        expect(errorNotif?.content).toContain('User already exists');
      },
      { timeout: 3000 },
    );

    // When SOME fail - form retains values so user can retry failed emails
    expect(emailInput).toHaveValue(`success1@example.com, ${failingEmail}, success2@example.com`);
  });

  it('validates multiple emails and shows invalid ones', async () => {
    // ARRANGE
    const user = userEvent.setup();

    // ACT
    const { container } = renderInviteUsersPage();
    const wrapper = createWrapper(container);

    const emailInput = screen.getByLabelText('Email(s)');
    await user.type(emailInput, 'valid@example.com, invalid-email, another@example.com');

    // ASSERT
    await waitFor(() => {
      expect(screen.getByText(/Invalid email address: invalid-email/)).toBeInTheDocument();
    });
    expect(emailInput).toHaveAttribute('aria-invalid', 'true');
    expect(screen.getByRole('button', { name: 'Submit' })).toBeDisabled();
  });

  it('successfully invites account operator user with account IDs', async () => {
    // ARRANGE
    const user = userEvent.setup();
    server.use(http.post(`${MOCK_SERVER_URL}${ApiEndpoints.USERS}`, async () => await ok({})));

    // ACT
    const { container, store } = renderInviteUsersPage();
    const wrapper = createWrapper(container);

    const emailInput = screen.getByLabelText('Email(s)');
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
    // When ALL succeed - form clears
    await waitFor(() => {
      expect(emailInput).toHaveValue('');
    });

    await waitFor(() => {
      const state = store.getState();
      expect(state.notifications.notifications).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            type: 'success',
            content: 'Successfully invited 1 user',
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

    const emailInput = screen.getByLabelText('Email(s)');
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

    resolveRequest!(await ok({}));
  });

  it('displays error notification when all invitations fail', async () => {
    // ARRANGE
    const user = userEvent.setup();
    server.resetHandlers();
    server.use(
      http.post(`${MOCK_SERVER_URL}${ApiEndpoints.USERS}`, async () => {
        return Response.json({ message: 'User already exists' }, { status: 400 });
      }),
    );

    // ACT
    const { container, store } = renderInviteUsersPage();
    const wrapper = createWrapper(container);

    const emailInput = screen.getByLabelText('Email(s)');
    const selectWrapper = wrapper.findSelect();

    await user.type(emailInput, 'existing@example.com, another@example.com');
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
      const errorNotifications = state.notifications.notifications.filter((n) => n.type === 'error');
      expect(errorNotifications.length).toBeGreaterThan(0);
      const hasFailedInviteNotification = errorNotifications.some(
        (notificationPayload) =>
          // @ts-ignore - n.content.includes is valid on NotificationPayload
          notificationPayload.content.includes('Failed to invite') && notificationPayload.content.includes('user'),
      );
      expect(hasFailedInviteNotification).toBe(true);
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

    const emailInput = screen.getByLabelText('Email(s)');
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

  it('updates notifications on sequential form submissions', async () => {
    // ARRANGE
    const user = userEvent.setup();
    server.use(http.post(`${MOCK_SERVER_URL}${ApiEndpoints.USERS}`, async () => await ok({})));

    // ACT
    const { container, store } = renderInviteUsersPage();
    const wrapper = createWrapper(container);

    const emailInput = screen.getByLabelText('Email(s)');
    const selectWrapper = wrapper.findSelect();
    const submitButton = screen.getByRole('button', { name: 'Submit' });

    await user.type(emailInput, 'user1@example.com');
    act(() => {
      selectWrapper!.openDropdown();
    });
    act(() => {
      selectWrapper!.selectOptionByValue('delegated-admin');
    });
    await user.click(submitButton);

    // ASSERT
    await waitFor(() => {
      const state = store.getState();
      expect(state.notifications.notifications).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            type: 'success',
            content: 'Successfully invited 1 user',
          }),
        ]),
      );
    });

    // ACT - second submission
    await user.type(emailInput, 'user2@example.com, user3@example.com');
    act(() => {
      selectWrapper!.openDropdown();
    });
    act(() => {
      selectWrapper!.selectOptionByValue('delegated-admin');
    });
    await user.click(submitButton);

    // ASSERT - new notification added
    await waitFor(() => {
      const state = store.getState();
      const notifications = state.notifications.notifications;
      expect(notifications.length).toBeGreaterThanOrEqual(2);
      expect(notifications).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            type: 'success',
            content: 'Successfully invited 2 users',
          }),
        ]),
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
