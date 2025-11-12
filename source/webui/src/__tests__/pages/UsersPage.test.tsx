// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { screen, within, render } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { http } from 'msw';
import { Provider } from 'react-redux';
import { MemoryRouter } from 'react-router-dom';
import { configureStore } from '@reduxjs/toolkit';

import { MOCK_SERVER_URL, server } from '../server.ts';
import { ApiEndpoints, solutionApi } from '../../store/solutionApi.ts';
import { ok } from '../../mocks/handlers.ts';
import { User } from '@data-models';
import { generateTestUsers, mockCurrentUser, mockUserContext } from '../test-data-factory.ts';
import { UsersOverviewPage } from '../../pages/users/UsersOverviewPage.tsx';
import { UserContext } from '../../contexts/UserContext.tsx';
import { NotificationContextProvider } from '../../contexts/NotificationContext.tsx';
import { rootReducer } from '../../store/store.ts';

const renderUsersPage = () => {
  const store = configureStore({
    reducer: rootReducer,
    middleware: (getDefaultMiddleware) => getDefaultMiddleware().concat(solutionApi.middleware),
  });

  return render(
    <MemoryRouter>
      <Provider store={store}>
        <UserContext.Provider value={mockUserContext}>
          <NotificationContextProvider>
            <div data-testid="main-content">
              <UsersOverviewPage />
            </div>
          </NotificationContextProvider>
        </UserContext.Provider>
      </Provider>
    </MemoryRouter>,
  );
};

beforeEach(() => {
  // ARRANGE - Mock current user endpoint
  server.use(
    http.get(`${MOCK_SERVER_URL}${ApiEndpoints.USERS}/current%40example.com`, async () => await ok(mockCurrentUser)),
  );
});

describe('UsersOverviewPage', () => {
  it('renders an empty users table', async () => {
    // ARRANGE
    server.use(http.get(MOCK_SERVER_URL + ApiEndpoints.USERS, async () => await ok([])));

    // ACT
    renderUsersPage();

    // ASSERT
    const withinMain = within(screen.getByTestId('main-content'));
    expect(withinMain.getByRole('heading', { name: 'Users (0)' })).toBeInTheDocument();
    expect(await withinMain.findByText(/no users to display/i)).toBeInTheDocument();
  });

  it('renders a table with users', async () => {
    // ARRANGE
    const users = generateTestUsers(3);
    server.use(http.get(MOCK_SERVER_URL + ApiEndpoints.USERS, async () => await ok(users)));

    // ACT
    renderUsersPage();

    // ASSERT
    const withinMain = within(screen.getByTestId('main-content'));
    const heading = await withinMain.findByRole('heading', { name: `Users (3)` });
    expect(heading).toBeInTheDocument();

    const table = await withinMain.findByRole('table');
    const rows = await within(table).findAllByRole('row');
    expect(rows).toHaveLength(users.length + 1);

    const user1EmailCell = await within(table).findByRole('cell', { name: users[0].email });
    expect(user1EmailCell).toBeInTheDocument();
  });

  it('displays loading state', async () => {
    // ARRANGE
    const users = generateTestUsers(1);
    server.use(http.get(MOCK_SERVER_URL + ApiEndpoints.USERS, async () => await ok(users)));

    // ACT
    renderUsersPage();

    // ASSERT
    const withinMain = within(screen.getByTestId('main-content'));
    expect(await withinMain.findByRole('heading', { name: 'Users (1)' })).toBeInTheDocument();
  });

  it('filters users by email', async () => {
    // ARRANGE
    const users = generateTestUsers(5);
    server.use(http.get(MOCK_SERVER_URL + ApiEndpoints.USERS, async () => await ok(users)));

    // ACT
    renderUsersPage();

    const withinMain = within(screen.getByTestId('main-content'));
    await withinMain.findByRole('heading', { name: 'Users (5)' });

    const searchInput = await withinMain.findByPlaceholderText('Search by User ID...');
    await userEvent.type(searchInput, 'user0');

    // ASSERT
    const table = await withinMain.findByRole('table');
    const rows = await within(table).findAllByRole('row');
    expect(rows).toHaveLength(2); // header + 1 matching user
    expect(await within(table).findByRole('cell', { name: 'user0@example.com' })).toBeInTheDocument();
  });

  it('clears filter when clear button is clicked', async () => {
    // ARRANGE
    const users = generateTestUsers(3);
    server.use(http.get(MOCK_SERVER_URL + ApiEndpoints.USERS, async () => await ok(users)));

    // ACT
    renderUsersPage();

    const withinMain = within(screen.getByTestId('main-content'));
    await withinMain.findByRole('heading', { name: 'Users (3)' });

    const searchInput = await withinMain.findByPlaceholderText('Search by User ID...');
    await userEvent.type(searchInput, 'nonexistent');

    const clearButton = await withinMain.findByRole('button', { name: 'Clear filter' });
    await userEvent.click(clearButton);

    // ASSERT
    const table = await withinMain.findByRole('table');
    const rows = await within(table).findAllByRole('row');
    expect(rows).toHaveLength(4); // header + 3 users
  });

  it('refreshes users when refresh button is clicked', async () => {
    // ARRANGE
    let callCount = 0;
    server.use(
      http.get(MOCK_SERVER_URL + ApiEndpoints.USERS, async () => {
        callCount++;
        return await ok(generateTestUsers(callCount));
      }),
    );

    // ACT
    renderUsersPage();

    const withinMain = within(screen.getByTestId('main-content'));
    expect(await withinMain.findByRole('heading', { name: 'Users (1)' })).toBeInTheDocument();

    const refreshButton = withinMain
      .getAllByRole('button')
      .find((button) => button.querySelector('svg path[d*="M15 8c0 3.87"]'));
    expect(refreshButton).toBeInTheDocument();
    await userEvent.click(refreshButton!);

    // ASSERT
    expect(await withinMain.findByRole('heading', { name: 'Users (2)' })).toBeInTheDocument();
    expect(callCount).toBe(2);
  });

  it('displays correct status badges', async () => {
    // ARRANGE
    const users: User[] = [
      {
        email: 'confirmed@example.com',
        invitedBy: 'admin@example.com',
        invitationTimestamp: new Date().toISOString(),
        status: 'Confirmed',
        type: 'admin',
      },
      {
        email: 'invited@example.com',
        invitedBy: 'admin@example.com',
        invitationTimestamp: new Date().toISOString(),
        status: 'Invited',
        type: 'admin',
      },
    ];
    server.use(http.get(MOCK_SERVER_URL + ApiEndpoints.USERS, async () => await ok(users)));

    // ACT
    renderUsersPage();

    const withinMain = within(screen.getByTestId('main-content'));
    await withinMain.findByRole('heading', { name: 'Users (2)' });

    // ASSERT
    const table = await withinMain.findByRole('table');
    expect(await within(table).findByText('Confirmed')).toBeInTheDocument();
    expect(await within(table).findByText('Invited')).toBeInTheDocument();
  });

  it('displays formatted invitation timestamp', async () => {
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
    server.use(http.get(MOCK_SERVER_URL + ApiEndpoints.USERS, async () => await ok(users)));

    // ACT
    renderUsersPage();

    const withinMain = within(screen.getByTestId('main-content'));
    await withinMain.findByRole('heading', { name: 'Users (1)' });

    // ASSERT
    const table = await withinMain.findByRole('table');
    expect(await within(table).findByText(testDate.toLocaleString())).toBeInTheDocument();
  });

  it('shows manage user button', async () => {
    // ARRANGE
    server.use(http.get(MOCK_SERVER_URL + ApiEndpoints.USERS, async () => await ok([])));

    // ACT
    renderUsersPage();

    const withinMain = within(screen.getByTestId('main-content'));

    // ASSERT
    expect(await withinMain.findByRole('button', { name: 'Manage User' })).toBeInTheDocument();
  });

  it('displays error notification when users API fails', async () => {
    // ARRANGE
    server.use(
      http.get(MOCK_SERVER_URL + ApiEndpoints.USERS, async () => {
        return new Response(JSON.stringify({ message: 'API Error' }), {
          status: 500,
          headers: { 'Content-Type': 'application/json' },
        });
      }),
    );

    // ACT
    renderUsersPage();

    // ASSERT
    expect(await screen.findByText(/Failed to load users/i)).toBeInTheDocument();
  });

  it('handles users API error with unknown error message', async () => {
    // ARRANGE
    server.use(
      http.get(MOCK_SERVER_URL + ApiEndpoints.USERS, async () => {
        return new Response(null, {
          status: 500,
          headers: { 'Content-Type': 'application/json' },
        });
      }),
    );

    // ACT
    renderUsersPage();

    // ASSERT
    expect(await screen.findByText(/Failed to load users.*Cannot read properties of null/i)).toBeInTheDocument();
  });
});
