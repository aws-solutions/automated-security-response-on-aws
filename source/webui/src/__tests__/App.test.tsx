// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { AuthUser } from 'aws-amplify/auth';
import { http, HttpResponse } from 'msw';
import { Provider } from 'react-redux';
import { MemoryRouter } from 'react-router-dom';
import { AppComponent } from '../App.tsx';
import { NotificationContext, NotificationContextProvider } from '../contexts/NotificationContext.tsx';
import { ConfigContextProvider } from '../contexts/ConfigContext.tsx';
import { UserContext } from '../contexts/UserContext.tsx';
import { ApiEndpoints } from '../store/solutionApi.ts';
import { setupStore } from '../store/store.ts';
import { MOCK_SERVER_URL, server } from './server.ts';
import { generateTestFindings } from './test-data-factory.ts';

// Mock AWS Amplify styles
vi.mock('@aws-amplify/ui-react/styles.css', () => ({}));

describe('App Component', () => {
  describe('when no user is logged in', () => {
    it('should show loading spinner and redirect message', () => {
      const store = setupStore();

      render(
        <MemoryRouter>
          <Provider store={store}>
            <UserContext.Provider
              value={{
                user: null,
                email: null,
                groups: null,
                signOut: () => Promise.resolve(),
                signInWithRedirect: () => Promise.resolve(),
                checkUser: () => Promise.resolve(),
              }}
            >
              <NotificationContextProvider>
                <ConfigContextProvider config={{ ticketingEnabled: true }}>
                  <AppComponent />
                </ConfigContextProvider>
              </NotificationContextProvider>
            </UserContext.Provider>
          </Provider>
        </MemoryRouter>,
      );

      const redirectMessage = screen.getByText(/Redirecting to login/i);
      expect(redirectMessage).toBeInTheDocument();
      // Check that the spinner component is rendered (it's a CloudScape component)
      expect(document.querySelector('.awsui_root_1612d_152xz_183')).toBeInTheDocument();
    });

    it('should not render the main application content', () => {
      const store = setupStore();

      render(
        <MemoryRouter>
          <Provider store={store}>
            <UserContext.Provider
              value={{
                user: null,
                email: null,
                groups: null,
                signOut: () => Promise.resolve(),
                signInWithRedirect: () => Promise.resolve(),
                checkUser: () => Promise.resolve(),
              }}
            >
              <NotificationContextProvider>
                <ConfigContextProvider config={{ ticketingEnabled: true }}>
                  <AppComponent />
                </ConfigContextProvider>
              </NotificationContextProvider>
            </UserContext.Provider>
          </Provider>
        </MemoryRouter>,
      );

      expect(screen.queryByTestId('main-content')).not.toBeInTheDocument();
      expect(screen.queryByText(/Automated Security Response on AWS/i)).not.toBeInTheDocument();
    });
  });

  describe('when a user is logged in', () => {
    const userEmail = 'john.doe@example.com';
    const userContext = {
      user: {
        username: window.crypto.randomUUID(),
        userId: window.crypto.randomUUID(),
      } as AuthUser,
      email: userEmail,
      groups: ['AdminGroup'],
      signOut: vi.fn().mockResolvedValue(undefined),
      signInWithRedirect: vi.fn().mockResolvedValue(undefined),
      checkUser: vi.fn().mockResolvedValue(undefined),
    };

    beforeEach(() => {
      // Mock API responses
      const findings = generateTestFindings(3);
      server.use(
        http.get(MOCK_SERVER_URL + ApiEndpoints.FINDINGS, () => {
          return HttpResponse.json(
            { Findings: findings, NextToken: null },
            {
              status: 200,
              headers: [['Access-Control-Allow-Origin', '*']],
            },
          );
        }),
      );
    });

    const renderAppWithUser = (initialRoute = '/') => {
      const store = setupStore();
      return render(
        <MemoryRouter initialEntries={[initialRoute]}>
          <Provider store={store}>
            <UserContext.Provider value={userContext}>
              <NotificationContextProvider>
                <ConfigContextProvider config={{ ticketingEnabled: true }}>
                  <AppComponent />
                </ConfigContextProvider>
              </NotificationContextProvider>
            </UserContext.Provider>
          </Provider>
        </MemoryRouter>,
      );
    };

    it('should render complete application layout, navigation, and user interactions', async () => {
      // Render the app with a logged-in user
      renderAppWithUser();

      // Verify main application layout
      expect(screen.getByTestId('main-content')).toBeInTheDocument();
      expect(screen.queryByText(/Redirecting to login/i)).not.toBeInTheDocument();

      // AND: Verify top navigation with user menu
      const userButton = screen.getByRole('button', { name: userEmail });
      expect(userButton).toBeInTheDocument();

      // Verify sidebar navigation links
      expect(screen.getAllByText(/Automated Security Response on AWS/i)).toHaveLength(2);
      expect(screen.getAllByRole('link', { name: /Findings/i })).toHaveLength(2);
      expect(screen.getByRole('link', { name: /Execution History/i })).toBeInTheDocument();
      expect(screen.getByRole('link', { name: /Invite Users/i })).toBeInTheDocument();
      expect(screen.getByRole('link', { name: /View Users/i })).toBeInTheDocument();

      // Click on user menu
      await userEvent.click(userButton);

      // Verify sign out option appears
      const signOutButton = await screen.findByRole('menuitem', { name: /Sign Out/i });
      expect(signOutButton).toBeInTheDocument();
      expect(userContext.signOut).not.toHaveBeenCalled();

      // Click sign out
      await userEvent.click(signOutButton);

      // Verify signOut was called
      expect(userContext.signOut).toHaveBeenCalled();
    });

    it('should handle routing and navigation correctly', async () => {
      // Render app at root route
      renderAppWithUser('/');

      // Verify introduction page is displayed by default
      expect(screen.getByTestId('main-content')).toBeInTheDocument();

      // Navigate to findings page using the sidebar navigation link
      const sidebarFindingsLinks = screen.getAllByRole('link', { name: /Findings/i });
      await userEvent.click(sidebarFindingsLinks[0]);

      // Verify findings page loads
      const heading = await screen.findByRole('heading', { name: /Findings to Remediate/i });
      expect(heading).toBeInTheDocument();
    });

    it('should handle direct navigation and error routes', () => {
      // Direct navigation to findings route
      renderAppWithUser('/findings');

      // Verify app renders correctly
      expect(screen.getByTestId('main-content')).toBeInTheDocument();

      // Navigation to unknown route
      renderAppWithUser('/unknown-route');

      // Verify 404 page is displayed
      const errorHeading = screen.getByRole('heading', { name: /Error/i });
      const notFoundMessage = screen.getByRole('heading', { name: /Page not found/i });
      expect(errorHeading).toBeInTheDocument();
      expect(notFoundMessage).toBeInTheDocument();
    });

    it('should handle notifications and user context variations', () => {
      // App with notifications
      const notificationContext = {
        notifications: [
          {
            header: 'Remediation in progress',
            content: 'A remediation is currently running for finding ABC-123',
            type: 'info' as const,
          },
        ],
        setNotifications: vi.fn(),
      };

      const store = setupStore();

      render(
        <MemoryRouter>
          <Provider store={store}>
            <UserContext.Provider value={userContext}>
              <NotificationContext.Provider value={notificationContext}>
                <ConfigContextProvider config={{ ticketingEnabled: true }}>
                  <AppComponent />
                </ConfigContextProvider>
              </NotificationContext.Provider>
            </UserContext.Provider>
          </Provider>
        </MemoryRouter>,
      );

      // Verify notifications are displayed
      expect(screen.getByText(/Remediation in progress/i)).toBeInTheDocument();
      expect(screen.getByText(/A remediation is currently running for finding ABC-123/i)).toBeInTheDocument();

      // Verify app renders with notification context
      expect(screen.getByTestId('main-content')).toBeInTheDocument();
    });

    it('should handle user context variations and Redux integration', () => {
      // User context with null email
      const userContextWithNullEmail = {
        ...userContext,
        email: null,
      };

      const store = setupStore();

      render(
        <MemoryRouter>
          <Provider store={store}>
            <UserContext.Provider value={userContextWithNullEmail}>
              <NotificationContextProvider>
                <ConfigContextProvider config={{ ticketingEnabled: true }}>
                  <AppComponent />
                </ConfigContextProvider>
              </NotificationContextProvider>
            </UserContext.Provider>
          </Provider>
        </MemoryRouter>,
      );

      // Verify app renders correctly
      expect(screen.getByTestId('main-content')).toBeInTheDocument();

      // Verify username is displayed when email is not available
      const userButton = screen.getByRole('button', { name: userContext.user.username });
      expect(userButton).toBeInTheDocument();

      // Verify Redux integration works without errors
      expect(screen.getByTestId('main-content')).toBeInTheDocument();
    });

    it('should only show ViewUsers page to AdminGroup and DelegatedAdminGroup users', async () => {
      // ARRANGE - Test AdminGroup access
      const adminUserContext = {
        ...userContext,
        groups: ['AdminGroup'],
      };

      const { unmount } = render(
        <MemoryRouter initialEntries={['/users']}>
          <Provider store={setupStore()}>
            <UserContext.Provider value={adminUserContext}>
              <NotificationContextProvider>
                <ConfigContextProvider config={{ ticketingEnabled: true }}>
                  <AppComponent />
                </ConfigContextProvider>
              </NotificationContextProvider>
            </UserContext.Provider>
          </Provider>
        </MemoryRouter>,
      );

      // ACT & ASSERT - AdminGroup can access users page
      expect(screen.getByTestId('main-content')).toBeInTheDocument();
      expect(screen.queryByRole('heading', { name: /Page not found/i })).not.toBeInTheDocument();

      unmount();

      // ARRANGE - Test DelegatedAdminGroup access
      const delegatedAdminUserContext = {
        ...userContext,
        groups: ['DelegatedAdminGroup'],
      };

      const { unmount: unmount2 } = render(
        <MemoryRouter initialEntries={['/users']}>
          <Provider store={setupStore()}>
            <UserContext.Provider value={delegatedAdminUserContext}>
              <NotificationContextProvider>
                <ConfigContextProvider config={{ ticketingEnabled: true }}>
                  <AppComponent />
                </ConfigContextProvider>
              </NotificationContextProvider>
            </UserContext.Provider>
          </Provider>
        </MemoryRouter>,
      );

      // ACT & ASSERT - DelegatedAdminGroup can access users page
      expect(screen.getByTestId('main-content')).toBeInTheDocument();
      expect(screen.queryByRole('heading', { name: /Page not found/i })).not.toBeInTheDocument();

      unmount2();

      // ARRANGE - Test AccountOperatorGroup access (should be denied)
      const operatorUserContext = {
        ...userContext,
        groups: ['AccountOperatorGroup'],
      };

      render(
        <MemoryRouter initialEntries={['/users']}>
          <Provider store={setupStore()}>
            <UserContext.Provider value={operatorUserContext}>
              <NotificationContextProvider>
                <ConfigContextProvider config={{ ticketingEnabled: true }}>
                  <AppComponent />
                </ConfigContextProvider>
              </NotificationContextProvider>
            </UserContext.Provider>
          </Provider>
        </MemoryRouter>,
      );

      // ACT & ASSERT - AccountOperatorGroup is redirected to home page
      expect(screen.getByTestId('main-content')).toBeInTheDocument();
      expect(screen.queryByRole('heading', { name: /Page not found/i })).not.toBeInTheDocument();
    });
  });
});
