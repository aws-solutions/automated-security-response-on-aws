// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { DEFAULT_INITIAL_STATE } from '../store/types.ts';
import { configureStore } from '@reduxjs/toolkit';
import { Provider } from 'react-redux';
import { NotificationContextProvider } from '../contexts/NotificationContext.tsx';
import { UserContext } from '../contexts/UserContext.tsx';
import { ConfigContextProvider } from '../contexts/ConfigContext.tsx';
import { MemoryRouter } from 'react-router';
import { AppRoutes } from '../AppRoutes.tsx';
import { render } from '@testing-library/react';
import { rootReducer, RootState } from '../store/store.ts';
import { solutionApi } from '../store/solutionApi.ts';
import { AuthUser } from 'aws-amplify/auth';
import { ReactNode } from 'react';

/*
 * Render a page within the context of a Router, redux store and NotificationContext.
 *
 * This function provides setup for component tests that
 * - interact with the store state,
 *  -navigate between pages
 *  and/or
 * - emit notifications.
 */
export function renderAppContent(props?: {
  preloadedState?: Partial<RootState>;
  initialRoute: string;
  config?: { ticketingEnabled: boolean; solutionVersion: string };
  groups?: string[];
}) {
  const store = configureStore({
    reducer: rootReducer,
    preloadedState: props?.preloadedState ?? {},
    middleware: (getDefaultMiddleware) => getDefaultMiddleware().concat(solutionApi.middleware),
  });

  const defaultConfig = { ticketingEnabled: true, solutionVersion: '4.0.0' };
  const config = props?.config ?? defaultConfig;

  const mockUser: AuthUser = { userId: 'mock-local-user', username: 'local-dev-user' };
  const userContextValue = {
    user: mockUser,
    email: 'local-dev@example.com',
    groups: props?.groups ?? [],
    signOut: () => Promise.resolve(),
    signInWithRedirect: () => Promise.resolve(),
    checkUser: () => Promise.resolve(),
  };

  const UserProvider = ({ children }: { children: ReactNode }) => (
    <UserContext.Provider value={userContextValue}>{children}</UserContext.Provider>
  );

  const renderResult = render(
    <MemoryRouter initialEntries={[props?.initialRoute ?? '/']}>
      <Provider store={store}>
        <UserProvider>
          <NotificationContextProvider>
            <ConfigContextProvider config={config}>
              <AppRoutes></AppRoutes>
            </ConfigContextProvider>
          </NotificationContextProvider>
        </UserProvider>
      </Provider>
    </MemoryRouter>,
  );
  return {
    renderResult,
    store,
  };
}
