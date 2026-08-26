// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { ReactNode, useMemo } from 'react';
import { UserContext } from './UserContext.tsx';

/**
 * Provides a mock user context for local development when Cognito auth is not configured.
 * Grants AdminGroup access so all pages (including Control Panel) are accessible.
 */
export const MockUserContextProvider = ({ children }: { children: ReactNode }) => {
  // Static mock value; memoized so the Context value identity is stable across renders.
  const contextValue = useMemo(
    () => ({
      user: { userId: 'mock-local-user', username: 'local-dev-user' } as any,
      email: 'local-dev@example.com',
      groups: ['AdminGroup'],
      signOut: () => Promise.resolve(),
      signInWithRedirect: () => Promise.resolve(),
      checkUser: () => Promise.resolve(),
    }),
    [],
  );

  return <UserContext.Provider value={contextValue}>{children}</UserContext.Provider>;
};
