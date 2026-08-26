// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import React, { createContext, ReactNode, useEffect, useState } from 'react';
import {
  AuthUser,
  fetchUserAttributes,
  getCurrentUser,
  signInWithRedirect,
  signOut,
  fetchAuthSession,
} from 'aws-amplify/auth';
import { Hub } from 'aws-amplify/utils';
import { AUTH_REDIRECT_DESTINATION_KEY } from '../utils/constants.ts';

export const UserContext = createContext<{
  user: AuthUser | null;
  email: string | null;
  groups: string[] | null;
  signOut: () => Promise<void>;
  signInWithRedirect: () => Promise<void>;
  checkUser: () => Promise<void>;
}>({
  user: null,
  email: null,
  groups: [],
  signOut: () => Promise.resolve(),
  signInWithRedirect: () => Promise.resolve(),
  checkUser: () => Promise.resolve(),
});

export const UserContextProvider = (props: { children: ReactNode }) => {
  const [user, setUser] = useState<AuthUser | null>(null);
  const [groups, setGroups] = useState<string[] | null>(null);
  const [email, setEmail] = useState<string | null>(null);

  useEffect(() => {
    Hub.listen('auth', ({ payload }) => {
      switch (payload.event) {
        case 'signInWithRedirect':
          checkUser();
          break;
        case 'signedOut':
          setUser(null);
          break;
      }
    });

    // Don't call checkUser immediately on callback page - let CallbackPage handle it
    const isCallbackPage = globalThis.location.pathname === '/callback';
    if (!isCallbackPage) {
      checkUser();
    }
  }, []);

  const checkUser = async () => {
    try {
      const responseUser: AuthUser | null = await getCurrentUser();
      setUser({
        ...responseUser,
      });
      try {
        const userAttributesOutput = await fetchUserAttributes();
        setEmail(userAttributesOutput.email ?? null);

        const authSession = await fetchAuthSession();
        const groups = authSession.tokens?.accessToken.payload['cognito:groups'] as string[];
        setGroups(groups);
      } catch (e) {
        setGroups([]); // Set groups to empty array to resolve loading state in ProtectedRoute

        console.log(e);
      }
    } catch (error) {
      console.error(error);
      setUser(null);
      setEmail(null);
      setGroups(null);

      const isCallbackPage = globalThis.location.pathname === '/callback';
      if (!isCallbackPage) {
        try {
          const currentPath = globalThis.location.pathname + globalThis.location.search + globalThis.location.hash;
          if (currentPath !== '/' && currentPath !== '/callback') {
            sessionStorage.setItem(AUTH_REDIRECT_DESTINATION_KEY, currentPath);
          }
          await signInWithRedirect();
        } catch (signInError) {
          console.debug('Sign in error:', signInError);
        }
      }
    }
  };

  return (
    <UserContext.Provider
      value={{
        user,
        email,
        groups,
        signOut,
        signInWithRedirect,
        checkUser,
      }}
    >
      {props.children}
    </UserContext.Provider>
  );
};
