// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import '@aws-amplify/ui-react/styles.css';
import { useContext } from 'react';
import { AppRoutes } from './AppRoutes.tsx';
import { useDispatch } from 'react-redux';
import { UserContext } from './contexts/UserContext.tsx';
import { Spinner } from '@cloudscape-design/components';
import { useLocation } from 'react-router-dom';

export const AppComponent = () => {
  const dispatch = useDispatch<any>();
  const { user } = useContext(UserContext);
  const location = useLocation();

  /**
   * Load base data here that should be available on app start up for all pages.
   * Other data will only load once the user navigates to pages that require it.
   */

  // Allow callback page to render even without user
  if (!user && location.pathname !== '/callback') {
    return (
      <>
        <Spinner />
        <div>Redirecting to login...</div>
      </>
    );
  }

  return <AppRoutes></AppRoutes>;
};
