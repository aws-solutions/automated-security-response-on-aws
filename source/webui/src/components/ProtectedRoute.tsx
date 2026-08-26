// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import React, { useContext } from 'react';
import { Navigate } from 'react-router';
import { Spinner, Box } from '@cloudscape-design/components';
import { UserContext } from '../contexts/UserContext.tsx';
import { canAccessUsers, canAccessControlPanel } from '../utils/userPermissions.ts';

interface ProtectedRouteProps {
  children: React.ReactNode;
  requireUsersAccess?: boolean;
  requireControlPanelAccess?: boolean;
}

export const ProtectedRoute = ({
  children,
  requireUsersAccess = false,
  requireControlPanelAccess = false,
}: ProtectedRouteProps) => {
  const { groups, user } = useContext(UserContext);

  // Wait for user context to fully load before making access decisions
  // groups is null while loading, becomes an array (possibly empty) once loaded
  if (user && groups === null) {
    return (
      <Box textAlign="center" padding="xxl">
        <Spinner size="large" />
      </Box>
    );
  }

  if (requireUsersAccess && !canAccessUsers(groups)) {
    return <Navigate to="/" replace />;
  }

  if (requireControlPanelAccess && !canAccessControlPanel(groups)) {
    return <Navigate to="/findings" replace />;
  }

  return <>{children}</>;
};
