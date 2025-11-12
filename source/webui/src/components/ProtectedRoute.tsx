// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import React, { useContext } from 'react';
import { Navigate } from 'react-router-dom';
import { UserContext } from '../contexts/UserContext.tsx';
import { canAccessUsers } from '../utils/userPermissions.ts';

interface ProtectedRouteProps {
  children: React.ReactNode;
  requireUsersAccess?: boolean;
}

export const ProtectedRoute = ({ children, requireUsersAccess = false }: ProtectedRouteProps) => {
  const { groups } = useContext(UserContext);

  if (requireUsersAccess && !canAccessUsers(groups)) {
    return <Navigate to="/" replace />;
  }

  return <>{children}</>;
};
