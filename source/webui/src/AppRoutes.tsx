// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { Route, Routes, Navigate } from 'react-router';
import Layout from './Layout.tsx';
import { Container, ContentLayout, Header } from '@cloudscape-design/components';
import { FindingsOverviewPage } from './pages/findings/FindingsOverviewPage.tsx';
import { RemediationHistoryOverviewPage } from './pages/history/RemediationHistoryOverviewPage.tsx';
import { UsersOverviewPage } from './pages/users/UsersOverviewPage.tsx';
import { InviteUsersPage } from './pages/users/invite/InviteUsersPage.tsx';
import { ProtectedRoute } from './components/ProtectedRoute.tsx';
import { CallbackPage } from './pages/callback/CallbackPage.tsx';
import { ResourceFiltersOverviewPage } from './pages/resource-filters/ResourceFiltersOverviewPage.tsx';
import { NotificationsOverviewPage } from './pages/notifications/NotificationsOverviewPage.tsx';
import { ControlsOverviewPage } from './pages/controls/ControlsOverviewPage.tsx';

export const AppRoutes = () => (
  <Routes>
    <Route path="callback" element={<CallbackPage />} />
    <Route path={'/*'} element={<Layout />}>
      <Route index element={<Navigate to="/findings" replace />} />
      <Route path="findings" element={<FindingsOverviewPage />} />
      <Route path="history" element={<RemediationHistoryOverviewPage />} />
      <Route
        path="users"
        element={
          <ProtectedRoute requireUsersAccess>
            <UsersOverviewPage />
          </ProtectedRoute>
        }
      />
      <Route
        path="invite"
        element={
          <ProtectedRoute requireUsersAccess>
            <InviteUsersPage />
          </ProtectedRoute>
        }
      />
      <Route
        path="controls"
        element={
          <ProtectedRoute requireControlPanelAccess>
            <ControlsOverviewPage />
          </ProtectedRoute>
        }
      />
      <Route
        path="resource-filters"
        element={
          <ProtectedRoute requireControlPanelAccess>
            <ResourceFiltersOverviewPage />
          </ProtectedRoute>
        }
      />
      <Route
        path="notifications"
        element={
          <ProtectedRoute requireControlPanelAccess>
            <NotificationsOverviewPage />
          </ProtectedRoute>
        }
      />

      {/*<Route path="projects" element={<ProjectsOverviewPage />} />*/}
      {/*<Route path="projects/create" element={<ProjectCreatePage />} />*/}
      {/*<Route path="projects/:projectId" element={<ProjectDetailsPage />} />*/}

      {/* Add more child routes that use the same Layout here */}

      {/* IaC download — handled by Layout useEffect, render nothing */}
      <Route path="iac/*" element={null} />

      <Route
        path="*"
        element={
          <ContentLayout header={<Header>Error</Header>}>
            <Container header={<Header>Page not found 😿</Header>}></Container>
          </ContentLayout>
        }
      />
    </Route>

    {/* Add another set of routes with a different layout here */}
  </Routes>
);
