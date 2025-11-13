// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { useContext } from 'react';
import { AppLayout, Flashbar } from '@cloudscape-design/components';
import SideNavigationBar from './components/navigation/SideNavigationBar.tsx';
import { NotificationContext } from './contexts/NotificationContext.tsx';
import { Outlet } from 'react-router-dom';
import { Breadcrumbs } from './components/navigation/Breadcrumbs.tsx';
import TopNavigationBar from './components/navigation/TopNavigationBar.tsx';

export default function Layout() {
  const { notifications } = useContext(NotificationContext);

  return (
    <>
      <div id="top-nav">
        <TopNavigationBar />
      </div>
      <div>
        <AppLayout
          headerSelector="#top-nav"
          content={
            <div data-testid={'main-content'}>
              <Outlet />
            </div>
          }
          contentType={'dashboard'}
          breadcrumbs={<Breadcrumbs />}
          navigation={<SideNavigationBar />}
          notifications={<Flashbar stackItems={true} items={notifications}></Flashbar>}
          stickyNotifications={true}
          toolsHide={true}
          ariaLabels={{
            navigation: 'Navigation drawer',
            navigationClose: 'Close navigation drawer',
            navigationToggle: 'Open navigation drawer',
            notifications: 'Notifications',
          }}
        />
      </div>
    </>
  );
}
