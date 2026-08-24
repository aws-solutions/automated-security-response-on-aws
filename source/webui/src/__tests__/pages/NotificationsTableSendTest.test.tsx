// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { screen, within, waitForElementToBeRemoved, render } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { http } from 'msw';
import { Provider } from 'react-redux';
import { createMemoryRouter } from 'react-router';
import { RouterProvider } from 'react-router/dom';
import { configureStore } from '@reduxjs/toolkit';
import { vi, describe, it, expect, afterEach, beforeEach } from 'vitest';

import { ok } from '../../mocks/handlers.ts';
import { ApiEndpoints, solutionApi } from '../../store/solutionApi.ts';
import { MOCK_SERVER_URL, server } from '../server.ts';
import { mockUserContext } from '../test-data-factory.ts';
import { NotificationsOverviewPage } from '../../pages/notifications/NotificationsOverviewPage.tsx';
import { UserContext } from '../../contexts/UserContext.tsx';
import { NotificationContextProvider } from '../../contexts/NotificationContext.tsx';
import { rootReducer } from '../../store/store.ts';
import { NotificationConfigurationItem } from '../../store/controlPanelTypes.ts';
import { ConfigId } from '@data-models';

const NOTIFICATIONS_URL = MOCK_SERVER_URL + ApiEndpoints.NOTIFICATIONS;
const CONTROLS_URL = MOCK_SERVER_URL + ApiEndpoints.CONTROLS;
const FILTERS_URL = MOCK_SERVER_URL + ApiEndpoints.FILTERS;

beforeEach(() => {
  localStorage.clear();
});

afterEach(() => {
  server.resetHandlers();
});

const createMockConfig = (overrides: Partial<NotificationConfigurationItem> = {}): NotificationConfigurationItem => ({
  configId: '00000000-0000-4000-8000-000000000001' as ConfigId,
  name: 'Critical Alerts',
  enabled: true,
  notificationType: 'finding',
  severityFilter: ['Critical'],
  controlIds: ['S3.1'],
  resourceFilterIds: [],
  deliveryChannels: [
    {
      type: 'email',
      enabled: true,
      recipients: [{ recipientType: 'custom', emailAddresses: ['admin@example.com'] }],
    },
    {
      type: 'slack',
      enabled: true,
      credentialsSecretArn: 'arn:aws:secretsmanager:us-east-1:123456789012:secret:asr/notifications/slack-abc',
    },
  ],
  batchWindow: { enabled: false },
  contentOptions: {
    includeManualRemediationLink: false,
    includeRemediationDeadline: false,
    enforceDeadline: false,
    includeIaCSnippet: false,
    includeEnableAutomationLink: false,
  },
  version: 1,
  createdAt: '2025-01-01T00:00:00Z',
  createdBy: 'admin',
  ...overrides,
});

interface RenderOptions {
  userContextOverrides?: Partial<typeof mockUserContext>;
}

const renderNotificationsPage = ({ userContextOverrides }: RenderOptions = {}): ReturnType<typeof render> => {
  const store = configureStore({
    reducer: rootReducer,
    middleware: (getDefaultMiddleware) => getDefaultMiddleware().concat(solutionApi.middleware),
  });

  const contextValue = { ...mockUserContext, ...userContextOverrides };

  const router = createMemoryRouter(
    [
      {
        path: '/notifications',
        element: (
          <main>
            <NotificationsOverviewPage />
          </main>
        ),
      },
    ],
    { initialEntries: ['/notifications'] },
  );

  return render(
    <Provider store={store}>
      <UserContext.Provider value={contextValue}>
        <NotificationContextProvider>
          <RouterProvider router={router} />
        </NotificationContextProvider>
      </UserContext.Provider>
    </Provider>,
  );
};

async function waitForLoadingToFinish(container: ReturnType<typeof within>): Promise<void> {
  const existing = container.queryByText('Loading notification configurations');
  if (!existing) return;
  await waitForElementToBeRemoved(existing, { timeout: 2000 });
}

const setupServerWithConfig = (configs: NotificationConfigurationItem[]): void => {
  server.use(
    http.get(NOTIFICATIONS_URL, async () => await ok({ configurations: configs })),
    http.get(CONTROLS_URL, async () => await ok({ controls: [] })),
    http.get(FILTERS_URL, async () => await ok({ filters: [] })),
  );
};

describe('NotificationsTable "Send test" action', () => {
  it.each([
    // Admins and delegated admins can send tests on any config. An operator can only send tests on
    // configs they created — createMockConfig() is created by 'admin', so the operator cannot here.
    { role: 'AdminGroup', shouldShowSendTest: true },
    { role: 'DelegatedAdminGroup', shouldShowSendTest: true },
    { role: 'AccountOperatorGroup', shouldShowSendTest: false },
  ])('$role: "Send test" visibility is $shouldShowSendTest', async ({ role, shouldShowSendTest }) => {
    // ARRANGE
    const config = createMockConfig();
    setupServerWithConfig([config]);

    // ACT
    renderNotificationsPage({ userContextOverrides: { groups: [role] } });
    const main = within(screen.getByRole('main'));
    await waitForLoadingToFinish(main);

    const actionsButton = await main.findByRole('button', { name: 'Actions for Critical Alerts' });
    await userEvent.click(actionsButton);

    // ASSERT
    const menuItems = await screen.findAllByRole('menuitem');
    const sendTestItem = menuItems.find((el) => el.textContent === 'Send test');

    if (shouldShowSendTest) {
      expect(sendTestItem).toBeDefined();
    } else {
      expect(sendTestItem).toBeUndefined();
    }
  });

  it('shows "Send test" to an operator on a configuration they created', async () => {
    // ARRANGE - config created by the current operator
    const config = createMockConfig({ createdBy: 'current@example.com' });
    setupServerWithConfig([config]);

    // ACT
    renderNotificationsPage({
      userContextOverrides: { groups: ['AccountOperatorGroup'], email: 'current@example.com' },
    });
    const main = within(screen.getByRole('main'));
    await waitForLoadingToFinish(main);

    const actionsButton = await main.findByRole('button', { name: 'Actions for Critical Alerts' });
    await userEvent.click(actionsButton);

    // ASSERT - Send test and Email subscriptions are both available on their own config
    const menuItems = await screen.findAllByRole('menuitem');
    expect(menuItems.find((el) => el.textContent === 'Send test')).toBeDefined();
    expect(menuItems.find((el) => el.textContent === 'Email subscriptions')).toBeDefined();
  });

  it('is visible for both enabled and disabled configurations', async () => {
    // ARRANGE
    const enabledConfig = createMockConfig({
      configId: 'config-enabled' as ConfigId,
      name: 'Enabled Config',
      enabled: true,
    });
    const disabledConfig = createMockConfig({
      configId: 'config-disabled' as ConfigId,
      name: 'Disabled Config',
      enabled: false,
    });
    setupServerWithConfig([enabledConfig, disabledConfig]);

    // ACT
    renderNotificationsPage({ userContextOverrides: { groups: ['AdminGroup'] } });
    const main = within(screen.getByRole('main'));
    await waitForLoadingToFinish(main);

    // ASSERT — "Send test" appears in dropdown for the enabled config
    const enabledActionsButton = await main.findByRole('button', { name: 'Actions for Enabled Config' });
    await userEvent.click(enabledActionsButton);

    const enabledMenuItems = await screen.findAllByRole('menuitem');
    const enabledSendTest = enabledMenuItems.find((el) => el.textContent === 'Send test');
    expect(enabledSendTest).toBeDefined();

    // Close the dropdown by pressing Escape
    await userEvent.keyboard('{Escape}');

    // ASSERT — "Send test" appears in dropdown for the disabled config
    const disabledActionsButton = await main.findByRole('button', { name: 'Actions for Disabled Config' });
    await userEvent.click(disabledActionsButton);

    const disabledMenuItems = await screen.findAllByRole('menuitem');
    const disabledSendTest = disabledMenuItems.find((el) => el.textContent === 'Send test');
    expect(disabledSendTest).toBeDefined();
  });

  it('opens TestNotificationDialog when "Send test" is clicked', async () => {
    // ARRANGE
    const config = createMockConfig();
    setupServerWithConfig([config]);

    // ACT
    renderNotificationsPage({ userContextOverrides: { groups: ['AdminGroup'] } });
    const main = within(screen.getByRole('main'));
    await waitForLoadingToFinish(main);

    const actionsButton = await main.findByRole('button', { name: 'Actions for Critical Alerts' });
    await userEvent.click(actionsButton);

    const menuItems = await screen.findAllByRole('menuitem');
    const sendTestItem = menuItems.find((el) => el.textContent === 'Send test');
    if (!sendTestItem) throw new Error('Expected "Send test" menu item to exist');
    await userEvent.click(sendTestItem);

    // ASSERT — TestNotificationDialog is shown with the config name and enabled channels
    expect(await screen.findByText('Send test notification')).toBeInTheDocument();
    expect(
      screen.getByText(/A synthetic test notification will be sent to all enabled channels on/),
    ).toBeInTheDocument();
    expect(screen.getByText(/Channels to test/)).toBeInTheDocument();
  });
});
