// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { screen, within, waitForElementToBeRemoved, render } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { http } from 'msw';
import { Provider } from 'react-redux';
import { createMemoryRouter } from 'react-router';
import { RouterProvider } from 'react-router/dom';
import { configureStore } from '@reduxjs/toolkit';
import { describe, it, expect, afterEach, beforeEach } from 'vitest';

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

const OPERATOR_EMAIL = 'operator@example.com';

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

const setupServerWithConfigs = (configs: NotificationConfigurationItem[]): void => {
  server.use(
    http.get(NOTIFICATIONS_URL, async () => await ok({ configurations: configs })),
    http.get(CONTROLS_URL, async () => await ok({ controls: [] })),
    http.get(FILTERS_URL, async () => await ok({ filters: [] })),
  );
};

describe('NotificationsTable creator-based action gating', () => {
  it('shows the creator email in the "Created by" column', async () => {
    // updatedBy is set so the creator email is distinct from the "Modified By" fallback value.
    setupServerWithConfigs([createMockConfig({ createdBy: OPERATOR_EMAIL, updatedBy: 'editor@example.com' })]);

    renderNotificationsPage({ userContextOverrides: { groups: ['AdminGroup'] } });
    const main = within(screen.getByRole('main'));
    await waitForLoadingToFinish(main);

    const table = await main.findByRole('table');
    expect(within(table).getByText(OPERATOR_EMAIL)).toBeInTheDocument();
  });

  it('disables Edit and Delete for an operator on a config they did not create', async () => {
    setupServerWithConfigs([createMockConfig({ createdBy: 'someone-else@example.com' })]);

    renderNotificationsPage({
      userContextOverrides: { groups: ['AccountOperatorGroup'], email: OPERATOR_EMAIL },
    });
    const main = within(screen.getByRole('main'));
    await waitForLoadingToFinish(main);

    const actionsButton = await main.findByRole('button', { name: 'Actions for Critical Alerts' });
    await userEvent.click(actionsButton);

    const menuItems = await screen.findAllByRole('menuitem');
    const edit = menuItems.find((el) => el.textContent === 'Edit');
    const del = menuItems.find((el) => el.textContent === 'Delete');
    expect(edit).toHaveAttribute('aria-disabled', 'true');
    expect(del).toHaveAttribute('aria-disabled', 'true');
  });

  it('enables Edit and Delete for an operator on a config they created', async () => {
    setupServerWithConfigs([createMockConfig({ createdBy: OPERATOR_EMAIL })]);

    renderNotificationsPage({
      userContextOverrides: { groups: ['AccountOperatorGroup'], email: OPERATOR_EMAIL },
    });
    const main = within(screen.getByRole('main'));
    await waitForLoadingToFinish(main);

    const actionsButton = await main.findByRole('button', { name: 'Actions for Critical Alerts' });
    await userEvent.click(actionsButton);

    const menuItems = await screen.findAllByRole('menuitem');
    const edit = menuItems.find((el) => el.textContent === 'Edit');
    const del = menuItems.find((el) => el.textContent === 'Delete');
    expect(edit).not.toHaveAttribute('aria-disabled', 'true');
    expect(del).not.toHaveAttribute('aria-disabled', 'true');
  });

  it('disables the status toggle for an operator on a config they did not create', async () => {
    setupServerWithConfigs([createMockConfig({ createdBy: 'someone-else@example.com' })]);

    renderNotificationsPage({
      userContextOverrides: { groups: ['AccountOperatorGroup'], email: OPERATOR_EMAIL },
    });
    const main = within(screen.getByRole('main'));
    await waitForLoadingToFinish(main);

    const toggle = await main.findByRole('checkbox', { name: /Toggle Critical Alerts/ });
    expect(toggle).toBeDisabled();
  });

  it('leaves Edit and Delete enabled for admins regardless of creator', async () => {
    setupServerWithConfigs([createMockConfig({ createdBy: 'someone-else@example.com' })]);

    renderNotificationsPage({ userContextOverrides: { groups: ['AdminGroup'], email: 'admin@example.com' } });
    const main = within(screen.getByRole('main'));
    await waitForLoadingToFinish(main);

    const actionsButton = await main.findByRole('button', { name: 'Actions for Critical Alerts' });
    await userEvent.click(actionsButton);

    const menuItems = await screen.findAllByRole('menuitem');
    const edit = menuItems.find((el) => el.textContent === 'Edit');
    const del = menuItems.find((el) => el.textContent === 'Delete');
    expect(edit).not.toHaveAttribute('aria-disabled', 'true');
    expect(del).not.toHaveAttribute('aria-disabled', 'true');
  });
});
