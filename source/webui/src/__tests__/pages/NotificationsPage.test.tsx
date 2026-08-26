// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { screen, within, waitFor, waitForElementToBeRemoved, render } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { http } from 'msw';
import { Provider } from 'react-redux';
import { createMemoryRouter } from 'react-router';
import { RouterProvider } from 'react-router/dom';
import { configureStore } from '@reduxjs/toolkit';
import { useContext } from 'react';

import { ok } from '../../mocks/handlers.ts';
import { ApiEndpoints, solutionApi } from '../../store/solutionApi.ts';
import { MOCK_SERVER_URL, server } from '../server.ts';
import { mockUserContext } from '../test-data-factory.ts';
import { NotificationsOverviewPage } from '../../pages/notifications/NotificationsOverviewPage.tsx';
import { UserContext } from '../../contexts/UserContext.tsx';
import { NotificationContext, NotificationContextProvider } from '../../contexts/NotificationContext.tsx';
import { rootReducer } from '../../store/store.ts';
import Flashbar from '@cloudscape-design/components/flashbar';
import { NotificationConfigurationItem } from '../../store/controlPanelTypes.ts';
import { ConfigId } from '@data-models';

const GlobalFlashbar = () => {
  const { notifications } = useContext(NotificationContext);
  return <Flashbar items={notifications} stackItems />;
};

beforeEach(() => {
  localStorage.clear();
});

afterEach(() => {
  server.resetHandlers();
});

const NOTIFICATIONS_URL = MOCK_SERVER_URL + ApiEndpoints.NOTIFICATIONS;
const CONTROLS_URL = MOCK_SERVER_URL + ApiEndpoints.CONTROLS;
const FILTERS_URL = MOCK_SERVER_URL + ApiEndpoints.FILTERS;

const createMockConfig = (overrides: Partial<NotificationConfigurationItem> = {}): NotificationConfigurationItem => ({
  configId: 'config-1' as ConfigId,
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

const renderNotificationsPage = () => {
  const store = configureStore({
    reducer: rootReducer,
    middleware: (getDefaultMiddleware) => getDefaultMiddleware().concat(solutionApi.middleware),
  });

  const router = createMemoryRouter(
    [
      {
        path: '/notifications',
        element: (
          <div data-testid="main-content">
            <NotificationsOverviewPage />
          </div>
        ),
      },
    ],
    { initialEntries: ['/notifications'] },
  );

  return render(
    <Provider store={store}>
      <UserContext.Provider value={{ ...mockUserContext }}>
        <NotificationContextProvider>
          <GlobalFlashbar />
          <RouterProvider router={router} />
        </NotificationContextProvider>
      </UserContext.Provider>
    </Provider>,
  );
};

async function waitForLoadingToFinish(container: ReturnType<typeof within>) {
  const existing = container.queryByText('Loading notification configurations');
  if (!existing) return;
  await waitForElementToBeRemoved(existing, { timeout: 2000 });
}

describe('NotificationsPage', () => {
  it('renders an empty table', async () => {
    server.use(
      http.get(NOTIFICATIONS_URL, async () => await ok({ configurations: [] })),
      http.get(CONTROLS_URL, async () => await ok({ controls: [] })),
      http.get(FILTERS_URL, async () => await ok({ filters: [] })),
    );

    renderNotificationsPage();

    const main = within(screen.getByTestId('main-content'));
    await waitForLoadingToFinish(main);

    expect(await main.findByText('No notification configurations')).toBeInTheDocument();
  });

  it('renders table with configs', async () => {
    const mockConfigs = [
      createMockConfig(),
      createMockConfig({
        configId: 'config-2' as ConfigId,
        name: 'Medium Findings',
        enabled: false,
        severityFilter: ['Medium'],
        deliveryChannels: [
          { type: 'slack', enabled: true, credentialsSecretArn: 'arn:aws:secretsmanager:us-east-1:123:secret:slack' },
        ],
      }),
      createMockConfig({
        configId: 'config-3' as ConfigId,
        name: 'Low Remediation',
        notificationType: 'remediation',
        severityFilter: ['Low'],
        controlIds: [],
        deliveryChannels: [
          {
            type: 'email',
            enabled: true,
            recipients: [{ recipientType: 'custom', emailAddresses: ['ops@example.com'] }],
          },
          { type: 'sns', enabled: true, topicArn: 'arn:aws:sns:us-east-1:123456789012:my-topic' },
        ],
      }),
    ];

    server.use(
      http.get(NOTIFICATIONS_URL, async () => await ok({ configurations: mockConfigs })),
      http.get(CONTROLS_URL, async () => await ok({ controls: [] })),
      http.get(FILTERS_URL, async () => await ok({ filters: [] })),
    );

    renderNotificationsPage();

    const main = within(screen.getByTestId('main-content'));
    await waitForLoadingToFinish(main);

    // Verify header counter
    expect(await main.findByRole('heading', { name: /Notifications\s*\(3\)/ })).toBeInTheDocument();

    // Verify table rows: 3 configs + 1 header row
    const table = await main.findByRole('table');
    const rows = await within(table).findAllByRole('row');
    expect(rows).toHaveLength(3 + 1);

    // Verify config names appear
    expect(within(table).getByText('Critical Alerts')).toBeInTheDocument();
    expect(within(table).getByText('Medium Findings')).toBeInTheDocument();
    expect(within(table).getByText('Low Remediation')).toBeInTheDocument();

    // Verify severity badges
    expect(within(table).getByText('Critical')).toBeInTheDocument();
    expect(within(table).getByText('Medium')).toBeInTheDocument();
    expect(within(table).getByText('Low')).toBeInTheDocument();

    // Verify channel badges exist (use getAllByText since channel names appear in multiple columns)
    expect(within(table).getAllByText('Email').length).toBeGreaterThanOrEqual(1);
    expect(within(table).getAllByText('Slack').length).toBeGreaterThanOrEqual(1);
    expect(within(table).getAllByText('SNS').length).toBeGreaterThanOrEqual(1);
  });

  it('calls PATCH API when toggle is clicked', async () => {
    const config = createMockConfig({ enabled: true });
    let patchCalled = false;
    let patchBody: Record<string, unknown> | null = null;

    server.use(
      http.get(NOTIFICATIONS_URL, async () => await ok({ configurations: [config] })),
      http.get(CONTROLS_URL, async () => await ok({ controls: [] })),
      http.get(FILTERS_URL, async () => await ok({ filters: [] })),
      http.patch(`${NOTIFICATIONS_URL}/:configId`, async ({ request }) => {
        patchCalled = true;
        patchBody = (await request.json()) as Record<string, unknown>;
        return await ok({ ...config, enabled: false });
      }),
    );

    renderNotificationsPage();

    const main = within(screen.getByTestId('main-content'));
    await waitForLoadingToFinish(main);

    // The toggle ariaLabel is "Toggle Critical Alerts off" when enabled
    const toggle = await main.findByLabelText('Toggle Critical Alerts off');
    await userEvent.click(toggle);

    await waitFor(() => {
      expect(patchCalled).toBe(true);
    });
    expect(patchBody).toMatchObject({ enabled: false, version: 1 });
  });

  it('filters table by name using text filter', async () => {
    const mockConfigs = [
      createMockConfig({ configId: 'config-1' as ConfigId, name: 'Production Alerts' }),
      createMockConfig({ configId: 'config-2' as ConfigId, name: 'Staging Notifications', severityFilter: ['Low'] }),
    ];

    server.use(
      http.get(NOTIFICATIONS_URL, async () => await ok({ configurations: mockConfigs })),
      http.get(CONTROLS_URL, async () => await ok({ controls: [] })),
      http.get(FILTERS_URL, async () => await ok({ filters: [] })),
    );

    renderNotificationsPage();

    const main = within(screen.getByTestId('main-content'));
    await waitForLoadingToFinish(main);

    // Both configs should be visible initially
    const table = await main.findByRole('table');
    let rows = await within(table).findAllByRole('row');
    expect(rows).toHaveLength(2 + 1);

    // Type in the filter input
    const filterInput = main.getByPlaceholderText('Search by name, channel type, or severity...');
    await userEvent.type(filterInput, 'Production');

    // Only the matching config should remain
    await waitFor(() => {
      const filteredRows = within(table).getAllByRole('row');
      expect(filteredRows).toHaveLength(1 + 1); // 1 match + header
    });
    expect(within(table).getByText('Production Alerts')).toBeInTheDocument();
    expect(within(table).queryByText('Staging Notifications')).not.toBeInTheDocument();
  });

  it('shows Create channel button', async () => {
    server.use(
      http.get(NOTIFICATIONS_URL, async () => await ok({ configurations: [] })),
      http.get(CONTROLS_URL, async () => await ok({ controls: [] })),
      http.get(FILTERS_URL, async () => await ok({ filters: [] })),
    );

    renderNotificationsPage();

    const main = within(screen.getByTestId('main-content'));
    await waitForLoadingToFinish(main);

    const createButton = await main.findByRole('button', { name: 'Create channel' });
    expect(createButton).toBeInTheDocument();
    expect(createButton).toBeEnabled();
  });
});
