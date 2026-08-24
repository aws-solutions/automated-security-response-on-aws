// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { screen, within, waitFor, render } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { http, HttpResponse, delay } from 'msw';
import { Provider } from 'react-redux';
import { createMemoryRouter } from 'react-router';
import { RouterProvider } from 'react-router/dom';
import { configureStore } from '@reduxjs/toolkit';
import { vi } from 'vitest';

import { solutionApi, ApiEndpoints } from '../../store/solutionApi.ts';
import { MOCK_SERVER_URL, server } from '../server.ts';
import { rootReducer } from '../../store/store.ts';
import { UserContext } from '../../contexts/UserContext.tsx';
import { NotificationContextProvider } from '../../contexts/NotificationContext.tsx';
import { mockUserContext } from '../test-data-factory.ts';
import { TestNotificationDialog } from '../../pages/notifications/test-notification-dialog/TestNotificationDialog.tsx';
import { NotificationConfigurationItem, TestNotificationResult } from '@data-models';
import { ConfigId } from '@data-models';

const NOTIFICATIONS_URL = MOCK_SERVER_URL + ApiEndpoints.NOTIFICATIONS;

const createMockConfig = (overrides: Partial<NotificationConfigurationItem> = {}): NotificationConfigurationItem => ({
  configId: '00000000-0000-4000-8000-000000000001' as ConfigId,
  name: 'Production Alerts',
  enabled: true,
  notificationType: 'finding',
  severityFilter: ['Critical'],
  controlIds: ['S3.1'],
  resourceFilterIds: [],
  deliveryChannels: [
    {
      type: 'email',
      enabled: true,
      recipients: [
        { recipientType: 'rootAccountEmail', emailAddresses: ['primary@example.com'] },
        { recipientType: 'custom', emailAddresses: ['admin@example.com', 'ops@example.com'] },
      ],
    },
    {
      type: 'slack',
      enabled: true,
      channelId: 'C12345678',
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

const createSuccessResult = (config: NotificationConfigurationItem): TestNotificationResult => ({
  success: true,
  configId: config.configId,
  configName: config.name,
  eventId: 'aaaaaaaa-bbbb-4ccc-addd-111111111111',
  testedAt: '2025-06-01T12:00:00Z',
  results: {
    email: {
      channelType: 'email',
      enabled: true,
      status: 'success',
    },
    slack: {
      channelType: 'slack',
      enabled: true,
      status: 'success',
    },
  },
});

const createFailureResult = (config: NotificationConfigurationItem): TestNotificationResult => ({
  success: false,
  configId: config.configId,
  configName: config.name,
  eventId: 'aaaaaaaa-bbbb-4ccc-addd-222222222222',
  testedAt: '2025-06-01T12:00:00Z',
  results: {
    email: {
      channelType: 'email',
      enabled: true,
      status: 'success',
    },
    slack: {
      channelType: 'slack',
      enabled: true,
      status: 'failure',
      error: 'Webhook returned HTTP 403: Forbidden',
    },
  },
});

interface RenderDialogOptions {
  config?: NotificationConfigurationItem;
  onClose?: () => void;
  onEditConfig?: (configId: string) => void;
}

interface RenderDialogResult {
  config: NotificationConfigurationItem;
  onClose: () => void;
  onEditConfig: (configId: string) => void;
}

const renderDialog = (options: RenderDialogOptions = {}): RenderDialogResult => {
  const config = options.config ?? createMockConfig();
  const onClose = options.onClose ?? vi.fn();
  const onEditConfig = options.onEditConfig ?? vi.fn();

  const store = configureStore({
    reducer: rootReducer,
    middleware: (getDefaultMiddleware) => getDefaultMiddleware().concat(solutionApi.middleware),
  });

  const router = createMemoryRouter(
    [
      {
        path: '/notifications',
        element: <TestNotificationDialog config={config} onClose={onClose} onEditConfig={onEditConfig} />,
      },
    ],
    { initialEntries: ['/notifications'] },
  );

  render(
    <Provider store={store}>
      <UserContext.Provider value={{ ...mockUserContext }}>
        <NotificationContextProvider>
          <RouterProvider router={router} />
        </NotificationContextProvider>
      </UserContext.Provider>
    </Provider>,
  );

  return { config, onClose, onEditConfig };
};

const findVisibleDialog = async (): Promise<HTMLElement> => {
  return screen.findByRole('dialog');
};

describe('TestNotificationDialog', () => {
  afterEach(() => {
    vi.useRealTimers();
  });

  it('shows confirmation state with config name, enabled channels, and disabled config note', async () => {
    // ARRANGE
    const disabledConfig = createMockConfig({ enabled: false });

    // ACT
    renderDialog({ config: disabledConfig });

    // ASSERT
    const dialog = await findVisibleDialog();
    expect(within(dialog).getByText('Production Alerts')).toBeInTheDocument();
    expect(within(dialog).getByText(/email/i)).toBeInTheDocument();
    expect(within(dialog).getByText(/slack/i)).toBeInTheDocument();
    expect(within(dialog).getByText(/does not need to be enabled/i)).toBeInTheDocument();
  });

  it('does not show disabled config note when configuration is enabled', async () => {
    // ARRANGE
    const enabledConfig = createMockConfig({ enabled: true });

    // ACT
    renderDialog({ config: enabledConfig });

    // ASSERT
    const dialog = await findVisibleDialog();
    expect(within(dialog).getByText('Production Alerts')).toBeInTheDocument();
    expect(within(dialog).queryByText(/does not need to be enabled/i)).not.toBeInTheDocument();
  });

  it('shows loading state with spinner and disabled confirm button, and loading indicator is not visible before submit', async () => {
    // ARRANGE
    server.use(
      http.post(`${NOTIFICATIONS_URL}/:configId/test`, async () => {
        await delay(5000);
        return HttpResponse.json(createSuccessResult(createMockConfig()), { status: 200 });
      }),
    );

    renderDialog();

    const dialog = await findVisibleDialog();

    // ASSERT — loading indicator is NOT visible before submit
    expect(within(dialog).queryByText(/sending/i)).not.toBeInTheDocument();

    // ACT — click send test
    const sendButton = within(dialog).getByRole('button', { name: /send test/i });
    await userEvent.click(sendButton);

    // ASSERT — loading state shows spinner and disables confirm button
    await waitFor(() => {
      expect(within(dialog).getByRole('button', { name: /send test/i })).toBeDisabled();
    });
  });

  it('transitions to success state listing all channels by type name', async () => {
    // ARRANGE
    const config = createMockConfig();
    server.use(
      http.post(`${NOTIFICATIONS_URL}/:configId/test`, async () => {
        return HttpResponse.json(createSuccessResult(config), { status: 200 });
      }),
    );

    renderDialog({ config });

    // ACT
    const dialog = await findVisibleDialog();
    const sendButton = within(dialog).getByRole('button', { name: /send test/i });
    await userEvent.click(sendButton);

    // ASSERT — success state shows channel names and event ID
    expect(await within(dialog).findByText(/email/i)).toBeInTheDocument();
    expect(within(dialog).getByText(/slack/i)).toBeInTheDocument();
    expect(within(dialog).getByText('aaaaaaaa-bbbb-4ccc-addd-111111111111')).toBeInTheDocument();

    // ASSERT — loading indicator not visible after completion
    expect(within(dialog).queryByRole('button', { name: /send test/i })).not.toBeInTheDocument();
  });

  it('transitions to failure state showing per-channel error summary with mixed results', async () => {
    // ARRANGE
    const config = createMockConfig();
    server.use(
      http.post(`${NOTIFICATIONS_URL}/:configId/test`, async () => {
        return HttpResponse.json(createFailureResult(config), { status: 200 });
      }),
    );

    renderDialog({ config });

    // ACT
    const dialog = await findVisibleDialog();
    const sendButton = within(dialog).getByRole('button', { name: /send test/i });
    await userEvent.click(sendButton);

    // ASSERT — failure state shows both successful and failed channels with event ID
    expect(await within(dialog).findByText(/Webhook returned HTTP 403: Forbidden/)).toBeInTheDocument();
    expect(within(dialog).getByText(/email/i)).toBeInTheDocument();
    expect(within(dialog).getByText(/slack/i)).toBeInTheDocument();
    expect(within(dialog).getByText('aaaaaaaa-bbbb-4ccc-addd-222222222222')).toBeInTheDocument();
  });

  it('sends retry request with only failed channel types and updates error summary on retry failure', async () => {
    // ARRANGE
    const config = createMockConfig();
    let requestCount = 0;
    let capturedRetryBody: Record<string, unknown> | null = null;

    server.use(
      http.post(`${NOTIFICATIONS_URL}/:configId/test`, async ({ request }) => {
        requestCount++;
        const body = (await request.json()) as Record<string, unknown> | null;

        if (requestCount === 1) {
          return HttpResponse.json(createFailureResult(config), { status: 200 });
        }

        capturedRetryBody = body;
        return HttpResponse.json(
          {
            success: false,
            configId: config.configId,
            configName: config.name,
            eventId: 'aaaaaaaa-bbbb-4ccc-addd-333333333333',
            testedAt: '2025-06-01T12:01:00Z',
            results: {
              slack: {
                channelType: 'slack',
                enabled: true,
                status: 'failure',
                error: 'Connection timeout after 10 seconds',
              },
            },
          } satisfies TestNotificationResult,
          { status: 200 },
        );
      }),
    );

    renderDialog({ config });

    // ACT — trigger initial test
    const dialog = await findVisibleDialog();
    const sendButton = within(dialog).getByRole('button', { name: /send test/i });
    await userEvent.click(sendButton);

    // Wait for failure state
    expect(await within(dialog).findByText(/Webhook returned HTTP 403: Forbidden/)).toBeInTheDocument();

    // ACT — click retry
    const retryButton = within(dialog).getByRole('button', { name: /retry/i });
    await userEvent.click(retryButton);

    // ASSERT — retry sends only failed channel types
    await waitFor(() => expect(capturedRetryBody).not.toBeNull());
    expect(capturedRetryBody).toMatchObject({ channels: ['slack'] });

    // ASSERT — error summary updates with new failure reasons
    expect(await within(dialog).findByText(/Connection timeout after 10 seconds/)).toBeInTheDocument();
  });

  it('triggers onEditConfig callback when "Edit configuration" button is clicked', async () => {
    // ARRANGE
    const config = createMockConfig();
    const onEditConfig = vi.fn();

    server.use(
      http.post(`${NOTIFICATIONS_URL}/:configId/test`, async () => {
        return HttpResponse.json(createFailureResult(config), { status: 200 });
      }),
    );

    renderDialog({ config, onEditConfig });

    // ACT — trigger test to get to failure state
    const dialog = await findVisibleDialog();
    const sendButton = within(dialog).getByRole('button', { name: /send test/i });
    await userEvent.click(sendButton);

    // Wait for failure state
    expect(await within(dialog).findByText(/Webhook returned HTTP 403: Forbidden/)).toBeInTheDocument();

    // ACT — click edit configuration
    const editButton = within(dialog).getByRole('button', { name: /edit configuration/i });
    await userEvent.click(editButton);

    // ASSERT
    expect(onEditConfig).toHaveBeenCalledWith(config.configId);
  });

  it('calls onClose when "Close" button is clicked in success state', async () => {
    // ARRANGE
    const config = createMockConfig();
    const onClose = vi.fn();

    server.use(
      http.post(`${NOTIFICATIONS_URL}/:configId/test`, async () => {
        return HttpResponse.json(createSuccessResult(config), { status: 200 });
      }),
    );

    renderDialog({ config, onClose });

    // ACT
    const dialog = await findVisibleDialog();
    const sendButton = within(dialog).getByRole('button', { name: /send test/i });
    await userEvent.click(sendButton);

    // Wait for success state
    await within(dialog).findByText(/all channels delivered successfully/i);

    // ACT — click close
    const closeButton = within(dialog).getByRole('button', { name: /close/i });
    await userEvent.click(closeButton);

    // ASSERT
    expect(onClose).toHaveBeenCalled();
  });

  it('transitions to failure state after 30-second client-side timeout', async () => {
    // ARRANGE
    vi.useFakeTimers({ shouldAdvanceTime: true });
    const user = userEvent.setup({ advanceTimers: vi.advanceTimersByTime });

    server.use(
      http.post(`${NOTIFICATIONS_URL}/:configId/test`, async () => {
        await delay('infinite');
        return HttpResponse.json({}, { status: 200 });
      }),
    );

    renderDialog();

    // ACT
    const dialog = await findVisibleDialog();
    const sendButton = within(dialog).getByRole('button', { name: /send test/i });
    await user.click(sendButton);

    // Advance time past 30-second timeout
    vi.advanceTimersByTime(31_000);

    // ASSERT — failure state after timeout
    await waitFor(() => {
      expect(within(dialog).getByText(/timed out|timeout/i)).toBeInTheDocument();
    });
  });

  it('displays channel-specific details for JIRA, ServiceNow, and SNS channels', async () => {
    // ARRANGE
    const config = createMockConfig({
      deliveryChannels: [
        {
          type: 'jira',
          enabled: true,
          projectKey: 'SEC',
          issueType: 'Bug',
          endpointUrl: 'https://jira.corp.example.com',
          credentialsSecretArn: 'arn:aws:secretsmanager:us-east-1:123456789012:secret:asr/notifications/jira-abc',
          customFieldMappings: [],
        },
        {
          type: 'servicenow',
          enabled: true,
          endpointUrl: 'https://dev12345.service-now.com',
          tableName: 'incident',
          credentialsSecretArn: 'arn:aws:secretsmanager:us-east-1:123456789012:secret:asr/notifications/snow-abc',
          customFieldMappings: [],
        },
        {
          type: 'sns',
          enabled: true,
          topicArn: 'arn:aws:sns:us-east-1:123456789012:security-alerts',
        },
      ],
    });

    // ACT
    renderDialog({ config });

    // ASSERT
    const dialog = await findVisibleDialog();
    expect(within(dialog).getByText(/https:\/\/jira\.corp\.example\.com/)).toBeInTheDocument();
    expect(within(dialog).getByText(/Project: SEC/)).toBeInTheDocument();
    expect(within(dialog).getByText(/https:\/\/dev12345\.service-now\.com/)).toBeInTheDocument();
    expect(within(dialog).getByText(/Table: incident/)).toBeInTheDocument();
    expect(within(dialog).getByText(/arn:aws:sns:us-east-1:123456789012:security-alerts/)).toBeInTheDocument();
  });

  it('transitions to failure state when the API request throws a network error and retries all channels', async () => {
    // ARRANGE
    let requestCount = 0;
    let capturedRetryBody: Record<string, unknown> | null = null;

    server.use(
      http.post(`${NOTIFICATIONS_URL}/:configId/test`, async ({ request }) => {
        requestCount++;
        if (requestCount === 1) {
          return HttpResponse.error();
        }
        capturedRetryBody = (await request.json()) as Record<string, unknown> | null;
        return HttpResponse.json(createSuccessResult(createMockConfig()), { status: 200 });
      }),
    );

    renderDialog();

    // ACT
    const dialog = await findVisibleDialog();
    const sendButton = within(dialog).getByRole('button', { name: /send test/i });
    await userEvent.click(sendButton);

    // ASSERT — transitions to failure state with user-visible network error message
    expect(await within(dialog).findByText(/network error occurred/i)).toBeInTheDocument();
    expect(within(dialog).queryByText(/Event ID/)).not.toBeInTheDocument();
    const retryButton = within(dialog).getByRole('button', { name: /retry/i });
    expect(retryButton).toBeInTheDocument();

    // ACT — click retry (should send all channels since results is empty)
    await userEvent.click(retryButton);

    // ASSERT — retry sends undefined (no channels filter), not an empty array
    await waitFor(() => expect(capturedRetryBody).not.toBeNull());
    expect(capturedRetryBody).not.toHaveProperty('channels');
  });
});
