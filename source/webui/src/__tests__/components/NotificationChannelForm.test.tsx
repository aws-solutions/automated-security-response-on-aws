// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { vi, describe, it, expect, beforeEach } from 'vitest';
import { Provider } from 'react-redux';
import { configureStore } from '@reduxjs/toolkit';
import { http } from 'msw';

import { MOCK_SERVER_URL, server } from '../server.ts';
import { ok } from '../../mocks/handlers.ts';

import NotificationChannelForm from '../../pages/notifications/notification-channel-form/NotificationChannelForm.tsx';
import { NotificationChannelFormProps } from '../../pages/notifications/notification-channel-form/NotificationChannelForm.tsx';
import { NotificationConfigurationItem } from '../../store/controlPanelTypes.ts';
import { ConfigIdSchema, SecurityControl } from '@data-models';
import { rootReducer } from '../../store/store.ts';
import { solutionApi } from '../../store/solutionApi.ts';

const defaultProps: NotificationChannelFormProps = {
  mode: 'create',
  resourceFilters: [],
  controls: [],
  onSubmit: vi.fn(),
  onCancel: vi.fn(),
  isSubmitting: false,
};

const renderForm = (overrides: Partial<NotificationChannelFormProps> = {}) => {
  const store = configureStore({
    reducer: rootReducer,
    middleware: (getDefaultMiddleware) => getDefaultMiddleware().concat(solutionApi.middleware),
  });
  // A fresh element on every call: re-rendering the identical element reference lets
  // React bail out of the subtree entirely, which would defeat rerenderSameProps.
  const formTree = () => (
    <Provider store={store}>
      <NotificationChannelForm {...defaultProps} {...overrides} />
    </Provider>
  );
  const result = render(formTree());
  return { ...result, rerenderSameProps: () => result.rerender(formTree()) };
};

/** Click the wizard "Next" button. */
const clickNext = async () => {
  const btn = await screen.findByRole('button', { name: /next/i });
  await userEvent.click(btn);
};

/** Navigate forward through N wizard steps. */
const advanceSteps = async (count: number) => {
  for (let i = 0; i < count; i++) {
    await clickNext();
  }
};

/** Fill name, enable email with primary contact, and advance to the content options step. */
const advanceToContentOptionsStep = async (name: string) => {
  const nameInput = screen.getByPlaceholderText('e.g., Critical Findings - Security Team');
  await userEvent.type(nameInput, name);
  await clickNext();
  const emailCheckbox = await screen.findByLabelText('Email');
  await userEvent.click(emailCheckbox);
  const primaryCheckbox = await screen.findByLabelText('Primary account contact');
  await userEvent.click(primaryCheckbox);
  await advanceSteps(2);
};

/** Fill name, enable email with primary contact, and advance to filters step. */
const setupFormToFiltersStep = async (name: string) => {
  await advanceToContentOptionsStep(name);
  await clickNext();
};

const createTestNotificationConfig = (
  overrides: Partial<NotificationConfigurationItem> = {},
): NotificationConfigurationItem => ({
  configId: '00000000-0000-4000-8000-000000000001' as NotificationConfigurationItem['configId'],
  name: 'Test Config',
  enabled: true,
  notificationType: 'finding',
  severityFilter: [],
  controlIds: [],
  resourceFilterIds: [],
  deliveryChannels: [{ type: 'email', enabled: true, recipients: [{ recipientType: 'rootAccountEmail' }] }],
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

const createTestControl = (overrides: Partial<SecurityControl> = {}): SecurityControl => ({
  controlId: 'S3.1',
  description: 'Block public access',
  automatedRemediationEnabled: true,
  filters: [],
  filterMode: 'include',
  version: 1,
  lastModified: '2025-01-01T00:00:00Z',
  modifiedBy: 'admin',
  ...overrides,
});

describe('NotificationChannelForm', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('renders wizard with first step showing basic information fields', async () => {
    renderForm();

    // Wizard step title appears in both nav and content — verify at least one exists
    const titles = await screen.findAllByText('Basic information');
    expect(titles.length).toBeGreaterThanOrEqual(1);

    // Name input with placeholder
    expect(screen.getByPlaceholderText('e.g., Critical Findings - Security Team')).toBeInTheDocument();

    // Notification type radio options
    expect(screen.getByText('Finding')).toBeInTheDocument();
    expect(screen.getByText('Remediation')).toBeInTheDocument();
  });

  it('shows validation error when trying to advance with empty name', async () => {
    renderForm();

    // ACT — try to advance past step 1 without filling name
    await clickNext();

    // ASSERT — Validation error appears and wizard stays on step 1
    await waitFor(() => {
      const errors = screen.getAllByText(/configuration name is required/i);
      expect(errors.length).toBeGreaterThanOrEqual(1);
    });
  });

  it('shows validation error when no delivery channel is enabled', async () => {
    renderForm();

    // Fill in name on step 1
    const nameInput = screen.getByPlaceholderText('e.g., Critical Findings - Security Team');
    await userEvent.type(nameInput, 'Test Config');

    // Navigate to step 2
    await clickNext();

    // ACT — try to advance past step 2 without enabling any channel
    await clickNext();

    // ASSERT — should show channel validation error and stay on step 2
    await waitFor(() => {
      const errors = screen.getAllByText(/at least one delivery channel must be enabled/i);
      expect(errors.length).toBeGreaterThanOrEqual(1);
    });
  });

  it('submits correct payload when creating with email channel', async () => {
    const onSubmit = vi.fn();
    renderForm({ onSubmit });

    // Step 1: Fill name
    const nameInput = screen.getByPlaceholderText('e.g., Critical Findings - Security Team');
    await userEvent.type(nameInput, 'My Email Config');

    await clickNext();

    // Step 2: Enable email channel
    const emailCheckbox = await screen.findByLabelText('Email', {}, { timeout: 3000 });
    await userEvent.click(emailCheckbox);

    // Select "Primary account contact" recipient
    const primaryCheckbox = await screen.findByLabelText('Primary account contact', {}, { timeout: 3000 });
    await userEvent.click(primaryCheckbox);

    // Navigate through remaining steps (batching, content, filters)
    await advanceSteps(3);

    // Submit on last step
    const submitBtn = await screen.findByRole('button', { name: /create configuration/i });
    await userEvent.click(submitBtn);

    await waitFor(() => {
      expect(onSubmit).toHaveBeenCalledTimes(1);
    });

    const payload = onSubmit.mock.calls[0][0];
    expect(payload.name).toBe('My Email Config');
    expect(payload.enabled).toBe(true);
    expect(payload.notificationType).toBe('finding');
    expect(payload.deliveryChannels).toHaveLength(1);
    expect(payload.deliveryChannels[0].type).toBe('email');
    expect(payload.deliveryChannels[0].recipients).toEqual(
      expect.arrayContaining([expect.objectContaining({ recipientType: 'rootAccountEmail' })]),
    );
    // Default filter selection ('All' sentinel) must NOT be persisted as a literal
    // value — the backend filters would never match against the string 'All'.
    expect(payload.severityFilter).toBeUndefined();
    expect(payload.remediationStatusFilter).toBeUndefined();
  });

  it('calls onCancel when Cancel button is clicked', async () => {
    const onCancel = vi.fn();
    renderForm({ onCancel });

    const cancelBtn = await screen.findByRole('button', { name: /cancel/i });
    await userEvent.click(cancelBtn);

    expect(onCancel).toHaveBeenCalledTimes(1);
  });

  it('populates form fields from initialValues in edit mode', async () => {
    const initialValues: NotificationConfigurationItem = {
      configId: '00000000-0000-4000-8000-000000000001' as NotificationConfigurationItem['configId'],
      name: 'Existing Config',
      enabled: true,
      notificationType: 'finding',
      severityFilter: ['High'],
      controlIds: [],
      resourceFilterIds: [],
      deliveryChannels: [
        {
          type: 'email',
          enabled: true,
          recipients: [{ recipientType: 'rootAccountEmail' }],
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
    };

    renderForm({ mode: 'edit', initialValues });

    // Verify name input is pre-filled
    const nameInput = screen.getByPlaceholderText('e.g., Critical Findings - Security Team');
    expect(nameInput).toHaveValue('Existing Config');
  });

  describe('Email channel validation', () => {
    it('shows validation error when email is enabled but no recipient checkbox or custom email is provided', async () => {
      // ARRANGE
      renderForm();

      const nameInput = screen.getByPlaceholderText('e.g., Critical Findings - Security Team');
      await userEvent.type(nameInput, 'Email Test Config');

      await clickNext();

      // Enable email channel without selecting any recipients
      const emailCheckbox = await screen.findByLabelText('Email');
      await userEvent.click(emailCheckbox);

      // ACT — try to advance past step 2
      await clickNext();

      // ASSERT — recipient validation error is shown
      await waitFor(() => {
        const errors = screen.getAllByText(/select at least one recipient type or enter a custom email address/i);
        expect(errors.length).toBeGreaterThanOrEqual(1);
      });
    });

    it('passes validation when email is enabled with only a custom email address', async () => {
      // ARRANGE
      const onSubmit = vi.fn();
      renderForm({ onSubmit });

      const nameInput = screen.getByPlaceholderText('e.g., Critical Findings - Security Team');
      await userEvent.type(nameInput, 'Custom Email Config');

      await clickNext();

      // Enable email channel
      const emailCheckbox = await screen.findByLabelText('Email');
      await userEvent.click(emailCheckbox);

      // Add a custom email without selecting any recipient checkboxes
      const emailInput = await screen.findByPlaceholderText('user@example.com');
      await userEvent.type(emailInput, 'team@example.com{enter}');

      // ACT — advance through remaining steps
      await advanceSteps(3);

      const submitBtn = await screen.findByRole('button', { name: /create configuration/i });
      await userEvent.click(submitBtn);

      // ASSERT — form submits successfully
      await waitFor(() => {
        expect(onSubmit).toHaveBeenCalledTimes(1);
      });

      const payload = onSubmit.mock.calls[0][0];
      expect(payload.deliveryChannels[0].type).toBe('email');
      expect(payload.deliveryChannels[0].recipients).toEqual(
        expect.arrayContaining([
          expect.objectContaining({ recipientType: 'custom', emailAddresses: ['team@example.com'] }),
        ]),
      );
    });

    it('passes validation when email is enabled with only a recipient checkbox selected', async () => {
      // ARRANGE
      renderForm();

      const nameInput = screen.getByPlaceholderText('e.g., Critical Findings - Security Team');
      await userEvent.type(nameInput, 'Checkbox Email Config');

      await clickNext();

      // Enable email channel
      const emailCheckbox = await screen.findByLabelText('Email');
      await userEvent.click(emailCheckbox);

      // Select only a recipient checkbox, no custom emails
      const securityCheckbox = await screen.findByLabelText('Security contact');
      await userEvent.click(securityCheckbox);

      // ACT — try to advance past step 2
      await clickNext();

      // ASSERT — no validation error, wizard advances to step 3
      await waitFor(() => {
        expect(screen.getByText('Batching Configuration')).toBeInTheDocument();
      });
    });
  });

  describe('Remediation deadline disabled for Remediation type', () => {
    it('hides the remediation deadline option entirely when notification type is Remediation', async () => {
      // ARRANGE
      renderForm();

      const nameInput = screen.getByPlaceholderText('e.g., Critical Findings - Security Team');
      await userEvent.type(nameInput, 'Remediation Config');

      // Select Remediation type
      const remediationRadio = screen.getByRole('radio', { name: /remediation/i });
      await userEvent.click(remediationRadio);

      await clickNext();

      // Enable email channel to pass step 2 validation
      const emailCheckbox = await screen.findByLabelText('Email');
      await userEvent.click(emailCheckbox);
      const primaryCheckbox = await screen.findByLabelText('Primary account contact');
      await userEvent.click(primaryCheckbox);

      // ACT — navigate to Content Options step (step 4)
      await advanceSteps(2);

      // ASSERT — deadline FormField is not rendered at all for remediation type
      expect(screen.queryByLabelText('Include remediation deadline')).not.toBeInTheDocument();
      expect(screen.queryByText('Remediation deadline only applies to Finding notifications.')).not.toBeInTheDocument();

      // ASSERT — manual remediation link is enabled (shows as history link for remediation type)
      const manualLinkCheckbox = screen.getByLabelText('Include history link');
      expect(manualLinkCheckbox).not.toBeDisabled();
    });

    it('unchecks and hides the deadline option when switching from Finding to Remediation after enabling it', async () => {
      // ARRANGE
      renderForm();

      const nameInput = screen.getByPlaceholderText('e.g., Critical Findings - Security Team');
      await userEvent.type(nameInput, 'Switch Type Config');

      // Leave as Finding (default), advance to step 2
      await clickNext();

      // Enable email channel
      const emailCheckbox = await screen.findByLabelText('Email');
      await userEvent.click(emailCheckbox);
      const primaryCheckbox = await screen.findByLabelText('Primary account contact');
      await userEvent.click(primaryCheckbox);

      // Advance to Content Options (step 4)
      await advanceSteps(2);

      // Enable the remediation deadline checkbox
      const deadlineCheckbox = screen.getByLabelText('Include remediation deadline');
      await userEvent.click(deadlineCheckbox);
      expect(deadlineCheckbox).toBeChecked();

      // Enable the manual remediation link checkbox
      const manualLinkCheckbox = screen.getByLabelText('Include remediation link');
      await userEvent.click(manualLinkCheckbox);
      expect(manualLinkCheckbox).toBeChecked();

      // Verify deadline days input is visible
      expect(screen.getByPlaceholderText('7')).toBeInTheDocument();

      // ACT — navigate back to step 1 using wizard nav link
      const step1Link = screen.getAllByRole('button', { name: /step 1: basic information/i })[0];
      await userEvent.click(step1Link);

      // Switch to Remediation type
      await waitFor(() => {
        expect(screen.getByText('Finding')).toBeInTheDocument();
      });
      const remediationLabel = screen.getByText('Remediation');
      await userEvent.click(remediationLabel);

      // Navigate back to Content Options (step 4)
      await advanceSteps(3);

      // ASSERT — entire deadline section is hidden after switching to remediation
      expect(screen.queryByLabelText('Include remediation deadline')).not.toBeInTheDocument();
      expect(screen.queryByPlaceholderText('7')).not.toBeInTheDocument();
      expect(screen.queryByText('Remediation deadline only applies to Finding notifications.')).not.toBeInTheDocument();

      // ASSERT — manual remediation link is checked and is enabled
      const updatedManualLink = screen.getByLabelText('Include history link');
      expect(updatedManualLink).toBeChecked();
      expect(updatedManualLink).not.toBeDisabled();
    });

    it('enables the remediation deadline checkbox when notification type is Finding', async () => {
      // ARRANGE
      renderForm();

      const nameInput = screen.getByPlaceholderText('e.g., Critical Findings - Security Team');
      await userEvent.type(nameInput, 'Finding Config');

      // Finding is the default type, advance to step 2
      await clickNext();

      // Enable email channel
      const emailCheckbox = await screen.findByLabelText('Email');
      await userEvent.click(emailCheckbox);
      const primaryCheckbox = await screen.findByLabelText('Primary account contact');
      await userEvent.click(primaryCheckbox);

      // ACT — navigate to Content Options step (step 4)
      await advanceSteps(2);

      // ASSERT — checkbox is enabled
      const deadlineCheckbox = screen.getByLabelText('Include remediation deadline');
      expect(deadlineCheckbox).not.toBeDisabled();
      expect(screen.queryByText('Remediation deadline only applies to Finding notifications.')).not.toBeInTheDocument();

      // ASSERT — manual remediation link is also enabled
      const manualLinkCheckbox = screen.getByLabelText('Include remediation link');
      expect(manualLinkCheckbox).not.toBeDisabled();
      expect(
        screen.queryByText('Manual remediation link only applies to Finding notifications.'),
      ).not.toBeInTheDocument();
    });
  });

  describe('Edit mode with complex initial values', () => {
    it('populates JIRA, batch export, and content options from initialValues', async () => {
      // ARRANGE
      const initialValues: NotificationConfigurationItem = {
        configId: '00000000-0000-4000-8000-000000000002' as NotificationConfigurationItem['configId'],
        name: 'JIRA Config',
        enabled: true,
        notificationType: 'finding',
        severityFilter: ['Critical'],
        controlIds: [],
        resourceFilterIds: [],
        deliveryChannels: [
          {
            type: 'jira',
            enabled: true,
            endpointUrl: 'https://my-domain.atlassian.net',
            projectKey: 'SEC',
            issueType: 'Bug',
            credentialsSecretArn: 'arn:aws:secretsmanager:us-east-1:123456789012:secret:asr/notifications/jira',
            customFieldMappings: [{ key: 'customfield_10001', value: '${SEVERITY}' }],
          },
        ],
        batchWindow: { enabled: true, duration: 30, unit: 'Minutes' },
        batchExport: { enabled: true, presignedUrlExpirationHours: 4 },
        contentOptions: {
          includeManualRemediationLink: true,
          includeRemediationDeadline: true,
          enforceDeadline: false,
          remediationDeadlineDays: 14,
          // IaC snippets are remediation-only and not asserted by this finding-type test.
          includeIaCSnippet: false,
          includeEnableAutomationLink: true,
        },
        version: 2,
        createdAt: '2025-01-01T00:00:00Z',
        createdBy: 'admin',
      };

      // ACT
      renderForm({ mode: 'edit', initialValues });

      // ASSERT — name is populated
      const nameInput = screen.getByPlaceholderText('e.g., Critical Findings - Security Team');
      expect(nameInput).toHaveValue('JIRA Config');

      // Navigate to delivery channels step to verify JIRA fields
      await clickNext();
      const jiraCheckbox = await screen.findByLabelText('JIRA');
      expect(jiraCheckbox).toBeChecked();
      expect(screen.getByPlaceholderText('https://your-domain.atlassian.net')).toHaveValue(
        'https://my-domain.atlassian.net',
      );
      expect(screen.getByPlaceholderText('SEC')).toHaveValue('SEC');
      expect(screen.getByPlaceholderText('Bug')).toHaveValue('Bug');

      // Navigate to batching step
      await clickNext();
      await waitFor(() => {
        expect(screen.getByText('Batching Configuration')).toBeInTheDocument();
      });

      // Navigate to content options step
      await clickNext();
      const deadlineCheckbox = screen.getByLabelText('Include remediation deadline');
      expect(deadlineCheckbox).toBeChecked();
      // IaC checkbox is not rendered for finding type.
      expect(screen.queryByLabelText('Include IaC remediation code')).not.toBeInTheDocument();
    });

    it('populates ServiceNow and SNS channels from initialValues', async () => {
      // ARRANGE
      const initialValues: NotificationConfigurationItem = {
        configId: '00000000-0000-4000-8000-000000000003' as NotificationConfigurationItem['configId'],
        name: 'ServiceNow Config',
        enabled: true,
        notificationType: 'finding',
        severityFilter: ['All'],
        controlIds: [],
        resourceFilterIds: [],
        deliveryChannels: [
          {
            type: 'servicenow',
            enabled: true,
            endpointUrl: 'https://my-instance.service-now.com',
            tableName: 'incident',
            credentialsSecretArn: 'arn:aws:secretsmanager:us-east-1:123456789012:secret:asr/notifications/snow',
            customFieldMappings: [{ key: 'urgency', value: '2' }],
          },
          {
            type: 'sns',
            enabled: true,
            topicArn: 'arn:aws:sns:us-east-1:123456789012:my-topic',
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
      };

      // ACT
      renderForm({ mode: 'edit', initialValues });

      // ASSERT — navigate to delivery channels step
      await clickNext();
      const serviceNowCheckbox = await screen.findByLabelText('ServiceNow');
      expect(serviceNowCheckbox).toBeChecked();
      const snsCheckbox = screen.getByLabelText('SNS Topic');
      expect(snsCheckbox).toBeChecked();
      expect(screen.getByPlaceholderText('https://your-instance.service-now.com')).toHaveValue(
        'https://my-instance.service-now.com',
      );
      expect(screen.getByPlaceholderText('arn:aws:sns:us-east-1:123456789012:my-topic')).toHaveValue(
        'arn:aws:sns:us-east-1:123456789012:my-topic',
      );
    });
  });

  describe('JIRA project key validation', () => {
    it('shows project key error when JIRA enabled and key does not match pattern, and accepts valid keys', async () => {
      // ARRANGE
      renderForm();

      const nameInput = screen.getByPlaceholderText('e.g., Critical Findings - Security Team');
      await userEvent.type(nameInput, 'JIRA Key Validation');

      await clickNext();

      const jiraCheckbox = await screen.findByLabelText('JIRA');
      await userEvent.click(jiraCheckbox);

      // Fill all required fields except project key with valid values
      const endpointInput = await screen.findByPlaceholderText('https://your-domain.atlassian.net');
      await userEvent.type(endpointInput, 'https://company.atlassian.net');

      const projectKeyInput = await screen.findByPlaceholderText('SEC');
      await userEvent.type(projectKeyInput, 'bad-key');

      const issueTypeInput = await screen.findByPlaceholderText('Bug');
      await userEvent.type(issueTypeInput, 'Task');

      const secretArnInput = await screen.findByPlaceholderText(
        `arn:aws:secretsmanager:us-east-1:123456789012:secret:asr/notifications/jira-token`,
      );
      await userEvent.type(
        secretArnInput,
        'arn:aws:secretsmanager:us-east-1:123456789012:secret:asr/notifications/jira',
      );

      // ACT — try to advance past step 2 with invalid project key
      await clickNext();

      // ASSERT — project key validation error is shown
      await waitFor(() => {
        const errors = screen.getAllByText(/project key must be 2–10 characters/i);
        expect(errors.length).toBeGreaterThanOrEqual(1);
      });
      expect(screen.queryByText('Batching Configuration')).not.toBeInTheDocument();

      // ACT — fix the project key with a valid value and retry
      await userEvent.clear(projectKeyInput);
      await userEvent.type(projectKeyInput, 'SEC');
      await clickNext();

      // ASSERT — wizard advances to step 3 (valid key accepted)
      await waitFor(() => {
        expect(screen.getByText('Batching Configuration')).toBeInTheDocument();
      });
    });

    it('accepts valid project key formats including underscores and digits', async () => {
      // ARRANGE
      const onSubmit = vi.fn();
      renderForm({ onSubmit });

      const nameInput = screen.getByPlaceholderText('e.g., Critical Findings - Security Team');
      await userEvent.type(nameInput, 'JIRA Valid Key');

      await clickNext();

      const jiraCheckbox = await screen.findByLabelText('JIRA');
      await userEvent.click(jiraCheckbox);

      const endpointInput = await screen.findByPlaceholderText('https://your-domain.atlassian.net');
      await userEvent.type(endpointInput, 'https://company.atlassian.net');

      const projectKeyInput = await screen.findByPlaceholderText('SEC');
      await userEvent.type(projectKeyInput, 'OPS_1');

      const issueTypeInput = await screen.findByPlaceholderText('Bug');
      await userEvent.type(issueTypeInput, 'Bug');

      const secretArnInput = await screen.findByPlaceholderText(
        `arn:aws:secretsmanager:us-east-1:123456789012:secret:asr/notifications/jira-token`,
      );
      await userEvent.type(
        secretArnInput,
        'arn:aws:secretsmanager:us-east-1:123456789012:secret:asr/notifications/jira',
      );

      // ACT — advance through remaining steps and submit
      await advanceSteps(3);
      const submitBtn = await screen.findByRole('button', { name: /create configuration/i });
      await userEvent.click(submitBtn);

      // ASSERT — form submits successfully with valid project key
      await waitFor(() => {
        expect(onSubmit).toHaveBeenCalledTimes(1);
      });
      expect(onSubmit.mock.calls[0][0].deliveryChannels[0].projectKey).toBe('OPS_1');
    });

    it('renders constraint text on the project key input', async () => {
      // ARRANGE
      renderForm();

      const nameInput = screen.getByPlaceholderText('e.g., Critical Findings - Security Team');
      await userEvent.type(nameInput, 'Constraint Text');

      await clickNext();

      const jiraCheckbox = await screen.findByLabelText('JIRA');
      await userEvent.click(jiraCheckbox);

      // ASSERT — constraint text is visible on the project key field
      await waitFor(() => {
        expect(
          screen.getByText(
            '2–10 characters: starts with an uppercase letter, followed by uppercase letters, digits, or underscores',
          ),
        ).toBeInTheDocument();
      });
    });
  });

  describe('JIRA channel validation', () => {
    it('shows validation error when JIRA is enabled but required fields are missing', async () => {
      // ARRANGE
      renderForm();

      const nameInput = screen.getByPlaceholderText('e.g., Critical Findings - Security Team');
      await userEvent.type(nameInput, 'JIRA Test Config');

      await clickNext();

      // Enable JIRA channel without filling any fields
      const jiraCheckbox = await screen.findByLabelText('JIRA');
      await userEvent.click(jiraCheckbox);

      // ACT — try to advance past step 2
      await clickNext();

      // ASSERT — JIRA validation error is shown (endpoint URL error maps to jira error)
      await waitFor(() => {
        const errors = screen.getAllByText(/jira instance url is required/i);
        expect(errors.length).toBeGreaterThanOrEqual(1);
      });
    });

    it('shows validation error when ServiceNow is enabled but required fields are missing', async () => {
      // ARRANGE
      renderForm();

      const nameInput = screen.getByPlaceholderText('e.g., Critical Findings - Security Team');
      await userEvent.type(nameInput, 'ServiceNow Test Config');

      await clickNext();

      // Enable ServiceNow channel without filling any fields
      const serviceNowCheckbox = await screen.findByLabelText('ServiceNow');
      await userEvent.click(serviceNowCheckbox);

      // ACT — try to advance past step 2
      await clickNext();

      // ASSERT — ServiceNow field-level validation errors are shown
      await waitFor(() => {
        expect(screen.getAllByText(/servicenow instance url is required/i).length).toBeGreaterThanOrEqual(1);
      });
    });
  });

  describe('Content options and submission', () => {
    it('submits correct payload with IaC snippets enabled (remediation type)', async () => {
      // ARRANGE
      const onSubmit = vi.fn();
      renderForm({ onSubmit });

      const nameInput = screen.getByPlaceholderText('e.g., Critical Findings - Security Team');
      await userEvent.type(nameInput, 'Content Options Config');

      // IaC snippets only render for remediation notifications (deadline-only-finding
      // is enforced separately by another test); switch type before advancing.
      const remediationRadio = screen.getByRole('radio', { name: /remediation/i });
      await userEvent.click(remediationRadio);

      await clickNext();

      // Enable email channel with a recipient
      const emailCheckbox = await screen.findByLabelText('Email');
      await userEvent.click(emailCheckbox);
      const primaryCheckbox = await screen.findByLabelText('Primary account contact');
      await userEvent.click(primaryCheckbox);

      // Advance past delivery channels and batching
      await advanceSteps(2);

      const iacCheckbox = screen.getByLabelText('Include IaC remediation code');
      await userEvent.click(iacCheckbox);

      // Select CloudFormation YAML and Terraform
      const cfnYamlCheckbox = await screen.findByLabelText('CloudFormation (YAML)');
      await userEvent.click(cfnYamlCheckbox);
      const terraformCheckbox = await screen.findByLabelText('Terraform');
      await userEvent.click(terraformCheckbox);

      // Advance to filters step and submit
      await clickNext();
      const submitBtn = await screen.findByRole('button', { name: /create configuration/i });
      await userEvent.click(submitBtn);

      // ASSERT
      await waitFor(() => {
        expect(onSubmit).toHaveBeenCalledTimes(1);
      });

      const payload = onSubmit.mock.calls[0][0];
      expect(payload.contentOptions.includeIaCSnippet).toBe(true);
      expect(payload.contentOptions.iacFormats).toEqual(expect.arrayContaining(['cloudformation-yaml', 'terraform']));
    });

    it('submits correct payload with SNS channel and batch window enabled', async () => {
      // ARRANGE
      const onSubmit = vi.fn();
      renderForm({ onSubmit });

      const nameInput = screen.getByPlaceholderText('e.g., Critical Findings - Security Team');
      await userEvent.type(nameInput, 'SNS Batch Config');

      await clickNext();

      // Enable SNS channel
      const snsCheckbox = await screen.findByLabelText('SNS Topic');
      await userEvent.click(snsCheckbox);
      const snsInput = await screen.findByPlaceholderText('arn:aws:sns:us-east-1:123456789012:my-topic');
      await userEvent.type(snsInput, 'arn:aws:sns:us-east-1:123456789012:alerts');

      await clickNext();

      // Enable batching on step 3
      const batchToggle = screen.getByLabelText('Batching disabled');
      await userEvent.click(batchToggle);

      // Clear the default value and type a custom duration
      const batchInput = screen.getByLabelText('Batch every');
      await userEvent.clear(batchInput);
      await userEvent.type(batchInput, '15');

      // Clear the pre-signed URL expiration and type a custom value
      const expirationInput = screen.getByLabelText('Pre-signed URL expiration (hours)');
      await userEvent.clear(expirationInput);
      await userEvent.type(expirationInput, '6');

      // Advance through content options and filters, then submit
      await advanceSteps(2);
      const submitBtn = await screen.findByRole('button', { name: /create configuration/i });
      await userEvent.click(submitBtn);

      // ASSERT
      await waitFor(() => {
        expect(onSubmit).toHaveBeenCalledTimes(1);
      });

      const payload = onSubmit.mock.calls[0][0];
      expect(payload.deliveryChannels).toEqual(
        expect.arrayContaining([
          expect.objectContaining({ type: 'sns', topicArn: 'arn:aws:sns:us-east-1:123456789012:alerts' }),
        ]),
      );
      expect(payload.batchWindow.enabled).toBe(true);
      expect(payload.batchWindow.duration).toBe(15);
      expect(payload.batchWindow.unit).toBe('Minutes');
      expect(payload.batchExport.presignedUrlExpirationHours).toBe(6);
    });

    it('shows validation error when IaC snippets enabled but no format selected', async () => {
      // ARRANGE
      renderForm();

      const nameInput = screen.getByPlaceholderText('e.g., Critical Findings - Security Team');
      await userEvent.type(nameInput, 'IaC Validation Config');

      // IaC snippets are remediation-only.
      const remediationRadio = screen.getByRole('radio', { name: /remediation/i });
      await userEvent.click(remediationRadio);

      await clickNext();

      // Enable email channel
      const emailCheckbox = await screen.findByLabelText('Email');
      await userEvent.click(emailCheckbox);
      const primaryCheckbox = await screen.findByLabelText('Primary account contact');
      await userEvent.click(primaryCheckbox);

      // Advance past delivery channels and batching
      await advanceSteps(2);

      // Enable IaC snippets without selecting any format
      const iacCheckbox = screen.getByLabelText('Include IaC remediation code');
      await userEvent.click(iacCheckbox);

      // ACT — try to advance past content options step
      await clickNext();

      // ASSERT — validation error is shown
      await waitFor(() => {
        const errors = screen.getAllByText(/select at least one iac format/i);
        expect(errors.length).toBeGreaterThanOrEqual(1);
      });
    });
  });

  describe('Batching number input validation', () => {
    it('shows validation error when batch duration is out of range for the selected unit', async () => {
      // ARRANGE
      renderForm();

      const nameInput = screen.getByPlaceholderText('e.g., Critical Findings - Security Team');
      await userEvent.type(nameInput, 'Batch Validation Config');

      await clickNext();

      const emailCheckbox = await screen.findByLabelText('Email');
      await userEvent.click(emailCheckbox);
      const primaryCheckbox = await screen.findByLabelText('Primary account contact');
      await userEvent.click(primaryCheckbox);

      await clickNext();

      // Enable batching
      const batchToggle = screen.getByLabelText('Batching disabled');
      await userEvent.click(batchToggle);

      // Clear and type an out-of-range value (Minutes range is 5–60)
      const batchInput = screen.getByLabelText('Batch every');
      await userEvent.clear(batchInput);
      await userEvent.type(batchInput, '2');

      // ACT — try to advance past batching step
      await clickNext();

      // ASSERT — validation error is shown and wizard stays on step 3
      await waitFor(() => {
        const errors = screen.getAllByText(/duration must be 5–60 minutes/i);
        expect(errors.length).toBeGreaterThanOrEqual(1);
      });

      // ACT — fix the value and retry
      await userEvent.clear(batchInput);
      await userEvent.type(batchInput, '10');
      await clickNext();

      // ASSERT — wizard advances to step 4
      await waitFor(() => {
        expect(screen.getByText('Include remediation deadline')).toBeInTheDocument();
      });
    });

    it('shows validation error when batch duration field is empty', async () => {
      // ARRANGE
      renderForm();

      const nameInput = screen.getByPlaceholderText('e.g., Critical Findings - Security Team');
      await userEvent.type(nameInput, 'Empty Batch Config');

      await clickNext();

      const emailCheckbox = await screen.findByLabelText('Email');
      await userEvent.click(emailCheckbox);
      const primaryCheckbox = await screen.findByLabelText('Primary account contact');
      await userEvent.click(primaryCheckbox);

      await clickNext();

      // Enable batching
      const batchToggle = screen.getByLabelText('Batching disabled');
      await userEvent.click(batchToggle);

      // Clear the field entirely (simulates user deleting the value to type a new one)
      const batchInput = screen.getByLabelText('Batch every');
      await userEvent.clear(batchInput);

      // ASSERT — the field accepts an empty value without resetting
      expect(batchInput).toHaveValue(null);

      // ACT — try to advance with empty field
      await clickNext();

      // ASSERT — validation error is shown
      await waitFor(() => {
        const errors = screen.getAllByText(/duration must be 5–60 minutes/i);
        expect(errors.length).toBeGreaterThanOrEqual(1);
      });
    });
  });

  describe('Slack channel validation', () => {
    it('blocks navigation when Slack enabled and Secret ARN is empty', async () => {
      // ARRANGE
      renderForm();

      const nameInput = screen.getByPlaceholderText('e.g., Critical Findings - Security Team');
      await userEvent.type(nameInput, 'Slack Test Config');

      await clickNext();

      // Enable Slack channel
      const slackCheckbox = await screen.findByLabelText('Slack');
      await userEvent.click(slackCheckbox);

      // Fill only channel ID, leave Secret ARN empty
      const channelIdInput = await screen.findByPlaceholderText('C0123456789');
      await userEvent.type(channelIdInput, 'C0123456789');

      // ACT — try to advance past step 2
      await clickNext();

      // ASSERT — Secret ARN required error is shown and wizard stays on step 2
      await waitFor(() => {
        const errors = screen.getAllByText(/slack credentials secret arn is required/i);
        expect(errors.length).toBeGreaterThanOrEqual(1);
      });
      expect(screen.queryByText('Batching Configuration')).not.toBeInTheDocument();
    });

    it('blocks navigation when Slack channel ID is empty', async () => {
      // ARRANGE
      renderForm();

      const nameInput = screen.getByPlaceholderText('e.g., Critical Findings - Security Team');
      await userEvent.type(nameInput, 'Slack Test Config');

      await clickNext();

      // Enable Slack channel
      const slackCheckbox = await screen.findByLabelText('Slack');
      await userEvent.click(slackCheckbox);

      // Fill only Secret ARN, leave channel ID empty
      const secretArnInput = await screen.findByPlaceholderText(
        'arn:aws:secretsmanager:us-east-1:123456789012:secret:asr/notifications/slack-webhook',
      );
      await userEvent.type(
        secretArnInput,
        'arn:aws:secretsmanager:us-east-1:123456789012:secret:asr/notifications/slack',
      );

      // ACT — try to advance past step 2
      await clickNext();

      // ASSERT — Channel ID required error is shown and wizard stays on step 2
      await waitFor(() => {
        const errors = screen.getAllByText(/slack channel id is required/i);
        expect(errors.length).toBeGreaterThanOrEqual(1);
      });
      expect(screen.queryByText('Batching Configuration')).not.toBeInTheDocument();
    });

    it('blocks navigation when channel ID does not match expected format', async () => {
      // ARRANGE
      renderForm();

      const nameInput = screen.getByPlaceholderText('e.g., Critical Findings - Security Team');
      await userEvent.type(nameInput, 'Slack Test Config');

      await clickNext();

      // Enable Slack channel
      const slackCheckbox = await screen.findByLabelText('Slack');
      await userEvent.click(slackCheckbox);

      const secretArnInput = await screen.findByPlaceholderText(
        'arn:aws:secretsmanager:us-east-1:123456789012:secret:asr/notifications/slack-webhook',
      );
      await userEvent.type(
        secretArnInput,
        'arn:aws:secretsmanager:us-east-1:123456789012:secret:asr/notifications/slack',
      );

      const channelIdInput = await screen.findByPlaceholderText('C0123456789');
      await userEvent.type(channelIdInput, 'invalid-id');

      // ACT — try to advance past step 2
      await clickNext();

      // ASSERT — channel ID format error is shown
      await waitFor(() => {
        const errors = screen.getAllByText(/channel id must start with C followed by/i);
        expect(errors.length).toBeGreaterThanOrEqual(1);
      });
      expect(screen.queryByText('Batching Configuration')).not.toBeInTheDocument();
    });

    it('blocks navigation when Secret ARN has invalid format', async () => {
      // ARRANGE
      renderForm();

      const nameInput = screen.getByPlaceholderText('e.g., Critical Findings - Security Team');
      await userEvent.type(nameInput, 'Slack Test Config');

      await clickNext();

      // Enable Slack channel
      const slackCheckbox = await screen.findByLabelText('Slack');
      await userEvent.click(slackCheckbox);

      const secretArnInput = await screen.findByPlaceholderText(
        'arn:aws:secretsmanager:us-east-1:123456789012:secret:asr/notifications/slack-webhook',
      );
      await userEvent.type(secretArnInput, 'arn:aws:secretsmanager:us-east-1:123456789012:secret:wrong-prefix-name');

      const channelIdInput = await screen.findByPlaceholderText('C0123456789');
      await userEvent.type(channelIdInput, 'C0123456789');

      // ACT — try to advance past step 2
      await clickNext();

      // ASSERT — Secret ARN format error is shown
      await waitFor(() => {
        const errors = screen.getAllByText(/secret name must start with "asr\/notifications\/"/i);
        expect(errors.length).toBeGreaterThanOrEqual(1);
      });
      expect(screen.queryByText('Batching Configuration')).not.toBeInTheDocument();
    });

    it('submits successfully with valid Secret ARN and valid channel ID', async () => {
      // ARRANGE
      const onSubmit = vi.fn();
      renderForm({ onSubmit });

      const nameInput = screen.getByPlaceholderText('e.g., Critical Findings - Security Team');
      await userEvent.type(nameInput, 'Valid Slack Config');

      await clickNext();

      const slackCheckbox = await screen.findByLabelText('Slack');
      await userEvent.click(slackCheckbox);

      const secretArnInput = await screen.findByPlaceholderText(
        'arn:aws:secretsmanager:us-east-1:123456789012:secret:asr/notifications/slack-webhook',
      );
      await userEvent.type(
        secretArnInput,
        'arn:aws:secretsmanager:us-east-1:123456789012:secret:asr/notifications/my-secret',
      );

      const channelIdInput = await screen.findByPlaceholderText('C0123456789');
      await userEvent.type(channelIdInput, 'C0123456789');

      // ACT
      await advanceSteps(3);
      const submitBtn = await screen.findByRole('button', { name: /create configuration/i });
      await userEvent.click(submitBtn);

      // ASSERT — form submits without validation errors
      await waitFor(() => {
        expect(onSubmit).toHaveBeenCalledTimes(1);
      });

      const payload = onSubmit.mock.calls[0][0];
      expect(payload.deliveryChannels).toEqual(
        expect.arrayContaining([expect.objectContaining({ type: 'slack', channelId: 'C0123456789' })]),
      );
    });

    it('renders constraint text on channel ID input', async () => {
      // ARRANGE
      renderForm();

      const nameInput = screen.getByPlaceholderText('e.g., Critical Findings - Security Team');
      await userEvent.type(nameInput, 'Constraint Text Test');

      await clickNext();

      const slackCheckbox = await screen.findByLabelText('Slack');
      await userEvent.click(slackCheckbox);

      // ASSERT — constraint text is visible
      await waitFor(() => {
        expect(
          screen.getByText('Format: C followed by 8 or more uppercase alphanumeric characters (e.g. C0123456789)'),
        ).toBeInTheDocument();
      });
    });
  });

  describe('Filters step rendering and submission', () => {
    it('renders severity, resource filter, and control filter multiselects on the filters step', async () => {
      // ARRANGE
      const resourceFilters = [
        {
          filterId: '00000000-0000-4000-8000-000000000010',
          name: 'Production Accounts',
          accountIds: ['123456789012', '987654321098'],
          organizationalUnits: ['ou-abcd-12345678'],
          tags: [{ key: 'env', value: 'prod' }],
          arnPatterns: [],
          version: 1,
          createdAt: '2025-01-01T00:00:00Z',
          createdBy: 'admin',
          lastModified: '2025-01-01T00:00:00Z',
          modifiedBy: 'admin',
        },
      ];
      const controls = [
        createTestControl(),
        createTestControl({ controlId: 'IAM.1', description: 'Rotate keys', automatedRemediationEnabled: false }),
      ];

      renderForm({ resourceFilters, controls });

      // Navigate to filters step (step 5)
      const nameInput = screen.getByPlaceholderText('e.g., Critical Findings - Security Team');
      await userEvent.type(nameInput, 'Filters Test Config');
      await clickNext();

      const emailCheckbox = await screen.findByLabelText('Email');
      await userEvent.click(emailCheckbox);
      const primaryCheckbox = await screen.findByLabelText('Primary account contact');
      await userEvent.click(primaryCheckbox);

      await advanceSteps(3);

      // ASSERT — filters step is rendered with all sections
      await waitFor(() => {
        expect(screen.getByText('Severity Filtering')).toBeInTheDocument();
        expect(screen.getByText('Resource Filtering')).toBeInTheDocument();
        expect(screen.getByText('Security Control Filtering')).toBeInTheDocument();
        expect(
          screen.getByText('Select which security controls trigger notifications, or choose All'),
        ).toBeInTheDocument();
      });
    });

    it('describes an ARN-pattern-only resource filter by its ARN pattern count, not "No criteria"', async () => {
      // ARRANGE
      const resourceFilters = [
        {
          filterId: '00000000-0000-4000-8000-000000000020',
          name: 'ARN Only Filter',
          accountIds: [],
          organizationalUnits: [],
          tags: [],
          arnPatterns: ['arn:aws:s3:::my-bucket', 'arn:aws:s3:::my-other-*'],
          version: 1,
          createdAt: '2025-01-01T00:00:00Z',
          createdBy: 'admin',
          lastModified: '2025-01-01T00:00:00Z',
          modifiedBy: 'admin',
        },
      ];

      renderForm({ resourceFilters });
      await setupFormToFiltersStep('ARN Filter Config');

      // ACT — open the resource filter multiselect to reveal option descriptions
      const resourceFilterSelect = (await screen.findAllByText('Select resource filters'))[0];
      await userEvent.click(resourceFilterSelect);

      // ASSERT — the ARN-only filter reports its ARN pattern count and is not "No criteria"
      expect(await screen.findByText('2 ARN pattern(s)')).toBeInTheDocument();
      expect(screen.queryByText('No criteria')).not.toBeInTheDocument();
    });

    it('submits payload with severity filter, resource filters, and control IDs from edit mode initialValues', async () => {
      // ARRANGE
      const onSubmit = vi.fn();
      const resourceFilters = [
        {
          filterId: '00000000-0000-4000-8000-000000000010',
          name: 'Production Accounts',
          accountIds: ['123456789012'],
          organizationalUnits: [],
          tags: [],
          arnPatterns: [],
          version: 1,
          createdAt: '2025-01-01T00:00:00Z',
          createdBy: 'admin',
          lastModified: '2025-01-01T00:00:00Z',
          modifiedBy: 'admin',
        },
      ];
      const controls = [createTestControl()];
      const initialValues: NotificationConfigurationItem = {
        configId: '00000000-0000-4000-8000-000000000099' as NotificationConfigurationItem['configId'],
        name: 'Filters Edit Config',
        enabled: true,
        notificationType: 'finding',
        severityFilter: ['Critical', 'High'],
        controlIds: ['S3.1'],
        resourceFilterIds: ['00000000-0000-4000-8000-000000000010'],
        deliveryChannels: [{ type: 'email', enabled: true, recipients: [{ recipientType: 'rootAccountEmail' }] }],
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
      };

      renderForm({ mode: 'edit', initialValues, onSubmit, resourceFilters, controls });

      // ACT — submit from step 1 using the wizard submit
      // Navigate to last step and submit
      await advanceSteps(4);
      const submitBtn = await screen.findByRole('button', { name: /save changes/i });
      await userEvent.click(submitBtn);

      // ASSERT
      await waitFor(() => {
        expect(onSubmit).toHaveBeenCalledTimes(1);
      });

      const payload = onSubmit.mock.calls[0][0];
      expect(payload.severityFilter).toEqual(['Critical', 'High']);
      expect(payload.controlIds).toEqual(['S3.1']);
      expect(payload.resourceFilterIds).toEqual(['00000000-0000-4000-8000-000000000010']);
    });
  });

  describe('ServiceNow channel validation', () => {
    it('shows endpoint URL error when ServiceNow enabled and URL is not valid HTTPS, and table name error when pattern does not match', async () => {
      // ARRANGE
      renderForm();

      const nameInput = screen.getByPlaceholderText('e.g., Critical Findings - Security Team');
      await userEvent.type(nameInput, 'ServiceNow Validation');

      await clickNext();

      const serviceNowCheckbox = await screen.findByLabelText('ServiceNow');
      await userEvent.click(serviceNowCheckbox);

      const endpointInput = await screen.findByPlaceholderText('https://your-instance.service-now.com');
      await userEvent.type(endpointInput, 'http://insecure.service-now.com');

      const tableNameInput = await screen.findByPlaceholderText('incident');
      await userEvent.type(tableNameInput, 'INVALID_TABLE');

      const secretArnInput = await screen.findByPlaceholderText(
        'arn:aws:secretsmanager:us-east-1:123456789012:secret:asr/notifications/servicenow-credentials',
      );
      await userEvent.type(
        secretArnInput,
        'arn:aws:secretsmanager:us-east-1:123456789012:secret:asr/notifications/snow',
      );

      // ACT
      await clickNext();

      // ASSERT — endpoint URL HTTPS error is shown
      await waitFor(() => {
        const urlErrors = screen.getAllByText(/servicenow instance url must use https protocol/i);
        expect(urlErrors.length).toBeGreaterThanOrEqual(1);
      });

      // ASSERT — table name pattern error is shown
      const tableErrors = screen.getAllByText(/table name must start with a lowercase letter/i);
      expect(tableErrors.length).toBeGreaterThanOrEqual(1);

      // ASSERT — wizard stays on step 2
      expect(screen.queryByText('Batching Configuration')).not.toBeInTheDocument();
    });

    it('accepts valid table name formats and advances past step 2', async () => {
      // ARRANGE
      const onSubmit = vi.fn();
      renderForm({ onSubmit });

      const nameInput = screen.getByPlaceholderText('e.g., Critical Findings - Security Team');
      await userEvent.type(nameInput, 'ServiceNow Valid Table');

      await clickNext();

      const serviceNowCheckbox = await screen.findByLabelText('ServiceNow');
      await userEvent.click(serviceNowCheckbox);

      const endpointInput = await screen.findByPlaceholderText('https://your-instance.service-now.com');
      await userEvent.type(endpointInput, 'https://company.service-now.com');

      const tableNameInput = await screen.findByPlaceholderText('incident');
      await userEvent.type(tableNameInput, 'security_incident');

      const secretArnInput = await screen.findByPlaceholderText(
        'arn:aws:secretsmanager:us-east-1:123456789012:secret:asr/notifications/servicenow-credentials',
      );
      await userEvent.type(
        secretArnInput,
        'arn:aws:secretsmanager:us-east-1:123456789012:secret:asr/notifications/snow',
      );

      // ACT
      await clickNext();

      // ASSERT — wizard advances to step 3 (valid inputs accepted)
      await waitFor(() => {
        expect(screen.getByText('Batching Configuration')).toBeInTheDocument();
      });
    });

    it('renders constraint text on table name and endpoint URL inputs', async () => {
      // ARRANGE
      renderForm();

      const nameInput = screen.getByPlaceholderText('e.g., Critical Findings - Security Team');
      await userEvent.type(nameInput, 'ServiceNow Constraint Text');

      await clickNext();

      const serviceNowCheckbox = await screen.findByLabelText('ServiceNow');
      await userEvent.click(serviceNowCheckbox);

      // ASSERT — constraint text is visible on the table name field
      await waitFor(() => {
        expect(
          screen.getByText(/starts with a lowercase letter, followed by lowercase letters, digits, or underscores/i),
        ).toBeInTheDocument();
      });

      // ASSERT — constraint text is visible on the endpoint URL field
      expect(screen.getByText(/must be a valid https url/i)).toBeInTheDocument();
    });
  });

  describe('CloudFormation JSON checkbox', () => {
    it('submits payload with cloudformation-json when that format is selected', async () => {
      // ARRANGE
      const onSubmit = vi.fn();
      renderForm({ onSubmit });

      const nameInput = screen.getByPlaceholderText('e.g., Critical Findings - Security Team');
      await userEvent.type(nameInput, 'CFN JSON Config');

      // IaC snippets are remediation-only.
      const remediationRadio = screen.getByRole('radio', { name: /remediation/i });
      await userEvent.click(remediationRadio);

      await clickNext();

      const emailCheckbox = await screen.findByLabelText('Email');
      await userEvent.click(emailCheckbox);
      const primaryCheckbox = await screen.findByLabelText('Primary account contact');
      await userEvent.click(primaryCheckbox);

      await advanceSteps(2);

      // Enable IaC snippets and select CloudFormation JSON
      const iacCheckbox = screen.getByLabelText('Include IaC remediation code');
      await userEvent.click(iacCheckbox);
      const cfnJsonCheckbox = await screen.findByLabelText('CloudFormation (JSON)');
      await userEvent.click(cfnJsonCheckbox);

      // ACT — advance to filters and submit
      await clickNext();
      const submitBtn = await screen.findByRole('button', { name: /create configuration/i });
      await userEvent.click(submitBtn);

      // ASSERT
      await waitFor(() => {
        expect(onSubmit).toHaveBeenCalledTimes(1);
      });

      const payload = onSubmit.mock.calls[0][0];
      expect(payload.contentOptions.includeIaCSnippet).toBe(true);
      expect(payload.contentOptions.iacFormats).toContain('cloudformation-json');
    });
  });

  describe('Pre-signed URL expiration validation', () => {
    it('shows validation error when pre-signed URL expiration is out of range', async () => {
      // ARRANGE
      const onSubmit = vi.fn();
      renderForm({ onSubmit });

      const nameInput = screen.getByPlaceholderText('e.g., Critical Findings - Security Team');
      await userEvent.type(nameInput, 'Presigned URL Config');

      await clickNext();

      const emailCheckbox = await screen.findByLabelText('Email');
      await userEvent.click(emailCheckbox);
      const primaryCheckbox = await screen.findByLabelText('Primary account contact');
      await userEvent.click(primaryCheckbox);

      await clickNext();

      // Enable batching
      const batchToggle = screen.getByLabelText('Batching disabled');
      await userEvent.click(batchToggle);

      // Set valid batch duration but invalid pre-signed URL expiration (>8)
      const batchInput = screen.getByLabelText('Batch every');
      await userEvent.clear(batchInput);
      await userEvent.type(batchInput, '10');

      const expirationInput = screen.getByLabelText('Pre-signed URL expiration (hours)');
      await userEvent.clear(expirationInput);
      await userEvent.type(expirationInput, '12');

      // ACT
      await clickNext();

      // ASSERT
      await waitFor(() => {
        const errors = screen.getAllByText(/pre-signed url expiration must be 1–8 hours/i);
        expect(errors.length).toBeGreaterThanOrEqual(1);
      });
      expect(onSubmit).not.toHaveBeenCalled();
    });
  });

  describe('Control IDs filter with All toggle', () => {
    it('submits empty controlIds array when All is selected', async () => {
      // ARRANGE
      const onSubmit = vi.fn();
      const controls = [
        createTestControl(),
        createTestControl({ controlId: 'IAM.1', description: 'Rotate keys', automatedRemediationEnabled: false }),
      ];

      renderForm({ onSubmit, controls });
      await setupFormToFiltersStep('Control Filter Config');

      // ACT — submit with default "All" selected
      const submitBtn = await screen.findByRole('button', { name: /create configuration/i });
      await userEvent.click(submitBtn);

      // ASSERT — controlIds is empty array when "All" is selected
      await waitFor(() => {
        expect(onSubmit).toHaveBeenCalledTimes(1);
      });
      expect(onSubmit.mock.calls[0][0].controlIds).toEqual([]);
    });
  });

  describe('ServiceNow custom field mappings validation', () => {
    it('shows custom field validation error when ServiceNow has invalid custom field mappings', async () => {
      // ARRANGE
      const initialValues = createTestNotificationConfig({
        configId: '00000000-0000-4000-8000-000000000004' as NotificationConfigurationItem['configId'],
        name: 'ServiceNow Custom Fields',
        deliveryChannels: [
          {
            type: 'servicenow',
            enabled: true,
            endpointUrl: 'https://my-instance.service-now.com',
            tableName: 'incident',
            credentialsSecretArn: 'arn:aws:secretsmanager:us-east-1:123456789012:secret:asr/notifications/snow',
            customFieldMappings: [{ key: '', value: 'some-value' }],
          },
        ],
      });

      renderForm({ mode: 'edit', initialValues });

      // ACT — navigate to delivery channels and try to advance
      await clickNext();
      await clickNext();

      // ASSERT — custom field validation error is shown
      await waitFor(() => {
        const errors = screen.getAllByText(/custom field mapping \[0\]: key must not be empty/i);
        expect(errors.length).toBeGreaterThanOrEqual(1);
      });
    });
  });

  describe('JIRA custom field mappings validation', () => {
    it('shows custom field validation error when JIRA has invalid custom field mappings', async () => {
      // ARRANGE
      const initialValues = createTestNotificationConfig({
        configId: '00000000-0000-4000-8000-000000000006' as NotificationConfigurationItem['configId'],
        name: 'JIRA Custom Fields',
        deliveryChannels: [
          {
            type: 'jira',
            enabled: true,
            endpointUrl: 'https://my-domain.atlassian.net',
            projectKey: 'SEC',
            issueType: 'Bug',
            credentialsSecretArn: 'arn:aws:secretsmanager:us-east-1:123456789012:secret:asr/notifications/jira',
            customFieldMappings: [{ key: 'not_a_custom_field', value: 'some-value' }],
          },
        ],
      });

      renderForm({ mode: 'edit', initialValues });

      // ACT — navigate to delivery channels and try to advance
      await clickNext();
      await clickNext();

      // ASSERT — custom field validation error is shown
      await waitFor(() => {
        const errors = screen.getAllByText(/custom field key "not_a_custom_field" must match pattern/i);
        expect(errors.length).toBeGreaterThanOrEqual(1);
      });
    });
  });

  describe('Custom field mapping editor', () => {
    it('adds, edits, and removes JIRA custom field rows and submits the remaining mapping', async () => {
      // ARRANGE
      const onSubmit = vi.fn();
      renderForm({ onSubmit });

      const nameInput = screen.getByPlaceholderText('e.g., Critical Findings - Security Team');
      await userEvent.type(nameInput, 'JIRA Custom Field Editor');
      await clickNext();

      const jiraCheckbox = await screen.findByLabelText('JIRA');
      await userEvent.click(jiraCheckbox);

      const endpointInput = await screen.findByPlaceholderText('https://your-domain.atlassian.net');
      await userEvent.type(endpointInput, 'https://company.atlassian.net');
      const projectKeyInput = await screen.findByPlaceholderText('SEC');
      await userEvent.type(projectKeyInput, 'SEC');
      const issueTypeInput = await screen.findByPlaceholderText('Bug');
      await userEvent.type(issueTypeInput, 'Bug');
      const secretArnInput = await screen.findByPlaceholderText(
        'arn:aws:secretsmanager:us-east-1:123456789012:secret:asr/notifications/jira-token',
      );
      await userEvent.type(
        secretArnInput,
        'arn:aws:secretsmanager:us-east-1:123456789012:secret:asr/notifications/jira',
      );

      // ACT — add two mapping rows, fill the first, then remove the empty second row
      const addFieldButton = await screen.findByRole('button', { name: 'Add field' });
      await userEvent.click(addFieldButton);
      await userEvent.type(await screen.findByPlaceholderText('Field key'), 'customfield_10001');
      await userEvent.type(await screen.findByPlaceholderText('Field value'), 'critical');

      await userEvent.click(await screen.findByRole('button', { name: 'Add field' }));
      await waitFor(() => {
        expect(screen.getAllByPlaceholderText('Field key')).toHaveLength(2);
      });

      const removeButtons = screen.getAllByRole('button', { name: 'Remove field' });
      await userEvent.click(removeButtons[1]);

      // ASSERT — only the filled row survives, with the typed key and value retained
      await waitFor(() => {
        expect(screen.getAllByPlaceholderText('Field key')).toHaveLength(1);
      });
      expect(screen.getByPlaceholderText('Field key')).toHaveValue('customfield_10001');
      expect(screen.getByPlaceholderText('Field value')).toHaveValue('critical');

      // ACT — submit the configuration
      await advanceSteps(3);
      await userEvent.click(await screen.findByRole('button', { name: /create configuration/i }));

      // ASSERT — the surviving mapping is included in the JIRA channel payload
      await waitFor(() => {
        expect(onSubmit).toHaveBeenCalledTimes(1);
      });
      expect(onSubmit.mock.calls[0][0].deliveryChannels).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            type: 'jira',
            customFieldMappings: [{ key: 'customfield_10001', value: 'critical' }],
          }),
        ]),
      );
    });

    it('adds, edits, and removes ServiceNow custom field rows and submits the remaining mapping', async () => {
      // ARRANGE
      const onSubmit = vi.fn();
      renderForm({ onSubmit });

      const nameInput = screen.getByPlaceholderText('e.g., Critical Findings - Security Team');
      await userEvent.type(nameInput, 'ServiceNow Custom Field Editor');
      await clickNext();

      const serviceNowCheckbox = await screen.findByLabelText('ServiceNow');
      await userEvent.click(serviceNowCheckbox);

      const endpointInput = await screen.findByPlaceholderText('https://your-instance.service-now.com');
      await userEvent.type(endpointInput, 'https://company.service-now.com');
      const tableNameInput = await screen.findByPlaceholderText('incident');
      await userEvent.type(tableNameInput, 'incident');
      const secretArnInput = await screen.findByPlaceholderText(
        'arn:aws:secretsmanager:us-east-1:123456789012:secret:asr/notifications/servicenow-credentials',
      );
      await userEvent.type(
        secretArnInput,
        'arn:aws:secretsmanager:us-east-1:123456789012:secret:asr/notifications/snow',
      );

      // ACT — add two mapping rows, fill the first, then remove the empty second row
      await userEvent.click(await screen.findByRole('button', { name: 'Add field' }));
      await userEvent.type(await screen.findByPlaceholderText('Field key'), 'u_severity');
      await userEvent.type(await screen.findByPlaceholderText('Field value'), 'high');

      await userEvent.click(await screen.findByRole('button', { name: 'Add field' }));
      await waitFor(() => {
        expect(screen.getAllByPlaceholderText('Field key')).toHaveLength(2);
      });

      const removeButtons = screen.getAllByRole('button', { name: 'Remove field' });
      await userEvent.click(removeButtons[1]);

      // ASSERT — only the filled row survives, with the typed key and value retained
      await waitFor(() => {
        expect(screen.getAllByPlaceholderText('Field key')).toHaveLength(1);
      });
      expect(screen.getByPlaceholderText('Field key')).toHaveValue('u_severity');
      expect(screen.getByPlaceholderText('Field value')).toHaveValue('high');

      // ACT — submit the configuration
      await advanceSteps(3);
      await userEvent.click(await screen.findByRole('button', { name: /create configuration/i }));

      // ASSERT — the surviving mapping is included in the ServiceNow channel payload
      await waitFor(() => {
        expect(onSubmit).toHaveBeenCalledTimes(1);
      });
      expect(onSubmit.mock.calls[0][0].deliveryChannels).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            type: 'servicenow',
            customFieldMappings: [{ key: 'u_severity', value: 'high' }],
          }),
        ]),
      );
    });
  });

  describe('Edit mode with Slack channel', () => {
    it('populates Slack channel fields from initialValues', async () => {
      // ARRANGE
      const initialValues = createTestNotificationConfig({
        configId: '00000000-0000-4000-8000-000000000005' as NotificationConfigurationItem['configId'],
        name: 'Slack Edit Config',
        deliveryChannels: [
          {
            type: 'slack',
            enabled: true,
            channelId: 'C0123456789',
            credentialsSecretArn:
              'arn:aws:secretsmanager:us-east-1:123456789012:secret:asr/notifications/slack-webhook',
          },
        ],
      });

      // ACT
      renderForm({ mode: 'edit', initialValues });

      // Navigate to delivery channels step
      await clickNext();

      // ASSERT — Slack fields are populated
      const slackCheckbox = await screen.findByLabelText('Slack');
      expect(slackCheckbox).toBeChecked();
      expect(screen.getByPlaceholderText('C0123456789')).toHaveValue('C0123456789');
    });
  });

  describe('ServiceNow submission payload', () => {
    it('submits correct payload with ServiceNow channel enabled', async () => {
      // ARRANGE
      const onSubmit = vi.fn();
      renderForm({ onSubmit });

      const nameInput = screen.getByPlaceholderText('e.g., Critical Findings - Security Team');
      await userEvent.type(nameInput, 'ServiceNow Submit Config');

      await clickNext();

      const serviceNowCheckbox = await screen.findByLabelText('ServiceNow');
      await userEvent.click(serviceNowCheckbox);

      const endpointInput = await screen.findByPlaceholderText('https://your-instance.service-now.com');
      await userEvent.type(endpointInput, 'https://company.service-now.com');

      const tableNameInput = await screen.findByPlaceholderText('incident');
      await userEvent.type(tableNameInput, 'incident');

      const secretArnInput = await screen.findByPlaceholderText(
        'arn:aws:secretsmanager:us-east-1:123456789012:secret:asr/notifications/servicenow-credentials',
      );
      await userEvent.type(
        secretArnInput,
        'arn:aws:secretsmanager:us-east-1:123456789012:secret:asr/notifications/snow',
      );

      // ACT — advance through remaining steps and submit
      await advanceSteps(3);
      const submitBtn = await screen.findByRole('button', { name: /create configuration/i });
      await userEvent.click(submitBtn);

      // ASSERT
      await waitFor(() => {
        expect(onSubmit).toHaveBeenCalledTimes(1);
      });

      const payload = onSubmit.mock.calls[0][0];
      expect(payload.deliveryChannels).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            type: 'servicenow',
            enabled: true,
            endpointUrl: 'https://company.service-now.com',
            tableName: 'incident',
          }),
        ]),
      );
    });
  });

  describe('Edit mode with batch export and controlIds', () => {
    it('populates batch export presigned URL expiration and non-All controlIds from initialValues', async () => {
      // ARRANGE
      const controls = [createTestControl()];
      const initialValues = createTestNotificationConfig({
        configId: '00000000-0000-4000-8000-000000000006' as NotificationConfigurationItem['configId'],
        name: 'Batch Export Edit',
        controlIds: ['S3.1'],
        batchWindow: { enabled: true, duration: 15, unit: 'Minutes' },
        batchExport: { enabled: true, presignedUrlExpirationHours: 6 },
      });

      const onSubmit = vi.fn();
      renderForm({ mode: 'edit', initialValues, onSubmit, controls });

      // ACT — submit the form
      await advanceSteps(4);
      const submitBtn = await screen.findByRole('button', { name: /save changes/i });
      await userEvent.click(submitBtn);

      // ASSERT
      await waitFor(() => {
        expect(onSubmit).toHaveBeenCalledTimes(1);
      });

      const payload = onSubmit.mock.calls[0][0];
      expect(payload.batchWindow).toEqual({ enabled: true, duration: 15, unit: 'Minutes' });
      expect(payload.batchExport).toEqual({ enabled: true, presignedUrlExpirationHours: 6 });
      expect(payload.controlIds).toEqual(['S3.1']);
    });
  });

  describe('Severity filter multiselect toggleMutualExclusiveAll logic', () => {
    it('submits selected severity levels when specific options are chosen', async () => {
      // ARRANGE
      const onSubmit = vi.fn();
      renderForm({ onSubmit });
      await setupFormToFiltersStep('Severity Filter Config');

      // On the filters step, open the severity multiselect
      // Cloudscape Multiselect renders placeholder as text inside the trigger, not as an accessible label
      const severitySelect = (await screen.findAllByText('Select severity levels'))[0];
      await userEvent.click(severitySelect);

      // Select "Critical" option
      const criticalOption = await screen.findByRole('option', { name: 'Critical' });
      await userEvent.click(criticalOption);

      // Select "High" option
      const highOption = await screen.findByRole('option', { name: 'High' });
      await userEvent.click(highOption);

      // Close the dropdown by clicking elsewhere
      await userEvent.click(screen.getByText('Severity Filtering'));

      // ACT — submit
      const submitBtn = await screen.findByRole('button', { name: /create configuration/i });
      await userEvent.click(submitBtn);

      // ASSERT — severity filter includes selected values
      await waitFor(() => {
        expect(onSubmit).toHaveBeenCalledTimes(1);
      });
      expect(onSubmit.mock.calls[0][0].severityFilter).toEqual(expect.arrayContaining(['Critical', 'High']));
    });

    it('selects All when All option is chosen and deselects All when a specific item is chosen after All', async () => {
      // ARRANGE
      const onSubmit = vi.fn();
      renderForm({ onSubmit });
      await setupFormToFiltersStep('All Toggle Config');

      // Open severity multiselect and select "All"
      // Cloudscape Multiselect renders placeholder as text inside the trigger, not as an accessible label
      const severitySelect = (await screen.findAllByText('Select severity levels'))[0];
      await userEvent.click(severitySelect);

      const allOption = await screen.findByRole('option', { name: 'All' });
      await userEvent.click(allOption);

      // Now select "Critical" — this should deselect "All" (toggleMutualExclusiveAll branch: selected.length > 1 && selected.includes('All'))
      const criticalOption = await screen.findByRole('option', { name: 'Critical' });
      await userEvent.click(criticalOption);

      // Close the dropdown
      await userEvent.click(screen.getByText('Severity Filtering'));

      // ACT — submit
      const submitBtn = await screen.findByRole('button', { name: /create configuration/i });
      await userEvent.click(submitBtn);

      // ASSERT — severity filter should have only Critical (All was removed)
      await waitFor(() => {
        expect(onSubmit).toHaveBeenCalledTimes(1);
      });
      expect(onSubmit.mock.calls[0][0].severityFilter).toEqual(['Critical']);
    });
  });

  describe('Remediation status filter for remediation type', () => {
    it('submits remediation status filter when notification type is remediation', async () => {
      // ARRANGE
      const onSubmit = vi.fn();
      renderForm({ onSubmit });

      const nameInput = screen.getByPlaceholderText('e.g., Critical Findings - Security Team');
      await userEvent.type(nameInput, 'Remediation Status Config');

      // Select Remediation type
      const remediationRadio = screen.getByRole('radio', { name: /remediation/i });
      await userEvent.click(remediationRadio);

      await clickNext();

      const emailCheckbox = await screen.findByLabelText('Email');
      await userEvent.click(emailCheckbox);
      const primaryCheckbox = await screen.findByLabelText('Primary account contact');
      await userEvent.click(primaryCheckbox);

      await advanceSteps(3);

      // On filters step, open the remediation status multiselect
      // Cloudscape Multiselect renders placeholder as text inside the trigger, not as an accessible label
      const statusSelect = (await screen.findAllByText('Select remediation statuses'))[0];
      await userEvent.click(statusSelect);

      // Select "Success"
      const successOption = await screen.findByRole('option', { name: 'Success' });
      await userEvent.click(successOption);

      // Close dropdown
      await userEvent.click(screen.getByText('Remediation Status Filtering'));

      // ACT — submit
      const submitBtn = await screen.findByRole('button', { name: /create configuration/i });
      await userEvent.click(submitBtn);

      // ASSERT
      await waitFor(() => {
        expect(onSubmit).toHaveBeenCalledTimes(1);
      });
      expect(onSubmit.mock.calls[0][0].remediationStatusFilter).toEqual(expect.arrayContaining(['Success']));
    });
  });

  describe('toggleMutualExclusiveAll: deselecting all items resets to All', () => {
    it('resets severityFilter to All when user deselects all specific items', async () => {
      // ARRANGE
      const onSubmit = vi.fn();
      renderForm({ onSubmit });
      await setupFormToFiltersStep('Deselect All Config');

      // Open severity multiselect and select "Critical"
      const severitySelect = (await screen.findAllByText('Select severity levels'))[0];
      await userEvent.click(severitySelect);

      const criticalOption = await screen.findByRole('option', { name: 'Critical' });
      await userEvent.click(criticalOption);

      // Deselect "Critical" — selected becomes empty, toggleMutualExclusiveAll returns ['All']
      await userEvent.click(criticalOption);

      // Close dropdown
      await userEvent.click(screen.getByText('Severity Filtering'));

      // ACT — submit
      const submitBtn = await screen.findByRole('button', { name: /create configuration/i });
      await userEvent.click(submitBtn);

      // ASSERT — severityFilter resets to undefined when all items are deselected (All = no filter)
      await waitFor(() => {
        expect(onSubmit).toHaveBeenCalledTimes(1);
      });
      expect(onSubmit.mock.calls[0][0].severityFilter).toBeUndefined();
    });
  });

  describe('Edit mode without email channel', () => {
    it('leaves email checkboxes unchecked when initialValues has no email channel', async () => {
      // ARRANGE
      const initialValues = createTestNotificationConfig({
        configId: '00000000-0000-4000-8000-000000000007' as NotificationConfigurationItem['configId'],
        name: 'SNS Only Config',
        deliveryChannels: [{ type: 'sns', enabled: true, topicArn: 'arn:aws:sns:us-east-1:123456789012:alerts' }],
      });

      // ACT
      renderForm({ mode: 'edit', initialValues });
      await clickNext();

      // ASSERT — Email is not checked, SNS Topic is checked
      const emailCheckbox = await screen.findByLabelText('Email');
      expect(emailCheckbox).not.toBeChecked();
      const snsCheckbox = await screen.findByLabelText('SNS Topic');
      expect(snsCheckbox).toBeChecked();
    });
  });

  describe('Submit validation redirects to correct step', () => {
    it('shows name error and stays on step 0 when name is cleared before submit', async () => {
      // ARRANGE — edit mode with valid data, navigate to last step, go back, clear name
      const initialValues = createTestNotificationConfig({
        configId: '00000000-0000-4000-8000-000000000008' as NotificationConfigurationItem['configId'],
        name: 'Valid Name',
      });
      const onSubmit = vi.fn();
      renderForm({ mode: 'edit', initialValues, onSubmit });

      // Navigate to the last step (all validations pass with valid initialValues)
      await advanceSteps(4);

      // Verify we're on the last step (submit button visible)
      const saveBtn = await screen.findByRole('button', { name: /save changes/i });
      expect(saveBtn).toBeInTheDocument();

      // Go back to step 0 using Previous button
      const prevBtn = screen.getByRole('button', { name: /previous/i });
      await userEvent.click(prevBtn);
      await userEvent.click(screen.getByRole('button', { name: /previous/i }));
      await userEvent.click(screen.getByRole('button', { name: /previous/i }));
      await userEvent.click(screen.getByRole('button', { name: /previous/i }));

      // Clear the name field
      const nameInput = screen.getByPlaceholderText('e.g., Critical Findings - Security Team');
      await userEvent.clear(nameInput);

      // ACT — try to advance (triggers step 0 validation)
      await clickNext();

      // ASSERT — name error is shown, wizard stays on step 0
      await waitFor(() => {
        const errors = screen.getAllByText('Configuration name is required.');
        expect(errors.length).toBeGreaterThanOrEqual(1);
      });
      expect(onSubmit).not.toHaveBeenCalled();
    });

    it('shows delivery channel error when no channel is enabled', async () => {
      // ARRANGE — edit mode with valid data, navigate to step 1, disable the channel
      const initialValues = createTestNotificationConfig({
        configId: '00000000-0000-4000-8000-000000000009' as NotificationConfigurationItem['configId'],
        name: 'Channel Test Config',
      });
      const onSubmit = vi.fn();
      renderForm({ mode: 'edit', initialValues, onSubmit });

      // Navigate to step 1 (delivery channels)
      await clickNext();

      // Uncheck email to disable all channels
      const emailCheckbox = await screen.findByLabelText('Email');
      await userEvent.click(emailCheckbox);

      // ACT — try to advance past step 1
      await clickNext();

      // ASSERT — delivery channel error is shown
      await waitFor(() => {
        const errors = screen.getAllByText('At least one delivery channel must be enabled.');
        expect(errors.length).toBeGreaterThanOrEqual(1);
      });
      expect(onSubmit).not.toHaveBeenCalled();
    });
  });

  describe('Enforce deadline checkbox', () => {
    it('only appears when includeRemediationDeadline is checked for finding type', async () => {
      // ARRANGE
      renderForm();
      await advanceToContentOptionsStep('Enforce Deadline Config');

      // ASSERT — checkbox is not rendered when includeRemediationDeadline is unchecked
      expect(screen.queryByLabelText('Auto-remediate overdue findings')).not.toBeInTheDocument();

      // ACT — enable includeRemediationDeadline
      const deadlineCheckbox = screen.getByLabelText('Include remediation deadline');
      await userEvent.click(deadlineCheckbox);

      // ASSERT — enforce checkbox now appears and is enabled
      const enforceCheckbox = screen.getByLabelText('Auto-remediate overdue findings');
      expect(enforceCheckbox).toBeInTheDocument();
      expect(enforceCheckbox).not.toBeDisabled();
      expect(enforceCheckbox).not.toBeChecked();

      // ASSERT — the enforcement help text documents the 24-hour grace period verbatim
      expect(
        screen.getByText(
          "Automatically triggers remediation for findings that are not resolved before the deadline. Applies to findings matching this configuration's control, severity, and resource filters. Findings are never auto-remediated less than 24 hours after they become eligible for enforcement.",
        ),
      ).toBeInTheDocument();
    });

    it('is not rendered when notification type is remediation', async () => {
      // ARRANGE
      renderForm();

      const nameInput = screen.getByPlaceholderText('e.g., Critical Findings - Security Team');
      await userEvent.type(nameInput, 'Remediation Type Enforce');
      const remediationRadio = screen.getByRole('radio', { name: /remediation/i });
      await userEvent.click(remediationRadio);
      await clickNext();

      const emailCheckbox = await screen.findByLabelText('Email');
      await userEvent.click(emailCheckbox);
      const primaryCheckbox = await screen.findByLabelText('Primary account contact');
      await userEvent.click(primaryCheckbox);
      await advanceSteps(2);

      // ASSERT — enforce checkbox is not rendered for remediation type
      expect(screen.queryByLabelText('Auto-remediate overdue findings')).not.toBeInTheDocument();
    });

    it('resets to false when includeRemediationDeadline is unchecked, and submits correct enforceDeadline values in contentOptions', async () => {
      // ARRANGE
      const onSubmit = vi.fn();
      renderForm({ onSubmit });
      await advanceToContentOptionsStep('Enforce Submit Config');

      // ACT — enable deadline and enforce
      const deadlineCheckbox = screen.getByLabelText('Include remediation deadline');
      await userEvent.click(deadlineCheckbox);
      const enforceCheckbox = screen.getByLabelText('Auto-remediate overdue findings');
      await userEvent.click(enforceCheckbox);

      // ASSERT — enforce is checked
      expect(enforceCheckbox).toBeChecked();

      // ACT — uncheck includeRemediationDeadline (should reset enforceDeadline and hide checkbox)
      await userEvent.click(deadlineCheckbox);

      // ASSERT — enforce checkbox is no longer rendered
      expect(screen.queryByLabelText('Auto-remediate overdue findings')).not.toBeInTheDocument();

      // ACT — re-enable deadline, leave enforce unchecked, submit
      await userEvent.click(deadlineCheckbox);
      await clickNext();
      const submitBtn = await screen.findByRole('button', { name: /create configuration/i });
      await userEvent.click(submitBtn);

      // ASSERT — payload includes enforceDeadline: false
      await waitFor(() => {
        expect(onSubmit).toHaveBeenCalledTimes(1);
      });
      expect(onSubmit.mock.calls[0][0].contentOptions.enforceDeadline).toBe(false);
    });

    it('submits enforceDeadline: true in contentOptions when checked', async () => {
      // ARRANGE
      const onSubmit = vi.fn();
      renderForm({ onSubmit });
      await advanceToContentOptionsStep('Enforce True Config');

      // ACT — enable deadline and enforce, then submit
      const deadlineCheckbox = screen.getByLabelText('Include remediation deadline');
      await userEvent.click(deadlineCheckbox);
      const enforceCheckbox = screen.getByLabelText('Auto-remediate overdue findings');
      await userEvent.click(enforceCheckbox);

      await clickNext();
      const submitBtn = await screen.findByRole('button', { name: /create configuration/i });
      await userEvent.click(submitBtn);

      // ASSERT — payload includes enforceDeadline: true
      await waitFor(() => {
        expect(onSubmit).toHaveBeenCalledTimes(1);
      });
      const payload = onSubmit.mock.calls[0][0];
      expect(payload.contentOptions.enforceDeadline).toBe(true);
      expect(payload.contentOptions.includeRemediationDeadline).toBe(true);
      expect(payload.contentOptions.remediationDeadlineDays).toBe(7);
    });
  });

  describe('Match-all enforcement help text', () => {
    const SYNC_CYCLE_MESSAGE =
      'Enforcement applies immediately to new findings as they arrive. Findings that already exist may take up to one synchronization cycle to be enforced.';
    const PROCESSING_CYCLE_MESSAGE =
      'Disabling enforcement or shortening the deadline takes effect on existing findings during the next processing cycle.';

    it('shows the help text only while enforcement is enabled for a match-all (no control) selection', async () => {
      // ARRANGE — create mode defaults the control selection to "All" (match-all).
      renderForm();
      await advanceToContentOptionsStep('Match All Help Text');

      // ASSERT — no help text before enforcement is enabled.
      expect(screen.queryByText(SYNC_CYCLE_MESSAGE)).not.toBeInTheDocument();

      // ACT — enable the remediation deadline and the auto-remediate (enforcement) checkbox.
      await userEvent.click(screen.getByLabelText('Include remediation deadline'));
      await userEvent.click(screen.getByLabelText('Auto-remediate overdue findings'));

      // ASSERT — both verbatim help strings appear for the match-all selection.
      expect(screen.getByText(SYNC_CYCLE_MESSAGE)).toBeInTheDocument();
      expect(screen.getByText(PROCESSING_CYCLE_MESSAGE)).toBeInTheDocument();

      // ACT — disable enforcement again.
      await userEvent.click(screen.getByLabelText('Auto-remediate overdue findings'));

      // ASSERT — the help text is hidden once enforcement is off.
      expect(screen.queryByText(SYNC_CYCLE_MESSAGE)).not.toBeInTheDocument();
      expect(screen.queryByText(PROCESSING_CYCLE_MESSAGE)).not.toBeInTheDocument();
    });

    it('hides the help text when enforcement is enabled but specific controls are selected', async () => {
      // ARRANGE — edit mode with a specific control selected and enforcement already on.
      const initialValues = createTestNotificationConfig({
        controlIds: ['S3.1'],
        contentOptions: {
          includeManualRemediationLink: false,
          includeRemediationDeadline: true,
          enforceDeadline: true,
          remediationDeadlineDays: 7,
          includeIaCSnippet: false,
          includeEnableAutomationLink: false,
        },
      });
      renderForm({ mode: 'edit', initialValues, controls: [createTestControl()] });

      // ACT — navigate to the content options step (basic → delivery → batching → content).
      await advanceSteps(3);

      // ASSERT — enforcement is on, but the match-all help text is not shown for a scoped selection.
      expect(screen.getByLabelText('Auto-remediate overdue findings')).toBeChecked();
      expect(screen.queryByText(SYNC_CYCLE_MESSAGE)).not.toBeInTheDocument();
      expect(screen.queryByText(PROCESSING_CYCLE_MESSAGE)).not.toBeInTheDocument();
    });
  });

  describe('Notification type change detection', () => {
    it('leaves remediation-only fields untouched on mount and resets them once per real type change', async () => {
      // ARRANGE — edit mode at remediation type, with IaC snippets on and a non-default
      // remediation-status filter. Both are what the type-change effect resets, so they
      // are the observables for "fired" and "did not fire".
      const onSubmit = vi.fn();
      const initialValues = createTestNotificationConfig({
        configId: ConfigIdSchema.parse('00000000-0000-4000-8000-000000000011'),
        name: 'Type Change Config',
        notificationType: 'remediation',
        remediationStatusFilter: ['Success'],
        contentOptions: {
          includeManualRemediationLink: false,
          includeRemediationDeadline: false,
          enforceDeadline: false,
          includeIaCSnippet: true,
          iacFormats: ['terraform'],
          includeEnableAutomationLink: false,
        },
      });
      server.use(
        http.get(`${MOCK_SERVER_URL}notifications/:configId/subscriptions`, async () =>
          ok({ subscriptions: [], hasFailure: false }),
        ),
      );
      const { rerenderSameProps } = renderForm({ mode: 'edit', initialValues, onSubmit });

      // ASSERT — mount quiescence: the content option survives the initial render
      await advanceSteps(3);
      expect(await screen.findByLabelText('Include IaC remediation code')).toBeChecked();
      expect(screen.getByLabelText('Terraform')).toBeChecked();

      // ASSERT — mount quiescence: the remediation-status filter survives the initial render.
      // A reset would replace this token with 'All'; the filters step shows no other 'Success'.
      await clickNext();
      expect(await screen.findByText('Success')).toBeInTheDocument();

      // ACT — switch the notification type to Finding, then save from the last step
      await userEvent.click(screen.getAllByRole('button', { name: /step 1: basic information/i })[0]);
      await userEvent.click(await screen.findByRole('radio', { name: /^finding/i }));
      await advanceSteps(4);
      await userEvent.click(await screen.findByRole('button', { name: /save changes/i }));

      // ASSERT — the real type change reset both dependent fields ('All' collapses to undefined)
      await waitFor(() => {
        expect(onSubmit).toHaveBeenCalledTimes(1);
      });
      expect(onSubmit.mock.calls[0][0].remediationStatusFilter).toBeUndefined();
      expect(onSubmit.mock.calls[0][0].contentOptions.includeIaCSnippet).toBe(false);

      // ACT — return to remediation, re-enable the IaC option, then re-render at the same type
      await userEvent.click(screen.getAllByRole('button', { name: /step 1: basic information/i })[0]);
      await userEvent.click(await screen.findByRole('radio', { name: /^remediation/i }));
      await advanceSteps(3);
      await userEvent.click(await screen.findByLabelText('Include IaC remediation code'));
      rerenderSameProps();

      // ASSERT — a re-render without a type change does not reset again
      expect(screen.getByLabelText('Include IaC remediation code')).toBeChecked();
    });
  });

  describe('Edit mode secondary save action', () => {
    it('offers a save action on every step but the last, and only in edit mode', async () => {
      // ARRANGE
      const onSubmit = vi.fn();
      const initialValues = createTestNotificationConfig({
        configId: '00000000-0000-4000-8000-000000000012' as NotificationConfigurationItem['configId'],
        name: 'Secondary Save Config',
      });
      server.use(
        http.get(`${MOCK_SERVER_URL}notifications/:configId/subscriptions`, async () =>
          ok({ subscriptions: [], hasFailure: false }),
        ),
      );

      // ACT — create mode, first step
      const createModeRender = renderForm({ onSubmit });

      // ASSERT — the save action is gated to edit mode
      expect(await screen.findByRole('button', { name: /next/i })).toBeInTheDocument();
      expect(screen.queryByRole('button', { name: /save changes/i })).not.toBeInTheDocument();
      createModeRender.unmount();

      // ACT — edit mode, first step
      renderForm({ mode: 'edit', initialValues, onSubmit });

      // ASSERT — a save action sits alongside the "Next" primary, so it is the secondary one
      const saveOnFirstStep = await screen.findByRole('button', { name: /save changes/i });
      expect(screen.getByRole('button', { name: /next/i })).toBeInTheDocument();

      // ACT — the secondary save submits without walking to the last step
      await userEvent.click(saveOnFirstStep);

      // ASSERT
      await waitFor(() => {
        expect(onSubmit).toHaveBeenCalledTimes(1);
      });

      // ACT — walk to the last step
      await advanceSteps(4);

      // ASSERT — only the primary submit remains, the secondary is not duplicated there
      expect(screen.getAllByRole('button', { name: /save changes/i })).toHaveLength(1);
      expect(screen.queryByRole('button', { name: /next/i })).not.toBeInTheDocument();
    });
  });
});
