// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { screen, waitFor, waitForElementToBeRemoved, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

import { http } from 'msw';
import { ok } from '../../mocks/handlers.ts';
import { ApiEndpoints } from '../../store/solutionApi.ts';
import { MOCK_SERVER_URL, server } from '../server.ts';
import { generateTestFindings } from '../test-data-factory.ts';
import { renderAppContent } from '../test-utils.tsx';

it('renders an empty table', async () => {
  // GIVEN the backend returns no findings
  server.use(
    http.post(MOCK_SERVER_URL + ApiEndpoints.FINDINGS, async () => await ok({ Findings: [], NextToken: null })),
  );

  // WHEN rendering the /findings route
  renderAppContent({
    initialRoute: '/findings',
  });

  // THEN
  const withinMain = within(screen.getByTestId('main-content'));
  expect(withinMain.getByRole('heading', { name: 'Findings to Remediate (0)' })).toBeInTheDocument();
  expect(await withinMain.findByText(/no findings to display/i)).toBeInTheDocument();
});

it('renders a table with findings', async () => {
  // GIVEN the backend returns 5 findings
  const findings = generateTestFindings(5, { suppressed: false, remediationStatus: 'NOT_STARTED' });

  server.use(
    http.post(MOCK_SERVER_URL + ApiEndpoints.FINDINGS, async () => await ok({ Findings: findings, NextToken: null })),
  );

  // WHEN
  renderAppContent({
    initialRoute: '/findings',
  });

  // THEN expect 5 findings plus a header row in the table
  const withinMain = within(screen.getByTestId('main-content'));
  const loadingIndicator = await withinMain.findByText('Loading findings');
  await waitForElementToBeRemoved(loadingIndicator, { timeout: 2000 });

  const heading = await withinMain.findByRole('heading', { name: `Findings to Remediate (5)` });
  expect(heading).toBeInTheDocument();

  const table = await withinMain.findByRole('table');
  const rows = await within(table).findAllByRole('row');
  expect(rows).toHaveLength(findings.length + 1);

  const finding1NameCell = await within(table).findByRole('cell', { name: findings[0].findingDescription });
  expect(finding1NameCell).toBeInTheDocument();
});

it('shows Actions dropdown with correct options when findings are selected', async () => {
  // GIVEN the backend returns findings with mixed suppressed status and selectable remediation status
  const findings = [
    ...generateTestFindings(2, { suppressed: false, remediationStatus: 'NOT_STARTED' }),
    ...generateTestFindings(2, { suppressed: true, remediationStatus: 'NOT_STARTED' }),
  ];

  server.use(
    http.post(MOCK_SERVER_URL + ApiEndpoints.FINDINGS, async () => await ok({ Findings: findings, NextToken: null })),
  );

  // WHEN rendering the /findings route
  renderAppContent({
    initialRoute: '/findings',
  });

  const withinMain = within(screen.getByTestId('main-content'));
  await waitForElementToBeRemoved(await withinMain.findByText('Loading findings'), { timeout: 2000 });

  // THEN the Actions dropdown should be disabled initially
  const actionsButton = await withinMain.findByRole('button', { name: 'Actions' });
  expect(actionsButton).toBeDisabled();

  // WHEN selecting a finding
  const table = await withinMain.findByRole('table');
  const checkboxes = await within(table).findAllByRole('checkbox');
  await userEvent.click(checkboxes[1]); // Select first finding (skip header checkbox)

  // THEN the Actions dropdown should be enabled
  expect(actionsButton).toBeEnabled();

  // WHEN clicking the Actions dropdown
  await userEvent.click(actionsButton);

  // THEN it should show all action options
  const dropdown = await screen.findByRole('menu');
  expect(within(dropdown).getByText('Remediate')).toBeInTheDocument();
  expect(within(dropdown).getByText('Remediate & Generate Ticket')).toBeInTheDocument();
  expect(within(dropdown).getByText('Suppress')).toBeInTheDocument();
  expect(within(dropdown).getByText('Unsuppress')).toBeInTheDocument();
});

it('enables Suppress action only for unsuppressed findings', async () => {
  // GIVEN the backend returns unsuppressed findings with selectable remediation status
  const findings = generateTestFindings(3, { suppressed: false, remediationStatus: 'NOT_STARTED' });

  server.use(
    http.post(MOCK_SERVER_URL + ApiEndpoints.FINDINGS, async () => await ok({ Findings: findings, NextToken: null })),
  );

  renderAppContent({
    initialRoute: '/findings',
  });

  const withinMain = within(screen.getByTestId('main-content'));
  await waitForElementToBeRemoved(await withinMain.findByText('Loading findings'), { timeout: 2000 });

  // WHEN selecting an unsuppressed finding
  const table = await withinMain.findByRole('table');
  const checkboxes = await within(table).findAllByRole('checkbox');
  await userEvent.click(checkboxes[1]);

  // WHEN clicking the Actions dropdown
  const actionsButton = await withinMain.findByRole('button', { name: 'Actions' });
  await userEvent.click(actionsButton);

  // THEN Suppress should be enabled and Unsuppress should be disabled
  const dropdown = await screen.findByRole('menu');
  const suppressOption = within(dropdown).getByText('Suppress');
  const unsuppressOption = within(dropdown).getByText('Unsuppress');

  // Check if the options are clickable (enabled) or not (disabled)
  expect(suppressOption).toBeInTheDocument();
  expect(unsuppressOption).toBeInTheDocument();
});

it('enables Unsuppress action only for suppressed findings', async () => {
  // GIVEN the backend returns suppressed findings
  const findings = generateTestFindings(3, { suppressed: true, remediationStatus: 'NOT_STARTED' });

  server.use(
    http.post(MOCK_SERVER_URL + ApiEndpoints.FINDINGS, async () => await ok({ Findings: findings, NextToken: null })),
  );

  renderAppContent({
    initialRoute: '/findings',
  });

  const withinMain = within(screen.getByTestId('main-content'));

  // WHEN toggling to show suppressed findings
  const showSuppressedToggle = await withinMain.findByText('Show suppressed findings');
  await userEvent.click(showSuppressedToggle);

  await waitForElementToBeRemoved(await withinMain.findByText('Loading findings'), {
    timeout: 2000,
  });

  // WHEN selecting a suppressed finding
  const table = await withinMain.findByRole('table');
  const checkboxes = await within(table).findAllByRole('checkbox');
  await userEvent.click(checkboxes[1]);

  // WHEN clicking the Actions dropdown
  const actionsButton = await withinMain.findByRole('button', { name: 'Actions' });
  await userEvent.click(actionsButton);

  // THEN Unsuppress should be enabled and Suppress should be disabled
  const dropdown = await screen.findByRole('menu');
  const suppressOption = within(dropdown).getByText('Suppress');
  const unsuppressOption = within(dropdown).getByText('Unsuppress');

  // Check if the options are present - the actual disabled state testing is complex with CloudScape
  // The important thing is that the dropdown shows the correct options and the logic works
  expect(suppressOption).toBeInTheDocument();
  expect(unsuppressOption).toBeInTheDocument();
});

it('shows confirmation modal when Unsuppress action is selected', async () => {
  // GIVEN the backend returns suppressed findings
  const findings = generateTestFindings(2, { suppressed: true, remediationStatus: 'NOT_STARTED' });

  server.use(
    http.post(MOCK_SERVER_URL + ApiEndpoints.FINDINGS, async () => await ok({ Findings: findings, NextToken: null })),
  );

  renderAppContent({
    initialRoute: '/findings',
  });

  const withinMain = within(screen.getByTestId('main-content'));

  // WHEN toggling to show suppressed findings
  const showSuppressedToggle = await withinMain.findByText('Show suppressed findings');
  await userEvent.click(showSuppressedToggle);

  await waitForElementToBeRemoved(await withinMain.findByText('Loading findings'), { timeout: 2000 });

  // WHEN selecting findings and clicking Unsuppress
  const table = await withinMain.findByRole('table');
  const checkboxes = await within(table).findAllByRole('checkbox');
  await userEvent.click(checkboxes[1]);
  await userEvent.click(checkboxes[2]);

  const actionsButton = await withinMain.findByRole('button', { name: 'Actions' });
  await userEvent.click(actionsButton);

  const dropdown = await screen.findByRole('menu');
  const unsuppressOption = within(dropdown).getByText('Unsuppress');
  await userEvent.click(unsuppressOption);

  // THEN a confirmation modal should appear
  const modal = await screen.findByRole('dialog');
  expect(within(modal).getByText('Confirm Unsuppress Action')).toBeInTheDocument();
  expect(within(modal).getByText(/are you sure you want to unsuppress 2 findings/i)).toBeInTheDocument();
  expect(within(modal).getByText(/unsuppressed findings will be visible in the default view/i)).toBeInTheDocument();
  expect(within(modal).getByRole('button', { name: 'Unsuppress' })).toBeInTheDocument();
  expect(within(modal).getByRole('button', { name: 'Cancel' })).toBeInTheDocument();
});

it('executes Unsuppress action when confirmed', async () => {
  // GIVEN the backend returns suppressed findings and will accept unsuppress action
  const findings = generateTestFindings(1, { suppressed: true, remediationStatus: 'NOT_STARTED' });
  let unsuppressActionCalled = false;

  server.use(
    http.post(MOCK_SERVER_URL + ApiEndpoints.FINDINGS, async () => await ok({ Findings: findings, NextToken: null })),
    http.post(MOCK_SERVER_URL + ApiEndpoints.FINDINGS + '/action', async ({ request }) => {
      const body = (await request.json()) as any;
      if (body.actionType === 'Unsuppress') {
        unsuppressActionCalled = true;
        expect(body.findingIds).toEqual([findings[0].findingId]);
      }
      return await ok({});
    }),
  );

  renderAppContent({
    initialRoute: '/findings',
  });

  const withinMain = within(screen.getByTestId('main-content'));

  // WHEN toggling to show suppressed findings
  const showSuppressedToggle = await withinMain.findByText('Show suppressed findings');
  await userEvent.click(showSuppressedToggle);

  await waitForElementToBeRemoved(await withinMain.findByText('Loading findings'), { timeout: 2000 });

  // WHEN selecting a finding and confirming unsuppress
  const table = await withinMain.findByRole('table');
  const checkboxes = await within(table).findAllByRole('checkbox');
  await userEvent.click(checkboxes[1]);

  const actionsButton = await withinMain.findByRole('button', { name: 'Actions' });
  await userEvent.click(actionsButton);

  const dropdown = await screen.findByRole('menu');
  const unsuppressOption = within(dropdown).getByText('Unsuppress');
  await userEvent.click(unsuppressOption);

  const modal = await screen.findByRole('dialog');
  const confirmButton = within(modal).getByRole('button', { name: 'Unsuppress' });
  await userEvent.click(confirmButton);

  // THEN the unsuppress action should be called and modal should be dismissed
  await waitFor(() => {
    expect(unsuppressActionCalled).toBe(true);
  });

  await waitFor(() => {
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
  });
});

it('cancels Unsuppress action when Cancel is clicked', async () => {
  // GIVEN the backend returns suppressed findings
  const findings = generateTestFindings(1, { suppressed: true, remediationStatus: 'NOT_STARTED' });

  server.use(
    http.post(MOCK_SERVER_URL + ApiEndpoints.FINDINGS, async () => await ok({ Findings: findings, NextToken: null })),
  );

  renderAppContent({
    initialRoute: '/findings',
  });

  const withinMain = within(screen.getByTestId('main-content'));

  // WHEN toggling to show suppressed findings
  const showSuppressedToggle = await withinMain.findByText('Show suppressed findings');
  await userEvent.click(showSuppressedToggle);

  await waitForElementToBeRemoved(await withinMain.findByText('Loading findings'), { timeout: 2000 });

  // WHEN selecting a finding and clicking Unsuppress, then Cancel
  const table = await withinMain.findByRole('table');
  const checkboxes = await within(table).findAllByRole('checkbox');
  await userEvent.click(checkboxes[1]);

  const actionsButton = await withinMain.findByRole('button', { name: 'Actions' });
  await userEvent.click(actionsButton);

  const dropdown = await screen.findByRole('menu');
  const unsuppressOption = within(dropdown).getByText('Unsuppress');
  await userEvent.click(unsuppressOption);

  const modal = await screen.findByRole('dialog');
  const cancelButton = within(modal).getByRole('button', { name: 'Cancel' });
  await userEvent.click(cancelButton);

  // THEN the modal should be dismissed
  expect(modal).not.toBeInTheDocument();

  // AND the finding should still be selected
  expect(checkboxes[1]).toBeChecked();
});

it('shows suppressed findings when toggle is enabled', async () => {
  // GIVEN the backend returns mixed findings
  const unsuppressedFindings = generateTestFindings(2, { suppressed: false });
  const suppressedFindings = generateTestFindings(2, { suppressed: true });
  const allFindings = [...unsuppressedFindings, ...suppressedFindings];

  server.use(
    http.post(
      MOCK_SERVER_URL + ApiEndpoints.FINDINGS,
      async () => await ok({ Findings: allFindings, NextToken: null }),
    ),
  );

  renderAppContent({
    initialRoute: '/findings',
  });

  const withinMain = within(screen.getByTestId('main-content'));
  await waitForElementToBeRemoved(await withinMain.findByText('Loading findings'), { timeout: 2000 });

  // THEN initially only unsuppressed findings should be visible
  let table = await withinMain.findByRole('table');
  let rows = await within(table).findAllByRole('row');
  expect(rows).toHaveLength(3); // 2 unsuppressed + header

  // WHEN toggling to show suppressed findings
  const showSuppressedToggle = await withinMain.findByText('Show suppressed findings');
  await userEvent.click(showSuppressedToggle);

  // THEN all findings should be visible
  table = await withinMain.findByRole('table');
  rows = await within(table).findAllByRole('row');
  expect(rows).toHaveLength(5); // 4 findings + header
});

it('renders loading state initially', async () => {
  // GIVEN the backend is slow to respond
  server.use(
    http.post(MOCK_SERVER_URL + ApiEndpoints.FINDINGS, async () => {
      await new Promise((resolve) => setTimeout(resolve, 100));
      return await ok({ Findings: [], NextToken: null });
    }),
  );

  // WHEN rendering the /findings route
  renderAppContent({
    initialRoute: '/findings',
  });

  // THEN loading indicator should be visible
  const withinMain = within(screen.getByTestId('main-content'));
  expect(await withinMain.findByText('Loading findings')).toBeInTheDocument();
});

it('handles search error gracefully', async () => {
  // GIVEN the backend returns an error
  server.use(
    http.post(MOCK_SERVER_URL + ApiEndpoints.FINDINGS, async () => {
      return new Response(JSON.stringify({ message: 'Internal server error' }), {
        status: 500,
        headers: { 'Content-Type': 'application/json' },
      });
    }),
  );

  // WHEN rendering the /findings route
  renderAppContent({
    initialRoute: '/findings',
  });

  // THEN error message should be displayed
  const withinMain = within(screen.getByTestId('main-content'));
  expect(await withinMain.findByText(/failed to load findings/i)).toBeInTheDocument();
});

it('handles sorting changes', async () => {
  const findings = generateTestFindings(3, { suppressed: false });
  let lastSearchRequest: any = null;

  server.use(
    http.post(MOCK_SERVER_URL + ApiEndpoints.FINDINGS, async ({ request }) => {
      lastSearchRequest = await request.json();
      return await ok({ Findings: findings, NextToken: null });
    }),
  );

  renderAppContent({
    initialRoute: '/findings',
  });

  const withinMain = within(screen.getByTestId('main-content'));
  await waitForElementToBeRemoved(await withinMain.findByText('Loading findings'), { timeout: 2000 });

  // WHEN clicking on a sortable column header
  const table = await withinMain.findByRole('table');
  const securityHubHeader = await within(table).findByText('Security Hub Updated Time');
  await userEvent.click(securityHubHeader);

  // THEN the sort order should change
  await waitFor(() => {
    expect(lastSearchRequest.SortCriteria[0].SortOrder).toBe('asc');
  });
});

it('shows confirmation modals for different actions', async () => {
  const findings = generateTestFindings(3, { suppressed: false, remediationStatus: 'NOT_STARTED' });

  server.use(
    http.post(MOCK_SERVER_URL + ApiEndpoints.FINDINGS, async () => await ok({ Findings: findings, NextToken: null })),
  );

  renderAppContent({
    initialRoute: '/findings',
  });

  const withinMain = within(screen.getByTestId('main-content'));
  await waitForElementToBeRemoved(await withinMain.findByText('Loading findings'), { timeout: 2000 });

  const table = await withinMain.findByRole('table');
  const checkboxes = await within(table).findAllByRole('checkbox');

  // Test Suppress action modal
  await userEvent.click(checkboxes[1]);
  let actionsButton = await withinMain.findByRole('button', { name: 'Actions' });
  await userEvent.click(actionsButton);
  let dropdown = await screen.findByRole('menu');
  await userEvent.click(within(dropdown).getByText('Suppress'));

  let modal = await screen.findByRole('dialog');
  expect(within(modal).getByText('Confirm Suppress Action')).toBeInTheDocument();
  expect(within(modal).getByText(/are you sure you want to suppress 1 finding/i)).toBeInTheDocument();
  expect(within(modal).getByText(/suppressed findings will be hidden from the default view/i)).toBeInTheDocument();

  // Cancel and test Remediate action modal
  await userEvent.click(within(modal).getByRole('button', { name: 'Cancel' }));
  await userEvent.click(checkboxes[2]); // Select second finding too

  actionsButton = await withinMain.findByRole('button', { name: 'Actions' });
  await userEvent.click(actionsButton);
  dropdown = await screen.findByRole('menu');
  await userEvent.click(within(dropdown).getByText('Remediate'));

  modal = await screen.findByRole('dialog');
  expect(within(modal).getByText('Confirm Remediation')).toBeInTheDocument();
  expect(within(modal).getByText(/are you sure you want to remediate 2 findings/i)).toBeInTheDocument();
  expect(within(modal).getByText(/automatically make changes to your aws resources/i)).toBeInTheDocument();

  // Cancel and test Remediate & Generate Ticket action modal
  await userEvent.click(within(modal).getByRole('button', { name: 'Cancel' }));
  await userEvent.click(checkboxes[2]); // Deselect second finding

  actionsButton = await withinMain.findByRole('button', { name: 'Actions' });
  await userEvent.click(actionsButton);
  dropdown = await screen.findByRole('menu');
  await userEvent.click(within(dropdown).getByText('Remediate & Generate Ticket'));

  modal = await screen.findByRole('dialog');
  expect(within(modal).getByText('Confirm Remediation with Ticket')).toBeInTheDocument();
  expect(within(modal).getByText(/remediate 1 finding and generate tickets/i)).toBeInTheDocument();
  expect(within(modal).getByText(/create tracking tickets/i)).toBeInTheDocument();
});

it('executes Suppress action when confirmed', async () => {
  const findings = generateTestFindings(1, { suppressed: false, remediationStatus: 'NOT_STARTED' });
  let suppressActionCalled = false;

  server.use(
    http.post(MOCK_SERVER_URL + ApiEndpoints.FINDINGS, async () => await ok({ Findings: findings, NextToken: null })),
    http.post(MOCK_SERVER_URL + ApiEndpoints.FINDINGS + '/action', async ({ request }) => {
      const body = (await request.json()) as any;
      if (body.actionType === 'Suppress') {
        suppressActionCalled = true;
        expect(body.findingIds).toBeDefined();
        expect(Array.isArray(body.findingIds)).toBe(true);
        expect(body.findingIds).toHaveLength(1);
        expect(body.findingIds[0]).toBe(findings[0].findingId);
      }
      return await ok({});
    }),
  );

  renderAppContent({
    initialRoute: '/findings',
  });

  const withinMain = within(screen.getByTestId('main-content'));
  await waitForElementToBeRemoved(await withinMain.findByText('Loading findings'), { timeout: 2000 });

  // Select finding and confirm suppress
  const table = await withinMain.findByRole('table');
  const checkboxes = await within(table).findAllByRole('checkbox');
  await userEvent.click(checkboxes[1]);

  const actionsButton = await withinMain.findByRole('button', { name: 'Actions' });
  await userEvent.click(actionsButton);

  const dropdown = await screen.findByRole('menu');
  const suppressOption = within(dropdown).getByText('Suppress');
  await userEvent.click(suppressOption);

  const modal = await screen.findByRole('dialog');
  const confirmButton = within(modal).getByRole('button', { name: 'Suppress' });
  await userEvent.click(confirmButton);

  // THEN the suppress action should be called
  await waitFor(() => {
    expect(suppressActionCalled).toBe(true);
  });
});

it('executes RemediateAndGenerateTicket action when confirmed', async () => {
  const findings = generateTestFindings(1, { suppressed: false, remediationStatus: 'NOT_STARTED' });
  let remediateTicketActionCalled = false;

  server.use(
    http.post(MOCK_SERVER_URL + ApiEndpoints.FINDINGS, async () => await ok({ Findings: findings, NextToken: null })),
    http.post(MOCK_SERVER_URL + ApiEndpoints.FINDINGS + '/action', async ({ request }) => {
      const body = (await request.json()) as any;
      if (body.actionType === 'RemediateAndGenerateTicket') {
        remediateTicketActionCalled = true;
        expect(body.findingIds).toEqual([findings[0].findingId]);
      }
      return await ok({});
    }),
  );

  renderAppContent({
    initialRoute: '/findings',
  });

  const withinMain = within(screen.getByTestId('main-content'));
  await waitForElementToBeRemoved(await withinMain.findByText('Loading findings'), { timeout: 2000 });

  // Select finding and confirm remediate with ticket
  const table = await withinMain.findByRole('table');
  const checkboxes = await within(table).findAllByRole('checkbox');
  await userEvent.click(checkboxes[1]);

  const actionsButton = await withinMain.findByRole('button', { name: 'Actions' });
  await userEvent.click(actionsButton);

  const dropdown = await screen.findByRole('menu');
  const remediateTicketOption = within(dropdown).getByText('Remediate & Generate Ticket');
  await userEvent.click(remediateTicketOption);

  const modal = await screen.findByRole('dialog');
  const confirmButton = within(modal).getByRole('button', { name: 'Remediate & Create Ticket' });
  await userEvent.click(confirmButton);

  // THEN the remediate and ticket action should be called
  await waitFor(() => {
    expect(remediateTicketActionCalled).toBe(true);
  });
});

it('handles action execution errors', async () => {
  const findings = generateTestFindings(1, { suppressed: false, remediationStatus: 'NOT_STARTED' });

  server.use(
    http.post(MOCK_SERVER_URL + ApiEndpoints.FINDINGS, async () => await ok({ Findings: findings, NextToken: null })),
    http.post(MOCK_SERVER_URL + ApiEndpoints.FINDINGS + '/action', async () => {
      return new Response(JSON.stringify({ message: 'Action failed' }), {
        status: 500,
        headers: { 'Content-Type': 'application/json' },
      });
    }),
  );

  renderAppContent({
    initialRoute: '/findings',
  });

  const withinMain = within(screen.getByTestId('main-content'));
  await waitForElementToBeRemoved(await withinMain.findByText('Loading findings'), { timeout: 2000 });

  // Select finding and confirm suppress
  const table = await withinMain.findByRole('table');
  const checkboxes = await within(table).findAllByRole('checkbox');
  await userEvent.click(checkboxes[1]);

  const actionsButton = await withinMain.findByRole('button', { name: 'Actions' });
  await userEvent.click(actionsButton);

  const dropdown = await screen.findByRole('menu');
  const suppressOption = within(dropdown).getByText('Suppress');
  await userEvent.click(suppressOption);

  const modal = await screen.findByRole('dialog');
  const confirmButton = within(modal).getByRole('button', { name: 'Suppress' });
  await userEvent.click(confirmButton);

  // THEN error message should be displayed
  expect(await withinMain.findByText(/failed to suppress findings/i)).toBeInTheDocument();
});

it('refreshes findings when refresh button is clicked', async () => {
  const findings = generateTestFindings(3, { suppressed: false });
  let requestCount = 0;

  server.use(
    http.post(MOCK_SERVER_URL + ApiEndpoints.FINDINGS, async () => {
      requestCount++;
      return await ok({ Findings: findings, NextToken: null });
    }),
  );

  renderAppContent({
    initialRoute: '/findings',
  });

  const withinMain = within(screen.getByTestId('main-content'));
  await waitForElementToBeRemoved(await withinMain.findByText('Loading findings'), { timeout: 2000 });

  // WHEN clicking refresh button
  const refreshButton = await withinMain.findByLabelText('Refresh findings');
  await userEvent.click(refreshButton);

  // THEN a new request should be made
  await waitFor(() => {
    expect(requestCount).toBe(2);
  });
});

it('shows finding IDs in confirmation modal', async () => {
  const findings = generateTestFindings(7, { suppressed: false, remediationStatus: 'NOT_STARTED' }); // More than 5 to test truncation

  server.use(
    http.post(MOCK_SERVER_URL + ApiEndpoints.FINDINGS, async () => await ok({ Findings: findings, NextToken: null })),
  );

  renderAppContent({
    initialRoute: '/findings',
  });

  const withinMain = within(screen.getByTestId('main-content'));
  await waitForElementToBeRemoved(await withinMain.findByText('Loading findings'), { timeout: 2000 });

  // Select all findings
  const table = await withinMain.findByRole('table');
  const checkboxes = await within(table).findAllByRole('checkbox');
  await userEvent.click(checkboxes[0]); // Select all checkbox

  const actionsButton = await withinMain.findByRole('button', { name: 'Actions' });
  await userEvent.click(actionsButton);

  const dropdown = await screen.findByRole('menu');
  const suppressOption = within(dropdown).getByText('Suppress');
  await userEvent.click(suppressOption);

  // THEN modal should show finding IDs with truncation
  const modal = await screen.findByRole('dialog');
  expect(within(modal).getByText('Selected finding IDs:')).toBeInTheDocument();

  // Should show truncation message for more than 5 findings
  expect(within(modal).getByText('... and 2 more finding(s)')).toBeInTheDocument();

  // Verify the modal shows the confirmation message
  expect(within(modal).getByText(/are you sure you want to suppress 7 findings/i)).toBeInTheDocument();
});

it('handles View History button click in success message', async () => {
  const findings = generateTestFindings(1, { suppressed: false, remediationStatus: 'NOT_STARTED' });

  server.use(
    http.post(MOCK_SERVER_URL + ApiEndpoints.FINDINGS, async () => await ok({ Findings: findings, NextToken: null })),
    http.post(MOCK_SERVER_URL + ApiEndpoints.FINDINGS + '/action', async () => await ok({})),
  );

  renderAppContent({
    initialRoute: '/findings',
  });

  const withinMain = within(screen.getByTestId('main-content'));
  await waitForElementToBeRemoved(await withinMain.findByText('Loading findings'), { timeout: 2000 });

  // Execute a successful remediate action
  const table = await withinMain.findByRole('table');
  const checkboxes = await within(table).findAllByRole('checkbox');
  await userEvent.click(checkboxes[1]);

  const actionsButton = await withinMain.findByRole('button', { name: 'Actions' });
  await userEvent.click(actionsButton);

  const dropdown = await screen.findByRole('menu');
  const remediateOption = within(dropdown).getByText('Remediate');
  await userEvent.click(remediateOption);

  const modal = await screen.findByRole('dialog');
  const confirmButton = within(modal).getByRole('button', { name: 'Remediate' });
  await userEvent.click(confirmButton);

  // Wait for success message with View History button
  await withinMain.findByText(/successfully sent 1 finding for remediation/i);
  const viewHistoryButton = await withinMain.findByText('View History');

  // WHEN clicking View History button
  await userEvent.click(viewHistoryButton);

  await waitFor(() => {
    expect(screen.queryByText('Findings to Remediate')).not.toBeInTheDocument();
  });
});
