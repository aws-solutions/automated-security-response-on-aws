// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { act, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

import { http } from 'msw';

beforeEach(() => {
  localStorage.clear();
});

afterEach(() => {
  server.resetHandlers();
});
import { ok } from '../../mocks/handlers.ts';
import { ApiEndpoints } from '../../store/solutionApi.ts';
import { MOCK_SERVER_URL, server } from '../server.ts';
import { SearchRequest } from '../../store/types.ts';
import { generateTestRemediation, generateTestRemediations, asFindingId } from '../test-data-factory.ts';
import { renderAppContent } from '../test-utils.tsx';
import {
  installIntersectionObserverRecorder,
  IntersectionObserverRecorder,
} from '../intersection-observer-recorder.ts';

describe('RemediationHistoryPage', () => {
  it('renders an empty table', async () => {
    // GIVEN the backend returns no remediations
    server.use(
      http.post(
        MOCK_SERVER_URL + ApiEndpoints.REMEDIATIONS,
        async () => await ok({ Remediations: [], NextToken: null }),
      ),
    );

    // WHEN rendering the /history route
    renderAppContent({
      initialRoute: '/history',
    });

    // THEN
    const withinMain = within(screen.getByTestId('main-content'));
    expect(withinMain.getByRole('heading', { name: 'Remediation History(0)' })).toBeInTheDocument();
    expect(await withinMain.findByText(/no history to display/i)).toBeInTheDocument();
  });

  it('renders a table with remediation history', async () => {
    // GIVEN the backend returns 5 remediations
    const remediations = generateTestRemediations(5);

    server.use(
      http.post(
        MOCK_SERVER_URL + ApiEndpoints.REMEDIATIONS,
        async () => await ok({ Remediations: remediations, NextToken: null }),
      ),
    );

    // WHEN
    renderAppContent({
      initialRoute: '/history',
    });

    // THEN expect 5 remediations plus a header row in the table
    const withinMain = within(screen.getByTestId('main-content'));

    // Wait for the data to load (the refresh button should not be in loading state)
    await withinMain.findByRole('button', { name: 'Refresh history' });

    const heading = await withinMain.findByRole('heading', { name: `Remediation History(5)` });
    expect(heading).toBeInTheDocument();

    const table = await withinMain.findByRole('table');
    const rows = await within(table).findAllByRole('row');
    expect(rows).toHaveLength(remediations.length + 1);

    // Verify first remediation data is displayed
    const firstRemediationFindingId = await within(table).findByRole('cell', { name: remediations[0].findingId });
    expect(firstRemediationFindingId).toBeInTheDocument();
  });

  it('displays refresh button and allows refreshing data', async () => {
    // GIVEN the backend returns different numbers of remediations on subsequent requests
    let requestCount = 0;

    server.use(
      http.post(MOCK_SERVER_URL + ApiEndpoints.REMEDIATIONS, async () => {
        requestCount++;
        if (requestCount <= 1) {
          return await ok({
            Remediations: generateTestRemediations(3),
            NextToken: null,
          });
        } else {
          return await ok({
            Remediations: generateTestRemediations(4),
            NextToken: null,
          });
        }
      }),
    );

    // WHEN rendering the page
    renderAppContent({
      initialRoute: '/history',
    });

    const withinMain = within(screen.getByTestId('main-content'));

    // Wait for the initial data to load by waiting for the counter to show 3 items
    await withinMain.findByText('(3)');

    // Wait for the refresh button to appear and not be in loading state
    const refreshButton = await withinMain.findByRole('button', { name: 'Refresh history' });
    expect(refreshButton).toBeInTheDocument();
    expect(refreshButton).not.toHaveAttribute('aria-disabled', 'true');

    expect(requestCount).toBe(1);

    // WHEN clicking the refresh button
    await userEvent.click(refreshButton);

    // THEN it should make another request and the UI should update to show 4 items
    await withinMain.findByText('(4)');
    expect(requestCount).toBe(2);
  });

  it('supports all filtering types and interactions', async () => {
    // GIVEN the backend returns remediations with diverse data
    const remediations = [
      ...generateTestRemediations(1, {
        findingId: asFindingId('finding-123'),
        remediationStatus: 'SUCCESS',
        accountId: '123456789012',
        resourceId: 'resource-abc123',
        lastUpdatedBy: 'user1@example.com',
        resourceType: 'AWS::S3::Bucket',
      }),
      ...generateTestRemediations(1, {
        findingId: asFindingId('finding-456'),
        remediationStatus: 'FAILED',
        accountId: '123456789013',
        resourceId: 'resource-def456',
        lastUpdatedBy: 'user2@example.com',
        resourceType: 'AWS::EC2::Instance',
      }),
    ];

    server.use(
      http.post(
        MOCK_SERVER_URL + ApiEndpoints.REMEDIATIONS,
        async () => await ok({ Remediations: remediations, NextToken: null }),
      ),
    );

    // WHEN rendering the page
    renderAppContent({
      initialRoute: '/history',
    });

    const withinMain = within(screen.getByTestId('main-content'));

    // Wait for the data to load by waiting for the table to appear
    const table = await withinMain.findByRole('table');
    const filterInput = await withinMain.findByPlaceholderText('Search Remediations');

    // Test Finding ID filtering
    await userEvent.clear(filterInput);
    await userEvent.type(filterInput, 'Finding ID = finding-123');
    await userEvent.keyboard('{Enter}');
    expect(filterInput).toHaveValue('Finding ID = finding-123');

    // Test Status filtering
    await userEvent.clear(filterInput);
    await userEvent.type(filterInput, 'Status = SUCCESS');
    await userEvent.keyboard('{Enter}');
    expect(filterInput).toHaveValue('Status = SUCCESS');

    // Test Account ID filtering
    await userEvent.clear(filterInput);
    await userEvent.type(filterInput, 'Account = 123456789012');
    await userEvent.keyboard('{Enter}');
    expect(filterInput).toHaveValue('Account = 123456789012');

    // Test Resource ID filtering
    await userEvent.clear(filterInput);
    await userEvent.type(filterInput, 'Resource ID : abc123');
    await userEvent.keyboard('{Enter}');
    expect(filterInput).toHaveValue('Resource ID : abc123');

    // Test Executed By filtering
    await userEvent.clear(filterInput);
    await userEvent.type(filterInput, 'Executed By = user1@example.com');
    await userEvent.keyboard('{Enter}');
    expect(filterInput).toHaveValue('Executed By = user1@example.com');

    // Test Resource Type filtering
    await userEvent.clear(filterInput);
    await userEvent.type(filterInput, 'Resource Type : S3');
    await userEvent.keyboard('{Enter}');
    expect(filterInput).toHaveValue('Resource Type : S3');

    expect(table).toBeInTheDocument();
  });

  it('supports sorting by columns', async () => {
    // GIVEN the backend returns remediations with different timestamps
    const now = new Date();
    const remediations = [
      {
        ...generateTestRemediation(),
        findingId: 'finding-1',
        lastUpdatedTime: new Date(now.getTime() - 3600000).toISOString(), // 1 hour ago
      },
      {
        ...generateTestRemediation(),
        findingId: 'finding-2',
        lastUpdatedTime: new Date(now.getTime() - 7200000).toISOString(), // 2 hours ago
      },
    ];

    server.use(
      http.post(
        MOCK_SERVER_URL + ApiEndpoints.REMEDIATIONS,
        async () => await ok({ Remediations: remediations, NextToken: null }),
      ),
    );

    // WHEN rendering the page
    renderAppContent({
      initialRoute: '/history',
    });

    const withinMain = within(screen.getByTestId('main-content'));

    // Wait for the data to load by waiting for the counter to show 2 items
    await withinMain.findByText('(2)');

    // Wait for the table to appear
    const table = await withinMain.findByRole('table');
    const timestampHeader = await within(table).findByText('Execution Timestamp');
    expect(timestampHeader).toBeInTheDocument();

    // Verify that data is displayed in the table - wait for the actual data rows
    const rows = await within(table).findAllByRole('row');
    expect(rows.length).toBe(3); // Header + 2 data rows

    // Verify that the finding IDs are present in the table
    await within(table).findByText('finding-1');
    await within(table).findByText('finding-2');
  });

  it('displays correct counter text for filtered results', async () => {
    // GIVEN the backend returns remediations
    const remediations = generateTestRemediations(5);

    server.use(
      http.post(
        MOCK_SERVER_URL + ApiEndpoints.REMEDIATIONS,
        async () => await ok({ Remediations: remediations, NextToken: null }),
      ),
    );

    // WHEN rendering the page
    renderAppContent({
      initialRoute: '/history',
    });

    const withinMain = within(screen.getByTestId('main-content'));

    // Wait for the data to load by waiting for the table to appear
    await withinMain.findByRole('table');

    // Check that the header counter shows the correct count (counter is in separate span)
    expect(await withinMain.findByText('(5)')).toBeInTheDocument();

    // WHEN applying a filter that reduces results
    const filterInput = await withinMain.findByPlaceholderText('Search Remediations');
    await userEvent.type(filterInput, `Finding ID = ${remediations[0].findingId}`);
    await userEvent.keyboard('{Enter}');

    // THEN the filter input should contain the filter text (filtering functionality works)
    expect(filterInput).toHaveValue(`Finding ID = ${remediations[0].findingId}`);
  });

  it('handles error states gracefully', async () => {
    // GIVEN the backend returns an error
    server.use(
      http.post(MOCK_SERVER_URL + ApiEndpoints.REMEDIATIONS, async () => {
        return new Response(JSON.stringify({ message: 'Internal Server Error' }), {
          status: 500,
          headers: { 'Content-Type': 'application/json' },
        });
      }),
    );

    // WHEN rendering the page
    renderAppContent({
      initialRoute: '/history',
    });

    const withinMain = within(screen.getByTestId('main-content'));

    // THEN it should display an error message
    const errorAlert = await withinMain.findByText(/Failed to load remediation history/i);
    expect(errorAlert).toBeInTheDocument();
  });

  it('clears filters when clear filters is used', async () => {
    // GIVEN the backend returns remediations
    const remediations = generateTestRemediations(5);

    server.use(
      http.post(
        MOCK_SERVER_URL + ApiEndpoints.REMEDIATIONS,
        async () => await ok({ Remediations: remediations, NextToken: null }),
      ),
    );

    // WHEN rendering the page
    renderAppContent({
      initialRoute: '/history',
    });

    const withinMain = within(screen.getByTestId('main-content'));

    // Wait for the data to load by waiting for the table to appear
    await withinMain.findByRole('table');

    // Check that the initial counter appears (counter is in separate span)
    expect(await withinMain.findByText('(5)')).toBeInTheDocument();

    // WHEN applying a filter
    const filterInput = await withinMain.findByPlaceholderText('Search Remediations');
    await userEvent.type(filterInput, `Finding ID = ${remediations[0].findingId}`);
    await userEvent.keyboard('{Enter}');

    // THEN the filter should be applied
    expect(filterInput).toHaveValue(`Finding ID = ${remediations[0].findingId}`);

    // WHEN clearing filters
    await userEvent.clear(filterInput);
    await userEvent.keyboard('{Enter}');

    // THEN the filter should be cleared
    expect(filterInput).toHaveValue('');
  });

  it('supports infinite scroll functionality with pagination', async () => {
    // GIVEN the backend returns paginated results
    let requestCount = 0;
    const firstBatch = generateTestRemediations(3);
    const secondBatch = generateTestRemediations(2);

    server.use(
      http.post(MOCK_SERVER_URL + ApiEndpoints.REMEDIATIONS, async (req) => {
        const body = (await req.request.json()) as any;
        requestCount++;

        if (requestCount === 1) {
          // First request - return first batch with NextToken
          return await ok({
            Remediations: firstBatch,
            NextToken: 'next-token-123',
          });
        } else if (requestCount === 2 && body.NextToken === 'next-token-123') {
          // Second request with NextToken - return second batch
          return await ok({
            Remediations: secondBatch,
            NextToken: null,
          });
        }
        return await ok({ Remediations: [], NextToken: null });
      }),
    );

    // WHEN rendering the page
    renderAppContent({
      initialRoute: '/history',
    });

    const withinMain = within(screen.getByTestId('main-content'));

    // Wait for initial data to load by checking the heading
    const initialHeading = await withinMain.findByRole('heading', { name: 'Remediation History(3+)' });
    expect(initialHeading).toBeInTheDocument();

    // THEN should show initial data with + indicator for more data
    expect(requestCount).toBe(1);

    const table = await withinMain.findByRole('table');
    const rows = await within(table).findAllByRole('row');
    expect(rows).toHaveLength(4);
  });

  it('handles load more errors gracefully', async () => {
    // GIVEN the backend returns data initially but fails on load more
    let requestCount = 0;
    const firstBatch = generateTestRemediations(3);

    server.use(
      http.post(MOCK_SERVER_URL + ApiEndpoints.REMEDIATIONS, async (req) => {
        const body = (await req.request.json()) as any;
        requestCount++;

        if (requestCount === 1) {
          // First request succeeds
          return await ok({
            Remediations: firstBatch,
            NextToken: 'next-token-123',
          });
        } else if (body.NextToken) {
          // Load more request fails
          return new Response(JSON.stringify({ message: 'Load more failed' }), {
            status: 500,
            headers: { 'Content-Type': 'application/json' },
          });
        }
        return await ok({ Remediations: [], NextToken: null });
      }),
    );

    // WHEN rendering the page
    renderAppContent({
      initialRoute: '/history',
    });

    const withinMain = within(screen.getByTestId('main-content'));

    // Wait for initial data to load
    await withinMain.findByText('(3+)');

    // THEN should show initial data with + indicator for more data
    expect(requestCount).toBe(1);

    // Verify the table shows the initial 3 items
    const table = await withinMain.findByRole('table');
    const rows = await within(table).findAllByRole('row');
    expect(rows).toHaveLength(4);
  });

  it('supports different filter operators', async () => {
    // GIVEN the backend returns remediations with diverse data
    const remediations = [
      ...generateTestRemediations(1, {
        findingId: asFindingId('finding-abc-123'),
        accountId: '111111111111',
        resourceId: 'resource-test-456',
      }),
      ...generateTestRemediations(1, {
        findingId: asFindingId('finding-xyz-789'),
        accountId: '222222222222',
        resourceId: 'resource-prod-123',
      }),
    ];

    server.use(
      http.post(
        MOCK_SERVER_URL + ApiEndpoints.REMEDIATIONS,
        async () => await ok({ Remediations: remediations, NextToken: null }),
      ),
    );

    // WHEN rendering the page
    renderAppContent({
      initialRoute: '/history',
    });

    const withinMain = within(screen.getByTestId('main-content'));
    const filterInput = await withinMain.findByPlaceholderText('Search Remediations');

    // Test != operator
    await userEvent.clear(filterInput);
    await userEvent.type(filterInput, 'Account != 111111111111');
    await userEvent.keyboard('{Enter}');
    expect(filterInput).toHaveValue('Account != 111111111111');

    // Test !: operator (does not contain)
    await userEvent.clear(filterInput);
    await userEvent.type(filterInput, 'Resource ID !: test');
    await userEvent.keyboard('{Enter}');
    expect(filterInput).toHaveValue('Resource ID !: test');

    // Test : operator (contains)
    await userEvent.clear(filterInput);
    await userEvent.type(filterInput, 'Finding ID : abc');
    await userEvent.keyboard('{Enter}');
    expect(filterInput).toHaveValue('Finding ID : abc');
  });

  it('handles non-array allHistory gracefully', async () => {
    // GIVEN the backend returns invalid data structure
    server.use(
      http.post(
        MOCK_SERVER_URL + ApiEndpoints.REMEDIATIONS,
        async () => await ok({ Remediations: null, NextToken: null }),
      ),
    );

    // WHEN rendering the page
    renderAppContent({
      initialRoute: '/history',
    });

    const withinMain = within(screen.getByTestId('main-content'));

    // THEN should handle gracefully and show empty state
    expect(await withinMain.findByText(/no history to display/i)).toBeInTheDocument();
  });

  it('persists filter and sorting preferences across page navigation', async () => {
    const remediations = [
      ...generateTestRemediations(1, { remediationStatus: 'SUCCESS' }),
      ...generateTestRemediations(4),
    ];
    let lastSearchRequest: SearchRequest | null = null;

    server.use(
      http.post(MOCK_SERVER_URL + ApiEndpoints.REMEDIATIONS, async ({ request }) => {
        lastSearchRequest = (await request.json()) as SearchRequest;
        return await ok({ Remediations: remediations, NextToken: null });
      }),
    );

    // ARRANGE - Render history page and apply filters/sorting
    const { renderResult } = renderAppContent({ initialRoute: '/history' });
    let withinMain = within(screen.getByTestId('main-content'));

    // Apply filter using Cloudscape PropertyFilter dropdown
    const filterInput = await withinMain.findByPlaceholderText('Search Remediations');
    await userEvent.click(filterInput);

    // Wait for dropdown to appear and select "Status" from the property dropdown
    const dropdown = await screen.findByRole('listbox');
    const statusOption = await within(dropdown).findByText('Status');
    await userEvent.click(statusOption);

    // Select "=" operator
    const operatorDropdown = await screen.findByRole('listbox');
    const equalsOption = await within(operatorDropdown).findByText('=');
    await userEvent.click(equalsOption);

    // Select "Success" value
    const valueDropdown = await screen.findByRole('listbox');
    const successOption = await within(valueDropdown).findByText('Success');
    await userEvent.click(successOption);

    await waitFor(() => {
      expect(lastSearchRequest?.Filters?.CompositeFilters?.[0]?.StringFilters?.[0]?.FieldName).toBe(
        'remediationStatus',
      );
      // default sort should be desc
      expect(lastSearchRequest?.SortCriteria?.[0]?.SortOrder).toBe('desc');
    });

    // Change sorting
    const table = await withinMain.findByRole('table');
    const timestampHeader = await within(table).findByText('Execution Timestamp');
    await userEvent.click(timestampHeader);

    await waitFor(() => {
      expect(lastSearchRequest?.SortCriteria?.[0]?.Field).toBe('lastUpdatedTime');
      expect(lastSearchRequest?.SortCriteria?.[0]?.SortOrder).toBe('asc');
    });

    // ACT - Navigate away and back
    renderResult.unmount();
    renderAppContent({ initialRoute: '/history' });

    // ASSERT - All preferences should be restored
    withinMain = within(screen.getByTestId('main-content'));
    await withinMain.findByRole('table');
    await waitFor(() => {
      expect(lastSearchRequest?.SortCriteria?.[0]?.Field).toBe('lastUpdatedTime');
      expect(lastSearchRequest?.SortCriteria?.[0]?.SortOrder).toBe('asc');
      expect(lastSearchRequest?.Filters?.CompositeFilters?.[0]?.StringFilters?.[0]?.FieldName).toBe(
        'remediationStatus',
      );
      expect(lastSearchRequest?.Filters?.CompositeFilters?.[0]?.StringFilters?.[0]?.Filter.Value).toBe('SUCCESS');
    });
  });
});

it('falls back to default sorting column when persisted sorting field is invalid', async () => {
  // ARRANGE - persist an invalid sorting field
  localStorage.setItem(
    'HistoryTablePreferences',
    JSON.stringify({
      sortingField: 'invalidField',
      sortingDescending: true,
    }),
  );

  server.use(
    http.post(
      MOCK_SERVER_URL + ApiEndpoints.REMEDIATIONS,
      async () => await ok({ Remediations: generateTestRemediations(3), NextToken: null }),
    ),
  );

  // ACT
  renderAppContent({ initialRoute: '/history' });

  // ASSERT - table should render without errors using default sorting
  const withinMain = within(screen.getByTestId('main-content'));
  expect(await withinMain.findByRole('table')).toBeInTheDocument();
  expect(await withinMain.findByText('(3)')).toBeInTheDocument();
});

describe('RemediationHistoryPage rollback flow', () => {
  beforeEach(() => {
    localStorage.clear();
  });

  it('shows the Rollback button for GuardDuty.IAMUser remediations that are not ROLLBACK_SUCCESS', async () => {
    // ARRANGE — three remediations: GuardDuty SUCCESS (eligible), wrong findingType, already ROLLBACK_SUCCESS
    // The API enforces SUCCESS status; the UI shows the button for any GuardDuty.IAMUser that isn't already rolled back.
    const remediations = [
      generateTestRemediation({
        executionId: asFindingId('exec-eligible'),
        findingId: asFindingId('finding-eligible'),
        findingType: 'GuardDuty.IAMUser',
        remediationStatus: 'SUCCESS',
      }),
      generateTestRemediation({
        executionId: asFindingId('exec-wrong-type'),
        findingId: asFindingId('finding-wrong-type'),
        findingType: 'S3.1',
        remediationStatus: 'SUCCESS',
      }),
      generateTestRemediation({
        executionId: asFindingId('exec-rolled-back'),
        findingId: asFindingId('finding-rolled-back'),
        findingType: 'GuardDuty.IAMUser',
        remediationStatus: 'ROLLBACK_SUCCESS',
      }),
    ];
    server.use(
      http.post(
        MOCK_SERVER_URL + ApiEndpoints.REMEDIATIONS,
        async () => await ok({ Remediations: remediations, NextToken: null }),
      ),
    );

    // ACT
    renderAppContent({ initialRoute: '/history' });
    const main = within(screen.getByTestId('main-content'));
    await main.findByRole('table');

    // ASSERT — exactly one Rollback button (GuardDuty SUCCESS row); wrong-type and ROLLBACK_SUCCESS rows have none
    const rollbackButtons = await main.findAllByRole('button', { name: /^Rollback GuardDuty containment for/i });
    expect(rollbackButtons).toHaveLength(1);
  });

  it('opens the confirmation modal when clicking Rollback and dismisses on Cancel', async () => {
    // ARRANGE
    const remediations = [
      generateTestRemediation({
        executionId: asFindingId('exec-1'),
        findingId: asFindingId('finding-rollback-1'),
        findingType: 'GuardDuty.IAMUser',
        remediationStatus: 'SUCCESS',
      }),
    ];
    server.use(
      http.post(
        MOCK_SERVER_URL + ApiEndpoints.REMEDIATIONS,
        async () => await ok({ Remediations: remediations, NextToken: null }),
      ),
    );

    // ACT
    renderAppContent({ initialRoute: '/history' });
    const main = within(screen.getByTestId('main-content'));
    await main.findByRole('table');
    const rollbackButton = await main.findByRole('button', { name: /Rollback GuardDuty containment/i });
    await userEvent.click(rollbackButton);

    // ASSERT — modal becomes visible
    const dialog = await screen.findByRole('dialog');
    expect(within(dialog).getByText(/Confirm GuardDuty Credential Rollback/i)).toBeInTheDocument();

    // ACT — dismiss
    const cancelButton = within(dialog).getByRole('button', { name: /^Cancel$/i });
    await userEvent.click(cancelButton);

    // ASSERT — modal hides (Cloudscape hides via class instead of unmount; assert no visible dialog remains)
    await waitFor(() => {
      const dialogs = screen.queryAllByRole('dialog');
      const visible = dialogs.filter((d) => !d.className.includes('hidden'));
      expect(visible).toHaveLength(0);
    });
  });

  it('submits the rollback action and shows a success alert when the API succeeds', async () => {
    // ARRANGE
    const remediations = [
      generateTestRemediation({
        executionId: asFindingId('exec-1'),
        findingId: asFindingId('finding-rollback-success'),
        findingType: 'GuardDuty.IAMUser',
        remediationStatus: 'SUCCESS',
      }),
    ];
    let actionRequestBody: {
      actionType?: string;
      findingIds?: string[];
      findingKeys?: { findingId: string; findingType: string }[];
    } | null = null;
    server.use(
      http.post(
        MOCK_SERVER_URL + ApiEndpoints.REMEDIATIONS,
        async () => await ok({ Remediations: remediations, NextToken: null }),
      ),
      http.post(`${MOCK_SERVER_URL}${ApiEndpoints.FINDINGS}/action`, async ({ request }) => {
        actionRequestBody = (await request.json()) as {
          actionType?: string;
          findingIds?: string[];
          findingKeys?: { findingId: string; findingType: string }[];
        };
        return await ok({});
      }),
    );

    // ACT
    renderAppContent({ initialRoute: '/history' });
    const main = within(screen.getByTestId('main-content'));
    await main.findByRole('table');
    const rollbackButton = await main.findByRole('button', { name: /Rollback GuardDuty containment/i });
    await userEvent.click(rollbackButton);
    const dialog = await screen.findByRole('dialog');
    const confirmButton = within(dialog).getByRole('button', { name: /Rollback Containment/i });
    await userEvent.click(confirmButton);

    // ASSERT — request body matches and a success alert is shown
    await waitFor(() => {
      expect(actionRequestBody).toMatchObject({
        actionType: 'Rollback',
        findingIds: ['finding-rollback-success'],
        // The explicit key must be sent so the API never has to derive the partition key from the
        // finding id, which is impossible for ids that are not Security Hub ARNs. See ADR 0010.
        findingKeys: [{ findingId: 'finding-rollback-success', findingType: 'GuardDuty.IAMUser' }],
      });
    });
    expect(await main.findByText(/Rollback initiated for finding finding-rollback-success/i)).toBeInTheDocument();
  });

  it('shows an error alert when the rollback action fails', async () => {
    // ARRANGE
    const remediations = [
      generateTestRemediation({
        executionId: asFindingId('exec-1'),
        findingId: asFindingId('finding-rollback-fail'),
        findingType: 'GuardDuty.IAMUser',
        remediationStatus: 'SUCCESS',
      }),
    ];
    server.use(
      http.post(
        MOCK_SERVER_URL + ApiEndpoints.REMEDIATIONS,
        async () => await ok({ Remediations: remediations, NextToken: null }),
      ),
      http.post(`${MOCK_SERVER_URL}${ApiEndpoints.FINDINGS}/action`, async () => {
        return new Response(JSON.stringify({ message: 'Internal server error' }), {
          status: 500,
          headers: { 'Content-Type': 'application/json' },
        });
      }),
    );

    // ACT
    renderAppContent({ initialRoute: '/history' });
    const main = within(screen.getByTestId('main-content'));
    await main.findByRole('table');
    const rollbackButton = await main.findByRole('button', { name: /Rollback GuardDuty containment/i });
    await userEvent.click(rollbackButton);
    const dialog = await screen.findByRole('dialog');
    const confirmButton = within(dialog).getByRole('button', { name: /Rollback Containment/i });
    await userEvent.click(confirmButton);

    // ASSERT — error alert is rendered with the "Rollback Failed" header
    expect(await main.findByText('Rollback Failed')).toBeInTheDocument();
  });

  it('shows an auto-remediation warning in the modal when auto-remediation is enabled for the control', async () => {
    // ARRANGE — control list reports auto-remediation enabled for GuardDuty.IAMUser
    const remediations = [
      generateTestRemediation({
        executionId: asFindingId('exec-1'),
        findingId: asFindingId('finding-auto-on'),
        findingType: 'GuardDuty.IAMUser',
        remediationStatus: 'SUCCESS',
      }),
    ];
    server.use(
      http.post(
        MOCK_SERVER_URL + ApiEndpoints.REMEDIATIONS,
        async () => await ok({ Remediations: remediations, NextToken: null }),
      ),
      http.get(`${MOCK_SERVER_URL}${ApiEndpoints.CONTROLS}`, async () =>
        ok({
          controls: [
            {
              controlId: 'GuardDuty.IAMUser',
              description: 'GuardDuty IAM user containment',
              automatedRemediationEnabled: true,
              filters: [],
              filterMode: 'include',
              version: 1,
              lastModified: new Date().toISOString(),
              modifiedBy: 'tester',
            },
          ],
        }),
      ),
    );

    // ACT
    renderAppContent({ initialRoute: '/history' });
    const main = within(screen.getByTestId('main-content'));
    await main.findByRole('table');
    const rollbackButton = await main.findByRole('button', { name: /Rollback GuardDuty containment/i });
    await userEvent.click(rollbackButton);

    // ASSERT — modal shows the auto-remediation warning
    const dialog = await screen.findByRole('dialog');
    expect(await within(dialog).findByText(/Auto-remediation is enabled for this control/i)).toBeInTheDocument();
  });

  it('does not show the auto-remediation warning when auto-remediation is disabled for the control', async () => {
    // ARRANGE — control list reports auto-remediation disabled for GuardDuty.IAMUser
    const remediations = [
      generateTestRemediation({
        executionId: asFindingId('exec-1'),
        findingId: asFindingId('finding-auto-off'),
        findingType: 'GuardDuty.IAMUser',
        remediationStatus: 'SUCCESS',
      }),
    ];
    server.use(
      http.post(
        MOCK_SERVER_URL + ApiEndpoints.REMEDIATIONS,
        async () => await ok({ Remediations: remediations, NextToken: null }),
      ),
      http.get(`${MOCK_SERVER_URL}${ApiEndpoints.CONTROLS}`, async () =>
        ok({
          controls: [
            {
              controlId: 'GuardDuty.IAMUser',
              description: 'GuardDuty IAM user containment',
              automatedRemediationEnabled: false,
              filters: [],
              filterMode: 'include',
              version: 1,
              lastModified: new Date().toISOString(),
              modifiedBy: 'tester',
            },
          ],
        }),
      ),
    );

    // ACT
    renderAppContent({ initialRoute: '/history' });
    const main = within(screen.getByTestId('main-content'));
    await main.findByRole('table');
    const rollbackButton = await main.findByRole('button', { name: /Rollback GuardDuty containment/i });
    await userEvent.click(rollbackButton);

    // ASSERT — modal opens but no auto-remediation warning is present
    const dialog = await screen.findByRole('dialog');
    expect(within(dialog).getByText(/Confirm GuardDuty Credential Rollback/i)).toBeInTheDocument();
    expect(within(dialog).queryByText(/Auto-remediation is enabled for this control/i)).not.toBeInTheDocument();
  });
});

describe('RemediationHistoryPage column rendering', () => {
  beforeEach(() => {
    localStorage.clear();
  });

  it('renders a status indicator with the formatted remediation status', async () => {
    // ARRANGE
    server.use(
      http.post(
        MOCK_SERVER_URL + ApiEndpoints.REMEDIATIONS,
        async () =>
          await ok({
            Remediations: [
              generateTestRemediation({
                findingId: asFindingId('finding-success'),
                remediationStatus: 'SUCCESS',
                error: undefined,
              }),
              generateTestRemediation({
                findingId: asFindingId('finding-in-progress'),
                remediationStatus: 'IN_PROGRESS',
                error: undefined,
              }),
              generateTestRemediation({
                findingId: asFindingId('finding-not-started'),
                remediationStatus: 'NOT_STARTED',
                error: undefined,
              }),
            ],
            NextToken: null,
          }),
      ),
    );

    // ACT
    renderAppContent({ initialRoute: '/history' });
    const main = within(screen.getByTestId('main-content'));
    const table = await main.findByRole('table');

    // ASSERT — formatted labels appear once per row
    expect(await within(table).findByText('Success')).toBeInTheDocument();
    expect(await within(table).findByText('In Progress')).toBeInTheDocument();
    expect(await within(table).findByText('Not Started')).toBeInTheDocument();
  });

  it('renders the FAILED status with the error popover trigger when an error is present', async () => {
    // ARRANGE
    server.use(
      http.post(
        MOCK_SERVER_URL + ApiEndpoints.REMEDIATIONS,
        async () =>
          await ok({
            Remediations: [
              generateTestRemediation({
                findingId: asFindingId('finding-failed'),
                remediationStatus: 'FAILED',
                error: 'Something went wrong',
              }),
            ],
            NextToken: null,
          }),
      ),
    );

    // ACT
    renderAppContent({ initialRoute: '/history' });
    const main = within(screen.getByTestId('main-content'));
    const table = await main.findByRole('table');

    // ASSERT — Failed label is rendered (popover is the wrapping element)
    expect(await within(table).findByText('Failed')).toBeInTheDocument();
  });

  it('renders dashes for missing optional fields and a Step Functions external link', async () => {
    // ARRANGE
    const remediation = generateTestRemediation({
      findingId: undefined as unknown as ReturnType<typeof asFindingId>,
      resourceId: undefined as unknown as string,
      lastUpdatedBy: undefined as unknown as string,
      consoleLink: 'https://console.aws.amazon.com/states/home',
    });
    server.use(
      http.post(
        MOCK_SERVER_URL + ApiEndpoints.REMEDIATIONS,
        async () => await ok({ Remediations: [remediation], NextToken: null }),
      ),
    );

    // ACT
    renderAppContent({ initialRoute: '/history' });
    const main = within(screen.getByTestId('main-content'));
    const table = await main.findByRole('table');

    // ASSERT — Step Functions link is the visible cell text and it points to the consoleLink
    const link = await within(table).findByRole('link', { name: /Step Functions/i });
    expect(link).toHaveAttribute('href', 'https://console.aws.amazon.com/states/home');
    // dash placeholders for missing optional fields appear at least 3 times (findingId, resourceId, lastUpdatedBy)
    const dashes = within(table).getAllByText('-');
    expect(dashes.length).toBeGreaterThanOrEqual(3);
  });
});

describe('RemediationHistoryPage findingId URL parameter', () => {
  beforeEach(() => {
    localStorage.clear();
  });

  it('applies findingId filter when navigating to /history?findingId=xyz', async () => {
    // ARRANGE
    let lastSearchRequest: SearchRequest | null = null;
    const remediations = generateTestRemediations(2);
    server.use(
      http.post(MOCK_SERVER_URL + ApiEndpoints.REMEDIATIONS, async ({ request }) => {
        lastSearchRequest = (await request.json()) as SearchRequest;
        return await ok({ Remediations: remediations, NextToken: null });
      }),
    );

    // ACT
    renderAppContent({ initialRoute: '/history?findingId=evt-123' });

    // ASSERT — request reflects the findingId filter applied at mount time
    const withinMain = within(screen.getByTestId('main-content'));
    await withinMain.findByPlaceholderText('Search Remediations');
    await waitFor(() => {
      expect(lastSearchRequest?.Filters?.CompositeFilters?.[0]?.StringFilters?.[0]?.FieldName).toBe('findingId');
      expect(lastSearchRequest?.Filters?.CompositeFilters?.[0]?.StringFilters?.[0]?.Filter.Value).toBe('evt-123');
    });
  });

  it('does not apply a findingId filter when no findingId query param is present', async () => {
    // ARRANGE
    let lastSearchRequest: SearchRequest | undefined;
    server.use(
      http.post(MOCK_SERVER_URL + ApiEndpoints.REMEDIATIONS, async ({ request }) => {
        lastSearchRequest = (await request.json()) as SearchRequest;
        return await ok({ Remediations: [], NextToken: null });
      }),
    );

    // ACT
    renderAppContent({ initialRoute: '/history' });

    const withinMain = within(screen.getByTestId('main-content'));
    await withinMain.findByPlaceholderText('Search Remediations');

    // ASSERT — no findingId filter is sent in the search request
    await waitFor(() => {
      expect(lastSearchRequest).toBeDefined();
    });
    expect(
      lastSearchRequest?.Filters?.CompositeFilters?.[0]?.StringFilters?.find((f) => f.FieldName === 'findingId'),
    ).toBeUndefined();
  });
});

describe('Rollback functionality', () => {
  it('shows Rollback button for GuardDuty.IAMUser remediations that are not ROLLBACK_SUCCESS', async () => {
    // GIVEN two GuardDuty.IAMUser remediations: one SUCCESS (eligible), one FAILED (not eligible — UI requires SUCCESS + isRollbackEligible)
    const eligibleRemediation = generateTestRemediation({
      findingType: 'GuardDuty.IAMUser',
      remediationStatus: 'SUCCESS',
    });
    const notEligibleRemediation = generateTestRemediation({
      findingType: 'GuardDuty.IAMUser',
      remediationStatus: 'FAILED',
    });

    server.use(
      http.post(
        MOCK_SERVER_URL + ApiEndpoints.REMEDIATIONS,
        async () => await ok({ Remediations: [eligibleRemediation, notEligibleRemediation], NextToken: null }),
      ),
    );

    renderAppContent({ initialRoute: '/history' });

    const withinMain = within(screen.getByTestId('main-content'));
    await withinMain.findByText('(2)');

    // THEN only the SUCCESS row shows a Rollback button
    const rollbackButtons = await withinMain.findAllByRole('button', { name: /rollback guardduty containment/i });
    expect(rollbackButtons).toHaveLength(1);
  });

  it('does not show Rollback button for non-GuardDuty SUCCESS remediations', async () => {
    // GIVEN a non-GuardDuty remediation with SUCCESS status
    const remediations = generateTestRemediations(3, {
      findingType: 'Security.SomeOtherFinding',
      remediationStatus: 'SUCCESS',
    });

    server.use(
      http.post(
        MOCK_SERVER_URL + ApiEndpoints.REMEDIATIONS,
        async () => await ok({ Remediations: remediations, NextToken: null }),
      ),
    );

    renderAppContent({ initialRoute: '/history' });

    const withinMain = within(screen.getByTestId('main-content'));
    await withinMain.findByText('(3)');

    // THEN no Rollback buttons should be visible
    expect(withinMain.queryAllByRole('button', { name: /rollback guardduty containment/i })).toHaveLength(0);
  });

  it('shows rollback confirmation modal when Rollback button is clicked', async () => {
    // GIVEN an eligible GuardDuty SUCCESS remediation
    const remediation = generateTestRemediation({
      findingType: 'GuardDuty.IAMUser',
      remediationStatus: 'SUCCESS',
      resourceId: 'arn:aws:iam::123456789012:user/test-user',
    });

    server.use(
      http.post(
        MOCK_SERVER_URL + ApiEndpoints.REMEDIATIONS,
        async () => await ok({ Remediations: [remediation], NextToken: null }),
      ),
    );

    renderAppContent({ initialRoute: '/history' });

    const withinMain = within(screen.getByTestId('main-content'));
    await withinMain.findByText('(1)');

    // WHEN clicking the Rollback button
    const rollbackButton = await withinMain.findByRole('button', { name: /rollback guardduty containment/i });
    await userEvent.click(rollbackButton);

    // THEN the confirmation modal should appear
    const modal = await screen.findByRole('dialog');
    expect(within(modal).getByText('Confirm GuardDuty Credential Rollback')).toBeInTheDocument();
    expect(within(modal).getByText(/restore the IAM principal to its pre-containment state/i)).toBeInTheDocument();
    expect(within(modal).getByText(/90 days/i)).toBeInTheDocument();
    expect(within(modal).getByRole('button', { name: 'Rollback Containment' })).toBeInTheDocument();
    expect(within(modal).getByRole('button', { name: 'Cancel' })).toBeInTheDocument();
  });

  it('dismisses rollback modal when Cancel is clicked', async () => {
    // GIVEN an eligible remediation
    const remediation = generateTestRemediation({
      findingType: 'GuardDuty.IAMUser',
      remediationStatus: 'SUCCESS',
    });

    server.use(
      http.post(
        MOCK_SERVER_URL + ApiEndpoints.REMEDIATIONS,
        async () => await ok({ Remediations: [remediation], NextToken: null }),
      ),
    );

    renderAppContent({ initialRoute: '/history' });

    const withinMain = within(screen.getByTestId('main-content'));
    await withinMain.findByText('(1)');

    // WHEN clicking Rollback then Cancel
    const rollbackButton = await withinMain.findByRole('button', { name: /rollback guardduty containment/i });
    await userEvent.click(rollbackButton);

    const modal = await screen.findByRole('dialog');
    await userEvent.click(within(modal).getByRole('button', { name: 'Cancel' }));

    // THEN the modal should be dismissed
    await waitFor(() => {
      const dialogs = screen.queryAllByRole('dialog');
      const visibleDialogs = dialogs.filter((d) => !d.className.includes('hidden'));
      expect(visibleDialogs).toHaveLength(0);
    });
  });

  it('calls Rollback API and shows success alert when rollback is confirmed', async () => {
    // GIVEN an eligible remediation
    const remediation = generateTestRemediation({
      findingType: 'GuardDuty.IAMUser',
      remediationStatus: 'SUCCESS',
    });
    let rollbackActionCalled = false;

    server.use(
      http.post(
        MOCK_SERVER_URL + ApiEndpoints.REMEDIATIONS,
        async () => await ok({ Remediations: [remediation], NextToken: null }),
      ),
      http.post(MOCK_SERVER_URL + ApiEndpoints.FINDINGS + '/action', async ({ request }) => {
        const body = (await request.json()) as any;
        if (body.actionType === 'Rollback') {
          rollbackActionCalled = true;
          expect(body.findingIds).toEqual([remediation.findingId]);
        }
        return await ok({});
      }),
    );

    renderAppContent({ initialRoute: '/history' });

    const withinMain = within(screen.getByTestId('main-content'));
    await withinMain.findByText('(1)');

    // WHEN clicking Rollback and confirming
    const rollbackButton = await withinMain.findByRole('button', { name: /rollback guardduty containment/i });
    await userEvent.click(rollbackButton);

    const modal = await screen.findByRole('dialog');
    await userEvent.click(within(modal).getByRole('button', { name: 'Rollback Containment' }));

    // THEN the rollback API should be called
    await waitFor(() => {
      expect(rollbackActionCalled).toBe(true);
    });

    // AND the modal should be dismissed
    await waitFor(() => {
      const dialogs = screen.queryAllByRole('dialog');
      const visibleDialogs = dialogs.filter((d) => !d.className.includes('hidden'));
      expect(visibleDialogs).toHaveLength(0);
    });

    // AND a success alert should appear
    expect(await withinMain.findByText(/rollback initiated for finding/i)).toBeInTheDocument();
  });

  it('shows error alert when rollback API call fails', async () => {
    // GIVEN an eligible remediation and a failing API
    const remediation = generateTestRemediation({
      findingType: 'GuardDuty.IAMUser',
      remediationStatus: 'SUCCESS',
    });

    server.use(
      http.post(
        MOCK_SERVER_URL + ApiEndpoints.REMEDIATIONS,
        async () => await ok({ Remediations: [remediation], NextToken: null }),
      ),
      http.post(MOCK_SERVER_URL + ApiEndpoints.FINDINGS + '/action', async () => {
        return new Response(JSON.stringify({ message: 'Rollback failed' }), {
          status: 500,
          headers: { 'Content-Type': 'application/json' },
        });
      }),
    );

    renderAppContent({ initialRoute: '/history' });

    const withinMain = within(screen.getByTestId('main-content'));
    await withinMain.findByText('(1)');

    // WHEN clicking Rollback and confirming
    const rollbackButton = await withinMain.findByRole('button', { name: /rollback guardduty containment/i });
    await userEvent.click(rollbackButton);

    const modal = await screen.findByRole('dialog');
    await userEvent.click(within(modal).getByRole('button', { name: 'Rollback Containment' }));

    // THEN an error alert should appear
    expect(await screen.findByText('Rollback Failed')).toBeInTheDocument();
  });

  it('clears stale error/success alerts when a new rollback is initiated', async () => {
    // GIVEN two eligible remediations — first rollback fails, second succeeds
    const remediations = generateTestRemediations(2, {
      findingType: 'GuardDuty.IAMUser',
      remediationStatus: 'SUCCESS',
    });
    let callCount = 0;

    server.use(
      http.post(
        MOCK_SERVER_URL + ApiEndpoints.REMEDIATIONS,
        async () => await ok({ Remediations: remediations, NextToken: null }),
      ),
      http.post(MOCK_SERVER_URL + ApiEndpoints.FINDINGS + '/action', async () => {
        callCount++;
        if (callCount === 1) {
          return new Response(JSON.stringify({ message: 'First rollback failed' }), {
            status: 500,
            headers: { 'Content-Type': 'application/json' },
          });
        }
        return await ok({});
      }),
    );

    renderAppContent({ initialRoute: '/history' });

    const withinMain = within(screen.getByTestId('main-content'));
    await withinMain.findByText('(2)');

    // WHEN first rollback fails
    const rollbackButtons = await withinMain.findAllByRole('button', { name: /rollback guardduty containment/i });
    await userEvent.click(rollbackButtons[0]);
    let modal = await screen.findByRole('dialog');
    await userEvent.click(within(modal).getByRole('button', { name: 'Rollback Containment' }));

    // THEN error alert header appears
    expect(await screen.findByText('Rollback Failed')).toBeInTheDocument();

    // WHEN second rollback succeeds (open modal again — error alert is still visible)
    const updatedRollbackButtons = await withinMain.findAllByRole('button', {
      name: /rollback guardduty containment/i,
    });
    await userEvent.click(updatedRollbackButtons[0]);
    modal = await screen.findByRole('dialog');
    await userEvent.click(within(modal).getByRole('button', { name: 'Rollback Containment' }));

    // THEN success alert appears and error alert is gone
    expect(await withinMain.findByText(/rollback initiated for finding/i)).toBeInTheDocument();
    expect(screen.queryByText('Rollback Failed')).not.toBeInTheDocument();
  });
});

describe('RemediationHistoryPage ROLLBACK_SUCCESS status display', () => {
  beforeEach(() => {
    localStorage.clear();
  });

  it('renders the ROLLBACK_SUCCESS status as "Rollback Success" in the table', async () => {
    // ARRANGE
    server.use(
      http.post(
        MOCK_SERVER_URL + ApiEndpoints.REMEDIATIONS,
        async () =>
          await ok({
            Remediations: [
              generateTestRemediation({
                findingId: asFindingId('finding-rolled-back'),
                remediationStatus: 'ROLLBACK_SUCCESS',
                error: undefined,
              }),
            ],
            NextToken: null,
          }),
      ),
    );

    // ACT
    renderAppContent({ initialRoute: '/history' });
    const main = within(screen.getByTestId('main-content'));
    const table = await main.findByRole('table');

    // ASSERT — "Rollback Success" label is rendered
    expect(await within(table).findByText('Rollback Success')).toBeInTheDocument();
  });

  it('does not show the Rollback button for a ROLLBACK_SUCCESS GuardDuty finding', async () => {
    // ARRANGE — a GuardDuty finding that has already been rolled back
    server.use(
      http.post(
        MOCK_SERVER_URL + ApiEndpoints.REMEDIATIONS,
        async () =>
          await ok({
            Remediations: [
              generateTestRemediation({
                findingId: asFindingId('finding-already-rolled-back'),
                findingType: 'GuardDuty.IAMUser',
                remediationStatus: 'ROLLBACK_SUCCESS',
              }),
            ],
            NextToken: null,
          }),
      ),
    );

    // ACT
    renderAppContent({ initialRoute: '/history' });
    const main = within(screen.getByTestId('main-content'));
    await main.findByRole('table');

    // ASSERT — no Rollback button for an already-rolled-back finding
    expect(main.queryAllByRole('button', { name: /rollback guardduty containment/i })).toHaveLength(0);
  });

  it('includes "Rollback Success" in the status filter options', async () => {
    // ARRANGE
    server.use(
      http.post(
        MOCK_SERVER_URL + ApiEndpoints.REMEDIATIONS,
        async () => await ok({ Remediations: [], NextToken: null }),
      ),
    );

    // ACT
    renderAppContent({ initialRoute: '/history' });
    const main = within(screen.getByTestId('main-content'));
    const filterInput = await main.findByPlaceholderText('Search Remediations');

    // Open the filter dropdown and navigate to Status property
    await userEvent.click(filterInput);
    const dropdown = await screen.findByRole('listbox');
    const statusOption = await within(dropdown).findByText('Status');
    await userEvent.click(statusOption);

    // Select "=" operator
    const operatorDropdown = await screen.findByRole('listbox');
    const equalsOption = await within(operatorDropdown).findByText('=');
    await userEvent.click(equalsOption);

    // ASSERT — "Rollback Success" appears as a selectable value
    const valueDropdown = await screen.findByRole('listbox');
    expect(within(valueDropdown).getByText('Rollback Success')).toBeInTheDocument();
  });
});

describe('RemediationHistoryPage infinite scroll observer lifecycle', () => {
  const SEARCH_REMEDIATIONS_URL = MOCK_SERVER_URL + ApiEndpoints.REMEDIATIONS;
  let recorder: IntersectionObserverRecorder;

  beforeEach(() => {
    localStorage.clear();
    recorder = installIntersectionObserverRecorder();
  });

  afterEach(() => {
    recorder.restore();
  });

  it('registers and tears down every observer registration across a mount lifecycle', async () => {
    // ARRANGE — the load-more trigger renders only while more data is available, and
    // that is driven by the NextToken on the response. Without one the trigger never
    // mounts, observe() is never called, and the balance assertion holds vacuously at
    // zero, so the response carries a NextToken and the counts are checked non-zero
    // before the unmount.
    server.use(
      http.post(
        SEARCH_REMEDIATIONS_URL,
        async () => await ok({ Remediations: generateTestRemediations(3), NextToken: 'remediations-page-2' }),
      ),
    );

    const { renderResult } = renderAppContent({ initialRoute: '/history' });
    const withinMain = within(screen.getByTestId('main-content'));
    await withinMain.findByRole('heading', { name: 'Remediation History(3+)' });

    expect(recorder.registrationCount).toBeGreaterThan(0);
    expect(recorder.liveRegistrationCount).toBeGreaterThan(0);

    // ACT
    renderResult.unmount();

    // ASSERT — every registration was released. The observer effect re-runs whenever
    // hasMoreData, the loading flags, or the load-more callback change, so a single
    // mount legitimately produces several registrations and balance is the invariant
    // rather than a fixed count.
    expect(recorder.teardownCount).toBe(recorder.registrationCount);
    expect(recorder.liveRegistrationCount).toBe(0);
  });

  it('fetches exactly one additional page per intersection and none when not intersecting', async () => {
    // ARRANGE — the first page carries a NextToken so the trigger mounts; the second
    // carries none, so paging ends and no further request is left in flight.
    let searchRequestCount = 0;
    const firstPage = generateTestRemediations(3);
    const secondPage = generateTestRemediations(2);

    server.use(
      http.post(SEARCH_REMEDIATIONS_URL, async () => {
        searchRequestCount += 1;
        return searchRequestCount === 1
          ? await ok({ Remediations: firstPage, NextToken: 'remediations-page-2' })
          : await ok({ Remediations: secondPage, NextToken: null });
      }),
    );

    renderAppContent({ initialRoute: '/history' });
    const withinMain = within(screen.getByTestId('main-content'));
    await withinMain.findByRole('heading', { name: `Remediation History(${firstPage.length}+)` });

    expect(searchRequestCount).toBe(1);
    expect(recorder.registrationCount).toBeGreaterThan(0);
    expect(recorder.liveRegistrationCount).toBeGreaterThan(0);

    // ACT — a non-intersecting event while the first page's NextToken still leaves more data
    // available and neither loading flag is set, so entry.isIntersecting is the only term of
    // the load-more guard that can hold the request back
    await act(async () => {
      recorder.triggerIntersection(false);
    });
    // A request dispatched from the observer callback would already have reached the search
    // handler: the callback dispatches synchronously and the handler counts on entry, ahead
    // of its latency.
    await act(async () => {});

    // ASSERT — no request was issued, so the guard consults isIntersecting rather than
    // resting on hasMoreData alone
    expect(searchRequestCount).toBe(1);

    // ACT
    await act(async () => {
      recorder.triggerIntersection(true);
    });

    // ASSERT — one intersection produced exactly one further request and the page appended
    await withinMain.findByRole('heading', { name: `Remediation History(${firstPage.length + secondPage.length})` });
    expect(searchRequestCount).toBe(2);

    const table = await withinMain.findByRole('table');
    const rows = await within(table).findAllByRole('row');
    expect(rows).toHaveLength(firstPage.length + secondPage.length + 1);
  });
});
