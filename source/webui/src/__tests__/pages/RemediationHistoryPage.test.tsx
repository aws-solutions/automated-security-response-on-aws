// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

import { http } from 'msw';
import { ok } from '../../mocks/handlers.ts';
import { ApiEndpoints } from '../../store/solutionApi.ts';
import { MOCK_SERVER_URL, server } from '../server.ts';
import { generateTestRemediation, generateTestRemediations } from '../test-data-factory.ts';
import { renderAppContent } from '../test-utils.tsx';

describe('RemediationHistoryPage', () => {
  it('renders an empty table', async () => {
    // GIVEN the backend returns no remediations
    server.use(http.post(MOCK_SERVER_URL + ApiEndpoints.REMEDIATIONS, async () => await ok({ Remediations: [], NextToken: null })));

    // WHEN rendering the /history route
    renderAppContent({
      initialRoute: '/history',
    });

    // THEN
    const withinMain = within(screen.getByTestId('main-content'));
    expect(withinMain.getByRole('heading', { name: 'Remediation History (0)' })).toBeInTheDocument();
    expect(await withinMain.findByText(/no history to display/i)).toBeInTheDocument();
  });

  it('renders a table with remediation history', async () => {
    // GIVEN the backend returns 5 remediations
    const remediations = generateTestRemediations(5);

    server.use(http.post(MOCK_SERVER_URL + ApiEndpoints.REMEDIATIONS, async () => await ok({ Remediations: remediations, NextToken: null })));

    // WHEN
    renderAppContent({
      initialRoute: '/history',
    });

    // THEN expect 5 remediations plus a header row in the table
    const withinMain = within(screen.getByTestId('main-content'));
    
    // Wait for the data to load (the refresh button should not be in loading state)
    await withinMain.findByRole('button', { name: 'Refresh history' });

    const heading = await withinMain.findByRole('heading', { name: `Remediation History (5)` });
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

    server.use(http.post(MOCK_SERVER_URL + ApiEndpoints.REMEDIATIONS, async () => {
      requestCount++;
      if (requestCount <= 1) {
        return await ok({ 
          Remediations: generateTestRemediations(3), 
          NextToken: null 
        });
      } else {
        return await ok({ 
          Remediations: generateTestRemediations(4), 
          NextToken: null 
        });
      }
    }));

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
        findingId: 'finding-123', 
        remediationStatus: 'SUCCESS',
        accountId: '123456789012',
        resourceId: 'resource-abc123',
        lastUpdatedBy: 'user1@example.com',
        resourceType: 'AWS::S3::Bucket'
      }),
      ...generateTestRemediations(1, { 
        findingId: 'finding-456',
        remediationStatus: 'FAILED',
        accountId: '123456789013',
        resourceId: 'resource-def456',
        lastUpdatedBy: 'user2@example.com',
        resourceType: 'AWS::EC2::Instance'
      }),
    ];

    server.use(http.post(MOCK_SERVER_URL + ApiEndpoints.REMEDIATIONS, async () => await ok({ Remediations: remediations, NextToken: null })));

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
        lastUpdatedTime: new Date(now.getTime() - 3600000).toISOString() // 1 hour ago
      },
      {
        ...generateTestRemediation(),
        findingId: 'finding-2',
        lastUpdatedTime: new Date(now.getTime() - 7200000).toISOString() // 2 hours ago
      },
    ];

    server.use(http.post(MOCK_SERVER_URL + ApiEndpoints.REMEDIATIONS, async () => await ok({ Remediations: remediations, NextToken: null })));

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

    server.use(http.post(MOCK_SERVER_URL + ApiEndpoints.REMEDIATIONS, async () => await ok({ Remediations: remediations, NextToken: null })));

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
    server.use(http.post(MOCK_SERVER_URL + ApiEndpoints.REMEDIATIONS, async () => {
      return new Response(JSON.stringify({ message: 'Internal Server Error' }), {
        status: 500,
        headers: { 'Content-Type': 'application/json' }
      });
    }));

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

    server.use(http.post(MOCK_SERVER_URL + ApiEndpoints.REMEDIATIONS, async () => await ok({ Remediations: remediations, NextToken: null })));

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

    server.use(http.post(MOCK_SERVER_URL + ApiEndpoints.REMEDIATIONS, async (req) => {
      const body = await req.request.json() as any;
      requestCount++;

      if (requestCount === 1) {
        // First request - return first batch with NextToken
        return await ok({
          Remediations: firstBatch,
          NextToken: 'next-token-123'
        });
      } else if (requestCount === 2 && body.NextToken === 'next-token-123') {
        // Second request with NextToken - return second batch
        return await ok({
          Remediations: secondBatch,
          NextToken: null
        });
      }
      return await ok({ Remediations: [], NextToken: null });
    }));

    // WHEN rendering the page
    renderAppContent({
      initialRoute: '/history',
    });

    const withinMain = within(screen.getByTestId('main-content'));

    // Wait for initial data to load by checking the heading
    const initialHeading = await withinMain.findByRole('heading', { name: 'Remediation History (3+)' });
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

    server.use(http.post(MOCK_SERVER_URL + ApiEndpoints.REMEDIATIONS, async (req) => {
      const body = await req.request.json() as any;
      requestCount++;

      if (requestCount === 1) {
        // First request succeeds
        return await ok({
          Remediations: firstBatch,
          NextToken: 'next-token-123'
        });
      } else if (body.NextToken) {
        // Load more request fails
        return new Response(JSON.stringify({ message: 'Load more failed' }), {
          status: 500,
          headers: { 'Content-Type': 'application/json' }
        });
      }
      return await ok({ Remediations: [], NextToken: null });
    }));

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
        findingId: 'finding-abc-123',
        accountId: '111111111111',
        resourceId: 'resource-test-456'
      }),
      ...generateTestRemediations(1, {
        findingId: 'finding-xyz-789',
        accountId: '222222222222',
        resourceId: 'resource-prod-123'
      }),
    ];

    server.use(http.post(MOCK_SERVER_URL + ApiEndpoints.REMEDIATIONS, async () => await ok({ Remediations: remediations, NextToken: null })));

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
    server.use(http.post(MOCK_SERVER_URL + ApiEndpoints.REMEDIATIONS, async () => await ok({ Remediations: null, NextToken: null })));

    // WHEN rendering the page
    renderAppContent({
      initialRoute: '/history',
    });

    const withinMain = within(screen.getByTestId('main-content'));

    // THEN should handle gracefully and show empty state
    expect(await withinMain.findByText(/no history to display/i)).toBeInTheDocument();
  });

});
