// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { screen, within, render, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { http, HttpResponse } from 'msw';
import { Provider } from 'react-redux';
import { createMemoryRouter } from 'react-router';
import { RouterProvider } from 'react-router/dom';
import { configureStore } from '@reduxjs/toolkit';
import React, { StrictMode, useContext } from 'react';

import { MOCK_SERVER_URL, server } from '../server.ts';
import { solutionApi } from '../../store/solutionApi.ts';
import { ok } from '../../mocks/handlers.ts';
import { SecurityControl, ResourceFilter } from '@data-models';
import { mockUserContext } from '../test-data-factory.ts';
import { ControlsOverviewPage } from '../../pages/controls/ControlsOverviewPage.tsx';
import { UserContext } from '../../contexts/UserContext.tsx';
import { NotificationContext, NotificationContextProvider } from '../../contexts/NotificationContext.tsx';
import { rootReducer } from '../../store/store.ts';
import Flashbar from '@cloudscape-design/components/flashbar';
import { SplitPanelProvider, useSplitPanel } from '../../contexts/SplitPanelContext.tsx';
import { AppLayout } from '@cloudscape-design/components';

const GlobalFlashbar = () => {
  const { notifications } = useContext(NotificationContext);
  return <Flashbar items={notifications} stackItems />;
};

function generateTestControls(count: number): SecurityControl[] {
  const services = ['S3', 'EC2', 'IAM', 'RDS', 'Lambda', 'CloudTrail', 'KMS', 'VPC'];
  return Array.from({ length: count }, (_, i) => {
    const service = services[i % services.length];
    const num = Math.floor(i / services.length) + 1;
    return {
      controlId: `${service}.${num}`,
      description: `${service} control ${num} description`,
      automatedRemediationEnabled: i % 3 === 0,
      filters: [],
      filterMode: 'include' as const,
      version: 1,
      lastModified: '2025-01-01T00:00:00Z',
      modifiedBy: 'system',
    };
  });
}

const createTestControl = (overrides: Partial<SecurityControl> = {}): SecurityControl => ({
  controlId: 'S3.1',
  description: 'S3 control',
  automatedRemediationEnabled: false,
  filters: [],
  filterMode: 'include',
  version: 1,
  lastModified: '2025-01-01T00:00:00Z',
  modifiedBy: 'system',
  rollbackSupported: false,
  ...overrides,
});

const CONTROLS_URL = MOCK_SERVER_URL + 'controls';
const BULK_EDIT_URL = MOCK_SERVER_URL + 'controls/bulk-edit';
const FILTERS_URL = MOCK_SERVER_URL + 'filters';

const okControls = (controls: SecurityControl[]) => ok({ controls });
const okFilters = (filters: ResourceFilter[]) => ok({ filters });

const FILTER_UUID_1 = '00000000-0000-4000-8000-000000000001';
const FILTER_UUID_2 = '00000000-0000-4000-8000-000000000002';

const TEST_FILTERS: ResourceFilter[] = [
  {
    filterId: FILTER_UUID_1,
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
  {
    filterId: FILTER_UUID_2,
    name: 'US Regions',
    accountIds: [],
    organizationalUnits: ['ou-abcd-12345678'],
    tags: [],
    arnPatterns: [],
    version: 1,
    createdAt: '2025-01-01T00:00:00Z',
    createdBy: 'admin',
    lastModified: '2025-01-01T00:00:00Z',
    modifiedBy: 'admin',
  },
];

interface RenderOptions {
  userContextOverrides?: Partial<typeof mockUserContext>;
  initialRoute?: string;
}

interface RenderControlsPageOptions extends RenderOptions {
  strictMode?: boolean;
}

const renderControlsPage = ({
  userContextOverrides,
  initialRoute = '/controls',
  strictMode = false,
}: RenderControlsPageOptions = {}) => {
  const store = configureStore({
    reducer: rootReducer,
    middleware: (getDefaultMiddleware) => getDefaultMiddleware().concat(solutionApi.middleware),
  });

  const contextValue = { ...mockUserContext, ...userContextOverrides };

  const router = createMemoryRouter(
    [
      {
        path: '/controls',
        element: (
          <div data-testid="main-content">
            <ControlsOverviewPage />
          </div>
        ),
      },
      {
        path: '/other',
        element: <div>Other page</div>,
      },
    ],
    { initialEntries: [initialRoute] },
  );

  const providerTree = (
    <Provider store={store}>
      <UserContext.Provider value={contextValue}>
        <NotificationContextProvider>
          <GlobalFlashbar />
          <RouterProvider router={router} />
        </NotificationContextProvider>
      </UserContext.Provider>
    </Provider>
  );

  return render(strictMode ? <StrictMode>{providerTree}</StrictMode> : providerTree);
};

const SplitPanelConsumer = ({ children }: { children: React.ReactNode }) => {
  const { splitPanelContent, isSplitPanelOpen, closeSplitPanel } = useSplitPanel();
  return (
    <AppLayout
      content={<div data-testid="main-content">{children}</div>}
      splitPanel={splitPanelContent}
      splitPanelOpen={isSplitPanelOpen}
      onSplitPanelToggle={({ detail }) => {
        if (!detail.open) closeSplitPanel();
      }}
      navigationHide
      toolsHide
    />
  );
};

const renderControlsPageWithSplitPanel = ({ userContextOverrides, initialRoute = '/controls' }: RenderOptions = {}) => {
  const store = configureStore({
    reducer: rootReducer,
    middleware: (getDefaultMiddleware) => getDefaultMiddleware().concat(solutionApi.middleware),
  });

  const contextValue = { ...mockUserContext, ...userContextOverrides };

  const router = createMemoryRouter(
    [
      {
        path: '/controls',
        element: <ControlsOverviewPage />,
      },
    ],
    { initialEntries: [initialRoute] },
  );

  return render(
    <Provider store={store}>
      <UserContext.Provider value={contextValue}>
        <NotificationContextProvider>
          <SplitPanelProvider>
            <GlobalFlashbar />
            <SplitPanelConsumer>
              <RouterProvider router={router} />
            </SplitPanelConsumer>
          </SplitPanelProvider>
        </NotificationContextProvider>
      </UserContext.Provider>
    </Provider>,
  );
};

beforeEach(() => {
  localStorage.clear();
});

describe('ControlsOverviewPage', () => {
  it('renders an empty table and displays loading then empty state', async () => {
    // ARRANGE
    server.use(http.get(CONTROLS_URL, async () => await okControls([])));

    // ACT
    renderControlsPage();

    // ASSERT
    const withinMain = within(screen.getByTestId('main-content'));
    expect(await withinMain.findByText(/no security controls to display/i)).toBeInTheDocument();
    expect(withinMain.getByRole('heading', { name: /Controls\s*\(0\)/ })).toBeInTheDocument();
  });

  it('renders a table with controls and shows correct header counter', async () => {
    // ARRANGE
    const controls = generateTestControls(5);
    server.use(http.get(CONTROLS_URL, async () => await okControls(controls)));

    // ACT
    renderControlsPage();

    // ASSERT
    const withinMain = within(screen.getByTestId('main-content'));
    const heading = await withinMain.findByRole('heading', { name: /Controls\s*\(5\)/ });
    expect(heading).toBeInTheDocument();

    const table = await withinMain.findByRole('table');
    const rows = await within(table).findAllByRole('row');
    expect(rows).toHaveLength(controls.length + 1);

    expect(await within(table).findByText('S3.1')).toBeInTheDocument();
    expect(await within(table).findByText('EC2.1')).toBeInTheDocument();

    const modifiedByCells = await within(table).findAllByText('system');
    expect(modifiedByCells.length).toBeGreaterThanOrEqual(5);
    const lastModifiedCells = await within(table).findAllByText(new Date('2025-01-01T00:00:00Z').toLocaleString());
    expect(lastModifiedCells.length).toBeGreaterThanOrEqual(5);
  });

  it('filters controls by Control ID and clears the filter', async () => {
    // ARRANGE
    const controls = generateTestControls(8);
    server.use(http.get(CONTROLS_URL, async () => await okControls(controls)));

    // ACT
    renderControlsPage();

    const withinMain = within(screen.getByTestId('main-content'));
    await withinMain.findByRole('heading', { name: /Controls\s*\(8\)/ });

    const searchInput = await withinMain.findByPlaceholderText('Search by Control ID...');
    await userEvent.type(searchInput, 's3');

    // ASSERT - case-insensitive filter narrows results
    const table = await withinMain.findByRole('table');
    let rows = await within(table).findAllByRole('row');
    expect(rows).toHaveLength(2); // header + 1 S3 control
    expect(await within(table).findByText('S3.1')).toBeInTheDocument();

    // ACT - type a non-matching filter, then clear it
    await userEvent.clear(searchInput);
    await userEvent.type(searchInput, 'nonexistent');
    expect(await withinMain.findByText(/no matches/i)).toBeInTheDocument();

    const clearButton = await withinMain.findByRole('button', { name: 'Clear filter' });
    await userEvent.click(clearButton);

    // ASSERT - all controls restored
    rows = await within(table).findAllByRole('row');
    expect(rows).toHaveLength(9); // header + 8 controls
  });

  it('shows unsaved changes bar after toggling a control and saves successfully', async () => {
    // ARRANGE
    const controls = generateTestControls(3);
    let capturedBody: Record<string, unknown> | null = null;

    server.use(
      http.get(CONTROLS_URL, async () => await okControls(controls)),
      http.post(BULK_EDIT_URL, async ({ request }) => {
        capturedBody = (await request.json()) as Record<string, unknown>;
        return await ok({ message: 'Controls updated successfully', updatedCount: 1 });
      }),
    );

    // ACT
    renderControlsPage();

    const withinMain = within(screen.getByTestId('main-content'));
    await withinMain.findByRole('heading', { name: /Controls\s*\(3\)/ });

    const table = await withinMain.findByRole('table');
    const toggleLabel = await within(table).findByLabelText('Toggle automated remediation for S3.1');
    await userEvent.click(toggleLabel);

    // ASSERT - unsaved changes bar appears
    expect(await withinMain.findByText(/you have unsaved changes/i)).toBeInTheDocument();
    expect(await withinMain.findByText(/1 control/)).toBeInTheDocument();

    // ACT - click save
    const saveButton = await withinMain.findByRole('button', { name: /save changes/i });
    await userEvent.click(saveButton);

    // ASSERT - save was called with correct payload
    await waitFor(() => {
      expect(capturedBody).not.toBeNull();
    });
    expect(capturedBody).toMatchObject({
      operation: 'update',
      data: [expect.objectContaining({ controlId: 'S3.1' })],
    });
    expect(await screen.findByText(/controls saved successfully/i)).toBeInTheDocument();
  });

  it('explains a refused custom control instead of telling the operator to retry it', async () => {
    // A mixed batch: the built-in saves, the custom one is refused because a custom runbook
    // runs only on a manual trigger. The API reports that separately in rejectedControlIds,
    // and the notification has to use it — the generic "please refresh and retry the failed
    // controls" is advice that can never work for this control, since a retry is refused
    // identically.
    const controls = [
      createTestControl({ controlId: 'S3.1', source: 'builtin' }),
      createTestControl({ controlId: 'MCPProbe.1', source: 'custom', automatedRemediationEnabled: true }),
    ];
    server.use(
      http.get(CONTROLS_URL, async () => await okControls(controls)),
      http.post(BULK_EDIT_URL, async () =>
        HttpResponse.json(
          {
            message:
              'Some controls failed to update. Automated remediation cannot be enabled for controls served by a custom runbook. Controls: MCPProbe.1.',
            successCount: 1,
            failedControlIds: ['MCPProbe.1'],
            rejectedControlIds: ['MCPProbe.1'],
          },
          { status: 207 },
        ),
      ),
    );

    renderControlsPage();
    const withinMain = within(screen.getByTestId('main-content'));
    await withinMain.findByRole('heading', { name: /Controls\s*\(2\)/ });

    const table = await withinMain.findByRole('table');
    await userEvent.click(await within(table).findByLabelText('Toggle automated remediation for S3.1'));
    await userEvent.click(await withinMain.findByRole('button', { name: /save changes/i }));

    // The reason reaches the operator, naming the control...
    const notification = await screen.findByText(/manual trigger/i);
    expect(notification).toHaveTextContent('MCPProbe.1');
    // ...and it is not presented as something a refresh would fix.
    expect(notification).not.toHaveTextContent(/retry the failed controls/i);
  });

  describe('rollback column', () => {
    // The Rollback column is opt-in, so make it visible the way a user who selected it would.
    const ROLLBACK_PREFERENCES = {
      pageSize: 20,
      visibleContent: ['controlId', 'description', 'isEnabled', 'rollbackEnabled'],
      contentDensity: 'comfortable',
    };

    beforeEach(() => {
      localStorage.setItem('controlsTablePreferences', JSON.stringify(ROLLBACK_PREFERENCES));
    });

    const renderWithControls = async (controls: SecurityControl[]) => {
      server.use(http.get(CONTROLS_URL, async () => await okControls(controls)));
      renderControlsPage();
      const withinMain = within(screen.getByTestId('main-content'));
      await withinMain.findByRole('heading', { name: new RegExp(`Controls\\s*\\(${controls.length}\\)`) });
      return { withinMain, table: await withinMain.findByRole('table') };
    };

    it('treats an absent rollbackEnabled as enabled, matching the Orchestrator default', async () => {
      // Controls carry no rollbackEnabled until someone toggles it, and the Orchestrator defaults the
      // same way, so showing these as disabled would contradict what a rollback would actually do.
      const { table } = await renderWithControls([createTestControl({ controlId: 'KMS.4', rollbackSupported: true })]);

      const toggle = await within(table).findByLabelText('Toggle rollback for KMS.4');
      expect(toggle).toBeChecked();
      expect(toggle.closest('td')).toHaveTextContent('Enabled');
    });

    it('renders the toggle as disabled when rollbackEnabled is explicitly false', async () => {
      const { table } = await renderWithControls([
        createTestControl({ controlId: 'KMS.4', rollbackSupported: true, rollbackEnabled: false }),
      ]);

      const toggle = await within(table).findByLabelText('Toggle rollback for KMS.4');
      expect(toggle).not.toBeChecked();
      expect(toggle.closest('td')).toHaveTextContent('Disabled');
    });

    it('shows Not supported and no toggle for a control with no rollback capability', async () => {
      const { table } = await renderWithControls([createTestControl({ controlId: 'S3.1' })]);

      expect(await within(table).findByText('Not supported')).toBeInTheDocument();
      expect(within(table).queryByLabelText('Toggle rollback for S3.1')).not.toBeInTheDocument();
    });

    it('reports the toggle as an unsaved change and sends rollbackEnabled on save', async () => {
      let capturedBody: Record<string, unknown> | null = null;
      server.use(
        http.post(BULK_EDIT_URL, async ({ request }) => {
          capturedBody = (await request.json()) as Record<string, unknown>;
          return await ok({ message: 'Controls updated successfully', updatedCount: 1 });
        }),
      );
      const { withinMain, table } = await renderWithControls([
        createTestControl({ controlId: 'KMS.4', rollbackSupported: true }),
      ]);

      await userEvent.click(await within(table).findByLabelText('Toggle rollback for KMS.4'));

      expect(await withinMain.findByText(/you have unsaved changes/i)).toBeInTheDocument();
      expect(await withinMain.findByText(/1 control/)).toBeInTheDocument();

      await userEvent.click(await withinMain.findByRole('button', { name: /save changes/i }));

      await waitFor(() => {
        expect(capturedBody).not.toBeNull();
      });
      expect(capturedBody).toMatchObject({
        operation: 'update',
        data: [expect.objectContaining({ controlId: 'KMS.4', rollbackEnabled: false })],
      });
    });
  });

  // A custom runbook runs only on a manual trigger: the Orchestrator's resolver checks the
  // event type before it ever looks up a custom runbook, so an automatically triggered
  // finding never reaches one. An actionable toggle here would let the page report
  // "Enabled" for a control that is never remediated — the API refuses the write, and these
  // cover the readable half of that guard.
  describe('custom runbook controls', () => {
    const CUSTOM_COLUMN_PREFERENCES = {
      pageSize: 20,
      visibleContent: ['controlId', 'description', 'isEnabled', 'source'],
      contentDensity: 'comfortable',
    };

    beforeEach(() => {
      localStorage.setItem('controlsTablePreferences', JSON.stringify(CUSTOM_COLUMN_PREFERENCES));
    });

    const renderWithControls = async (controls: SecurityControl[]) => {
      server.use(http.get(CONTROLS_URL, async () => await okControls(controls)));
      renderControlsPage();
      const withinMain = within(screen.getByTestId('main-content'));
      await withinMain.findByRole('heading', { name: new RegExp(`Controls\\s*\\(${controls.length}\\)`) });
      return { withinMain, table: await withinMain.findByRole('table') };
    };

    it('offers no automated-remediation toggle for a custom control', async () => {
      const { table } = await renderWithControls([createTestControl({ controlId: 'MCPProbe.1', source: 'custom' })]);

      expect(await within(table).findByText('Manual trigger only')).toBeInTheDocument();
      expect(within(table).queryByLabelText('Toggle automated remediation for MCPProbe.1')).not.toBeInTheDocument();
    });

    it('lets a custom control that is already enabled be turned off', async () => {
      // The escape hatch for the inconsistent state: a control enabled before the guard
      // existed reads "Enabled" while the resolver ignores it, so the customer needs a way
      // to correct it. Hiding the switch entirely would trap them.
      const { withinMain, table } = await renderWithControls([
        createTestControl({
          controlId: 'MCPProbe.1',
          source: 'custom',
          automatedRemediationEnabled: true,
        }),
      ]);

      const toggle = await within(table).findByLabelText('Turn off automated remediation for MCPProbe.1');
      expect(toggle).toBeChecked();
      expect(toggle.closest('td')).toHaveTextContent('Enabled (no effect)');

      await userEvent.click(toggle);

      // Turning it off registers as an unsaved change, the same as any other control edit.
      expect(await withinMain.findByText(/unsaved change/i)).toBeInTheDocument();
    });

    it('still offers the toggle for a built-in control', async () => {
      const { table } = await renderWithControls([createTestControl({ controlId: 'S3.1', source: 'builtin' })]);

      expect(await within(table).findByLabelText('Toggle automated remediation for S3.1')).toBeInTheDocument();
      expect(within(table).queryByText('Manual trigger only')).not.toBeInTheDocument();
    });

    it('keeps the toggle for a control with no source, which predates the field', async () => {
      // Controls stored before `source` existed carry no value and are built-ins; losing
      // their toggle would disable automated remediation management for every one of them.
      const { table } = await renderWithControls([createTestControl({ controlId: 'S3.1' })]);

      expect(await within(table).findByLabelText('Toggle automated remediation for S3.1')).toBeInTheDocument();
    });

    it('scopes the table to custom runbooks only', async () => {
      // A customer with a few custom runbooks among 100+ built-ins has no other way to see
      // just theirs; the Control ID text filter cannot express "custom".
      const { withinMain, table } = await renderWithControls([
        createTestControl({ controlId: 'MCPProbe.1', source: 'custom' }),
        createTestControl({ controlId: 'S3.1', source: 'builtin' }),
        createTestControl({ controlId: 'LEGACY.1' }),
      ]);

      await userEvent.click(withinMain.getAllByLabelText('Filter by control source')[0]);
      await userEvent.click(await screen.findByRole('option', { name: 'Custom runbooks only' }));

      expect(await within(table).findByText('MCPProbe.1')).toBeInTheDocument();
      expect(within(table).queryByText('S3.1')).not.toBeInTheDocument();
      expect(within(table).queryByText('LEGACY.1')).not.toBeInTheDocument();
    });

    it('counts a control with no source as built-in when scoping', async () => {
      // Controls stored before `source` existed are built-ins. Dropping them from both
      // scopes would make them invisible under any filter but "All".
      const { withinMain, table } = await renderWithControls([
        createTestControl({ controlId: 'MCPProbe.1', source: 'custom' }),
        createTestControl({ controlId: 'LEGACY.1' }),
      ]);

      await userEvent.click(withinMain.getAllByLabelText('Filter by control source')[0]);
      await userEvent.click(await screen.findByRole('option', { name: 'Built-in only' }));

      expect(await within(table).findByText('LEGACY.1')).toBeInTheDocument();
      expect(within(table).queryByText('MCPProbe.1')).not.toBeInTheDocument();
    });

    it('names the runbook per row: type in one column, deployed version in another', async () => {
      const { table } = await renderWithControls([
        createTestControl({ controlId: 'MCPProbe.1', source: 'custom', version: 0, runbookVersion: 3 }),
        createTestControl({ controlId: 'S3.1', source: 'builtin', version: 7 }),
      ]);

      const customRow = (await within(table).findByText('MCPProbe.1')).closest('tr');
      const builtInRow = (await within(table).findByText('S3.1')).closest('tr');

      // The version shown is `runbookVersion` (3), not the config row's `version`
      // optimistic-lock counter (0 / 7), which would read as a meaningless "version".
      expect(customRow).toHaveTextContent('Custom');
      expect(customRow).toHaveTextContent('v3');
      expect(customRow).not.toHaveTextContent('v0');
      expect(builtInRow).toHaveTextContent('Built-in');
      expect(builtInRow).not.toHaveTextContent('v7');
    });

    it('shows the live version, which after a rollback is the older one', async () => {
      // After a rollback from v3 to v1 the API reports runbookVersion 1; the column shows it
      // as-is and must not "correct" it upward.
      const { table } = await renderWithControls([
        createTestControl({ controlId: 'MCPProbe.1', source: 'custom', runbookVersion: 1 }),
      ]);

      const row = (await within(table).findByText('MCPProbe.1')).closest('tr');
      expect(row).toHaveTextContent('Custom');
      expect(row).toHaveTextContent('v1');
    });

    it('shows Custom with no version when the deployed version is not known', async () => {
      // Deploy record unread (the API degrades to built-ins-only): still identifiable as
      // custom, version column empty.
      const { table } = await renderWithControls([createTestControl({ controlId: 'MCPProbe.1', source: 'custom' })]);

      const row = (await within(table).findByText('MCPProbe.1')).closest('tr');
      expect(row).toHaveTextContent('Custom');
      expect(row).not.toHaveTextContent(/v\d/);
    });
  });

  it('batches bulk edit requests when saving many controls', async () => {
    // ARRANGE - 20 enabled controls so "Disable All" produces a large changeset
    const controls = Array.from({ length: 20 }, (_, i) =>
      createTestControl({
        controlId: `S3.${i + 1}`,
        description: `S3 control ${i + 1}`,
        automatedRemediationEnabled: true,
      }),
    );
    const capturedBodies: Record<string, unknown>[] = [];

    server.use(
      http.get(CONTROLS_URL, async () => await okControls(controls)),
      http.post(BULK_EDIT_URL, async ({ request }) => {
        const body = (await request.json()) as Record<string, unknown>;
        capturedBodies.push(body);
        return await ok({ message: 'Controls updated successfully', updatedCount: (body.data as unknown[]).length });
      }),
    );

    // ACT
    renderControlsPage();

    const withinMain = within(screen.getByTestId('main-content'));
    await withinMain.findByRole('heading', { name: /Controls\s*\(20\)/ });

    const disableAllButton = await withinMain.findByRole('button', { name: /Disable All Automated Remediations/i });
    await userEvent.click(disableAllButton);

    const saveButton = await withinMain.findByRole('button', { name: /save changes/i });
    await userEvent.click(saveButton);

    // ASSERT - multiple batched requests were made
    await waitFor(() => {
      expect(capturedBodies.length).toBeGreaterThan(1);
    });

    // Each batch should have at most 15 controls
    for (const body of capturedBodies) {
      expect((body.data as unknown[]).length).toBeLessThanOrEqual(15);
    }

    // Total controls across all batches should equal 20
    const totalControls = capturedBodies.reduce((sum, body) => sum + (body.data as unknown[]).length, 0);
    expect(totalControls).toBe(20);

    expect(await screen.findByText(/controls saved successfully/i)).toBeInTheDocument();
  });

  it('discards unsaved changes and shows info notification', async () => {
    // ARRANGE
    const controls = generateTestControls(2);
    server.use(http.get(CONTROLS_URL, async () => await okControls(controls)));

    // ACT
    renderControlsPage();

    const withinMain = within(screen.getByTestId('main-content'));
    await withinMain.findByRole('heading', { name: /Controls\s*\(2\)/ });

    const table = await withinMain.findByRole('table');
    const toggleLabel = await within(table).findByLabelText('Toggle automated remediation for S3.1');
    await userEvent.click(toggleLabel);

    expect(await withinMain.findByText(/you have unsaved changes/i)).toBeInTheDocument();

    const discardButton = await withinMain.findByRole('button', { name: /discard/i });
    await userEvent.click(discardButton);

    // ASSERT
    expect(await screen.findByText(/changes discarded/i)).toBeInTheDocument();
    expect(withinMain.queryByText(/you have unsaved changes/i)).not.toBeInTheDocument();
  });

  it('shows error notification on save conflict (409)', async () => {
    // ARRANGE
    const controls = generateTestControls(2);
    server.use(
      http.get(CONTROLS_URL, async () => await okControls(controls)),
      http.post(BULK_EDIT_URL, async () => {
        return HttpResponse.json(
          { error: 'ConflictError', message: 'Data was modified by another user' },
          { status: 409 },
        );
      }),
    );

    // ACT
    renderControlsPage();

    const withinMain = within(screen.getByTestId('main-content'));
    await withinMain.findByRole('heading', { name: /Controls\s*\(2\)/ });

    const table = await withinMain.findByRole('table');
    const toggleLabel = await within(table).findByLabelText('Toggle automated remediation for S3.1');
    await userEvent.click(toggleLabel);

    const saveButton = await withinMain.findByRole('button', { name: /save changes/i });
    await userEvent.click(saveButton);

    // ASSERT
    expect(await screen.findByText(/data was modified by another user/i)).toBeInTheDocument();
  });

  it('shows loading state while controls are being fetched', async () => {
    // ARRANGE
    server.use(
      http.get(CONTROLS_URL, async () => {
        await new Promise((resolve) => setTimeout(resolve, 500));
        return await okControls([]);
      }),
    );

    // ACT
    renderControlsPage();

    // ASSERT
    const withinMain = within(screen.getByTestId('main-content'));
    expect(await withinMain.findByText('Loading controls')).toBeInTheDocument();
  });

  it('disables refresh button when unsaved changes exist', async () => {
    // ARRANGE
    const controls = generateTestControls(2);
    server.use(http.get(CONTROLS_URL, async () => await okControls(controls)));

    // ACT
    renderControlsPage();

    const withinMain = within(screen.getByTestId('main-content'));
    await withinMain.findByRole('heading', { name: /Controls\s*\(2\)/ });

    const refreshButton = await withinMain.findByLabelText('Refresh controls');
    expect(refreshButton).not.toBeDisabled();

    const table = await withinMain.findByRole('table');
    const toggleLabel = await within(table).findByLabelText('Toggle automated remediation for S3.1');
    await userEvent.click(toggleLabel);

    // ASSERT
    await waitFor(() => {
      expect(refreshButton).toBeDisabled();
    });
  });

  it('displays "All resources" when a control has no filters', async () => {
    // ARRANGE
    const controls = generateTestControls(1);
    server.use(http.get(CONTROLS_URL, async () => await okControls(controls)));

    // ACT
    renderControlsPage();

    // ASSERT
    const withinMain = within(screen.getByTestId('main-content'));
    await withinMain.findByRole('heading', { name: /Controls\s*\(1\)/ });
    expect(await withinMain.findByText('All resources')).toBeInTheDocument();
  });

  it('displays filter badges when a control has applied filters', async () => {
    // ARRANGE
    const controls = [
      createTestControl({ automatedRemediationEnabled: true, filters: [FILTER_UUID_1, FILTER_UUID_2] }),
    ];
    server.use(
      http.get(CONTROLS_URL, async () => await okControls(controls)),
      http.get(FILTERS_URL, async () => await okFilters(TEST_FILTERS)),
    );

    // ACT
    renderControlsPage();

    // ASSERT
    const withinMain = within(screen.getByTestId('main-content'));
    await withinMain.findByRole('heading', { name: /Controls\s*\(1\)/ });
    expect(await withinMain.findByText('Production Accounts')).toBeInTheDocument();
    expect(await withinMain.findByText('US Regions')).toBeInTheDocument();
  });

  it('shows "+N more" badge when a control has more than 2 filters', async () => {
    // ARRANGE
    const thirdFilter: ResourceFilter = {
      filterId: '00000000-0000-4000-8000-000000000003',
      name: 'Dev Accounts',
      accountIds: ['999999999999'],
      organizationalUnits: [],
      tags: [],
      arnPatterns: [],
      version: 1,
      createdAt: '2025-01-01T00:00:00Z',
      createdBy: 'admin',
      lastModified: '2025-01-01T00:00:00Z',
      modifiedBy: 'admin',
    };
    const controls = [
      createTestControl({
        automatedRemediationEnabled: true,
        filters: [FILTER_UUID_1, FILTER_UUID_2, thirdFilter.filterId],
        filterMode: 'exclude',
      }),
    ];
    server.use(
      http.get(CONTROLS_URL, async () => await okControls(controls)),
      http.get(FILTERS_URL, async () => await okFilters([...TEST_FILTERS, thirdFilter])),
    );

    // ACT
    renderControlsPage();

    // ASSERT
    const withinMain = within(screen.getByTestId('main-content'));
    await withinMain.findByRole('heading', { name: /Controls\s*\(1\)/ });
    expect(await withinMain.findByText('Production Accounts')).toBeInTheDocument();
    expect(await withinMain.findByText('+2 more')).toBeInTheDocument();
    expect(withinMain.queryByText('US Regions')).not.toBeInTheDocument();
    expect(withinMain.queryByText('Dev Accounts')).not.toBeInTheDocument();
  });

  it('pre-selects a control when controlId query param is present in the URL', async () => {
    // ARRANGE
    const controls = generateTestControls(5);
    server.use(http.get(CONTROLS_URL, async () => await okControls(controls)));

    // ACT
    renderControlsPage({ initialRoute: '/controls?controlId=EC2.1' });

    // ASSERT
    const withinMain = within(screen.getByTestId('main-content'));
    const heading = await withinMain.findByRole('heading', { name: /Controls\s*\(5\)/ });
    expect(heading).toBeInTheDocument();

    await waitFor(() => {
      const counterText = withinMain.getByRole('heading', { level: 1 }).textContent;
      expect(counterText).toMatch(/\(1\/5\)/);
    });
  });

  it('does not pre-select when controlId query param does not match any control', async () => {
    // ARRANGE
    const controls = generateTestControls(3);
    server.use(http.get(CONTROLS_URL, async () => await okControls(controls)));

    // ACT
    renderControlsPage({ initialRoute: '/controls?controlId=NONEXISTENT.99' });

    // ASSERT
    const withinMain = within(screen.getByTestId('main-content'));
    const heading = await withinMain.findByRole('heading', { name: /Controls\s*\(3\)/ });
    expect(heading).toBeInTheDocument();
    expect(heading.textContent).not.toMatch(/\d+\/3/);
  });

  it('renders controls as read-only for Account Operators with disabled toggles', async () => {
    // ARRANGE
    const controls = generateTestControls(3);
    server.use(http.get(CONTROLS_URL, async () => await okControls(controls)));

    // ACT
    renderControlsPage({ userContextOverrides: { groups: ['AccountOperatorGroup'] } });

    // ASSERT - page renders with controls visible and read-only badge
    const withinMain = within(screen.getByTestId('main-content'));
    const heading = await withinMain.findByRole('heading', { name: /Controls.*\(3\)/ });
    expect(heading).toBeInTheDocument();
    expect(heading).toHaveTextContent('Read-only');

    // ASSERT - all toggles are disabled
    const table = await withinMain.findByRole('table');
    const s3Toggle = await within(table).findByLabelText('Toggle automated remediation for S3.1');
    const ec2Toggle = await within(table).findByLabelText('Toggle automated remediation for EC2.1');
    const iamToggle = await within(table).findByLabelText('Toggle automated remediation for IAM.1');
    expect(s3Toggle).toBeDisabled();
    expect(ec2Toggle).toBeDisabled();
    expect(iamToggle).toBeDisabled();

    // ASSERT - clicking a disabled toggle does not show unsaved changes bar
    await userEvent.click(s3Toggle);
    expect(withinMain.queryByText(/you have unsaved changes/i)).not.toBeInTheDocument();
  });

  it('resets page index to 1 when filtering narrows results below current page', async () => {
    // ARRANGE - use page size of 3 so 8 controls span multiple pages
    localStorage.setItem(
      'controlsTablePreferences',
      JSON.stringify({
        pageSize: 3,
        visibleContent: ['controlId', 'description', 'isEnabled', 'appliedFilters'],
        contentDensity: 'comfortable',
      }),
    );
    const controls = generateTestControls(8);
    server.use(http.get(CONTROLS_URL, async () => await okControls(controls)));

    // ACT
    renderControlsPage();

    const withinMain = within(screen.getByTestId('main-content'));
    await withinMain.findByRole('heading', { name: /Controls\s*\(8\)/ });

    // ACT - navigate to page 2 via the Pagination onChange
    const page2Button = withinMain.getByText('2');
    await userEvent.click(page2Button);

    // ASSERT - on page 2, table shows next batch of controls
    const table = await withinMain.findByRole('table');
    let rows = await within(table).findAllByRole('row');
    expect(rows).toHaveLength(4); // header + 3 controls on page 2

    // ACT - filter to narrow results to 1 control
    const searchInput = await withinMain.findByPlaceholderText('Search by Control ID...');
    await userEvent.type(searchInput, 's3');

    // ASSERT - table shows the filtered result, not a blank page
    rows = await within(table).findAllByRole('row');
    expect(rows).toHaveLength(2); // header + 1 S3 control
    expect(await within(table).findByText('S3.1')).toBeInTheDocument();
  });

  it('resets page index to 1 when the source scope narrows results below current page', async () => {
    // The text filter already resets the page index. Narrowing by source shrinks the list
    // the same way, so without its own reset the operator lands on a page that no longer
    // exists and sees an empty table — with no indication that the filter matched anything.
    localStorage.setItem(
      'controlsTablePreferences',
      JSON.stringify({
        pageSize: 3,
        visibleContent: ['controlId', 'description', 'isEnabled', 'source'],
        contentDensity: 'comfortable',
      }),
    );
    const controls = [
      ...generateTestControls(8).map((control) => ({ ...control, source: 'builtin' as const })),
      createTestControl({ controlId: 'MCPProbe.1', source: 'custom' }),
    ];
    server.use(http.get(CONTROLS_URL, async () => await okControls(controls)));

    renderControlsPage();

    const withinMain = within(screen.getByTestId('main-content'));
    await withinMain.findByRole('heading', { name: /Controls\s*\(9\)/ });

    // ACT - go to page 3, which only exists while all 9 controls are listed
    await userEvent.click(withinMain.getByText('3'));
    const table = await withinMain.findByRole('table');
    expect(await within(table).findAllByRole('row')).toHaveLength(4); // header + 3

    // ACT - narrow to the single custom runbook
    await userEvent.click(withinMain.getAllByLabelText('Filter by control source')[0]);
    await userEvent.click(await screen.findByRole('option', { name: 'Custom runbooks only' }));

    // ASSERT - the one match is visible rather than a blank page 3
    expect(await within(table).findByText('MCPProbe.1')).toBeInTheDocument();
    expect(await within(table).findAllByRole('row')).toHaveLength(2); // header + 1
  });

  it('disables all remediation locally when clicking "Disable all remediation" button', async () => {
    // ARRANGE - some controls have remediation enabled
    const controls = [
      createTestControl({ controlId: 'S3.1', automatedRemediationEnabled: true }),
      createTestControl({ controlId: 'EC2.1', description: 'EC2 control', automatedRemediationEnabled: true }),
      createTestControl({ controlId: 'IAM.1', description: 'IAM control', automatedRemediationEnabled: false }),
    ];
    server.use(http.get(CONTROLS_URL, async () => await okControls(controls)));

    // ACT
    renderControlsPage();

    const withinMain = within(screen.getByTestId('main-content'));
    await withinMain.findByRole('heading', { name: /Controls\s*\(3\)/ });

    const disableAllButton = await withinMain.findByRole('button', { name: /Disable All Automated Remediations/i });
    await userEvent.click(disableAllButton);

    // ASSERT - unsaved changes bar appears for the 2 controls that were enabled
    expect(await withinMain.findByText(/you have unsaved changes/i)).toBeInTheDocument();
    expect(await withinMain.findByText(/2 controls/)).toBeInTheDocument();

    // ASSERT - all toggles now show "Disabled"
    const table = await withinMain.findByRole('table');
    const toggles = await within(table).findAllByRole('checkbox');
    toggles.forEach((toggle) => {
      expect(toggle).not.toBeChecked();
    });

    // ASSERT - button is now disabled since all are already off
    expect(disableAllButton).toBeDisabled();
  });

  it('disables the "Disable all remediation" button when all controls are already disabled', async () => {
    // ARRANGE
    const controls = [createTestControl()];
    server.use(http.get(CONTROLS_URL, async () => await okControls(controls)));

    // ACT
    renderControlsPage();

    const withinMain = within(screen.getByTestId('main-content'));
    await withinMain.findByRole('heading', { name: /Controls\s*\(1\)/ });

    // ASSERT
    const disableAllButton = await withinMain.findByRole('button', { name: /Disable All Automated Remediations/i });
    expect(disableAllButton).toBeDisabled();
  });

  it('disables the "Disable all remediation" button for read-only users', async () => {
    // ARRANGE
    const controls = generateTestControls(3);
    server.use(http.get(CONTROLS_URL, async () => await okControls(controls)));

    // ACT
    renderControlsPage({ userContextOverrides: { groups: ['AccountOperatorGroup'] } });

    const withinMain = within(screen.getByTestId('main-content'));
    await withinMain.findByRole('heading', { name: /Controls.*\(3\)/ });

    // ASSERT
    const disableAllButton = await withinMain.findByRole('button', { name: /Disable All Automated Remediations/i });
    expect(disableAllButton).toBeDisabled();
  });
});

describe('ControlsOverviewPage under StrictMode', () => {
  it('applies the deep-linked selection once per mount so a later user selection is not stomped', async () => {
    // ARRANGE
    const controls = [
      createTestControl({ controlId: 'S3.1', description: 'S3 bucket encryption' }),
      createTestControl({ controlId: 'S3.2', description: 'S3 bucket logging' }),
    ];
    server.use(
      http.get(CONTROLS_URL, async () => await okControls(controls)),
      http.get(FILTERS_URL, async () => await okFilters(TEST_FILTERS)),
    );

    renderControlsPage({ initialRoute: '/controls?controlId=S3.1', strictMode: true });

    const withinMain = within(screen.getByTestId('main-content'));
    await withinMain.findByRole('heading', { name: /Controls\s*\(1\/2\)/ });

    const searchInput = await withinMain.findByPlaceholderText('Search by Control ID...');
    expect(searchInput).toHaveValue('S3.1');

    const table = await withinMain.findByRole('table');

    // ACT - clear the deep-link filter so both controls are selectable, then select the other control
    await userEvent.clear(searchInput);
    await waitFor(() => {
      expect(within(table).getAllByRole('row')).toHaveLength(controls.length + 1);
    });

    const rowForSecondControl = within(table)
      .getAllByRole('row')
      .find((row) => within(row).queryByText('S3.2'));
    if (!rowForSecondControl) throw new Error('Row for S3.2 not found');
    await userEvent.click(within(rowForSecondControl).getByRole('radio'));

    // ASSERT - a re-applied mount-time selection would have re-populated the filter and hidden a row
    expect(searchInput).toHaveValue('');
    expect(within(table).getAllByRole('row')).toHaveLength(controls.length + 1);

    // ASSERT - the user's selection survives; the mount-time selection is not re-applied
    const rowForFirstControl = within(table)
      .getAllByRole('row')
      .find((row) => within(row).queryByText('S3.1'));
    if (!rowForFirstControl) throw new Error('Row for S3.1 not found');
    expect(within(rowForSecondControl).getByRole('radio')).toBeChecked();
    expect(within(rowForFirstControl).getByRole('radio')).not.toBeChecked();
  });

  it('leaves pagination alone on mount but resets it to page 1 on a user filter change', async () => {
    // ARRANGE - page size of 3 so 8 controls span three pages, and a filter that still leaves two
    localStorage.setItem(
      'controlsTablePreferences',
      JSON.stringify({
        pageSize: 3,
        visibleContent: ['controlId', 'description', 'isEnabled', 'appliedFilters'],
        contentDensity: 'comfortable',
      }),
    );
    const controls = [
      ...Array.from({ length: 6 }, (_, index) =>
        createTestControl({ controlId: `S3.${index + 1}`, description: `S3 control ${index + 1}` }),
      ),
      createTestControl({ controlId: 'EC2.1', description: 'EC2 control 1' }),
      createTestControl({ controlId: 'EC2.2', description: 'EC2 control 2' }),
    ];
    server.use(
      http.get(CONTROLS_URL, async () => await okControls(controls)),
      http.get(FILTERS_URL, async () => await okFilters(TEST_FILTERS)),
    );

    renderControlsPage({ strictMode: true });

    const withinMain = within(screen.getByTestId('main-content'));
    await withinMain.findByRole('heading', { name: /Controls\s*\(8\)/ });

    // ASSERT - the mount-time filter effect left the page index untouched
    expect(withinMain.getByRole('button', { name: '1' })).toHaveAttribute('aria-current', 'true');

    // ACT - move to page 2
    await userEvent.click(withinMain.getByRole('button', { name: '2' }));

    // ASSERT - page 2 is current and shows the second batch of the sorted list
    const table = await withinMain.findByRole('table');
    expect(withinMain.getByRole('button', { name: '2' })).toHaveAttribute('aria-current', 'true');
    expect(await within(table).findByText('S3.2')).toBeInTheDocument();
    expect(await within(table).findByText('S3.4')).toBeInTheDocument();

    // ACT - a user-driven filter change, still leaving more than one page of matches
    const searchInput = await withinMain.findByPlaceholderText('Search by Control ID...');
    await userEvent.type(searchInput, 's3');

    // ASSERT - pagination reset to page 1 even though page 2 still exists
    await waitFor(() => {
      expect(withinMain.getByRole('button', { name: '1' })).toHaveAttribute('aria-current', 'true');
    });
    expect(withinMain.getByRole('button', { name: '2' })).toHaveAttribute('aria-current', 'false');
    expect(await within(table).findByText('S3.1')).toBeInTheDocument();
    expect(within(table).queryByText('S3.4')).not.toBeInTheDocument();
  });
});

describe('ControlDetailPanel integration', () => {
  it('opens the detail panel when a control row is selected and shows control info', async () => {
    // ARRANGE
    const controls = [
      createTestControl({
        controlId: 'S3.1',
        description: 'Ensure S3 bucket encryption',
        automatedRemediationEnabled: true,
        filters: [FILTER_UUID_1],
      }),
    ];
    server.use(
      http.get(CONTROLS_URL, async () => await okControls(controls)),
      http.get(FILTERS_URL, async () => await okFilters(TEST_FILTERS)),
    );

    // ACT
    renderControlsPageWithSplitPanel();
    const withinMain = within(screen.getByTestId('main-content'));
    await withinMain.findByRole('heading', { name: /Controls\s*\(1\)/ });

    const table = await withinMain.findByRole('table');
    const radioInput = within(table).getByRole('radio');
    await userEvent.click(radioInput);

    // ASSERT
    expect(await screen.findByText(/Control: S3\.1/)).toBeInTheDocument();
    const descriptions = await screen.findAllByText('Ensure S3 bucket encryption');
    expect(descriptions.length).toBeGreaterThanOrEqual(1);
    const enabledElements = await screen.findAllByText('Enabled');
    expect(enabledElements.length).toBeGreaterThanOrEqual(1);
    const filterNames = await screen.findAllByText('Production Accounts');
    expect(filterNames.length).toBeGreaterThanOrEqual(1);
  });

  it('keeps the "no effect" qualification in the panel for an enabled custom control', async () => {
    // The table calls this state "Enabled (no effect)": a custom-runbook control runs only
    // on a manual trigger, so the stored flag changes nothing. The panel describing the
    // same row must not upgrade that to a plain green "Enabled" — an operator reading the
    // panel would believe automated remediation is active when the resolver ignores it.
    server.use(
      http.get(
        CONTROLS_URL,
        async () =>
          await okControls([
            createTestControl({ controlId: 'MCPProbe.1', source: 'custom', automatedRemediationEnabled: true }),
          ]),
      ),
      http.get(FILTERS_URL, async () => await okFilters([])),
    );
    renderControlsPageWithSplitPanel();
    const withinMain = within(screen.getByTestId('main-content'));
    await withinMain.findByRole('heading', { name: /Controls\s*\(1\)/ });
    const table = await withinMain.findByRole('table');
    await userEvent.click(within(table).getByRole('radio'));

    await screen.findByRole('heading', { name: /Control: MCPProbe\.1/ });
    // The row's toggle label says it once; the panel must say it a second time, and a bare
    // "Enabled" — the text the panel used to show — must appear nowhere on the page.
    expect(await screen.findAllByText('Enabled (no effect)')).toHaveLength(2);
    expect(screen.queryByText(/^Enabled$/)).not.toBeInTheDocument();
  });

  it('shows "Manual trigger only" in the panel for a custom control that is off, matching the table', async () => {
    server.use(
      http.get(
        CONTROLS_URL,
        async () =>
          await okControls([
            createTestControl({ controlId: 'MCPProbe.2', source: 'custom', automatedRemediationEnabled: false }),
          ]),
      ),
      http.get(FILTERS_URL, async () => await okFilters([])),
    );
    renderControlsPageWithSplitPanel();
    const withinMain = within(screen.getByTestId('main-content'));
    await withinMain.findByRole('heading', { name: /Controls\s*\(1\)/ });
    const table = await withinMain.findByRole('table');
    await userEvent.click(within(table).getByRole('radio'));

    await screen.findByRole('heading', { name: /Control: MCPProbe\.2/ });
    // Both the row and the panel say it, so there are two; neither may say "Disabled",
    // which would imply a switch the operator could turn on.
    expect(await screen.findAllByText('Manual trigger only')).toHaveLength(2);
    expect(screen.queryByText('Disabled')).not.toBeInTheDocument();
  });

  it('names the live runbook version in the panel and states that only the latest deployed one runs', async () => {
    server.use(
      http.get(
        CONTROLS_URL,
        async () =>
          await okControls([
            createTestControl({
              controlId: 'MCPProbe.1',
              source: 'custom',
              automatedRemediationEnabled: false,
              runbookVersion: 2,
            }),
          ]),
      ),
      http.get(FILTERS_URL, async () => await okFilters([])),
    );
    renderControlsPageWithSplitPanel();
    const withinMain = within(screen.getByTestId('main-content'));
    await withinMain.findByRole('heading', { name: /Controls\s*\(1\)/ });
    const table = await withinMain.findByRole('table');
    await userEvent.click(within(table).getByRole('radio'));

    await screen.findByRole('heading', { name: /Control: MCPProbe\.1/ });
    // The panel keeps the combined label; the row now splits type and version into their own
    // columns, so "Custom v2" as one string appears once (the panel), while the row carries
    // "Custom" and "v2" in separate cells.
    expect(await screen.findByText('Custom v2')).toBeInTheDocument();
    const row = (await within(table).findByText('MCPProbe.1')).closest('tr');
    expect(row).toHaveTextContent('Custom');
    expect(row).toHaveTextContent('v2');
    expect(screen.getByText(/Only the most recently deployed version runs/)).toBeInTheDocument();
  });

  it('does not attach the deployed-version note to a built-in control', async () => {
    server.use(
      http.get(
        CONTROLS_URL,
        async () => await okControls([createTestControl({ controlId: 'S3.1', source: 'builtin' })]),
      ),
      http.get(FILTERS_URL, async () => await okFilters([])),
    );
    renderControlsPageWithSplitPanel();
    const withinMain = within(screen.getByTestId('main-content'));
    await withinMain.findByRole('heading', { name: /Controls\s*\(1\)/ });
    const table = await withinMain.findByRole('table');
    await userEvent.click(within(table).getByRole('radio'));

    await screen.findByRole('heading', { name: /Control: S3\.1/ });
    expect(await screen.findAllByText('Built-in')).toHaveLength(2);
    expect(screen.queryByText(/most recently deployed version/)).not.toBeInTheDocument();
  });

  it('shows "No filters" indicator in the detail panel when control has no filters', async () => {
    // ARRANGE
    const controls = [createTestControl({ controlId: 'EC2.6', description: 'VPC flow logging' })];
    server.use(
      http.get(CONTROLS_URL, async () => await okControls(controls)),
      http.get(FILTERS_URL, async () => await okFilters(TEST_FILTERS)),
    );

    // ACT
    renderControlsPageWithSplitPanel();
    const withinMain = within(screen.getByTestId('main-content'));
    await withinMain.findByRole('heading', { name: /Controls\s*\(1\)/ });

    const table = await withinMain.findByRole('table');
    const radioInput = within(table).getByRole('radio');
    await userEvent.click(radioInput);

    // ASSERT
    expect(await screen.findByText(/Control: EC2\.6/)).toBeInTheDocument();
    expect(await screen.findByText(/No filters — applies to all resources/)).toBeInTheDocument();
  });

  it('tracks filter removal from the detail panel as an unsaved change', async () => {
    // ARRANGE
    const controls = [
      createTestControl({
        controlId: 'S3.1',
        automatedRemediationEnabled: true,
        filters: [FILTER_UUID_1],
      }),
    ];
    server.use(
      http.get(CONTROLS_URL, async () => await okControls(controls)),
      http.get(FILTERS_URL, async () => await okFilters(TEST_FILTERS)),
    );

    // ACT
    renderControlsPageWithSplitPanel();
    const withinMain = within(screen.getByTestId('main-content'));
    await withinMain.findByRole('heading', { name: /Controls\s*\(1\)/ });

    const table = await withinMain.findByRole('table');
    const radioInput = within(table).getByRole('radio');
    await userEvent.click(radioInput);

    await screen.findByText(/Control: S3\.1/);
    const removeButton = await screen.findByRole('button', { name: /Remove filter Production Accounts/ });
    await userEvent.click(removeButton);

    // ASSERT
    expect(await screen.findByText(/you have unsaved changes/i)).toBeInTheDocument();
  });

  it('shows filter mode inversion warning when mode is changed with filters applied', async () => {
    // ARRANGE
    const controls = [
      createTestControl({
        controlId: 'S3.1',
        filters: [FILTER_UUID_1],
        filterMode: 'include',
      }),
    ];
    server.use(
      http.get(CONTROLS_URL, async () => await okControls(controls)),
      http.get(FILTERS_URL, async () => await okFilters(TEST_FILTERS)),
    );

    // ACT
    renderControlsPageWithSplitPanel();
    const withinMain = within(screen.getByTestId('main-content'));
    await withinMain.findByRole('heading', { name: /Controls\s*\(1\)/ });

    const table = await withinMain.findByRole('table');
    const radioInput = within(table).getByRole('radio');
    await userEvent.click(radioInput);

    await screen.findByText(/Control: S3\.1/);
    const filterModeSelect = screen.getByRole('button', { name: /Include/ });
    await userEvent.click(filterModeSelect);
    const excludeOption = await screen.findByText('Exclude');
    await userEvent.click(excludeOption);

    // ASSERT
    expect(await screen.findByText(/Changing the filter mode will invert/)).toBeInTheDocument();
    expect(await screen.findByText(/you have unsaved changes/i)).toBeInTheDocument();
  });

  it('tracks filter addition via the detail panel multiselect as an unsaved change', async () => {
    // ARRANGE
    const controls = [
      createTestControl({
        controlId: 'S3.1',
        automatedRemediationEnabled: true,
        filters: [],
      }),
    ];
    server.use(
      http.get(CONTROLS_URL, async () => await okControls(controls)),
      http.get(FILTERS_URL, async () => await okFilters(TEST_FILTERS)),
    );

    // ACT
    renderControlsPageWithSplitPanel();
    const withinMain = within(screen.getByTestId('main-content'));
    await withinMain.findByRole('heading', { name: /Controls\s*\(1\)/ });

    const table = await withinMain.findByRole('table');
    const radioInput = within(table).getByRole('radio');
    await userEvent.click(radioInput);

    await screen.findByText(/Control: S3\.1/);
    const multiselect = screen.getByRole('button', { name: /Applied filters/ });
    await userEvent.click(multiselect);
    const prodOption = await screen.findByText('Production Accounts');
    await userEvent.click(prodOption);

    // ASSERT
    expect(await screen.findByText(/you have unsaved changes/i)).toBeInTheDocument();
  });

  it('does not modify controls when read-only user interacts with filter mode', async () => {
    // ARRANGE
    const controls = [
      createTestControl({
        controlId: 'S3.1',
        filters: [FILTER_UUID_1],
        filterMode: 'include',
      }),
    ];
    server.use(
      http.get(CONTROLS_URL, async () => await okControls(controls)),
      http.get(FILTERS_URL, async () => await okFilters(TEST_FILTERS)),
    );

    // ACT
    renderControlsPageWithSplitPanel({ userContextOverrides: { groups: ['AccountOperatorGroup'] } });
    const withinMain = within(screen.getByTestId('main-content'));
    await withinMain.findByRole('heading', { name: /Controls.*\(1\)/ });

    const table = await withinMain.findByRole('table');
    const radioInput = within(table).getByRole('radio');
    await userEvent.click(radioInput);

    await screen.findByText(/Control: S3\.1/);

    // ASSERT - filter mode select is disabled for read-only users
    const filterModeSelect = screen.getByRole('button', { name: /Include/ });
    expect(filterModeSelect).toBeDisabled();
    expect(screen.queryByText(/you have unsaved changes/i)).not.toBeInTheDocument();
  });

  it('opens the detail panel via deep link URL and displays the correct control', async () => {
    // ARRANGE
    const controls = [
      createTestControl({ controlId: 'S3.1', description: 'S3 encryption control' }),
      createTestControl({ controlId: 'EC2.6', description: 'VPC flow logging control' }),
    ];
    server.use(
      http.get(CONTROLS_URL, async () => await okControls(controls)),
      http.get(FILTERS_URL, async () => await okFilters(TEST_FILTERS)),
    );

    // ACT
    renderControlsPageWithSplitPanel({ initialRoute: '/controls?controlId=EC2.6' });

    // ASSERT
    expect(await screen.findByText(/Control: EC2\.6/)).toBeInTheDocument();
    const descriptions = await screen.findAllByText('VPC flow logging control');
    expect(descriptions.length).toBeGreaterThanOrEqual(1);
  });

  describe('deep linking pagination', () => {
    const DEEP_LINK_PREFERENCES = {
      pageSize: 3,
      visibleContent: ['controlId', 'description', 'isEnabled', 'appliedFilters'],
      contentDensity: 'comfortable',
    };

    beforeEach(() => {
      localStorage.setItem('controlsTablePreferences', JSON.stringify(DEEP_LINK_PREFERENCES));
      const controls = generateTestControls(8);
      server.use(
        http.get(CONTROLS_URL, async () => await okControls(controls)),
        http.get(FILTERS_URL, async () => await okFilters(TEST_FILTERS)),
      );
    });

    it('navigates to the correct page when deep linking to a control on page 2+', async () => {
      // ACT - deep link to Lambda.1 which should be on page 2 (sorted: CloudTrail.1, EC2.1, IAM.1 | KMS.1, Lambda.1, RDS.1 | S3.1, VPC.1)
      renderControlsPageWithSplitPanel({ initialRoute: '/controls?controlId=Lambda.1' });

      // ASSERT - detail panel opens for Lambda.1
      expect(await screen.findByText(/Control: Lambda\.1/)).toBeInTheDocument();

      // ASSERT - Lambda.1 is visible in the table (meaning we navigated to the correct page)
      const withinMain = within(screen.getByTestId('main-content'));
      const table = await withinMain.findByRole('table');
      expect(await within(table).findByText('Lambda.1')).toBeInTheDocument();

      // ASSERT - the radio button for Lambda.1 is selected
      const radioInputs = within(table).getAllByRole('radio');
      const selectedRadio = radioInputs.find((radio) => (radio as HTMLInputElement).checked);
      expect(selectedRadio).toBeDefined();
    });

    it('stays on page 1 when deep linking to a control on the first page', async () => {
      // ACT - deep link to CloudTrail.1 which should be on page 1 (first in sorted order)
      renderControlsPageWithSplitPanel({ initialRoute: '/controls?controlId=CloudTrail.1' });

      // ASSERT - detail panel opens for CloudTrail.1
      expect(await screen.findByText(/Control: CloudTrail\.1/)).toBeInTheDocument();

      // ASSERT - CloudTrail.1 is visible in the table
      const withinMain = within(screen.getByTestId('main-content'));
      const table = await withinMain.findByRole('table');
      expect(await within(table).findByText('CloudTrail.1')).toBeInTheDocument();
    });

    it('does not navigate to a different page when controlId param is invalid', async () => {
      // ACT - deep link to a non-existent control
      renderControlsPageWithSplitPanel({ initialRoute: '/controls?controlId=NONEXISTENT.99' });

      // ASSERT - no detail panel opens
      const withinMain = within(screen.getByTestId('main-content'));
      await withinMain.findByRole('heading', { name: /Controls\s*\(8\)/ });
      expect(screen.queryByText(/Control: NONEXISTENT\.99/)).not.toBeInTheDocument();

      // ASSERT - stays on page 1, showing first 3 controls
      const table = await withinMain.findByRole('table');
      expect(await within(table).findByText('CloudTrail.1')).toBeInTheDocument();
      expect(await within(table).findByText('EC2.1')).toBeInTheDocument();
      expect(await within(table).findByText('IAM.1')).toBeInTheDocument();
    });
  });
});
