// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { screen, within, render, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { http, HttpResponse } from 'msw';
import { Provider } from 'react-redux';
import { createMemoryRouter } from 'react-router';
import { RouterProvider } from 'react-router/dom';
import { configureStore } from '@reduxjs/toolkit';
import { useContext } from 'react';

import { MOCK_SERVER_URL, server } from '../server.ts';
import { solutionApi } from '../../store/solutionApi.ts';
import { ok } from '../../mocks/handlers.ts';
import { SecurityControl, ResourceFilter, ResourceFilterInput, UpdateFilterRequest } from '@data-models';
import { mockUserContext } from '../test-data-factory.ts';
import { ResourceFiltersOverviewPage } from '../../pages/resource-filters/ResourceFiltersOverviewPage.tsx';
import { UserContext } from '../../contexts/UserContext.tsx';
import { NotificationContext, NotificationContextProvider } from '../../contexts/NotificationContext.tsx';
import { rootReducer } from '../../store/store.ts';
import Flashbar from '@cloudscape-design/components/flashbar';

const GlobalFlashbar = () => {
  const { notifications } = useContext(NotificationContext);
  return <Flashbar items={notifications} stackItems />;
};

const CONTROLS_URL = MOCK_SERVER_URL + 'controls';
const FILTERS_URL = MOCK_SERVER_URL + 'filters';
const BULK_EDIT_URL = MOCK_SERVER_URL + 'controls/bulk-edit';

const okControls = (controls: SecurityControl[]) => ok({ controls });
const okFilters = (filters: ResourceFilter[]) => ok({ filters });

const FILTER_UUID_1 = '00000000-0000-4000-8000-000000000001';
const FILTER_UUID_2 = '00000000-0000-4000-8000-000000000002';
const FILTER_UUID_3 = '00000000-0000-4000-8000-000000000003';

const createTestFilter = (overrides: Partial<ResourceFilter> = {}): ResourceFilter => ({
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
  ...overrides,
});

const createTestControl = (overrides: Partial<SecurityControl> = {}): SecurityControl => ({
  controlId: 'S3.1',
  description: 'S3 control',
  automatedRemediationEnabled: false,
  filters: [],
  filterMode: 'include',
  version: 1,
  lastModified: '2025-01-01T00:00:00Z',
  modifiedBy: 'system',
  ...overrides,
});

const TEST_FILTERS: ResourceFilter[] = [
  createTestFilter(),
  createTestFilter({
    filterId: FILTER_UUID_2,
    name: 'Development Environment',
    accountIds: ['456789012345'],
    organizationalUnits: ['ou-dev0-12345abc'],
    tags: [{ key: 'Environment', value: 'Development' }],
  }),
  createTestFilter({
    filterId: FILTER_UUID_3,
    name: 'Critical Resources',
    accountIds: [],
    tags: [
      { key: 'Criticality', value: 'High' },
      { key: 'Compliance', value: 'Required' },
    ],
    arnPatterns: ['arn:aws:s3:::*'],
  }),
];

const TEST_CONTROLS: SecurityControl[] = [
  createTestControl({ controlId: 'S3.1', filters: [FILTER_UUID_1] }),
  createTestControl({ controlId: 'EC2.1', filters: [FILTER_UUID_1, FILTER_UUID_2] }),
  createTestControl({ controlId: 'IAM.1', filters: [] }),
];

interface RenderOptions {
  userContextOverrides?: Partial<typeof mockUserContext>;
}

const renderFiltersPage = ({ userContextOverrides }: RenderOptions = {}) => {
  const store = configureStore({
    reducer: rootReducer,
    middleware: (getDefaultMiddleware) => getDefaultMiddleware().concat(solutionApi.middleware),
  });

  const contextValue = { ...mockUserContext, ...userContextOverrides };

  const router = createMemoryRouter(
    [
      {
        path: '/resource-filters',
        element: (
          <main>
            <ResourceFiltersOverviewPage />
          </main>
        ),
      },
    ],
    { initialEntries: ['/resource-filters'] },
  );

  return render(
    <Provider store={store}>
      <UserContext.Provider value={contextValue}>
        <NotificationContextProvider>
          <GlobalFlashbar />
          <RouterProvider router={router} />
        </NotificationContextProvider>
      </UserContext.Provider>
    </Provider>,
  );
};

const withinMain = () => within(screen.getByRole('main'));

/** Find a button inside the currently visible Cloudscape dialog. */
const findVisibleDialogButton = (name: RegExp) => {
  const dialogs = screen.getAllByRole('dialog');
  const visibleDialog = dialogs.find((d) => !d.className.includes('hidden'));
  if (!visibleDialog) throw new Error('No visible dialog found');
  return within(visibleDialog).getByRole('button', { name });
};

/** Click a Cloudscape ButtonDropdown menu item by text after opening the dropdown. */
const clickDropdownMenuItem = async (menuItemText: string) => {
  const menuItems = await screen.findAllByRole('menuitem');
  const target = menuItems.find((el) => el.textContent === menuItemText);
  if (!target) throw new Error(`Menu item "${menuItemText}" not found`);
  await userEvent.click(target);
};

/**
 * Set up MSW handlers, render the page, and wait for data to load.
 * Returns the scoped `within(main)` query object.
 */
const renderAndWaitForData = async (
  filters: ResourceFilter[],
  controls: SecurityControl[],
  renderOptions?: RenderOptions,
) => {
  server.use(
    http.get(FILTERS_URL, async () => await okFilters(filters)),
    http.get(CONTROLS_URL, async () => await okControls(controls)),
  );
  renderFiltersPage(renderOptions);
  const main = withinMain();
  const countPattern = new RegExp(`Resource Filters.*\\(${filters.length}\\)`);
  await main.findByRole('heading', { name: countPattern });
  return main;
};

/** Open the actions dropdown for a given filter name and click a menu item. */
const openActionsDropdownFor = async (
  main: ReturnType<typeof withinMain>,
  filterName: string,
  menuItemText: string,
) => {
  const actionsButton = await main.findByRole('button', { name: `Actions for ${filterName}` });
  await userEvent.click(actionsButton);
  await clickDropdownMenuItem(menuItemText);
};

/** Render the page with empty filters/controls, wait for empty state, and open the create form. */
const renderEmptyPageAndOpenCreateForm = async () => {
  server.use(
    http.get(FILTERS_URL, async () => await okFilters([])),
    http.get(CONTROLS_URL, async () => await okControls([])),
  );
  renderFiltersPage();
  const main = withinMain();
  await main.findByText('No resource filters to display.');
  const createButton = main.getByRole('button', { name: /create resource filter/i });
  await userEvent.click(createButton);
};

/** Open the create form on an empty page, type a filter name, and return the submit button. */
const openCreateFormAndFillName = async (name: string) => {
  await renderEmptyPageAndOpenCreateForm();
  const nameInput = await screen.findByPlaceholderText('e.g., Production Accounts');
  await userEvent.type(nameInput, name);
  return screen.getByRole('button', { name: /^Create$/i });
};

describe('ResourceFiltersOverviewPage', () => {
  it('renders empty state with header counter (0) and create button', async () => {
    // ARRANGE
    server.use(
      http.get(FILTERS_URL, async () => await okFilters([])),
      http.get(CONTROLS_URL, async () => await okControls([])),
    );

    // ACT
    renderFiltersPage();

    // ASSERT
    const main = withinMain();
    expect(await main.findByText('No resource filters to display.')).toBeInTheDocument();
    expect(main.getByRole('heading', { name: /Resource Filters\s*\(0\)/ })).toBeInTheDocument();
    expect(main.getByRole('button', { name: /create resource filter/i })).toBeInTheDocument();
  });

  it('renders filters with correct header counter, usage counts, column data, and summary badges', async () => {
    // ARRANGE / ACT
    const main = await renderAndWaitForData(TEST_FILTERS, TEST_CONTROLS);

    // ASSERT
    expect(main.getByRole('heading', { name: /Resource Filters\s*\(3\)/ })).toBeInTheDocument();

    const table = await main.findByRole('table');
    expect(await within(table).findByText('Production Accounts')).toBeInTheDocument();
    expect(await within(table).findByText('Development Environment')).toBeInTheDocument();
    expect(await within(table).findByText('Critical Resources')).toBeInTheDocument();

    expect(await main.findByText('S3.1')).toBeInTheDocument();
    expect((await main.findAllByText('EC2.1')).length).toBe(2);
    // "Unused" now appears in both the Controls-usage column (one filter has
    // no controls attached) and the Notifications-usage column (no
    // notification configs are seeded). Assert presence without over-specifying
    // how many cells match.
    expect((await main.findAllByText('Unused')).length).toBeGreaterThanOrEqual(1);

    expect(await within(table).findByText('123456789012')).toBeInTheDocument();
    expect(await within(table).findByText('456789012345')).toBeInTheDocument();
    expect(await within(table).findByText('ou-dev0-12345abc')).toBeInTheDocument();
    expect(await within(table).findByText('Environment=Development')).toBeInTheDocument();
    expect(await within(table).findByText('arn:aws:s3:::*')).toBeInTheDocument();

    const modifiedByCells = await within(table).findAllByText('admin');
    expect(modifiedByCells.length).toBeGreaterThanOrEqual(3);
    const lastModifiedCells = await within(table).findAllByText(new Date('2025-01-01T00:00:00Z').toLocaleString());
    expect(lastModifiedCells.length).toBeGreaterThanOrEqual(3);
  });

  it('filters by search text (name, account ID, OU, tag) and clears the filter', async () => {
    // ARRANGE / ACT
    const main = await renderAndWaitForData(TEST_FILTERS, []);

    const searchInput = await main.findByPlaceholderText('Search resource filters...');
    const table = await main.findByRole('table');

    // search by name
    await userEvent.type(searchInput, 'production');
    let rows = await within(table).findAllByRole('row');
    expect(rows).toHaveLength(2);

    // search by account ID
    await userEvent.clear(searchInput);
    await userEvent.type(searchInput, '456789012345');
    rows = await within(table).findAllByRole('row');
    expect(rows).toHaveLength(2);

    // search by OU
    await userEvent.clear(searchInput);
    await userEvent.type(searchInput, 'ou-dev0');
    rows = await within(table).findAllByRole('row');
    expect(rows).toHaveLength(2);

    // search by tag value
    await userEvent.clear(searchInput);
    await userEvent.type(searchInput, 'High');
    rows = await within(table).findAllByRole('row');
    expect(rows).toHaveLength(2);

    // no match shows empty state, clear restores all
    await userEvent.clear(searchInput);
    await userEvent.type(searchInput, 'nonexistent');
    expect(await main.findByText(/no matches/i)).toBeInTheDocument();

    const clearButton = await main.findByRole('button', { name: 'Clear filter' });
    await userEvent.click(clearButton);
    rows = await within(table).findAllByRole('row');
    expect(rows).toHaveLength(4);
  });

  it('shows loading state while data is being fetched', async () => {
    // ARRANGE
    server.use(
      http.get(FILTERS_URL, async () => {
        await new Promise((resolve) => setTimeout(resolve, 500));
        return await okFilters([]);
      }),
      http.get(CONTROLS_URL, async () => await okControls([])),
    );

    // ACT
    renderFiltersPage();

    // ASSERT
    expect(await withinMain().findByText('Loading resource filters')).toBeInTheDocument();
  });

  it('opens delete modal with affected controls, confirms delete, and shows success notification', async () => {
    // ARRANGE
    const singleFilter = [createTestFilter()];
    const controlsUsingFilter = [
      createTestControl({ controlId: 'S3.1', filters: [FILTER_UUID_1] }),
      createTestControl({ controlId: 'EC2.1', filters: [FILTER_UUID_1] }),
    ];
    let deleteCalled = false;
    server.use(
      http.delete(`${FILTERS_URL}/:filterId`, async () => {
        deleteCalled = true;
        return await ok({ message: 'Deleted' });
      }),
    );
    const main = await renderAndWaitForData(singleFilter, controlsUsingFilter);

    // ACT
    await openActionsDropdownFor(main, 'Production Accounts', 'Delete');

    // ASSERT - delete modal shows with affected controls
    expect(await screen.findByText(/delete resource filter/i)).toBeInTheDocument();
    expect(await screen.findByText(/this filter is currently in use/i)).toBeInTheDocument();
    const modals = await screen.findAllByRole('dialog');
    const modal = modals.find((m) => !m.className.includes('hidden'))!;
    expect(within(modal).getByText('S3.1')).toBeInTheDocument();
    expect(within(modal).getByText('EC2.1')).toBeInTheDocument();

    // ACT - confirm delete
    const confirmButton = findVisibleDialogButton(/delete/i);
    await userEvent.click(confirmButton);

    // ASSERT
    await waitFor(() => expect(deleteCalled).toBe(true));
    expect(await screen.findByText(/deleted successfully/i)).toBeInTheDocument();
  });

  it('opens and cancels the delete confirmation modal for an unused filter', async () => {
    // ARRANGE
    const unusedFilter = [createTestFilter({ filterId: FILTER_UUID_3, name: 'Unused Filter', accountIds: [] })];
    const main = await renderAndWaitForData(unusedFilter, []);

    // ACT - open the delete confirmation
    await openActionsDropdownFor(main, 'Unused Filter', 'Delete');

    // ASSERT - the confirmation modal renders with the filter name
    const openDialogs = await screen.findAllByRole('dialog');
    const visibleOpenDialog = openDialogs.find((d) => !d.className.includes('hidden'));
    if (!visibleOpenDialog) throw new Error('Expected a visible dialog after opening the delete modal');
    expect(within(visibleOpenDialog).getByText(/Unused Filter/)).toBeInTheDocument();

    // ACT - cancel
    const cancelButton = findVisibleDialogButton(/cancel/i);
    await userEvent.click(cancelButton);

    // ASSERT - the delete modal is hidden (Cloudscape keeps it in DOM but hidden)
    await waitFor(() => {
      const dialogs = screen.getAllByRole('dialog');
      const visibleDialogs = dialogs.filter((d) => !d.className.includes('hidden'));
      expect(visibleDialogs).toHaveLength(0);
    });
  });

  it('shows error notification when delete fails', async () => {
    // ARRANGE
    const singleFilter = [createTestFilter()];
    server.use(
      http.delete(`${FILTERS_URL}/:filterId`, async () => {
        return HttpResponse.json({ message: 'Internal server error' }, { status: 500 });
      }),
    );
    const main = await renderAndWaitForData(singleFilter, []);

    // ACT
    await openActionsDropdownFor(main, 'Production Accounts', 'Delete');
    const confirmButton = findVisibleDialogButton(/delete/i);
    await userEvent.click(confirmButton);

    // ASSERT
    expect(await screen.findByText(/failed to delete filter/i)).toBeInTheDocument();
  });

  it('opens create form modal when "Create resource filter" button is clicked', async () => {
    // ARRANGE / ACT
    await renderEmptyPageAndOpenCreateForm();

    // ASSERT
    expect(await screen.findByText('Filter name')).toBeInTheDocument();
  });

  it('opens edit form modal via actions dropdown', async () => {
    // ARRANGE
    const main = await renderAndWaitForData([createTestFilter()], []);

    // ACT
    await openActionsDropdownFor(main, 'Production Accounts', 'Edit');

    // ASSERT
    expect(await screen.findByText(/edit resource filter/i)).toBeInTheDocument();
  });

  it('shows "Apply to all controls" confirmation dialog and calls bulk-edit on confirm', async () => {
    // ARRANGE
    const singleFilter = [createTestFilter({ filterId: FILTER_UUID_3, name: 'Critical Resources', accountIds: [] })];
    let capturedBody: unknown = null;
    server.use(
      http.post(BULK_EDIT_URL, async ({ request }) => {
        capturedBody = await request.json();
        return await ok({ message: 'Controls updated successfully', updatedCount: 3 });
      }),
    );
    const main = await renderAndWaitForData(singleFilter, TEST_CONTROLS);

    // ACT
    await openActionsDropdownFor(main, 'Critical Resources', 'Apply to all controls');

    // ASSERT - confirmation dialog
    expect(await screen.findByText(/apply filter to all controls/i)).toBeInTheDocument();
    expect(await screen.findByText(/3 controls/)).toBeInTheDocument();

    // ACT - confirm
    const confirmButton = findVisibleDialogButton(/confirm/i);
    await userEvent.click(confirmButton);

    // ASSERT
    await waitFor(() => expect(capturedBody).not.toBeNull());
    expect(capturedBody).toMatchObject({
      operation: 'applyFilterToAll',
      data: FILTER_UUID_3,
    });
    expect(await screen.findByText(/applied to all controls successfully/i)).toBeInTheDocument();
  });

  it('shows "Remove from all controls" confirmation dialog with affected count and calls bulk-edit', async () => {
    // ARRANGE
    const singleFilter = [createTestFilter()];
    const controlsUsingFilter = [
      createTestControl({ controlId: 'S3.1', filters: [FILTER_UUID_1] }),
      createTestControl({ controlId: 'EC2.1', filters: [FILTER_UUID_1] }),
    ];
    let capturedBody: unknown = null;
    server.use(
      http.post(BULK_EDIT_URL, async ({ request }) => {
        capturedBody = await request.json();
        return await ok({ message: 'Controls updated successfully', updatedCount: 2 });
      }),
    );
    const main = await renderAndWaitForData(singleFilter, controlsUsingFilter);

    // ACT
    await openActionsDropdownFor(main, 'Production Accounts', 'Remove from all controls');

    // ASSERT - confirmation dialog
    expect(await screen.findByText(/remove filter from all controls/i)).toBeInTheDocument();

    // ACT - confirm
    const confirmButton = findVisibleDialogButton(/confirm/i);
    await userEvent.click(confirmButton);

    // ASSERT
    await waitFor(() => expect(capturedBody).not.toBeNull());
    expect(capturedBody).toMatchObject({
      operation: 'removeFilterFromAll',
      data: FILTER_UUID_1,
    });
    expect(await screen.findByText(/removed from all controls successfully/i)).toBeInTheDocument();
  });

  it('shows warning notification on bulk-edit partial failure', async () => {
    // ARRANGE
    server.use(
      http.post(BULK_EDIT_URL, async () => {
        return await ok({ message: 'Partial success', successCount: 1, failedControlIds: ['S3.1', 'EC2.1'] });
      }),
    );
    const main = await renderAndWaitForData([createTestFilter()], TEST_CONTROLS);

    // ACT
    await openActionsDropdownFor(main, 'Production Accounts', 'Apply to all controls');
    const confirmButton = findVisibleDialogButton(/confirm/i);
    await userEvent.click(confirmButton);

    // ASSERT
    expect(await screen.findByText(/some controls failed to update/i)).toBeInTheDocument();
  });

  it('shows error notification on bulk-edit failure', async () => {
    // ARRANGE
    server.use(
      http.post(BULK_EDIT_URL, async () => {
        return HttpResponse.json({ message: 'Server error' }, { status: 500 });
      }),
    );
    const main = await renderAndWaitForData([createTestFilter()], TEST_CONTROLS);

    // ACT
    await openActionsDropdownFor(main, 'Production Accounts', 'Apply to all controls');
    const confirmButton = findVisibleDialogButton(/confirm/i);
    await userEvent.click(confirmButton);

    // ASSERT
    expect(await screen.findByText(/bulk operation failed/i)).toBeInTheDocument();
  });

  it('cancels bulk action dialog without making API call', async () => {
    // ARRANGE
    let bulkEditCalled = false;
    server.use(
      http.post(BULK_EDIT_URL, async () => {
        bulkEditCalled = true;
        return await ok({ message: 'ok', updatedCount: 1 });
      }),
    );
    const main = await renderAndWaitForData([createTestFilter()], TEST_CONTROLS);

    // ACT
    await openActionsDropdownFor(main, 'Production Accounts', 'Apply to all controls');
    expect(await screen.findByText(/apply filter to all controls/i)).toBeInTheDocument();

    // ACT - cancel via the visible modal's Cancel button
    const dialogs = screen.getAllByRole('dialog');
    const visibleDialog = dialogs.find((d) => !d.className.includes('hidden'));
    if (!visibleDialog) throw new Error('Expected a visible dialog');
    const cancelButton = within(visibleDialog).getByRole('button', { name: /cancel/i });
    await userEvent.click(cancelButton);

    // ASSERT - all dialogs should be hidden after cancel
    await waitFor(() => {
      const allDialogs = screen.getAllByRole('dialog');
      const stillVisible = allDialogs.filter((d) => !d.className.includes('hidden'));
      expect(stillVisible).toHaveLength(0);
    });
    expect(bulkEditCalled).toBe(false);
  });

  it('hides create button and action dropdowns for read-only users', async () => {
    // ARRANGE / ACT
    const main = await renderAndWaitForData(TEST_FILTERS, [], {
      userContextOverrides: { groups: ['AccountOperatorGroup'] },
    });

    // ASSERT - read-only badge is displayed
    const heading = main.getByRole('heading', { name: /Resource Filters.*\(3\)/ });
    expect(heading).toHaveTextContent('Read-only');

    // ASSERT - create button and action dropdowns are hidden
    expect(main.queryByRole('button', { name: /create resource filter/i })).not.toBeInTheDocument();
    expect(main.queryByRole('button', { name: /Actions for Production Accounts/ })).not.toBeInTheDocument();
  });

  it('filters by usage dropdown: "Used filters" and "Unused filters"', async () => {
    // ARRANGE / ACT
    const main = await renderAndWaitForData(TEST_FILTERS, TEST_CONTROLS);
    const table = await main.findByRole('table');

    // select "Used filters"
    const usageSelect = main.getAllByLabelText('Filter by usage')[0];
    await userEvent.click(usageSelect);
    const usedOption = await screen.findByRole('option', { name: 'Used filters' });
    await userEvent.click(usedOption);

    // ASSERT - only used filters shown
    await waitFor(() => {
      const usedRows = within(table).getAllByRole('row');
      expect(usedRows).toHaveLength(3);
    });
    expect(within(table).queryByText('Critical Resources')).not.toBeInTheDocument();
    expect(main.getByRole('heading', { name: /Resource Filters\s*\(2\/3\)/ })).toBeInTheDocument();

    // select "Unused filters"
    await userEvent.click(usageSelect);
    const unusedOption = await screen.findByRole('option', { name: 'Unused filters' });
    await userEvent.click(unusedOption);

    // ASSERT - only unused filters shown
    await waitFor(() => {
      const unusedRows = within(table).getAllByRole('row');
      expect(unusedRows).toHaveLength(2);
    });
    expect(await within(table).findByText('Critical Resources')).toBeInTheDocument();
    expect(within(table).queryByText('Production Accounts')).not.toBeInTheDocument();
    expect(main.getByRole('heading', { name: /Resource Filters\s*\(1\/3\)/ })).toBeInTheDocument();

    // select "All filters" to restore
    await userEvent.click(usageSelect);
    const allOption = await screen.findByRole('option', { name: 'All filters' });
    await userEvent.click(allOption);

    await waitFor(() => {
      const allRows = within(table).getAllByRole('row');
      expect(allRows).toHaveLength(4);
    });
    expect(main.getByRole('heading', { name: /Resource Filters\s*\(3\)/ })).toBeInTheDocument();
  });

  it('does not show "Remove from all controls" action for unused filters', async () => {
    // ARRANGE
    const unusedFilter = [createTestFilter({ filterId: FILTER_UUID_3, name: 'Unused Filter', accountIds: [] })];
    const main = await renderAndWaitForData(unusedFilter, TEST_CONTROLS);

    // ACT
    const actionsButton = await main.findByRole('button', { name: 'Actions for Unused Filter' });
    await userEvent.click(actionsButton);

    // ASSERT
    const menuItems = await screen.findAllByRole('menuitem');
    const menuTexts = menuItems.map((el) => el.textContent);
    expect(menuTexts).toContain('Edit');
    expect(menuTexts).toContain('Delete');
    expect(menuTexts).toContain('Apply to all controls');
    expect(menuTexts).not.toContain('Remove from all controls');
  });

  it('creates a filter successfully via the form and shows success notification', async () => {
    // ARRANGE
    let capturedBody: ResourceFilterInput | null = null;
    server.use(
      http.get(FILTERS_URL, async () => await okFilters([])),
      http.get(CONTROLS_URL, async () => await okControls([])),
      http.post(FILTERS_URL, async ({ request }) => {
        const body = (await request.json()) as ResourceFilterInput;
        capturedBody = body;
        return await ok({
          filterId: crypto.randomUUID(),
          ...body,
          version: 1,
          createdAt: new Date().toISOString(),
          createdBy: 'test-user',
          lastModified: new Date().toISOString(),
          modifiedBy: 'test-user',
        });
      }),
    );

    // ACT
    const submitButton = await openCreateFormAndFillName('New Test Filter');
    await userEvent.click(submitButton);

    // ASSERT
    await waitFor(() => expect(capturedBody).not.toBeNull());
    expect(capturedBody).toMatchObject({ name: 'New Test Filter' });
    expect(await screen.findByText(/created successfully/i)).toBeInTheDocument();
  });

  it('shows 409 conflict error when creating a filter and closes form', async () => {
    // ARRANGE
    server.use(
      http.post(FILTERS_URL, async () => {
        return HttpResponse.json({ message: 'Conflict' }, { status: 409 });
      }),
    );

    // ACT
    const submitButton = await openCreateFormAndFillName('Duplicate Name');
    await userEvent.click(submitButton);

    // ASSERT - error shown and form closed so user must reopen with fresh data
    expect(await screen.findByText(/modified by another user/i)).toBeInTheDocument();
    await waitFor(() => {
      expect(screen.queryByRole('button', { name: /^Create$/i })).not.toBeInTheDocument();
    });
  });

  it('updates a filter successfully via the edit form', async () => {
    // ARRANGE
    let capturedBody: UpdateFilterRequest | null = null;
    server.use(
      http.put(`${FILTERS_URL}/:filterId`, async ({ request }) => {
        const body = (await request.json()) as UpdateFilterRequest;
        capturedBody = body;
        return await ok(body);
      }),
    );
    const main = await renderAndWaitForData([createTestFilter()], []);

    // ACT
    await openActionsDropdownFor(main, 'Production Accounts', 'Edit');

    const nameInput = await screen.findByDisplayValue('Production Accounts');
    await userEvent.clear(nameInput);
    await userEvent.type(nameInput, 'Updated Filter Name');

    const saveButton = screen.getByRole('button', { name: /^Save$/i });
    await userEvent.click(saveButton);

    // ASSERT
    await waitFor(() => expect(capturedBody).not.toBeNull());
    expect(capturedBody).toMatchObject({ name: 'Updated Filter Name', version: 1 });
    expect(await screen.findByText(/updated successfully/i)).toBeInTheDocument();
  });

  it('shows generic error notification when create filter fails with non-409 error and keeps form open', async () => {
    // ARRANGE
    server.use(
      http.post(FILTERS_URL, async () => {
        return HttpResponse.json({ message: 'Validation failed' }, { status: 400 });
      }),
    );

    // ACT
    const submitButton = await openCreateFormAndFillName('Bad Filter');
    await userEvent.click(submitButton);

    // ASSERT - error shown and form stays open so user can retry
    expect(await screen.findByText(/failed to create filter/i)).toBeInTheDocument();
    expect(screen.getByDisplayValue('Bad Filter')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /^Create$/i })).toBeInTheDocument();
  });

  it('rejects invalid account IDs and accepts valid ones as token chips', async () => {
    // ARRANGE
    await renderEmptyPageAndOpenCreateForm();
    const accountInput = await screen.findByLabelText('AWS Account ID input');

    // ACT - enter invalid account ID (too short)
    await userEvent.type(accountInput, '12345');
    await userEvent.keyboard('{Enter}');

    // ASSERT - error shown, no token created
    expect(await screen.findByText(/Account ID must be exactly 12 digits/i)).toBeInTheDocument();
    expect(screen.queryByText('12345')).not.toBeInTheDocument();

    // ACT - enter invalid account ID (letters)
    await userEvent.clear(accountInput);
    await userEvent.type(accountInput, 'abcdefghijkl');
    await userEvent.keyboard('{Enter}');

    // ASSERT - error persists
    expect(screen.getByText(/Account ID must be exactly 12 digits/i)).toBeInTheDocument();

    // ACT - enter valid account ID
    await userEvent.clear(accountInput);
    await userEvent.type(accountInput, '123456789012');
    await userEvent.keyboard('{Enter}');

    // ASSERT - error cleared, token created, input cleared
    await waitFor(() => expect(screen.queryByText(/Account ID must be exactly 12 digits/i)).not.toBeInTheDocument());
    expect(screen.getByText('123456789012')).toBeInTheDocument();
    expect(accountInput).toHaveValue('');

    // ACT - enter duplicate account ID
    await userEvent.type(accountInput, '123456789012');
    await userEvent.keyboard('{Enter}');

    // ASSERT - no duplicate token, input cleared
    const tokens = screen.getAllByText('123456789012');
    expect(tokens).toHaveLength(1);
  });

  it('rejects invalid OU IDs and accepts valid ones as token chips', async () => {
    // ARRANGE
    await renderEmptyPageAndOpenCreateForm();
    const ouInput = await screen.findByLabelText('Organizational Unit input');

    // ACT - enter invalid OU ID (wrong format)
    await userEvent.type(ouInput, 'invalid-ou');
    await userEvent.keyboard('{Enter}');

    // ASSERT - error shown, no token created
    expect(await screen.findByText(/OU ID must match pattern/i)).toBeInTheDocument();
    expect(screen.queryByText('invalid-ou')).not.toBeInTheDocument();

    // ACT - enter valid OU ID
    await userEvent.clear(ouInput);
    await userEvent.type(ouInput, 'ou-abcd-12345678');
    await userEvent.keyboard('{Enter}');

    // ASSERT - error cleared, token created, input cleared
    await waitFor(() => expect(screen.queryByText(/OU ID must match pattern/i)).not.toBeInTheDocument());
    expect(screen.getByText('ou-abcd-12345678')).toBeInTheDocument();
    expect(ouInput).toHaveValue('');
  });

  it('rejects invalid ARN patterns and accepts valid ones as token chips', async () => {
    // ARRANGE
    await renderEmptyPageAndOpenCreateForm();
    const arnInput = await screen.findByLabelText('ARN Pattern input');

    // ACT - enter invalid ARN (missing partition)
    await userEvent.type(arnInput, 'not-an-arn');
    await userEvent.keyboard('{Enter}');

    // ASSERT - error shown, no token created
    expect(await screen.findByText(/ARN must follow/i)).toBeInTheDocument();
    expect(screen.queryByText('not-an-arn')).not.toBeInTheDocument();

    // ACT - enter valid ARN pattern
    await userEvent.clear(arnInput);
    await userEvent.type(arnInput, 'arn:aws:s3:::my-bucket*');
    await userEvent.keyboard('{Enter}');

    // ASSERT - error cleared, token created, input cleared
    await waitFor(() => expect(screen.queryByText(/ARN must follow/i)).not.toBeInTheDocument());
    expect(screen.getByText('arn:aws:s3:::my-bucket*')).toBeInTheDocument();
    expect(arnInput).toHaveValue('');
  });

  it('prevents form submission when tag key or value is empty', async () => {
    // ARRANGE
    server.use(http.post(FILTERS_URL, async () => await ok({})));
    await renderEmptyPageAndOpenCreateForm();

    // fill in name so that's not the blocker
    const nameInput = await screen.findByPlaceholderText('e.g., Production Accounts');
    await userEvent.type(nameInput, 'Tag Test Filter');

    // add a valid account ID so filter has at least one criterion
    const accountInput = await screen.findByLabelText('AWS Account ID input');
    await userEvent.type(accountInput, '111111111111');
    await userEvent.keyboard('{Enter}');

    // ACT - add a tag with empty key and value
    const addTagButton = screen.getByRole('button', { name: /add tag/i });
    await userEvent.click(addTagButton);

    // fill only the value, leave key empty
    const valueInput = await screen.findByPlaceholderText('Enter tag value');
    await userEvent.type(valueInput, 'SomeValue');

    const submitButton = screen.getByRole('button', { name: /^Create$/i });
    await userEvent.click(submitButton);

    // ASSERT - tag validation error shown
    expect(await screen.findByText(/Tag keys and values cannot be empty/i)).toBeInTheDocument();
  });

  it('shows summary badges for >2 tags, >2 accounts, >2 OUs, and >2 ARN patterns', async () => {
    // ARRANGE
    const filterWithManyCriteria = createTestFilter({
      filterId: FILTER_UUID_1,
      name: 'Complex Filter',
      accountIds: ['111111111111', '222222222222', '333333333333'],
      organizationalUnits: ['ou-aaaa-11111111', 'ou-bbbb-22222222', 'ou-cccc-33333333'],
      tags: [
        { key: 'Env', value: 'Prod' },
        { key: 'Team', value: 'Eng' },
        { key: 'Cost', value: 'High' },
      ],
      arnPatterns: ['arn:aws:s3:::bucket1', 'arn:aws:s3:::bucket2', 'arn:aws:ec2:*:*:instance/*'],
    });

    // ACT
    const main = await renderAndWaitForData([filterWithManyCriteria], []);

    // ASSERT
    expect(await main.findByText('3 accounts')).toBeInTheDocument();
    expect(await main.findByText('3 OUs')).toBeInTheDocument();
    expect(await main.findByText('3 tags')).toBeInTheDocument();
    expect(await main.findByText('3 ARN patterns')).toBeInTheDocument();
  });
});
