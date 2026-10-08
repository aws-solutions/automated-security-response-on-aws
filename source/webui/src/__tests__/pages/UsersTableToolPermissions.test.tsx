// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { Provider } from 'react-redux';
import { ReactNode } from 'react';
import { http, HttpResponse } from 'msw';
import UsersTable from '../../pages/users/users-table/UsersTable';
import { AccountOperatorUser, DelegatedAdminUser, User } from '@data-models';
import { setupStore } from '../../store/store';
import { UserContext } from '../../contexts/UserContext';
import { server, MOCK_SERVER_URL } from '../server';
import { getUsersHandler, ok } from '../../mocks/handlers';

const mockRefresh = vi.fn();

// Two target users the tool table renders for: an Account Operator carrying an existing
// grant, and a Delegated Admin. Admins are intentionally omitted — they receive every
// tool implicitly, so the modal shows no editable grant for them.
//
// The target's tier decides which catalog rows appear, so tests that need a Delegated
// Admin-only tool (execute_runbook, create_filter) must target the Delegated Admin: the
// API refuses to store those for an Account Operator, so the table does not offer them.
const accountOperator: AccountOperatorUser = {
  email: 'operator1@example.com',
  type: 'account-operator',
  accountIds: ['123456789012'],
  allowedMcpTools: ['execute_finding_action'],
  invitedBy: 'admin@example.com',
  invitationTimestamp: new Date().toISOString(),
  status: 'Confirmed',
};

const delegatedAdmin: DelegatedAdminUser = {
  email: 'delegate1@example.com',
  type: 'delegated-admin',
  allowedMcpTools: ['execute_finding_action'],
  invitedBy: 'admin@example.com',
  invitationTimestamp: new Date().toISOString(),
  status: 'Confirmed',
};

// An Account Operator whose stored grant illegitimately includes a Delegated Admin-only
// tool (execute_runbook). The table hides that tool for an Account Operator target, so the
// Admin cannot see or revoke it — the save path must drop it rather than re-submit it.
const accountOperatorWithHiddenTool: AccountOperatorUser = {
  email: 'operator2@example.com',
  type: 'account-operator',
  accountIds: ['123456789012'],
  allowedMcpTools: ['execute_finding_action', 'execute_runbook'],
  invitedBy: 'admin@example.com',
  invitationTimestamp: new Date().toISOString(),
  status: 'Confirmed',
};

const testUsers: User[] = [accountOperator, delegatedAdmin, accountOperatorWithHiddenTool];

function renderWithViewer(groups: string[]) {
  const store = setupStore();
  const userContextValue = {
    user: null,
    email: 'viewer@example.com',
    groups,
    signOut: () => Promise.resolve(),
    signInWithRedirect: () => Promise.resolve(),
    checkUser: () => Promise.resolve(),
  };
  const Wrapper = ({ children }: { children: ReactNode }) => (
    <Provider store={store}>
      <UserContext.Provider value={userContextValue}>{children}</UserContext.Provider>
    </Provider>
  );
  return render(<UsersTable users={testUsers} loading={false} onRefresh={mockRefresh} />, { wrapper: Wrapper });
}

// Select the row for `email`, then open Manage User. The row is located by its email cell
// rather than by radio order so adding a user does not silently retarget other tests.
async function openManageUserModal(email = 'operator1@example.com') {
  const row = (await screen.findByText(email)).closest('tr');
  if (!row) throw new Error(`No table row found for ${email}`);
  await userEvent.click(within(row).getByRole('radio'));
  await userEvent.click(screen.getByRole('button', { name: /manage user/i }));
  return screen.findByRole('dialog', { name: /manage user/i });
}

const DELEGATED_ADMIN = 'delegate1@example.com';

describe('UsersTable tool permissions', () => {
  beforeEach(() => {
    mockRefresh.mockClear();
    server.use(getUsersHandler(MOCK_SERVER_URL));
  });

  it('shows the tool permissions table with the user’s existing grant reflected', async () => {
    renderWithViewer(['AdminGroup']);
    const dialog = await openManageUserModal(DELEGATED_ADMIN);

    const table = await within(dialog).findByTestId('tool-permissions-table');
    // Catalog rows come from the mocked GET /mcp/tools handler. Groups start expanded,
    // so every tool is visible without interacting with the category rows.
    await within(table).findByText('execute_finding_action');
    within(table).getByText('execute_runbook');
    within(table).getByText('Remediation');
    within(table).getByText('Policy & controls');

    // The granted tool is checked; the ungranted one is not. Find each checkbox by
    // its accessible label — the same path assistive technology would use.
    expect(await within(dialog).findByLabelText('Grant execute_finding_action')).toBeChecked();
    expect(within(dialog).getByLabelText('Grant execute_runbook')).not.toBeChecked();
  });

  it('offers an Account Operator only the tools their tier can hold', async () => {
    // PUT /users/{id}/mcp-tools rejects the whole grant if it names a tool above the
    // target's tier, so a Delegated Admin-only tool must not be offered for an Account
    // Operator at all. Without this, a mixed category's grant-all builds a set that the
    // API refuses, and the Admin sees a failed save with no way to tell which tool caused it.
    renderWithViewer(['AdminGroup']);
    const dialog = await openManageUserModal();

    const table = await within(dialog).findByTestId('tool-permissions-table');
    await within(table).findByText('execute_finding_action');
    within(table).getByText('list_filters');

    expect(within(table).queryByText('execute_runbook')).not.toBeInTheDocument();
    expect(within(table).queryByText('create_filter')).not.toBeInTheDocument();

    // Each category now holds only its Account Operator tool, so grant-all cannot
    // produce an unsaveable set and no group reports a Delegated Admin minimum.
    expect(within(table).getAllByText('1 of 1 granted').length).toBeGreaterThanOrEqual(1);
    expect(within(table).queryByText('Delegated Admin')).not.toBeInTheDocument();
  });

  it('drops a hidden above-tier tool from the submitted grant instead of re-submitting it', async () => {
    // operator2 stores execute_runbook (Delegated Admin-only), which the table hides for an
    // Account Operator. Seeded from the full stored grant, it stays in the editable set; the
    // save path must intersect the submission with the target's tier so the hidden tool is
    // not re-sent, which would fail the whole PUT.
    const putSpy = vi.fn();
    server.use(
      http.put(`${MOCK_SERVER_URL}users/:id/mcp-tools`, async ({ request }) => {
        const body = (await request.json()) as { allowedTools: string[] };
        putSpy(body.allowedTools);
        return ok({ email: 'operator2@example.com', allowedMcpTools: body.allowedTools });
      }),
    );

    renderWithViewer(['AdminGroup']);
    const dialog = await openManageUserModal('operator2@example.com');

    const table = await within(dialog).findByTestId('tool-permissions-table');
    // Toggle an in-tier tool so the tools write runs, then save.
    await userEvent.click(await within(table).findByLabelText('Grant list_filters'));
    await userEvent.click(within(dialog).getByRole('button', { name: /save/i }));

    await waitFor(() => expect(putSpy).toHaveBeenCalledTimes(1));
    const submitted = putSpy.mock.calls[0][0] as string[];
    expect(submitted).toContain('execute_finding_action');
    expect(submitted).toContain('list_filters');
    // The hidden Delegated Admin-only tool is not re-submitted.
    expect(submitted).not.toContain('execute_runbook');
  });

  it('groups tools by category, showing the group’s minimum tier and partial grant state', async () => {
    renderWithViewer(['AdminGroup']);
    const dialog = await openManageUserModal(DELEGATED_ADMIN);

    const table = await within(dialog).findByTestId('tool-permissions-table');

    // Remediation holds one granted tool (execute_finding_action) and one ungranted
    // (execute_runbook), so its group checkbox is partial: neither checked nor empty.
    const remediationGroupToggle = await within(table).findByLabelText('Grant all Remediation tools');
    expect(remediationGroupToggle).not.toBeChecked();
    expect(remediationGroupToggle).toBePartiallyChecked();
    within(table).getByText('1 of 2 granted');

    // Policy holds nothing granted, so its group checkbox is plain unchecked.
    const policyGroupToggle = within(table).getByLabelText('Grant all Policy & controls tools');
    expect(policyGroupToggle).not.toBeChecked();
    expect(policyGroupToggle).not.toBePartiallyChecked();
    within(table).getByText('0 of 2 granted');

    // The group's Minimum tier is the lowest of its members: both groups pair an
    // Account Operator tool with a Delegated Admin one, so both read Account Operator.
    expect(within(table).getAllByText('Account Operator').length).toBeGreaterThanOrEqual(4);
  });

  it('grants every tool in a category from the group checkbox and saves them together', async () => {
    const putSpy = vi.fn();
    server.use(
      http.put(`${MOCK_SERVER_URL}users/:id/mcp-tools`, async ({ request }) => {
        const body = (await request.json()) as { allowedTools: string[] };
        putSpy(body.allowedTools);
        return ok({ email: 'operator1@example.com', allowedMcpTools: body.allowedTools });
      }),
    );

    renderWithViewer(['AdminGroup']);
    const dialog = await openManageUserModal(DELEGATED_ADMIN);

    const table = await within(dialog).findByTestId('tool-permissions-table');
    await userEvent.click(await within(table).findByLabelText('Grant all Policy & controls tools'));

    // Both tools in the category flip, and the group reads fully granted.
    expect(within(table).getByLabelText('Grant list_filters')).toBeChecked();
    expect(within(table).getByLabelText('Grant create_filter')).toBeChecked();
    expect(within(table).getByLabelText('Grant all Policy & controls tools')).toBeChecked();

    await userEvent.click(within(dialog).getByRole('button', { name: /save/i }));

    await waitFor(() => expect(putSpy).toHaveBeenCalledTimes(1));
    expect(putSpy.mock.calls[0][0]).toEqual(
      expect.arrayContaining(['execute_finding_action', 'list_filters', 'create_filter']),
    );
  });

  it('revokes a fully granted category from the group checkbox', async () => {
    renderWithViewer(['AdminGroup']);
    const dialog = await openManageUserModal(DELEGATED_ADMIN);

    const table = await within(dialog).findByTestId('tool-permissions-table');
    const groupToggle = await within(table).findByLabelText('Grant all Remediation tools');

    // Partial → all granted → none granted.
    await userEvent.click(groupToggle);
    expect(within(table).getByLabelText('Grant execute_runbook')).toBeChecked();

    await userEvent.click(within(table).getByLabelText('Grant all Remediation tools'));
    expect(within(table).getByLabelText('Grant execute_finding_action')).not.toBeChecked();
    expect(within(table).getByLabelText('Grant execute_runbook')).not.toBeChecked();
    const groupToggleAfterRevoke = within(table).getByLabelText('Grant all Remediation tools');
    expect(groupToggleAfterRevoke).not.toBeChecked();
    expect(groupToggleAfterRevoke).not.toBePartiallyChecked();
  });

  it('collapses a category to hide its tools and keeps their grants intact', async () => {
    renderWithViewer(['AdminGroup']);
    const dialog = await openManageUserModal(DELEGATED_ADMIN);

    const table = await within(dialog).findByTestId('tool-permissions-table');
    await within(table).findByLabelText('Grant execute_runbook');

    // Cloudscape renders one expand/collapse control per expandable row, named by the
    // ariaLabels the table supplies.
    await userEvent.click(within(table).getByRole('button', { name: 'Collapse Remediation' }));

    await waitFor(() => expect(within(table).queryByLabelText('Grant execute_runbook')).not.toBeInTheDocument());
    // The collapsed group still reports its grant state, and other groups are untouched.
    within(table).getByLabelText('Grant all Remediation tools');
    within(table).getByLabelText('Grant list_filters');

    await userEvent.click(within(table).getByRole('button', { name: 'Expand Remediation' }));
    expect(await within(table).findByLabelText('Grant execute_runbook')).not.toBeChecked();
    expect(within(table).getByLabelText('Grant execute_finding_action')).toBeChecked();
  });

  it('lets an Admin toggle a tool and save, calling PUT /users/{id}/mcp-tools', async () => {
    const putSpy = vi.fn();
    server.use(
      // Assert the PUT body carries the newly-toggled tool set.
      http.put(`${MOCK_SERVER_URL}users/:id/mcp-tools`, async ({ request }) => {
        const body = (await request.json()) as { allowedTools: string[] };
        putSpy(body.allowedTools);
        return ok({ email: 'operator1@example.com', allowedMcpTools: body.allowedTools });
      }),
    );

    renderWithViewer(['AdminGroup']);
    const dialog = await openManageUserModal(DELEGATED_ADMIN);

    const grantToggle = await within(dialog).findByLabelText('Grant execute_runbook');
    expect(grantToggle).not.toBeDisabled();
    await userEvent.click(grantToggle);

    await userEvent.click(within(dialog).getByRole('button', { name: /save/i }));

    await waitFor(() => expect(putSpy).toHaveBeenCalledTimes(1));
    expect(putSpy.mock.calls[0][0]).toEqual(expect.arrayContaining(['execute_finding_action', 'execute_runbook']));
    await waitFor(() => expect(mockRefresh).toHaveBeenCalled());
  });

  it('does not render the tool permissions table for a non-Admin viewer', async () => {
    // The catalog endpoint is Admin-only, so a non-Admin viewer never fetches it and the
    // table is not rendered at all (rather than shown read-only).
    renderWithViewer(['DelegatedAdminGroup']);
    const dialog = await openManageUserModal();

    expect(within(dialog).queryByTestId('tool-permissions-table')).not.toBeInTheDocument();
    expect(within(dialog).queryByLabelText('Grant execute_finding_action')).not.toBeInTheDocument();
  });

  it('still refreshes when the account update commits but the tools update fails', async () => {
    // Account update (PUT /users/{id}) succeeds; the tools update (PUT .../mcp-tools)
    // fails. The committed account change must still trigger onRefresh so the table
    // reflects it, even though the tools write errored.
    server.use(
      // Account update succeeds...
      http.put(`${MOCK_SERVER_URL}users/:id`, () => ok({})),
      // ...but the tools update fails.
      http.put(`${MOCK_SERVER_URL}users/:id/mcp-tools`, () => new HttpResponse(null, { status: 500 })),
    );

    renderWithViewer(['AdminGroup']);
    const dialog = await openManageUserModal();

    // Change the owned accounts (an account-operator field) so the account write runs.
    const accountsField = within(await within(dialog).findByTestId('owned-accounts-form-field')).getByRole('textbox');
    await userEvent.clear(accountsField);
    await userEvent.type(accountsField, '123456789099');

    // Also toggle a tool so the (failing) tools write runs.
    await userEvent.click(await within(dialog).findByLabelText('Grant list_filters'));

    await userEvent.click(within(dialog).getByRole('button', { name: /save/i }));

    await waitFor(() => expect(mockRefresh).toHaveBeenCalled());
  });

  it('keeps Save enabled for a tools-only change and does not write accounts', async () => {
    // An Admin toggles a tool without editing the accounts field. The account write must
    // not run, and Save must not be gated on account validation for a tools-only change.
    const putToolsSpy = vi.fn();
    server.use(
      http.put(`${MOCK_SERVER_URL}users/:id/mcp-tools`, async ({ request }) => {
        const body = (await request.json()) as { allowedTools: string[] };
        putToolsSpy(body.allowedTools);
        return ok({ email: 'operator1@example.com', allowedMcpTools: body.allowedTools });
      }),
      http.put(`${MOCK_SERVER_URL}users/:id`, () => {
        throw new Error('account update must not run for a tools-only save');
      }),
    );

    renderWithViewer(['AdminGroup']);
    const dialog = await openManageUserModal();

    await userEvent.click(await within(dialog).findByLabelText('Grant list_filters'));

    const saveButton = within(dialog).getByRole('button', { name: /save/i });
    expect(saveButton).not.toBeDisabled();
    await userEvent.click(saveButton);

    await waitFor(() => expect(putToolsSpy).toHaveBeenCalledTimes(1));
  });

  it('preserves in-progress tool toggles when the users list re-renders with a new reference', async () => {
    // A background users refetch (e.g. invalidatesTags) hands UsersTable a fresh array
    // with the same data. The modal's checkbox edits must survive that re-render — the
    // seed effect is keyed on modal-open + user, not on the users array identity.
    const store = setupStore();
    const userContextValue = {
      user: null,
      email: 'viewer@example.com',
      groups: ['AdminGroup'],
      signOut: () => Promise.resolve(),
      signInWithRedirect: () => Promise.resolve(),
      checkUser: () => Promise.resolve(),
    };
    const Wrapper = ({ children }: { children: ReactNode }) => (
      <Provider store={store}>
        <UserContext.Provider value={userContextValue}>{children}</UserContext.Provider>
      </Provider>
    );
    const { rerender } = render(<UsersTable users={testUsers} loading={false} onRefresh={mockRefresh} />, {
      wrapper: Wrapper,
    });

    const dialog = await openManageUserModal(DELEGATED_ADMIN);
    const grantToggle = await within(dialog).findByLabelText('Grant execute_runbook');
    await userEvent.click(grantToggle);
    expect(grantToggle).toBeChecked();

    // Same data, brand-new array reference — mimics a background refetch.
    rerender(<UsersTable users={[...testUsers]} loading={false} onRefresh={mockRefresh} />);

    expect(within(dialog).getByLabelText('Grant execute_runbook')).toBeChecked();
  });
});
