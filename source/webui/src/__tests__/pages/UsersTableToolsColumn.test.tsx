// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { render, screen } from '@testing-library/react';
import { describe, it, expect, vi } from 'vitest';
import type { TableProps } from '@cloudscape-design/components/table';
import type { AccountOperatorUser, User } from '@data-models';
import { createColumnDefinitions } from '../../pages/users/users-table/createColumnDefinitions';

type ColumnDef = NonNullable<TableProps<User>['columnDefinitions']>[number];

function makeUser(overrides: Partial<AccountOperatorUser> = {}): AccountOperatorUser {
  return {
    email: 'operator@example.com',
    type: 'account-operator',
    accountIds: ['123456789012'],
    invitedBy: 'admin@example.com',
    invitationTimestamp: '2026-01-15T10:30:00Z',
    status: 'Confirmed',
    ...overrides,
  };
}

function renderToolsCell(user: User) {
  const columns = createColumnDefinitions();
  const toolsColumn = columns!.find((c): c is ColumnDef => c.header === 'Tools');
  if (!toolsColumn?.cell) throw new Error('Tools column not found');
  return render(<>{toolsColumn.cell(user)}</>);
}

describe('Users table Tools column', () => {
  it('renders a dash when the user has no granted tools', () => {
    renderToolsCell(makeUser({ allowedMcpTools: undefined }));
    expect(screen.getByText('-')).toBeInTheDocument();
  });

  it('lists all tools inline when there are three or fewer', () => {
    renderToolsCell(makeUser({ allowedMcpTools: ['list_findings', 'get_runbook', 'execute_runbook'] }));
    expect(screen.getByText('list_findings')).toBeInTheDocument();
    expect(screen.getByText('get_runbook')).toBeInTheDocument();
    expect(screen.getByText('execute_runbook')).toBeInTheDocument();
    // No overflow badge when the count is exactly the visible cap.
    expect(screen.queryByText(/^\+\d+$/)).not.toBeInTheDocument();
  });

  it('shows the first three tools and a +N overflow badge when there are more', () => {
    renderToolsCell(
      makeUser({
        allowedMcpTools: ['list_findings', 'get_runbook', 'execute_runbook', 'list_controls', 'create_filter'],
      }),
    );
    // First three are shown inline.
    expect(screen.getByText('list_findings')).toBeInTheDocument();
    expect(screen.getByText('get_runbook')).toBeInTheDocument();
    expect(screen.getByText('execute_runbook')).toBeInTheDocument();
    // The two beyond the cap collapse into a +2 overflow badge, not shown inline.
    expect(screen.getByText('+2')).toBeInTheDocument();
    expect(screen.queryByText('list_controls')).not.toBeInTheDocument();
    expect(screen.queryByText('create_filter')).not.toBeInTheDocument();
  });
});
