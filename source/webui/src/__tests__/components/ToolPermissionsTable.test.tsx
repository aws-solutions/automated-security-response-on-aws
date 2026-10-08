// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, it, expect, vi } from 'vitest';
import { ToolPermissionsTable } from '../../components/ToolPermissionsTable';
import { GrantableTool, ToolCategory } from '../../store/usersApiSlice';

const tool = (
  name: string,
  category: ToolCategory,
  tier: GrantableTool['tier'] = 'AccountOperator',
): GrantableTool => ({
  name,
  category,
  tier,
});

describe('ToolPermissionsTable', () => {
  it('orders categories least-privileged first, regardless of catalog order', async () => {
    render(
      <ToolPermissionsTable
        tools={[tool('update_controls', 'Policy'), tool('remediations', 'Reporting'), tool('findings', 'Discovery')]}
        grantedTools={new Set()}
        onToggle={vi.fn()}
      />,
    );

    const table = await screen.findByTestId('tool-permissions-table');
    const rowText = within(table)
      .getAllByRole('row')
      .map((row) => row.textContent ?? '');

    const categoryPosition = (label: string) => rowText.findIndex((text) => text.includes(label));
    expect(categoryPosition('Discovery & triage')).toBeLessThan(categoryPosition('Reporting'));
    expect(categoryPosition('Reporting')).toBeLessThan(categoryPosition('Policy & controls'));
  });

  it('reports a group as fully granted only when every tool in it is granted', async () => {
    render(
      <ToolPermissionsTable
        tools={[tool('list_filters', 'Policy'), tool('create_filter', 'Policy', 'DelegatedAdmin')]}
        grantedTools={new Set(['list_filters', 'create_filter'])}
        onToggle={vi.fn()}
      />,
    );

    const groupToggle = await screen.findByLabelText('Grant all Policy & controls tools');
    expect(groupToggle).toBeChecked();
    expect(groupToggle).not.toBePartiallyChecked();
    screen.getByText('2 of 2 granted');
  });

  it('shows a category the UI has no label for under its raw name, sorted last', async () => {
    // The backend can emit 'Other' for a tool it has not categorized, and a future
    // release can add a category this build does not know. Neither may hide a tool:
    // the group still renders, still toggles, and sorts after the known categories.
    const unknownCategory = 'Experimental' as ToolCategory;
    const onToggle = vi.fn();
    render(
      <ToolPermissionsTable
        tools={[tool('brand_new_tool', unknownCategory), tool('findings', 'Discovery')]}
        grantedTools={new Set()}
        onToggle={onToggle}
      />,
    );

    const table = await screen.findByTestId('tool-permissions-table');
    const rowText = within(table)
      .getAllByRole('row')
      .map((row) => row.textContent ?? '');
    expect(rowText.findIndex((text) => text.includes('Discovery & triage'))).toBeLessThan(
      rowText.findIndex((text) => text.includes('Experimental')),
    );

    within(table).getByText('brand_new_tool');
    await userEvent.click(within(table).getByLabelText('Grant all Experimental tools'));
    expect(onToggle).toHaveBeenCalledWith(['brand_new_tool'], true);

    // The expand control names the group by its raw category too.
    within(table).getByRole('button', { name: 'Collapse Experimental' });
  });

  it('shows a group’s minimum tier as the lowest tier among its tools', async () => {
    render(
      <ToolPermissionsTable
        tools={[
          tool('findings', 'Discovery'),
          tool('list_controls', 'Discovery', 'DelegatedAdmin'),
          tool('deploy_runbook', 'Infrastructure', 'DelegatedAdmin'),
        ]}
        grantedTools={new Set()}
        onToggle={vi.fn()}
      />,
    );

    const table = await screen.findByTestId('tool-permissions-table');
    const rowFor = (label: string) =>
      within(table)
        .getAllByRole('row')
        .find((row) => (row.textContent ?? '').includes(label));

    // Mixed group reports the lower tier; an all-Delegated-Admin group reports its own.
    expect(rowFor('Discovery & triage')?.textContent).toContain('Account Operator');
    expect(rowFor('Infrastructure & deployment')?.textContent).toContain('Delegated Admin');
  });

  it('renders an empty state when the catalog is empty', () => {
    render(<ToolPermissionsTable tools={[]} grantedTools={new Set()} onToggle={vi.fn()} />);

    expect(screen.getByText('No grantable tools are available.')).toBeInTheDocument();
  });
});
