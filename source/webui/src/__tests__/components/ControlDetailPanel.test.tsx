// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { vi, describe, it, expect } from 'vitest';
import { AppLayout } from '@cloudscape-design/components';

import { ControlDetailPanel } from '../../pages/controls/ControlDetailPanel.tsx';
import { FilterMode, ResourceFilter, SecurityControl } from '@data-models';

const FILTER_UUID_1 = '00000000-0000-4000-8000-000000000001';
const FILTER_UUID_2 = '00000000-0000-4000-8000-000000000002';
const FILTER_UUID_3 = '00000000-0000-4000-8000-000000000003';

const createControl = (overrides: Partial<SecurityControl> = {}): SecurityControl => ({
  controlId: 'S3.1',
  description: 'Ensure S3 buckets have server-side encryption enabled',
  automatedRemediationEnabled: true,
  filters: [],
  filterMode: 'include',
  version: 1,
  lastModified: '2025-01-01T00:00:00Z',
  modifiedBy: 'admin',
  ...overrides,
});

const createFilter = (overrides: Partial<ResourceFilter> = {}): ResourceFilter => ({
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

const FILTERS = [
  createFilter({ filterId: FILTER_UUID_1, name: 'Production Accounts' }),
  createFilter({ filterId: FILTER_UUID_2, name: 'US Regions' }),
  createFilter({ filterId: FILTER_UUID_3, name: 'Critical Resources' }),
];

interface RenderPanelOptions {
  control?: SecurityControl;
  filters?: ResourceFilter[];
  isReadOnly?: boolean;
  serverFilterMode?: FilterMode;
  onFilterModeChange?: (controlId: string, filterMode: FilterMode) => void;
  onAddFilter?: (controlId: string, filterId: string) => void;
  onRemoveFilter?: (controlId: string, filterId: string) => void;
}

const renderPanel = ({
  control = createControl(),
  filters = FILTERS,
  isReadOnly = false,
  serverFilterMode = control.filterMode,
  onFilterModeChange = vi.fn(),
  onAddFilter = vi.fn(),
  onRemoveFilter = vi.fn(),
}: RenderPanelOptions = {}) => {
  const callbacks = { onFilterModeChange, onAddFilter, onRemoveFilter };
  const panel = (
    <ControlDetailPanel
      control={control}
      filters={filters}
      isReadOnly={isReadOnly}
      serverFilterMode={serverFilterMode}
      onFilterModeChange={callbacks.onFilterModeChange}
      onAddFilter={callbacks.onAddFilter}
      onRemoveFilter={callbacks.onRemoveFilter}
    />
  );
  const renderResult = render(<AppLayout content={<div />} splitPanel={panel} splitPanelOpen={true} />);
  return { ...callbacks, ...renderResult };
};

describe('ControlDetailPanel', () => {
  it('displays control metadata: ID, description, and remediation status', () => {
    // ARRANGE
    const control = createControl({
      controlId: 'EC2.6',
      description: 'VPC flow logging should be enabled',
      automatedRemediationEnabled: false,
    });

    // ACT
    renderPanel({ control });

    // ASSERT
    expect(screen.getByText('EC2.6')).toBeInTheDocument();
    expect(screen.getByText('VPC flow logging should be enabled')).toBeInTheDocument();
    expect(screen.getByText('Disabled')).toBeInTheDocument();
    expect(screen.getByText(/Control: EC2\.6/)).toBeInTheDocument();
  });

  it('shows "Enabled" status indicator when remediation is enabled', () => {
    // ARRANGE & ACT
    renderPanel({ control: createControl({ automatedRemediationEnabled: true }) });

    // ASSERT
    expect(screen.getByText('Enabled')).toBeInTheDocument();
  });

  it('shows "No filters" indicator when control has no filters applied', () => {
    // ARRANGE & ACT
    renderPanel({ control: createControl({ filters: [] }) });

    // ASSERT
    expect(screen.getByText(/No filters — applies to all resources/)).toBeInTheDocument();
  });

  it('displays filter names as badges when filters are applied', () => {
    // ARRANGE
    const control = createControl({ filters: [FILTER_UUID_1, FILTER_UUID_2] });

    // ACT
    renderPanel({ control });

    // ASSERT
    expect(screen.getAllByText('Production Accounts').length).toBeGreaterThanOrEqual(1);
    expect(screen.getAllByText('US Regions').length).toBeGreaterThanOrEqual(1);
    expect(screen.getByRole('button', { name: /Remove filter Production Accounts/ })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /Remove filter US Regions/ })).toBeInTheDocument();
  });

  it('shows green badges for include mode and red badges for exclude mode', () => {
    // ARRANGE - include mode
    const includeControl = createControl({ filters: [FILTER_UUID_1], filterMode: 'include' });

    // ACT
    const { unmount } = renderPanel({ control: includeControl, isReadOnly: true, serverFilterMode: 'include' });

    // ASSERT - include mode renders green badge
    const includeBadge = screen.getByText('Production Accounts');
    expect(includeBadge.className).toMatch(/badge-color-green/);
    unmount();

    // ARRANGE - exclude mode
    const excludeControl = createControl({ filters: [FILTER_UUID_1], filterMode: 'exclude' });

    // ACT
    renderPanel({ control: excludeControl, isReadOnly: true, serverFilterMode: 'exclude' });

    // ASSERT - exclude mode renders red badge
    const excludeBadge = screen.getByText('Production Accounts');
    expect(excludeBadge.className).toMatch(/badge-color-red/);
  });

  it('falls back to filterId when filter name is not found', () => {
    // ARRANGE
    const control = createControl({ filters: ['unknown-filter-id'] });

    // ACT
    renderPanel({ control, filters: [] });

    // ASSERT
    expect(screen.getAllByText('unknown-filter-id').length).toBeGreaterThanOrEqual(1);
  });

  it('calls onFilterModeChange when filter mode is changed', async () => {
    // ARRANGE
    const control = createControl({ filterMode: 'include' });
    const callbacks = renderPanel({ control });

    // ACT
    const filterModeSelect = screen.getByRole('button', { name: /Include/ });
    await userEvent.click(filterModeSelect);
    const excludeOption = await screen.findByText('Exclude');
    await userEvent.click(excludeOption);

    // ASSERT
    expect(callbacks.onFilterModeChange).toHaveBeenCalledWith('S3.1', 'exclude');
  });

  it('shows filter mode inversion warning when mode differs from server and filters exist', () => {
    // ARRANGE
    const control = createControl({
      filters: [FILTER_UUID_1, FILTER_UUID_2],
      filterMode: 'exclude',
    });

    // ACT
    renderPanel({ control, serverFilterMode: 'include' });

    // ASSERT
    expect(
      screen.getByText(/Changing the filter mode will invert the behavior of all 2 applied filters/),
    ).toBeInTheDocument();
    expect(screen.getByText(/previously included/)).toBeInTheDocument();
    expect(screen.getByText(/will now be excluded/)).toBeInTheDocument();
  });

  it('does not show filter mode warning when mode matches server', () => {
    // ARRANGE
    const control = createControl({ filters: [FILTER_UUID_1], filterMode: 'include' });

    // ACT
    renderPanel({ control, serverFilterMode: 'include' });

    // ASSERT
    expect(screen.queryByText(/Changing the filter mode/)).not.toBeInTheDocument();
  });

  it('does not show filter mode warning when no filters are applied', () => {
    // ARRANGE
    const control = createControl({ filters: [], filterMode: 'exclude' });

    // ACT
    renderPanel({ control, serverFilterMode: 'include' });

    // ASSERT
    expect(screen.queryByText(/Changing the filter mode/)).not.toBeInTheDocument();
  });

  it('calls onRemoveFilter when a remove button is clicked', async () => {
    // ARRANGE
    const control = createControl({ filters: [FILTER_UUID_1] });
    const callbacks = renderPanel({ control });

    // ACT
    const removeButton = screen.getByRole('button', { name: /Remove filter Production Accounts/ });
    await userEvent.click(removeButton);

    // ASSERT
    expect(callbacks.onRemoveFilter).toHaveBeenCalledWith('S3.1', FILTER_UUID_1);
  });

  it('disables filter mode select and hides remove buttons in read-only mode', () => {
    // ARRANGE
    const control = createControl({ filters: [FILTER_UUID_1] });

    // ACT
    renderPanel({ control, isReadOnly: true });

    // ASSERT
    const filterModeButton = screen.getByRole('button', { name: /Include/ });
    expect(filterModeButton).toBeDisabled();
    expect(screen.queryByRole('button', { name: /Remove filter/ })).not.toBeInTheDocument();
  });

  it('shows filter badges without remove buttons in read-only mode', () => {
    // ARRANGE
    const control = createControl({ filters: [FILTER_UUID_1, FILTER_UUID_2] });

    // ACT
    renderPanel({ control, isReadOnly: true });

    // ASSERT
    expect(screen.getByText('Production Accounts')).toBeInTheDocument();
    expect(screen.getByText('US Regions')).toBeInTheDocument();
    expect(screen.queryAllByRole('button', { name: /Remove/ })).toHaveLength(0);
  });

  it('calls onAddFilter and onRemoveFilter when multiselect selection changes', async () => {
    // ARRANGE
    const control = createControl({ filters: [FILTER_UUID_1] });
    const callbacks = renderPanel({ control });

    // ACT - open the multiselect and select a new filter
    const multiselect = screen.getByRole('button', { name: /Applied filters/ });
    await userEvent.click(multiselect);
    const usRegionsOption = await screen.findByText('US Regions');
    await userEvent.click(usRegionsOption);

    // ASSERT
    expect(callbacks.onAddFilter).toHaveBeenCalledWith('S3.1', FILTER_UUID_2);
  });

  it('calls onRemoveFilter when a filter is deselected via multiselect', async () => {
    // ARRANGE
    const control = createControl({ filters: [FILTER_UUID_1, FILTER_UUID_2] });
    const callbacks = renderPanel({ control });

    // ACT - open the multiselect and deselect a filter
    const multiselect = screen.getByRole('button', { name: /Applied filters/ });
    await userEvent.click(multiselect);
    const prodOption = await screen.findByRole('option', { name: /Production Accounts/ });
    await userEvent.click(prodOption);

    // ASSERT
    expect(callbacks.onRemoveFilter).toHaveBeenCalledWith('S3.1', FILTER_UUID_1);
  });

  it('uses singular "filter" in warning when only one filter is applied', () => {
    // ARRANGE
    const control = createControl({ filters: [FILTER_UUID_1], filterMode: 'exclude' });

    // ACT
    renderPanel({ control, serverFilterMode: 'include' });

    // ASSERT
    expect(screen.getByText(/all 1 applied filter\./)).toBeInTheDocument();
  });
});
