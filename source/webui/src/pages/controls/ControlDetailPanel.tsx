// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import React, { useMemo } from 'react';
import {
  Alert,
  Badge,
  Box,
  Button,
  ColumnLayout,
  FormField,
  Header,
  Multiselect,
  MultiselectProps,
  Select,
  SelectProps,
  SpaceBetween,
  SplitPanel,
  StatusIndicator,
} from '@cloudscape-design/components';

import { FilterMode, ResourceFilter, SecurityControl } from '@data-models';
import { describeRunbook, isCustomControl } from './createControlsColumnDefinitions';

const FILTER_MODE_OPTIONS: SelectProps.Option[] = [
  { label: 'Include', value: 'include', description: 'Remediation applies only to matching resources' },
  { label: 'Exclude', value: 'exclude', description: 'Remediation applies to all resources except matching ones' },
];

/**
 * The same three states the table's Automated Remediation column shows, so the panel
 * never contradicts the row it describes. A custom-runbook control runs only on a manual
 * trigger, so its stored flag has no effect either way: "Enabled" here would be a green
 * success indicator for a setting the resolver ignores, and the row beside it says
 * "Enabled (no effect)". Rendered as a warning, not a success, for that reason.
 */
const renderAutomatedRemediationStatus = (control: SecurityControl): React.ReactElement => {
  if (!isCustomControl(control)) {
    return (
      <StatusIndicator type={control.automatedRemediationEnabled ? 'success' : 'stopped'}>
        {control.automatedRemediationEnabled ? 'Enabled' : 'Disabled'}
      </StatusIndicator>
    );
  }
  if (control.automatedRemediationEnabled) {
    return <StatusIndicator type="warning">Enabled (no effect)</StatusIndicator>;
  }
  return <StatusIndicator type="stopped">Manual trigger only</StatusIndicator>;
};

interface ControlDetailPanelProps {
  control: SecurityControl;
  filters: ResourceFilter[];
  isReadOnly: boolean;
  serverFilterMode: FilterMode;
  onFilterModeChange: (controlId: string, filterMode: FilterMode) => void;
  onAddFilter: (controlId: string, filterId: string) => void;
  onRemoveFilter: (controlId: string, filterId: string) => void;
}

export const ControlDetailPanel = ({
  control,
  filters,
  isReadOnly,
  serverFilterMode,
  onFilterModeChange,
  onAddFilter,
  onRemoveFilter,
}: ControlDetailPanelProps): React.ReactElement => {
  const filterMap = useMemo(() => new Map(filters.map((f) => [f.filterId, f])), [filters]);

  const filterOptions: MultiselectProps.Option[] = useMemo(
    () => filters.map((f) => ({ label: f.name, value: f.filterId })),
    [filters],
  );

  const selectedFilterOptions: MultiselectProps.Option[] = useMemo(
    () =>
      control.filters.map((filterId) => {
        const filter = filterMap.get(filterId);
        return { label: filter?.name ?? filterId, value: filterId };
      }),
    [control.filters, filterMap],
  );

  const selectedFilterModeOption = useMemo(
    () => FILTER_MODE_OPTIONS.find((o) => o.value === control.filterMode) ?? FILTER_MODE_OPTIONS[0],
    [control.filterMode],
  );

  const handleFilterSelectionChange = (detail: MultiselectProps.MultiselectChangeDetail) => {
    const newFilterIds = new Set(detail.selectedOptions.flatMap((o) => (o.value ? [o.value] : [])));
    const currentFilterIds = new Set(control.filters);

    for (const filterId of newFilterIds) {
      if (!currentFilterIds.has(filterId)) {
        onAddFilter(control.controlId, filterId);
      }
    }
    for (const filterId of currentFilterIds) {
      if (!newFilterIds.has(filterId)) {
        onRemoveFilter(control.controlId, filterId);
      }
    }
  };

  return (
    <SplitPanel
      header={`Control: ${control.controlId}`}
      closeBehavior="hide"
      i18nStrings={{
        preferencesTitle: 'Split panel preferences',
        preferencesPositionLabel: 'Split panel position',
        preferencesPositionDescription: 'Choose the default split panel position for the browser.',
        preferencesPositionSide: 'Side',
        preferencesPositionBottom: 'Bottom',
        preferencesConfirm: 'Confirm',
        preferencesCancel: 'Cancel',
        closeButtonAriaLabel: 'Close panel',
        openButtonAriaLabel: 'Open panel',
        resizeHandleAriaLabel: 'Resize split panel',
      }}
    >
      <SpaceBetween size="l">
        <ColumnLayout columns={2} variant="text-grid">
          <SpaceBetween size="xs">
            <Box variant="awsui-key-label">Control ID</Box>
            <Box>{control.controlId}</Box>
          </SpaceBetween>
          <SpaceBetween size="xs">
            <Box variant="awsui-key-label">Automated Remediation</Box>
            {renderAutomatedRemediationStatus(control)}
          </SpaceBetween>
          <SpaceBetween size="xs">
            <Box variant="awsui-key-label">Runbook</Box>
            <Box>{describeRunbook(control)}</Box>
            {isCustomControl(control) && (
              <Box variant="small" color="text-body-secondary">
                Only the most recently deployed version runs. Deploying a newer version, or rolling back to an older
                one, changes which version this is.
              </Box>
            )}
          </SpaceBetween>
        </ColumnLayout>

        <SpaceBetween size="xs">
          <Box variant="awsui-key-label">Description</Box>
          <Box>{control.description}</Box>
        </SpaceBetween>

        <Header variant="h3">Resource Filters</Header>

        <FormField
          label="Filter mode"
          description="Include mode applies remediation only to matching resources. Exclude mode applies to all except matching."
        >
          <SpaceBetween size="xs">
            <Select
              selectedOption={selectedFilterModeOption}
              options={FILTER_MODE_OPTIONS}
              onChange={({ detail }) => {
                const value = detail.selectedOption.value;
                if (value === 'include' || value === 'exclude') {
                  onFilterModeChange(control.controlId, value);
                }
              }}
              disabled={isReadOnly}
              ariaLabel="Filter mode"
            />
            {control.filterMode !== serverFilterMode && control.filters.length > 0 && (
              <Alert type="warning">
                Changing the filter mode will invert the behavior of all {control.filters.length} applied{' '}
                {control.filters.length === 1 ? 'filter' : 'filters'}. Resources that were previously{' '}
                {serverFilterMode === 'include' ? 'included' : 'excluded'} will now be{' '}
                {control.filterMode === 'include' ? 'included' : 'excluded'}.
              </Alert>
            )}
          </SpaceBetween>
        </FormField>

        <FormField label="Applied filters">
          {isReadOnly ? (
            <SpaceBetween direction="horizontal" size="xs">
              {control.filters.length === 0 ? (
                <StatusIndicator type="info">No filters — applies to all resources</StatusIndicator>
              ) : (
                control.filters.map((filterId) => {
                  const filter = filterMap.get(filterId);
                  const color = control.filterMode === 'exclude' ? 'red' : 'green';
                  return (
                    <Badge key={filterId} color={color}>
                      {filter?.name ?? filterId}
                    </Badge>
                  );
                })
              )}
            </SpaceBetween>
          ) : (
            <SpaceBetween size="s">
              <Multiselect
                selectedOptions={selectedFilterOptions}
                options={filterOptions}
                onChange={({ detail }) => handleFilterSelectionChange(detail)}
                placeholder="Select filters to apply"
                filteringType="auto"
                ariaLabel="Applied filters"
              />
              {control.filters.length === 0 && (
                <StatusIndicator type="info">No filters — applies to all resources</StatusIndicator>
              )}
              {control.filters.length > 0 && (
                <SpaceBetween size="xs">
                  {control.filters.map((filterId) => {
                    const filter = filterMap.get(filterId);
                    const color = control.filterMode === 'exclude' ? 'red' : 'green';
                    return (
                      <SpaceBetween key={filterId} direction="horizontal" size="xs">
                        <Badge color={color}>{filter?.name ?? filterId}</Badge>
                        <Button
                          variant="inline-link"
                          onClick={() => onRemoveFilter(control.controlId, filterId)}
                          ariaLabel={`Remove filter ${filter?.name ?? filterId}`}
                        >
                          Remove
                        </Button>
                      </SpaceBetween>
                    );
                  })}
                </SpaceBetween>
              )}
            </SpaceBetween>
          )}
        </FormField>
      </SpaceBetween>
    </SplitPanel>
  );
};
