// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import React, { useCallback, useContext, useEffect, useMemo, useRef, useState } from 'react';
import { useSearchParams } from 'react-router';
import { TableProps } from '@cloudscape-design/components/table';
import { useCollection } from '@cloudscape-design/collection-hooks';
import {
  Button,
  CollectionPreferences,
  ContentLayout,
  Header,
  NonCancelableCustomEvent,
  Pagination,
  SpaceBetween,
  Table,
  TextFilter,
} from '@cloudscape-design/components';

import { SecurityControl, ResourceFilter } from '@data-models';
import { EmptyTableState } from '../../components/EmptyTableState.tsx';
import { ReadOnlyBadge } from '../../components/ReadOnlyBadge.tsx';
import { UserContext } from '../../contexts/UserContext.tsx';
import { canEditControls } from '../../utils/userPermissions.ts';
import { controlsTablePreferences } from '../../utils/tablePreferences.ts';
import { UnsavedChangesBar } from './UnsavedChangesBar.tsx';
import { useControlsEditing } from './useControlsEditing.ts';
import { createControlsColumnDefinitions } from './createControlsColumnDefinitions.tsx';
import { ControlDetailPanel } from './ControlDetailPanel.tsx';
import { useGetFiltersQuery } from '../../store/filtersApiSlice.ts';
import { useGetNotificationConfigsQuery } from '../../store/notificationConfigApiSlice.ts';
import { useSplitPanel } from '../../contexts/SplitPanelContext.tsx';

const getFilterCounterText = (count = 0): string => `${count} ${count === 1 ? 'match' : 'matches'}`;
const getHeaderCounterText = (total: number, selected: number): string =>
  selected > 0 ? `(${selected}/${total})` : `(${total})`;

interface Preferences {
  pageSize: number;
  visibleContent: string[];
  contentDensity: 'compact' | 'comfortable';
}

const DEFAULT_PREFERENCES: Preferences = {
  pageSize: 20,
  visibleContent: [
    'controlId',
    'description',
    'isEnabled',
    'appliedFilters',
    'notifications',
    'modifiedBy',
    'lastModified',
  ],
  contentDensity: 'comfortable',
};

const EMPTY_FILTERS: ResourceFilter[] = [];

export const ControlsOverviewPage = (): React.ReactElement => {
  const { groups } = useContext(UserContext);
  const isReadOnly = !canEditControls(groups);
  const [searchParams, setSearchParams] = useSearchParams();

  const {
    localControls,
    serverControls,
    isLoading,
    isSaving,
    hasUnsavedChanges,
    changedControlIds,
    handleToggle,
    handleDisableAll,
    handleSave,
    handleDiscard,
    handleRefresh,
    handleFilterModeChange,
    handleAddFilter,
    handleRemoveFilter,
  } = useControlsEditing(isReadOnly);

  const { data: filters = EMPTY_FILTERS } = useGetFiltersQuery();
  const { data: notificationConfigs = [] } = useGetNotificationConfigsQuery();
  const { registerPanel, unregisterPanel, openSplitPanel, closeSplitPanel } = useSplitPanel();

  const allRemediationDisabled = localControls.length > 0 && localControls.every((c) => !c.automatedRemediationEnabled);

  const [preferences, setPreferences] = useState<Preferences>(() => controlsTablePreferences.load());
  const [currentPageIndex, setCurrentPageIndex] = useState(1);

  const columnDefinitions = useMemo(
    () => createControlsColumnDefinitions({ onToggle: handleToggle, isReadOnly, filters, notificationConfigs }),
    [handleToggle, isReadOnly, filters, notificationConfigs],
  );

  const visibleColumns = columnDefinitions.filter((col) => preferences.visibleContent.includes(col.id ?? ''));

  const { items, filterProps, actions, filteredItemsCount, collectionProps } = useCollection<SecurityControl>(
    localControls,
    {
      filtering: {
        filteringFunction: (item, filteringText) => {
          const searchText = filteringText.toLowerCase();
          return item.controlId.toLowerCase().includes(searchText);
        },
        noMatch: (
          <EmptyTableState
            title="No matches"
            subtitle="We can't find a match."
            action={<Button onClick={() => actions.setFiltering('')}>Clear filter</Button>}
          />
        ),
        empty: <EmptyTableState title="No controls" subtitle="No security controls to display." />,
      },
      sorting: { defaultState: { sortingColumn: { sortingField: 'controlId' } } },
      selection: { trackBy: 'controlId' },
    },
  );

  const initialSelectionApplied = useRef(false);
  useEffect(() => {
    if (initialSelectionApplied.current) return;
    if (isLoading) return;
    if (localControls.length === 0) {
      if (serverControls.length === 0) {
        initialSelectionApplied.current = true;
        if (searchParams.has('controlId')) {
          setSearchParams(
            (prev) => {
              const next = new URLSearchParams(prev);
              next.delete('controlId');
              return next;
            },
            { replace: true },
          );
        }
      }
      return;
    }
    const controlIdFromUrl = searchParams.get('controlId')?.replace(/^security-control\//, '');
    if (!controlIdFromUrl) {
      initialSelectionApplied.current = true;
      return;
    }
    // Always look up the targeted control in the full list (independent of any
    // existing TextFilter) and pre-apply both the filter and the selection so
    // the table is narrowed to the linked control.
    const targetControl = localControls.find((c) => c.controlId === controlIdFromUrl);
    if (targetControl) {
      actions.setFiltering(controlIdFromUrl);
      actions.setSelectedItems([targetControl]);
      setCurrentPageIndex(1);
    } else {
      setSearchParams(
        (prev) => {
          const next = new URLSearchParams(prev);
          next.delete('controlId');
          return next;
        },
        { replace: true },
      );
    }
    initialSelectionApplied.current = true;
  }, [isLoading, localControls, serverControls.length, searchParams, actions, setSearchParams]);

  // Selection → URL: keep query param in sync when user selects/deselects
  const handleSelectionChange = useCallback(
    (event: NonCancelableCustomEvent<TableProps.SelectionChangeDetail<SecurityControl>>) => {
      const selected = event.detail.selectedItems;
      actions.setSelectedItems(selected);
      setSearchParams(
        (prev) => {
          const next = new URLSearchParams(prev);
          if (selected.length > 0 && selected[0].controlId) {
            next.set('controlId', selected[0].controlId);
          } else {
            next.delete('controlId');
          }
          return next;
        },
        { replace: true },
      );
    },
    [actions, setSearchParams],
  );

  const isInitialFilterSkipped = useRef(false);
  useEffect(() => {
    if (!isInitialFilterSkipped.current) {
      isInitialFilterSkipped.current = true;
      return;
    }
    setCurrentPageIndex(1);
  }, [filterProps.filteringText]);

  const totalPages = Math.ceil(items.length / preferences.pageSize);
  const startIndex = (currentPageIndex - 1) * preferences.pageSize;
  const paginatedItems = items.slice(startIndex, startIndex + preferences.pageSize);
  const selectedItems = collectionProps.selectedItems ?? [];

  const selectedControlId = selectedItems.length > 0 ? selectedItems[0].controlId : null;

  const selectedControl = useMemo(() => {
    if (!selectedControlId) return null;
    return localControls.find((c) => c.controlId === selectedControlId) ?? null;
  }, [selectedControlId, localControls]);

  const serverFilterModeForSelected = useMemo(() => {
    if (!selectedControl) return 'include' as const;
    const serverControl = serverControls.find((c) => c.controlId === selectedControl.controlId);
    return serverControl?.filterMode ?? 'include';
  }, [selectedControl, serverControls]);

  // Split panel lifecycle is split into two effects so that content updates
  // (e.g. filters changing) don't force the panel open after the user closed it.
  const splitPanelContent = useMemo(() => {
    if (!selectedControl) return null;
    return (
      <ControlDetailPanel
        control={selectedControl}
        filters={filters}
        isReadOnly={isReadOnly}
        serverFilterMode={serverFilterModeForSelected}
        onFilterModeChange={handleFilterModeChange}
        onAddFilter={handleAddFilter}
        onRemoveFilter={handleRemoveFilter}
      />
    );
  }, [
    selectedControl,
    filters,
    isReadOnly,
    serverFilterModeForSelected,
    handleFilterModeChange,
    handleAddFilter,
    handleRemoveFilter,
  ]);

  useEffect(() => {
    if (splitPanelContent) {
      registerPanel(splitPanelContent);
    } else {
      unregisterPanel();
    }
  }, [splitPanelContent, registerPanel, unregisterPanel]);

  useEffect(() => {
    return () => {
      unregisterPanel();
    };
  }, [unregisterPanel]);

  useEffect(() => {
    if (selectedControlId) {
      openSplitPanel();
    } else {
      closeSplitPanel();
    }
  }, [selectedControlId, openSplitPanel, closeSplitPanel]);

  return (
    <ContentLayout
      header={
        hasUnsavedChanges ? (
          <UnsavedChangesBar
            changedCount={changedControlIds.length}
            onSave={handleSave}
            onDiscard={handleDiscard}
            isSaving={isSaving}
          />
        ) : undefined
      }
    >
      <Table<SecurityControl>
        items={paginatedItems}
        loading={isLoading}
        loadingText="Loading controls"
        columnDefinitions={visibleColumns}
        stickyHeader
        stripedRows
        contentDensity={preferences.contentDensity}
        variant="full-page"
        selectionType="single"
        trackBy="controlId"
        ariaLabels={{
          selectionGroupLabel: 'Controls selection',
          tableLabel: 'Controls table',
        }}
        empty={<EmptyTableState title="No controls" subtitle="No controls to display." />}
        filter={
          <TextFilter
            {...filterProps}
            filteringPlaceholder="Search by Control ID..."
            countText={getFilterCounterText(filteredItemsCount)}
          />
        }
        header={
          <Header
            variant="awsui-h1-sticky"
            counter={getHeaderCounterText(localControls.length, selectedItems.length)}
            actions={
              <SpaceBetween direction="horizontal" size="xs">
                <Button
                  iconName="refresh"
                  onClick={() => {
                    handleRefresh();
                    if (!hasUnsavedChanges) setCurrentPageIndex(1);
                  }}
                  loading={isLoading}
                  disabled={hasUnsavedChanges}
                  ariaLabel="Refresh controls"
                />
                <Button
                  onClick={handleDisableAll}
                  disabled={isReadOnly || allRemediationDisabled || isLoading || isSaving}
                  ariaLabel="Disable All Automated Remediations"
                >
                  Disable All Automated Remediations
                </Button>
              </SpaceBetween>
            }
            description="Manage automated remediation settings for security findings across all accounts."
          >
            <SpaceBetween direction="horizontal" size="xs">
              Controls
              <ReadOnlyBadge visible={isReadOnly} />
            </SpaceBetween>
          </Header>
        }
        pagination={
          <Pagination
            currentPageIndex={currentPageIndex}
            pagesCount={totalPages || 1}
            onChange={({ detail }) => setCurrentPageIndex(detail.currentPageIndex)}
          />
        }
        preferences={
          <CollectionPreferences
            title="Preferences"
            confirmLabel="Confirm"
            cancelLabel="Cancel"
            preferences={{
              pageSize: preferences.pageSize,
              visibleContent: preferences.visibleContent,
              contentDensity: preferences.contentDensity,
            }}
            onConfirm={({ detail }) => {
              const updated: Preferences = {
                pageSize: detail.pageSize || DEFAULT_PREFERENCES.pageSize,
                visibleContent: [...(detail.visibleContent || DEFAULT_PREFERENCES.visibleContent)],
                contentDensity:
                  (detail.contentDensity as 'compact' | 'comfortable') || DEFAULT_PREFERENCES.contentDensity,
              };
              setPreferences(updated);
              controlsTablePreferences.save(updated);
              setCurrentPageIndex(1);
            }}
            pageSizePreference={{
              title: 'Page size',
              options: [
                { value: 10, label: '10 controls' },
                { value: 20, label: '20 controls' },
                { value: 50, label: '50 controls' },
              ],
            }}
            visibleContentPreference={{
              title: 'Select visible columns',
              options: [
                {
                  label: 'Column options',
                  options: [
                    { id: 'controlId', label: 'Control ID', editable: false },
                    { id: 'description', label: 'Description' },
                    { id: 'isEnabled', label: 'Automated Remediation' },
                    { id: 'appliedFilters', label: 'Applied Filters' },
                    { id: 'notifications', label: 'Notifications' },
                    { id: 'modifiedBy', label: 'Modified By' },
                    { id: 'lastModified', label: 'Last Modified' },
                  ],
                },
              ],
            }}
            contentDensityPreference={{
              label: 'Content density',
              description: 'Select the amount of vertical padding for table rows',
            }}
          />
        }
        {...collectionProps}
        selectedItems={selectedItems}
        onSelectionChange={handleSelectionChange}
      />
    </ContentLayout>
  );
};
