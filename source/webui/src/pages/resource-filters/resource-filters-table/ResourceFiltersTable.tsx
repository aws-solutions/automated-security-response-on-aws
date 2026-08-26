// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { useState, useEffect, useMemo } from 'react';

import { useCollection } from '@cloudscape-design/collection-hooks';
import Header from '@cloudscape-design/components/header';
import Table from '@cloudscape-design/components/table';
import Button from '@cloudscape-design/components/button';
import ButtonDropdown from '@cloudscape-design/components/button-dropdown';
import Pagination from '@cloudscape-design/components/pagination';
import TextFilter from '@cloudscape-design/components/text-filter';
import SpaceBetween from '@cloudscape-design/components/space-between';
import Box from '@cloudscape-design/components/box';
import Badge from '@cloudscape-design/components/badge';
import Popover from '@cloudscape-design/components/popover';
import CollectionPreferences from '@cloudscape-design/components/collection-preferences';
import Select from '@cloudscape-design/components/select';

import { EmptyTableState } from '../../../components/EmptyTableState.tsx';
import { ReadOnlyBadge } from '../../../components/ReadOnlyBadge.tsx';
import { NotificationConfigurationItem, ResourceFilter, SecurityControl } from '@data-models';

const getFilterCounterText = (count = 0) => `${count} ${count === 1 ? 'match' : 'matches'}`;
const getHeaderCounterText = (
  items: readonly ResourceFilter[] | null = [],
  selected: readonly ResourceFilter[] = [],
) => {
  const total = items?.length || 0;
  return selected.length > 0 ? `(${selected.length}/${total})` : `(${total})`;
};

export interface ResourceFiltersTableProps {
  loading: boolean;
  filters: ResourceFilter[];
  controls: SecurityControl[];
  notificationConfigs: NotificationConfigurationItem[];
  onRefresh: () => void;
  onCreateFilter: () => void;
  onEditFilter: (filter: ResourceFilter) => void;
  onDeleteFilter: (filter: ResourceFilter) => void;
  onApplyToAll: (filter: ResourceFilter) => void;
  onRemoveFromAll: (filter: ResourceFilter) => void;
  resetPagination: boolean;
  mutationInFlight?: boolean;
  isReadOnly?: boolean;
}

interface Preferences {
  pageSize: number;
  visibleContent: string[];
  contentDensity: 'compact' | 'comfortable';
}

const DEFAULT_PREFERENCES: Preferences = {
  pageSize: 20,
  visibleContent: [
    'name',
    'accountIds',
    'ous',
    'tags',
    'arnPatterns',
    'usageCount',
    'notifications',
    'modifiedBy',
    'lastModified',
    'actions',
  ],
  contentDensity: 'comfortable',
};

type UsageFilterOption = 'all' | 'used' | 'unused';

const USAGE_FILTER_OPTIONS = [
  { label: 'All filters', value: 'all' },
  { label: 'Used filters', value: 'used' },
  { label: 'Unused filters', value: 'unused' },
];

export default function ResourceFiltersTable({
  loading,
  filters,
  controls,
  notificationConfigs,
  onRefresh,
  onCreateFilter,
  onEditFilter,
  onDeleteFilter,
  onApplyToAll,
  onRemoveFromAll,
  resetPagination,
  mutationInFlight = false,
  isReadOnly = false,
}: Readonly<ResourceFiltersTableProps>) {
  const [preferences, setPreferences] = useState<Preferences>(DEFAULT_PREFERENCES);
  const [currentPageIndex, setCurrentPageIndex] = useState(1);
  const [usageFilter, setUsageFilter] = useState<UsageFilterOption>('all');

  const filterUsageMap = useMemo(() => {
    const usage: Record<string, string[]> = {};
    filters.forEach((f) => {
      usage[f.filterId] = [];
    });
    controls.forEach((c) => {
      c.filters.forEach((fId) => {
        if (usage[fId]) {
          usage[fId].push(c.controlId);
        }
      });
    });
    return usage;
  }, [filters, controls]);

  const notificationUsageMap = useMemo(() => {
    const usage: Record<string, string[]> = {};
    filters.forEach((f) => {
      usage[f.filterId] = [];
    });
    notificationConfigs.forEach((c) => {
      (c.resourceFilterIds ?? []).forEach((fId) => {
        if (usage[fId]) usage[fId].push(c.name);
      });
    });
    return usage;
  }, [filters, notificationConfigs]);

  const globalNotificationNames = useMemo(
    () => notificationConfigs.filter((c) => (c.resourceFilterIds ?? []).length === 0).map((c) => c.name),
    [notificationConfigs],
  );

  const filteredByUsage = useMemo(() => {
    if (usageFilter === 'all') return filters;
    if (usageFilter === 'used') return filters.filter((f) => (filterUsageMap[f.filterId]?.length ?? 0) > 0);
    return filters.filter((f) => (filterUsageMap[f.filterId]?.length ?? 0) === 0);
  }, [filters, usageFilter, filterUsageMap]);

  const allColumnDefinitions = useMemo(
    () => [
      {
        id: 'name',
        header: 'Filter Name',
        cell: (item: ResourceFilter) => item.name,
        sortingField: 'name',
      },
      {
        id: 'accountIds',
        header: 'Account IDs',
        cell: (item: ResourceFilter) => {
          if (item.accountIds.length === 0) return <Box color="text-status-inactive">None</Box>;
          if (item.accountIds.length <= 2) {
            return (
              <SpaceBetween direction="horizontal" size="xs">
                {item.accountIds.map((id) => (
                  <Badge key={id}>{id}</Badge>
                ))}
              </SpaceBetween>
            );
          }
          return <Badge>{item.accountIds.length} accounts</Badge>;
        },
      },
      {
        id: 'ous',
        header: 'OUs',
        cell: (item: ResourceFilter) => {
          if (item.organizationalUnits.length === 0) return <Box color="text-status-inactive">None</Box>;
          if (item.organizationalUnits.length <= 2) {
            return (
              <SpaceBetween direction="horizontal" size="xs">
                {item.organizationalUnits.map((ou) => (
                  <Badge key={ou}>{ou}</Badge>
                ))}
              </SpaceBetween>
            );
          }
          return <Badge>{item.organizationalUnits.length} OUs</Badge>;
        },
      },
      {
        id: 'tags',
        header: 'Tags',
        cell: (item: ResourceFilter) => {
          if (item.tags.length === 0) return <Box color="text-status-inactive">None</Box>;
          if (item.tags.length <= 2) {
            return (
              <SpaceBetween direction="horizontal" size="xs">
                {item.tags.map((t) => (
                  <Badge key={`${t.key}=${t.value}`}>{`${t.key}=${t.value}`}</Badge>
                ))}
              </SpaceBetween>
            );
          }
          return <Badge>{item.tags.length} tags</Badge>;
        },
      },
      {
        id: 'arnPatterns',
        header: 'ARN Patterns',
        cell: (item: ResourceFilter) => {
          if (item.arnPatterns.length === 0) return <Box color="text-status-inactive">None</Box>;
          if (item.arnPatterns.length <= 2) {
            return (
              <SpaceBetween direction="horizontal" size="xs">
                {item.arnPatterns.map((arn) => (
                  <Badge key={arn}>{arn}</Badge>
                ))}
              </SpaceBetween>
            );
          }
          return <Badge>{item.arnPatterns.length} ARN patterns</Badge>;
        },
      },
      {
        id: 'usageCount',
        header: 'Controls',
        cell: (item: ResourceFilter) => {
          const controlIds = filterUsageMap[item.filterId] ?? [];
          if (controlIds.length === 0) {
            return <Box color="text-status-inactive">Unused</Box>;
          }
          if (controlIds.length <= 2) {
            return (
              <SpaceBetween direction="horizontal" size="xs">
                {controlIds.map((id) => (
                  <Badge key={id} color="green">
                    {id}
                  </Badge>
                ))}
              </SpaceBetween>
            );
          }
          return (
            <Popover
              dismissButton={false}
              position="top"
              size="medium"
              triggerType="custom"
              content={
                <Box padding="s">
                  <ul style={{ margin: 0, paddingLeft: '16px' }}>
                    {controlIds.map((id) => (
                      <li key={id}>{id}</li>
                    ))}
                  </ul>
                </Box>
              }
            >
              <SpaceBetween direction="horizontal" size="xs">
                <Badge color="green">{controlIds[0]}</Badge>
                <Badge color="green">+{controlIds.length - 1} more</Badge>
              </SpaceBetween>
            </Popover>
          );
        },
      },
      {
        id: 'notifications',
        header: 'Notifications',
        cell: (item: ResourceFilter) => {
          const specific = notificationUsageMap[item.filterId] ?? [];
          const names = [...globalNotificationNames, ...specific];
          if (names.length === 0) return <Box color="text-status-inactive">None</Box>;
          if (names.length <= 2) {
            return (
              <SpaceBetween direction="horizontal" size="xs">
                {globalNotificationNames.map((name) => (
                  <Badge key={`global-${name}`} color="grey">
                    {name}
                  </Badge>
                ))}
                {specific.map((name) => (
                  <Badge key={`specific-${name}`} color="blue">
                    {name}
                  </Badge>
                ))}
              </SpaceBetween>
            );
          }
          return (
            <Popover
              dismissButton={false}
              position="top"
              size="medium"
              triggerType="custom"
              content={
                <Box padding="s">
                  {globalNotificationNames.length > 0 && (
                    <>
                      <Box variant="small" color="text-status-inactive">
                        All resources:
                      </Box>
                      <ul style={{ margin: 0, paddingLeft: '16px' }}>
                        {globalNotificationNames.map((name) => (
                          <li key={name}>{name}</li>
                        ))}
                      </ul>
                    </>
                  )}
                  {specific.length > 0 && (
                    <>
                      <Box variant="small" color="text-status-inactive">
                        This filter:
                      </Box>
                      <ul style={{ margin: 0, paddingLeft: '16px' }}>
                        {specific.map((name) => (
                          <li key={name}>{name}</li>
                        ))}
                      </ul>
                    </>
                  )}
                </Box>
              }
            >
              <SpaceBetween direction="horizontal" size="xs">
                <Badge color={globalNotificationNames.includes(names[0]) ? 'grey' : 'blue'}>{names[0]}</Badge>
                <Badge color="blue">+{names.length - 1} more</Badge>
              </SpaceBetween>
            </Popover>
          );
        },
        width: 180,
      },
      {
        id: 'modifiedBy',
        header: 'Modified By',
        cell: (item: ResourceFilter) => item.modifiedBy || <Box color="text-status-inactive">—</Box>,
        sortingField: 'modifiedBy',
        width: 140,
      },
      {
        id: 'lastModified',
        header: 'Last Modified',
        cell: (item: ResourceFilter) =>
          item.lastModified ? new Date(item.lastModified).toLocaleString() : <Box color="text-status-inactive">—</Box>,
        sortingField: 'lastModified',
        width: 180,
      },
      {
        id: 'actions',
        header: 'Actions',
        cell: (item: ResourceFilter) => {
          const controlIds = filterUsageMap[item.filterId] ?? [];
          const actionItems = isReadOnly
            ? []
            : [
                { id: 'edit', text: 'Edit' },
                { id: 'delete', text: 'Delete' },
                { id: 'applyToAll', text: 'Apply to all controls' },
                ...(controlIds.length > 0 ? [{ id: 'removeFromAll', text: 'Remove from all controls' }] : []),
              ];
          if (actionItems.length === 0) return <Box color="text-status-inactive">—</Box>;
          return (
            <ButtonDropdown
              items={actionItems}
              onItemClick={({ detail }) => {
                if (detail.id === 'edit') onEditFilter(item);
                else if (detail.id === 'delete') onDeleteFilter(item);
                else if (detail.id === 'applyToAll') onApplyToAll(item);
                else if (detail.id === 'removeFromAll') onRemoveFromAll(item);
              }}
              expandToViewport
              variant="icon"
              ariaLabel={`Actions for ${item.name}`}
              disabled={mutationInFlight}
            />
          );
        },
        width: 80,
      },
    ],
    [
      filterUsageMap,
      notificationUsageMap,
      globalNotificationNames,
      onEditFilter,
      onDeleteFilter,
      onApplyToAll,
      onRemoveFromAll,
      isReadOnly,
      mutationInFlight,
    ],
  );

  const visibleColumns = allColumnDefinitions.filter((col) => preferences.visibleContent.includes(col.id));

  const { items, filterProps, actions, filteredItemsCount, collectionProps } = useCollection<ResourceFilter>(
    filteredByUsage,
    {
      filtering: {
        filteringFunction: (item, filteringText) => {
          const s = filteringText.toLowerCase();
          return (
            item.name.toLowerCase().includes(s) ||
            item.accountIds.some((id) => id.includes(s)) ||
            item.organizationalUnits.some((ou) => ou.toLowerCase().includes(s)) ||
            item.tags.some((t) => t.key.toLowerCase().includes(s) || t.value.toLowerCase().includes(s)) ||
            item.arnPatterns.some((arn) => arn.toLowerCase().includes(s))
          );
        },
        noMatch: (
          <EmptyTableState
            title="No matches"
            subtitle="We can't find a match."
            action={<Button onClick={() => actions.setFiltering('')}>Clear filter</Button>}
          />
        ),
        empty: (
          <EmptyTableState
            title="No resource filters"
            subtitle="No resource filters to display."
            action={
              isReadOnly ? undefined : (
                <Button onClick={onCreateFilter} disabled={mutationInFlight}>
                  Create filter
                </Button>
              )
            }
          />
        ),
      },
      sorting: { defaultState: { sortingColumn: { sortingField: 'name' } } },
      selection: { trackBy: 'filterId' },
    },
  );

  useEffect(() => {
    if (resetPagination) setCurrentPageIndex(1);
  }, [resetPagination]);

  const totalPages = Math.ceil(items.length / preferences.pageSize);
  const startIndex = (currentPageIndex - 1) * preferences.pageSize;
  const paginatedItems = items.slice(startIndex, startIndex + preferences.pageSize);

  return (
    <Table<ResourceFilter>
      items={paginatedItems}
      loading={loading}
      loadingText="Loading resource filters"
      columnDefinitions={visibleColumns}
      stickyHeader
      stripedRows
      contentDensity={preferences.contentDensity}
      variant="full-page"
      ariaLabels={{ tableLabel: 'Resource filters table' }}
      empty={
        <EmptyTableState
          title="No resource filters"
          subtitle="Create your first resource filter to scope remediation."
          action={
            isReadOnly ? undefined : (
              <Button onClick={onCreateFilter} disabled={mutationInFlight}>
                Create filter
              </Button>
            )
          }
        />
      }
      filter={
        <SpaceBetween direction="horizontal" size="s">
          <TextFilter
            {...filterProps}
            filteringPlaceholder="Search resource filters..."
            countText={getFilterCounterText(filteredItemsCount)}
          />
          <Select
            selectedOption={
              USAGE_FILTER_OPTIONS.find((option) => option.value === usageFilter) ?? USAGE_FILTER_OPTIONS[0]
            }
            onChange={({ detail }) => {
              const value = detail.selectedOption.value;
              setUsageFilter(value === 'used' || value === 'unused' ? value : 'all');
              setCurrentPageIndex(1);
            }}
            options={USAGE_FILTER_OPTIONS}
            ariaLabel="Filter by usage"
          />
        </SpaceBetween>
      }
      header={
        <Header
          variant="awsui-h1-sticky"
          counter={
            usageFilter === 'all' ? getHeaderCounterText(filters) : `(${filteredByUsage.length}/${filters.length})`
          }
          actions={
            <SpaceBetween direction="horizontal" size="xs">
              <Button iconName="refresh" onClick={onRefresh} loading={loading} ariaLabel="Refresh resource filters" />
              {!isReadOnly && (
                <Button variant="primary" onClick={onCreateFilter} disabled={mutationInFlight}>
                  Create resource filter
                </Button>
              )}
            </SpaceBetween>
          }
          description="Define reusable filters to target specific AWS accounts, organizational units, resources by tags, or ARN patterns."
        >
          <SpaceBetween direction="horizontal" size="xs">
            Resource Filters
            <ReadOnlyBadge visible={isReadOnly} />
          </SpaceBetween>
        </Header>
      }
      pagination={
        // Cloudscape Pagination requires pagesCount >= 1
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
            setPreferences({
              pageSize: detail.pageSize || DEFAULT_PREFERENCES.pageSize,
              visibleContent: [...(detail.visibleContent || DEFAULT_PREFERENCES.visibleContent)],
              contentDensity:
                (detail.contentDensity as 'compact' | 'comfortable') || DEFAULT_PREFERENCES.contentDensity,
            });
            setCurrentPageIndex(1);
          }}
          pageSizePreference={{
            title: 'Page size',
            options: [
              { value: 10, label: '10 filters' },
              { value: 20, label: '20 filters' },
              { value: 50, label: '50 filters' },
            ],
          }}
          visibleContentPreference={{
            title: 'Select visible columns',
            options: [
              {
                label: 'Column options',
                options: [
                  { id: 'name', label: 'Filter Name', editable: false },
                  { id: 'accountIds', label: 'Account IDs' },
                  { id: 'ous', label: 'OUs' },
                  { id: 'tags', label: 'Tags' },
                  { id: 'arnPatterns', label: 'ARN Patterns' },
                  { id: 'usageCount', label: 'Usage' },
                  { id: 'notifications', label: 'Notifications' },
                  { id: 'modifiedBy', label: 'Modified By' },
                  { id: 'lastModified', label: 'Last Modified' },
                  { id: 'actions', label: 'Actions' },
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
    />
  );
}
