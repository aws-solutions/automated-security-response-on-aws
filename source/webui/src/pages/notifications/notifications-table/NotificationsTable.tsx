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
import Toggle from '@cloudscape-design/components/toggle';
import Badge from '@cloudscape-design/components/badge';
import Box from '@cloudscape-design/components/box';
import Popover from '@cloudscape-design/components/popover';
import CollectionPreferences from '@cloudscape-design/components/collection-preferences';

import { EmptyTableState } from '../../../components/EmptyTableState.tsx';
import {
  NotificationConfigurationItem,
  channelLabel,
  severityLabel,
  severityBadgeColor,
} from '../../../store/controlPanelTypes.ts';
import { ResourceFilter } from '@data-models';

const getFilterCounterText = (count = 0) => `${count} ${count === 1 ? 'match' : 'matches'}`;

/** Shown to account operators on configurations they did not create, where actions are disabled. */
const RESTRICTED_ACTION_MESSAGE =
  'Only the account operator who created this notification, or an administrator, can modify it.';

const getHeaderCounterText = (
  items: readonly NotificationConfigurationItem[] | null = [],
  selectedItems: readonly NotificationConfigurationItem[] = [],
) => {
  const total = items?.length || 0;
  return selectedItems.length > 0 ? `(${selectedItems.length}/${total})` : `(${total})`;
};

/** Visible column preference id — kept as a stable identifier for persistence. */
interface PreferencesState {
  pageSize: number;
  visibleContent: string[];
  contentDensity: 'compact' | 'comfortable';
}

const DEFAULT_PREFERENCES: PreferencesState = {
  pageSize: 20,
  visibleContent: [
    'name',
    'enabled',
    'notificationType',
    'severity',
    'remediationStatus',
    'deliveryChannels',
    'controlIds',
    'resourceFilters',
    'batch',
    'createdBy',
    'modifiedBy',
    'lastModified',
    'actions',
  ],
  contentDensity: 'comfortable',
};

export interface NotificationsTableProps {
  loading: boolean;
  configs: NotificationConfigurationItem[];
  resourceFilters: ResourceFilter[];
  onRefresh: () => void;
  onCreateConfig: () => void;
  onEditConfig: (config: NotificationConfigurationItem) => void;
  onDeleteConfig: (config: NotificationConfigurationItem) => void;
  onManageSubscriptions: (config: NotificationConfigurationItem) => void;
  onSendTest?: (config: NotificationConfigurationItem) => void;
  onToggle: (configId: string, enabled: boolean) => void;
  resetPagination: boolean;
  mutationInFlight?: boolean;
  canSendTest?: boolean;
  /**
   * Whether the current user may modify (edit, delete, toggle) a given configuration. Rows the user
   * cannot modify render their mutating actions disabled. Defaults to allowing all when omitted.
   */
  canModifyConfig?: (config: NotificationConfigurationItem) => boolean;
}

export default function NotificationsTable({
  loading,
  configs,
  resourceFilters,
  onRefresh,
  onCreateConfig,
  onEditConfig,
  onDeleteConfig,
  onManageSubscriptions,
  onSendTest,
  onToggle,
  resetPagination,
  mutationInFlight = false,
  canSendTest = false,
  canModifyConfig = () => true,
}: Readonly<NotificationsTableProps>) {
  const [preferences, setPreferences] = useState<PreferencesState>(DEFAULT_PREFERENCES);
  const [currentPageIndex, setCurrentPageIndex] = useState(1);

  const filterNameMap = useMemo(() => new Map(resourceFilters.map((f) => [f.filterId, f.name])), [resourceFilters]);

  const { items, filterProps, actions, filteredItemsCount, collectionProps } =
    useCollection<NotificationConfigurationItem>(Array.isArray(configs) ? configs : [], {
      filtering: {
        filteringFunction: (item, filteringText) => {
          const s = filteringText.toLowerCase();
          return (
            item.name.toLowerCase().includes(s) ||
            item.deliveryChannels.some((dc) => dc.type.toLowerCase().includes(s)) ||
            (item.severityFilter ?? []).some((sev) => sev.toLowerCase().includes(s)) ||
            item.notificationType.toLowerCase().includes(s)
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
            title="No notification configurations"
            subtitle="No notification configurations to display."
            action={<Button onClick={onCreateConfig}>Create configuration</Button>}
          />
        ),
      },
      sorting: { defaultState: { sortingColumn: { sortingField: 'name' } } },
      selection: { trackBy: 'configId' },
    });

  useEffect(() => {
    if (resetPagination) setCurrentPageIndex(1);
  }, [resetPagination]);

  const pageSize = preferences.pageSize;
  const totalPages = Math.ceil(items.length / pageSize);
  const startIndex = (currentPageIndex - 1) * pageSize;
  const paginatedItems = items.slice(startIndex, startIndex + pageSize);

  const allColumnDefinitions = [
    {
      id: 'name',
      header: 'Name',
      cell: (item: NotificationConfigurationItem) => item.name,
      sortingField: 'name',
      minWidth: 180,
    },
    {
      id: 'enabled',
      header: 'Status',
      cell: (item: NotificationConfigurationItem) => {
        const canModify = canModifyConfig(item);
        const toggle = (
          <Toggle
            checked={item.enabled}
            onChange={({ detail }) => onToggle(item.configId, detail.checked)}
            disabled={mutationInFlight || !canModify}
            ariaLabel={`Toggle ${item.name} ${item.enabled ? 'off' : 'on'}`}
          />
        );
        if (canModify) return toggle;
        return (
          <Popover
            dismissButton={false}
            position="top"
            size="small"
            triggerType="custom"
            content={RESTRICTED_ACTION_MESSAGE}
          >
            {toggle}
          </Popover>
        );
      },
      width: 100,
    },
    {
      id: 'notificationType',
      header: 'Type',
      cell: (item: NotificationConfigurationItem) => (
        <Box color={item.notificationType === 'finding' ? 'text-status-info' : 'text-status-success'}>
          {item.notificationType === 'finding' ? 'Finding' : 'Remediation'}
        </Box>
      ),
      width: 130,
    },
    {
      id: 'severity',
      header: 'Severity',
      cell: (item: NotificationConfigurationItem) => {
        const filter = item.severityFilter ?? [];
        if (filter.length === 0 || filter.includes('All')) {
          return <Badge color="grey">All</Badge>;
        }
        return (
          <SpaceBetween direction="horizontal" size="xxs">
            {filter.map((s) => (
              <Badge key={s} color={severityBadgeColor(s)}>
                {severityLabel(s)}
              </Badge>
            ))}
          </SpaceBetween>
        );
      },
      width: 160,
    },
    {
      id: 'deliveryChannels',
      header: 'Channels',
      cell: (item: NotificationConfigurationItem) => {
        if (item.deliveryChannels.length === 0) return <Box color="text-status-inactive">None</Box>;
        return (
          <SpaceBetween direction="horizontal" size="xs">
            {/* dc.type is a safe React key: the config schema enforces one channel per type
                (`new Set(types).size === types.length` refine in notification.ts). */}
            {item.deliveryChannels.map((dc) => (
              <Badge key={dc.type} color="blue">
                {channelLabel(dc.type)}
              </Badge>
            ))}
          </SpaceBetween>
        );
      },
      width: 160,
    },
    {
      id: 'controlIds',
      header: 'Controls',
      cell: (item: NotificationConfigurationItem) => {
        const ids = item.controlIds ?? [];
        if (ids.length === 0) {
          return <Box color="text-status-inactive">All controls</Box>;
        }
        if (ids.length <= 2) {
          return (
            <SpaceBetween direction="horizontal" size="xs">
              {ids.map((id) => (
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
                  {ids.map((id) => (
                    <li key={id}>{id}</li>
                  ))}
                </ul>
              </Box>
            }
          >
            <SpaceBetween direction="horizontal" size="xs">
              <Badge color="green">{ids[0]}</Badge>
              <Badge color="green">+{ids.length - 1} more</Badge>
            </SpaceBetween>
          </Popover>
        );
      },
      width: 180,
    },
    {
      id: 'resourceFilters',
      header: 'Resource filters',
      cell: (item: NotificationConfigurationItem) => {
        const ids = item.resourceFilterIds ?? [];
        if (ids.length === 0) return <Box color="text-status-inactive">All resources</Box>;
        if (ids.length <= 2) {
          return (
            <SpaceBetween direction="horizontal" size="xs">
              {ids.map((id) => (
                <Badge key={id} color="green">
                  {filterNameMap.get(id) ?? id}
                </Badge>
              ))}
            </SpaceBetween>
          );
        }
        return (
          <SpaceBetween direction="horizontal" size="xs">
            <Badge color="green">{filterNameMap.get(ids[0]) ?? ids[0]}</Badge>
            <Badge color="green">+{ids.length - 1} more</Badge>
          </SpaceBetween>
        );
      },
      width: 160,
    },
    {
      id: 'batch',
      header: 'Batch',
      cell: (item: NotificationConfigurationItem) => (
        <Badge color={item.batchWindow.enabled ? 'green' : 'grey'}>{item.batchWindow.enabled ? 'true' : 'false'}</Badge>
      ),
      width: 100,
    },
    {
      id: 'createdBy',
      header: 'Created by',
      cell: (item: NotificationConfigurationItem) => item.createdBy || <Box color="text-status-inactive">—</Box>, // NOSONAR: Cloudscape cell render prop, not a mounted component
      sortingField: 'createdBy',
      width: 200,
    },
    {
      id: 'modifiedBy',
      header: 'Modified By',
      cell: (item: NotificationConfigurationItem) =>
        item.updatedBy || item.createdBy || <Box color="text-status-inactive">—</Box>,
      sortingField: 'updatedBy',
      width: 140,
    },
    {
      id: 'lastModified',
      header: 'Last Modified',
      cell: (item: NotificationConfigurationItem) => {
        const timestamp = item.updatedAt || item.createdAt;
        return timestamp ? new Date(timestamp).toLocaleString() : <Box color="text-status-inactive">—</Box>;
      },
      sortingField: 'updatedAt',
      width: 180,
    },
    {
      id: 'remediationStatus',
      header: 'Status Filter',
      cell: (item: NotificationConfigurationItem) => {
        if (item.notificationType !== 'remediation') return <Box color="text-status-inactive">—</Box>;
        const filter = item.remediationStatusFilter ?? [];
        if (filter.length === 0 || filter.includes('All')) {
          return <Badge color="grey">All</Badge>;
        }
        return (
          <SpaceBetween direction="horizontal" size="xxs">
            {filter.map((s) => (
              <Badge key={s} color="grey">
                {s}
              </Badge>
            ))}
          </SpaceBetween>
        );
      },
      width: 140,
    },
    {
      id: 'actions',
      header: 'Actions',
      cell: (item: NotificationConfigurationItem) => {
        const hasEmail = item.deliveryChannels.some((ch) => ch.type === 'email' && ch.enabled);
        const canModify = canModifyConfig(item);
        const restricted = canModify ? {} : { disabled: true, disabledReason: RESTRICTED_ACTION_MESSAGE };
        // Send test and Email subscriptions act on a specific config, so they follow the same
        // creator-based authority as edit/delete: available to admins on any config, and to an
        // account operator only on configurations they created.
        const items = [
          { id: 'edit', text: 'Edit', ...restricted },
          ...(hasEmail && canModify ? [{ id: 'subscriptions', text: 'Email subscriptions' }] : []),
          ...(canSendTest && canModify && onSendTest ? [{ id: 'send-test', text: 'Send test' }] : []),
          { id: 'delete', text: 'Delete', ...restricted },
        ];
        return (
          <ButtonDropdown
            items={items}
            onItemClick={({ detail }) => {
              if (detail.id === 'edit') onEditConfig(item);
              else if (detail.id === 'subscriptions') onManageSubscriptions(item);
              else if (detail.id === 'send-test') onSendTest?.(item);
              else if (detail.id === 'delete') onDeleteConfig(item);
            }}
            expandToViewport
            variant="icon"
            ariaLabel={`Actions for ${item.name}`}
            disabled={mutationInFlight}
          />
        );
      },
      width: 60,
    },
  ];

  const visibleColumns = allColumnDefinitions.filter((col) => preferences.visibleContent.includes(col.id));

  return (
    <Table<NotificationConfigurationItem>
      items={paginatedItems}
      loading={loading}
      loadingText="Loading notification configurations"
      columnDefinitions={visibleColumns}
      stickyHeader
      stripedRows
      contentDensity={preferences.contentDensity}
      variant="full-page"
      selectionType="single"
      ariaLabels={{
        selectionGroupLabel: 'Notification configurations selection',
        tableLabel: 'Notification configurations table',
      }}
      empty={
        <EmptyTableState
          title="No notification configurations"
          subtitle="No notification configurations to display."
          action={<Button onClick={onCreateConfig}>Create configuration</Button>}
        />
      }
      filter={
        <TextFilter
          {...filterProps}
          filteringPlaceholder="Search by name, channel type, or severity..."
          countText={getFilterCounterText(filteredItemsCount)}
        />
      }
      header={
        <Header
          variant="awsui-h1-sticky"
          counter={getHeaderCounterText(configs)}
          actions={
            <SpaceBetween direction="horizontal" size="xs">
              <Button iconName="refresh" onClick={onRefresh} loading={loading} ariaLabel="Refresh" />
              <Button variant="primary" onClick={onCreateConfig} disabled={mutationInFlight}>
                Create channel
              </Button>
            </SpaceBetween>
          }
          description="Configure notification channels to alert your team about security findings and remediation events."
        >
          Notifications
        </Header>
      }
      pagination={
        <Pagination
          currentPageIndex={currentPageIndex}
          pagesCount={totalPages}
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
              { value: 10, label: '10 configurations' },
              { value: 20, label: '20 configurations' },
              { value: 50, label: '50 configurations' },
            ],
          }}
          visibleContentPreference={{
            title: 'Select visible columns',
            options: [
              {
                label: 'Column options',
                options: [
                  { id: 'name', label: 'Name', editable: false },
                  { id: 'enabled', label: 'Status' },
                  { id: 'notificationType', label: 'Type' },
                  { id: 'severity', label: 'Severity' },
                  { id: 'remediationStatus', label: 'Status Filter' },
                  { id: 'deliveryChannels', label: 'Delivery Channels' },
                  { id: 'controlIds', label: 'Controls' },
                  { id: 'resourceFilters', label: 'Applied filters' },
                  { id: 'batch', label: 'Batch' },
                  { id: 'createdBy', label: 'Created by' },
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
