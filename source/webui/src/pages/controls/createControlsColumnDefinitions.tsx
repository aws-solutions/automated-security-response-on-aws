// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { TableProps } from '@cloudscape-design/components/table';
import { Badge, Box, Popover, SpaceBetween, Toggle } from '@cloudscape-design/components';

import { SecurityControl, ResourceFilter, NotificationConfigurationItem } from '@data-models';

interface CreateControlsColumnDefinitionsParams {
  onToggle: (controlId: string, isEnabled: boolean) => void;
  isReadOnly: boolean;
  filters: ResourceFilter[];
  notificationConfigs: NotificationConfigurationItem[];
}

const DESCRIPTION_MAX_LENGTH = 80;

export const createControlsColumnDefinitions = ({
  onToggle,
  isReadOnly,
  filters,
  notificationConfigs,
}: CreateControlsColumnDefinitionsParams): TableProps<SecurityControl>['columnDefinitions'] => {
  const filterMap = new Map(filters.map((f) => [f.filterId, f.name]));
  const globalNotificationNames = notificationConfigs
    .filter((config) => (config.controlIds ?? []).length === 0)
    .map((config) => config.name);
  const notificationUsageMap = new Map<string, string[]>();
  notificationConfigs.forEach((config) => {
    (config.controlIds ?? []).forEach((controlId) => {
      const existing = notificationUsageMap.get(controlId) ?? [];
      existing.push(config.name);
      notificationUsageMap.set(controlId, existing);
    });
  });
  return [
    {
      id: 'controlId',
      header: 'Control ID',
      cell: (item) => item.controlId,
      sortingField: 'controlId',
      width: 140,
    },
    {
      id: 'description',
      header: 'Description',
      cell: (item) => {
        if (item.description.length <= DESCRIPTION_MAX_LENGTH) {
          return item.description;
        }
        return (
          <Popover
            dismissButton={false}
            position="top"
            size="large"
            triggerType="custom"
            content={<Box padding="s">{item.description}</Box>}
          >
            <span style={{ cursor: 'pointer' }}>{item.description.slice(0, DESCRIPTION_MAX_LENGTH)}…</span>
          </Popover>
        );
      },
      width: 360,
    },
    {
      id: 'isEnabled',
      header: 'Automated Remediation',
      cell: (item) => (
        <Toggle
          checked={item.automatedRemediationEnabled}
          onChange={({ detail }) => onToggle(item.controlId, detail.checked)}
          disabled={isReadOnly}
          ariaLabel={`Toggle automated remediation for ${item.controlId}`}
        >
          {item.automatedRemediationEnabled ? 'Enabled' : 'Disabled'}
        </Toggle>
      ),
      sortingComparator: (a, b) => Number(a.automatedRemediationEnabled) - Number(b.automatedRemediationEnabled),
      width: 200,
    },
    {
      id: 'appliedFilters',
      header: 'Applied Filters',
      cell: (item) => {
        if (item.filters.length === 0) {
          return <Box color="text-status-inactive">All resources</Box>;
        }
        const color = item.filterMode === 'exclude' ? 'red' : 'green';
        if (item.filters.length <= 2) {
          return (
            <SpaceBetween direction="horizontal" size="xs">
              {item.filters.map((id) => (
                <Badge key={id} color={color}>
                  {filterMap.get(id) ?? id}
                </Badge>
              ))}
            </SpaceBetween>
          );
        }
        return (
          <SpaceBetween direction="horizontal" size="xs">
            <Badge color={color}>{filterMap.get(item.filters[0]) ?? item.filters[0]}</Badge>
            <Badge color={color}>+{item.filters.length - 1} more</Badge>
          </SpaceBetween>
        );
      },
    },
    {
      id: 'notifications',
      header: 'Notifications',
      cell: (item) => {
        const specific = notificationUsageMap.get(item.controlId) ?? [];
        const names = [...globalNotificationNames, ...specific];
        if (names.length === 0) return <Box color="text-status-inactive">None</Box>;
        if (names.length <= 2) {
          return (
            <SpaceBetween direction="horizontal" size="xs">
              {globalNotificationNames.map((name) => (
                <Badge key={name} color="grey">
                  {name}
                </Badge>
              ))}
              {specific.map((name) => (
                <Badge key={name} color="blue">
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
                      All controls:
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
                      This control:
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
      cell: (item) => item.modifiedBy || <Box color="text-status-inactive">—</Box>,
      sortingField: 'modifiedBy',
      width: 140,
    },
    {
      id: 'lastModified',
      header: 'Last Modified',
      cell: (item) =>
        item.lastModified ? new Date(item.lastModified).toLocaleString() : <Box color="text-status-inactive">—</Box>,
      sortingField: 'lastModified',
      width: 180,
    },
  ];
};
