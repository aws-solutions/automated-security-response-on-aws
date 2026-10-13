// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { TableProps } from '@cloudscape-design/components/table';
import { Badge, Box, Popover, SpaceBetween, Toggle } from '@cloudscape-design/components';

import type { ReactElement } from 'react';

import { SecurityControl, ResourceFilter, NotificationConfigurationItem } from '@data-models';

interface CreateControlsColumnDefinitionsParams {
  onToggle: (controlId: string, isEnabled: boolean) => void;
  onRollbackToggle: (controlId: string, isEnabled: boolean) => void;
  isReadOnly: boolean;
  filters: ResourceFilter[];
  notificationConfigs: NotificationConfigurationItem[];
}

const DESCRIPTION_MAX_LENGTH = 80;

/**
 * True when the control's remediation comes from a customer-authored custom runbook.
 *
 * `source` is optional on the API response: controls written before the field existed
 * carry no value, and those are built-ins. Treating only an explicit 'custom' as custom
 * keeps an older record from losing its actionable toggle.
 */
export const isCustomControl = (control: SecurityControl): boolean => control.source === 'custom';

/**
 * Which runbook a control is served by, as the operator should read it: `Built-in` for a
 * shipped remediation, `Custom v3` for a customer-authored one. Composed from
 * {@link describeRunbookType} and {@link describeRunbookVersion} so the `Built-in`, `Custom`
 * and `v` tokens have a single definition — the table renders the two parts in their own
 * columns, the detail panel renders this combined form.
 *
 * The number is the deployed runbook version the API reports (`runbookVersion`), never the
 * config row's `version`, which is an optimistic-lock counter and would read as a meaningless
 * "version". Only the most recently DEPLOYED version of a custom runbook runs — re-deploying
 * an earlier version makes that earlier version current again — so the number shown is the one
 * the Orchestrator will start on the next finding, not the highest ever registered. A custom
 * control whose version is not yet known (the deploy record has not been read) shows `Custom`
 * alone.
 */
export const describeRunbook = (control: SecurityControl): string =>
  [describeRunbookType(control), describeRunbookVersion(control)].filter(Boolean).join(' ');

/**
 * The runbook type on its own: `Built-in` for a shipped remediation, `Custom` for a
 * customer-authored one.
 */
export const describeRunbookType = (control: SecurityControl): string =>
  isCustomControl(control) ? 'Custom' : 'Built-in';

/**
 * The deployed version of a custom runbook, rendered on its own: `v3` for a known version,
 * empty for a built-in (which has no version) or a custom control whose version is not yet
 * known. See {@link describeRunbook} for why this is `runbookVersion`, not the config row's
 * optimistic-lock `version`.
 */
export const describeRunbookVersion = (control: SecurityControl): string => {
  if (!isCustomControl(control) || control.runbookVersion === undefined) return '';
  return `v${control.runbookVersion}`;
};

/**
 * Render the Automated Remediation cell.
 *
 * A custom runbook only runs on a manual trigger — the Orchestrator's resolver checks the
 * event type before it looks up a custom runbook, so an automatically triggered finding
 * never reaches one. Offering an actionable toggle for one would let the page report
 * "Enabled" for a control that is never remediated, so a custom control shows its state
 * without a switch. The API refuses the write too; this is the readable half of that
 * guard, not the whole of it.
 *
 * Three outcomes, as early returns rather than nested ternaries in the cell: a built-in
 * gets the ordinary toggle, a custom control that is somehow enabled gets a one-way
 * switch, and a custom control that is off gets an explanation.
 */
const renderAutomatedRemediation = (
  control: SecurityControl,
  isReadOnly: boolean,
  onToggle: (controlId: string, isEnabled: boolean) => void,
): ReactElement => {
  if (!isCustomControl(control)) {
    return (
      <Toggle
        checked={control.automatedRemediationEnabled}
        onChange={({ detail }) => onToggle(control.controlId, detail.checked)}
        disabled={isReadOnly}
        ariaLabel={`Toggle automated remediation for ${control.controlId}`}
      >
        {control.automatedRemediationEnabled ? 'Enabled' : 'Disabled'}
      </Toggle>
    );
  }

  // Enabled before this guard existed, so the stored flag disagrees with what the
  // resolver does. The switch stays available in the off direction only, otherwise a
  // customer sees "Enabled", learns it means nothing, and has no way to correct it —
  // the API still accepts disabling for exactly this case.
  if (control.automatedRemediationEnabled) {
    return (
      <Toggle
        checked
        onChange={() => onToggle(control.controlId, false)}
        disabled={isReadOnly}
        ariaLabel={`Turn off automated remediation for ${control.controlId}`}
      >
        Enabled (no effect)
      </Toggle>
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
          This control is remediated by a custom runbook, which runs only on a manual trigger — a Security Hub custom
          action or the API. Automated remediation does not apply.
        </Box>
      }
    >
      <Box color="text-status-inactive">Manual trigger only</Box>
    </Popover>
  );
};

export const createControlsColumnDefinitions = ({
  onToggle,
  onRollbackToggle,
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
      cell: (item) => renderAutomatedRemediation(item, isReadOnly, onToggle),
      sortingComparator: (a, b) => Number(a.automatedRemediationEnabled) - Number(b.automatedRemediationEnabled),
      width: 200,
    },
    {
      id: 'source',
      header: 'Runbook Type',
      // Which runbook serves the control: a shipped remediation, or a customer-authored one.
      // Without it, the "Manual trigger only" cell above reads as arbitrary — this is the
      // column that explains it. The live version is shown separately in 'Runbook Version'.
      cell: (item) => describeRunbookType(item),
      sortingComparator: (a, b) => Number(isCustomControl(a)) - Number(isCustomControl(b)),
      width: 120,
    },
    {
      id: 'runbookVersion',
      header: 'Runbook Version',
      // The version of the customer-authored runbook that is live, so the operator can tell
      // which version actually runs. Empty for built-ins and for custom controls whose
      // deployed version is not yet known.
      cell: (item) => describeRunbookVersion(item) || <Box color="text-status-inactive">—</Box>,
      sortingComparator: (a, b) => (a.runbookVersion ?? 0) - (b.runbookVersion ?? 0),
      width: 130,
    },
    {
      id: 'rollbackEnabled',
      header: 'Rollback',
      cell: (item) =>
        // Only rollback-eligible controls get a toggle; others show a muted placeholder.
        item.rollbackSupported ? (
          <Toggle
            checked={item.rollbackEnabled !== false}
            onChange={({ detail }) => onRollbackToggle(item.controlId, detail.checked)}
            disabled={isReadOnly}
            ariaLabel={`Toggle rollback for ${item.controlId}`}
          >
            {item.rollbackEnabled === false ? 'Disabled' : 'Enabled'}
          </Toggle>
        ) : (
          <Box color="text-status-inactive">Not supported</Box>
        ),
      sortingComparator: (a, b) => Number(a.rollbackEnabled !== false) - Number(b.rollbackEnabled !== false),
      width: 160,
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
