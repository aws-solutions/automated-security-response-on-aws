// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { useMemo, useState } from 'react';
import { Box, Checkbox, SpaceBetween, Table } from '@cloudscape-design/components';
import { TableProps } from '@cloudscape-design/components/table';
import { GrantableTool, ToolCategory } from '../store/usersApiSlice.ts';

interface ToolPermissionsTableProps {
  /** The grantable-tool catalog (name + lowest tier that may be granted it + category). */
  tools: readonly GrantableTool[];
  /** Names of the tools currently granted to the user. */
  grantedTools: ReadonlySet<string>;
  /**
   * Called with every tool name whose grant is changing and the new state. A single
   * row passes one name; a category row passes every tool in that category, so the
   * whole group is applied as one update instead of a burst of single-tool calls.
   */
  onToggle: (toolNames: readonly string[], granted: boolean) => void;
  loading?: boolean;
}

const tierLabel: Record<GrantableTool['tier'], string> = {
  AccountOperator: 'Account Operator',
  DelegatedAdmin: 'Delegated Admin',
};

// Display order for the categories: read-only surfaces first, then the ones that
// mutate remediation state, then policy. Ordering is explicit rather than
// alphabetical so the least privileged groups are what an Admin sees first.
const categoryDisplayOrder: readonly ToolCategory[] = [
  'Discovery',
  'Reporting',
  'Notifications',
  'Remediation',
  'Infrastructure',
  'Policy',
  'Other',
];

const categoryLabel: Record<ToolCategory, string> = {
  Discovery: 'Discovery & triage',
  Reporting: 'Reporting',
  Notifications: 'Notifications',
  Remediation: 'Remediation',
  Infrastructure: 'Infrastructure & deployment',
  Policy: 'Policy & controls',
  Other: 'Other tools',
};

// A category the backend introduces before this component knows about it sorts last
// rather than jumping to the front of the list.
const categoryRank = (category: ToolCategory): number => {
  const rank = categoryDisplayOrder.indexOf(category);
  return rank === -1 ? categoryDisplayOrder.length : rank;
};

interface ToolRow {
  kind: 'tool';
  key: string;
  tool: GrantableTool;
}

interface CategoryRow {
  kind: 'category';
  key: string;
  category: ToolCategory;
  children: readonly ToolRow[];
}

/**
 * A row in the grouped table: either a category header (expandable, with a
 * grant-all toggle) or a single tool nested under one.
 */
type ToolPermissionRow = CategoryRow | ToolRow;

/**
 * Group the flat catalog into one expandable row per category, preserving the
 * catalog's order within each category (which mirrors the tier lists, so the tools
 * grantable to the lower tier come first).
 */
const buildCategoryRows = (tools: readonly GrantableTool[]): readonly CategoryRow[] => {
  const toolsByCategory = new Map<ToolCategory, GrantableTool[]>();
  tools.forEach((tool) => {
    const existing = toolsByCategory.get(tool.category);
    if (existing) {
      existing.push(tool);
    } else {
      toolsByCategory.set(tool.category, [tool]);
    }
  });

  return [...toolsByCategory.entries()]
    .sort(([left], [right]) => categoryRank(left) - categoryRank(right))
    .map(([category, categoryTools]) => ({
      kind: 'category' as const,
      key: `category:${category}`,
      category,
      children: categoryTools.map((tool) => ({ kind: 'tool' as const, key: `tool:${tool.name}`, tool })),
    }));
};

/** The lowest tier any tool in the category is grantable to — the group's minimum tier. */
const lowestTierInCategory = (row: CategoryRow): GrantableTool['tier'] =>
  row.children.some(({ tool }) => tool.tier === 'AccountOperator') ? 'AccountOperator' : 'DelegatedAdmin';

const categoryToolNames = (row: CategoryRow): readonly string[] => row.children.map(({ tool }) => tool.name);

/** How a row is named in the expand/collapse control's accessible label. */
const rowLabel = (row: ToolPermissionRow): string =>
  row.kind === 'category' ? (categoryLabel[row.category] ?? row.category) : row.tool.name;

const countGranted = (row: CategoryRow, grantedTools: ReadonlySet<string>): number =>
  row.children.filter(({ tool }) => grantedTools.has(tool.name)).length;

interface ToolGrantCheckboxProps {
  tool: GrantableTool;
  granted: boolean;
  onToggle: ToolPermissionsTableProps['onToggle'];
}

/**
 * The "Granted" cell for one tool row. Defined at module scope (not inline in the
 * table's columnDefinitions) so it is a stable component that receives its row data
 * as props rather than being re-created on every parent render.
 */
const ToolGrantCheckbox = ({ tool, granted, onToggle }: ToolGrantCheckboxProps): React.ReactElement => (
  <Checkbox
    checked={granted}
    onChange={({ detail }) => onToggle([tool.name], detail.checked)}
    data-testid={`tool-grant-${tool.name}`}
    ariaLabel={`Grant ${tool.name}`}
  />
);

interface CategoryGrantCheckboxProps {
  row: CategoryRow;
  grantedTools: ReadonlySet<string>;
  onToggle: ToolPermissionsTableProps['onToggle'];
}

/**
 * The "Granted" cell for a category row: grants or revokes every tool in the
 * category at once, and shows the indeterminate state while only some are granted so
 * a partial group is never mistaken for an empty one.
 */
const CategoryGrantCheckbox = ({ row, grantedTools, onToggle }: CategoryGrantCheckboxProps): React.ReactElement => {
  const grantedCount = countGranted(row, grantedTools);
  return (
    <Checkbox
      checked={grantedCount === row.children.length}
      indeterminate={grantedCount > 0 && grantedCount < row.children.length}
      onChange={({ detail }) => onToggle(categoryToolNames(row), detail.checked)}
      data-testid={`tool-grant-category-${row.category}`}
      ariaLabel={`Grant all ${categoryLabel[row.category] ?? row.category} tools`}
    />
  );
};

/** Name cell for a category row: the category label plus how much of it is granted. */
const CategoryNameCell = ({
  row,
  grantedTools,
}: {
  row: CategoryRow;
  grantedTools: ReadonlySet<string>;
}): React.ReactElement => (
  <SpaceBetween direction="horizontal" size="xs">
    <Box variant="strong">{categoryLabel[row.category] ?? row.category}</Box>
    <Box variant="span" color="text-status-inactive">
      {countGranted(row, grantedTools)} of {row.children.length} granted
    </Box>
  </SpaceBetween>
);

// Column definitions for the tool-permissions table. Extracted into a module-scope
// builder so each cell delegates to a stable component instead of one defined inside
// ToolPermissionsTable's render body (react/no-unstable-nested-components). The
// returned array is rebuilt per render, which is fine — Table only re-renders cells
// whose row data changed.
const buildColumnDefinitions = (
  grantedTools: ReadonlySet<string>,
  onToggle: ToolPermissionsTableProps['onToggle'],
): TableProps<ToolPermissionRow>['columnDefinitions'] => [
  {
    id: 'name',
    header: 'Tool',
    cell: (row) =>
      row.kind === 'category' ? <CategoryNameCell row={row} grantedTools={grantedTools} /> : row.tool.name,
    isRowHeader: true,
  },
  {
    id: 'tier',
    header: 'Minimum tier',
    cell: (row) => tierLabel[row.kind === 'category' ? lowestTierInCategory(row) : row.tool.tier],
  },
  {
    id: 'granted',
    header: 'Granted',
    cell: (row) =>
      row.kind === 'category' ? (
        <CategoryGrantCheckbox row={row} grantedTools={grantedTools} onToggle={onToggle} />
      ) : (
        <ToolGrantCheckbox tool={row.tool} granted={grantedTools.has(row.tool.name)} onToggle={onToggle} />
      ),
  },
];

/**
 * Renders the per-user MCP tool grant as a table of tools grouped by category, each
 * group expandable and carrying a grant-all toggle. Managing grants is Admin-only, so
 * the caller renders this only for a full Admin viewer; the toggles are always
 * interactive.
 *
 * The table carries no header of its own: the caller labels it with a FormField, so the
 * section heading matches the other sections of the Manage User form rather than
 * rendering at a different size.
 *
 * Every group starts expanded, so the default view is the full catalog and no tool is
 * hidden behind a collapsed row. Collapse state is tracked as the set of categories
 * the Admin has explicitly closed, which means a category that arrives later (a new
 * tool group from the backend) is expanded rather than silently collapsed.
 */
export const ToolPermissionsTable = ({
  tools,
  grantedTools,
  onToggle,
  loading,
}: ToolPermissionsTableProps): React.ReactElement => {
  const [collapsedCategories, setCollapsedCategories] = useState<ReadonlySet<string>>(new Set());
  const categoryRows = useMemo(() => buildCategoryRows(tools), [tools]);
  const expandedRows = useMemo(
    () => categoryRows.filter((row) => !collapsedCategories.has(row.key)),
    [categoryRows, collapsedCategories],
  );

  const toggleCategoryExpansion = (row: ToolPermissionRow, expanded: boolean) => {
    setCollapsedCategories((current) => {
      const next = new Set(current);
      if (expanded) {
        next.delete(row.key);
      } else {
        next.add(row.key);
      }
      return next;
    });
  };

  return (
    <Table<ToolPermissionRow>
      data-testid="tool-permissions-table"
      variant="embedded"
      loading={loading}
      loadingText="Loading tool permissions"
      items={categoryRows}
      trackBy="key"
      empty={<Box variant="p">No grantable tools are available.</Box>}
      columnDefinitions={buildColumnDefinitions(grantedTools, onToggle)}
      // Without these, the per-row expand/collapse control renders with no accessible
      // name — Cloudscape supplies only the caret icon.
      ariaLabels={{
        tableLabel: 'Tool permissions',
        expandButtonLabel: (row) => `Expand ${rowLabel(row)}`,
        collapseButtonLabel: (row) => `Collapse ${rowLabel(row)}`,
      }}
      expandableRows={{
        getItemChildren: (row) => (row.kind === 'category' ? [...row.children] : []),
        isItemExpandable: (row) => row.kind === 'category',
        expandedItems: expandedRows,
        onExpandableItemToggle: ({ detail }) => toggleCategoryExpansion(detail.item, detail.expanded),
      }}
    />
  );
};
