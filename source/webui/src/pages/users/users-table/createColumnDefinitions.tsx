// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { TableProps } from '@cloudscape-design/components/table';
import { Badge, Box, Popover, SpaceBetween } from '@cloudscape-design/components';
import { User } from '@data-models';

const getStatusBadge = (status: string) => {
  if (!status) return <Badge>Unknown</Badge>;
  const statusLower = status.toLowerCase();
  if (statusLower === 'confirmed' || statusLower === 'active') {
    return <Badge color="green">Confirmed</Badge>;
  }
  if (statusLower === 'invited' || statusLower === 'pending') {
    return <Badge color="blue">Invited</Badge>;
  }
  return <Badge>{status}</Badge>;
};

const MAX_VISIBLE_TOOLS = 3;

// Render a user's granted MCP tools: the first three inline, and — when there are
// more — a "+N" badge whose popover lists the overflow. Admins have no stored grant
// (they receive every tool implicitly), so their cell shows a dash.
const renderToolPermissions = (allowedMcpTools?: string[]): React.ReactElement | string => {
  if (!allowedMcpTools || allowedMcpTools.length === 0) return '-';

  const visible = allowedMcpTools.slice(0, MAX_VISIBLE_TOOLS);
  const overflow = allowedMcpTools.slice(MAX_VISIBLE_TOOLS);

  return (
    <SpaceBetween direction="horizontal" size="xxs">
      {visible.map((tool) => (
        <Badge key={tool}>{tool}</Badge>
      ))}
      {overflow.length > 0 && (
        <Popover
          dismissButton={false}
          position="top"
          size="small"
          triggerType="custom"
          content={
            <Box padding="xs">
              <SpaceBetween direction="vertical" size="xxs">
                {overflow.map((tool) => (
                  <span key={tool}>{tool}</span>
                ))}
              </SpaceBetween>
            </Box>
          }
        >
          <Badge color="grey">{`+${overflow.length}`}</Badge>
        </Popover>
      )}
    </SpaceBetween>
  );
};

export const createColumnDefinitions = (): TableProps<User>['columnDefinitions'] => [
  {
    header: 'User ID',
    cell: ({ email }) => email,
    sortingField: 'email',
    maxWidth: '250px',
  },
  {
    header: 'Status',
    cell: ({ status }) => getStatusBadge(status),
    sortingField: 'status',
    maxWidth: '120px',
  },
  {
    header: 'Permission Type',
    cell: ({ type }) => type,
    sortingField: 'type',
    maxWidth: '150px',
  },
  {
    header: 'Tools',
    cell: ({ allowedMcpTools }) => renderToolPermissions(allowedMcpTools),
    maxWidth: '260px',
  },
  {
    header: 'Invited By',
    cell: ({ invitedBy }) => invitedBy,
    sortingField: 'invitedBy',
    maxWidth: '200px',
  },
  {
    header: 'Invitation Timestamp',
    cell: ({ invitationTimestamp }) => new Date(invitationTimestamp).toLocaleString(),
    sortingField: 'invitationTimestamp',
    maxWidth: '200px',
  },
];
