// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { TableProps } from '@cloudscape-design/components/table';
import { Badge } from '@cloudscape-design/components';
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
