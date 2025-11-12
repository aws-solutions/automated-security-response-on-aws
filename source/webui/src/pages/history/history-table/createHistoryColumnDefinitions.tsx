// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { TableProps } from '@cloudscape-design/components/table';

import { Link, StatusIndicator, Popover, Box } from '@cloudscape-design/components';
import { NavigateFunction } from 'react-router-dom';
import { RemediationHistoryApiResponse } from '@data-models';

const getStatusIndicatorType = (status: string) => {
  switch (status.toLowerCase()) {
    case 'success':
      return 'success';
    case 'failed':
      return 'error';
    case 'in_progress':
      return 'in-progress';
    default:
      return 'pending';
  }
};

const formatStatus = (status: string) => {
  if (!status) return 'Unknown';

  // Convert underscores to spaces and capitalize each word
  return status
    .replace(/_/g, ' ')
    .toLowerCase()
    .replace(/\b\w/g, (l) => l.toUpperCase());
};

const formatDateTime = (dateTimeString: string) => {
  if (!dateTimeString) return '-';

  try {
    const date = new Date(dateTimeString);
    return date.toLocaleString('en-US', {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
      timeZoneName: 'short',
    });
  } catch (error) {
    console.error(`Error formatting date string "${dateTimeString}":`, error);
    return dateTimeString;
  }
};

export const createHistoryColumnDefinitions = (
  navigate: NavigateFunction,
): TableProps<RemediationHistoryApiResponse>['columnDefinitions'] => [
  {
    header: 'Finding ID',
    cell: ({ findingId }) => findingId || '-',
    minWidth: '300px',
  },
  {
    header: 'Status',
    cell: ({ remediationStatus, error }) => {
      const statusIndicator = (
        <StatusIndicator type={getStatusIndicatorType(remediationStatus)}>
          {formatStatus(remediationStatus)}
        </StatusIndicator>
      );

      if (error && remediationStatus === 'FAILED') {
        return (
          <Box color="text-status-error">
            <Popover dismissButton={false} position="top" size="small" content={<Box padding="s">{error}</Box>}>
              <StatusIndicator type={getStatusIndicatorType(remediationStatus)}>
                {formatStatus(remediationStatus)}
              </StatusIndicator>
            </Popover>
          </Box>
        );
      }

      return statusIndicator;
    },
    minWidth: '140px',
  },
  {
    header: 'Account',
    cell: ({ accountId }) => accountId,
    minWidth: '140px',
  },
  {
    header: 'Resource ID',
    cell: ({ resourceId }) => resourceId || '-',
    minWidth: '150px',
  },
  {
    header: 'Execution Timestamp',
    cell: ({ lastUpdatedTime }) => formatDateTime(lastUpdatedTime),
    sortingField: 'lastUpdatedTime',
    minWidth: '200px',
  },
  {
    header: 'Executed By',
    cell: ({ lastUpdatedBy }) => lastUpdatedBy || '-',
    minWidth: '180px',
  },
  {
    header: 'View Execution',
    cell: ({ consoleLink }) => (
      <Link external href={consoleLink} target="_blank">
        Step Functions
      </Link>
    ),
    minWidth: '140px',
  },
];
