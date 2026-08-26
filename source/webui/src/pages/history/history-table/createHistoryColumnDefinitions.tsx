// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { TableProps } from '@cloudscape-design/components/table';

import { Link, StatusIndicator, Popover, Box, Button } from '@cloudscape-design/components';
import { NavigateFunction } from 'react-router';
import { RemediationHistoryApiResponse, normalizeRemediationStatus } from '@data-models';

const getStatusIndicatorType = (status: string) => {
  switch (status.toLowerCase()) {
    case 'success':
    case 'rollback_success':
      return 'success';
    case 'failed':
    case 'rollback_failed':
      return 'error';
    case 'in_progress':
    case 'rollback_in_progress':
      return 'in-progress';
    default:
      return 'pending';
  }
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
  onRollback?: (item: RemediationHistoryApiResponse) => void,
): TableProps<RemediationHistoryApiResponse>['columnDefinitions'] => [
  {
    id: 'findingId',
    header: 'Finding ID',
    cell: ({ findingId }) => findingId || '-',
    minWidth: '300px',
  },
  {
    id: 'status',
    header: 'Status',
    cell: ({ remediationStatus, error }) => {
      const statusIndicator = (
        <StatusIndicator type={getStatusIndicatorType(remediationStatus)}>
          {normalizeRemediationStatus(remediationStatus)}
        </StatusIndicator>
      );

      if (error && remediationStatus === 'FAILED') {
        return (
          <Box color="text-status-error">
            <Popover dismissButton={false} position="top" size="small" content={<Box padding="s">{error}</Box>}>
              <StatusIndicator type={getStatusIndicatorType(remediationStatus)}>
                {normalizeRemediationStatus(remediationStatus)}
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
    id: 'accountId',
    header: 'Account',
    cell: ({ accountId }) => accountId,
    minWidth: '140px',
  },
  {
    id: 'resourceId',
    header: 'Resource ID',
    cell: ({ resourceId }) => resourceId || '-',
    minWidth: '150px',
  },
  {
    id: 'executionTimestamp',
    header: 'Execution Timestamp',
    cell: ({ lastUpdatedTime }) => formatDateTime(lastUpdatedTime),
    sortingField: 'lastUpdatedTime',
    minWidth: '200px',
  },
  {
    id: 'executedBy',
    header: 'Executed By',
    cell: ({ lastUpdatedBy }) => lastUpdatedBy || '-',
    minWidth: '180px',
  },
  {
    id: 'viewExecution',
    header: 'View Execution',
    cell: ({ consoleLink }) => (
      <Link external href={consoleLink} target="_blank">
        Step Functions
      </Link>
    ),
    minWidth: '140px',
  },
  {
    id: 'rollback',
    header: 'Rollback',
    cell: (item) => {
      // isRollbackEligible is the single source of truth (computed server-side:
      // GuardDuty.IAMUser, original remediation SUCCESS or a prior ROLLBACK_FAILED,
      // newest entry per finding). Eligibility is not re-derived from
      // remediationStatus here, so the server decision is authoritative.
      if (item.isRollbackEligible !== true || !onRollback) return null;
      return (
        <Button
          variant="inline-link"
          onClick={() => onRollback(item)}
          ariaLabel={`Rollback GuardDuty containment for ${item.resourceId || item.findingId}`}
        >
          Rollback
        </Button>
      );
    },
    minWidth: '100px',
  },
];
