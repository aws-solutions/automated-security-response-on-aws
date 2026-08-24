// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { TableProps } from '@cloudscape-design/components/table';

import { Badge, Link, StatusIndicator } from '@cloudscape-design/components';
import { NavigateFunction } from 'react-router';
import { FindingApiResponse } from '@data-models';

const getStatusIndicatorType = (status: string) => {
  switch (status.toLowerCase()) {
    case 'success':
      return 'success';
    case 'failed':
      return 'error';
    case 'in_progress':
      return 'in-progress';
    case 'not_started':
    default:
      return 'pending';
  }
};

const getSeverityColor = (severity: string) => {
  switch (severity.toLowerCase()) {
    case 'critical':
      return 'severity-critical';
    case 'high':
      return 'severity-high';
    case 'medium':
      return 'severity-medium';
    case 'low':
      return 'severity-low';
    case 'informational':
    default:
      return 'severity-neutral';
  }
};

const formatStatus = (status: string) => {
  if (!status) return 'Unknown';

  // Convert underscores to spaces and capitalize each word
  return status
    .replaceAll('_', ' ')
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

export const DEFAULT_VISIBLE_COLUMNS = [
  'findingType',
  'findingDescription',
  'remediationStatus',
  'accountId',
  'findingId',
  'resourceType',
  'resourceId',
  'severity',
  'securityHubUpdatedAtTime',
  'consoleLink',
] as const;

export const createColumnDefinitions = (
  navigate: NavigateFunction,
): TableProps<FindingApiResponse>['columnDefinitions'] => [
  {
    id: 'findingType',
    header: 'Finding Type',
    cell: ({ findingType }) => findingType || '-',
    minWidth: '150px',
  },
  {
    id: 'findingDescription',
    header: 'Finding Title',
    cell: ({ findingDescription }) => findingDescription || '-',
    minWidth: '300px',
  },
  {
    id: 'remediationStatus',
    header: 'Remediation Status',
    cell: ({ remediationStatus, findingId }) => {
      const hasHistory = ['in_progress', 'failed', 'success'].includes(remediationStatus?.toLowerCase() || '');

      if (hasHistory) {
        const goToHistory = () =>
          navigate('/history', {
            state: {
              filterTokens: [
                {
                  propertyKey: 'findingId',
                  operator: '=',
                  value: findingId,
                },
              ],
            },
          });
        const setUnderline = (target: EventTarget | null, value: 'underline' | 'none') => {
          if (target instanceof HTMLElement) target.style.textDecoration = value;
        };
        return (
          <StatusIndicator type={getStatusIndicatorType(remediationStatus)}>
            <span
              role="button"
              tabIndex={0}
              onClick={goToHistory}
              onKeyDown={(e) => {
                if (e.key === 'Enter' || e.key === ' ') {
                  e.preventDefault();
                  goToHistory();
                }
              }}
              style={{
                cursor: 'pointer',
                textDecoration: 'none',
              }}
              onMouseEnter={(e) => setUnderline(e.target, 'underline')}
              onMouseLeave={(e) => setUnderline(e.target, 'none')}
              onFocus={(e) => setUnderline(e.target, 'underline')}
              onBlur={(e) => setUnderline(e.target, 'none')}
            >
              {formatStatus(remediationStatus)}
            </span>
          </StatusIndicator>
        );
      }

      return (
        <StatusIndicator type={getStatusIndicatorType(remediationStatus)}>
          {formatStatus(remediationStatus)}
        </StatusIndicator>
      );
    },
    minWidth: '150px',
  },
  {
    id: 'accountId',
    header: 'Account',
    cell: ({ accountId }) => accountId,
    minWidth: '120px',
  },
  {
    id: 'findingId',
    header: 'Finding ID',
    cell: ({ findingId }) => findingId || '-',
    minWidth: '200px',
  },
  {
    id: 'resourceType',
    header: 'Resource Type',
    cell: ({ resourceType }) => resourceType || '-',
    minWidth: '150px',
  },
  {
    id: 'resourceId',
    header: 'Resource ID',
    cell: ({ resourceId }) => resourceId || '-',
    minWidth: '150px',
  },
  {
    id: 'severity',
    header: 'Severity',
    cell: ({ severity }) => <Badge color={getSeverityColor(severity)}>{severity}</Badge>,
    sortingField: 'severityNormalized',
    minWidth: '100px',
  },
  {
    id: 'securityHubUpdatedAtTime',
    header: 'Security Hub Updated Time',
    cell: ({ securityHubUpdatedAtTime }) => formatDateTime(securityHubUpdatedAtTime),
    sortingField: 'securityHubUpdatedAtTime',
    minWidth: '200px',
  },
  {
    id: 'consoleLink',
    header: 'Finding Link',
    cell: ({ consoleLink }) => (
      <Link external href={consoleLink} target="_blank">
        Security Hub
      </Link>
    ),
    minWidth: '120px',
  },
  {
    id: 'suppressed',
    header: 'Suppressed',
    cell: ({ suppressed }) => (
      <StatusIndicator type={suppressed ? 'warning' : 'success'}>{suppressed ? 'Yes' : 'No'}</StatusIndicator>
    ),
    minWidth: '100px',
  },
];
