// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { render, screen, fireEvent, cleanup } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import type { TableProps } from '@cloudscape-design/components/table';
import type { FindingApiResponse } from '@data-models';
import {
  createColumnDefinitions,
  DEFAULT_VISIBLE_COLUMNS,
} from '../../../pages/findings/findings-table/createColumnDefinitions';

afterEach(cleanup);

type ColumnDef = NonNullable<TableProps<FindingApiResponse>['columnDefinitions']>[number];

// Typed factory with valid defaults. Only `findingId` is cast, and only to its
// branded type (`FindingId`) — the object as a whole is fully type-checked.
function makeFinding(overrides: Partial<FindingApiResponse> = {}): FindingApiResponse {
  return {
    findingType: 'security-control/Lambda.3',
    findingDescription: 'Lambda should be in a VPC',
    remediationStatus: 'NOT_STARTED',
    accountId: '123456789012',
    findingId:
      'arn:aws:securityhub:us-east-1:123456789012:security-control/Lambda.3/finding/abc' as FindingApiResponse['findingId'],
    resourceType: 'AWS::Lambda::Function',
    resourceTypeNormalized: 'awslambdafunction',
    resourceId: 'arn:aws:lambda:us-east-1:123456789012:function:test',
    severity: 'HIGH',
    region: 'us-east-1',
    lastUpdatedTime: '2026-01-15T10:30:00Z',
    securityHubUpdatedAtTime: '2026-01-15T10:30:00Z',
    creationTime: '2026-01-15T10:30:00Z',
    suppressed: false,
    consoleLink: 'https://console.aws.amazon.com/securityhub',
    ...overrides,
  };
}

function getCell(id: string, navigate = vi.fn()): ColumnDef['cell'] {
  const columns = createColumnDefinitions(navigate);
  const column = columns!.find((c) => c.id === id);
  if (!column) throw new Error(`column ${id} not found`);
  return column.cell;
}

function renderCell(id: string, overrides: Partial<FindingApiResponse> = {}, navigate = vi.fn()) {
  const cell = getCell(id, navigate);
  if (!cell) throw new Error(`column ${id} has no cell renderer`);
  return render(cell(makeFinding(overrides)));
}

describe('createColumnDefinitions', () => {
  it('exposes the default visible columns for every rendered column', () => {
    const columns = createColumnDefinitions(vi.fn());
    const ids = columns!.map((c) => c.id);
    for (const visible of DEFAULT_VISIBLE_COLUMNS) {
      expect(ids).toContain(visible);
    }
  });

  it.each<[string, Partial<FindingApiResponse>]>([
    ['findingType', { findingType: '' }],
    ['findingDescription', { findingDescription: '' }],
    ['findingId', { findingId: '' as FindingApiResponse['findingId'] }],
    ['resourceType', { resourceType: '' }],
    ['resourceId', { resourceId: '' }],
  ])('renders "-" when %s is empty', (id, overrides) => {
    renderCell(id, overrides);
    expect(screen.getByText('-')).toBeInTheDocument();
  });

  it('renders the account id verbatim', () => {
    renderCell('accountId', { accountId: '999900001111' });
    expect(screen.getByText('999900001111')).toBeInTheDocument();
  });

  it.each(['critical', 'high', 'medium', 'low', 'informational', 'unknown'])(
    'renders severity badge for %s',
    (severity) => {
      renderCell('severity', { severity });
      expect(screen.getByText(severity)).toBeInTheDocument();
    },
  );

  it.each<[FindingApiResponse['remediationStatus'], string]>([
    ['SUCCESS', 'Success'],
    ['FAILED', 'Failed'],
    ['IN_PROGRESS', 'In Progress'],
    ['NOT_STARTED', 'Not Started'],
  ])('renders remediation status %s as "%s"', (remediationStatus, expectedText) => {
    renderCell('remediationStatus', { remediationStatus });
    expect(screen.getByText(expectedText)).toBeInTheDocument();
  });

  it('navigates to history when a status with history is clicked', () => {
    const navigate = vi.fn();
    renderCell('remediationStatus', { remediationStatus: 'SUCCESS' }, navigate);
    const trigger = screen.getByRole('button');
    fireEvent.click(trigger);
    expect(navigate).toHaveBeenCalledWith(
      '/history',
      expect.objectContaining({
        state: expect.objectContaining({
          filterTokens: expect.arrayContaining([
            expect.objectContaining({
              propertyKey: 'findingId',
              value: 'arn:aws:securityhub:us-east-1:123456789012:security-control/Lambda.3/finding/abc',
            }),
          ]),
        }),
      }),
    );
  });

  it('navigates on Enter and Space keydown and ignores other keys', () => {
    const navigate = vi.fn();
    renderCell('remediationStatus', { remediationStatus: 'FAILED' }, navigate);
    const trigger = screen.getByRole('button');

    fireEvent.keyDown(trigger, { key: 'Enter' });
    fireEvent.keyDown(trigger, { key: ' ' });
    expect(navigate).toHaveBeenCalledTimes(2);

    fireEvent.keyDown(trigger, { key: 'a' });
    expect(navigate).toHaveBeenCalledTimes(2);
  });

  it('toggles underline styling on hover and focus', () => {
    renderCell('remediationStatus', { remediationStatus: 'IN_PROGRESS' });
    const trigger = screen.getByRole('button') as HTMLElement;

    fireEvent.mouseEnter(trigger);
    expect(trigger.style.textDecoration).toBe('underline');
    fireEvent.mouseLeave(trigger);
    expect(trigger.style.textDecoration).toBe('none');
    fireEvent.focus(trigger);
    expect(trigger.style.textDecoration).toBe('underline');
    fireEvent.blur(trigger);
    expect(trigger.style.textDecoration).toBe('none');
  });

  it('formats a valid date and returns "-" for an empty date', () => {
    const { getByText, unmount } = renderCell('securityHubUpdatedAtTime', {
      securityHubUpdatedAtTime: '2026-01-15T10:30:00Z',
    });
    expect(getByText(/2026/)).toBeInTheDocument();
    unmount();

    renderCell('securityHubUpdatedAtTime', { securityHubUpdatedAtTime: '' });
    expect(screen.getByText('-')).toBeInTheDocument();
  });

  it('renders the console link', () => {
    renderCell('consoleLink');
    expect(screen.getByText('Security Hub')).toBeInTheDocument();
  });

  it.each<[boolean, string]>([
    [true, 'Yes'],
    [false, 'No'],
  ])('renders the suppressed indicator for %s', (suppressed, expectedText) => {
    renderCell('suppressed', { suppressed });
    expect(screen.getByText(expectedText)).toBeInTheDocument();
  });
});
