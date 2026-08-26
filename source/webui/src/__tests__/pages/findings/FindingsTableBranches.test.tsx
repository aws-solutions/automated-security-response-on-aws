// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { act, screen, waitFor, waitForElementToBeRemoved, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { vi } from 'vitest';

import { http } from 'msw';
import { ok } from '../../../mocks/handlers.ts';
import { ApiEndpoints } from '../../../store/solutionApi.ts';
import {
  installIntersectionObserverRecorder,
  IntersectionObserverRecorder,
} from '../../intersection-observer-recorder.ts';
import { MOCK_SERVER_URL, server } from '../../server.ts';
import { asFindingId, generateTestFindings } from '../../test-data-factory.ts';
import { renderAppContent } from '../../test-utils.tsx';

// Held at module scope so the recorder installed by an infinite-scroll test is
// always reinstated, even when that test fails part way through.
let intersectionObserverRecorder: IntersectionObserverRecorder | undefined;

beforeEach(() => {
  localStorage.clear();
});

afterEach(() => {
  intersectionObserverRecorder?.restore();
  intersectionObserverRecorder = undefined;
  server.resetHandlers();
  vi.restoreAllMocks();
});

async function waitForLoadingToFinish(container: ReturnType<typeof within>) {
  const loading = container.queryByText('Loading findings');
  if (loading) {
    await waitForElementToBeRemoved(() => container.queryByText('Loading findings'), { timeout: 2000 });
  }
}

async function openRemediateModal(withinMain: ReturnType<typeof within>) {
  const table = await withinMain.findByRole('table');
  const checkboxes = await within(table).findAllByRole('checkbox');
  await userEvent.click(checkboxes[0]); // select all
  const actionsButton = await withinMain.findByRole('button', { name: 'Actions' });
  await userEvent.click(actionsButton);
  const dropdown = await screen.findByRole('menu');
  await userEvent.click(within(dropdown).getByText('Remediate'));
  return screen.findByRole('dialog');
}

it('applies a findingId filter from the URL query param and strips it from the URL', async () => {
  const targetId = 'arn:aws:securityhub:us-east-1:111122223333:finding/abc';
  const findings = generateTestFindings(1, { suppressed: false, findingId: asFindingId(targetId) });
  let lastSearchRequest: any = null;

  server.use(
    http.post(MOCK_SERVER_URL + ApiEndpoints.FINDINGS, async ({ request }) => {
      lastSearchRequest = await request.json();
      return await ok({ Findings: findings, NextToken: null });
    }),
  );

  renderAppContent({ initialRoute: `/findings?findingId=${encodeURIComponent(targetId)}` });

  // The initial search must carry the findingId filter derived from the URL.
  await waitFor(() => {
    const composite = lastSearchRequest?.Filters?.CompositeFilters ?? [];
    const hasFindingId = composite.some((cf: any) =>
      (cf.StringFilters ?? []).some((sf: any) => sf.FieldName === 'findingId'),
    );
    expect(hasFindingId).toBe(true);
  });

  // The findingId query param is removed after being consumed.
  await waitFor(() => {
    expect(window.location.search).not.toContain('findingId');
  });
});

it('shows the GuardDuty containment modal when all selected findings are GuardDuty', async () => {
  const findings = generateTestFindings(2, {
    suppressed: false,
    remediationStatus: 'NOT_STARTED',
    findingType: 'GuardDuty.IAMUser',
  });

  server.use(
    http.post(MOCK_SERVER_URL + ApiEndpoints.FINDINGS, async () => await ok({ Findings: findings, NextToken: null })),
  );

  renderAppContent({ initialRoute: '/findings' });
  const withinMain = within(screen.getByTestId('main-content'));
  await waitForLoadingToFinish(withinMain);

  const modal = await openRemediateModal(withinMain);
  expect(within(modal).getByText('Confirm GuardDuty Credential Containment')).toBeInTheDocument();
  expect(within(modal).getByRole('button', { name: 'Contain Credentials' })).toBeInTheDocument();
});

it('shows the Macie protection modal when all selected findings are Macie', async () => {
  const findings = generateTestFindings(2, {
    suppressed: false,
    remediationStatus: 'NOT_STARTED',
    findingType: 'Macie.SensitiveDataS3Object',
  });

  server.use(
    http.post(MOCK_SERVER_URL + ApiEndpoints.FINDINGS, async () => await ok({ Findings: findings, NextToken: null })),
  );

  renderAppContent({ initialRoute: '/findings' });
  const withinMain = within(screen.getByTestId('main-content'));
  await waitForLoadingToFinish(withinMain);

  const modal = await openRemediateModal(withinMain);
  expect(within(modal).getByText('Confirm Macie Sensitive Data Protection')).toBeInTheDocument();
  expect(within(modal).getByRole('button', { name: 'Enable Block Public Access' })).toBeInTheDocument();
});

it('notes mixed special finding types in the generic remediation modal', async () => {
  const findings = [
    ...generateTestFindings(1, {
      suppressed: false,
      remediationStatus: 'NOT_STARTED',
      findingType: 'GuardDuty.IAMUser',
    }),
    ...generateTestFindings(1, { suppressed: false, remediationStatus: 'NOT_STARTED', findingType: 'S3.1' }),
  ];

  server.use(
    http.post(MOCK_SERVER_URL + ApiEndpoints.FINDINGS, async () => await ok({ Findings: findings, NextToken: null })),
  );

  renderAppContent({ initialRoute: '/findings' });
  const withinMain = within(screen.getByTestId('main-content'));
  await waitForLoadingToFinish(withinMain);

  const modal = await openRemediateModal(withinMain);
  expect(within(modal).getByText('Confirm Remediation')).toBeInTheDocument();
  expect(within(modal).getByText(/findings of different types/i)).toBeInTheDocument();
});

it('warns when the API skips findings whose resource type is unsupported', async () => {
  const findings = generateTestFindings(1, {
    suppressed: false,
    remediationStatus: 'NOT_STARTED',
    findingType: 'Inspector.InstanceVulnerability',
    resourceType: 'AwsLambdaFunction',
  });

  server.use(
    http.post(MOCK_SERVER_URL + ApiEndpoints.FINDINGS, async () => await ok({ Findings: findings, NextToken: null })),
    http.post(
      MOCK_SERVER_URL + ApiEndpoints.FINDINGS + '/action',
      async () => await ok({ unresolvedIds: [findings[0].findingId] }),
    ),
  );

  renderAppContent({ initialRoute: '/findings' });
  const withinMain = within(screen.getByTestId('main-content'));
  await waitForLoadingToFinish(withinMain);

  const modal = await openRemediateModal(withinMain);
  await userEvent.click(within(modal).getByRole('button', { name: 'Remediate' }));

  const warning = await withinMain.findByText(/skipped: the resource type is not supported/i);
  expect(warning).toBeInTheDocument();
  expect(
    withinMain.getByText(/Inspector\.InstanceVulnerability does not support AwsLambdaFunction/),
  ).toBeInTheDocument();
});

it('opens the download URL on a successful CSV export', async () => {
  const findings = generateTestFindings(2, { suppressed: false });
  const openSpy = vi.spyOn(window, 'open').mockImplementation(() => null);

  server.use(
    http.post(MOCK_SERVER_URL + ApiEndpoints.FINDINGS, async () => await ok({ Findings: findings, NextToken: null })),
    http.post(
      MOCK_SERVER_URL + ApiEndpoints.FINDINGS + '/export',
      async () => await ok({ downloadUrl: 'https://example.com/report.csv', status: 'complete', totalExported: 2 }),
    ),
  );

  renderAppContent({ initialRoute: '/findings' });
  const withinMain = within(screen.getByTestId('main-content'));
  await waitForLoadingToFinish(withinMain);

  await userEvent.click(await withinMain.findByRole('button', { name: 'Export to CSV' }));

  await waitFor(() => {
    expect(openSpy).toHaveBeenCalledWith('https://example.com/report.csv', '_blank');
  });
});

it('surfaces a partial-export message', async () => {
  const findings = generateTestFindings(2, { suppressed: false });
  vi.spyOn(window, 'open').mockImplementation(() => null);

  server.use(
    http.post(MOCK_SERVER_URL + ApiEndpoints.FINDINGS, async () => await ok({ Findings: findings, NextToken: null })),
    http.post(
      MOCK_SERVER_URL + ApiEndpoints.FINDINGS + '/export',
      async () =>
        await ok({
          downloadUrl: 'https://example.com/partial.csv',
          status: 'partial',
          totalExported: 1000,
          message: 'Export capped at 1000 records.',
        }),
    ),
  );

  renderAppContent({ initialRoute: '/findings' });
  const withinMain = within(screen.getByTestId('main-content'));
  await waitForLoadingToFinish(withinMain);

  await userEvent.click(await withinMain.findByRole('button', { name: 'Export to CSV' }));

  expect(await withinMain.findByText(/Partial Export/i)).toBeInTheDocument();
});

it('shows an error when CSV export fails', async () => {
  const findings = generateTestFindings(2, { suppressed: false });

  server.use(
    http.post(MOCK_SERVER_URL + ApiEndpoints.FINDINGS, async () => await ok({ Findings: findings, NextToken: null })),
    http.post(MOCK_SERVER_URL + ApiEndpoints.FINDINGS + '/export', async () => {
      return new Response(JSON.stringify({ message: 'Export boom' }), {
        status: 500,
        headers: { 'Content-Type': 'application/json' },
      });
    }),
  );

  renderAppContent({ initialRoute: '/findings' });
  const withinMain = within(screen.getByTestId('main-content'));
  await waitForLoadingToFinish(withinMain);

  await userEvent.click(await withinMain.findByRole('button', { name: 'Export to CSV' }));

  expect(await withinMain.findByText(/Failed to export findings/i)).toBeInTheDocument();
});

it('registers and releases its infinite-scroll observer in balanced pairs across a mount lifecycle', async () => {
  // ARRANGE: a first page that reports more data available. The load-more trigger element renders
  // only while hasMoreData is true, so without a NextToken the trigger never mounts, observe() is
  // never called, and a balance assertion would hold vacuously at zero.
  const findings = generateTestFindings(5, { suppressed: false });
  server.use(
    http.post(
      MOCK_SERVER_URL + ApiEndpoints.FINDINGS,
      async () => await ok({ Findings: findings, NextToken: 'page-2' }),
    ),
  );
  const recorder = installIntersectionObserverRecorder();
  intersectionObserverRecorder = recorder;

  const { renderResult } = renderAppContent({ initialRoute: '/findings' });
  const withinMain = within(screen.getByTestId('main-content'));
  await waitForLoadingToFinish(withinMain);
  const table = await withinMain.findByRole('table');
  await waitFor(() => {
    expect(within(table).getAllByRole('row')).toHaveLength(findings.length + 1); // +1 for the header row
  });

  // The observer effect re-runs whenever hasMoreData, isLoading, isLoadingMore, or the load-more
  // callback changes, so a single mount legitimately produces several observers. Assert the counts
  // are non-zero rather than fixed: a fixed count would encode incidental effect scheduling.
  await waitFor(() => {
    expect(recorder.registrationCount).toBeGreaterThan(0);
  });
  expect(recorder.liveRegistrationCount).toBeGreaterThan(0);

  // ACT
  renderResult.unmount();

  // ASSERT: every registration was released, so nothing is left observing after teardown
  expect(recorder.teardownCount).toBe(recorder.registrationCount);
  expect(recorder.liveRegistrationCount).toBe(0);
});

it('fetches exactly one additional page per intersection and fetches nothing when the trigger leaves view', async () => {
  // ARRANGE: two pages, counted at the search handler. The first page advertises a NextToken so the
  // load-more trigger mounts; the second reports none, so paging ends and no request is left in
  // flight when the test finishes.
  const firstPage = generateTestFindings(5, { suppressed: false });
  const secondPage = generateTestFindings(5, { suppressed: false });
  let searchRequestCount = 0;
  server.use(
    http.post(MOCK_SERVER_URL + ApiEndpoints.FINDINGS, async ({ request }) => {
      searchRequestCount += 1;
      const body = (await request.json()) as { NextToken?: string | null };
      // Only the load-more request carries a NextToken; the initial load does not.
      if (body?.NextToken) {
        return await ok({ Findings: secondPage, NextToken: null });
      }
      return await ok({ Findings: firstPage, NextToken: 'page-2' });
    }),
  );
  const recorder = installIntersectionObserverRecorder();
  intersectionObserverRecorder = recorder;

  renderAppContent({ initialRoute: '/findings' });
  const withinMain = within(screen.getByTestId('main-content'));
  await waitForLoadingToFinish(withinMain);
  const table = await withinMain.findByRole('table');
  await waitFor(() => {
    expect(within(table).getAllByRole('row')).toHaveLength(firstPage.length + 1); // +1 for the header row
  });
  await waitFor(() => {
    expect(recorder.registrationCount).toBeGreaterThan(0);
  });
  expect(recorder.liveRegistrationCount).toBeGreaterThan(0);
  const searchRequestCountAfterInitialLoad = searchRequestCount;

  // ACT: the trigger reports leaving the viewport. This happens while the first page's NextToken
  // still leaves more data available and neither loading flag is set, so entry.isIntersecting is
  // the only term of the load-more guard that can hold the request back.
  await act(async () => {
    recorder.triggerIntersection(false);
  });
  // A request dispatched from the observer callback would already have reached the search handler:
  // the callback dispatches synchronously and the handler counts on entry, ahead of its latency.
  await act(async () => {});

  // ASSERT: no request was issued, so the guard consults isIntersecting rather than resting on
  // hasMoreData alone
  expect(searchRequestCount).toBe(searchRequestCountAfterInitialLoad);

  // ACT: the load-more trigger scrolls into view
  await act(async () => {
    recorder.triggerIntersection(true);
  });

  // ASSERT: exactly one further search request, and the second page appended to the first
  await waitFor(() => {
    expect(within(table).getAllByRole('row')).toHaveLength(firstPage.length + secondPage.length + 1);
  });
  expect(searchRequestCount).toBe(searchRequestCountAfterInitialLoad + 1);
});
