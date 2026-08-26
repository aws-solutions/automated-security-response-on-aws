// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { act, screen, waitFor, waitForElementToBeRemoved, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { vi } from 'vitest';

import { http, HttpResponse } from 'msw';
import { FindingApiResponse } from '@data-models';
import { SELECTION_LIMIT } from '../../../pages/findings/findings-table/FindingsTable';
import { FINDINGS_ACTION_BATCH_SIZE } from '../../../pages/findings/findings-table/findingsActionBatch';
import { ok } from '../../../mocks/handlers.ts';
import { ApiEndpoints } from '../../../store/solutionApi.ts';
import {
  installIntersectionObserverRecorder,
  IntersectionObserverRecorder,
} from '../../intersection-observer-recorder.ts';
import { MOCK_SERVER_URL, server } from '../../server.ts';
import { generateTestFindings } from '../../test-data-factory.ts';
import { renderAppContent } from '../../test-utils.tsx';

// Enough findings to span more than one action batch (so a single batch can be
// failed while others succeed) without the render cost of a full 100-row
// selection. Tests that specifically exercise the selection cap use
// SELECTION_LIMIT instead.
const MULTI_BATCH_COUNT = FINDINGS_ACTION_BATCH_SIZE + 5;

// Only the infinite-scroll test needs intersections to fire, so the recorder is
// installed there and reinstated here for the rest of the suite.
let intersectionObserverRecorder: IntersectionObserverRecorder | undefined;

beforeEach(() => {
  localStorage.clear();
});

afterEach(() => {
  server.resetHandlers();
  vi.restoreAllMocks();
  intersectionObserverRecorder?.restore();
  intersectionObserverRecorder = undefined;
});

async function waitForLoadingToFinish(container: ReturnType<typeof within>) {
  const loading = container.queryByText('Loading findings');
  if (loading) {
    await waitForElementToBeRemoved(() => container.queryByText('Loading findings'), { timeout: 10000 });
  }
}

function mockFindings(findings: FindingApiResponse[]) {
  server.use(
    http.post(MOCK_SERVER_URL + ApiEndpoints.FINDINGS, async () => await ok({ Findings: findings, NextToken: null })),
  );
}

function isEligible(finding: FindingApiResponse): boolean {
  return finding.remediationStatus !== 'IN_PROGRESS' && finding.remediationStatus !== 'SUCCESS';
}

function isChecked(element: HTMLElement): boolean {
  return element instanceof HTMLInputElement && element.checked;
}

it('caps select-all to the first 100 eligible findings in display order and excludes in-progress and succeeded findings', async () => {
  // GIVEN a table with more than 100 eligible findings, with ineligible (IN_PROGRESS/SUCCESS) rows interspersed
  const findings = generateTestFindings(120, { suppressed: false, remediationStatus: 'NOT_STARTED' });
  [7, 22, 41].forEach((index) => (findings[index] = { ...findings[index], remediationStatus: 'IN_PROGRESS' }));
  [14, 33].forEach((index) => (findings[index] = { ...findings[index], remediationStatus: 'SUCCESS' }));
  mockFindings(findings);

  renderAppContent({ initialRoute: '/findings' });
  const withinMain = within(screen.getByTestId('main-content'));
  await waitForLoadingToFinish(withinMain);

  const table = await withinMain.findByRole('table');
  const rowCheckboxes = () => within(table).getAllByRole('checkbox').slice(1); // drop the header select-all control

  // The first 50 eligible findings in display order are the ones expected to end up selected.
  let eligibleSelected = 0;
  const expectedRowChecked = findings.map((finding) => {
    if (isEligible(finding) && eligibleSelected < SELECTION_LIMIT) {
      eligibleSelected += 1;
      return true;
    }
    return false;
  });

  // WHEN the user activates the header select-all control
  await userEvent.click(within(table).getAllByRole('checkbox')[0]);

  // THEN exactly the first 50 eligible findings in display order are selected, and no ineligible row is selected
  await waitFor(() => {
    expect(rowCheckboxes().filter(isChecked)).toHaveLength(SELECTION_LIMIT);
  });
  rowCheckboxes().forEach((checkbox, index) => {
    expect(isChecked(checkbox)).toBe(expectedRowChecked[index]);
  });
});

it('disables unselected eligible rows once the limit is reached and re-enables them after a deselection', async () => {
  // GIVEN a table with more eligible findings than the selection limit
  const findings = generateTestFindings(110, { suppressed: false, remediationStatus: 'NOT_STARTED' });
  mockFindings(findings);

  renderAppContent({ initialRoute: '/findings' });
  const withinMain = within(screen.getByTestId('main-content'));
  await waitForLoadingToFinish(withinMain);

  const table = await withinMain.findByRole('table');
  const rowCheckboxes = () => within(table).getAllByRole('checkbox').slice(1);

  // WHEN the user activates select-all, filling the selection to exactly the limit
  await userEvent.click(within(table).getAllByRole('checkbox')[0]);
  await waitFor(() => {
    expect(rowCheckboxes().filter(isChecked)).toHaveLength(SELECTION_LIMIT);
  });

  // THEN the selected rows stay enabled while every unselected eligible row is disabled
  rowCheckboxes().forEach((checkbox, index) => {
    if (index < SELECTION_LIMIT) {
      expect(checkbox).not.toBeDisabled();
    } else {
      expect(checkbox).toBeDisabled();
    }
  });

  // WHEN the user deselects one finding, dropping the count below the limit
  await userEvent.click(rowCheckboxes()[0]);
  await waitFor(() => {
    expect(rowCheckboxes().filter(isChecked)).toHaveLength(SELECTION_LIMIT - 1);
  });

  // THEN every eligible row becomes selectable again
  rowCheckboxes().forEach((checkbox) => {
    expect(checkbox).not.toBeDisabled();
  });
});

it('shows a non-dismissible info alert with the batch-limit guidance only when the selection reaches the limit', async () => {
  // GIVEN a table with more eligible findings than the selection limit
  const findings = generateTestFindings(110, { suppressed: false, remediationStatus: 'NOT_STARTED' });
  mockFindings(findings);

  renderAppContent({ initialRoute: '/findings' });
  const withinMain = within(screen.getByTestId('main-content'));
  await waitForLoadingToFinish(withinMain);

  // THEN no alert is shown while nothing is selected (below the limit)
  expect(withinMain.queryByText(/call the API directly/i)).not.toBeInTheDocument();

  const table = await withinMain.findByRole('table');
  const rowCheckboxes = () => within(table).getAllByRole('checkbox').slice(1);

  // WHEN the user activates select-all, reaching the limit
  await userEvent.click(within(table).getAllByRole('checkbox')[0]);

  // THEN an informational, non-dismissible alert explains the batch limit and directs the user to the API
  const alertBody = await withinMain.findByText(/up to 100 findings at a time/i);
  expect(withinMain.getByText(/call the API directly/i)).toBeInTheDocument();

  const alertRoot = alertBody.closest('[data-analytics-alert]');
  if (!(alertRoot instanceof HTMLElement)) {
    throw new Error('Selection limit alert root not found');
  }
  expect(alertRoot).toHaveAttribute('data-analytics-alert', 'info');
  expect(within(alertRoot).queryAllByRole('button')).toHaveLength(0); // non-dismissible: no dismiss/action button

  // WHEN the user deselects one finding, dropping the count below the limit
  await userEvent.click(rowCheckboxes()[0]);

  // THEN the alert is hidden again
  await waitFor(() => {
    expect(withinMain.queryByText(/call the API directly/i)).not.toBeInTheDocument();
  });
});

it('caps select-all to the limit and lets the header toggle deselect the capped selection', async () => {
  // GIVEN a table with many more eligible findings than the selection limit
  const findings = generateTestFindings(120, { suppressed: false, remediationStatus: 'NOT_STARTED' });
  mockFindings(findings);

  renderAppContent({ initialRoute: '/findings' });
  const withinMain = within(screen.getByTestId('main-content'));
  await waitForLoadingToFinish(withinMain);

  const table = await withinMain.findByRole('table');
  const allCheckboxes = () => within(table).getAllByRole('checkbox');
  const rowCheckboxes = () => allCheckboxes().slice(1);

  // WHEN the user activates the header select-all control
  await userEvent.click(allCheckboxes()[0]);

  // THEN exactly the limit is selected — not every displayed row — and the limit alert appears
  await waitFor(() => {
    expect(rowCheckboxes().filter(isChecked)).toHaveLength(SELECTION_LIMIT);
  });
  expect(rowCheckboxes().filter(isChecked)).not.toHaveLength(findings.length);
  expect(withinMain.getByText(/call the API directly/i)).toBeInTheDocument();

  // WHEN the user activates the header control again
  await userEvent.click(allCheckboxes()[0]);

  // THEN the header still functions as a real toggle: the capped selection is cleared and the alert disappears
  await waitFor(() => {
    expect(rowCheckboxes().filter(isChecked)).toHaveLength(0);
  });
  expect(withinMain.queryByText(/call the API directly/i)).not.toBeInTheDocument();
});

it('drops findings from the selection once a display change removes them from the table', async () => {
  // GIVEN a table holding both suppressed and unsuppressed eligible findings, with the suppressed rows
  // first in display order so they land inside the first 100 when select-all fills the cap
  const suppressedFindings = generateTestFindings(20, { suppressed: true, remediationStatus: 'NOT_STARTED' });
  const unsuppressedFindings = generateTestFindings(90, { suppressed: false, remediationStatus: 'NOT_STARTED' });
  mockFindings([...suppressedFindings, ...unsuppressedFindings]);

  renderAppContent({ initialRoute: '/findings' });
  const withinMain = within(screen.getByTestId('main-content'));
  await waitForLoadingToFinish(withinMain);

  // Reveal the suppressed findings so they become displayed and selectable alongside the unsuppressed ones
  await userEvent.click(withinMain.getByRole('checkbox', { name: /show suppressed findings/i }));

  const table = await withinMain.findByRole('table');
  const rowCheckboxes = () => within(table).getAllByRole('checkbox').slice(1);
  await waitFor(() => {
    expect(rowCheckboxes()).toHaveLength(110);
  });

  // WHEN the user activates select-all, filling the selection to the cap (which includes suppressed rows)
  await userEvent.click(within(table).getAllByRole('checkbox')[0]);
  await waitFor(() => {
    expect(rowCheckboxes().filter(isChecked)).toHaveLength(SELECTION_LIMIT);
  });
  expect(withinMain.getByText(/call the API directly/i)).toBeInTheDocument();

  // WHEN the displayed set changes so the suppressed rows leave the table
  await userEvent.click(withinMain.getByRole('checkbox', { name: /show suppressed findings/i }));
  await waitFor(() => {
    expect(rowCheckboxes()).toHaveLength(90);
  });

  // THEN the selection reflects only the still-displayed selectable findings: the surviving count falls below
  // the cap, so the limit alert is hidden again
  await waitFor(
    () => {
      expect(withinMain.queryByText(/call the API directly/i)).not.toBeInTheDocument();
    },
    { timeout: 3000 },
  );

  // AND because the selection dropped below the cap, every still-displayed unselected eligible row is selectable again
  rowCheckboxes()
    .filter((checkbox) => !isChecked(checkbox))
    .forEach((checkbox) => {
      expect(checkbox).not.toBeDisabled();
    });
  // This is the heaviest test in the suite: it renders 110 rows, reveals the
  // suppressed set, fills the selection cap, then hides the suppressed set —
  // several full re-renders of a 100+ row table. On slower CI hosts it runs
  // well past the default 60s ceiling, so give it a dedicated headroom.
}, 120000);

it('keeps an under-cap selection unchanged when infinite scroll appends more rows', async () => {
  // GIVEN a first page of eligible findings with more available to load
  const firstPage = generateTestFindings(5, { suppressed: false, remediationStatus: 'NOT_STARTED' });
  const secondPage = generateTestFindings(5, { suppressed: false, remediationStatus: 'NOT_STARTED' });
  server.use(
    http.post(MOCK_SERVER_URL + ApiEndpoints.FINDINGS, async ({ request }) => {
      const body = (await request.json()) as { NextToken?: string | null };
      // The load-more request carries a NextToken; the initial load does not.
      if (body?.NextToken) {
        return await ok({ Findings: secondPage, NextToken: null });
      }
      return await ok({ Findings: firstPage, NextToken: 'more' });
    }),
  );

  // Capture the infinite-scroll observer callback so the test can simulate the trigger scrolling into view.
  const recorder = installIntersectionObserverRecorder();
  intersectionObserverRecorder = recorder;

  renderAppContent({ initialRoute: '/findings' });
  const withinMain = within(screen.getByTestId('main-content'));
  await waitForLoadingToFinish(withinMain);

  const table = await withinMain.findByRole('table');
  const rowCheckboxes = () => within(table).getAllByRole('checkbox').slice(1);
  await waitFor(() => {
    expect(rowCheckboxes()).toHaveLength(5);
  });

  // AND an under-cap selection of the first two findings
  await userEvent.click(rowCheckboxes()[0]);
  await userEvent.click(rowCheckboxes()[1]);
  await waitFor(() => {
    expect(rowCheckboxes().filter(isChecked)).toHaveLength(2);
  });

  // WHEN infinite scroll appends the next page with no other change
  await act(async () => {
    recorder.triggerIntersection(true);
  });
  await waitFor(() => {
    expect(rowCheckboxes()).toHaveLength(10);
  });

  // THEN the existing selection is retained unchanged: exactly the same two rows stay checked
  expect(rowCheckboxes().filter(isChecked)).toHaveLength(2);
  expect(isChecked(rowCheckboxes()[0])).toBe(true);
  expect(isChecked(rowCheckboxes()[1])).toBe(true);
});

it('sends a capped selection as multiple batches whose union preserves the selected findings', async () => {
  // GIVEN the cap's worth of eligible findings of a single generic type
  const findings = generateTestFindings(SELECTION_LIMIT, {
    suppressed: false,
    remediationStatus: 'NOT_STARTED',
    findingType: 'S3.1',
  });
  mockFindings(findings);

  // Capture every action request body so the batching can be inspected
  const capturedBodies: Array<{
    actionType: string;
    findingIds: string[];
    findingKeys: Array<{ findingId: string; findingType: string }>;
  }> = [];
  server.use(
    http.post(MOCK_SERVER_URL + ApiEndpoints.FINDINGS + '/action', async ({ request }) => {
      capturedBodies.push(
        (await request.json()) as {
          actionType: string;
          findingIds: string[];
          findingKeys: Array<{ findingId: string; findingType: string }>;
        },
      );
      return await ok({});
    }),
  );

  renderAppContent({ initialRoute: '/findings' });
  const withinMain = within(screen.getByTestId('main-content'));
  await waitForLoadingToFinish(withinMain);

  const table = await withinMain.findByRole('table');

  // WHEN the user selects the whole cap and confirms Remediate
  await userEvent.click(within(table).getAllByRole('checkbox')[0]);
  await userEvent.click(await withinMain.findByRole('button', { name: 'Actions' }));
  const dropdown = await screen.findByRole('menu');
  await userEvent.click(within(dropdown).getByText('Remediate'));
  const modal = await screen.findByRole('dialog');
  await userEvent.click(within(modal).getByRole('button', { name: 'Remediate' }));

  // THEN every finding is sent, but never in one oversized request
  const selectedIds: string[] = findings.map((finding) => finding.findingId);
  await waitFor(() => {
    expect(capturedBodies.flatMap((body) => body.findingIds)).toHaveLength(selectedIds.length);
  });

  // AND the action was split across more than one request, each within the WAF-safe batch size, carrying aligned keys
  expect(capturedBodies.length).toBeGreaterThan(1);
  capturedBodies.forEach((body) => {
    expect(body.actionType).toBe('Remediate');
    expect(body.findingIds.length).toBeLessThanOrEqual(FINDINGS_ACTION_BATCH_SIZE);
    expect(body.findingKeys).toEqual(body.findingIds.map((findingId) => ({ findingId, findingType: 'S3.1' })));
  });

  // AND the union of every request's findingIds equals the selected findings in display order
  const orderedBodies = [...capturedBodies].sort(
    (first, second) => selectedIds.indexOf(first.findingIds[0]) - selectedIds.indexOf(second.findingIds[0]),
  );
  expect(orderedBodies.flatMap((body) => body.findingIds)).toEqual(selectedIds);
});

it('reports partial success when one batch request fails', async () => {
  // GIVEN a multi-batch set of eligible findings
  const findings = generateTestFindings(MULTI_BATCH_COUNT, {
    suppressed: false,
    remediationStatus: 'NOT_STARTED',
    findingType: 'S3.1',
  });
  mockFindings(findings);

  // Fail the second action request that arrives; the rest succeed
  let actionCallCount = 0;
  server.use(
    http.post(MOCK_SERVER_URL + ApiEndpoints.FINDINGS + '/action', async () => {
      actionCallCount += 1;
      if (actionCallCount === 2) {
        return HttpResponse.json({ message: 'boom' }, { status: 500 });
      }
      return await ok({});
    }),
  );

  renderAppContent({ initialRoute: '/findings' });
  const withinMain = within(screen.getByTestId('main-content'));
  await waitForLoadingToFinish(withinMain);

  const table = await withinMain.findByRole('table');

  // WHEN the user selects the whole cap and confirms Remediate
  await userEvent.click(within(table).getAllByRole('checkbox')[0]);
  await userEvent.click(await withinMain.findByRole('button', { name: 'Actions' }));
  const dropdown = await screen.findByRole('menu');
  await userEvent.click(within(dropdown).getByText('Remediate'));
  const modal = await screen.findByRole('dialog');
  await userEvent.click(within(modal).getByRole('button', { name: 'Remediate' }));

  // THEN the findings from the successful batches are still reported as sent
  expect(await withinMain.findByText(/Successfully sent \d+ findings? for Remediation/i)).toBeInTheDocument();

  // AND the failed batch is surfaced as a warning rather than throwing
  expect(await withinMain.findByText(/Failed to Remediate \d+ findings?/i)).toBeInTheDocument();
});

it('reports partial success when one suppress batch request fails', async () => {
  // GIVEN a multi-batch set of unsuppressed eligible findings
  const findings = generateTestFindings(MULTI_BATCH_COUNT, {
    suppressed: false,
    remediationStatus: 'NOT_STARTED',
    findingType: 'S3.1',
  });
  mockFindings(findings);

  // Fail the second suppress request that arrives; the rest succeed
  let actionCallCount = 0;
  server.use(
    http.post(MOCK_SERVER_URL + ApiEndpoints.FINDINGS + '/action', async () => {
      actionCallCount += 1;
      if (actionCallCount === 2) {
        return HttpResponse.json({ message: 'boom' }, { status: 500 });
      }
      return await ok({});
    }),
  );

  renderAppContent({ initialRoute: '/findings' });
  const withinMain = within(screen.getByTestId('main-content'));
  await waitForLoadingToFinish(withinMain);

  const table = await withinMain.findByRole('table');

  // WHEN the user selects the whole cap and confirms Suppress
  await userEvent.click(within(table).getAllByRole('checkbox')[0]);
  await userEvent.click(await withinMain.findByRole('button', { name: 'Actions' }));
  const dropdown = await screen.findByRole('menu');
  await userEvent.click(within(dropdown).getByText('Suppress'));
  const modal = await screen.findByRole('dialog');
  await userEvent.click(within(modal).getByRole('button', { name: 'Suppress' }));

  // THEN the suppressed findings from the successful batches are reported, and the failed batch surfaces as a warning
  expect(await withinMain.findByText(/Successfully suppressed \d+ findings?/i)).toBeInTheDocument();
  expect(await withinMain.findByText(/Failed to Suppress \d+ findings?/i)).toBeInTheDocument();
});

it('surfaces an error when every remediate batch fails', async () => {
  // GIVEN a small set of eligible findings that fit in a single batch
  const findings = generateTestFindings(3, {
    suppressed: false,
    remediationStatus: 'NOT_STARTED',
    findingType: 'S3.1',
  });
  mockFindings(findings);

  // AND the action endpoint always fails
  server.use(
    http.post(MOCK_SERVER_URL + ApiEndpoints.FINDINGS + '/action', async () =>
      HttpResponse.json({ message: 'boom' }, { status: 500 }),
    ),
  );

  renderAppContent({ initialRoute: '/findings' });
  const withinMain = within(screen.getByTestId('main-content'));
  await waitForLoadingToFinish(withinMain);

  const table = await withinMain.findByRole('table');

  // WHEN the user selects the findings and confirms Remediate
  await userEvent.click(within(table).getAllByRole('checkbox')[0]);
  await userEvent.click(await withinMain.findByRole('button', { name: 'Actions' }));
  const dropdown = await screen.findByRole('menu');
  await userEvent.click(within(dropdown).getByText('Remediate'));
  const modal = await screen.findByRole('dialog');
  await userEvent.click(within(modal).getByRole('button', { name: 'Remediate' }));

  // THEN the total failure is surfaced with the original failure wording and no success message
  expect(await withinMain.findByText(/Failed to Remediate:/i)).toBeInTheDocument();
  expect(withinMain.queryByText(/successfully sent .* for remediation/i)).not.toBeInTheDocument();
});

const ACTION_ENDPOINT = MOCK_SERVER_URL + ApiEndpoints.FINDINGS + '/action';

interface ActionRequestBody {
  actionType: string;
  findingIds: string[];
  findingKeys: Array<{ findingId: string; findingType: string }>;
}

// Drive the real UI flow the other tests use: select every row, open the
// Actions dropdown, pick the action, and confirm it in the modal.
async function selectAllAndConfirmAction(
  withinMain: ReturnType<typeof within>,
  table: HTMLElement,
  actionName: 'Remediate' | 'Suppress',
) {
  await userEvent.click(within(table).getAllByRole('checkbox')[0]);
  await userEvent.click(await withinMain.findByRole('button', { name: 'Actions' }));
  const dropdown = await screen.findByRole('menu');
  await userEvent.click(within(dropdown).getByText(actionName));
  const modal = await screen.findByRole('dialog');
  await userEvent.click(within(modal).getByRole('button', { name: actionName }));
}

it('shows the skip text, the failure text, and the combined header when a Remediate has both a skipped batch and a failed batch', async () => {
  // GIVEN a multi-batch set of eligible findings, one batch's lead finding is returned as unsupported (a skip)
  // while a different batch's request fails
  const findings = generateTestFindings(MULTI_BATCH_COUNT, {
    suppressed: false,
    remediationStatus: 'NOT_STARTED',
    findingType: 'S3.1',
    resourceType: 'AwsS3Bucket',
  });
  mockFindings(findings);

  const skippedFindingId = findings[0].findingId; // first batch
  const failedBatchFindingId = findings[FINDINGS_ACTION_BATCH_SIZE].findingId; // second batch
  server.use(
    http.post(ACTION_ENDPOINT, async ({ request }) => {
      const body = (await request.json()) as ActionRequestBody;
      if (body.findingIds.includes(failedBatchFindingId)) {
        return HttpResponse.json({ message: 'boom' }, { status: 500 });
      }
      if (body.findingIds.includes(skippedFindingId)) {
        return await ok({ unresolvedIds: [skippedFindingId] });
      }
      return await ok({});
    }),
  );

  renderAppContent({ initialRoute: '/findings' });
  const withinMain = within(screen.getByTestId('main-content'));
  await waitForLoadingToFinish(withinMain);
  const table = await withinMain.findByRole('table');

  // WHEN the user selects the whole cap and confirms Remediate
  await selectAllAndConfirmAction(withinMain, table, 'Remediate');

  // THEN the warning surfaces both the skipped findings and the failed batch under the combined header
  expect(await withinMain.findByText('Some findings were skipped or could not be submitted')).toBeInTheDocument();
  expect(await withinMain.findByText(/finding was skipped: the resource type is not supported/i)).toBeInTheDocument();
  expect(await withinMain.findByText(/Failed to Remediate \d+ findings?/i)).toBeInTheDocument();
  // AND the successful batches are still reported as sent
  expect(await withinMain.findByText(/Successfully sent \d+ findings? for Remediation/i)).toBeInTheDocument();
});

it('labels a pure Remediate batch failure under the "could not be submitted" header rather than the skipped header', async () => {
  // GIVEN a multi-batch set of eligible findings where one batch fails and no batch reports a skip
  const findings = generateTestFindings(MULTI_BATCH_COUNT, {
    suppressed: false,
    remediationStatus: 'NOT_STARTED',
    findingType: 'S3.1',
  });
  mockFindings(findings);

  const failedBatchFindingId = findings[FINDINGS_ACTION_BATCH_SIZE].findingId;
  server.use(
    http.post(ACTION_ENDPOINT, async ({ request }) => {
      const body = (await request.json()) as ActionRequestBody;
      if (body.findingIds.includes(failedBatchFindingId)) {
        return HttpResponse.json({ message: 'boom' }, { status: 500 });
      }
      return await ok({});
    }),
  );

  renderAppContent({ initialRoute: '/findings' });
  const withinMain = within(screen.getByTestId('main-content'));
  await waitForLoadingToFinish(withinMain);
  const table = await withinMain.findByRole('table');

  // WHEN the user selects the whole cap and confirms Remediate
  await selectAllAndConfirmAction(withinMain, table, 'Remediate');

  // THEN the failure is shown under the failure header, never the skipped header
  expect(await withinMain.findByText('Some findings could not be submitted')).toBeInTheDocument();
  expect(await withinMain.findByText(/Failed to Remediate \d+ findings?/i)).toBeInTheDocument();
  expect(withinMain.queryByText('Some findings were skipped')).not.toBeInTheDocument();
  expect(withinMain.queryByText('Some findings were skipped or could not be submitted')).not.toBeInTheDocument();
});

it('surfaces an error and shows no success message when every suppress batch fails', async () => {
  // GIVEN a small set of eligible findings that fit in a single batch, with the action endpoint always failing
  const findings = generateTestFindings(3, {
    suppressed: false,
    remediationStatus: 'NOT_STARTED',
    findingType: 'S3.1',
  });
  mockFindings(findings);
  server.use(http.post(ACTION_ENDPOINT, async () => HttpResponse.json({ message: 'boom' }, { status: 500 })));

  renderAppContent({ initialRoute: '/findings' });
  const withinMain = within(screen.getByTestId('main-content'));
  await waitForLoadingToFinish(withinMain);
  const table = await withinMain.findByRole('table');

  // WHEN the user selects the findings and confirms Suppress
  await selectAllAndConfirmAction(withinMain, table, 'Suppress');

  // THEN the total failure is surfaced with the suppress failure wording and no success message
  expect(await withinMain.findByText(/Failed to Suppress findings:/i)).toBeInTheDocument();
  expect(withinMain.queryByText(/successfully suppressed/i)).not.toBeInTheDocument();
});

it('labels a partial Suppress batch failure under the "could not be submitted" header', async () => {
  // GIVEN a multi-batch set of unsuppressed eligible findings where one batch fails
  const findings = generateTestFindings(MULTI_BATCH_COUNT, {
    suppressed: false,
    remediationStatus: 'NOT_STARTED',
    findingType: 'S3.1',
  });
  mockFindings(findings);

  const failedBatchFindingId = findings[FINDINGS_ACTION_BATCH_SIZE].findingId;
  server.use(
    http.post(ACTION_ENDPOINT, async ({ request }) => {
      const body = (await request.json()) as ActionRequestBody;
      if (body.findingIds.includes(failedBatchFindingId)) {
        return HttpResponse.json({ message: 'boom' }, { status: 500 });
      }
      return await ok({});
    }),
  );

  renderAppContent({ initialRoute: '/findings' });
  const withinMain = within(screen.getByTestId('main-content'));
  await waitForLoadingToFinish(withinMain);
  const table = await withinMain.findByRole('table');

  // WHEN the user selects the whole cap and confirms Suppress
  await selectAllAndConfirmAction(withinMain, table, 'Suppress');

  // THEN the successful batches are reported and the failed batch is shown under the failure header
  expect(await withinMain.findByText(/Successfully suppressed \d+ findings?/i)).toBeInTheDocument();
  expect(await withinMain.findByText('Some findings could not be submitted')).toBeInTheDocument();
  expect(await withinMain.findByText(/Failed to Suppress \d+ findings?/i)).toBeInTheDocument();
});

it('clears a stale warning once a later all-success action completes', async () => {
  // GIVEN a multi-batch set of eligible findings where one batch fails on the first action only
  const findings = generateTestFindings(MULTI_BATCH_COUNT, {
    suppressed: false,
    remediationStatus: 'NOT_STARTED',
    findingType: 'S3.1',
  });
  mockFindings(findings);

  const failedBatchFindingId = findings[FINDINGS_ACTION_BATCH_SIZE].findingId;
  let shouldFailBatch = true;
  server.use(
    http.post(ACTION_ENDPOINT, async ({ request }) => {
      const body = (await request.json()) as ActionRequestBody;
      if (shouldFailBatch && body.findingIds.includes(failedBatchFindingId)) {
        return HttpResponse.json({ message: 'boom' }, { status: 500 });
      }
      return await ok({});
    }),
  );

  renderAppContent({ initialRoute: '/findings' });
  const withinMain = within(screen.getByTestId('main-content'));
  await waitForLoadingToFinish(withinMain);
  const table = await withinMain.findByRole('table');

  // WHEN a first Remediate partially fails, a warning is shown
  await selectAllAndConfirmAction(withinMain, table, 'Remediate');
  expect(await withinMain.findByText(/Failed to Remediate \d+ findings?/i)).toBeInTheDocument();

  // WHEN a second action succeeds for every remaining eligible finding
  shouldFailBatch = false;
  await selectAllAndConfirmAction(withinMain, table, 'Remediate');

  // THEN the stale warning is gone: no failure text and no warning header remain
  await waitFor(() => {
    expect(withinMain.queryByText(/Failed to Remediate \d+ findings?/i)).not.toBeInTheDocument();
  });
  expect(withinMain.queryByText('Some findings could not be submitted')).not.toBeInTheDocument();
});

it('shows a pure skip under the "Some findings were skipped" header when no batch fails', async () => {
  // GIVEN eligible findings where the API reports one as unsupported (a skip) and every batch request succeeds
  const findings = generateTestFindings(3, {
    suppressed: false,
    remediationStatus: 'NOT_STARTED',
    findingType: 'S3.1',
    resourceType: 'AwsS3Bucket',
  });
  mockFindings(findings);

  const skippedFindingId = findings[0].findingId;
  server.use(
    http.post(ACTION_ENDPOINT, async ({ request }) => {
      const body = (await request.json()) as ActionRequestBody;
      if (body.findingIds.includes(skippedFindingId)) {
        return await ok({ unresolvedIds: [skippedFindingId] });
      }
      return await ok({});
    }),
  );

  renderAppContent({ initialRoute: '/findings' });
  const withinMain = within(screen.getByTestId('main-content'));
  await waitForLoadingToFinish(withinMain);
  const table = await withinMain.findByRole('table');

  // WHEN the user selects the findings and confirms Remediate
  await selectAllAndConfirmAction(withinMain, table, 'Remediate');

  // THEN the skip is shown under the skipped header, with no failure text
  expect(await withinMain.findByText('Some findings were skipped')).toBeInTheDocument();
  expect(await withinMain.findByText(/finding was skipped: the resource type is not supported/i)).toBeInTheDocument();
  expect(withinMain.queryByText(/Failed to Remediate/i)).not.toBeInTheDocument();
});

it('clears a stale success banner when a later Remediate totally fails', async () => {
  // GIVEN a multi-batch set of eligible findings where one batch fails on the first Remediate
  const findings = generateTestFindings(MULTI_BATCH_COUNT, {
    suppressed: false,
    remediationStatus: 'NOT_STARTED',
    findingType: 'S3.1',
  });
  mockFindings(findings);

  const failedBatchFindingId = findings[FINDINGS_ACTION_BATCH_SIZE].findingId;
  let failEveryBatch = false;
  server.use(
    http.post(ACTION_ENDPOINT, async ({ request }) => {
      const body = (await request.json()) as ActionRequestBody;
      if (failEveryBatch || body.findingIds.includes(failedBatchFindingId)) {
        return HttpResponse.json({ message: 'boom' }, { status: 500 });
      }
      return await ok({});
    }),
  );

  renderAppContent({ initialRoute: '/findings' });
  const withinMain = within(screen.getByTestId('main-content'));
  await waitForLoadingToFinish(withinMain);
  const table = await withinMain.findByRole('table');

  // WHEN a first Remediate partially succeeds, leaving a success banner visible
  await selectAllAndConfirmAction(withinMain, table, 'Remediate');
  expect(await withinMain.findByText(/Successfully sent \d+ findings? for Remediation/i)).toBeInTheDocument();

  // WHEN a second Remediate fails for every batch (only the previously-failed, still-eligible findings remain)
  failEveryBatch = true;
  await selectAllAndConfirmAction(withinMain, table, 'Remediate');

  // THEN the total failure is surfaced and the stale success banner is cleared
  expect(await withinMain.findByText(/Failed to Remediate:/i)).toBeInTheDocument();
  await waitFor(() => {
    expect(withinMain.queryByText(/Successfully sent .* for Remediation/i)).not.toBeInTheDocument();
  });
});

it('clears a stale success banner when a later Suppress totally fails', async () => {
  // GIVEN a multi-batch set of eligible findings where one batch fails on the first Suppress
  const findings = generateTestFindings(MULTI_BATCH_COUNT, {
    suppressed: false,
    remediationStatus: 'NOT_STARTED',
    findingType: 'S3.1',
  });
  mockFindings(findings);

  const failedBatchFindingId = findings[FINDINGS_ACTION_BATCH_SIZE].findingId;
  let failEveryBatch = false;
  server.use(
    http.post(ACTION_ENDPOINT, async ({ request }) => {
      const body = (await request.json()) as ActionRequestBody;
      if (failEveryBatch || body.findingIds.includes(failedBatchFindingId)) {
        return HttpResponse.json({ message: 'boom' }, { status: 500 });
      }
      return await ok({});
    }),
  );

  renderAppContent({ initialRoute: '/findings' });
  const withinMain = within(screen.getByTestId('main-content'));
  await waitForLoadingToFinish(withinMain);
  const table = await withinMain.findByRole('table');

  // WHEN a first Suppress partially succeeds, leaving a success banner visible
  await selectAllAndConfirmAction(withinMain, table, 'Suppress');
  expect(await withinMain.findByText(/Successfully suppressed \d+ findings?/i)).toBeInTheDocument();

  // WHEN a second Suppress fails for every batch (the submitted findings are now hidden, only the failed remain)
  failEveryBatch = true;
  await selectAllAndConfirmAction(withinMain, table, 'Suppress');

  // THEN the total failure is surfaced and the stale success banner is cleared
  expect(await withinMain.findByText(/Failed to Suppress findings:/i)).toBeInTheDocument();
  await waitFor(() => {
    expect(withinMain.queryByText(/successfully suppressed/i)).not.toBeInTheDocument();
  });
});
