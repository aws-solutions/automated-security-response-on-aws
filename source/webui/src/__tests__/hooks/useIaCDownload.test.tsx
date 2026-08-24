// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { act, render, screen, waitFor, within } from '@testing-library/react';
import { describe, it, expect, beforeEach } from 'vitest';
import { StrictMode } from 'react';
import { MemoryRouter, Routes, Route, Outlet } from 'react-router';
import { Provider } from 'react-redux';
import { Flashbar } from '@cloudscape-design/components';
import { useSelector } from 'react-redux';
import { http, HttpResponse } from 'msw';

import { useIaCDownload } from '../../hooks/useIaCDownload.ts';
import { setupStore } from '../../store/store.ts';
import type { RootState } from '../../store/store.ts';
import { MOCK_SERVER_URL, server } from '../server.ts';

/** Minimal shell that calls useIaCDownload and renders notifications + child route. */
function TestShell() {
  useIaCDownload();
  const notifications = useSelector((state: RootState) => state.notifications?.notifications ?? []);
  return (
    <>
      <Flashbar items={notifications.map((n) => ({ ...n, dismissible: true }))} />
      <Outlet />
    </>
  );
}

function HistoryPage() {
  return <div data-testid="history-page">History</div>;
}

interface RenderAtPathOptions {
  strictMode?: boolean;
}

function renderAtPath(path: string, { strictMode = false }: RenderAtPathOptions = {}) {
  const store = setupStore();
  const providerTree = (
    <MemoryRouter initialEntries={[path]}>
      <Provider store={store}>
        <Routes>
          <Route element={<TestShell />}>
            <Route path="iac/*" element={null} />
            <Route path="history" element={<HistoryPage />} />
          </Route>
        </Routes>
      </Provider>
    </MemoryRouter>
  );

  return render(strictMode ? <StrictMode>{providerTree}</StrictMode> : providerTree);
}

describe('useIaCDownload', () => {
  beforeEach(() => {
    server.use(
      http.get(`${MOCK_SERVER_URL}iac/:findingId`, () => {
        return HttpResponse.json({ content: 'template-content', filename: 'S3.1.yaml' });
      }),
    );
  });

  it('redirects /iac/{findingId} to /history page', async () => {
    renderAtPath('/iac/finding-123?format=terraform');

    expect(await screen.findByTestId('history-page')).toBeInTheDocument();
  });

  it('shows error notification on API failure', async () => {
    server.use(
      http.get(`${MOCK_SERVER_URL}iac/:findingId`, () => {
        return new HttpResponse(null, { status: 500 });
      }),
    );

    renderAtPath('/iac/finding-1?format=terraform');

    expect(await screen.findByText('IaC template download failed')).toBeInTheDocument();
  });

  it('does not fetch when path does not start with /iac/', async () => {
    renderAtPath('/history');

    expect(screen.getByTestId('history-page')).toBeInTheDocument();
    // If an unhandled request were made, MSW would throw due to onUnhandledRequest: 'error'
  });

  it('forwards an allowlisted format to the API unchanged', async () => {
    // ARRANGE
    let capturedFormat: string | null = null;
    server.use(
      http.get(`${MOCK_SERVER_URL}iac/:findingId`, ({ request }) => {
        capturedFormat = new URL(request.url).searchParams.get('format');
        return HttpResponse.json({ content: 'template-content', filename: 'S3.1.yaml' });
      }),
    );

    // ACT
    renderAtPath('/iac/finding-123?format=terraform');

    // ASSERT
    await waitFor(() => expect(capturedFormat).toBe('terraform'));
  });

  it('falls back to the default format when format is not allowlisted', async () => {
    // ARRANGE
    let capturedFormat: string | null = null;
    server.use(
      http.get(`${MOCK_SERVER_URL}iac/:findingId`, ({ request }) => {
        capturedFormat = new URL(request.url).searchParams.get('format');
        return HttpResponse.json({ content: 'template-content', filename: 'S3.1.yaml' });
      }),
    );

    // ACT
    renderAtPath('/iac/finding-123?format=../../etc/passwd');

    // ASSERT
    await waitFor(() => expect(capturedFormat).toBe('cloudformation-yaml'));
  });

  it('falls back to the default format when format param is absent', async () => {
    // ARRANGE
    let capturedFormat: string | null = null;
    server.use(
      http.get(`${MOCK_SERVER_URL}iac/:findingId`, ({ request }) => {
        capturedFormat = new URL(request.url).searchParams.get('format');
        return HttpResponse.json({ content: 'template-content', filename: 'S3.1.yaml' });
      }),
    );

    // ACT
    renderAtPath('/iac/finding-123');

    // ASSERT
    await waitFor(() => expect(capturedFormat).toBe('cloudformation-yaml'));
  });

  it('issues one request per download identifier under StrictMode double invocation', async () => {
    // ARRANGE
    const requestedFindingIds: string[] = [];
    server.use(
      http.get(`${MOCK_SERVER_URL}iac/:findingId`, ({ params }) => {
        requestedFindingIds.push(String(params.findingId));
        return HttpResponse.json({ content: 'template-content', filename: 'S3.1.yaml' });
      }),
    );

    // ACT
    const firstDownloadRender = renderAtPath('/iac/finding-123?format=terraform', { strictMode: true });

    // ASSERT — the effect ran twice. Settle the download path first, then assert the exact
    // contents once: waiting for the array to equal a single element would pass on the first
    // poll and never observe a duplicate arriving a tick later, so instead wait for the
    // redirect and for at least one request, flush pending work, and only then compare. Both
    // StrictMode invocations dispatch in the same commit, so a second request would already be
    // recorded by the time the comparison runs.
    await within(firstDownloadRender.container).findByTestId('history-page');
    await waitFor(() => expect(requestedFindingIds.length).toBeGreaterThan(0));
    await act(async () => {});
    expect(requestedFindingIds).toEqual(['finding-123']);

    // ACT — a second identifier proves the dedupe key is per-identifier, not a global latch
    const secondDownloadRender = renderAtPath('/iac/finding-456', { strictMode: true });

    // ASSERT — same settle-then-compare ordering, so a duplicate for the second identifier
    // would be present in the array when the comparison runs
    await within(secondDownloadRender.container).findByTestId('history-page');
    await waitFor(() => expect(requestedFindingIds.length).toBeGreaterThan(1));
    await act(async () => {});
    expect(requestedFindingIds).toEqual(['finding-123', 'finding-456']);
  });
});
