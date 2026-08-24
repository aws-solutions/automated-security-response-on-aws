// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { useEffect, useRef } from 'react';
import { useLocation, useNavigate } from 'react-router';
import { useDispatch } from 'react-redux';
import { IaCFormatSchema, type IaCFormat } from '@data-models';
import { API } from '../utils/API.adapter.ts';
import { addNotification } from '../store/notificationsSlice.ts';

interface IaCDownloadResponse {
  readonly content: string;
  readonly filename: string;
}

const DEFAULT_IAC_FORMAT: IaCFormat = 'cloudformation-yaml';

/**
 * Resolves the requested IaC format against the canonical allowlist. Any value
 * outside {@link IaCFormatSchema} (including a missing param) falls back to the
 * default so an attacker-controlled query string can never reach the API.
 */
function resolveIaCFormat(rawFormat: string | null): IaCFormat {
  const parsed = IaCFormatSchema.safeParse(rawFormat);
  return parsed.success ? parsed.data : DEFAULT_IAC_FORMAT;
}

/** Best-effort, JSON-safe stringification of unknown error data. */
function describeError(err: unknown): string {
  if (err === null || err === undefined || typeof err !== 'object') {
    return typeof err === 'string' && err.length > 0 ? err : 'Download failed';
  }
  const resp = 'response' in err ? err.response : undefined;
  const data = resp !== null && typeof resp === 'object' && 'data' in resp ? resp.data : undefined;
  if (typeof data === 'string' && data.length > 0) return data;
  if (data !== null && data !== undefined) {
    try {
      return JSON.stringify(data);
    } catch {
      /* fall through */
    }
  }
  if ('message' in err && typeof err.message === 'string' && err.message.length > 0) return err.message;
  return 'Download failed';
}

/**
 * Handles /iac/* URLs: redirects to the remediation history page with the
 * finding pre-filtered, then kicks off the IaC download in the background.
 * The user lands on the row that triggered the notification while the file streams in.
 */
export function useIaCDownload(): void {
  const location = useLocation();
  const navigate = useNavigate();
  const dispatch = useDispatch();
  const inFlightDownloads = useRef<Set<string>>(new Set());

  useEffect(() => {
    if (!location.pathname.startsWith('/iac/')) return;
    const rawPath = location.pathname.replace(/^\/iac\//, '');
    const findingId = decodeURIComponent(rawPath);
    if (!findingId) return;
    const format = resolveIaCFormat(new URLSearchParams(location.search).get('format'));
    const inFlightKey = `${findingId}|${format}`;

    const historyTarget = `/history?findingId=${encodeURIComponent(findingId)}`;
    if (inFlightDownloads.current.has(inFlightKey)) {
      navigate(historyTarget, { replace: true });
      return;
    }
    inFlightDownloads.current.add(inFlightKey);

    navigate(historyTarget, { replace: true });

    (async () => {
      try {
        const response: IaCDownloadResponse = await API.get('solution-api', `iac/${encodeURIComponent(findingId)}`, {
          queryParams: { format },
        });
        if (!response?.content || !response?.filename) throw new Error('Unexpected API response');
        const blob = new Blob([response.content], { type: 'text/plain' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = response.filename;
        a.click();
        setTimeout(() => URL.revokeObjectURL(url), 1000);
      } catch (err: unknown) {
        dispatch(
          addNotification({
            id: `iac-download-error-${inFlightKey}`,
            type: 'error',
            header: 'IaC template download failed',
            content: describeError(err),
          }),
        );
      } finally {
        inFlightDownloads.current.delete(inFlightKey);
      }
    })();
  }, [location.pathname, location.search, navigate, dispatch]);
}
