// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { renderHook, waitFor, act } from '@testing-library/react';
import { vi, describe, it, expect, beforeEach } from 'vitest';
import { useVersionCheck, isDismissed, dismissVersionAlert } from '../components/navigation/use-version-check.ts';

const CURRENT_VERSION = 'v4.0.0';

const mockGitHubRelease = (tagName: string): Partial<Response> => ({
  ok: true,
  json: () => Promise.resolve({ tag_name: tagName }),
});

describe('useVersionCheck', () => {
  beforeEach(() => {
    localStorage.clear();
    vi.restoreAllMocks();
  });

  it('returns null when disabled', () => {
    // GIVEN / WHEN
    const { result } = renderHook(() => useVersionCheck(false, CURRENT_VERSION));

    // THEN
    expect(result.current).toBeNull();
  });

  it('fetches latest version from GitHub and returns result when newer version available', async () => {
    // GIVEN
    vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(mockGitHubRelease('v5.0.0') as Response);

    // WHEN
    const { result } = renderHook(() => useVersionCheck(true, CURRENT_VERSION));

    // THEN
    await waitFor(() => {
      expect(result.current).toEqual({ latestVersion: 'v5.0.0', isNewestVersion: false });
    });
  });

  it('returns isNewestVersion true when versions match', async () => {
    // GIVEN
    vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(mockGitHubRelease('v4.0.0') as Response);

    // WHEN
    const { result } = renderHook(() => useVersionCheck(true, CURRENT_VERSION));

    // THEN
    await waitFor(() => {
      expect(result.current).toEqual({ latestVersion: 'v4.0.0', isNewestVersion: true });
    });
  });

  it('returns isNewestVersion true when current version is ahead of latest release', async () => {
    // GIVEN
    vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(mockGitHubRelease('v3.1.5') as Response);

    // WHEN
    const { result } = renderHook(() => useVersionCheck(true, CURRENT_VERSION));

    // THEN
    await waitFor(() => {
      expect(result.current).toEqual({ latestVersion: 'v3.1.5', isNewestVersion: true });
    });
  });

  it('uses cached version when cache is fresh', async () => {
    // GIVEN
    const now = 1000000;
    localStorage.setItem('asr_github_latest_version', JSON.stringify({ tagName: 'v5.0.0', timestamp: now }));
    const fetchSpy = vi.spyOn(globalThis, 'fetch');
    const clock = () => now + 1000;

    // WHEN
    const { result } = renderHook(() => useVersionCheck(true, CURRENT_VERSION, clock));

    // THEN
    await waitFor(() => {
      expect(result.current).toEqual({ latestVersion: 'v5.0.0', isNewestVersion: false });
    });
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it('fetches from GitHub when cache is expired', async () => {
    // GIVEN
    const now = 1000000;
    localStorage.setItem('asr_github_latest_version', JSON.stringify({ tagName: 'v3.0.0', timestamp: now }));
    vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(mockGitHubRelease('v5.0.0') as Response);
    const clock = () => now + 25 * 60 * 60 * 1000; // 25 hours later

    // WHEN
    const { result } = renderHook(() => useVersionCheck(true, CURRENT_VERSION, clock));

    // THEN
    await waitFor(() => {
      expect(result.current).toEqual({ latestVersion: 'v5.0.0', isNewestVersion: false });
    });
  });

  it('returns null silently when fetch fails', async () => {
    // GIVEN
    vi.spyOn(globalThis, 'fetch').mockRejectedValueOnce(new Error('Network error'));

    // WHEN
    const { result } = renderHook(() => useVersionCheck(true, CURRENT_VERSION));

    // THEN
    await waitFor(() => expect(globalThis.fetch).toHaveBeenCalledTimes(1));
    await act(async () => {});
    expect(result.current).toBeNull();
  });

  it('rejects non-semver tag_name from GitHub', async () => {
    // GIVEN
    vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(mockGitHubRelease('not-a-version') as Response);

    // WHEN
    const { result } = renderHook(() => useVersionCheck(true, CURRENT_VERSION));

    // THEN
    await waitFor(() => expect(globalThis.fetch).toHaveBeenCalledTimes(1));
    await act(async () => {});
    expect(result.current).toBeNull();
  });
});

describe('dismissVersionAlert', () => {
  beforeEach(() => {
    localStorage.clear();
  });

  it('isDismissed returns false when no dismissal cached', () => {
    // GIVEN / WHEN / THEN
    expect(isDismissed()).toBe(false);
  });

  it('isDismissed returns true after dismissing', () => {
    // GIVEN
    const clock = () => 1000000;

    // WHEN
    dismissVersionAlert(clock);

    // THEN
    expect(isDismissed(clock)).toBe(true);
  });

  it('isDismissed returns false when dismissal is expired', () => {
    // GIVEN
    const dismissedAt = 1000000;
    localStorage.setItem('asr_version_alert_dismissed', JSON.stringify({ timestamp: dismissedAt }));
    const clock = () => dismissedAt + 8 * 24 * 60 * 60 * 1000; // 8 days later

    // WHEN / THEN
    expect(isDismissed(clock)).toBe(false);
  });
});
