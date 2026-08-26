// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { useEffect, useState } from 'react';

export interface VersionCheckResult {
  latestVersion: string;
  isNewestVersion: boolean;
}

export type Clock = () => number;

const defaultClock: Clock = () => Date.now();

const VERSION_CACHE_KEY = 'asr_github_latest_version';
const DISMISSAL_CACHE_KEY = 'asr_version_alert_dismissed';
const CACHE_DURATION_MS = 24 * 60 * 60 * 1000; // 24 hours
const DISMISSAL_DURATION_MS = 7 * 24 * 60 * 60 * 1000; // 1 week
const GITHUB_API = 'https://api.github.com/repos/aws-solutions/automated-security-response-on-aws/releases/latest';
const SEMVER_PATTERN = /^v\d+\.\d+\.\d+$/;

const isGithubRelease = (data: unknown): data is { tag_name: string } =>
  typeof data === 'object' &&
  data !== null &&
  'tag_name' in data &&
  typeof (data as Record<string, unknown>).tag_name === 'string';

const isCachedVersion = (data: unknown): data is { tagName: string; timestamp: number } =>
  typeof data === 'object' &&
  data !== null &&
  'tagName' in data &&
  typeof (data as Record<string, unknown>).tagName === 'string' &&
  'timestamp' in data &&
  typeof (data as Record<string, unknown>).timestamp === 'number';

const isCachedTimestamp = (data: unknown): data is { timestamp: number } =>
  typeof data === 'object' &&
  data !== null &&
  'timestamp' in data &&
  typeof (data as Record<string, unknown>).timestamp === 'number';

/** Returns true if latestTag is newer than the currentVersion */
const isNewerVersion = (latestTag: string, currentVersion: string): boolean => {
  const latest = latestTag.replace(/^v/, '').split('.').map(Number);
  const current = currentVersion.replace(/^v/, '').split('.').map(Number);
  for (let i = 0; i < Math.max(latest.length, current.length); i++) {
    const l = latest[i] ?? 0;
    const c = current[i] ?? 0;
    if (l > c) return true;
    if (l < c) return false;
  }
  return false;
};

const getCachedVersion = (clock: Clock, currentVersion: string): VersionCheckResult | null => {
  try {
    const cached = localStorage.getItem(VERSION_CACHE_KEY);
    if (!cached) return null;
    const data: unknown = JSON.parse(cached);
    if (!isCachedVersion(data)) return null;
    if (clock() - data.timestamp > CACHE_DURATION_MS) return null;
    return { latestVersion: data.tagName, isNewestVersion: !isNewerVersion(data.tagName, currentVersion) };
  } catch {
    return null;
  }
};

const fetchLatestVersion = async (clock: Clock, currentVersion: string): Promise<VersionCheckResult> => {
  const response = await fetch(GITHUB_API, { signal: AbortSignal.timeout(5000) });
  if (!response.ok) throw new Error(`GitHub API error: ${response.status}`);
  const data: unknown = await response.json();
  if (!isGithubRelease(data) || !SEMVER_PATTERN.test(data.tag_name)) {
    throw new Error('Unexpected GitHub API response');
  }
  const tagName = data.tag_name;
  try {
    localStorage.setItem(VERSION_CACHE_KEY, JSON.stringify({ tagName, timestamp: clock() }));
  } catch {
    // localStorage may be unavailable
  }
  return { latestVersion: tagName, isNewestVersion: !isNewerVersion(tagName, currentVersion) };
};

export const isDismissed = (clock: Clock = defaultClock): boolean => {
  try {
    const cached = localStorage.getItem(DISMISSAL_CACHE_KEY);
    if (!cached) return false;
    const data: unknown = JSON.parse(cached);
    if (!isCachedTimestamp(data)) return false;
    return clock() - data.timestamp < DISMISSAL_DURATION_MS;
  } catch {
    return false;
  }
};

export const dismissVersionAlert = (clock: Clock = defaultClock): void => {
  try {
    localStorage.setItem(DISMISSAL_CACHE_KEY, JSON.stringify({ timestamp: clock() }));
  } catch {
    // localStorage may be unavailable
  }
};

export const useVersionCheck = (
  isEnabled: boolean = true,
  currentVersion: string = '',
  clock: Clock = defaultClock,
): VersionCheckResult | null => {
  const [result, setResult] = useState<VersionCheckResult | null>(null);

  useEffect(() => {
    if (!isEnabled || !currentVersion) return;

    const cached = getCachedVersion(clock, currentVersion);
    if (cached) {
      setResult(cached);
      return;
    }

    fetchLatestVersion(clock, currentVersion)
      .then(setResult)
      .catch(() => {
        // Silent failure — feature is non-critical
      });
  }, [isEnabled, currentVersion, clock]);

  return result;
};
