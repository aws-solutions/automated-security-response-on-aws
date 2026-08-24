// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { z } from 'zod';
import { accountIdsSchema } from '@data-models';

export const parseAccountIds = (ids: string) =>
  ids
    .split(',')
    .map((id) => id.trim())
    .filter(Boolean);

export const validateAccountIds = (accountIds: string): string | null => {
  const ids = parseAccountIds(accountIds);
  try {
    if (!ids.length) return 'Please enter at least one account ID.';

    accountIdsSchema.parse(ids);
    return null;
  } catch {
    return 'Invalid account IDs. Each account ID must be exactly 12 digits separated by commas.';
  }
};

export const validateEmail = (email: string): string | null => {
  const trimmedEmail = email.trim();
  if (!trimmedEmail) return null;
  const result = z.string().email().safeParse(trimmedEmail);
  return result.success ? null : 'Please enter a valid email address';
};

const ACCOUNT_ID_PATTERN = /^\d{12}$/;
const OU_ID_PATTERN = /^ou-[0-9a-z]{4,32}-[a-z0-9]{8,32}$/;

export const validateAccountId = (accountId: string): string | null => {
  if (!ACCOUNT_ID_PATTERN.test(accountId)) return 'Account ID must be exactly 12 digits.';
  return null;
};

export const validateOrganizationalUnitId = (ouId: string): string | null => {
  if (!OU_ID_PATTERN.test(ouId)) return 'OU ID must match pattern ou-xxxx-xxxxxxxx.';
  return null;
};

const ARN_PATTERN = /^arn:[^:]+:[^:]*:[^:]*:[^:]*:.+$/;

export const validateArnPattern = (arn: string): string | null => {
  if (!ARN_PATTERN.test(arn)) return 'ARN must follow arn:partition:service:region:account-id:resource format.';
  return null;
};

export const parseEmails = (emails: string): string[] =>
  emails
    .split(',')
    .map((email) => email.trim())
    .filter(Boolean);

/**
 * Validates that a path is a safe internal relative path for redirect purposes.
 * Prevents open redirect vulnerabilities by rejecting absolute URLs and protocol attacks.
 */
export const isValidInternalPath = (path: string | null | undefined): path is string => {
  if (!path || typeof path !== 'string') return false;
  if (!path.startsWith('/')) return false;

  try {
    // Base URL is arbitrary; we use it to detect if the path resolves to a different origin
    const url = new URL(path, 'http://localhost');
    if (url.origin !== 'http://localhost') return false;
  } catch {
    return false;
  }

  return true;
};
