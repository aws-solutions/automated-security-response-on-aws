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

export const parseEmails = (emails: string): string[] =>
  emails
    .split(',')
    .map((email) => email.trim())
    .filter(Boolean);
