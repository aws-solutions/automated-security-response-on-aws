// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { AccountScopeSchema } from '@asr/data-models';
import { passesAccountScopeFilter } from '../../common/utils/notificationFilters';

/**
 * Unit tests for the account scope delivery filter used by the notification dispatcher to decide
 * whether a finding/event account is in a configuration's delivery scope.
 */

describe('passesAccountScopeFilter', () => {
  it('passes when config has no accountIds (global config)', () => {
    expect(passesAccountScopeFilter(undefined, '123456789012')).toBe(true);
  });

  it('passes when config has empty accountIds array (global config)', () => {
    expect(passesAccountScopeFilter([], '123456789012')).toBe(true);
  });

  it('passes when event accountId is in config accountIds', () => {
    expect(passesAccountScopeFilter(['123456789012', '987654321098'], '123456789012')).toBe(true);
  });

  it('fails when event accountId is NOT in config accountIds', () => {
    expect(passesAccountScopeFilter(['111111111111', '222222222222'], '123456789012')).toBe(false);
  });

  it('passes with single account scope matching the event', () => {
    expect(passesAccountScopeFilter(['123456789012'], '123456789012')).toBe(true);
  });

  it('fails with single account scope not matching the event', () => {
    expect(passesAccountScopeFilter(['999999999999'], '123456789012')).toBe(false);
  });
});

describe('AccountScopeSchema validation', () => {
  it('accepts a valid 12-digit account ID array', () => {
    const result = AccountScopeSchema.safeParse(['123456789012']);
    expect(result.success).toBe(true);
  });

  it('accepts multiple valid account IDs', () => {
    const result = AccountScopeSchema.safeParse(['123456789012', '987654321098']);
    expect(result.success).toBe(true);
  });

  it('rejects account IDs with fewer than 12 digits', () => {
    const result = AccountScopeSchema.safeParse(['12345678901']);
    expect(result.success).toBe(false);
  });

  it('rejects account IDs with more than 12 digits', () => {
    const result = AccountScopeSchema.safeParse(['1234567890123']);
    expect(result.success).toBe(false);
  });

  it('rejects account IDs with non-digit characters', () => {
    const result = AccountScopeSchema.safeParse(['12345678901a']);
    expect(result.success).toBe(false);
  });

  it('rejects an empty array', () => {
    const result = AccountScopeSchema.safeParse([]);
    expect(result.success).toBe(false);
  });

  it('accepts many accounts (no upper limit)', () => {
    const many = Array.from({ length: 200 }, (_, i) => String(100000000000 + i));
    const result = AccountScopeSchema.safeParse(many);
    expect(result.success).toBe(true);
  });
});
