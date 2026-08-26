// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { SeverityFilter } from '@asr/data-models';

/**
 * Determines whether a finding/event severity passes a configured severity
 * filter. An absent, empty, or `All`-containing filter matches everything;
 * otherwise the comparison is case-insensitive.
 */
export function passesSeverityFilter(filter: SeverityFilter | undefined, severity: string): boolean {
  if (!filter || filter.length === 0 || filter.includes('All')) return true;
  return filter.some((allowed) => allowed.toLowerCase() === severity.toLowerCase());
}

/**
 * Determines whether a control ID passes a configured control filter. An empty
 * control ID list matches every control; otherwise the control ID must be
 * explicitly listed.
 */
export function passesControlFilter(controlIds: string[], controlId: string): boolean {
  return controlIds.length === 0 || controlIds.includes(controlId);
}

/**
 * Determines whether an event's account ID passes a configured account scope
 * filter. An absent or empty `accountIds` array (global config) matches all
 * accounts; otherwise the event account must be explicitly listed.
 */
export function passesAccountScopeFilter(configAccountIds: string[] | undefined, eventAccountId: string): boolean {
  if (!configAccountIds || configAccountIds.length === 0) return true;
  return configAccountIds.includes(eventAccountId);
}
