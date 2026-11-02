// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { z } from 'zod';

/**
 * Size limits for the lists that API and MCP requests carry (CVE-2023-54404).
 *
 * zod 4.6+ checks an array's `.max()` before it parses any element, so a request with an
 * oversized list fails with one issue instead of one issue per element. A list without a
 * limit still collects an issue for every invalid element, which lets a single request
 * allocate hundreds of MB. Each limit sits well above what the Web UI sends, or at the
 * number of distinct values the field accepts.
 */

/** CompositeFilters per search. The Web UI sends one per filtered field. */
export const MAX_SEARCH_COMPOSITE_FILTERS = 20;

/**
 * StringFilters per search, and per CompositeFilter. The Web UI sends one per filter token and joins the
 * tokens for one field with OR. Each filter costs a comparator and an OR, and DynamoDB allows at most 300
 * operators in a FilterExpression, so one field cannot be filtered by more than about 150 values anyway.
 */
export const MAX_SEARCH_STRING_FILTERS = 100;

/** SortCriteria per search. The search services sort by the first entry only. */
export const MAX_SEARCH_SORT_CRITERIA = 10;

/** Finding IDs (and finding keys) per finding action. The Web UI sends batches of 15. */
export const MAX_FINDING_ACTION_ITEMS = 100;

/** Controls per bulk control update. The solution ships about 110 Security Control remediations. */
export const MAX_BULK_EDIT_CONTROLS = 500;

/** Resource filter IDs attached to one control or one notification configuration. */
export const MAX_RESOURCE_FILTER_IDS = 100;

/** Control IDs a notification configuration can be scoped to. */
export const MAX_CONTROL_IDS = 500;

/**
 * AWS account IDs in a resource filter, a user's account scope, or a notification's account scope.
 * Security Hub supports at most 10,000 member accounts per administrator, and that quota is not adjustable.
 */
export const MAX_ACCOUNT_IDS = 10000;

/** Organizational units in a resource filter. AWS Organizations allows at most 2,000 OUs per organization. */
export const MAX_ORGANIZATIONAL_UNITS = 2000;

/**
 * Tag pairs in a resource filter. A resource matches only when it carries every pair, and an AWS resource can
 * carry at most 50 tags, so a filter with more pairs can never match.
 */
export const MAX_RESOURCE_FILTER_TAGS = 50;

/** ARN patterns in a resource filter. */
export const MAX_RESOURCE_FILTER_ARN_PATTERNS = 500;

/** Custom email addresses across a notification configuration's email channel. */
export const MAX_CUSTOM_EMAIL_ADDRESSES = 50;

/** Recipient groups in one email channel. There are 5 recipient types; this leaves room for repeats. */
export const MAX_EMAIL_RECIPIENT_GROUPS = 20;

/** IaC formats requested for remediation snippets. There are 4 formats; this leaves room for repeats. */
export const MAX_IAC_FORMATS = 10;

/** MCP tools granted to one user. The MCP server exposes 28 tools. */
export const MAX_MCP_TOOLS = 100;

/** IAM actions declared for one runbook. */
export const MAX_IAM_ACTIONS = 100;

/** Resource ARNs a remediation role's policy can be scoped to. The role's inline policies are capped at 10,240 characters in total. */
export const MAX_IAM_POLICY_RESOURCE_ARNS = 100;

/** Dynamic values embedded in a generated runbook as SSM parameter defaults. */
export const MAX_RUNBOOK_DYNAMIC_VALUES = 50;

/** Tag key length in a resource filter. AWS tag keys are at most 128 characters. */
export const MAX_TAG_KEY_LENGTH = 128;

/** Tag value length in a resource filter. AWS tag values are at most 256 characters. */
export const MAX_TAG_VALUE_LENGTH = 256;

/** ARN pattern length in a resource filter. AWS APIs accept ARNs of at most 2,048 characters. */
export const MAX_ARN_PATTERN_LENGTH = 2048;

/**
 * Stored size of a resource filter: the UTF-8 bytes of its name, account IDs, OUs, tag keys and values, and
 * ARN patterns. A filter is one DynamoDB item, limited to 400 KB (409,600 bytes), so a request that fits every
 * list limit could still fail the write with a server error. 390,000 bytes leaves room for the item's other
 * attributes (IDs, timestamps, version, attribute names).
 */
export const MAX_RESOURCE_FILTER_STORED_BYTES = 390_000;

/**
 * A string-to-string record capped at `maxEntries` entries.
 *
 * zod checks no entry count on a record before it parses the entries, so the count is checked on the raw
 * input first and the record is parsed only when it is within the limit. An oversized record fails with
 * one issue and none of its entries are visited. The JSON Schema it publishes (for MCP tool inputs) is
 * still an object of strings.
 */
export function boundedStringRecordSchema(maxEntries: number): z.ZodType<Record<string, string>, unknown> {
  return z
    .unknown()
    .refine(
      (value) => typeof value !== 'object' || value === null || Object.keys(value).length <= maxEntries,
      `Too many entries: expected at most ${maxEntries}`,
    )
    .pipe(z.record(z.string(), z.string()))
    .meta({ type: 'object', additionalProperties: { type: 'string' }, propertyNames: { type: 'string' } });
}
