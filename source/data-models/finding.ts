// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { z } from 'zod';

// Branded type for FindingId — prevents mixing up arbitrary strings with finding identifiers
export type FindingId = string & { readonly __brand: 'FindingId' };
export const FindingIdSchema = z.string().transform((val) => val as FindingId);

/**
 * The findings-table partition key (`findingType`), branded to record that it came from a resolver
 * that knew the finding's family rather than from an arbitrary string.
 *
 * Which source the key comes from depends on the family, and that distinction is erased once a
 * finding is flattened to ASFF, so it can only be resolved upstream: `resolveFindingType` for the
 * ingestion path, `resolveControlId` for the Security-Hub-only sync path. Those two functions are
 * the only places that brand, which makes "the key was resolved where the family was still known"
 * a compile-time guarantee on every write signature instead of a convention. See ADR 0006 and
 * ADR 0010.
 *
 * Deliberately one brand for both forms — a prefixed Security Hub control id
 * (`security-control/S3.1`) and a multi-service remediation id (`GuardDuty.IAMUser`) are equally
 * valid partition keys and are interchangeable at every consumer, so distinguishing them would add
 * casts without preventing a bug.
 */
export type ResolvedFindingType = string & { readonly __brand: 'ResolvedFindingType' };

export const ComparisonOperatorSchema = z.enum([
  'EQUALS',
  'NOT_EQUALS',
  'CONTAINS',
  'NOT_CONTAINS',
  'GREATER_THAN_OR_EQUAL',
  'LESS_THAN_OR_EQUAL',
]);

export const StringFilterSchema = z.object({
  FieldName: z.string(),
  Filter: z.object({
    Value: z.string(),
    Comparison: ComparisonOperatorSchema,
  }),
});

export const CompositeFilterSchema = z.object({
  Operator: z.enum(['AND', 'OR']),
  StringFilters: z.array(StringFilterSchema),
});

export const SortCriteriaSchema = z.object({
  Field: z.string(),
  SortOrder: z.enum(['asc', 'desc']),
});

export const FindingsRequestSchema = z.object({
  Filters: z
    .object({
      CompositeFilters: z.array(CompositeFilterSchema).optional(),
      CompositeOperator: z.enum(['AND', 'OR']).optional(),
    })
    .optional(),
  SortCriteria: z.array(SortCriteriaSchema).optional(),
  NextToken: z.string().optional(),
});

// Explicit (findingId, findingType) key pair. findingType is the findings-table partition key, so
// supplying it lets the API look findings up directly instead of re-deriving the key from the id.
// Required for ids that are not Security Hub ARNs (e.g. Macie's bare-hash FindingInfoUid), where
// derivation is impossible.
export const FindingKeySchema = z.object({
  findingId: FindingIdSchema,
  // findingType is the DynamoDB partition key; reject empty strings so a malformed
  // request cannot produce a key that errors at query time.
  findingType: z.string().min(1, 'findingType must not be empty'),
});

export const FindingsActionRequestSchema = z.object({
  actionType: z.enum(['Suppress', 'Unsuppress', 'Remediate', 'RemediateAndGenerateTicket', 'Rollback']),
  findingIds: z.array(FindingIdSchema).min(1, 'At least one finding ID is required'),
  // Optional explicit keys for the same findings, aligned by findingId. When present the API
  // resolves findings by key; findingIds is retained for backward compatibility with older clients.
  findingKeys: z.array(FindingKeySchema).optional(),
});

export type FindingsRequest = z.infer<typeof FindingsRequestSchema>;
export type FindingsActionRequest = z.infer<typeof FindingsActionRequestSchema>;
export type FindingKey = z.infer<typeof FindingKeySchema>;
export type ComparisonOperator = z.infer<typeof ComparisonOperatorSchema>;
