// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { z } from 'zod';

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

export const FindingsActionRequestSchema = z.object({
  actionType: z.enum(['Suppress', 'Unsuppress', 'Remediate', 'RemediateAndGenerateTicket']),
  findingIds: z.array(z.string()).min(1, 'At least one finding ID is required'),
});

export type FindingsRequest = z.infer<typeof FindingsRequestSchema>;
export type FindingsActionRequest = z.infer<typeof FindingsActionRequestSchema>;
export type ComparisonOperator = z.infer<typeof ComparisonOperatorSchema>;
