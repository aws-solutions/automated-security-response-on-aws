// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { z } from 'zod';
import { CompositeFilterSchema, SortCriteriaSchema, StringFilterSchema } from './finding';
import { MAX_SEARCH_COMPOSITE_FILTERS, MAX_SEARCH_SORT_CRITERIA, MAX_SEARCH_STRING_FILTERS } from './requestLimits';

const FiltersSchema = z
  .object({
    StringFilters: z.array(StringFilterSchema).max(MAX_SEARCH_STRING_FILTERS).optional(),
    CompositeFilters: z.array(CompositeFilterSchema).max(MAX_SEARCH_COMPOSITE_FILTERS).optional(),
    CompositeOperator: z.enum(['AND', 'OR']).optional(),
  })
  .optional();

const BaseRequestSchema = z.object({
  Filters: FiltersSchema,
  SortCriteria: z.array(SortCriteriaSchema).max(MAX_SEARCH_SORT_CRITERIA).optional(),
});

export const RemediationsRequestSchema = BaseRequestSchema.extend({
  NextToken: z.string().optional(),
});

export const ExportRequestSchema = RemediationsRequestSchema;

export type RemediationsRequest = z.infer<typeof RemediationsRequestSchema>;
export type ExportRequest = z.infer<typeof ExportRequestSchema>;
