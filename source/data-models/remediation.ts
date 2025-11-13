// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { z } from 'zod';
import { CompositeFilterSchema, SortCriteriaSchema, StringFilterSchema } from './finding';

const FiltersSchema = z
  .object({
    StringFilters: z.array(StringFilterSchema).optional(),
    CompositeFilters: z.array(CompositeFilterSchema).optional(),
    CompositeOperator: z.enum(['AND', 'OR']).optional(),
  })
  .optional();

const BaseRequestSchema = z.object({
  Filters: FiltersSchema,
  SortCriteria: z.array(SortCriteriaSchema).optional(),
});

export const RemediationsRequestSchema = BaseRequestSchema.extend({
  NextToken: z.string().optional(),
});

export const ExportRequestSchema = RemediationsRequestSchema;

export type RemediationsRequest = z.infer<typeof RemediationsRequestSchema>;
export type ExportRequest = z.infer<typeof ExportRequestSchema>;
