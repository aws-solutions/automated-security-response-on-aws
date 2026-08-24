// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { z } from 'zod';

export const FilterModeSchema = z.enum(['include', 'exclude']);

export const TagPairSchema = z.object({
  key: z.string().min(1, 'Tag key cannot be empty'),
  value: z.string().min(1, 'Tag value cannot be empty'),
});

export const SecurityControlSchema = z.object({
  controlId: z.string(),
  description: z.string(),
  automatedRemediationEnabled: z.boolean(),
  filters: z.array(z.string()),
  filterMode: FilterModeSchema,
  version: z.number(),
  lastModified: z.string(),
  modifiedBy: z.string(),
});

export const ResourceFilterSchema = z.object({
  filterId: z.uuid(),
  name: z.string().max(100, 'Filter name cannot exceed 100 characters'),
  accountIds: z.array(z.string().regex(/^\d{12}$/, 'Account ID must be exactly 12 digits')),
  organizationalUnits: z.array(
    z.string().regex(/^ou-[0-9a-z]{4,32}-[a-z0-9]{8,32}$/, 'OU identifier must match pattern ou-xxxx-xxxxxxxx'),
  ),
  tags: z.array(TagPairSchema),
  arnPatterns: z.array(
    z
      .string()
      .regex(
        /^arn:[^:]+:[^:]*:[^:]*:[^:]*:.+$/,
        'ARN pattern must follow arn:partition:service:region:account-id:resource-id format',
      ),
  ),
  version: z.number(),
  createdAt: z.string(),
  createdBy: z.string(),
  lastModified: z.string(),
  modifiedBy: z.string(),
});

export type FilterMode = z.infer<typeof FilterModeSchema>;
export type TagPair = z.infer<typeof TagPairSchema>;

export type SecurityControl = z.infer<typeof SecurityControlSchema>;
export type ResourceFilter = z.infer<typeof ResourceFilterSchema>;
export type ResourceFilterInput = Pick<
  ResourceFilter,
  'name' | 'accountIds' | 'organizationalUnits' | 'tags' | 'arnPatterns'
>;

/**
 * DynamoDB item type derived from their corresponding API types.
 *
 * DynamoDB String Sets (SS) are returned as JavaScript Set<string> by the AWS SDK.
 * However, JSON doesn't support Set types, so these must be converted to arrays
 * before serializing for API responses.
 *
 * The union type `Set<string> | string[]` handles both:
 * - Set<string>: Raw data from DynamoDB scan/query operations
 * - string[]: Already-transformed data or data from DynamoDB Local
 */
type SecurityControlDynamoDBOverrides = {
  filters?: Set<string> | string[];
};

export type SecurityControlDynamoDBItem = Omit<SecurityControl, 'filters'> & SecurityControlDynamoDBOverrides;

/**
 * DynamoDB item type derived from their corresponding API types.
 *
 * DynamoDB String Sets (SS) are returned as JavaScript Set<string> by the AWS SDK.
 * However, JSON doesn't support Set types, so these must be converted to arrays
 * before serializing for API responses.
 *
 * The union type `Set<string> | string[]` handles both:
 * - Set<string>: Raw data from DynamoDB scan/query operations
 * - string[]: Already-transformed data or data from DynamoDB Local
 */
type ResourceFilterDynamoDBOverrides = {
  accountIds?: Set<string> | string[];
  organizationalUnits?: Set<string> | string[];
  arnPatterns?: Set<string> | string[];
};

export type ResourceFilterDynamoDBItem = Omit<ResourceFilter, 'accountIds' | 'organizationalUnits' | 'arnPatterns'> &
  ResourceFilterDynamoDBOverrides;

const BaseFilterFieldsSchema = z.object({
  name: z.string().min(1, 'Filter name cannot be empty').max(100, 'Filter name cannot exceed 100 characters'),
  accountIds: z.array(z.string().regex(/^\d{12}$/, 'Account ID must be exactly 12 digits')),
  organizationalUnits: z.array(
    z.string().regex(/^ou-[0-9a-z]{4,32}-[a-z0-9]{8,32}$/, 'OU identifier must match pattern ou-xxxx-xxxxxxxx'),
  ),
  tags: z.array(TagPairSchema),
  arnPatterns: z.array(
    z
      .string()
      .regex(
        /^arn:[^:]+:[^:]*:[^:]*:[^:]*:.+$/,
        'ARN pattern must follow arn:partition:service:region:account-id:resource-id format',
      ),
  ),
});

const atLeastOneFilterCriterion = (data: z.infer<typeof BaseFilterFieldsSchema>) =>
  data.accountIds.length > 0 ||
  data.organizationalUnits.length > 0 ||
  data.tags.length > 0 ||
  data.arnPatterns.length > 0;

const filterCriterionMessage = {
  message: 'At least one filter criterion (accountIds, organizationalUnits, tags, or arnPatterns) is required',
};

export const UpdateFilterRequestSchema = BaseFilterFieldsSchema.extend({
  version: z.number().int().min(1, 'Version must be a positive integer'),
}).refine(atLeastOneFilterCriterion, filterCriterionMessage);

export type UpdateFilterRequest = z.infer<typeof UpdateFilterRequestSchema>;

export const CreateFilterRequestSchema = BaseFilterFieldsSchema.refine(
  atLeastOneFilterCriterion,
  filterCriterionMessage,
);

export type CreateFilterRequest = z.infer<typeof CreateFilterRequestSchema>;

export const BulkEditUpdateRequestSchema = z.object({
  operation: z.literal('update'),
  data: z.array(SecurityControlSchema).min(1, 'At least one control is required'),
});

export const BulkEditApplyFilterRequestSchema = z.object({
  operation: z.literal('applyFilterToAll'),
  data: z.uuid('Filter ID must be a valid UUID'),
});

export const BulkEditRemoveFilterRequestSchema = z.object({
  operation: z.literal('removeFilterFromAll'),
  data: z.uuid('Filter ID must be a valid UUID'),
});

export const BulkEditRequestSchema = z.discriminatedUnion('operation', [
  BulkEditUpdateRequestSchema,
  BulkEditApplyFilterRequestSchema,
  BulkEditRemoveFilterRequestSchema,
]);

export type BulkEditUpdateRequest = z.infer<typeof BulkEditUpdateRequestSchema>;
export type BulkEditApplyFilterRequest = z.infer<typeof BulkEditApplyFilterRequestSchema>;
export type BulkEditRemoveFilterRequest = z.infer<typeof BulkEditRemoveFilterRequestSchema>;
export type BulkEditRequest = z.infer<typeof BulkEditRequestSchema>;
export type BulkFilterOperation = BulkEditApplyFilterRequest['operation'] | BulkEditRemoveFilterRequest['operation'];

export interface BulkEditSuccessResponse {
  message: string;
  updatedCount: number;
}

export interface BulkEditPartialSuccessResponse {
  message: string;
  successCount: number;
  failedControlIds: string[];
}

export type BulkEditResponse = BulkEditSuccessResponse | BulkEditPartialSuccessResponse;
