// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { EntityState } from '@reduxjs/toolkit';

/**
 * When using custom slices/thunks, we have to keep of the data loading status.
 * When using RTK Query instead, that's built in and we don't need the following types.
 */
export enum ApiDataStatus {
  IDLE = 'IDLE',
  LOADING = 'LOADING',
  SUCCEEDED = 'SUCCEEDED',
  FAILED = 'FAILED',
}

type StatusAndError = {
  status: ApiDataStatus;
  error: string | null;
};
export type ApiDataState<EntityType> = EntityState<EntityType, string> & StatusAndError;

export const DEFAULT_INITIAL_STATE: StatusAndError = {
  status: ApiDataStatus.IDLE,
  error: null,
};

// Search-related types
export interface StringFilter {
  FieldName: string;
  Filter: {
    Value: string;
    Comparison: 'EQUALS' | 'NOT_EQUALS' | 'CONTAINS' | 'NOT_CONTAINS' | 'GREATER_THAN_OR_EQUAL' | 'LESS_THAN_OR_EQUAL';
  };
}

export interface CompositeFilter {
  Operator: 'AND' | 'OR';
  StringFilters: StringFilter[];
}

export interface SearchFilters {
  StringFilters?: StringFilter[];
  CompositeFilters?: CompositeFilter[];
  CompositeOperator?: 'AND' | 'OR';
}

export interface SearchRequest {
  Filters?: SearchFilters;
  SortCriteria?: Array<{
    Field: string;
    SortOrder: 'asc' | 'desc';
  }>;
  NextToken?: string;
}
