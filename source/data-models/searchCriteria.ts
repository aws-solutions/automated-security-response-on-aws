// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { ComparisonOperator } from './finding';

export type PaginationAttributeValue = string | number | boolean | null | Uint8Array;

export interface SearchFilter {
  fieldName: string;
  value: string;
  comparison: ComparisonOperator;
}

export interface SearchCriteria {
  filters: SearchFilter[];
  sortField?: string;
  sortOrder?: 'asc' | 'desc';
  pageSize: number;
  nextToken?: string;
}

export interface SearchResult<T> {
  items: T[];
  nextToken?: string;
  totalCount?: number;
}

export interface PaginationToken {
  [key: string]: PaginationAttributeValue;
}
