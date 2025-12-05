// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { RemediationHistoryApiResponse } from '@data-models';
import { createEntityAdapter, EntityState } from '@reduxjs/toolkit';
import { ApiEndpoints, solutionApi } from './solutionApi.ts';
import { SearchRequest } from './types.ts';

export const remediationsAdapter = createEntityAdapter<RemediationHistoryApiResponse, string>({
  selectId: (remediation) => remediation.executionId!,
  // Sort by most recent first
  sortComparer: (a, b) => b.lastUpdatedTime.localeCompare(a.lastUpdatedTime),
});

export interface RemediationsSearchResponse {
  Remediations: RemediationHistoryApiResponse[];
  NextToken?: string;
}

export interface ExportRemediationsResponse {
  downloadUrl: string;
  status: 'complete' | 'partial';
  totalExported: number;
  message?: string;
}

interface RawRemediationsSearchResponse {
  Remediations?: RemediationHistoryApiResponse[];
  NextToken?: string;
}

interface RawExportRemediationsResponse {
  downloadUrl: string;
  status: 'complete' | 'partial';
  totalExported: number;
  message?: string;
}

export const remediationsApiSlice = solutionApi.injectEndpoints({
  endpoints: (builder) => ({
    getRemediations: builder.query<EntityState<RemediationHistoryApiResponse, string>, void>({
      query: () => ApiEndpoints.REMEDIATIONS,
      transformResponse: (rawResult: RemediationHistoryApiResponse[]) => {
        return remediationsAdapter.setAll(remediationsAdapter.getInitialState(), rawResult);
      },
      providesTags: ['Remediations'],
    }),

    searchRemediations: builder.query<RemediationsSearchResponse, SearchRequest>({
      query: (searchRequest) => ({
        url: ApiEndpoints.REMEDIATIONS,
        method: 'POST',
        body: searchRequest,
      }),
      transformResponse: (rawResult: RawRemediationsSearchResponse): RemediationsSearchResponse => ({
        Remediations: rawResult.Remediations || [],
        NextToken: rawResult.NextToken,
      }),
      providesTags: ['Remediations'],
    }),

    exportRemediations: builder.mutation<ExportRemediationsResponse, SearchRequest>({
      query: (exportRequest) => ({
        url: ApiEndpoints.EXPORT,
        method: 'POST',
        body: exportRequest,
      }),
      transformResponse: (rawResult: RawExportRemediationsResponse): ExportRemediationsResponse => ({
        downloadUrl: rawResult.downloadUrl,
        status: rawResult.status,
        totalExported: rawResult.totalExported,
        message: rawResult.message,
      }),
    }),
  }),
});

export const { useLazySearchRemediationsQuery, useExportRemediationsMutation } = remediationsApiSlice;
