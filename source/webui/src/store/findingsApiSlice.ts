// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { FindingApiResponse } from '@data-models';
import { createEntityAdapter } from '@reduxjs/toolkit';
import { ApiEndpoints, solutionApi } from './solutionApi.ts';
import { SearchRequest } from './types.ts';

export const findingsAdapter = createEntityAdapter<FindingApiResponse, string>({
  selectId: (finding) => finding.findingId,
  sortComparer: (a: FindingApiResponse, b: FindingApiResponse) => b.findingId.localeCompare(a.findingId),
});

export interface FindingsSearchResponse {
  Findings: FindingApiResponse[];
  NextToken?: string;
}

export interface FindingsActionRequest {
  actionType: 'Suppress' | 'Unsuppress' | 'Remediate' | 'RemediateAndGenerateTicket';
  findingIds: string[];
}

export const findingsApiSlice = solutionApi.injectEndpoints({
  endpoints: (builder) => ({
    searchFindings: builder.query<FindingsSearchResponse, SearchRequest>({
      query: (searchRequest) => ({
        url: ApiEndpoints.FINDINGS,
        method: 'POST',
        body: searchRequest,
      }),
      transformResponse: (rawResult: any): FindingsSearchResponse => ({
        Findings: rawResult.Findings,
        NextToken: rawResult.NextToken,
      }),
      providesTags: ['Findings'],
    }),

    // Get a single finding by ID
    getFinding: builder.query<FindingApiResponse, string>({
      query: (id) => `${ApiEndpoints.FINDINGS}/${id}`,
      transformResponse: (rawResult: any): FindingApiResponse => ({
        ...rawResult,
      }),
    }),

    // Update a finding
    updateFinding: builder.mutation<FindingApiResponse, Partial<FindingApiResponse>>({
      query: (finding) => ({
        url: `${ApiEndpoints.FINDINGS}/${finding.findingId}`,
        method: 'PUT',
        body: finding,
      }),
      transformResponse: (rawResult: any): FindingApiResponse => ({
        ...rawResult,
      }),
      invalidatesTags: ['Findings'],
    }),

    executeAction: builder.mutation<void, FindingsActionRequest>({
      query: (actionRequest) => ({
        url: `${ApiEndpoints.FINDINGS}/action`,
        method: 'POST',
        body: actionRequest,
      }),
    }),
  }),
});

export const {
  useSearchFindingsQuery,
  useLazySearchFindingsQuery,
  useUpdateFindingMutation,
  useExecuteActionMutation,
} = findingsApiSlice;
