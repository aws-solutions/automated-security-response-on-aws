// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { FindingApiResponse } from '@data-models';
import { ApiEndpoints, solutionApi } from './solutionApi.ts';
import { SearchRequest } from './types.ts';

export interface FindingsSearchResponse {
  Findings: FindingApiResponse[];
  NextToken?: string;
}

export interface FindingsActionRequest {
  actionType: 'Suppress' | 'Unsuppress' | 'Remediate' | 'RemediateAndGenerateTicket';
  findingIds: string[];
}

export interface ExportFindingsResponse {
  downloadUrl: string;
  status: 'complete' | 'partial';
  totalExported: number;
  message?: string;
}

interface RawExportFindingsResponse {
  downloadUrl: string;
  status: 'complete' | 'partial';
  totalExported: number;
  message?: string;
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

    exportFindings: builder.mutation<ExportFindingsResponse, SearchRequest>({
      query: (exportRequest) => ({
        url: `${ApiEndpoints.FINDINGS}/export`,
        method: 'POST',
        body: exportRequest,
      }),
      transformResponse: (rawResult: RawExportFindingsResponse): ExportFindingsResponse => ({
        downloadUrl: rawResult.downloadUrl,
        status: rawResult.status,
        totalExported: rawResult.totalExported,
        message: rawResult.message,
      }),
    }),
  }),
});

export const { useLazySearchFindingsQuery, useExecuteActionMutation, useExportFindingsMutation } = findingsApiSlice;
