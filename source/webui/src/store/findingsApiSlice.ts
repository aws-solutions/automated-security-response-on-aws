// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { FindingApiResponse, FindingId, FindingsActionRequest } from '@data-models';
import { ApiEndpoints, solutionApi } from './solutionApi.ts';
import { SearchRequest } from './types.ts';

export type { FindingsActionRequest, FindingId } from '@data-models';

export interface FindingsSearchResponse {
  Findings: FindingApiResponse[];
  NextToken?: string;
}

/**
 * Response body for a findings action (Remediate / RemediateAndGenerateTicket /
 * Rollback). `unresolvedIds` lists findings the API did not act on — e.g. a
 * finding whose resource type is not supported by the selected remediation
 * (an Amazon Inspector Lambda/ECR finding routed to the EC2-only patch
 * remediation) — so the UI can report them instead of silently flipping them
 * to IN_PROGRESS.
 */
export interface FindingsActionResponse {
  status?: string;
  unresolvedIds?: FindingId[];
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

    executeAction: builder.mutation<FindingsActionResponse, FindingsActionRequest>({
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
