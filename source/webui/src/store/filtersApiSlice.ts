// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { ResourceFilter, ResourceFilterInput, UpdateFilterRequest } from '@data-models';
import { ApiEndpoints, solutionApi } from './solutionApi.ts';

/**
 * Body of `DELETE /filters/{id}`. Both the 200 and the 207 carry it: `deleted` is false when the
 * filter was already absent (200) or when some controls still reference it (207, with the
 * survivors in `stillAttachedControlIds`). RTK Query resolves any 2xx, so the page has to read
 * these fields rather than treat a resolved mutation as "deleted".
 */
export interface DeleteFilterResponse {
  message: string;
  deleted: boolean;
  /** Controls this request detached the filter from — widened even when `deleted` is false. */
  detachedControlIds?: string[];
  /** Present on the 207: controls still referencing the filter, so it was kept. */
  stillAttachedControlIds?: string[];
}

export const filtersApiSlice = solutionApi.injectEndpoints({
  endpoints: (builder) => ({
    getFilters: builder.query<ResourceFilter[], void>({
      query: () => ApiEndpoints.FILTERS,
      transformResponse: (response: { filters: ResourceFilter[] }) => response.filters,
      providesTags: ['Filters'],
    }),

    createFilter: builder.mutation<ResourceFilter, ResourceFilterInput>({
      query: (body) => ({
        url: ApiEndpoints.FILTERS,
        method: 'POST',
        body,
      }),
      invalidatesTags: ['Filters'],
    }),

    updateFilter: builder.mutation<ResourceFilter, { filterId: string; body: UpdateFilterRequest }>({
      query: ({ filterId, body }) => ({
        url: `${ApiEndpoints.FILTERS}/${filterId}`,
        method: 'PUT',
        body,
      }),
      invalidatesTags: ['Filters'],
    }),

    deleteFilter: builder.mutation<DeleteFilterResponse, string>({
      query: (filterId) => ({
        url: `${ApiEndpoints.FILTERS}/${filterId}`,
        method: 'DELETE',
      }),
      invalidatesTags: ['Filters', 'Controls'],
    }),
  }),
});

export const { useGetFiltersQuery, useCreateFilterMutation, useUpdateFilterMutation, useDeleteFilterMutation } =
  filtersApiSlice;
