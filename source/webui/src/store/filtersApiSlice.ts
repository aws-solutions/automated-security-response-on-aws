// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { ResourceFilter, ResourceFilterInput, UpdateFilterRequest } from '@data-models';
import { ApiEndpoints, solutionApi } from './solutionApi.ts';

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

    deleteFilter: builder.mutation<void, string>({
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
