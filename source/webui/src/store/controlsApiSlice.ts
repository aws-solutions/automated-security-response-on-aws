// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { SecurityControl, BulkEditRequest, BulkEditResponse } from '@data-models';
import { solutionApi } from './solutionApi.ts';

export const controlsApiSlice = solutionApi.injectEndpoints({
  endpoints: (builder) => ({
    getControls: builder.query<SecurityControl[], void>({
      query: () => 'controls',
      transformResponse: (response: { controls: SecurityControl[] }) => response.controls,
      providesTags: ['Controls'],
    }),

    bulkEditControls: builder.mutation<BulkEditResponse, BulkEditRequest>({
      query: (body) => ({
        url: 'controls/bulk-edit',
        method: 'POST',
        body,
      }),
      invalidatesTags: ['Controls', 'Filters'],
    }),
  }),
});

export const { useGetControlsQuery, useBulkEditControlsMutation } = controlsApiSlice;
