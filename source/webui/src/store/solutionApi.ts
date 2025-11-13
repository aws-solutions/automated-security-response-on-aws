// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { BaseQueryApi, BaseQueryFn, createApi, FetchArgs, FetchBaseQueryError } from '@reduxjs/toolkit/query/react';
import { API } from '../utils/API.adapter.ts';

// Boilerplate code. Do not change.
export const dynamicBaseQuery: BaseQueryFn<string | FetchArgs, unknown, FetchBaseQueryError> = async (
  args: string | FetchArgs,
  api: BaseQueryApi,
  extraOptions: any,
) => {
  function runAmplifyAxiosRequest(): Promise<any> {
    if (typeof args === 'string') {
      return API.get('solution-api', args, extraOptions);
    } else {
      switch (args.method) {
        case 'POST':
          return API.post('solution-api', args.url, { body: args.body, ...extraOptions });
        case 'PUT':
          return API.put('solution-api', args.url, { body: args.body, ...extraOptions });
        case 'DELETE':
          return API.del('solution-api', args.url, extraOptions);
        case 'PATCH':
          return API.patch('solution-api', args.url, { body: args.body, ...extraOptions });
        case 'HEAD':
          return API.head('solution-api', args.url, extraOptions);
        default:
          return API.get('solution-api', args.url, extraOptions);
      }
    }
  }

  try {
    const data = await runAmplifyAxiosRequest();
    return { data };
  } catch (error: any) {
    return {
      error: {
        status: error.response?.status || 500,
        data: error.response?.data,
        message: error.message || 'Unknown error',
      },
    };
  }
};

/**
 * Create 1 api per base URL. Only create a second API if you use multiple API Gateways in the backend.
 */
export const solutionApi = createApi({
  reducerPath: 'solution-api',
  baseQuery: dynamicBaseQuery,
  endpoints: (_) => ({}),
  refetchOnMountOrArgChange: true,
  tagTypes: ['Findings', 'Remediations', 'User', 'Users'],
});

export enum ApiEndpoints {
  USERS = 'users',
  REMEDIATIONS = 'remediations',
  FINDINGS = 'findings',
  EXPORT = 'export',
}
