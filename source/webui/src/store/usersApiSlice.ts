// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { ApiEndpoints, solutionApi } from './solutionApi.ts';
import { User, InviteUserRequest, PutUserRequest } from '@data-models';
import { getHighestUserGroup } from '../utils/userPermissions.ts';

/** Category an MCP tool is grouped under in the tool-permission list. */
export type ToolCategory =
  | 'Discovery'
  | 'Reporting'
  | 'Notifications'
  | 'Remediation'
  | 'Infrastructure'
  | 'Policy'
  | 'Other';

/**
 * One grantable MCP tool, the lowest user tier it can be granted to, and the
 * category it is grouped under. The category is presentation only — grouping in the
 * UI — and carries no authorization meaning.
 */
export interface GrantableTool {
  name: string;
  tier: 'AccountOperator' | 'DelegatedAdmin';
  category: ToolCategory;
}

export const usersApiSlice = solutionApi.injectEndpoints({
  endpoints: (builder) => ({
    getUsers: builder.query<User[], { currentUserGroups?: string[] }>({
      query: ({ currentUserGroups }) => {
        const highestGroup = getHighestUserGroup(currentUserGroups ?? []);

        const type = highestGroup === 'DelegatedAdminGroup' ? 'accountOperators' : undefined;
        return type ? `${ApiEndpoints.USERS}?type=${type}` : ApiEndpoints.USERS;
      },
      providesTags: ['Users'],
    }),

    getGrantableTools: builder.query<GrantableTool[], void>({
      query: () => ApiEndpoints.MCP_TOOLS,
      transformResponse: (response: { tools: GrantableTool[] }) => response.tools,
    }),

    putUserMcpTools: builder.mutation<void, { email: string; allowedTools: string[] }>({
      query: ({ email, allowedTools }) => ({
        url: `${ApiEndpoints.USERS}/${encodeURIComponent(email)}/mcp-tools`,
        method: 'PUT',
        body: { allowedTools },
      }),
      invalidatesTags: (_, error) => (error ? [] : ['Users']),
    }),

    updateUser: builder.mutation<void, PutUserRequest>({
      query: (putRequest) => ({
        url: `${ApiEndpoints.USERS}/${encodeURIComponent(putRequest.email)}`,
        method: 'PUT',
        body: putRequest,
      }),
      invalidatesTags: (_, error) => (error ? [] : ['Users']),
    }),

    inviteUser: builder.mutation<void, InviteUserRequest>({
      query: (inviteRequest) => ({
        url: ApiEndpoints.USERS,
        method: 'POST',
        body: inviteRequest,
      }),
      invalidatesTags: (_, error) => (error ? [] : ['Users']),
    }),

    deleteUser: builder.mutation<void, string>({
      query: (email) => ({
        url: `${ApiEndpoints.USERS}/${encodeURIComponent(email)}`,
        method: 'DELETE',
      }),
      invalidatesTags: (_, error) => (error ? [] : ['Users']),
    }),
  }),
});

export const {
  useGetUsersQuery,
  useGetGrantableToolsQuery,
  usePutUserMcpToolsMutation,
  useUpdateUserMutation,
  useInviteUserMutation,
  useDeleteUserMutation,
} = usersApiSlice;
