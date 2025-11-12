// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { ApiEndpoints, solutionApi } from './solutionApi.ts';
import { User, InviteUserRequest, PutUserRequest } from '@data-models';
import { getHighestUserGroup } from '../utils/userPermissions.ts';

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

export const { useGetUsersQuery, useUpdateUserMutation, useInviteUserMutation, useDeleteUserMutation } = usersApiSlice;
