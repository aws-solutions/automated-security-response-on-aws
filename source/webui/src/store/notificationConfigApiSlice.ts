// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import {
  NotificationConfigurationItem,
  CreateNotificationConfigurationRequest,
  UpdateNotificationConfigurationRequest,
  ToggleStatusRequest,
  EmailSubscriptionStatusWithType,
  TestNotificationRequest,
  TestNotificationResult,
  ConfigId,
} from '@data-models';
import { ApiEndpoints, solutionApi } from './solutionApi.ts';

export type { EmailSubscriptionStatus } from '@data-models';

export const notificationConfigApiSlice = solutionApi.injectEndpoints({
  endpoints: (builder) => ({
    getNotificationConfigs: builder.query<NotificationConfigurationItem[], void>({
      query: () => ApiEndpoints.NOTIFICATIONS,
      transformResponse: (response: { configurations: NotificationConfigurationItem[] }) => response.configurations,
      providesTags: (result) =>
        result
          ? [
              ...result.map(({ configId }) => ({ type: 'Notifications' as const, id: configId })),
              { type: 'Notifications' as const, id: 'LIST' },
            ]
          : [{ type: 'Notifications' as const, id: 'LIST' }],
    }),

    getNotificationConfig: builder.query<NotificationConfigurationItem, string>({
      query: (configId) => `${ApiEndpoints.NOTIFICATIONS}/${configId}`,
      providesTags: (_result, _error, configId) => [{ type: 'Notifications', id: configId }],
    }),

    createNotificationConfig: builder.mutation<NotificationConfigurationItem, CreateNotificationConfigurationRequest>({
      query: (body) => ({
        url: ApiEndpoints.NOTIFICATIONS,
        method: 'POST',
        body,
      }),
      invalidatesTags: [{ type: 'Notifications', id: 'LIST' }],
    }),

    updateNotificationConfig: builder.mutation<
      NotificationConfigurationItem,
      { configId: string; body: UpdateNotificationConfigurationRequest }
    >({
      query: ({ configId, body }) => ({
        url: `${ApiEndpoints.NOTIFICATIONS}/${configId}`,
        method: 'PUT',
        body,
      }),
      invalidatesTags: (_result, _error, { configId }) => [
        { type: 'Notifications', id: configId },
        { type: 'Notifications', id: 'LIST' },
      ],
    }),

    deleteNotificationConfig: builder.mutation<void, string>({
      query: (configId) => ({
        url: `${ApiEndpoints.NOTIFICATIONS}/${configId}`,
        method: 'DELETE',
      }),
      invalidatesTags: (_result, _error, configId) => [
        { type: 'Notifications', id: configId },
        { type: 'Notifications', id: 'LIST' },
      ],
    }),

    toggleNotificationConfig: builder.mutation<
      NotificationConfigurationItem,
      { configId: string; body: ToggleStatusRequest }
    >({
      query: ({ configId, body }) => ({
        url: `${ApiEndpoints.NOTIFICATIONS}/${configId}`,
        method: 'PATCH',
        body,
      }),
      invalidatesTags: (_result, _error, { configId }) => [
        { type: 'Notifications', id: configId },
        { type: 'Notifications', id: 'LIST' },
      ],
    }),

    getEmailSubscriptions: builder.query<
      { subscriptions: EmailSubscriptionStatusWithType[]; hasFailure: boolean },
      string
    >({
      query: (configId) => `${ApiEndpoints.NOTIFICATIONS}/${configId}/subscriptions`,
      transformResponse: (response: { subscriptions: EmailSubscriptionStatusWithType[]; hasFailure: boolean }) =>
        response,
      providesTags: (_result, _error, configId) => [{ type: 'EmailSubscriptions', id: configId }],
    }),

    resendEmailConfirmation: builder.mutation<void, { configId: string; email: string }>({
      query: ({ configId, email }) => ({
        url: `${ApiEndpoints.NOTIFICATIONS}/${configId}/subscriptions/resend`,
        method: 'POST',
        body: { email },
      }),
      invalidatesTags: (_result, _error, { configId }) => [{ type: 'EmailSubscriptions', id: configId }],
    }),

    sendTestNotification: builder.mutation<
      TestNotificationResult,
      { configId: ConfigId; body?: TestNotificationRequest }
    >({
      query: ({ configId, body }) => ({
        url: `${ApiEndpoints.NOTIFICATIONS}/${configId}/test`,
        method: 'POST',
        body,
      }),
    }),
  }),
});

export const {
  useGetNotificationConfigsQuery,
  useGetNotificationConfigQuery,
  useCreateNotificationConfigMutation,
  useUpdateNotificationConfigMutation,
  useDeleteNotificationConfigMutation,
  useToggleNotificationConfigMutation,
  useGetEmailSubscriptionsQuery,
  useResendEmailConfirmationMutation,
  useSendTestNotificationMutation,
} = notificationConfigApiSlice;
