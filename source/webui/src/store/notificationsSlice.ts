// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { CaseReducer, createSlice, Slice } from '@reduxjs/toolkit';
import React from 'react';
import { RootState } from './store.ts';

export type NotificationPayload = {
  id: string;
  header?: React.ReactNode;
  content?: React.ReactNode;
  type: 'success' | 'warning' | 'info' | 'error' | 'in-progress';
};

export type NotificationReducers = {
  addNotification: CaseReducer<NotificationState, { payload: NotificationPayload; type: string }>;
  deleteNotification: CaseReducer<NotificationState, { payload: { id: string }; type: string }>;
};
export type NotificationState = {
  notifications: Array<NotificationPayload>;
};

export const notificationsSlice: Slice<NotificationState, NotificationReducers, string> = createSlice({
  name: 'notifications',
  initialState: {
    notifications: [] as Array<NotificationPayload>,
  },
  reducers: {
    addNotification: (state, action) => {
      const notification = action.payload;
      if (!state.notifications.find((it) => it.id === notification.id)) state.notifications.push(notification);
    },
    deleteNotification: (state, action) => {
      state.notifications = state.notifications.filter((it) => it.id !== action.payload.id);
    },
  },
});

export const selectNotifications = (state: RootState) => state.notifications.notifications;
export const { addNotification, deleteNotification } = notificationsSlice.actions;
