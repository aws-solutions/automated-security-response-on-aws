// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { createContext, ReactNode, useEffect, useMemo, useState } from 'react';
import { FlashbarProps } from '@cloudscape-design/components';
import { useDispatch, useSelector } from 'react-redux';
import { deleteNotification, selectNotifications } from '../store/notificationsSlice.ts';

/**
 * NotificationContext provides the notifications to the global FlashBar
 * and any component that needs to use them.
 *
 * The notifications are stored in the redux store,
 * but NotificationContext adds the onDismiss method to each notification object
 * which is not serializable and cannot be stored in redux.
 */
export type NotificationContextType = {
  notifications: ReadonlyArray<FlashbarProps.MessageDefinition>;
};

export const NotificationContext = createContext<NotificationContextType>(null as unknown as NotificationContextType);
export const NotificationContextProvider = (props: { children: ReactNode }) => {
  const storeNotifications = useSelector(selectNotifications);
  const dispatch = useDispatch();

  const initialState: ReadonlyArray<FlashbarProps.MessageDefinition> = [];
  const [notifications, setNotifications] = useState(initialState);

  useEffect(() => {
    setNotifications(
      storeNotifications.map((it) => {
        return {
          dismissible: true,
          onDismiss: () => dispatch(deleteNotification({ id: it.id })),
          ...it,
        };
      }),
    );
  }, [storeNotifications]);

  // Memoize so the Context value identity only changes when notifications change.
  const contextValue = useMemo<NotificationContextType>(() => ({ notifications }), [notifications]);

  return (
    <>
      <NotificationContext.Provider value={contextValue}>{props.children}</NotificationContext.Provider>
    </>
  );
};
