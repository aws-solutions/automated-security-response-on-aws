// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import UsersTable from './users-table/UsersTable.tsx';
import { useGetUsersQuery } from '../../store/usersApiSlice.ts';
import { useContext, useState } from 'react';
import { UserContext } from '../../contexts/UserContext.tsx';
import { Flashbar, FlashbarProps } from '@cloudscape-design/components';
import { getErrorMessage } from '../../utils/error.ts';

export const UsersOverviewPage = () => {
  const { groups } = useContext(UserContext);
  const queryResult = useGetUsersQuery({ currentUserGroups: groups ?? [] }, { skip: !groups });
  const { data: users, error: usersError, refetch, isFetching } = queryResult;
  const [resetPagination, setResetPagination] = useState(false);

  const handleRefresh = async () => {
    setResetPagination(true);
    await refetch();
    setResetPagination(false);
  };
  const notifications: FlashbarProps.MessageDefinition[] = [];

  if (usersError) {
    notifications.push({
      type: 'error',
      content: `Failed to load users: ${getErrorMessage(usersError) || 'Unknown error'}`,
      id: 'users-error',
    });
  }

  return (
    <>
      {notifications.length > 0 && <Flashbar items={notifications} />}
      <UsersTable
        loading={isFetching}
        users={users || []}
        onRefresh={handleRefresh}
        resetPagination={resetPagination}
      />
    </>
  );
};
