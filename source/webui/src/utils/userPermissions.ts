// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

export const getHighestUserGroup = (groups: string[] | null): string | null => {
  return groups?.find((group) => ['AdminGroup', 'DelegatedAdminGroup', 'AccountOperatorGroup'].includes(group)) || null;
};

export const canAccessUsers = (groups: string[] | null): boolean => {
  const highestGroup = getHighestUserGroup(groups);
  return highestGroup === 'AdminGroup' || highestGroup === 'DelegatedAdminGroup';
};
