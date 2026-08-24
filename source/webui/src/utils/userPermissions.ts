// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

export const getHighestUserGroup = (groups: string[] | null): string | null => {
  return groups?.find((group) => ['AdminGroup', 'DelegatedAdminGroup', 'AccountOperatorGroup'].includes(group)) || null;
};

const isAdminOrDelegatedAdmin = (groups: string[] | null): boolean => {
  const highestGroup = getHighestUserGroup(groups);
  return highestGroup === 'AdminGroup' || highestGroup === 'DelegatedAdminGroup';
};

export const canAccessUsers = isAdminOrDelegatedAdmin;

export const canEditControls = isAdminOrDelegatedAdmin;

export const canManageNotifications = isAdminOrDelegatedAdmin;

export const canAccessControlPanel = (groups: string[] | null): boolean => {
  const highestGroup = getHighestUserGroup(groups);
  return (
    highestGroup === 'AdminGroup' || highestGroup === 'DelegatedAdminGroup' || highestGroup === 'AccountOperatorGroup'
  );
};

const isAccountOperator = (groups: string[] | null): boolean => getHighestUserGroup(groups) === 'AccountOperatorGroup';

/**
 * Whether the current user may modify (edit, delete, toggle) a given notification configuration.
 * Admins and delegated admins may modify any configuration. Account operators may modify only the
 * configurations they created, mirroring the creator-based authorization enforced by the API.
 */
export const canModifyNotificationConfig = (
  groups: string[] | null,
  userEmail: string | null,
  config: { createdBy?: string },
): boolean => {
  if (isAdminOrDelegatedAdmin(groups)) return true;
  if (isAccountOperator(groups)) return !!userEmail && config.createdBy === userEmail;
  return false;
};
