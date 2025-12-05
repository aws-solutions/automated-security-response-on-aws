// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { useState, useMemo, useContext } from 'react';
import {
  Container,
  ContentLayout,
  Header,
  Form,
  FormField,
  Select,
  SelectProps,
  Textarea,
  Button,
  SpaceBetween,
} from '@cloudscape-design/components';
import { useDispatch } from 'react-redux';
import { validateAccountIds, parseAccountIds, validateEmail, parseEmails } from '../../../utils/validation.ts';
import { useInviteUserMutation } from '../../../store/usersApiSlice.ts';
import { UserContext } from '../../../contexts/UserContext.tsx';
import { getErrorMessage } from '../../../utils/error.ts';
import { getHighestUserGroup } from '../../../utils/userPermissions.ts';
import { addNotification } from '../../../store/notificationsSlice.ts';
import { USER_TYPE_DELEGATED_ADMIN, USER_TYPE_ACCOUNT_OPERATOR } from '@data-models';

const OPTION_DELEGATED_ADMIN = { label: 'Delegated Admin', value: USER_TYPE_DELEGATED_ADMIN };
const OPTION_ACCOUNT_OPERATOR = { label: 'Account Operator', value: USER_TYPE_ACCOUNT_OPERATOR };

export const InviteUsersPage = () => {
  const dispatch = useDispatch();
  const { groups } = useContext(UserContext);
  const highestUserGroup = getHighestUserGroup(groups);
  const isDelegatedAdmin = highestUserGroup === 'DelegatedAdminGroup';

  const initialPermissionType = isDelegatedAdmin ? OPTION_ACCOUNT_OPERATOR : null;

  const [emails, setEmails] = useState('');
  const [permissionType, setPermissionType] = useState<SelectProps.Option | null>(initialPermissionType);
  const [ownedAccounts, setOwnedAccounts] = useState('');
  const [inviteUser, { isLoading, reset }] = useInviteUserMutation();

  const permissionOptions = isDelegatedAdmin
    ? [OPTION_ACCOUNT_OPERATOR]
    : [OPTION_DELEGATED_ADMIN, OPTION_ACCOUNT_OPERATOR];

  const handleSubmit = async () => {
    if (!emails || !permissionType) {
      return;
    }

    const emailList = parseEmails(emails);
    const accountIds = isAccountOperator && ownedAccounts ? parseAccountIds(ownedAccounts) : undefined;

    const results = await Promise.allSettled(
      emailList.map((email) =>
        inviteUser({
          email,
          role: permissionType.value === 'delegated-admin' ? ('DelegatedAdmin' as const) : ('AccountOperator' as const),
          ...(accountIds ? { accountIds } : {}),
        }).unwrap(),
      ),
    );

    const successCount = results.filter((r) => r.status === 'fulfilled').length;
    const failures = results.filter((r) => r.status === 'rejected');
    const failureCount = failures.length;

    if (successCount > 0) {
      dispatch(
        addNotification({
          type: 'success',
          content: `Successfully invited ${successCount} user${successCount > 1 ? 's' : ''}`,
          id: `invite-success-${Date.now()}`,
        }),
      );
    }

    if (failureCount > 0) {
      const errorMessages = failures
        .map((f) => getErrorMessage(f.reason))
        .filter((msg): msg is string => !!msg)
        .join(', ');
      const content = errorMessages
        ? `Failed to invite ${failureCount} user${failureCount > 1 ? 's' : ''}: ${errorMessages}`
        : `Failed to invite ${failureCount} user${failureCount > 1 ? 's' : ''}`;
      dispatch(
        addNotification({
          type: 'error',
          content,
          id: `invite-error-${Date.now()}`,
        }),
      );
    }

    if (successCount === emailList.length) {
      setEmails('');
      setPermissionType(initialPermissionType);
      setOwnedAccounts('');
      reset();
    }
  };

  const isAccountOperator = permissionType?.value === OPTION_ACCOUNT_OPERATOR.value;
  const validationError = useMemo(() => {
    if (!isAccountOperator || !ownedAccounts.trim()) {
      return null;
    }
    return validateAccountIds(ownedAccounts);
  }, [ownedAccounts, isAccountOperator]);

  const emailValidationError = useMemo(() => {
    if (!emails.trim()) return null;
    const emailList = parseEmails(emails);
    const invalidEmails = emailList.filter((email) => validateEmail(email));
    return invalidEmails.length > 0
      ? `Invalid email address${invalidEmails.length > 1 ? 'es' : ''}: ${invalidEmails.join(', ')}`
      : null;
  }, [emails]);

  const isFormValid = useMemo(() => {
    const hasValidEmails = !!emails.trim() && !emailValidationError;
    const hasPermissionType = !!permissionType;
    const hasValidAccountIds = !isAccountOperator || !validationError;

    return hasValidEmails && hasPermissionType && hasValidAccountIds;
  }, [emails, emailValidationError, permissionType, isAccountOperator, validationError]);

  return (
    <ContentLayout
      header={
        <Header
          variant="h1"
          description="Send an access invitation for additional users to access this Web UI. The invitee will receive temporary credentials via email and must visit this app to complete account setup."
        >
          Invite Users
        </Header>
      }
    >
      <Container header={<Header variant="h2">Invitation Details</Header>}>
        <Form
          actions={
            <Button variant="primary" onClick={handleSubmit} loading={isLoading} disabled={!isFormValid}>
              Submit
            </Button>
          }
        >
          <SpaceBetween direction="vertical" size="l">
            <FormField
              label="Email(s)"
              description="Enter one or more email addresses separated by commas to invite multiple users."
              errorText={emailValidationError}
            >
              <Textarea
                value={emails}
                onChange={({ detail }) => setEmails(detail.value)}
                placeholder="johndoe@example.com, janedoe@example.com"
                invalid={!!emailValidationError}
                rows={3}
              />
            </FormField>

            <FormField
              label="Permission Type"
              description={
                isDelegatedAdmin
                  ? 'Delegated Admins can only invite Account Operators'
                  : 'What level of access should this user have?'
              }
            >
              <Select
                selectedOption={permissionType}
                onChange={({ detail }) => setPermissionType(detail.selectedOption)}
                options={permissionOptions}
                placeholder="Choose an option"
                disabled={isDelegatedAdmin}
              />
            </FormField>

            {isAccountOperator && (
              <FormField
                label="Owned Accounts"
                description="Enter a comma-separated list of Account IDs for which the user should have remediation access."
                errorText={validationError}
              >
                <Textarea
                  value={ownedAccounts}
                  onChange={({ detail }) => setOwnedAccounts(detail.value)}
                  placeholder="123456789012, 012345678901, 987654321012"
                  rows={3}
                  invalid={!!validationError}
                />
              </FormField>
            )}
          </SpaceBetween>
        </Form>
      </Container>
    </ContentLayout>
  );
};
