// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { useState, useMemo, useContext, useEffect } from 'react';
import {
  Container,
  ContentLayout,
  Header,
  Form,
  FormField,
  Input,
  Select,
  SelectProps,
  Textarea,
  Button,
  SpaceBetween,
} from '@cloudscape-design/components';
import { useDispatch } from 'react-redux';
import { validateAccountIds, parseAccountIds, validateEmail } from '../../../utils/validation.ts';
import { useInviteUserMutation } from '../../../store/usersApiSlice.ts';
import { UserContext } from '../../../contexts/UserContext.tsx';
import { getErrorMessage } from '../../../utils/error.ts';
import { getHighestUserGroup } from '../../../utils/userPermissions.ts';
import { addNotification } from '../../../store/notificationsSlice.ts';
import { USER_TYPE_DELEGATED_ADMIN, USER_TYPE_ACCOUNT_OPERATOR, InviteUserRequest } from '@data-models';

const OPTION_DELEGATED_ADMIN = { label: 'Delegated Admin', value: USER_TYPE_DELEGATED_ADMIN };
const OPTION_ACCOUNT_OPERATOR = { label: 'Account Operator', value: USER_TYPE_ACCOUNT_OPERATOR };

export const InviteUsersPage = () => {
  const dispatch = useDispatch();
  const { email: currentUserEmail, groups } = useContext(UserContext);
  const highestUserGroup = getHighestUserGroup(groups);
  const isDelegatedAdmin = highestUserGroup === 'DelegatedAdminGroup';

  const initialPermissionType = isDelegatedAdmin ? OPTION_ACCOUNT_OPERATOR : null;

  const [email, setEmail] = useState('');
  const [permissionType, setPermissionType] = useState<SelectProps.Option | null>(initialPermissionType);
  const [ownedAccounts, setOwnedAccounts] = useState('');
  const [inviteUser, { isLoading, error, reset }] = useInviteUserMutation();

  const permissionOptions = isDelegatedAdmin
    ? [OPTION_ACCOUNT_OPERATOR]
    : [OPTION_DELEGATED_ADMIN, OPTION_ACCOUNT_OPERATOR];

  const handleSubmit = async () => {
    if (!email || !permissionType) {
      return;
    }

    const inviteRequest: InviteUserRequest = {
      email,
      role: permissionType.value === 'delegated-admin' ? ('DelegatedAdmin' as const) : ('AccountOperator' as const),
      ...(isAccountOperator && ownedAccounts ? { accountIds: parseAccountIds(ownedAccounts) } : {}),
    };

    const result = await inviteUser(inviteRequest);

    if ('data' in result) {
      dispatch(
        addNotification({
          type: 'success',
          content: `User invitation sent successfully to ${email}`,
          id: `invite-success-${Date.now()}`,
        }),
      );

      setEmail('');
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

  useEffect(() => {
    if (error) {
      dispatch(
        addNotification({
          type: 'error',
          content: `Failed to invite user: ${getErrorMessage(error)}`,
          id: `invite-error-${Date.now()}`,
        }),
      );
    }
  }, [error, dispatch]);

  const emailValidationError = useMemo(() => validateEmail(email), [email]);

  const isFormValid = useMemo(() => {
    const hasValidEmail = !!email.trim() && !emailValidationError;
    const hasPermissionType = !!permissionType;
    const hasValidAccountIds = !isAccountOperator || !validationError;

    return hasValidEmail && hasPermissionType && hasValidAccountIds;
  }, [email, emailValidationError, permissionType, isAccountOperator, validationError]);

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
              label="Email"
              description="Let us know who the invitation should be sent to, and what kind of access they should have."
              errorText={emailValidationError}
            >
              <Input
                value={email}
                onChange={({ detail }) => setEmail(detail.value)}
                placeholder="johndoe@example.com"
                invalid={!!emailValidationError}
                type="email"
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
