// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * Email Subscription Management component.
 * Displays SNS subscription status (Pending/Confirmed/Deleted) with resend-confirmation action.
 */

import { useState } from 'react';
import Modal from '@cloudscape-design/components/modal';
import Table from '@cloudscape-design/components/table';
import Button from '@cloudscape-design/components/button';
import Box from '@cloudscape-design/components/box';
import SpaceBetween from '@cloudscape-design/components/space-between';
import Badge from '@cloudscape-design/components/badge';
import Alert from '@cloudscape-design/components/alert';

import {
  useGetEmailSubscriptionsQuery,
  useResendEmailConfirmationMutation,
  EmailSubscriptionStatus,
} from '../../store/notificationConfigApiSlice.ts';

export interface EmailSubscriptionManagementProps {
  visible: boolean;
  configId: string;
  configName: string;
  onDismiss: () => void;
}

const statusBadge = (status: EmailSubscriptionStatus['status']) => {
  switch (status) {
    case 'Confirmed':
      return <Badge color="green">Confirmed</Badge>;
    case 'PendingConfirmation':
      return <Badge color="blue">Pending</Badge>;
  }
};

export default function EmailSubscriptionManagement({
  visible,
  configId,
  configName,
  onDismiss,
}: Readonly<EmailSubscriptionManagementProps>) {
  const { data: subscriptionData, isLoading, refetch } = useGetEmailSubscriptionsQuery(configId, { skip: !visible });
  const subscriptions = subscriptionData?.subscriptions ?? [];
  const [resend] = useResendEmailConfirmationMutation();
  const [resendingEmail, setResendingEmail] = useState<string | null>(null);
  const [feedback, setFeedback] = useState<{ type: 'success' | 'error'; message: string } | null>(null);

  const handleResend = async (email: string) => {
    setResendingEmail(email);
    setFeedback(null);
    try {
      await resend({ configId, email }).unwrap();
      setFeedback({ type: 'success', message: `Confirmation resent to ${email}` });
    } catch {
      setFeedback({ type: 'error', message: `Failed to resend confirmation to ${email}` });
    } finally {
      setResendingEmail(null);
    }
  };

  return (
    <Modal
      visible={visible}
      onDismiss={onDismiss}
      size="large"
      header={`Email subscriptions — ${configName} (${subscriptions.length})`}
    >
      <SpaceBetween size="m">
        <Box float="right">
          <Button iconName="refresh" onClick={() => refetch()} loading={isLoading} ariaLabel="Refresh" />
        </Box>
        {feedback && <Alert type={feedback.type}>{feedback.message}</Alert>}
        <Table<EmailSubscriptionStatus>
          items={subscriptions}
          loading={isLoading}
          loadingText="Loading subscriptions..."
          columnDefinitions={[
            { id: 'email', header: 'Email', cell: (item) => item.email },
            { id: 'status', header: 'Status', cell: (item) => statusBadge(item.status), width: 140 },
            {
              id: 'actions',
              header: 'Actions',
              cell: (item) => (
                <SpaceBetween direction="horizontal" size="xs">
                  {item.status === 'PendingConfirmation' && (
                    <Button
                      variant="inline-link"
                      onClick={() => handleResend(item.email)}
                      loading={resendingEmail === item.email}
                    >
                      Resend
                    </Button>
                  )}
                </SpaceBetween>
              ),
              width: 200,
            },
          ]}
          empty={
            <Box textAlign="center" color="text-body-secondary">
              No email subscriptions
            </Box>
          }
        />
      </SpaceBetween>
    </Modal>
  );
}
