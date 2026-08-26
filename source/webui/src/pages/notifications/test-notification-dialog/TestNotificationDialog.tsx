// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { useCallback, useEffect, useRef, useState } from 'react';
import { Modal, Box, SpaceBetween, Button, Alert, StatusIndicator, Spinner } from '@cloudscape-design/components';
import {
  NotificationConfigurationItem,
  ChannelTestResult,
  DeliveryChannelType,
  DeliveryChannelConfig,
  RecipientType,
  ConfigId,
} from '@data-models';
import { useSendTestNotificationMutation } from '../../../store/notificationConfigApiSlice.ts';
import { channelLabel } from '../../../store/controlPanelTypes.ts';

const RECIPIENT_TYPE_LABELS: Record<RecipientType, string> = {
  rootAccountEmail: 'Primary account contact',
  securityContact: 'Security contact',
  operationsContact: 'Operations contact',
  accountOperators: 'Account Operators',
  custom: 'Custom emails',
};

function channelDescription(channel: DeliveryChannelConfig): string | undefined {
  switch (channel.type) {
    case 'email': {
      const parts = channel.recipients.map((r) => {
        if (r.recipientType === 'custom' && r.emailAddresses?.length) {
          return r.emailAddresses.join(', ');
        }
        return RECIPIENT_TYPE_LABELS[r.recipientType] ?? r.recipientType;
      });
      return parts.join(', ');
    }
    case 'slack':
      return channel.channelId ? `Channel: ${channel.channelId}` : undefined;
    case 'jira':
      return `${channel.endpointUrl} · Project: ${channel.projectKey}`;
    case 'servicenow':
      return `${channel.endpointUrl} · Table: ${channel.tableName}`;
    case 'sns':
      return channel.topicArn;
    default:
      return undefined;
  }
}

export interface TestNotificationDialogProps {
  config: NotificationConfigurationItem;
  onClose: () => void;
  onEditConfig: (configId: ConfigId) => void;
}

type DialogState = 'confirmation' | 'loading' | 'success' | 'failure';

const TIMEOUT_MS = 30_000;

/**
 * Modal dialog for sending a test notification for a given notification configuration.
 * Progresses through states: confirmation → loading → success/failure.
 */
export const TestNotificationDialog: React.FC<TestNotificationDialogProps> = ({ config, onClose, onEditConfig }) => {
  const [dialogState, setDialogState] = useState<DialogState>('confirmation');
  const [results, setResults] = useState<Record<string, ChannelTestResult>>({});
  const [eventId, setEventId] = useState<string | null>(null);
  const [isTimeoutError, setIsTimeoutError] = useState(false);
  const [isNetworkError, setIsNetworkError] = useState(false);
  const timeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const [sendTest] = useSendTestNotificationMutation();

  const enabledChannels = config.deliveryChannels.filter((ch) => ch.enabled);

  const clearTimeoutRef = useCallback((): void => {
    if (timeoutRef.current !== null) {
      globalThis.clearTimeout(timeoutRef.current);
      timeoutRef.current = null;
    }
  }, []);

  useEffect(() => {
    return () => clearTimeoutRef();
  }, [clearTimeoutRef]);

  const handleSendTest = useCallback(
    async (channels?: DeliveryChannelType[]): Promise<void> => {
      setDialogState('loading');
      setIsTimeoutError(false);
      setIsNetworkError(false);

      const body: { channels?: DeliveryChannelType[] } = channels ? { channels } : {};

      let timedOut = false;
      timeoutRef.current = globalThis.setTimeout(() => {
        timedOut = true;
        setIsTimeoutError(true);
        setDialogState('failure');
      }, TIMEOUT_MS);

      try {
        const response = await sendTest({ configId: config.configId, body }).unwrap();
        clearTimeoutRef();
        if (timedOut) return;

        setEventId(response.eventId);

        if (channels) {
          setResults((prev) => ({ ...prev, ...response.results }));
        } else {
          setResults(response.results);
        }

        if (response.success) {
          setDialogState('success');
        } else {
          setDialogState('failure');
        }
      } catch (error) {
        clearTimeoutRef();
        if (timedOut) return;
        console.error('Test notification request failed:', error);
        setIsNetworkError(true);
        setResults({});
        setDialogState('failure');
      }
    },
    [sendTest, config.configId, clearTimeoutRef],
  );

  const handleRetry = useCallback((): void => {
    const failedTypes = Object.values(results)
      .filter((r) => r.status === 'failure')
      .map((r) => r.channelType);
    const channelsToRetry = failedTypes.length > 0 ? failedTypes : undefined;
    void handleSendTest(channelsToRetry);
  }, [handleSendTest, results]);

  const handleEditConfig = useCallback((): void => {
    onEditConfig(config.configId);
  }, [onEditConfig, config.configId]);

  const footer = (
    <Box float="right">
      <SpaceBetween direction="horizontal" size="xs">
        {dialogState === 'confirmation' && (
          <>
            <Button variant="link" onClick={onClose}>
              Cancel
            </Button>
            <Button variant="primary" onClick={() => void handleSendTest()}>
              Send test
            </Button>
          </>
        )}
        {dialogState === 'loading' && (
          <Button variant="primary" disabled>
            Send test
          </Button>
        )}
        {dialogState === 'success' && (
          <Button variant="primary" onClick={onClose}>
            Close
          </Button>
        )}
        {dialogState === 'failure' && (
          <>
            <Button onClick={handleEditConfig}>Edit configuration</Button>
            <Button variant="primary" onClick={handleRetry}>
              Retry
            </Button>
          </>
        )}
      </SpaceBetween>
    </Box>
  );

  return (
    <Modal visible onDismiss={onClose} header="Send test notification" footer={footer}>
      {dialogState === 'confirmation' && (
        <SpaceBetween size="m">
          <Box>
            A synthetic test notification will be sent to all enabled channels on <strong>{config.name}</strong>. This
            verifies that each channel is correctly configured and can receive messages.
          </Box>
          <SpaceBetween size="s">
            <Box variant="awsui-key-label">Channels to test</Box>
            <SpaceBetween size="xs">
              {enabledChannels.map((ch, index) => {
                const description = channelDescription(ch);
                return (
                  <Box key={`${ch.type}-${index}`} padding={{ left: 's' }}>
                    <SpaceBetween size="xxxs">
                      <Box fontWeight="bold">{channelLabel(ch.type)}</Box>
                      {description && (
                        <Box variant="small" color="text-body-secondary">
                          {description}
                        </Box>
                      )}
                    </SpaceBetween>
                  </Box>
                );
              })}
            </SpaceBetween>
          </SpaceBetween>
          {!config.enabled && (
            <Alert type="info">This configuration does not need to be enabled to send a test notification.</Alert>
          )}
        </SpaceBetween>
      )}

      {dialogState === 'loading' && (
        <Box textAlign="center">
          <SpaceBetween size="s">
            <Spinner size="large" />
            <Box>Sending test notification...</Box>
          </SpaceBetween>
        </Box>
      )}

      {dialogState === 'success' && (
        <SpaceBetween size="m">
          <StatusIndicator type="success">All channels delivered successfully</StatusIndicator>
          <SpaceBetween size="xs">
            {Object.values(results).map((r) => (
              <Box key={r.channelType} padding={{ left: 's' }}>
                <StatusIndicator type="success">{channelLabel(r.channelType)}</StatusIndicator>
              </Box>
            ))}
          </SpaceBetween>
          {eventId && (
            <Box variant="small" color="text-body-secondary">
              Event ID:{' '}
              <Box variant="code" display="inline">
                {eventId}
              </Box>
            </Box>
          )}
        </SpaceBetween>
      )}

      {dialogState === 'failure' && (
        <SpaceBetween size="m">
          {isTimeoutError && <Alert type="error">The test notification request timed out. Please try again.</Alert>}
          {isNetworkError && !isTimeoutError && (
            <Alert type="error">
              A network error occurred while sending the test notification. Check your connection and try again.
            </Alert>
          )}
          {Object.keys(results).length > 0 && (
            <SpaceBetween size="xs">
              {Object.values(results).map((r) => (
                <Box key={r.channelType} padding={{ left: 's' }}>
                  <SpaceBetween size="xxxs">
                    <StatusIndicator type={r.status === 'success' ? 'success' : 'error'}>
                      {channelLabel(r.channelType)}
                    </StatusIndicator>
                    {r.error && (
                      <Box variant="small" color="text-status-error" padding={{ left: 'l' }}>
                        {r.error}
                      </Box>
                    )}
                  </SpaceBetween>
                </Box>
              ))}
            </SpaceBetween>
          )}
          {!isTimeoutError && Object.keys(results).length > 0 && (
            <Alert type="warning">
              One or more channels failed. Review the errors above and check your channel configuration.
            </Alert>
          )}
          {eventId && (
            <Box variant="small" color="text-body-secondary">
              Event ID:{' '}
              <Box variant="code" display="inline">
                {eventId}
              </Box>
            </Box>
          )}
        </SpaceBetween>
      )}
    </Modal>
  );
};
