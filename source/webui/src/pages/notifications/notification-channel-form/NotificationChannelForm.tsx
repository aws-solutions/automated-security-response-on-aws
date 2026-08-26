// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { useState, useEffect, useRef } from 'react';
import Modal from '@cloudscape-design/components/modal';
import Wizard, { WizardProps } from '@cloudscape-design/components/wizard';
import Box from '@cloudscape-design/components/box';
import SpaceBetween from '@cloudscape-design/components/space-between';
import FormField from '@cloudscape-design/components/form-field';
import Input from '@cloudscape-design/components/input';
import Toggle from '@cloudscape-design/components/toggle';
import Checkbox from '@cloudscape-design/components/checkbox';
import Header from '@cloudscape-design/components/header';
import Container from '@cloudscape-design/components/container';
import TokenGroup from '@cloudscape-design/components/token-group';
import Select from '@cloudscape-design/components/select';
import Multiselect from '@cloudscape-design/components/multiselect';
import RadioGroup from '@cloudscape-design/components/radio-group';
import Button from '@cloudscape-design/components/button';
import Alert from '@cloudscape-design/components/alert';
import Popover from '@cloudscape-design/components/popover';
import Icon from '@cloudscape-design/components/icon';

import {
  NotificationConfigurationItem,
  CreateNotificationConfigurationRequest,
  DeliveryChannelConfig,
  SeverityFilter,
  RemediationStatusFilter,
  BatchWindowUnit,
  RecipientType,
  NotificationType,
  IaCFormat,
} from '../../../store/controlPanelTypes.ts';
import {
  SecurityControl,
  ResourceFilter,
  NOTIFICATION_CHANNEL_SECRET_PREFIX,
  checkSlackChannelFields,
  checkJiraChannelFields,
  checkServiceNowChannelFields,
  REMEDIATION_STATUS_FILTER_OPTIONS,
  EmailSubscriptionStatusWithType,
} from '@data-models';
import { useGetEmailSubscriptionsQuery } from '../../../store/notificationConfigApiSlice.ts';

type WithAll<T extends string> = T | 'All';

function toggleMutualExclusiveAll<T extends string>(selected: WithAll<T>[], current: WithAll<T>[]): WithAll<T>[] {
  if (selected.includes('All') && !current.includes('All')) return ['All'];
  if (selected.length > 1 && selected.includes('All')) return selected.filter((s) => s !== 'All');
  if (selected.length === 0) return ['All'];
  return selected;
}

/**
 * Map a saved filter array to its editor state. An empty or undefined saved filter means
 * "all" semantically, so it surfaces as the ['All'] sentinel in the picker.
 */
function toFilterState<T extends string>(saved: readonly T[] | undefined): T[] | ['All'] {
  return saved && saved.length > 0 ? [...saved] : ['All'];
}

/** A subscription that is awaiting confirmation and has a known resolved recipient type. */
function hasPendingRecipientType(
  s: EmailSubscriptionStatusWithType,
): s is EmailSubscriptionStatusWithType & { recipientType: RecipientType } {
  return s.status === 'PendingConfirmation' && !!s.recipientType;
}

export interface NotificationChannelFormProps {
  mode: 'create' | 'edit';
  initialValues?: NotificationConfigurationItem;
  resourceFilters: ResourceFilter[];
  controls: SecurityControl[];
  onSubmit: (input: CreateNotificationConfigurationRequest, version?: number) => void;
  onCancel: () => void;
  isSubmitting: boolean;
}

interface FormErrors {
  name?: string;
  channels?: string;
  recipients?: string;
  snsArn?: string;
  slack?: string;
  slackChannelId?: string;
  jira?: string;
  jiraProjectKey?: string;
  jiraIssueType?: string;
  jiraSecretArn?: string;
  jiraCustomFields?: string;
  serviceNow?: string;
  serviceNowEndpointUrl?: string;
  serviceNowTableName?: string;
  serviceNowSecretArn?: string;
  serviceNowCustomFields?: string;
  batchWindow?: string;
  presignedUrlExpiration?: string;
  deadlineDays?: string;
  iacFormats?: string;
}

/** Extract email addresses from the email channel config's recipients. */
function extractEmailState(channels: DeliveryChannelConfig[]) {
  const email = channels.find((c) => c.type === 'email');
  if (email?.type !== 'email') {
    return { recipientTypes: [] as RecipientType[], customEmails: [] as string[] };
  }
  const recipientTypes = email.recipients.map((r) => r.recipientType);
  const customEmails = email.recipients
    .filter((r) => r.recipientType === 'custom')
    .flatMap((r) => r.emailAddresses ?? []);
  return { recipientTypes, customEmails };
}

export default function NotificationChannelForm({
  mode,
  initialValues,
  resourceFilters,
  controls,
  onSubmit,
  onCancel,
  isSubmitting,
}: Readonly<NotificationChannelFormProps>) {
  const isEdit = mode === 'edit';
  const [step, setStep] = useState(0);

  // Subscription query for per-item locking (edit mode only)
  const configId = isEdit && initialValues ? initialValues.configId : '';
  const { data: subscriptionData } = useGetEmailSubscriptionsQuery(configId, { skip: !configId });
  const subscriptions = subscriptionData?.subscriptions ?? [];
  const subscriptionResolutionFailed = subscriptionData?.hasFailure ?? false;

  // Basic info
  const [name, setName] = useState('');
  const [enabled, setEnabled] = useState(true);
  const [notificationType, setNotificationType] = useState<NotificationType>('finding');

  // Delivery channel toggles
  const [emailEnabled, setEmailEnabled] = useState(false);
  const [slackEnabled, setSlackEnabled] = useState(false);
  const [jiraEnabled, setJiraEnabled] = useState(false);
  const [serviceNowEnabled, setServiceNowEnabled] = useState(false);
  const [snsEnabled, setSnsEnabled] = useState(false);

  // Email recipients
  const [rootAccountEmail, setRootAccountEmail] = useState(false);
  const [securityContact, setSecurityContact] = useState(false);
  const [operationsContact, setOperationsContact] = useState(false);
  const [accountOperators, setAccountOperators] = useState(false);
  const [customEmails, setCustomEmails] = useState<string[]>([]);
  const [emailInput, setEmailInput] = useState('');

  // Per-item locking: only custom emails with pending subscriptions are locked (can't be removed).
  // Recipient type checkboxes are locked only if that type's own email is pending.
  // When resolution failed, the recipientType mapping may be incomplete — disable locking
  // to avoid blocking edits based on stale/partial data.
  const pendingEmails = subscriptionResolutionFailed
    ? new Set<string>()
    : new Set(subscriptions.filter((s) => s.status === 'PendingConfirmation').map((s) => s.email));
  const pendingRecipientTypes = subscriptionResolutionFailed
    ? new Set<string>()
    : new Set(subscriptions.filter(hasPendingRecipientType).map((s) => s.recipientType));

  // Channel configs
  const [snsTopicArn, setSnsTopicArn] = useState('');
  const [slackChannelId, setSlackChannelId] = useState('');
  const [slackSecretArn, setSlackSecretArn] = useState('');
  const [jiraEndpointUrl, setJiraEndpointUrl] = useState('');
  const [jiraProjectKey, setJiraProjectKey] = useState('');
  const [jiraIssueType, setJiraIssueType] = useState('');
  const [jiraSecretArn, setJiraSecretArn] = useState('');
  const [jiraCustomFields, setJiraCustomFields] = useState<{ key: string; value: string }[]>([]);
  const [serviceNowEndpointUrl, setServiceNowEndpointUrl] = useState('');
  const [serviceNowTableName, setServiceNowTableName] = useState('');
  const [serviceNowSecretArn, setServiceNowSecretArn] = useState('');
  const [serviceNowCustomFields, setServiceNowCustomFields] = useState<{ key: string; value: string }[]>([]);

  // Batching
  const [batchEnabled, setBatchEnabled] = useState(false);
  const [batchDuration, setBatchDuration] = useState('5');
  const [batchUnit, setBatchUnit] = useState<BatchWindowUnit>('Minutes');

  // Batch export
  const [presignedUrlExpirationHours, setPresignedUrlExpirationHours] = useState('1');

  // Content options
  const [includeManualRemediationLink, setIncludeManualRemediationLink] = useState(false);
  const [includeRemediationDeadline, setIncludeRemediationDeadline] = useState(false);
  const [enforceDeadline, setEnforceDeadline] = useState(false);
  const [deadlineDays, setDeadlineDays] = useState('7');
  const [includeIaCSnippet, setIncludeIaCSnippet] = useState(false);
  const [cloudFormationYaml, setCloudFormationYaml] = useState(false);
  const [cloudFormationJson, setCloudFormationJson] = useState(false);
  const [terraform, setTerraform] = useState(false);
  const [cdk, setCdk] = useState(false);
  const [includeEnableAutomationLink, setIncludeEnableAutomationLink] = useState(false);

  // Filters
  // On create, both filters default to 'All' so the user explicitly sees that
  // nothing is excluded. They can deselect 'All' to narrow the scope. The
  // toggleMutualExclusiveAll helper ensures empty selection auto-reverts to 'All'.
  const [severityFilter, setSeverityFilter] = useState<SeverityFilter>(['All']);
  const [remediationStatusFilter, setRemediationStatusFilter] = useState<RemediationStatusFilter>(['All']);
  const [resourceFilterIds, setResourceFilterIds] = useState<string[]>([]);
  const [controlIds, setControlIds] = useState<string[]>(['All']);

  const [errors, setErrors] = useState<FormErrors>({});

  const isRemediationType = notificationType === 'remediation';
  // Mirrors the controlIds payload normalization: an empty selection or the 'All'
  // sentinel both mean "match every control", which changes how enforcement reaches
  // existing findings (write-time stamping + sync rather than targeted reconciliation).
  const isMatchAllControls = controlIds.length === 0 || controlIds.includes('All');
  const prevNotificationTypeRef = useRef(notificationType);

  useEffect(() => {
    const wasTypeChange = prevNotificationTypeRef.current !== notificationType;
    prevNotificationTypeRef.current = notificationType;
    if (!wasTypeChange) return; // skip mount — hydration effect handles initial state

    if (isRemediationType) {
      setIncludeRemediationDeadline(false);
      setEnforceDeadline(false);
    } else {
      // Remediation-status filter doesn't apply to finding-type notifications;
      // reset to ['All'] so a later type switch back to remediation surfaces the
      // default selection rather than an empty multiselect.
      setRemediationStatusFilter(['All']);
      setIncludeIaCSnippet(false);
    }
  }, [isRemediationType]);
  // Populate form from initialValues in edit mode
  useEffect(() => {
    if (!isEdit || !initialValues) return;
    setName(initialValues.name);
    setEnabled(initialValues.enabled);
    setNotificationType(initialValues.notificationType);
    // Empty/undefined saved filter means "all" semantically; surface it as 'All'
    // in the picker so the user can see the current scope at a glance.
    setSeverityFilter(toFilterState(initialValues.severityFilter));
    setRemediationStatusFilter(toFilterState(initialValues.remediationStatusFilter));
    setControlIds(toFilterState(initialValues.controlIds));
    setResourceFilterIds([...(initialValues.resourceFilterIds ?? [])]);

    // Delivery channels
    for (const ch of initialValues.deliveryChannels) {
      switch (ch.type) {
        case 'email': {
          setEmailEnabled(ch.enabled);
          const { recipientTypes, customEmails: emails } = extractEmailState([ch]);
          setRootAccountEmail(recipientTypes.includes('rootAccountEmail'));
          setSecurityContact(recipientTypes.includes('securityContact'));
          setOperationsContact(recipientTypes.includes('operationsContact'));
          setAccountOperators(recipientTypes.includes('accountOperators'));
          setCustomEmails(emails);
          break;
        }
        case 'slack':
          setSlackEnabled(ch.enabled);
          setSlackChannelId(ch.channelId ?? '');
          setSlackSecretArn(ch.credentialsSecretArn);
          break;
        case 'jira':
          setJiraEnabled(ch.enabled);
          setJiraEndpointUrl(ch.endpointUrl);
          setJiraProjectKey(ch.projectKey);
          setJiraIssueType(ch.issueType);
          setJiraSecretArn(ch.credentialsSecretArn);
          if (ch.customFieldMappings) setJiraCustomFields([...ch.customFieldMappings]);
          break;
        case 'servicenow':
          setServiceNowEnabled(ch.enabled);
          setServiceNowEndpointUrl(ch.endpointUrl);
          setServiceNowTableName(ch.tableName);
          setServiceNowSecretArn(ch.credentialsSecretArn);
          if (ch.customFieldMappings) setServiceNowCustomFields([...ch.customFieldMappings]);
          break;
        case 'sns':
          setSnsEnabled(ch.enabled);
          setSnsTopicArn(ch.topicArn);
          break;
      }
    }

    // Batch window
    setBatchEnabled(initialValues.batchWindow.enabled);
    if (initialValues.batchWindow.duration) setBatchDuration(String(initialValues.batchWindow.duration));
    if (initialValues.batchWindow.unit) setBatchUnit(initialValues.batchWindow.unit);

    // Batch export
    if (initialValues.batchExport?.presignedUrlExpirationHours) {
      setPresignedUrlExpirationHours(String(initialValues.batchExport.presignedUrlExpirationHours));
    }

    // Content options
    const co = initialValues.contentOptions;
    setIncludeManualRemediationLink(co.includeManualRemediationLink);
    setIncludeRemediationDeadline(co.includeRemediationDeadline);
    setEnforceDeadline(co.enforceDeadline ?? false);
    if (co.remediationDeadlineDays) setDeadlineDays(String(co.remediationDeadlineDays));
    setIncludeIaCSnippet(co.includeIaCSnippet);
    setCloudFormationYaml(co.iacFormats?.includes('cloudformation-yaml') ?? false);
    setCloudFormationJson(co.iacFormats?.includes('cloudformation-json') ?? false);
    setTerraform(co.iacFormats?.includes('terraform') ?? false);
    setCdk(co.iacFormats?.includes('cdk') ?? false);
    setIncludeEnableAutomationLink(co.includeEnableAutomationLink);

    setErrors({});
    setStep(0);
  }, [mode, initialValues]);

  const validateBasicInfo = (): FormErrors => {
    const e: FormErrors = {};
    if (!name.trim()) e.name = 'Configuration name is required.';
    return e;
  };

  const validateEmailChannel = (): Pick<FormErrors, 'recipients'> => {
    const hasRecipient =
      rootAccountEmail || securityContact || operationsContact || accountOperators || customEmails.length > 0;
    return hasRecipient ? {} : { recipients: 'Select at least one recipient type or enter a custom email address.' };
  };

  const validateSlackChannel = (): FormErrors => {
    const result = checkSlackChannelFields({ credentialsSecretArn: slackSecretArn, channelId: slackChannelId });
    const e: FormErrors = {};
    if (result.credentialsSecretArn) e.slack = result.credentialsSecretArn;
    if (result.channelId) e.slackChannelId = result.channelId;
    return e;
  };

  const validateJiraChannel = (): FormErrors => {
    const result = checkJiraChannelFields({
      credentialsSecretArn: jiraSecretArn,
      projectKey: jiraProjectKey,
      endpointUrl: jiraEndpointUrl,
      issueType: jiraIssueType,
      customFieldMappings: jiraCustomFields,
    });
    const e: FormErrors = {};
    if (result.credentialsSecretArn) e.jiraSecretArn = result.credentialsSecretArn;
    if (result.projectKey) e.jiraProjectKey = result.projectKey;
    if (result.endpointUrl) e.jira = result.endpointUrl;
    if (result.issueType) e.jiraIssueType = result.issueType;
    if (result.customFieldMappings) e.jiraCustomFields = result.customFieldMappings;
    return e;
  };

  const validateServiceNowChannel = (): FormErrors => {
    const result = checkServiceNowChannelFields({
      credentialsSecretArn: serviceNowSecretArn,
      endpointUrl: serviceNowEndpointUrl,
      tableName: serviceNowTableName,
      customFieldMappings: serviceNowCustomFields,
    });
    const e: FormErrors = {};
    if (result.credentialsSecretArn) e.serviceNowSecretArn = result.credentialsSecretArn;
    if (result.endpointUrl) e.serviceNowEndpointUrl = result.endpointUrl;
    if (result.tableName) e.serviceNowTableName = result.tableName;
    if (result.customFieldMappings) e.serviceNowCustomFields = result.customFieldMappings;
    return e;
  };

  const validateDeliveryChannels = (): FormErrors => {
    const e: FormErrors = {};
    const hasChannel = emailEnabled || slackEnabled || jiraEnabled || serviceNowEnabled || snsEnabled;
    if (!hasChannel) e.channels = 'At least one delivery channel must be enabled.';
    if (emailEnabled) Object.assign(e, validateEmailChannel());
    if (snsEnabled && !snsTopicArn.trim()) e.snsArn = 'SNS Topic ARN is required.';
    if (slackEnabled) Object.assign(e, validateSlackChannel());
    if (jiraEnabled) Object.assign(e, validateJiraChannel());
    if (serviceNowEnabled) Object.assign(e, validateServiceNowChannel());
    return e;
  };

  const parseIntInRange = (value: string, min: number, max: number): number | null => {
    const parsed = Number.parseInt(value, 10);
    if (!value || Number.isNaN(parsed) || parsed < min || parsed > max) return null;
    return parsed;
  };

  const batchDurationRanges: Record<BatchWindowUnit, [number, number]> = {
    Minutes: [5, 60],
    Hours: [1, 24],
    Days: [1, 365],
  };

  const validateBatching = (): FormErrors => {
    const e: FormErrors = {};
    if (batchEnabled) {
      const [min, max] = batchDurationRanges[batchUnit];
      if (parseIntInRange(batchDuration, min, max) === null)
        e.batchWindow = `Duration must be ${min}–${max} ${batchUnit.toLowerCase()}.`;
      if (parseIntInRange(presignedUrlExpirationHours, 1, 8) === null)
        e.presignedUrlExpiration = `Pre-signed URL expiration must be 1–8 hours.`;
    }
    return e;
  };

  const validateContentOptions = (): FormErrors => {
    const e: FormErrors = {};
    if (includeRemediationDeadline && parseIntInRange(deadlineDays, 1, 90) === null)
      e.deadlineDays = 'Deadline must be 1–90 days.';
    if (includeIaCSnippet && !cloudFormationYaml && !cloudFormationJson && !terraform && !cdk)
      e.iacFormats = 'Select at least one IaC format.';
    return e;
  };

  const validateStep = (stepIndex: number): FormErrors => {
    switch (stepIndex) {
      case 0:
        return validateBasicInfo();
      case 1:
        return validateDeliveryChannels();
      case 2:
        return validateBatching();
      case 3:
        return validateContentOptions();
      default:
        return {};
    }
  };

  const handleRemediationDeadlineChange = ({ detail }: { detail: { checked: boolean } }) => {
    setIncludeRemediationDeadline(detail.checked);
    if (!detail.checked) setEnforceDeadline(false);
  };

  /** Handle wizard navigation — validate current step before allowing forward movement. */
  const handleNavigate: NonNullable<WizardProps['onNavigate']> = ({ detail }): void => {
    const isMovingForward = detail.requestedStepIndex > step;
    if (isMovingForward) {
      const stepErrors = validateStep(step);
      if (Object.keys(stepErrors).length > 0) {
        setErrors(stepErrors);
        return;
      }
    }
    setErrors({});
    setStep(detail.requestedStepIndex);
  };

  /** Focus the wizard step that holds the first validation error. */
  const focusFirstErrorStep = (allErrors: FormErrors): void => {
    const hasDeliveryChannelErrors =
      allErrors.channels ||
      allErrors.recipients ||
      allErrors.snsArn ||
      allErrors.slack ||
      allErrors.slackChannelId ||
      allErrors.jira ||
      allErrors.jiraProjectKey ||
      allErrors.jiraIssueType ||
      allErrors.jiraSecretArn ||
      allErrors.jiraCustomFields ||
      allErrors.serviceNow ||
      allErrors.serviceNowEndpointUrl ||
      allErrors.serviceNowTableName ||
      allErrors.serviceNowSecretArn ||
      allErrors.serviceNowCustomFields;
    if (allErrors.name) setStep(0);
    else if (hasDeliveryChannelErrors) setStep(1);
    else if (allErrors.batchWindow || allErrors.presignedUrlExpiration) setStep(2);
    else if (allErrors.deadlineDays || allErrors.iacFormats) setStep(3);
  };

  /** Collect the selected email recipient types (plus custom addresses) for the email channel. */
  const buildEmailRecipients = (): { recipientType: RecipientType; emailAddresses?: string[] }[] => {
    const recipients: { recipientType: RecipientType; emailAddresses?: string[] }[] = [];
    if (rootAccountEmail) recipients.push({ recipientType: 'rootAccountEmail' });
    if (securityContact) recipients.push({ recipientType: 'securityContact' });
    if (operationsContact) recipients.push({ recipientType: 'operationsContact' });
    if (accountOperators) recipients.push({ recipientType: 'accountOperators' });
    if (customEmails.length > 0) recipients.push({ recipientType: 'custom', emailAddresses: customEmails });
    return recipients;
  };

  /** Assemble the enabled delivery channels into the payload shape. */
  const buildDeliveryChannels = (): DeliveryChannelConfig[] => {
    const deliveryChannels: DeliveryChannelConfig[] = [];
    if (emailEnabled) {
      deliveryChannels.push({ type: 'email', enabled: true, recipients: buildEmailRecipients() });
    }
    if (slackEnabled) {
      deliveryChannels.push({
        type: 'slack',
        enabled: true,
        channelId: slackChannelId.trim() || undefined,
        credentialsSecretArn: slackSecretArn.trim(),
      });
    }
    if (jiraEnabled) {
      deliveryChannels.push({
        type: 'jira',
        enabled: true,
        projectKey: jiraProjectKey.trim(),
        issueType: jiraIssueType.trim(),
        endpointUrl: jiraEndpointUrl.trim(),
        credentialsSecretArn: jiraSecretArn.trim(),
        customFieldMappings: jiraCustomFields.length > 0 ? jiraCustomFields : undefined,
      });
    }
    if (serviceNowEnabled) {
      deliveryChannels.push({
        type: 'servicenow',
        enabled: true,
        endpointUrl: serviceNowEndpointUrl.trim(),
        tableName: serviceNowTableName.trim(),
        credentialsSecretArn: serviceNowSecretArn.trim(),
        customFieldMappings: serviceNowCustomFields.length > 0 ? serviceNowCustomFields : undefined,
      });
    }
    if (snsEnabled) {
      deliveryChannels.push({ type: 'sns', enabled: true, topicArn: snsTopicArn.trim() });
    }
    return deliveryChannels;
  };

  /** Collect the selected IaC snippet formats. */
  const buildIacFormats = (): IaCFormat[] => {
    const iacFormats: IaCFormat[] = [];
    if (cloudFormationYaml) iacFormats.push('cloudformation-yaml');
    if (cloudFormationJson) iacFormats.push('cloudformation-json');
    if (terraform) iacFormats.push('terraform');
    if (cdk) iacFormats.push('cdk');
    return iacFormats;
  };

  /**
   * Build the full API request payload from current form state. 'All'/empty
   * selections are UI sentinels for "no filter": severity/status collapse to
   * undefined, controlIds to [] (the backend's "no restriction" representation).
   */
  const buildPayload = (): CreateNotificationConfigurationRequest => {
    const iacFormats = buildIacFormats();
    const [batchMin, batchMax] = batchDurationRanges[batchUnit];

    const batchWindowPayload: CreateNotificationConfigurationRequest['batchWindow'] = batchEnabled
      ? { enabled: true, duration: parseIntInRange(batchDuration, batchMin, batchMax) ?? batchMin, unit: batchUnit }
      : { enabled: false };
    const batchExportPayload = batchEnabled
      ? {
          batchExport: {
            enabled: true,
            presignedUrlExpirationHours: parseIntInRange(presignedUrlExpirationHours, 1, 8) ?? 1,
          },
        }
      : {};
    const deadlineDaysPayload = includeRemediationDeadline
      ? { remediationDeadlineDays: parseIntInRange(deadlineDays, 1, 90) ?? 7 }
      : {};

    const severityPayload = severityFilter.length === 0 || severityFilter.includes('All') ? undefined : severityFilter;
    const remediationStatusPayload =
      remediationStatusFilter.length === 0 || remediationStatusFilter.includes('All')
        ? undefined
        : remediationStatusFilter;
    const controlIdsPayload = controlIds.length === 0 || controlIds.includes('All') ? [] : controlIds;

    return {
      name: name.trim(),
      enabled,
      notificationType,
      severityFilter: severityPayload,
      remediationStatusFilter: remediationStatusPayload,
      controlIds: controlIdsPayload,
      resourceFilterIds,
      deliveryChannels: buildDeliveryChannels(),
      batchWindow: batchWindowPayload,
      ...batchExportPayload,
      contentOptions: {
        includeManualRemediationLink,
        includeRemediationDeadline,
        enforceDeadline,
        ...deadlineDaysPayload,
        includeIaCSnippet,
        ...(includeIaCSnippet && iacFormats.length > 0 ? { iacFormats } : {}),
        includeEnableAutomationLink,
      },
    };
  };

  /** Validate all steps, then build the API request payload and submit. */
  const handleSubmit = () => {
    const allErrors: FormErrors = [0, 1, 2, 3].reduce<FormErrors>((acc, i) => ({ ...acc, ...validateStep(i) }), {});
    setErrors(allErrors);
    if (Object.keys(allErrors).length > 0) {
      focusFirstErrorStep(allErrors);
      return;
    }

    onSubmit(buildPayload(), isEdit && initialValues ? initialValues.version : undefined);
  };

  const addEmail = () => {
    const email = emailInput.trim();
    if (email && !customEmails.includes(email)) {
      setCustomEmails([...customEmails, email]);
      setEmailInput('');
    }
  };

  /* ---- Wizard Steps ---- */

  const wizardSteps = [
    // Step 1: Basic Information
    {
      title: 'Basic information',
      isOptional: false,
      content: (
        <SpaceBetween direction="vertical" size="l">
          <FormField label="Status">
            <Toggle checked={enabled} onChange={({ detail }) => setEnabled(detail.checked)} disabled={isSubmitting}>
              {enabled ? 'Enabled' : 'Disabled'}
            </Toggle>
          </FormField>
          <FormField label="Configuration name" errorText={errors.name}>
            <Input
              value={name}
              onChange={({ detail }) => {
                setName(detail.value);
                if (errors.name) setErrors((p) => ({ ...p, name: undefined }));
              }}
              placeholder="e.g., Critical Findings - Security Team"
              disabled={isSubmitting}
            />
          </FormField>
          <FormField label="Notification type" description="Choose whether to notify on findings or remediations">
            <RadioGroup
              value={notificationType}
              onChange={({ detail }) => setNotificationType(detail.value as NotificationType)}
              items={[
                { value: 'finding', label: 'Finding', description: 'Notify when new security findings are detected' },
                { value: 'remediation', label: 'Remediation', description: 'Notify when remediations are executed' },
              ]}
            />
          </FormField>
        </SpaceBetween>
      ),
      errorText: errors.name,
    },

    // Step 2: Delivery Channels & Recipients
    {
      title: 'Delivery channels',
      isOptional: false,
      content: (
        <SpaceBetween direction="vertical" size="l">
          <Container header={<Header variant="h2">Delivery Channels</Header>}>
            <SpaceBetween direction="vertical" size="l">
              <FormField label="Channel types" errorText={errors.channels}>
                <SpaceBetween direction="vertical" size="xs">
                  <Checkbox
                    checked={emailEnabled}
                    onChange={({ detail }) => setEmailEnabled(detail.checked)}
                    disabled={isSubmitting}
                  >
                    Email
                  </Checkbox>
                  <Checkbox
                    checked={slackEnabled}
                    onChange={({ detail }) => setSlackEnabled(detail.checked)}
                    disabled={isSubmitting}
                  >
                    Slack
                  </Checkbox>
                  <Checkbox
                    checked={jiraEnabled}
                    onChange={({ detail }) => setJiraEnabled(detail.checked)}
                    disabled={isSubmitting}
                  >
                    JIRA
                  </Checkbox>
                  <Checkbox
                    checked={serviceNowEnabled}
                    onChange={({ detail }) => setServiceNowEnabled(detail.checked)}
                    disabled={isSubmitting}
                  >
                    ServiceNow
                  </Checkbox>
                  <Checkbox
                    checked={snsEnabled}
                    onChange={({ detail }) => setSnsEnabled(detail.checked)}
                    disabled={isSubmitting}
                  >
                    SNS Topic
                  </Checkbox>
                </SpaceBetween>
              </FormField>

              {emailEnabled && (
                <SpaceBetween direction="vertical" size="l">
                  <FormField label="Email recipient types" errorText={errors.recipients}>
                    <SpaceBetween direction="vertical" size="xs">
                      <Checkbox
                        checked={rootAccountEmail}
                        onChange={({ detail }) => setRootAccountEmail(detail.checked)}
                        disabled={pendingRecipientTypes.has('rootAccountEmail') || isSubmitting}
                      >
                        Primary account contact
                      </Checkbox>
                      <Checkbox
                        checked={securityContact}
                        onChange={({ detail }) => setSecurityContact(detail.checked)}
                        disabled={pendingRecipientTypes.has('securityContact') || isSubmitting}
                      >
                        Security contact
                      </Checkbox>
                      <Checkbox
                        checked={operationsContact}
                        onChange={({ detail }) => setOperationsContact(detail.checked)}
                        disabled={pendingRecipientTypes.has('operationsContact') || isSubmitting}
                      >
                        Operations contact
                      </Checkbox>
                      <Checkbox
                        checked={accountOperators}
                        onChange={({ detail }) => setAccountOperators(detail.checked)}
                        disabled={pendingRecipientTypes.has('accountOperators') || isSubmitting}
                      >
                        Account Operators
                      </Checkbox>
                    </SpaceBetween>
                  </FormField>
                  <FormField
                    label={
                      <SpaceBetween direction="horizontal" size="xs">
                        <span>Custom email addresses</span>
                        {pendingEmails.size > 0 && (
                          <Popover
                            dismissButton={false}
                            position="top"
                            size="small"
                            triggerType="custom"
                            content="Emails with pending confirmations cannot be removed. Accept the confirmation or use Resend in the Email subscriptions panel."
                          >
                            <Box color="text-status-info" display="inline">
                              <Icon name="status-info" />
                            </Box>
                          </Popover>
                        )}
                      </SpaceBetween>
                    }
                    description="Press Enter to add."
                  >
                    <SpaceBetween direction="vertical" size="xs">
                      <Input
                        value={emailInput}
                        onChange={({ detail }) => setEmailInput(detail.value)}
                        onKeyDown={(e) => {
                          if (e.detail.key === 'Enter' || e.detail.key === ',') {
                            e.preventDefault();
                            addEmail();
                          }
                        }}
                        onBlur={addEmail}
                        placeholder="user@example.com"
                        disabled={isSubmitting}
                      />
                      {customEmails.length > 0 && (
                        <TokenGroup
                          items={customEmails.map((e) => ({
                            label: e,
                            dismissLabel: `Remove ${e}`,
                            disabled: pendingEmails.has(e),
                          }))}
                          onDismiss={({ detail }) => {
                            const email = customEmails[detail.itemIndex];
                            if (!pendingEmails.has(email)) {
                              setCustomEmails(customEmails.filter((_, i) => i !== detail.itemIndex));
                            }
                          }}
                        />
                      )}
                    </SpaceBetween>
                  </FormField>
                </SpaceBetween>
              )}

              {snsEnabled && (
                <FormField label="SNS Topic ARN" errorText={errors.snsArn}>
                  <Input
                    value={snsTopicArn}
                    onChange={({ detail }) => setSnsTopicArn(detail.value)}
                    placeholder="arn:aws:sns:us-east-1:123456789012:my-topic"
                    disabled={isSubmitting}
                  />
                </FormField>
              )}

              {(slackEnabled || jiraEnabled || serviceNowEnabled) && (
                <Alert type="warning" header="Required Secret format">
                  Each channel expects a specific JSON structure stored in AWS Secrets Manager:
                  <ul>
                    <li>
                      <strong>Slack</strong> — A JSON object:{' '}
                      <code>{`{"webhookUrl": "https://hooks.slack.com/services/T.../B.../..."}`}</code> (alternatively,
                      a plain string containing the webhook URL)
                    </li>
                    <li>
                      <strong>JIRA</strong> — A JSON object:{' '}
                      <code>{`{"username": "your-email@example.com", "apiToken": "your-api-token"}`}</code>
                    </li>
                    <li>
                      <strong>ServiceNow</strong> — A JSON object:{' '}
                      <code>{`{"username": "your-username", "password": "your-password"}`}</code>
                    </li>
                  </ul>
                  Notifications will fail at delivery time if the secret does not match the expected structure.
                </Alert>
              )}

              {slackEnabled && (
                <SpaceBetween direction="vertical" size="l">
                  <FormField
                    label="Slack credentials Secret ARN"
                    errorText={errors.slack}
                    description="Secrets Manager ARN containing the Slack webhook URL"
                    constraintText={`Secret name must start with "${NOTIFICATION_CHANNEL_SECRET_PREFIX}"`}
                  >
                    <Input
                      value={slackSecretArn}
                      onChange={({ detail }) => setSlackSecretArn(detail.value)}
                      placeholder={`arn:aws:secretsmanager:us-east-1:123456789012:secret:${NOTIFICATION_CHANNEL_SECRET_PREFIX}slack-webhook`}
                      disabled={isSubmitting}
                    />
                  </FormField>
                  <FormField
                    label="Slack channel ID"
                    description="Channel ID for posting notifications"
                    constraintText="Format: C followed by 8 or more uppercase alphanumeric characters (e.g. C0123456789)"
                    errorText={errors.slackChannelId}
                  >
                    <Input
                      value={slackChannelId}
                      onChange={({ detail }) => setSlackChannelId(detail.value)}
                      placeholder="C0123456789"
                      disabled={isSubmitting}
                    />
                  </FormField>
                </SpaceBetween>
              )}

              {jiraEnabled && (
                <SpaceBetween direction="vertical" size="l">
                  <FormField label="JIRA endpoint URL" errorText={errors.jira}>
                    <Input
                      value={jiraEndpointUrl}
                      onChange={({ detail }) => setJiraEndpointUrl(detail.value)}
                      placeholder="https://your-domain.atlassian.net"
                      disabled={isSubmitting}
                    />
                  </FormField>
                  <FormField
                    label="Project key"
                    constraintText="2–10 characters: starts with an uppercase letter, followed by uppercase letters, digits, or underscores"
                    errorText={errors.jiraProjectKey}
                  >
                    <Input
                      value={jiraProjectKey}
                      onChange={({ detail }) => setJiraProjectKey(detail.value)}
                      placeholder="SEC"
                      disabled={isSubmitting}
                    />
                  </FormField>
                  <FormField label="Issue type" errorText={errors.jiraIssueType}>
                    <Input
                      value={jiraIssueType}
                      onChange={({ detail }) => setJiraIssueType(detail.value)}
                      placeholder="Bug"
                      disabled={isSubmitting}
                    />
                  </FormField>
                  <FormField
                    label="Credentials Secret ARN"
                    description="Secrets Manager ARN containing JIRA API token"
                    constraintText={`Secret name must start with "${NOTIFICATION_CHANNEL_SECRET_PREFIX}"`}
                    errorText={errors.jiraSecretArn}
                  >
                    <Input
                      value={jiraSecretArn}
                      onChange={({ detail }) => setJiraSecretArn(detail.value)}
                      placeholder={`arn:aws:secretsmanager:us-east-1:123456789012:secret:${NOTIFICATION_CHANNEL_SECRET_PREFIX}jira-token`}
                      disabled={isSubmitting}
                    />
                  </FormField>
                  <FormField
                    label="Custom field mappings"
                    description="Define extra key-value pairs to include in JIRA tickets. Use template variables to dynamically insert finding details at send time: ${FINDING_ID}, ${CONTROL_ID}, ${SEVERITY}, ${ACCOUNT_ID}, ${REGION}, ${RESOURCE_ARN}, ${CONFIG_NAME}. Max 20 entries."
                    errorText={errors.jiraCustomFields}
                  >
                    <SpaceBetween direction="vertical" size="xs">
                      {jiraCustomFields.map((f, i) => (
                        <SpaceBetween key={i} direction="horizontal" size="xs">
                          <Input
                            value={f.key}
                            onChange={({ detail }) => {
                              const c = [...jiraCustomFields];
                              c[i] = { ...c[i], key: detail.value };
                              setJiraCustomFields(c);
                            }}
                            placeholder="Field key"
                            disabled={isSubmitting}
                          />
                          <Input
                            value={f.value}
                            onChange={({ detail }) => {
                              const c = [...jiraCustomFields];
                              c[i] = { ...c[i], value: detail.value };
                              setJiraCustomFields(c);
                            }}
                            placeholder="Field value"
                            disabled={isSubmitting}
                          />
                          <Button
                            onClick={() => setJiraCustomFields(jiraCustomFields.filter((_, j) => j !== i))}
                            disabled={isSubmitting}
                            variant="icon"
                            iconName="remove"
                            ariaLabel="Remove field"
                          />
                        </SpaceBetween>
                      ))}
                      {jiraCustomFields.length < 20 && (
                        <Button
                          onClick={() => setJiraCustomFields([...jiraCustomFields, { key: '', value: '' }])}
                          disabled={isSubmitting}
                          iconName="add-plus"
                          variant="normal"
                        >
                          Add field
                        </Button>
                      )}
                    </SpaceBetween>
                  </FormField>
                </SpaceBetween>
              )}

              {serviceNowEnabled && (
                <SpaceBetween direction="vertical" size="l">
                  <FormField
                    label="ServiceNow endpoint URL"
                    errorText={errors.serviceNowEndpointUrl || errors.serviceNow}
                    constraintText="Must be a valid HTTPS URL (e.g., https://company.service-now.com)"
                  >
                    <Input
                      value={serviceNowEndpointUrl}
                      onChange={({ detail }) => setServiceNowEndpointUrl(detail.value)}
                      placeholder="https://your-instance.service-now.com"
                      disabled={isSubmitting}
                    />
                  </FormField>
                  <FormField
                    label="Table name"
                    errorText={errors.serviceNowTableName}
                    constraintText="Starts with a lowercase letter, followed by lowercase letters, digits, or underscores (1–80 characters total)"
                  >
                    <Input
                      value={serviceNowTableName}
                      onChange={({ detail }) => setServiceNowTableName(detail.value)}
                      placeholder="incident"
                      disabled={isSubmitting}
                    />
                  </FormField>
                  <FormField
                    label="Credentials Secret ARN"
                    description="Secrets Manager ARN containing ServiceNow credentials"
                    constraintText={`Secret name must start with "${NOTIFICATION_CHANNEL_SECRET_PREFIX}"`}
                    errorText={errors.serviceNowSecretArn}
                  >
                    <Input
                      value={serviceNowSecretArn}
                      onChange={({ detail }) => setServiceNowSecretArn(detail.value)}
                      placeholder={`arn:aws:secretsmanager:us-east-1:123456789012:secret:${NOTIFICATION_CHANNEL_SECRET_PREFIX}servicenow-credentials`}
                      disabled={isSubmitting}
                    />
                  </FormField>
                  <FormField
                    label="Custom field mappings"
                    description="Define extra key-value pairs to include in ServiceNow records. Use template variables to dynamically insert finding details at send time: ${FINDING_ID}, ${CONTROL_ID}, ${SEVERITY}, ${ACCOUNT_ID}, ${REGION}, ${RESOURCE_ARN}, ${CONFIG_NAME}. Max 20 entries."
                    errorText={errors.serviceNowCustomFields}
                  >
                    <SpaceBetween direction="vertical" size="xs">
                      {serviceNowCustomFields.map((f, i) => (
                        <SpaceBetween key={i} direction="horizontal" size="xs">
                          <Input
                            value={f.key}
                            onChange={({ detail }) => {
                              const c = [...serviceNowCustomFields];
                              c[i] = { ...c[i], key: detail.value };
                              setServiceNowCustomFields(c);
                            }}
                            placeholder="Field key"
                            disabled={isSubmitting}
                          />
                          <Input
                            value={f.value}
                            onChange={({ detail }) => {
                              const c = [...serviceNowCustomFields];
                              c[i] = { ...c[i], value: detail.value };
                              setServiceNowCustomFields(c);
                            }}
                            placeholder="Field value"
                            disabled={isSubmitting}
                          />
                          <Button
                            onClick={() => setServiceNowCustomFields(serviceNowCustomFields.filter((_, j) => j !== i))}
                            disabled={isSubmitting}
                            variant="icon"
                            iconName="remove"
                            ariaLabel="Remove field"
                          />
                        </SpaceBetween>
                      ))}
                      {serviceNowCustomFields.length < 20 && (
                        <Button
                          onClick={() => setServiceNowCustomFields([...serviceNowCustomFields, { key: '', value: '' }])}
                          disabled={isSubmitting}
                          iconName="add-plus"
                          variant="normal"
                        >
                          Add field
                        </Button>
                      )}
                    </SpaceBetween>
                  </FormField>
                </SpaceBetween>
              )}
            </SpaceBetween>
          </Container>
        </SpaceBetween>
      ),
      errorText:
        errors.channels ||
        errors.recipients ||
        errors.snsArn ||
        errors.slack ||
        errors.slackChannelId ||
        errors.jira ||
        errors.jiraProjectKey ||
        errors.jiraIssueType ||
        errors.jiraSecretArn ||
        errors.jiraCustomFields ||
        errors.serviceNow ||
        errors.serviceNowEndpointUrl ||
        errors.serviceNowTableName ||
        errors.serviceNowSecretArn ||
        errors.serviceNowCustomFields,
    },

    // Step 3: Batching
    {
      title: 'Notification batching',
      isOptional: true,
      content: (
        <SpaceBetween direction="vertical" size="l">
          <Container header={<Header variant="h2">Batching Configuration</Header>}>
            <SpaceBetween direction="vertical" size="l">
              <FormField
                label="Enable batching"
                description="Collect findings over a time window and send one summary notification instead of individual alerts. For example, setting 30 minutes means all findings detected within each 30-minute window are grouped into a single notification."
              >
                <Toggle
                  checked={batchEnabled}
                  onChange={({ detail }) => setBatchEnabled(detail.checked)}
                  disabled={isSubmitting}
                >
                  {batchEnabled ? 'Batching enabled' : 'Batching disabled'}
                </Toggle>
              </FormField>
              {batchEnabled && (
                <SpaceBetween direction="horizontal" size="l">
                  <FormField label="Batch every" constraintText="Minutes: 5–60, Hours: 1–24, Days: 1–365">
                    <Input
                      value={batchDuration}
                      onChange={({ detail }) => setBatchDuration(detail.value)}
                      type="number"
                      inputMode="numeric"
                      disabled={isSubmitting}
                    />
                  </FormField>
                  <FormField label="Unit">
                    <Select
                      selectedOption={{ label: batchUnit, value: batchUnit }}
                      onChange={({ detail }) => setBatchUnit(detail.selectedOption.value as BatchWindowUnit)}
                      options={[
                        { label: 'Minutes', value: 'Minutes' },
                        { label: 'Hours', value: 'Hours' },
                        { label: 'Days', value: 'Days' },
                      ]}
                      disabled={isSubmitting}
                    />
                  </FormField>
                </SpaceBetween>
              )}
              {batchEnabled && (
                <>
                  <Alert type="info">
                    CSV export download links expire after the configured duration (1–8 hours). Recipients must download
                    the file before the link expires.
                  </Alert>
                  <FormField
                    label="Pre-signed URL expiration (hours)"
                    constraintText="1–8 hours (maximum allowed)"
                    errorText={errors.presignedUrlExpiration}
                  >
                    <Input
                      value={presignedUrlExpirationHours}
                      onChange={({ detail }) => setPresignedUrlExpirationHours(detail.value)}
                      type="number"
                      inputMode="numeric"
                      disabled={isSubmitting}
                    />
                  </FormField>
                </>
              )}
            </SpaceBetween>
          </Container>
        </SpaceBetween>
      ),
      errorText: errors.batchWindow || errors.presignedUrlExpiration,
    },

    // Step 4: Content Options
    {
      title: 'Notification content',
      isOptional: true,
      content: (
        <Container header={<Header variant="h2">Content Options</Header>}>
          <SpaceBetween direction="vertical" size="l">
            <FormField
              label="Deep link"
              constraintText={
                isRemediationType
                  ? 'Includes a link to the remediation history page.'
                  : 'Includes a link to manually remediate the finding.'
              }
            >
              <Checkbox
                checked={includeManualRemediationLink}
                onChange={({ detail }) => setIncludeManualRemediationLink(detail.checked)}
                disabled={isSubmitting}
              >
                {isRemediationType ? 'Include history link' : 'Include remediation link'}
              </Checkbox>
            </FormField>
            <FormField label="Enable control link">
              <Checkbox
                checked={includeEnableAutomationLink}
                onChange={({ detail }) => setIncludeEnableAutomationLink(detail.checked)}
                disabled={isSubmitting}
              >
                Include link to enable/disable automated remediation
              </Checkbox>
            </FormField>
            {!isRemediationType && (
              <FormField label="Remediation deadline" errorText={errors.deadlineDays}>
                <SpaceBetween direction="vertical" size="xs">
                  <Checkbox
                    checked={includeRemediationDeadline}
                    onChange={handleRemediationDeadlineChange}
                    disabled={isSubmitting}
                  >
                    Include remediation deadline
                  </Checkbox>
                  {includeRemediationDeadline && (
                    <>
                      <FormField label="Deadline (days)" constraintText="1–90 days">
                        <Input
                          value={deadlineDays}
                          onChange={({ detail }) => setDeadlineDays(detail.value)}
                          type="number"
                          inputMode="numeric"
                          placeholder="7"
                          disabled={isSubmitting}
                        />
                      </FormField>
                      <FormField
                        label="Deadline enforcement"
                        description="Automatically triggers remediation for findings that are not resolved before the deadline. Applies to findings matching this configuration's control, severity, and resource filters. Findings are never auto-remediated less than 24 hours after they become eligible for enforcement."
                      >
                        <Checkbox
                          checked={enforceDeadline}
                          onChange={({ detail }) => setEnforceDeadline(detail.checked)}
                          disabled={isSubmitting}
                        >
                          Auto-remediate overdue findings
                        </Checkbox>
                      </FormField>
                      {enforceDeadline && isMatchAllControls && (
                        <Alert type="info" data-testid="match-all-enforcement-info">
                          <SpaceBetween direction="vertical" size="xs">
                            <span>
                              Enforcement applies immediately to new findings as they arrive. Findings that already
                              exist may take up to one synchronization cycle to be enforced.
                            </span>
                            <span>
                              Disabling enforcement or shortening the deadline takes effect on existing findings during
                              the next processing cycle.
                            </span>
                          </SpaceBetween>
                        </Alert>
                      )}
                    </>
                  )}
                </SpaceBetween>
              </FormField>
            )}
            {isRemediationType && (
              <FormField label="Infrastructure-as-Code snippets" errorText={errors.iacFormats}>
                <SpaceBetween direction="vertical" size="xs">
                  <Alert type="info">
                    IaC remediation code is only included for findings that were <b>successfully remediated</b>.
                    Notifications for in-progress, failed, or rolled-back remediations will not contain IaC snippets
                    download links.
                  </Alert>
                  <Checkbox
                    checked={includeIaCSnippet}
                    onChange={({ detail }) => setIncludeIaCSnippet(detail.checked)}
                    disabled={isSubmitting}
                  >
                    Include IaC remediation code
                  </Checkbox>
                  {includeIaCSnippet && (
                    <Box margin={{ left: 'l' }}>
                      <SpaceBetween direction="vertical" size="xs">
                        <Checkbox
                          checked={cloudFormationYaml}
                          onChange={({ detail }) => setCloudFormationYaml(detail.checked)}
                          disabled={isSubmitting}
                        >
                          CloudFormation (YAML)
                        </Checkbox>
                        <Checkbox
                          checked={cloudFormationJson}
                          onChange={({ detail }) => setCloudFormationJson(detail.checked)}
                          disabled={isSubmitting}
                        >
                          CloudFormation (JSON)
                        </Checkbox>
                        <Checkbox
                          checked={terraform}
                          onChange={({ detail }) => setTerraform(detail.checked)}
                          disabled={isSubmitting}
                        >
                          Terraform
                        </Checkbox>
                        <Checkbox
                          checked={cdk}
                          onChange={({ detail }) => setCdk(detail.checked)}
                          disabled={isSubmitting}
                        >
                          CDK
                        </Checkbox>
                      </SpaceBetween>
                    </Box>
                  )}
                </SpaceBetween>
              </FormField>
            )}
          </SpaceBetween>
        </Container>
      ),
      errorText: errors.deadlineDays || errors.iacFormats,
    },

    // Step 5: Filters & Controls
    {
      title: 'Notification filters',
      isOptional: true,
      content: (
        <SpaceBetween direction="vertical" size="l">
          <Container header={<Header variant="h2">Severity Filtering</Header>}>
            <FormField
              label="Severity levels"
              description="Select which severity levels trigger notifications, or choose All"
            >
              <Multiselect
                selectedOptions={severityFilter.map((s) => ({ label: s, value: s }))}
                onChange={({ detail }) => {
                  const selected = detail.selectedOptions.map((o) => o.value || '') as SeverityFilter;
                  setSeverityFilter(toggleMutualExclusiveAll(selected, severityFilter) as SeverityFilter);
                }}
                options={[
                  { label: 'All', value: 'All' },
                  { label: 'Critical', value: 'Critical' },
                  { label: 'High', value: 'High' },
                  { label: 'Medium', value: 'Medium' },
                  { label: 'Low', value: 'Low' },
                  { label: 'Informational', value: 'Informational' },
                ]}
                placeholder="Select severity levels"
                disabled={isSubmitting}
              />
            </FormField>
          </Container>

          {isRemediationType && (
            <Container header={<Header variant="h2">Remediation Status Filtering</Header>}>
              <FormField
                label="Remediation statuses"
                description="Select which remediation outcomes trigger notifications, or choose All"
              >
                <Multiselect
                  selectedOptions={remediationStatusFilter.map((s) => ({ label: s, value: s }))}
                  onChange={({ detail }) => {
                    const selected = detail.selectedOptions.map((o) => o.value || '') as RemediationStatusFilter;
                    setRemediationStatusFilter(
                      toggleMutualExclusiveAll(selected, remediationStatusFilter) as RemediationStatusFilter,
                    );
                  }}
                  options={REMEDIATION_STATUS_FILTER_OPTIONS.map((s) => ({ label: s, value: s }))}
                  placeholder="Select remediation statuses"
                  disabled={isSubmitting}
                />
              </FormField>
            </Container>
          )}

          <Container header={<Header variant="h2">Resource Filtering</Header>}>
            <FormField
              label="Resource filters"
              description="Scope notifications to specific accounts, OUs, or resources"
            >
              <Multiselect
                selectedOptions={resourceFilterIds.map((fId) => {
                  const f = resourceFilters.find((rf) => rf.filterId === fId);
                  return { label: f?.name || fId, value: fId };
                })}
                onChange={({ detail }) => setResourceFilterIds(detail.selectedOptions.map((o) => o.value || ''))}
                options={resourceFilters.map((f) => ({
                  label: f.name,
                  value: f.filterId,
                  description:
                    [
                      f.accountIds.length > 0 ? `${f.accountIds.length} account(s)` : null,
                      f.organizationalUnits.length > 0 ? `${f.organizationalUnits.length} OU(s)` : null,
                      f.tags.length > 0 ? `${f.tags.length} tag(s)` : null,
                      f.arnPatterns.length > 0 ? `${f.arnPatterns.length} ARN pattern(s)` : null,
                    ]
                      .filter(Boolean)
                      .join(', ') || 'No criteria',
                }))}
                placeholder="Select resource filters"
                filteringType="auto"
                tokenLimit={3}
                disabled={isSubmitting}
              />
            </FormField>
          </Container>

          <Container header={<Header variant="h2">Security Control Filtering</Header>}>
            <FormField
              label="Security controls"
              description="Select which security controls trigger notifications, or choose All"
            >
              <Multiselect
                selectedOptions={controlIds.map((cId) => {
                  if (cId === 'All') return { label: 'All', value: 'All' };
                  const c = controls.find((ctrl) => ctrl.controlId === cId);
                  return { label: c?.controlId || cId, value: cId };
                })}
                onChange={({ detail }) => {
                  const selected = detail.selectedOptions.map((o) => o.value || '');
                  setControlIds(toggleMutualExclusiveAll(selected, controlIds));
                }}
                options={[
                  { label: 'All', value: 'All' },
                  ...controls.map((c) => ({ label: c.controlId, value: c.controlId })),
                ]}
                placeholder="Select security controls"
                filteringType="auto"
                tokenLimit={3}
                disabled={isSubmitting}
              />
            </FormField>
          </Container>
        </SpaceBetween>
      ),
    },
  ];

  const editSaveAction = isEdit ? (
    <Button variant="primary" onClick={handleSubmit} loading={isSubmitting} disabled={isSubmitting}>
      Save changes
    </Button>
  ) : null;

  return (
    <Modal
      visible
      onDismiss={onCancel}
      size="max"
      header={isEdit ? 'Edit notification configuration' : 'Create notification configuration'}
    >
      <Wizard
        key={isEdit ? (initialValues?.configId ?? 'edit') : 'create'}
        i18nStrings={{
          stepNumberLabel: (n) => `Step ${n}`,
          collapsedStepsLabel: (n, total) => `Step ${n} of ${total}`,
          skipToButtonLabel: (s) => `Skip to ${s.title}`,
          navigationAriaLabel: 'Notification configuration wizard steps',
          cancelButton: 'Cancel',
          previousButton: 'Previous',
          nextButton: 'Next',
          submitButton: isEdit ? 'Save changes' : 'Create configuration',
          optional: isEdit ? '' : 'optional',
        }}
        onNavigate={handleNavigate}
        onCancel={onCancel}
        onSubmit={handleSubmit}
        activeStepIndex={step}
        steps={wizardSteps}
        secondaryActions={step === wizardSteps.length - 1 ? undefined : editSaveAction}
        isLoadingNextStep={isSubmitting}
        allowSkipTo
      />
    </Modal>
  );
}
