// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { z } from 'zod';
import { FindingIdSchema } from './finding';
import { RemediationStatusEnum, remediationStatus } from './schemaTypes';

// --- Enums & primitives ---

export type ConfigId = string & { readonly __brand: 'ConfigId' };
export const ConfigIdSchema = z.uuid().transform((val) => val as ConfigId);

export const DeliveryChannelTypeSchema = z.enum(['email', 'slack', 'jira', 'servicenow', 'sns']);

export const NotificationTypeSchema = z.enum(['finding', 'remediation']);

export const SeverityLevelSchema = z.enum(['Critical', 'High', 'Medium', 'Low', 'Informational']);

export const SeverityFilterSchema = z.array(z.enum(['Critical', 'High', 'Medium', 'Low', 'Informational', 'All']));

export const RemediationStatusFilterValueSchema = z.enum([
  'Success',
  'In Progress',
  'Failed',
  'Rollback Success',
  'Rollback In Progress',
  'Rollback Failed',
  'Not Started',
  'All',
]);
export const REMEDIATION_STATUS_FILTER_OPTIONS = RemediationStatusFilterValueSchema.options;
export const RemediationStatusFilterSchema = z.array(RemediationStatusFilterValueSchema);

/**
 * Display filter values (excluding the 'All' sentinel) offered to users in the
 * findings/history status filters. Single source of truth so the picker can't
 * drift from the schema.
 */
export const REMEDIATION_STATUS_DISPLAY_OPTIONS = REMEDIATION_STATUS_FILTER_OPTIONS.filter(
  (value): value is Exclude<RemediationStatusFilterValue, 'All'> => value !== 'All',
);

/**
 * Maps a display filter value back to the canonical raw status persisted on the
 * findings table (the value `mapRemediationStatus` writes). The findings table
 * filters on this raw value, so the UI must denormalize before querying. This is
 * the inverse of `normalizeRemediationStatus` for the canonical raw value of
 * each display label.
 *
 * Returns a canonical `remediationStatus` enum value. The lookup covers every
 * non-`All` display option; for any other input the fallback derives a raw
 * value and validates it against the enum, returning `FAILED` if it is not a
 * known status so an un-validated string can never reach a DynamoDB filter.
 */
export function denormalizeRemediationStatus(display: string): remediationStatus {
  const map: Record<Exclude<RemediationStatusFilterValue, 'All'>, remediationStatus> = {
    Success: 'SUCCESS',
    Failed: 'FAILED',
    'Not Started': 'NOT_STARTED',
    'In Progress': 'IN_PROGRESS',
    'Rollback Success': 'ROLLBACK_SUCCESS',
    'Rollback In Progress': 'ROLLBACK_IN_PROGRESS',
    'Rollback Failed': 'ROLLBACK_FAILED',
  };
  if (display in map) {
    return map[display as Exclude<RemediationStatusFilterValue, 'All'>];
  }
  const fallback = display.toUpperCase().replace(/\s+/g, '_');
  const parsed = RemediationStatusEnum.safeParse(fallback);
  if (!parsed.success) {
    // An unrecognized label means the caller passed something outside the known
    // display options. Warn so the misuse is observable instead of silently
    // applying a FAILED filter that the caller did not intend.
    console.warn(`denormalizeRemediationStatus: unknown display value "${display}", defaulting to FAILED`);
    return 'FAILED';
  }
  return parsed.data;
}

/** Normalized remediation status values used for display, filtering, and IaC eligibility. */
export type NormalizedRemediationStatus = Exclude<RemediationStatusFilterValue, 'All'>;

/**
 * Normalize a raw remediation status (e.g. "SUCCESS", "ASSUME_ROLE_FAILURE",
 * "TIMEDOUT", "QUEUED") into one of the display values used by the
 * RemediationStatusFilter enum. This is the single source of truth shared
 * between the dispatcher (filter matching) and the UI (display + filter
 * picker), so a status string never gets two different interpretations
 * across services.
 *
 * Mapping rules (mirrors map_remediation_status in Python):
 * - SUCCESS                            -> 'Success'
 * - QUEUED | RUNNING | IN_PROGRESS     -> 'In Progress'
 * - ROLLBACK_IN_PROGRESS               -> 'Rollback In Progress'
 * - ROLLBACK_SUCCESS                   -> 'Rollback Success'
 * - ROLLBACK_FAILED                    -> 'Rollback Failed'
 * - NOT_STARTED                        -> 'Not Started'
 * - everything else (incl. failures)   -> 'Failed'
 *
 * Empty/undefined input is treated as 'Failed' to match dispatcher semantics
 * (a missing status on a remediation event is a failure mode, not success).
 *
 * Returns NormalizedRemediationStatus (never 'All') so call sites keep the
 * compile-time guarantee that the 'All' sentinel cannot leak into normalized
 * values used for filter matching or display.
 */
export function normalizeRemediationStatus(raw: string | undefined | null): NormalizedRemediationStatus {
  if (!raw) return 'Failed';
  const upper = raw.toUpperCase();
  if (upper === 'SUCCESS') return 'Success';
  if (upper === 'QUEUED' || upper === 'RUNNING' || upper === 'IN_PROGRESS') return 'In Progress';
  if (upper === 'ROLLBACK_IN_PROGRESS') return 'Rollback In Progress';
  if (upper === 'ROLLBACK_SUCCESS') return 'Rollback Success';
  if (upper === 'ROLLBACK_FAILED') return 'Rollback Failed';
  if (upper === 'NOT_STARTED') return 'Not Started';
  return 'Failed';
}

export const BatchWindowUnitSchema = z.enum(['Minutes', 'Hours', 'Days']);

export const RecipientTypeSchema = z.enum([
  'rootAccountEmail',
  'securityContact',
  'operationsContact',
  'accountOperators',
  'custom',
]);

export const BatchStatusSchema = z.enum(['open', 'processing', 'dispatched']);

export const EmailSubscriptionStatusValueSchema = z.enum(['PendingConfirmation', 'Confirmed']);

export const EmailSubscriptionStatusSchema = z.object({
  email: z.string().email(),
  subscriptionArn: z.string(),
  status: EmailSubscriptionStatusValueSchema,
});

export type EmailSubscriptionStatusValue = z.infer<typeof EmailSubscriptionStatusValueSchema>;
export type EmailSubscriptionStatus = z.infer<typeof EmailSubscriptionStatusSchema>;

// --- Delivery channel configs ---

export const EmailChannelConfigSchema = z.object({
  type: z.literal('email'),
  enabled: z.boolean(),
  recipients: z.array(
    z.object({
      recipientType: RecipientTypeSchema,
      emailAddresses: z.array(z.string().email()).optional(),
    }),
  ),
});

export const NOTIFICATION_CHANNEL_SECRET_PREFIX = 'asr/notifications/';

export const secretsManagerArnSchema = z
  .string()
  .regex(/^arn:[^:]+:secretsmanager:[^:]+:\d{12}:secret:.+$/, 'Must be a valid Secrets Manager ARN');

export const notificationChannelSecretArnSchema = z
  .string()
  .regex(
    new RegExp(String.raw`^arn:[^:]+:secretsmanager:[^:]+:\d{12}:secret:${NOTIFICATION_CHANNEL_SECRET_PREFIX}.+$`),
    `Secret name must start with "${NOTIFICATION_CHANNEL_SECRET_PREFIX}"`,
  );

export const SLACK_CHANNEL_ID_PATTERN = /^C[0-9A-Z]{8,}$/;

export const JIRA_PROJECT_KEY_PATTERN = /^[A-Z][A-Z0-9_]{1,9}$/;

export const MAX_JIRA_INSTANCE_URL_LENGTH = 2048;
export const MAX_JIRA_CUSTOM_FIELDS = 20;
export const MAX_JIRA_CUSTOM_FIELD_KEY_LENGTH = 80;
export const MAX_JIRA_CUSTOM_FIELD_VALUE_LENGTH = 1024;
export const JIRA_CUSTOM_FIELD_KEY_PATTERN = /^customfield_\d+$/;

export const MAX_SERVICENOW_INSTANCE_URL_LENGTH = 2048;
export const MAX_SERVICENOW_CUSTOM_FIELDS = 20;
export const MAX_SERVICENOW_CUSTOM_FIELD_KEY_LENGTH = 64;
export const MAX_SERVICENOW_CUSTOM_FIELD_VALUE_LENGTH = 256;
export const SERVICENOW_TABLE_NAME_PATTERN = /^[a-z][a-z0-9_]{0,79}$/;

export const RESERVED_SERVICENOW_FIELD_KEYS = new Set([
  'short_description',
  'description',
  'urgency',
  'impact',
  'work_notes',
]);

interface InstanceUrlValidationOptions {
  readonly label: string;
  readonly maxLength: number;
}

/**
 * Checks that an instance URL is well-formed and safe to use as an API base URL.
 * Returns an error message string if invalid, or null if valid.
 */
function checkInstanceUrl(url: string, options: InstanceUrlValidationOptions): string | null {
  const { label, maxLength } = options;

  if (!url) {
    return `${label} instance URL is required.`;
  }

  if (url.length > maxLength) {
    return `${label} instance URL must not exceed ${maxLength.toLocaleString()} characters.`;
  }

  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    return `${label} instance URL is not a valid URL.`;
  }

  if (parsed.protocol !== 'https:') {
    return `${label} instance URL must use HTTPS protocol.`;
  }

  if (parsed.search) {
    return `${label} instance URL must not contain query parameters.`;
  }

  if (parsed.hash) {
    return `${label} instance URL must not contain a fragment.`;
  }

  if (url.endsWith('/')) {
    return `${label} instance URL must not end with a trailing slash.`;
  }

  return null;
}

/**
 * Checks that a JIRA instance URL is well-formed and safe to use as an API base URL.
 * Returns an error message string if invalid, or null if valid.
 */
export function checkJiraInstanceUrl(url: string): string | null {
  return checkInstanceUrl(url, { label: 'JIRA', maxLength: MAX_JIRA_INSTANCE_URL_LENGTH });
}

/**
 * Checks that a ServiceNow instance URL is well-formed and safe to use as an API base URL.
 * Returns an error message string if invalid, or null if valid.
 */
export function checkServiceNowInstanceUrl(url: string): string | null {
  return checkInstanceUrl(url, { label: 'ServiceNow', maxLength: MAX_SERVICENOW_INSTANCE_URL_LENGTH });
}

export interface ServiceNowCustomFieldMapping {
  readonly key: string;
  readonly value: string;
}

export interface ServiceNowChannelFieldInput {
  readonly endpointUrl: string;
  readonly tableName: string;
  readonly credentialsSecretArn: string;
  readonly customFieldMappings?: ServiceNowCustomFieldMapping[];
}

export interface ServiceNowChannelFieldErrors {
  readonly endpointUrl?: string;
  readonly tableName?: string;
  readonly credentialsSecretArn?: string;
  readonly customFieldMappings?: string;
}

/**
 * Checks all ServiceNow channel configuration fields.
 * Returns an object with field-keyed error messages. An empty object means all fields are valid.
 */
export function checkServiceNowChannelFields(input: ServiceNowChannelFieldInput): ServiceNowChannelFieldErrors {
  const errors: { -readonly [K in keyof ServiceNowChannelFieldErrors]?: string } = {};

  const urlError = checkServiceNowInstanceUrl(input.endpointUrl.trim());
  if (urlError) {
    errors.endpointUrl = urlError;
  }

  const tableName = input.tableName.trim();
  if (!tableName) {
    errors.tableName = 'ServiceNow table name is required.';
  } else if (!SERVICENOW_TABLE_NAME_PATTERN.test(tableName)) {
    errors.tableName =
      'Table name must start with a lowercase letter, followed by lowercase letters, digits, or underscores (1–80 characters total).';
  }

  const arn = input.credentialsSecretArn.trim();
  if (!arn) {
    errors.credentialsSecretArn = 'ServiceNow credentials Secret ARN is required.';
  } else if (!notificationChannelSecretArnSchema.safeParse(arn).success) {
    errors.credentialsSecretArn =
      `Secret name must start with "${NOTIFICATION_CHANNEL_SECRET_PREFIX}". ` +
      `Example: arn:aws:secretsmanager:us-east-1:123456789012:secret:${NOTIFICATION_CHANNEL_SECRET_PREFIX}servicenow-creds`;
  }

  if (input.customFieldMappings) {
    const mappingsError = checkServiceNowCustomFieldMappings(input.customFieldMappings);
    if (mappingsError) {
      errors.customFieldMappings = mappingsError;
    }
  }

  return errors;
}

function checkServiceNowCustomFieldMappings(mappings: ServiceNowCustomFieldMapping[]): string | null {
  if (mappings.length > MAX_SERVICENOW_CUSTOM_FIELDS) {
    return `Custom field mappings must not exceed ${MAX_SERVICENOW_CUSTOM_FIELDS} entries.`;
  }

  for (const [index, mapping] of mappings.entries()) {
    const trimmedKey = mapping.key.trim();
    if (!trimmedKey) {
      return `Custom field mapping [${index}]: key must not be empty.`;
    }
    if (trimmedKey.length > MAX_SERVICENOW_CUSTOM_FIELD_KEY_LENGTH) {
      return `Custom field mapping [${index}]: key must not exceed ${MAX_SERVICENOW_CUSTOM_FIELD_KEY_LENGTH} characters.`;
    }
    if (RESERVED_SERVICENOW_FIELD_KEYS.has(trimmedKey)) {
      return `Custom field mapping [${index}]: key "${trimmedKey}" conflicts with a reserved ServiceNow record field.`;
    }
    const trimmedValue = mapping.value.trim();
    if (!trimmedValue) {
      return `Custom field mapping [${index}]: value must not be empty.`;
    }
    if (trimmedValue.length > MAX_SERVICENOW_CUSTOM_FIELD_VALUE_LENGTH) {
      return `Custom field mapping [${index}]: value must not exceed ${MAX_SERVICENOW_CUSTOM_FIELD_VALUE_LENGTH} characters.`;
    }
  }

  return null;
}

export interface SlackChannelFieldErrors {
  credentialsSecretArn?: string;
  channelId?: string;
}

export interface SlackChannelFieldInput {
  readonly credentialsSecretArn: string;
  readonly channelId: string;
}

export function checkSlackChannelFields(input: SlackChannelFieldInput): SlackChannelFieldErrors {
  const errors: SlackChannelFieldErrors = {};
  const arn = input.credentialsSecretArn.trim();
  if (!arn) {
    errors.credentialsSecretArn = 'Slack credentials Secret ARN is required.';
  } else if (!notificationChannelSecretArnSchema.safeParse(arn).success) {
    errors.credentialsSecretArn =
      `Secret name must start with "${NOTIFICATION_CHANNEL_SECRET_PREFIX}". ` +
      `Example: arn:aws:secretsmanager:us-east-1:123456789012:secret:${NOTIFICATION_CHANNEL_SECRET_PREFIX}slack-webhook`;
  }
  const channelId = input.channelId.trim();
  if (!channelId) {
    errors.channelId = 'Slack channel ID is required.';
  } else if (!SLACK_CHANNEL_ID_PATTERN.test(channelId)) {
    errors.channelId =
      'Channel ID must start with C followed by 8 or more uppercase alphanumeric characters (e.g. C0123456789).';
  }
  return errors;
}

export interface JiraCustomFieldMapping {
  readonly key: string;
  readonly value: string;
}

export interface JiraChannelFieldInput {
  readonly endpointUrl: string;
  readonly projectKey: string;
  readonly issueType: string;
  readonly credentialsSecretArn: string;
  readonly customFieldMappings?: JiraCustomFieldMapping[];
}

export interface JiraChannelFieldErrors {
  readonly endpointUrl?: string;
  readonly projectKey?: string;
  readonly issueType?: string;
  readonly credentialsSecretArn?: string;
  readonly customFieldMappings?: string;
}

function checkJiraCustomFieldEntry(mapping: JiraCustomFieldMapping): string | null {
  if (mapping.key.length > MAX_JIRA_CUSTOM_FIELD_KEY_LENGTH) {
    return `Custom field key must not exceed ${MAX_JIRA_CUSTOM_FIELD_KEY_LENGTH} characters.`;
  }
  if (mapping.value.length > MAX_JIRA_CUSTOM_FIELD_VALUE_LENGTH) {
    return `Custom field value must not exceed ${MAX_JIRA_CUSTOM_FIELD_VALUE_LENGTH.toLocaleString()} characters.`;
  }
  return null;
}

export function checkJiraCustomFieldMappings(mappings: JiraCustomFieldMapping[]): string | null {
  if (mappings.length > MAX_JIRA_CUSTOM_FIELDS) {
    return `Custom field mappings must not exceed ${MAX_JIRA_CUSTOM_FIELDS} entries.`;
  }

  const invalidKeyPattern = mappings.find((m) => !JIRA_CUSTOM_FIELD_KEY_PATTERN.test(m.key));
  if (invalidKeyPattern) {
    return `Custom field key "${invalidKeyPattern.key}" must match pattern customfield_<number> (e.g. customfield_10001).`;
  }

  for (const mapping of mappings) {
    const entryError = checkJiraCustomFieldEntry(mapping);
    if (entryError) return entryError;
  }

  return null;
}

export function checkJiraChannelFields(input: JiraChannelFieldInput): JiraChannelFieldErrors {
  const errors: { -readonly [K in keyof JiraChannelFieldErrors]?: string } = {};

  const urlError = checkJiraInstanceUrl(input.endpointUrl.trim());
  if (urlError) {
    errors.endpointUrl = urlError;
  }

  const projectKey = input.projectKey.trim();
  if (!projectKey) {
    errors.projectKey = 'JIRA project key is required.';
  } else if (!JIRA_PROJECT_KEY_PATTERN.test(projectKey)) {
    errors.projectKey =
      'Project key must be 2–10 characters: starts with an uppercase letter, followed by uppercase letters, digits, or underscores.';
  }

  const issueType = input.issueType.trim();
  if (!issueType) {
    errors.issueType = 'JIRA issue type is required.';
  }

  const arn = input.credentialsSecretArn.trim();
  if (!arn) {
    errors.credentialsSecretArn = 'JIRA credentials Secret ARN is required.';
  } else if (!notificationChannelSecretArnSchema.safeParse(arn).success) {
    errors.credentialsSecretArn =
      `Secret name must start with "${NOTIFICATION_CHANNEL_SECRET_PREFIX}". ` +
      `Example: arn:aws:secretsmanager:us-east-1:123456789012:secret:${NOTIFICATION_CHANNEL_SECRET_PREFIX}jira-creds`;
  }

  if (input.customFieldMappings) {
    const mappingsError = checkJiraCustomFieldMappings(input.customFieldMappings);
    if (mappingsError) {
      errors.customFieldMappings = mappingsError;
    }
  }

  return errors;
}

export const SlackChannelConfigSchema = z
  .object({
    type: z.literal('slack'),
    enabled: z.boolean(),
    channelId: z.string().optional(),
    credentialsSecretArn: secretsManagerArnSchema,
  })
  .refine((data) => data.channelId || data.credentialsSecretArn, {
    message: 'channelId or credentialsSecretArn must be provided',
  });

const jiraCustomFieldMappingsSchema = z
  .array(
    z.object({
      key: z.string().max(MAX_JIRA_CUSTOM_FIELD_KEY_LENGTH),
      value: z.string().max(MAX_JIRA_CUSTOM_FIELD_VALUE_LENGTH),
    }),
  )
  .max(MAX_JIRA_CUSTOM_FIELDS)
  .optional();

const serviceNowCustomFieldMappingsSchema = z
  .array(
    z.object({
      key: z.string().max(MAX_SERVICENOW_CUSTOM_FIELD_KEY_LENGTH),
      value: z.string().max(MAX_SERVICENOW_CUSTOM_FIELD_VALUE_LENGTH),
    }),
  )
  .max(MAX_SERVICENOW_CUSTOM_FIELDS)
  .optional();

export const JiraChannelConfigSchema = z.object({
  type: z.literal('jira'),
  enabled: z.boolean(),
  projectKey: z.string(),
  issueType: z.string(),
  endpointUrl: z.url(),
  credentialsSecretArn: secretsManagerArnSchema,
  customFieldMappings: jiraCustomFieldMappingsSchema,
});

export const ServiceNowChannelConfigSchema = z.object({
  type: z.literal('servicenow'),
  enabled: z.boolean(),
  endpointUrl: z.url(),
  tableName: z.string(),
  credentialsSecretArn: secretsManagerArnSchema,
  customFieldMappings: serviceNowCustomFieldMappingsSchema,
});

export const SNS_TOPIC_ARN_PATTERN = /^arn:([^:]+):sns:([^:]+):(\d{12}):(.+)$/;

export const SnsChannelConfigSchema = z.object({
  type: z.literal('sns'),
  enabled: z.boolean(),
  topicArn: z.string().regex(SNS_TOPIC_ARN_PATTERN),
});

export interface ParsedSnsTopicArn {
  readonly partition: string;
  readonly region: string;
  readonly accountId: string;
  readonly topicName: string;
}

export function parseSnsTopicArn(topicArn: string): ParsedSnsTopicArn | null {
  const match = SNS_TOPIC_ARN_PATTERN.exec(topicArn);
  if (!match) return null;
  return { partition: match[1], region: match[2], accountId: match[3], topicName: match[4] };
}

export interface SnsChannelValidationContext {
  readonly accountId: string;
  readonly partition: string;
  readonly region: string;
}

export type SnsChannelConfigSchemaT = ReturnType<typeof createSnsChannelConfigSchema>;

export function createSnsChannelConfigSchema(context: SnsChannelValidationContext): z.ZodObject<{
  type: z.ZodLiteral<'sns'>;
  enabled: z.ZodBoolean;
  topicArn: z.ZodString;
}> {
  return z.object({
    type: z.literal('sns'),
    enabled: z.boolean(),
    topicArn: z.string().superRefine((value, refinementContext) => {
      const parsed = parseSnsTopicArn(value);
      if (!parsed) {
        refinementContext.addIssue({
          code: 'custom',
          message: 'Must be a valid SNS topic ARN (arn:<partition>:sns:<region>:<account>:<name>)',
        });
        return;
      }
      if (parsed.partition !== context.partition) {
        refinementContext.addIssue({
          code: 'custom',
          message: `Topic ARN must be in partition "${context.partition}", got "${parsed.partition}"`,
        });
      }
      if (parsed.accountId !== context.accountId) {
        refinementContext.addIssue({
          code: 'custom',
          message: `Topic ARN must belong to account "${context.accountId}", got "${parsed.accountId}"`,
        });
      }
      if (parsed.region !== context.region) {
        refinementContext.addIssue({
          code: 'custom',
          message: `Topic ARN must be in region "${context.region}", got "${parsed.region}"`,
        });
      }
    }),
  });
}

export const DeliveryChannelConfigSchema = z.union([
  EmailChannelConfigSchema,
  SlackChannelConfigSchema,
  JiraChannelConfigSchema,
  ServiceNowChannelConfigSchema,
  SnsChannelConfigSchema,
]);

// --- Batch window ---

export const BatchWindowSchema = z
  .object({
    enabled: z.boolean(),
    duration: z.number().int().positive().optional(),
    unit: BatchWindowUnitSchema.optional(),
  })
  .refine((data) => !data.enabled || (data.duration !== undefined && data.unit !== undefined), {
    message: 'duration and unit are required when batching is enabled',
  })
  .refine(
    (data) => {
      if (!data.enabled || data.duration === undefined || data.unit === undefined) return true;

      const ranges: Record<string, [number, number]> = { Minutes: [5, 60], Hours: [1, 24], Days: [1, 365] };
      const range = ranges[data.unit];
      if (!range) return true;

      const [min, max] = range;
      return data.duration >= min && data.duration <= max;
    },
    {
      message: 'Batch window duration out of range (Minutes: 5–60, Hours: 1–24, Days: 1–365)',
      path: ['duration'],
    },
  );

export const BatchExportSchema = z.object({
  enabled: z.boolean(),
  presignedUrlExpirationHours: z.number().int().min(1).max(8).optional(),
});

// --- Content options ---

export const IaCFormatSchema = z.enum(['cloudformation-yaml', 'cloudformation-json', 'terraform', 'cdk']);
export type IaCFormat = z.infer<typeof IaCFormatSchema>;

export const ContentOptionsSchema = z
  .object({
    includeManualRemediationLink: z.boolean(),
    includeRemediationDeadline: z.boolean(),
    remediationDeadlineDays: z.number().int().min(1).max(90).optional(),
    enforceDeadline: z.boolean().optional().default(false),
    includeIaCSnippet: z.boolean(),
    iacFormats: z.array(IaCFormatSchema).optional(),
    includeEnableAutomationLink: z.boolean(),
  })
  .refine((data) => !data.includeRemediationDeadline || data.remediationDeadlineDays !== undefined, {
    message: 'remediationDeadlineDays is required when includeRemediationDeadline is enabled',
  })
  .refine((data) => !data.includeIaCSnippet || (data.iacFormats && data.iacFormats.length > 0), {
    message: 'At least one iacFormat is required when includeIaCSnippet is enabled',
  })
  .refine((data) => !data.enforceDeadline || data.includeRemediationDeadline, {
    message: 'includeRemediationDeadline must be enabled when deadline enforcement is active',
  })
  .refine((data) => !data.enforceDeadline || data.remediationDeadlineDays !== undefined, {
    message: 'remediationDeadlineDays must be specified when deadline enforcement is active',
  });

// --- Account scoping ---
export const AccountScopeSchema = z
  .array(z.string().regex(/^\d{12}$/, 'Must be a 12-digit AWS account ID'))
  .min(1, 'At least one account ID is required when scoping to accounts');

// --- NotificationConfiguration table item ---

export const NotificationConfigurationItemSchema = z.object({
  configId: ConfigIdSchema,
  name: z
    .string()
    .min(1)
    .max(100)
    .regex(/^[\w\s\-().]+$/, 'Name contains invalid characters'),
  enabled: z.boolean(),
  notificationType: NotificationTypeSchema,
  severityFilter: SeverityFilterSchema.optional(),
  remediationStatusFilter: RemediationStatusFilterSchema.optional(),
  controlIds: z.array(z.string()).optional(),
  resourceFilterIds: z.array(z.string().uuid()).optional(),
  accountIds: AccountScopeSchema.optional(),
  deliveryChannels: z.array(DeliveryChannelConfigSchema),
  batchWindow: BatchWindowSchema,
  batchExport: BatchExportSchema.optional(),
  contentOptions: ContentOptionsSchema,
  version: z.number().int().positive(),
  createdAt: z.iso.datetime(),
  createdBy: z.string(),
  updatedAt: z.iso.datetime().optional(),
  updatedBy: z.string().optional(),
  lastUpdatedBy: z.string().optional(),
});

// --- NotificationBatch table item ---

export const NotificationBatchItemSchema = z.object({
  configId: z.string().uuid(),
  windowEnd: z.string(), // ISO datetime, or "datetime#NNNN" for overflow sequences
  status: BatchStatusSchema,
  findingIds: z.array(FindingIdSchema),
  remediationIds: z.array(FindingIdSchema),
  itemCount: z.number().int().nonnegative(),
  expireAt: z.number().int(),
  createdAt: z.iso.datetime(),
  lastUpdatedBy: z.string().optional(),
  processingStartedAt: z.iso.datetime().optional(),
});

// --- Reconciliation task (NotificationBatches table item) ---

/**
 * Reserved `configId` prefix that distinguishes reconciliation tasks from notification batches,
 * which share the NotificationBatches table.
 */
export const RECONCILIATION_CONFIG_ID_PREFIX = 'reconciliation#';

/**
 * Partition-key attribute of the sparse GSI ({@link OUTSTANDING_RECONCILIATION_GSI}) used to query
 * outstanding reconciliation tasks without scanning the shared NotificationBatches table. The
 * attribute is stamped with {@link RECONCILIATION_QUEUE_VALUE} only while a task is PENDING or
 * IN_PROGRESS and removed when the task COMPLETES, so the index holds only outstanding work and is
 * empty in steady state.
 */
export const RECONCILIATION_QUEUE_ATTRIBUTE = 'reconciliationQueue';

/** Constant value stored in {@link RECONCILIATION_QUEUE_ATTRIBUTE} for every outstanding task. */
export const RECONCILIATION_QUEUE_VALUE = 'reconciliation';

/** Name of the sparse GSI on the NotificationBatches table that indexes outstanding tasks. */
export const OUTSTANDING_RECONCILIATION_GSI = 'outstandingReconciliation-windowEnd-GSI';

/** Lifecycle state of a reconciliation task as it moves through the Batch Processor. */
export type ReconciliationTaskStatus = 'PENDING' | 'IN_PROGRESS' | 'COMPLETED';

/** What changed about a notification configuration, determining how findings are reconciled. */
export type ReconciliationTaskType = 'enable' | 'disable' | 'deadlineChange' | 'filterChange';

/**
 * A unit of asynchronous reconciliation work, written to the NotificationBatches table when a
 * notification configuration's enforcement settings change. The Batch Processor picks up these
 * tasks on its next invocation and updates affected findings' `remediationDueBy` and
 * `enforcementConfigIds` values in bounded batches.
 *
 * Reconciliation tasks share the NotificationBatches table with notification batches; the
 * {@link RECONCILIATION_CONFIG_ID_PREFIX} on `configId` keeps the two item types distinct. All
 * DynamoDB access for these items lives on the NotificationBatchRepository.
 */
export interface ReconciliationTask {
  /** Partition key, formatted as `reconciliation#<uuid>`. */
  configId: string;
  /** Sort key, an ISO-8601 timestamp set to the task's creation time. */
  windowEnd: string;
  status: ReconciliationTaskStatus;
  taskType: ReconciliationTaskType;
  /** Snapshot of the configuration before the change (absent for create). */
  oldConfig?: NotificationConfigurationItem;
  /** Snapshot of the configuration after the change (absent for delete). */
  newConfig?: NotificationConfigurationItem;
  /** Pagination bookmark used to resume a task that exceeded the per-invocation finding limit. */
  lastProcessedKey?: Record<string, unknown>;
  /** Number of findings processed so far across invocations. */
  itemCount: number;
  /** DynamoDB TTL (Unix timestamp in seconds). */
  expireAt: number;
  /**
   * Sparse-GSI partition key ({@link RECONCILIATION_QUEUE_VALUE}) marking the task as outstanding.
   * Present while PENDING or IN_PROGRESS; removed when the task transitions to COMPLETED so the
   * {@link OUTSTANDING_RECONCILIATION_GSI} stays sparse.
   */
  reconciliationQueue?: string;
}

/**
 * The outcome of processing a single reconciliation task that the Batch Processor persists back to
 * the task. Declared structurally so it does not depend on a Lambda-specific module; the Batch
 * Processor's `ReconciliationResult` satisfies this shape.
 */
export interface ReconciliationTaskProgress {
  /** True when every targeted finding has been processed and the task is finished. */
  isComplete: boolean;
  /** Number of findings examined during the invocation, added to the task's running `itemCount`. */
  itemsProcessed: number;
  /** Bookmark to resume from on the next invocation; present only when `isComplete` is false. */
  lastProcessedKey?: Record<string, unknown>;
}

// --- Create request schema (fields submitted by the client) ---

export const CreateNotificationConfigurationRequestSchema = z
  .object({
    name: NotificationConfigurationItemSchema.shape.name,
    enabled: z.boolean(),
    notificationType: NotificationTypeSchema,
    severityFilter: SeverityFilterSchema.optional(),
    remediationStatusFilter: RemediationStatusFilterSchema.optional(),
    controlIds: z.array(z.string()).max(500).optional(),
    resourceFilterIds: z.array(z.uuid()).max(100).optional(),
    accountIds: AccountScopeSchema.optional(),
    deliveryChannels: z.array(DeliveryChannelConfigSchema).min(1, 'At least one delivery channel is required').max(10),
    batchWindow: BatchWindowSchema,
    batchExport: BatchExportSchema.optional(),
    contentOptions: ContentOptionsSchema,
  })
  .refine((data) => data.deliveryChannels.some((ch) => ch.enabled), {
    message: 'At least one delivery channel must be enabled',
    path: ['deliveryChannels'],
  })
  .refine(
    (data) => {
      const totalCustomEmails = data.deliveryChannels
        .filter((ch): ch is z.infer<typeof EmailChannelConfigSchema> => ch.type === 'email')
        .flatMap((ch) => ch.recipients)
        .filter((r) => r.recipientType === 'custom')
        .flatMap((r) => r.emailAddresses ?? []).length;
      return totalCustomEmails <= 50;
    },
    { message: 'Custom email addresses must not exceed 50', path: ['deliveryChannels'] },
  )
  .refine(
    (data) => {
      const types = data.deliveryChannels.map((ch) => ch.type);
      return new Set(types).size === types.length;
    },
    { message: 'Each delivery channel type may only appear once', path: ['deliveryChannels'] },
  )
  .refine(
    (data) => {
      if (!data.contentOptions.enforceDeadline) return true;
      return data.notificationType === 'finding';
    },
    {
      message: 'Deadline enforcement is only supported for finding-type notifications',
      path: ['contentOptions', 'enforceDeadline'],
    },
  );

export type CreateNotificationConfigurationRequest = z.infer<typeof CreateNotificationConfigurationRequestSchema>;

// --- Update request schema (full replacement, requires version for optimistic locking) ---

export const UpdateNotificationConfigurationRequestSchema = CreateNotificationConfigurationRequestSchema.and(
  z.object({ version: z.number().int().positive() }),
);

export type UpdateNotificationConfigurationRequest = z.infer<typeof UpdateNotificationConfigurationRequestSchema>;

// --- Toggle status request schema ---

export const ToggleStatusRequestSchema = z.object({
  enabled: z.boolean(),
  version: z.number().int().positive(),
});

export type ToggleStatusRequest = z.infer<typeof ToggleStatusRequestSchema>;

export const ResendEmailConfirmationRequestSchema = z.object({
  email: z.email(),
});

export type ResendEmailConfirmationRequest = z.infer<typeof ResendEmailConfirmationRequestSchema>;

// --- Type exports ---

export type DeliveryChannelType = z.infer<typeof DeliveryChannelTypeSchema>;
export type NotificationType = z.infer<typeof NotificationTypeSchema>;
export type SeverityLevel = z.infer<typeof SeverityLevelSchema>;
export type SeverityFilter = z.infer<typeof SeverityFilterSchema>;
export type RemediationStatusFilter = z.infer<typeof RemediationStatusFilterSchema>;
export type RemediationStatusFilterValue = z.infer<typeof RemediationStatusFilterValueSchema>;
export type AccountScope = z.infer<typeof AccountScopeSchema>;

/** Subscription status enriched with the recipient type that resolved to that email. */
export interface EmailSubscriptionStatusWithType extends EmailSubscriptionStatus {
  readonly recipientType?: RecipientType;
}

export type BatchWindowUnit = z.infer<typeof BatchWindowUnitSchema>;
export type RecipientType = z.infer<typeof RecipientTypeSchema>;
export type BatchStatus = z.infer<typeof BatchStatusSchema>;
export type DeliveryChannelConfig = z.infer<typeof DeliveryChannelConfigSchema>;
export type BatchWindow = z.infer<typeof BatchWindowSchema>;
export type BatchExport = z.infer<typeof BatchExportSchema>;
export type ContentOptions = z.infer<typeof ContentOptionsSchema>;
export type NotificationConfigurationItem = z.infer<typeof NotificationConfigurationItemSchema>;
export type NotificationBatchItem = z.infer<typeof NotificationBatchItemSchema>;

// --- Notification event (SQS message body for NotificationQueue) ---

export const NotificationEventSchema = z.object({
  eventType: NotificationTypeSchema,
  eventId: z.string(),
  controlId: z.string(),
  accountId: z.string(),
  region: z.string(),
  severity: z.string(),
  resourceType: z.string(),
  resourceId: z.string(),
  title: z.string(),
  description: z.string().optional(),
  findingDescription: z.string().optional(),
  detectedAt: z.iso.datetime(),
  remediationStatus: z.string().optional(),
  remediationStatusDetail: z.string().optional(),
  remediationMessage: z.string().optional(),
  automatedRemediationEnabled: z.boolean().optional(),
  standardName: z.string().optional(),
  standardVersion: z.string().optional(),
  accountAlias: z.string().optional(),
  remediationOutput: z.string().optional(),
  findingLink: z.string().optional(),
  stepFunctionsExecutionId: z.string().optional(),
  timestamp: z.iso.datetime(),
});

export type NotificationEvent = z.infer<typeof NotificationEventSchema>;
