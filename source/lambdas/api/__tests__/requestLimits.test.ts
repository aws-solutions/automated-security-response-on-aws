// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { randomUUID } from 'node:crypto';
import type { z } from 'zod';
import {
  BulkEditUpdateRequestSchema,
  CreateFilterRequestSchema,
  CreateNotificationConfigurationRequestSchema,
  CreateNotificationSchema,
  CreateRemediationRoleSchema,
  DeliveryChannelTypeSchema,
  DeployRunbookActionSchema,
  FindingsActionRequestSchema,
  FindingsRequestSchema,
  GenerateRunbookSchema,
  GetRemediationGuidanceSchema,
  InviteUserRequest,
  MAX_ACCOUNT_IDS,
  MAX_BULK_EDIT_CONTROLS,
  MAX_CONTROL_IDS,
  MAX_CUSTOM_EMAIL_ADDRESSES,
  MAX_EMAIL_RECIPIENT_GROUPS,
  MAX_FINDING_ACTION_ITEMS,
  MAX_IAC_FORMATS,
  MAX_IAM_ACTIONS,
  MAX_IAM_POLICY_RESOURCE_ARNS,
  MAX_MCP_TOOLS,
  MAX_ORGANIZATIONAL_UNITS,
  MAX_RESOURCE_FILTER_ARN_PATTERNS,
  MAX_RESOURCE_FILTER_IDS,
  MAX_RESOURCE_FILTER_TAGS,
  MAX_RESOURCE_FILTER_STORED_BYTES,
  MAX_TAG_KEY_LENGTH,
  MAX_TAG_VALUE_LENGTH,
  MAX_ARN_PATTERN_LENGTH,
  MAX_RUNBOOK_DYNAMIC_VALUES,
  MAX_SEARCH_COMPOSITE_FILTERS,
  MAX_SEARCH_SORT_CRITERIA,
  MAX_SEARCH_STRING_FILTERS,
  NotificationConfigurationItemSchema,
  PutUserMcpToolsRequestSchema,
  RemediationStatusFilterValueSchema,
  RemediationsRequestSchema,
  SeverityFilterSchema,
  TestNotificationRequestSchema,
  UpdateFilterRequestSchema,
  UpdateNotificationSchema,
} from '@asr/data-models';
import { TestRunbookYamlSchema } from '../../mcp-server/contract/toolContract';

// CVE-2023-54404: a list without a size limit collects one issue per invalid element, so one request can make
// validation allocate hundreds of MB. These tests send each bounded list at its limit, one over it, and with
// 100,000 invalid elements, which must produce a single size issue rather than one issue per element.

type Path = ReadonlyArray<PropertyKey>;

interface BoundedListCase {
  readonly name: string;
  readonly schema: z.ZodType;
  readonly limit: number;
  readonly validElement: unknown;
  readonly path: Path;
  readonly request: (list: unknown[]) => unknown;
}

const FLOOD_SIZE = 100_000;

const STRING_FILTER = { FieldName: 'accountId', Filter: { Value: '111111111111', Comparison: 'EQUALS' } };
const COMPOSITE_FILTER = { Operator: 'OR', StringFilters: [STRING_FILTER] };
const SORT_CRITERION = { Field: 'lastUpdatedTime', SortOrder: 'desc' };
const ACCOUNT_ID = '111111111111';
const EMAIL = 'admin@example.com';

const CONTROL = {
  controlId: 'S3.1',
  description: 'S3 general purpose buckets should have block public access settings enabled',
  automatedRemediationEnabled: false,
  filters: [],
  filterMode: 'include',
  version: 1,
  lastModified: '2026-01-01T00:00:00.000Z',
  modifiedBy: 'admin@example.com',
};

const EMPTY_FILTER = { name: 'filter', accountIds: [], organizationalUnits: [], tags: [], arnPatterns: [] };

const NOTIFICATION = {
  name: 'Critical Production Alerts',
  enabled: true,
  notificationType: 'finding',
  severityFilter: ['Critical'],
  deliveryChannels: [
    { type: 'email', enabled: true, recipients: [{ recipientType: 'custom', emailAddresses: [EMAIL] }] },
  ],
  batchWindow: { enabled: false },
  contentOptions: {
    includeManualRemediationLink: true,
    includeRemediationDeadline: false,
    includeIaCSnippet: false,
    includeEnableAutomationLink: true,
  },
};

function notificationWithEmailChannel(recipients: unknown[]): Record<string, unknown> {
  return { ...NOTIFICATION, deliveryChannels: [{ type: 'email', enabled: true, recipients }] };
}

const DEPLOY_ACTION = {
  action: 'deploy',
  runbook_id: randomUUID(),
  control_id: 'S3.1',
  security_standard: 'SC',
  standard_version: '2.0.0',
  member_account_ids: [ACCOUNT_ID],
};

const CASES: readonly BoundedListCase[] = [
  {
    name: 'MCP test_runbook_yaml required_iam_actions',
    schema: TestRunbookYamlSchema,
    limit: MAX_IAM_ACTIONS,
    validElement: 's3:GetObject',
    path: ['required_iam_actions'],
    request: (list) => ({ runbook_yaml: 'schemaVersion: "0.3"\nmainSteps: []', required_iam_actions: list }),
  },
  {
    name: 'findings search CompositeFilters',
    schema: FindingsRequestSchema,
    limit: MAX_SEARCH_COMPOSITE_FILTERS,
    validElement: COMPOSITE_FILTER,
    path: ['Filters', 'CompositeFilters'],
    request: (list) => ({ Filters: { CompositeFilters: list } }),
  },
  {
    name: 'findings search StringFilters in a CompositeFilter',
    schema: FindingsRequestSchema,
    limit: MAX_SEARCH_STRING_FILTERS,
    validElement: STRING_FILTER,
    path: ['Filters', 'CompositeFilters', 0, 'StringFilters'],
    request: (list) => ({ Filters: { CompositeFilters: [{ Operator: 'OR', StringFilters: list }] } }),
  },
  {
    name: 'findings search SortCriteria',
    schema: FindingsRequestSchema,
    limit: MAX_SEARCH_SORT_CRITERIA,
    validElement: SORT_CRITERION,
    path: ['SortCriteria'],
    request: (list) => ({ SortCriteria: list }),
  },
  {
    name: 'remediations search StringFilters',
    schema: RemediationsRequestSchema,
    limit: MAX_SEARCH_STRING_FILTERS,
    validElement: STRING_FILTER,
    path: ['Filters', 'StringFilters'],
    request: (list) => ({ Filters: { StringFilters: list } }),
  },
  {
    name: 'remediations search CompositeFilters',
    schema: RemediationsRequestSchema,
    limit: MAX_SEARCH_COMPOSITE_FILTERS,
    validElement: COMPOSITE_FILTER,
    path: ['Filters', 'CompositeFilters'],
    request: (list) => ({ Filters: { CompositeFilters: list } }),
  },
  {
    name: 'remediations search SortCriteria',
    schema: RemediationsRequestSchema,
    limit: MAX_SEARCH_SORT_CRITERIA,
    validElement: SORT_CRITERION,
    path: ['SortCriteria'],
    request: (list) => ({ SortCriteria: list }),
  },
  {
    name: 'finding action findingIds',
    schema: FindingsActionRequestSchema,
    limit: MAX_FINDING_ACTION_ITEMS,
    validElement: 'finding-id',
    path: ['findingIds'],
    request: (list) => ({ actionType: 'Suppress', findingIds: list }),
  },
  {
    name: 'finding action findingKeys',
    schema: FindingsActionRequestSchema,
    limit: MAX_FINDING_ACTION_ITEMS,
    validElement: { findingId: 'finding-id', findingType: 'S3.1' },
    path: ['findingKeys'],
    request: (list) => ({ actionType: 'Suppress', findingIds: ['finding-id'], findingKeys: list }),
  },
  {
    name: 'bulk control update data',
    schema: BulkEditUpdateRequestSchema,
    limit: MAX_BULK_EDIT_CONTROLS,
    validElement: CONTROL,
    path: ['data'],
    request: (list) => ({ operation: 'update', data: list }),
  },
  {
    name: 'bulk control update filters on one control',
    schema: BulkEditUpdateRequestSchema,
    limit: MAX_RESOURCE_FILTER_IDS,
    validElement: randomUUID(),
    path: ['data', 0, 'filters'],
    request: (list) => ({ operation: 'update', data: [{ ...CONTROL, filters: list }] }),
  },
  {
    name: 'resource filter accountIds',
    schema: CreateFilterRequestSchema,
    limit: MAX_ACCOUNT_IDS,
    validElement: ACCOUNT_ID,
    path: ['accountIds'],
    request: (list) => ({ ...EMPTY_FILTER, accountIds: list }),
  },
  {
    name: 'resource filter organizationalUnits',
    schema: CreateFilterRequestSchema,
    limit: MAX_ORGANIZATIONAL_UNITS,
    validElement: 'ou-abcd-abcdefgh',
    path: ['organizationalUnits'],
    request: (list) => ({ ...EMPTY_FILTER, organizationalUnits: list }),
  },
  {
    name: 'resource filter tags',
    schema: CreateFilterRequestSchema,
    limit: MAX_RESOURCE_FILTER_TAGS,
    validElement: { key: 'Environment', value: 'prod' },
    path: ['tags'],
    request: (list) => ({ ...EMPTY_FILTER, tags: list }),
  },
  {
    name: 'resource filter arnPatterns',
    schema: CreateFilterRequestSchema,
    limit: MAX_RESOURCE_FILTER_ARN_PATTERNS,
    validElement: 'arn:aws:s3:::prod-*',
    path: ['arnPatterns'],
    request: (list) => ({ ...EMPTY_FILTER, arnPatterns: list }),
  },
  {
    name: 'user invite accountIds',
    schema: InviteUserRequest,
    limit: MAX_ACCOUNT_IDS,
    validElement: ACCOUNT_ID,
    path: ['accountIds'],
    request: (list) => ({ role: 'AccountOperator', email: EMAIL, accountIds: list }),
  },
  {
    name: 'user MCP tool grant',
    schema: PutUserMcpToolsRequestSchema,
    limit: MAX_MCP_TOOLS,
    validElement: 'findings',
    path: ['allowedTools'],
    request: (list) => ({ allowedTools: list }),
  },
  {
    name: 'notification severityFilter',
    schema: CreateNotificationConfigurationRequestSchema,
    limit: SeverityFilterSchema.element.options.length,
    validElement: 'Critical',
    path: ['severityFilter'],
    request: (list) => ({ ...NOTIFICATION, severityFilter: list }),
  },
  {
    name: 'notification remediationStatusFilter',
    schema: CreateNotificationConfigurationRequestSchema,
    limit: RemediationStatusFilterValueSchema.options.length,
    validElement: 'Success',
    path: ['remediationStatusFilter'],
    request: (list) => ({ ...NOTIFICATION, notificationType: 'remediation', remediationStatusFilter: list }),
  },
  {
    name: 'notification controlIds',
    schema: CreateNotificationConfigurationRequestSchema,
    limit: MAX_CONTROL_IDS,
    validElement: 'S3.1',
    path: ['controlIds'],
    request: (list) => ({ ...NOTIFICATION, controlIds: list }),
  },
  {
    name: 'notification resourceFilterIds',
    schema: CreateNotificationConfigurationRequestSchema,
    limit: MAX_RESOURCE_FILTER_IDS,
    validElement: randomUUID(),
    path: ['resourceFilterIds'],
    request: (list) => ({ ...NOTIFICATION, resourceFilterIds: list }),
  },
  {
    name: 'notification accountIds',
    schema: CreateNotificationConfigurationRequestSchema,
    limit: MAX_ACCOUNT_IDS,
    validElement: ACCOUNT_ID,
    path: ['accountIds'],
    request: (list) => ({ ...NOTIFICATION, accountIds: list }),
  },
  {
    name: 'notification email recipient groups',
    schema: CreateNotificationConfigurationRequestSchema,
    limit: MAX_EMAIL_RECIPIENT_GROUPS,
    validElement: { recipientType: 'custom', emailAddresses: [EMAIL] },
    path: ['deliveryChannels', 0, 'recipients'],
    request: (list) => notificationWithEmailChannel(list),
  },
  {
    name: 'notification email addresses in one recipient group',
    schema: CreateNotificationConfigurationRequestSchema,
    limit: MAX_CUSTOM_EMAIL_ADDRESSES,
    validElement: EMAIL,
    path: ['deliveryChannels', 0, 'recipients', 0, 'emailAddresses'],
    request: (list) => notificationWithEmailChannel([{ recipientType: 'custom', emailAddresses: list }]),
  },
  {
    name: 'notification iacFormats',
    schema: CreateNotificationConfigurationRequestSchema,
    limit: MAX_IAC_FORMATS,
    validElement: 'terraform',
    path: ['contentOptions', 'iacFormats'],
    request: (list) => ({ ...NOTIFICATION, contentOptions: { ...NOTIFICATION.contentOptions, iacFormats: list } }),
  },
  {
    name: 'test notification channels',
    schema: TestNotificationRequestSchema,
    limit: DeliveryChannelTypeSchema.options.length,
    validElement: 'email',
    path: ['channels'],
    request: (list) => ({ channels: list }),
  },
  {
    name: 'MCP create_notification recipients',
    schema: CreateNotificationSchema,
    limit: MAX_CUSTOM_EMAIL_ADDRESSES,
    validElement: EMAIL,
    path: ['recipients'],
    request: (list) => ({ name: 'alerts', channel: 'email', notification_type: 'finding', recipients: list }),
  },
  {
    name: 'MCP create_notification control_ids',
    schema: CreateNotificationSchema,
    limit: MAX_CONTROL_IDS,
    validElement: 'S3.1',
    path: ['control_ids'],
    request: (list) => ({ name: 'alerts', channel: 'email', notification_type: 'finding', control_ids: list }),
  },
  {
    name: 'MCP update_notification control_ids',
    schema: UpdateNotificationSchema,
    limit: MAX_CONTROL_IDS,
    validElement: 'S3.1',
    path: ['control_ids'],
    request: (list) => ({ configuration_id: randomUUID(), control_ids: list }),
  },
  {
    name: 'MCP get_remediation_guidance include_iac',
    schema: GetRemediationGuidanceSchema,
    limit: 3,
    validElement: 'terraform',
    path: ['include_iac'],
    request: (list) => ({ target_id: 'target', include_iac: list }),
  },
  {
    name: 'generate_runbook guidance requiredPermissions',
    schema: GenerateRunbookSchema,
    limit: MAX_IAM_ACTIONS,
    validElement: 's3:PutBucketPublicAccessBlock',
    path: ['guidance', 'requiredPermissions'],
    request: (list) => ({
      description: 'Block public access on the bucket',
      guidance: { apiCall: { service: 's3', action: 'PutPublicAccessBlock' }, requiredPermissions: list },
    }),
  },
  {
    name: 'create_remediation_role iam_actions',
    schema: CreateRemediationRoleSchema,
    limit: MAX_IAM_ACTIONS,
    validElement: 's3:GetObject',
    path: ['iam_actions'],
    request: (list) => ({ control_id: 'S3.1', iam_actions: list }),
  },
  {
    name: 'create_remediation_role resource_arns',
    schema: CreateRemediationRoleSchema,
    limit: MAX_IAM_POLICY_RESOURCE_ARNS,
    validElement: 'arn:aws:s3:::prod-bucket',
    path: ['resource_arns'],
    request: (list) => ({ control_id: 'S3.1', iam_actions: ['s3:GetObject'], resource_arns: list }),
  },
  {
    name: 'deploy_runbook required_iam_actions',
    schema: DeployRunbookActionSchema,
    limit: MAX_IAM_ACTIONS,
    validElement: 's3:GetObject',
    path: ['required_iam_actions'],
    request: (list) => ({ ...DEPLOY_ACTION, required_iam_actions: list }),
  },
];

// A union reports a failing branch as one invalid_union issue that holds each branch's issues, with paths relative to
// the union. Flatten them, with full paths, so a size issue inside a union branch can be asserted like any other.
function flattenIssues(issues: readonly z.core.$ZodIssue[], prefix: Path = []): z.core.$ZodIssue[] {
  return issues.flatMap((issue) => {
    const path = [...prefix, ...issue.path];
    if (issue.code === 'invalid_union') {
      return issue.errors.flatMap((branchIssues) => flattenIssues(branchIssues, path));
    }
    return [{ ...issue, path }];
  });
}

function issuesUnder(schema: z.ZodType, request: unknown, path: Path): z.core.$ZodIssue[] {
  const result = schema.safeParse(request);
  if (result.success) return [];
  return flattenIssues(result.error.issues).filter((issue) =>
    path.every((segment, index) => issue.path[index] === segment),
  );
}

describe('request list limits (CVE-2023-54404)', () => {
  describe.each(CASES)('$name', ({ schema, limit, validElement, path, request }) => {
    it('accepts a list at the limit', () => {
      const issues = issuesUnder(schema, request(Array.from({ length: limit }, () => validElement)), path);
      expect(issues).toEqual([]);
    });

    it('rejects a list one over the limit with a size issue', () => {
      const issues = issuesUnder(schema, request(Array.from({ length: limit + 1 }, () => validElement)), path);
      expect(issues).toHaveLength(1);
      expect(issues[0].code).toBe('too_big');
    });

    it(`reports one issue, not one per element, for ${FLOOD_SIZE.toLocaleString()} invalid elements`, () => {
      const issues = issuesUnder(schema, request(Array.from({ length: FLOOD_SIZE }, () => 1)), path);
      expect(issues).toHaveLength(1);
      expect(issues[0].code).toBe('too_big');
    });
  });
});

describe('generate_runbook dynamic_values', () => {
  const requestWith = (dynamicValues: Record<string, unknown>): unknown => ({
    description: 'Block public access on the bucket',
    dynamic_values: dynamicValues,
  });
  const entries = (count: number, value: unknown): Record<string, unknown> =>
    Object.fromEntries(Array.from({ length: count }, (_, index) => [`Key${index}`, value]));

  it('accepts string values up to the limit and returns them unchanged', () => {
    const result = GenerateRunbookSchema.safeParse(requestWith(entries(MAX_RUNBOOK_DYNAMIC_VALUES, 'value')));
    expect(result.success).toBe(true);
    expect(result.data?.dynamic_values).toEqual(entries(MAX_RUNBOOK_DYNAMIC_VALUES, 'value'));
  });

  it('rejects one entry over the limit', () => {
    const issues = issuesUnder(GenerateRunbookSchema, requestWith(entries(MAX_RUNBOOK_DYNAMIC_VALUES + 1, 'value')), [
      'dynamic_values',
    ]);
    expect(issues).toHaveLength(1);
  });

  it('rejects a value that is not a string, naming its key', () => {
    const issues = issuesUnder(GenerateRunbookSchema, requestWith({ ContactEmail: 42 }), ['dynamic_values']);
    expect(issues).toHaveLength(1);
    expect(issues[0].path).toEqual(['dynamic_values', 'ContactEmail']);
  });

  it(`reports one issue for ${FLOOD_SIZE.toLocaleString()} entries with invalid values`, () => {
    const issues = issuesUnder(GenerateRunbookSchema, requestWith(entries(FLOOD_SIZE, 1)), ['dynamic_values']);
    expect(issues).toHaveLength(1);
  });
});

describe('stored notification configurations', () => {
  it('still parse when their lists exceed the request limits, so rows saved before the limits keep loading', () => {
    const storedRow = {
      ...notificationWithEmailChannel([
        {
          recipientType: 'custom',
          emailAddresses: Array.from(
            { length: MAX_CUSTOM_EMAIL_ADDRESSES + 1 },
            (_, index) => `user${index}@example.com`,
          ),
        },
        ...Array.from({ length: MAX_EMAIL_RECIPIENT_GROUPS }, () => ({ recipientType: 'securityContact' })),
      ]),
      severityFilter: Array.from({ length: SeverityFilterSchema.element.options.length + 1 }, () => 'Critical'),
      contentOptions: {
        ...NOTIFICATION.contentOptions,
        iacFormats: Array.from({ length: MAX_IAC_FORMATS + 1 }, () => 'terraform'),
      },
      configId: randomUUID(),
      version: 1,
      createdAt: '2026-01-01T00:00:00.000Z',
      createdBy: EMAIL,
    };

    expect(NotificationConfigurationItemSchema.safeParse(storedRow).success).toBe(true);
  });
});

describe('resource filter value lengths', () => {
  const create = (overrides: Record<string, unknown>) =>
    CreateFilterRequestSchema.safeParse({ ...EMPTY_FILTER, ...overrides });
  const arn = (length: number) => `arn:aws:s3:::${'b'.repeat(length - 'arn:aws:s3:::'.length)}`;

  it.each([
    ['tag key', (n: number) => ({ tags: [{ key: 'k'.repeat(n), value: 'v' }] }), MAX_TAG_KEY_LENGTH],
    ['tag value', (n: number) => ({ tags: [{ key: 'k', value: 'v'.repeat(n) }] }), MAX_TAG_VALUE_LENGTH],
    ['ARN pattern', (n: number) => ({ arnPatterns: [arn(n)] }), MAX_ARN_PATTERN_LENGTH],
  ])('accepts a %s at the AWS maximum length and rejects one character more', (_, filterWith, limit) => {
    expect(create(filterWith(limit)).success).toBe(true);
    const over = create(filterWith(limit + 1));
    expect(over.success).toBe(false);
    expect(over.error?.issues).toHaveLength(1);
    expect(over.error?.issues[0].code).toBe('too_big');
  });
});

describe('resource filter stored size (one DynamoDB item, 400 KB)', () => {
  const ou = (index: number) => `ou-${'a'.repeat(32)}-${String(index).padStart(32, '0')}`;
  const arn = (index: number) => `arn:aws:s3:::${String(index).padStart(2048 - 'arn:aws:s3:::'.length, 'b')}`;
  const accounts = Array.from({ length: MAX_ACCOUNT_IDS }, (_, index) => String(100000000000 + index));
  const ous = Array.from({ length: MAX_ORGANIZATIONAL_UNITS }, (_, index) => ou(index));
  const tags = Array.from({ length: MAX_RESOURCE_FILTER_TAGS }, (_, index) => ({
    key: String(index).padStart(MAX_TAG_KEY_LENGTH, 'k'),
    value: 'v'.repeat(MAX_TAG_VALUE_LENGTH),
  }));
  const tooLarge = (result: ReturnType<typeof CreateFilterRequestSchema.safeParse>) =>
    (result.error?.issues ?? []).filter((issue) => issue.message.startsWith('Resource filter is too large to store'));

  it('accepts a filter with every list at its limit when its values fit in one item', () => {
    // 10,000 accounts (120,000 bytes) + 2,000 OUs (136,000) + 50 maximum-length tags (19,200) + 50 maximum-length
    // ARN patterns (102,400) = 377,600 bytes.
    const result = CreateFilterRequestSchema.safeParse({
      ...EMPTY_FILTER,
      accountIds: accounts,
      organizationalUnits: ous,
      tags,
      arnPatterns: Array.from({ length: 50 }, (_, index) => arn(index)),
    });
    expect(result.success).toBe(true);
  });

  it('rejects the worst case, every list at its limit and every value at its maximum length, with one size issue', () => {
    const result = CreateFilterRequestSchema.safeParse({
      ...EMPTY_FILTER,
      accountIds: accounts,
      organizationalUnits: ous,
      tags,
      arnPatterns: Array.from({ length: MAX_RESOURCE_FILTER_ARN_PATTERNS }, (_, index) => arn(index)),
    });
    expect(result.success).toBe(false);
    expect(result.error?.issues).toHaveLength(1);
    expect(tooLarge(result)).toHaveLength(1);
  });

  it('applies the same size check to an update', () => {
    const result = UpdateFilterRequestSchema.safeParse({
      ...EMPTY_FILTER,
      version: 1,
      accountIds: accounts,
      organizationalUnits: ous,
      arnPatterns: Array.from({ length: MAX_RESOURCE_FILTER_ARN_PATTERNS }, (_, index) => arn(index)),
    });
    expect(tooLarge(result)).toHaveLength(1);
  });

  it('counts stored bytes, so the limit is the item budget and not the JSON request length', () => {
    expect(MAX_RESOURCE_FILTER_STORED_BYTES).toBeLessThan(400 * 1024);
  });
});
