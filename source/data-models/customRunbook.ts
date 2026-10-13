// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { z } from 'zod';

// --- Branded RunbookId ---

/** Branded type for RunbookId — prevents mixing up arbitrary strings with runbook identifiers */
export type RunbookId = string & { readonly __brand: 'RunbookId' };
export const RunbookIdSchema = z.uuid().transform((val) => val as RunbookId);

// --- RunbookStatus ---

export type RunbookStatus = 'DRAFT' | 'DEPLOYED';

/**
 * GSI on the Custom Runbook table that answers "which custom runbook serves this
 * control, and is it deployed?" — used by the API's control lookups and the
 * custom-runbook repository's `findByControlId`.
 */
export const CUSTOM_RUNBOOK_CONTROL_STATUS_GSI = 'controlId-status-index';

/** Distinguishes custom (user-created) runbooks from built-in (solution-shipped) SSM documents. */
export type RunbookType = 'custom' | 'builtin';

// --- Per-member deployment state ---

/**
 * State of one member account's own copy of a custom runbook's SSM document.
 *
 * Custom runbooks are deployed **copy-per-member**: each member account gets its
 * own SSM Automation document and scoped execution role, and no document is
 * shared out of the admin account. That means the admin-account record alone
 * can't answer "is this account actually running the version we think it is?",
 * so each account's installed version is tracked here.
 *
 * Registering a new version does not push it anywhere. Accounts that already ran
 * the previous version are carried onto the new version's record as `PENDING` —
 * staged and ready for release — and stay that way until a deploy names them in
 * `member_account_ids`. That makes a per-account staged rollout the default and
 * leaves version skew visible instead of silent.
 */
export interface MemberDeploymentState {
  /** Custom runbook version whose YAML is installed in this account. */
  runbookVersion: number;
  /** SSM document version reported by that account after create/update. */
  ssmDocumentVersion: string;
  /**
   * DEPLOYED — this account runs `runbookVersion`.
   * PENDING — a newer version is registered and awaiting release to this account.
   * FAILED — the last release attempt to this account failed; see `error`.
   */
  status: 'DEPLOYED' | 'PENDING' | 'FAILED';
  /** ISO timestamp of the last attempt, successful or not. */
  attemptedAt: string;
  /** Failure reason. Present only when status is FAILED. */
  error?: string;
}

export const SECURITY_CONTROL_STANDARD_VERSION = '2.0.0';

/**
 * Managed Custom Runbooks are always deployed under the consolidated Security Control (SC)
 * standard, so their SSM document names are `ASR-Custom-SC_{version}_{control}`. This is the
 * trusted standard short-name; deploy derives the document name from it and the version
 * constant rather than from caller-supplied values, which are not authoritative.
 */
export const SECURITY_CONTROL_STANDARD_NAME = 'SC';

// --- Test-account gate ---

/**
 * The PASSED or FAILED result of a custom runbook version's test-account run.
 */
export type RunbookTestStatus = 'PASSED' | 'FAILED';

export type RunbookTestResult = Required<
  Pick<
    RunbookMetadata,
    'testStatus' | 'testedAt' | 'testAccountId' | 'testedContentDigest' | 'testedIamActions' | 'testRoleArn'
  >
> &
  Pick<RunbookMetadata, 'testError'>;

// --- RunbookMetadata (DynamoDB record) ---

/**
 * DynamoDB metadata record for a Custom Runbook.
 * Each version of a Custom Runbook gets its own record.
 * The YAML content and Python scripts are stored in S3 (referenced by s3Key/scriptS3Key).
 */
export interface RunbookMetadata {
  runbookId: RunbookId;
  version: number;
  controlId: string;
  serviceName: string;
  description: string;
  remediationAction: string;
  status: RunbookStatus;
  s3Key: string;
  scriptS3Key?: string;
  createdBy: string;
  createdAt: string;
  deployedBy?: string;
  deployedAt?: string;
  ssmDocumentName?: string;
  ssmDocumentVersion?: string;
  remediationRole?: string;
  /**
   * Per-member-account deployment state, keyed by 12-digit account ID. Written
   * one account at a time so a failure in one account never rolls back another,
   * and read back to detect version skew across the fleet.
   */
  deployedAccounts?: Record<string, MemberDeploymentState>;
  /**
   * SHA-256 of the exact YAML bytes `register` wrote to `s3Key`. Register is the
   * only writer of that object and never overwrites it (a new register claims
   * version N+1 under a new key), so this is the authoritative fingerprint of
   * the version's content. `deploy` recomputes the hash of the S3 object and
   * compares, which detects out-of-band tampering with the bucket.
   */
  registeredContentDigest?: string;
  // Test-run results for the version's mandatory test-account run.
  testStatus?: RunbookTestStatus;
  testedAt?: string;
  testAccountId?: string;
  testError?: string;
  /**
   * SHA-256 of the YAML the caller passed to `test_runbook_yaml`. Compared
   * against `registeredContentDigest` when the outcome is recorded, so testing
   * bytes other than the registered ones is refused there — where it is
   * actionable — rather than surfacing later as a deploy-time mismatch.
   */
  testedContentDigest?: string;
  /**
   * Canonical, sorted IAM action set granted to the version-and-permission-set
   * scoped role that executed the test. Deploy compares this with
   * `required_iam_actions`, so any permission-set change requires another test.
   */
  testedIamActions?: string[];
  /** ARN of the bounded role SSM assumed for the recorded test. */
  testRoleArn?: string;
}

// --- Zod input schemas for MCP tools ---

// Matches AWS Security Hub consolidated control IDs: a service token, a dot, and
// a suffix. The suffix is usually a number (`S3.9`, `EC2.1`, `AutoScaling.1`,
// `CloudWatch.16`) but is alphanumeric for some controls ASR supports
// (`Inspector.InstanceVulnerability`, `GuardDuty.IAMUser`,
// `Macie.SensitiveDataS3Object`), so it allows letters too. AWS control IDs never
// contain hyphens, so the character classes deliberately omit them. Used by the
// tools that let a user *name a specific control* to author or query a runbook
// (generate/list/deploy), where a malformed ID should be rejected up front.
//
// The tool that instead receives a control ID that ASR itself already produced —
// `CheckDeployReadinessSchema` — relaxes this to `.min(1)` on purpose: the value
// there originates from a finding or a prior tool result rather than free-form
// operator input, so re-validating its shape would only risk rejecting a
// legitimate AWS ID this pattern hasn't been updated for.
const controlIdPattern = /^[A-Za-z0-9]+\.[A-Za-z0-9]+$/;

/** 12-digit AWS account ID. */
const ACCOUNT_ID_PATTERN = /^\d{12}$/;

/** Schema for generate_runbook tool input */
/** Structured guidance from Security Hub Remediation Center (or mock) */
export const RemediationGuidanceInputSchema = z.object({
  apiCall: z.object({
    service: z.string().describe('AWS service (e.g. "s3", "ec2", "rds")'),
    action: z.string().describe('API action (e.g. "PutPublicAccessBlock")'),
    parameters: z.record(z.string(), z.unknown()).optional().describe('API parameters'),
  }),
  requiredPermissions: z.array(z.string()).describe('IAM actions needed (e.g. ["s3:PutBucketPublicAccessBlock"])'),
  resourceType: z.string().optional().describe('CloudFormation resource type (e.g. "AWS::S3::Bucket")'),
  verifyAction: z.string().optional().describe('API action to verify remediation (e.g. "GetPublicAccessBlock")'),
});

export const GenerateRunbookSchema = z.object({
  description: z.string().min(10).max(4000),
  control_id: z.string().regex(controlIdPattern).optional(),
  service_name: z.string().optional(),
  dynamic_values: z
    .record(z.string(), z.string())
    .optional()
    .describe(
      'Key-value pairs for dynamic data to embed in the runbook (e.g. {"ContactEmail":"security@acme.com"}). These become SSM parameter defaults.',
    ),
  guidance: RemediationGuidanceInputSchema.optional().describe(
    'Structured remediation guidance (target API call, parameters, permissions). When provided, the runbook is generated deterministically from this data instead of requiring the agent to reason about which API to call.',
  ),
});
export type GenerateRunbookParams = z.infer<typeof GenerateRunbookSchema>;

/** Schema for get_finding_history tool input — returns change history for a finding */
export const GetFindingHistorySchema = z.object({
  finding_id: z.string().min(1).describe('Security Hub finding ARN.'),
  product_arn: z.string().optional().describe('Product ARN. Defaults to aws/securityhub.'),
  max_results: z.number().int().min(1).max(20).optional().describe('Max history records. Default 10.'),
});
export type GetFindingHistoryParams = z.infer<typeof GetFindingHistorySchema>;

/** Schema for list_findings_without_runbook tool input — finds remediation gaps */
export const ListFindingsWithoutRunbookSchema = z.object({
  compliance_status: z.enum(['PASSED', 'FAILED', 'WARNING', 'NOT_AVAILABLE']).optional(),
  workflow_status: z.enum(['NEW', 'NOTIFIED', 'RESOLVED', 'SUPPRESSED']).optional(),
});
export type ListFindingsWithoutRunbookParams = z.infer<typeof ListFindingsWithoutRunbookSchema>;

/** Schema for list_runbooks tool input */
export const ListRunbooksSchema = z.object({
  control_id: z.string().regex(controlIdPattern).optional(),
  status: z.enum(['DRAFT', 'DEPLOYED']).optional(),
  type: z.enum(['custom', 'builtin']).optional(),
});
export type ListRunbooksParams = z.infer<typeof ListRunbooksSchema>;

/** Schema for get_runbook tool input */
export const GetRunbookSchema = z.object({
  runbook_id: z.string().min(1),
});
export type GetRunbookParams = z.infer<typeof GetRunbookSchema>;

/** Schema for source_deploy tool input — build and deploy stacks */
export const SourceDeploySchema = z.object({
  action: z.enum(['update', 'create']).optional().default('update').describe('CloudFormation action.'),
});
export type SourceDeployParams = z.infer<typeof SourceDeploySchema>;

export const IAM_ACTION_SHAPE = /^([a-z][a-z0-9-]*):([A-Za-z0-9*?]+)$/;

export const FORBIDDEN_IAM_ACTION_NAMESPACES: ReadonlySet<string> = new Set(['iam', 'sts', 'organizations']);

export class IamActionValidationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'IamActionValidationError';
  }
}

export function checkIamAction(action: string, fieldName = 'iam_actions'): string | undefined {
  const match = IAM_ACTION_SHAPE.exec(action);
  if (!match) {
    return (
      `${fieldName} entry "${action}" is not a well-formed "service:Action" string (lowercase, hyphen-allowed ` +
      'service; no wildcard or colon in the service segment). A malformed entry cannot be proven safe.'
    );
  }
  const [, service, actionName] = match;
  if (/[*?]/.test(actionName)) {
    return (
      `${fieldName} entry "${action}" uses a wildcard in the action name; a specific action is required to ` +
      'enforce least privilege. A partial wildcard is not a narrowing — "s3:Get*" grants every current AND ' +
      'future s3 Get API, so what the role can do changes as AWS ships new actions. List the actions instead.'
    );
  }
  if (FORBIDDEN_IAM_ACTION_NAMESPACES.has(service.toLowerCase())) {
    return (
      `${fieldName} may not include "${action}" — the ${service.toLowerCase()} namespace is never granted to a ` +
      'custom-runbook remediation role.'
    );
  }
  return undefined;
}

export function validateIamActions(iamActions: readonly string[], fieldName = 'iam_actions'): readonly string[] {
  for (const action of iamActions) {
    const message = checkIamAction(action, fieldName);
    if (message) throw new IamActionValidationError(message);
  }
  return iamActions;
}

/** Schema for create_remediation_role tool input — create IAM role for a runbook */
export const CreateRemediationRoleSchema = z.object({
  control_id: z.string().min(1).describe('Control ID (e.g. S3.9).'),
  iam_actions: z
    .array(z.string())
    .min(1)
    .superRefine((actions, ctx) => {
      actions.forEach((action, index) => {
        const message = checkIamAction(action);
        if (message) ctx.addIssue({ code: 'custom', message, path: [index] });
      });
    })
    .describe(
      'IAM actions the runbook needs (e.g. ["s3:PutBucketLogging", "s3:GetBucketLogging"]). The iam/sts/organizations ' +
        'namespaces are rejected here, as is any wildcard in the action name — "s3:Get*" is refused, not just "s3:*" — ' +
        'and a PermissionsBoundary caps the resulting role.',
    ),
  resource_arns: z
    .array(z.string())
    .min(1, 'resource_arns must name at least one ARN; omit it entirely to leave the policy unscoped')
    .optional()
    .describe(
      'Resource ARNs to scope the policy. Omit to leave it unscoped ("*"), capped by the remediation ' +
        'PermissionsBoundary. An empty array is rejected rather than treated as unscoped, so a caller ' +
        'that meant to scope the policy cannot silently widen it.',
    ),
  standard_version: z
    .string()
    .optional()
    .describe(
      'Security Control standard version used in the role name. There is no default and nothing injects ' +
        'it, not even the deployed MCP server: pass it explicitly.',
    ),
});
export type CreateRemediationRoleParams = z.infer<typeof CreateRemediationRoleSchema>;

/** Schema for check_deploy_readiness tool input — verify all artifacts exist */
export const CheckDeployReadinessSchema = z.object({
  control_id: z.string().min(1).describe('Control ID (e.g. S3.9).'),
  remediation_name: z
    .string()
    .min(1)
    .describe(
      'Remediation name (e.g. ConfigureDynamoDBAutoScaling). Used to check ASR-{Name} doc and SO0111-{Name}-{ns} role.',
    ),
  namespace: z
    .string()
    .optional()
    .describe(
      'ASR namespace (the Namespace stack parameter) — the suffix in the SO0111-{Name}-{namespace} role ' +
        'name. There is no default and nothing injects it, not even the deployed MCP server: always pass ' +
        'it, or the call is rejected. Optional in the schema only so the rejection can name the parameter.',
    ),
  check_sc_wrapper: z
    .boolean()
    .optional()
    .describe(
      'Also check the SC wrapper document ASR-SC_<standardVersion>_{controlId} exists, at the standard ' +
        'version this deployment is configured with. Default: true.',
    ),
});
export type CheckDeployReadinessParams = z.infer<typeof CheckDeployReadinessSchema>;

/**
 * Schema for validate_runbook tool input.
 *
 * The tool returns the ASR validation ruleset (validation-rules.md) for the caller to apply;
 * it does not inspect the YAML server-side and does not emit a pass/fail verdict. There is
 * therefore no `strict` toggle — a dead `strict` field was removed because nothing read it,
 * so advertising it implied a server-side strictness mode that does not exist. `runbook_yaml`
 * is still required so the tool contract documents what the caller is validating.
 */
export const ValidateRunbookSchema = z.object({
  runbook_yaml: z.string().min(1),
});
export type ValidateRunbookParams = z.infer<typeof ValidateRunbookSchema>;

/** Schema for execute_runbook tool input — triggers remediation on a finding */
export const ExecuteRunbookSchema = z.object({
  finding_id: z.string().min(1),
  action_type: z.enum(['Remediate', 'RemediateAndGenerateTicket']).optional().default('Remediate'),
});
export type ExecuteRunbookParams = z.infer<typeof ExecuteRunbookSchema>;

/** Schema for execute_rollback tool input — triggers rollback of a previous remediation */
export const ExecuteRollbackSchema = z.object({
  finding_id: z.string().min(1).describe('The Security Hub finding ID that was remediated.'),
  execution_id: z
    .string()
    .min(1)
    .describe('The original remediation execution ID (used to locate the snapshot in S3).'),
});
export type ExecuteRollbackParams = z.infer<typeof ExecuteRollbackSchema>;

/** Schema for get_execution_status tool input — checks remediation execution status */
export const GetExecutionStatusSchema = z.object({
  finding_id: z.string().min(1),
});
export type GetExecutionStatusParams = z.infer<typeof GetExecutionStatusSchema>;

// ─── Discovery & Triage ─────────────────────────────────────────────────────

/**
 * Schema for the `findings` tool — query findings, or export them.
 *
 * One tool, two modes: when `format` is omitted it returns a JSON search result; when
 * `format` is `csv` or `json` it returns an export artifact for ITSM/Jira. The cloud
 * registry routes the two modes to the `/findings` and `/findings/export` API routes.
 */
export const FindingsSchema = z.object({
  control_id: z.string().optional().describe('Filter by control ID (e.g. "S3.5")'),
  severity: z.enum(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']).optional(),
  account_id: z.string().optional().describe('Filter by account ID (search mode only)'),
  compliance_status: z.enum(['FAILED', 'PASSED', 'WARNING', 'NOT_AVAILABLE']).optional().default('FAILED'),
  max_results: z.number().int().min(1).max(100).optional().default(25).describe('Max results (search mode only)'),
  format: z
    .enum(['csv', 'json'])
    .optional()
    .describe('Set to export instead of search: emits the findings as a CSV or JSON artifact.'),
});
export type FindingsParams = z.infer<typeof FindingsSchema>;

/** Schema for list_controls — list all controls with auto-remediation status */
export const ListControlsSchema = z.object({
  standard: z.string().optional().describe('Filter by standard (e.g. "SC", "AFSBP", "NIST80053")'),
  auto_remediation_enabled: z.boolean().optional().describe('Filter by auto-remediation status'),
});
export type ListControlsParams = z.infer<typeof ListControlsSchema>;

// ─── Resource Filters (Policy CRUD) ─────────────────────────────────────────

/** Schema for list_filters — list all resource filters */
export const ListFiltersSchema = z.object({
  control_id: z.string().optional().describe('Filter by control ID'),
});
export type ListFiltersParams = z.infer<typeof ListFiltersSchema>;

/** Schema for create_filter — create a resource filter */
export const CreateFilterSchema = z.object({
  control_id: z.string().optional().describe('Scope to a specific control, or omit for global'),
  filter_type: z.enum(['TAG', 'ACCOUNT', 'RESOURCE_ID']).describe('Type of filter'),
  key: z.string().optional().describe('Tag key (required for TAG type)'),
  value: z.string().describe('Tag value, account ID, or resource ID'),
  filter_mode: z.enum(['INCLUDE', 'EXCLUDE']).describe('Include or exclude matching resources'),
});
export type CreateFilterParams = z.infer<typeof CreateFilterSchema>;

/** Schema for update_filter — update an existing resource filter */
export const UpdateFilterSchema = z.object({
  filter_id: z.string().min(1).describe('Filter ID to update'),
  filter_mode: z.enum(['INCLUDE', 'EXCLUDE']).optional(),
  value: z.string().optional(),
});
export type UpdateFilterParams = z.infer<typeof UpdateFilterSchema>;

/** Schema for delete_filter — delete a resource filter */
export const DeleteFilterSchema = z.object({
  filter_id: z.string().min(1).describe('Filter ID to delete'),
});
export type DeleteFilterParams = z.infer<typeof DeleteFilterSchema>;

// ─── Notifications (config CRUD) ─────────────────────────────────────────────

const NotificationChannelSchema = z
  .enum(['email', 'slack', 'jira', 'servicenow', 'sns'])
  .describe('Delivery channel type');

/** Schema for list_notifications — list notification configurations */
export const ListNotificationsSchema = z.object({
  control_id: z.string().optional().describe('Filter configurations scoped to a control'),
});
export type ListNotificationsParams = z.infer<typeof ListNotificationsSchema>;

/** Schema for create_notification — create a notification configuration */
export const CreateNotificationSchema = z.object({
  name: z.string().min(1).describe('Human-readable configuration name'),
  channel: NotificationChannelSchema,
  notification_type: z.enum(['finding', 'remediation']).describe('Whether to notify on findings or on remediations'),
  recipients: z.array(z.string()).optional().describe('Custom email addresses or recipient identifiers'),
  severity_threshold: z
    .enum(['Critical', 'High', 'Medium', 'Low', 'Informational', 'All'])
    .optional()
    .describe('Minimum severity that triggers a notification'),
  control_ids: z.array(z.string()).optional().describe('Controls this configuration applies to; omit for all controls'),
  batch_window_minutes: z
    .number()
    .int()
    .min(5)
    .optional()
    .describe('Aggregate notifications over this window (minutes); omit for immediate'),
  channel_config: z
    .record(z.string(), z.unknown())
    .optional()
    .describe('Channel-specific settings (e.g. Slack channel ID, Jira project, SNS topic ARN)'),
});
export type CreateNotificationParams = z.infer<typeof CreateNotificationSchema>;

/** Schema for update_notification — update an existing configuration by ID */
export const UpdateNotificationSchema = z.object({
  configuration_id: z.string().min(1).describe('Notification configuration ID to update'),
  name: z.string().min(1).optional(),
  severity_threshold: z.enum(['Critical', 'High', 'Medium', 'Low', 'Informational', 'All']).optional(),
  control_ids: z.array(z.string()).optional(),
  batch_window_minutes: z.number().int().min(5).optional(),
  channel_config: z.record(z.string(), z.unknown()).optional(),
});
export type UpdateNotificationParams = z.infer<typeof UpdateNotificationSchema>;

/** Schema for delete_notification — remove a configuration by ID */
export const DeleteNotificationSchema = z.object({
  configuration_id: z.string().min(1).describe('Notification configuration ID to delete'),
});
export type DeleteNotificationParams = z.infer<typeof DeleteNotificationSchema>;

/** Schema for test_notification — send a test notification through a configuration */
export const TestNotificationSchema = z.object({
  configuration_id: z.string().min(1).describe('Notification configuration ID to test'),
});
export type TestNotificationParams = z.infer<typeof TestNotificationSchema>;

// ─── Verification & Reporting ───────────────────────────────────────────────

/**
 * Schema for the `remediations` tool — query remediation history, or export it.
 *
 * One tool, two modes: `format` omitted → JSON search result; `format` set → CSV/JSON
 * export artifact. The cloud registry routes the two modes to the `/remediations` and
 * `/export` API routes.
 */
export const RemediationsSchema = z.object({
  control_id: z.string().optional(),
  account_id: z.string().optional().describe('Filter by account ID (search mode only)'),
  status: z.enum(['SUCCESS', 'FAILED', 'ROLLED_BACK', 'IN_PROGRESS']).optional(),
  max_results: z.number().int().min(1).max(100).optional().default(25).describe('Max results (search mode only)'),
  format: z
    .enum(['csv', 'json'])
    .optional()
    .describe('Set to export instead of search: emits the remediation history as a CSV or JSON artifact.'),
});
export type RemediationsParams = z.infer<typeof RemediationsSchema>;

// ─── Remediation Guidance ────────────────────────────────────────────────────

/** Schema for list_remediation_targets — prioritized targets with urgency scores */
export const ListRemediationTargetsSchema = z.object({
  severity_filter: z.enum(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']).optional(),
  max_results: z.number().int().min(1).max(50).optional().default(10),
});
export type ListRemediationTargetsParams = z.infer<typeof ListRemediationTargetsSchema>;

/** Schema for get_remediation_guidance — full guidance per target */
export const GetRemediationGuidanceSchema = z.object({
  target_id: z.string().min(1).describe('Remediation target ID from list_remediation_targets'),
  include_iac: z.array(z.enum(['cloudformation', 'terraform', 'cdk'])).optional(),
});
export type GetRemediationGuidanceParams = z.infer<typeof GetRemediationGuidanceSchema>;

/** Schema for execute_mitigation — execute immediate mitigation from guidance */
export const ExecuteMitigationSchema = z.object({
  target_id: z.string().min(1).describe('Remediation target ID'),
  confirm: z.boolean().describe('Must be true to execute. Safety gate.'),
});
export type ExecuteMitigationParams = z.infer<typeof ExecuteMitigationSchema>;

// ─── Intent-based Policy ─────────────────────────────────────────────────────
//
// PLACEHOLDER — planned for a future release, not yet wired up. These two schemas
// are declared so the tool contract can reserve the names, but neither tool is
// advertised or dispatchable: both are absent from
// `source/lambdas/mcp-server/toolSchema.json`, have no API route
// (`/policies/preview`, `/policies/apply`), and hold no access tier in
// `TOOLS_BY_TIER`. See the matching note in `contract/toolContract.ts`. Wiring
// them up means adding the routes, the toolSchema entries, and the tiers in one
// change — until then nothing can call these, so the schemas describe an intended
// shape, not a live tool.

/**
 * Schema for preview_policy_change — translate a natural-language intent into a filter-config preview.
 * PLACEHOLDER (see the section note above): declared but not yet advertised or routed.
 */
export const PreviewPolicyChangeSchema = z.object({
  intent: z
    .string()
    .min(5)
    .describe(
      'Natural language description of the policy change (e.g. "never auto-remediate resources tagged env=production")',
    ),
});
export type PreviewPolicyChangeParams = z.infer<typeof PreviewPolicyChangeSchema>;

/**
 * Schema for apply_policy_change — apply a previously previewed policy change.
 * PLACEHOLDER (see the section note above): declared but not yet advertised or routed.
 */
export const ApplyPolicyChangeSchema = z.object({
  preview_id: z.string().min(1).describe('Preview ID returned by preview_policy_change'),
});
export type ApplyPolicyChangeParams = z.infer<typeof ApplyPolicyChangeSchema>;

// `update_controls` deliberately has no schema here. The tool validates and advertises
// `BulkEditRequestSchema` from ./securityControl — the `{operation, data[]}` shape the
// `/controls/bulk-edit` route actually accepts. An `UpdateControlsSchema` used to sit here
// declaring `{control_ids, auto_remediation_enabled}`; nothing validated against it, but
// `TOOL_CONTRACTS.update_controls` pointed at it, so the contract and the route disagreed and
// anything generating a client or docs from the contract emitted a call the tool rejects.

/**
 * Schema for the custom-runbook developer fast-loop tool — `push` a runbook's
 * SSM document into a member account, `execute` it against a finding, or read
 * `status`. This is a dev iteration loop, NOT drift detection; the `push` and
 * `execute` writes bypass the versioned register/deploy path and are gated
 * behind an enablement flag (off in production) in the service layer.
 *
 * The wire name (`drift_detection` tool + `/runbooks/drift-detection` route) is
 * retained here on purpose: renaming it to something self-describing (e.g.
 * `runbook_dev_loop`) also has to change the MCP tool registry that maps the
 * tool name to this route, so the rename is coordinated with that registry
 * change rather than split across the two.
 */
export const DriftDetectionSchema = z.discriminatedUnion('action', [
  z.object({
    action: z.literal('push'),
    control_id: z.string().min(1),
    runbook_yaml: z.string().min(1),
    account_id: z.string().regex(ACCOUNT_ID_PATTERN),
  }),
  z.object({
    action: z.literal('execute'),
    control_id: z.string().min(1),
    account_id: z.string().regex(ACCOUNT_ID_PATTERN),
    finding_id: z.string().min(1),
  }),
  z.object({
    action: z.literal('status'),
    execution_id: z.string().min(1),
    account_id: z.string().regex(ACCOUNT_ID_PATTERN),
  }),
]);
export type DriftDetectionParams = z.infer<typeof DriftDetectionSchema>;

/**
 * Member accounts to release a deploy to. Each must be a 12-digit AWS account ID
 * (the value drives cross-account IAM role creation and SSM document installation,
 * so a malformed entry would otherwise surface as an opaque STS error mid-rollout).
 *
 * Required with at least one account: a deploy releases the runbook copy-per-member
 * (each named account gets its own SSM document and scoped remediation role), so a
 * deploy that targets no account creates no executable remediation and must be
 * rejected rather than producing a DEPLOYED record that can run nowhere. Use
 * `register` to stage a version without releasing it.
 *
 * Deploy runs synchronously and processes each account serially — two
 * cross-account AssumeRole chains (role provisioning, then document install) plus
 * IAM, SSM, and DynamoDB writes per account — so the bound caps a request at a
 * size that can finish within API Gateway's ~29s integration timeout before the
 * client disconnects. Release to a larger fleet by splitting the rollout across
 * multiple deploy calls.
 */
const MemberAccountIdsSchema = z
  .array(z.string().regex(ACCOUNT_ID_PATTERN, 'member_account_ids entries must be 12-digit AWS account IDs'))
  .min(1)
  .max(10);

/** deploy_runbook `register` action — store runbook YAML as a new DRAFT version. */
export const RegisterRunbookSchema = z.object({
  action: z.literal('register'),
  runbook_yaml: z.string().min(1),
  control_id: z.string().regex(controlIdPattern),
  runbook_id: RunbookIdSchema.optional(),
  python_script: z.string().optional(),
  service_name: z.string().optional(),
  description: z.string().optional(),
});
export type RegisterRunbookParams = z.infer<typeof RegisterRunbookSchema>;

/** deploy_runbook `deploy` action — transition a version to DEPLOYED and release it to member accounts. */
export const DeployRunbookActionSchema = z.object({
  action: z.literal('deploy'),
  runbook_id: RunbookIdSchema,
  control_id: z.string().regex(controlIdPattern),
  /**
   * Informational only. Managed Custom Runbooks are always the consolidated Security Control
   * (SC) standard at SECURITY_CONTROL_STANDARD_VERSION, so the deploy service derives the
   * authoritative standard/version from those constants when it builds the SSM document name
   * for the built-in collision preflight and the install. These fields are NOT trusted for
   * that name — a wrong value here cannot make the guard probe the wrong document — and are
   * retained only for wire-contract compatibility.
   */
  security_standard: z.string().min(1),
  standard_version: z.string().min(1),
  required_iam_actions: z.array(z.string()).optional(),
  member_account_ids: MemberAccountIdsSchema,
  /**
   * Which registered version to release. Omitted means the latest, which is the
   * forward case: register a new version, then deploy it.
   *
   * Naming an older version is how a rollback is performed — the documented
   * mechanism is `deploy_runbook(deploy, runbook_id, version=N)`, which repoints
   * the SSM document at that version's stored YAML. Every version is retained in
   * S3, so reverting is content-addressed rather than a re-authoring step.
   *
   * This field is load-bearing precisely because it used to be absent: the object
   * strips unknown keys, so a caller passing `version` got no error and silently
   * redeployed the newest version instead of the one they named — the opposite of
   * a rollback when the newest version is the one being rolled back.
   */
  version: z.number().int().positive().optional(),
});
export type DeployRunbookActionParams = z.infer<typeof DeployRunbookActionSchema>;

/**
 * Schema for deploy_runbook tool input — a discriminated union on `action`, so
 * the per-action required fields are encoded in the parsed type and the
 * deployment service does not re-check them at runtime.
 */
export const DeployRunbookSchema = z.discriminatedUnion('action', [RegisterRunbookSchema, DeployRunbookActionSchema]);
export type DeployRunbookParams = z.infer<typeof DeployRunbookSchema>;

export interface GenerateRunbookResult {
  rules: string;
  examples?: string;
  guardrails?: string;
  description: string;
}

export interface RunbookMetadataSummary {
  runbook_id: string;
  control_id: string;
  type: RunbookType;
  status: RunbookStatus;
  version: number;
  description: string;
  service_name: string;
  created_at: string;
  deployed_at?: string;
  ssm_document_name?: string;
}

export interface DeployRunbookResult {
  action: 'register' | 'deploy';
  runbook_id: RunbookId;
  version: number;
  status: RunbookStatus;
  control_id?: string;
  s3_key?: string;
  document_name?: string;
  document_version?: string;
  remediation_role?: string;
  role_provisioning?: {
    succeeded: string[];
    failed: Array<{ accountId: string; error: string }>;
  };
  /** Result of copying the SSM document into each member account. */
  document_deployment?: {
    succeeded: string[];
    failed: Array<{ accountId: string; error: string }>;
  };
  /**
   * Which member accounts are actually running the version just deployed.
   * `consistent` is false whenever any known account is still staged or failed.
   * `accounts_pending_release` is the release backlog: accounts that ran an
   * earlier version and are waiting to be named in a later deploy.
   */
  version_consistency?: {
    consistent: boolean;
    target_version: number;
    accounts_on_target: string[];
    accounts_pending_release: Array<{ accountId: string; runbookVersion: number }>;
    accounts_failed: string[];
  };
}
