// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { z } from 'zod';
import { ValidationError } from '../backends/common/errors';
import {
  GenerateRunbookSchema,
  GetFindingHistorySchema,
  ListFindingsWithoutRunbookSchema,
  ListRunbooksSchema,
  GetRunbookSchema,
  ValidateRunbookSchema,
  DeployRunbookSchema,
  ExecuteRunbookSchema,
  ExecuteRollbackSchema,
  GetExecutionStatusSchema,
  SourceDeploySchema,
  CheckDeployReadinessSchema,
  FindingsSchema,
  ListControlsSchema,
  ListFiltersSchema,
  CreateFilterSchema,
  UpdateFilterSchema,
  DeleteFilterSchema,
  ListNotificationsSchema,
  CreateNotificationSchema,
  UpdateNotificationSchema,
  DeleteNotificationSchema,
  TestNotificationSchema,
  RemediationsSchema,
  PreviewPolicyChangeSchema,
  ApplyPolicyChangeSchema,
  BulkEditRequest,
  BulkEditUpdateRequestSchema,
  checkIamAction,
} from '@asr/data-models';

/**
 * Contract for a single MCP tool.
 *
 * The contract is backend-agnostic — it only describes the tool surface area
 * (name, description, input schema). The MCP server Lambda picks the
 * implementation: a direct executor from `backends/common/` or a proxied call to
 * an ASR API route (see source/lambdas/mcp-server/mcpServerHandler.ts).
 */
export interface ToolContract<TArgs = unknown> {
  readonly name: string;
  readonly description: string;
  readonly schema: z.ZodSchema<TArgs>;
}

/**
 * `update_controls` input, normalized so every field has exactly one type.
 *
 * The API's `BulkEditRequestSchema` is a discriminated union in which `data` is the controls
 * array under `update` but a bare filter-id string under `applyFilterToAll` /
 * `removeFilterFromAll`. AgentCore advertises a flat object with one `type` per property, so
 * that union cannot be advertised faithfully: whichever branch is kept, a client following the
 * schema cannot construct the other operations. The filter id therefore gets its own `filterId`
 * argument and `data` is only ever the controls array; {@link toBulkEditApiBody} maps back to
 * the union the API validates, so the API contract does not change.
 */
export const UpdateControlsToolSchema = z
  .object({
    operation: z.enum(['update', 'applyFilterToAll', 'removeFilterFromAll']),
    data: BulkEditUpdateRequestSchema.shape.data
      .optional()
      .describe('For `update`: the controls to write, each carrying its current `version` from list_controls.'),
    filterId: z
      .uuid()
      .optional()
      .describe('For `applyFilterToAll` / `removeFilterFromAll`: the `filterId` from list_filters.'),
  })
  .superRefine((value, context) => {
    // Each operation has exactly one payload field. The missing one is an error, and so is the
    // other one being present: toBulkEditApiBody forwards only the field its branch uses, so a
    // caller who supplies the wrong one would otherwise see their value silently ignored.
    if (value.operation === 'update') {
      if (value.data === undefined) {
        context.addIssue({ code: 'custom', path: ['data'], message: 'data is required for operation "update"' });
      }
      if (value.filterId !== undefined) {
        context.addIssue({
          code: 'custom',
          path: ['filterId'],
          message: 'filterId is not valid for operation "update"; pass the controls in data',
        });
      }
    } else {
      if (value.filterId === undefined) {
        context.addIssue({
          code: 'custom',
          path: ['filterId'],
          message: `filterId is required for operation "${value.operation}"`,
        });
      }
      if (value.data !== undefined) {
        context.addIssue({
          code: 'custom',
          path: ['data'],
          message: `data is not valid for operation "${value.operation}"; pass the filter in filterId`,
        });
      }
    }
  });
export type UpdateControlsToolArgs = z.infer<typeof UpdateControlsToolSchema>;

/**
 * Maps the normalized `update_controls` arguments to the `POST /controls/bulk-edit` body.
 *
 * The schema's refinement already requires the branch-specific field, so the guards below are
 * unreachable for parsed input. They exist so the narrowing is the compiler's, not an
 * assertion's: a caller that bypasses the schema gets the same message the schema would give.
 */
export function toBulkEditApiBody(args: UpdateControlsToolArgs): BulkEditRequest {
  if (args.operation === 'update') {
    if (args.data === undefined) throw new ValidationError('data is required for operation "update"');
    return { operation: 'update', data: args.data };
  }
  if (args.filterId === undefined) {
    throw new ValidationError(`filterId is required for operation "${args.operation}"`);
  }
  return { operation: args.operation, data: args.filterId };
}

/**
 * Schema for the `test_remediation_script` tool.
 *
 * Runs a candidate Python remediation handler as a transient SSM Automation
 * `aws:executeScript` document. Intended as the fast inner loop for authoring
 * remediations — iterate here before you commit changes to the source tree
 * and run `npm run build` + `deploy-dev.sh`.
 *
 * The tool creates an SSM document named after `control_id` (or a generated
 * ID), starts an automation execution with the provided `input_payload`,
 * polls for completion up to `timeout_seconds`, then deletes the document
 * unless `cleanup` is explicitly set to `false`. A document left behind by
 * `cleanup: false` or an interrupted run is tagged but not automatically
 * reaped — it counts against the account's SSM document quota until
 * something deletes it.
 */
export const TestRemediationScriptSchema = z.object({
  python_script: z
    .string()
    .min(10)
    .max(60000)
    .describe(
      'Inline Python source for the remediation handler. The handler must return a dict — a list or scalar return value fails with an opaque output-selector error.',
    ),
  input_payload: z
    .record(z.string(), z.unknown())
    .optional()
    .describe('Dict passed to the handler as its event parameter.'),
  handler: z.string().optional().describe('Python handler function name. Defaults to "handler".'),
  runtime: z
    .enum(['python3.11', 'python3.10', 'python3.9', 'python3.8'])
    .optional()
    .describe('Python runtime for aws:executeScript. Defaults to python3.11.'),
  control_id: z.string().optional().describe('Optional control ID used to name the transient document.'),
  automation_assume_role: z
    .string()
    .optional()
    .describe(
      'IAM role ARN SSM assumes when executing the script. There is no default and nothing injects it, not ' +
        'even the deployed MCP server: always pass it, or the call is rejected. The role must be in this ' +
        "server's account, at the root IAM path (no `role/<path>/` segment), and its name must begin with " +
        '"SO0111-Remediate-Custom-Test-" — that is the only role pattern the MCP server is allowed to ' +
        'iam:PassRole to SSM, and any other role ARN fails inside StartAutomationExecution. Optional in the ' +
        'schema only so the rejection can name the parameter.',
    ),
  timeout_seconds: z
    .number()
    .int()
    .min(30)
    .max(600)
    .optional()
    .describe(
      'Hard timeout for the test execution. Defaults to 300 seconds. Capped at 600 — the SSM ' +
        'aws:executeScript action this tool always builds does not run longer than that.',
    ),
  cleanup: z.boolean().optional().describe('Delete the transient SSM document after execution. Defaults to true.'),
  document_name: z.string().optional().describe('Explicit document name to use; otherwise one is generated.'),
});
export type TestRemediationScriptParams = z.infer<typeof TestRemediationScriptSchema>;

/**
 * Schema for the `test_runbook_yaml` tool.
 *
 * Registers a full SSM Automation runbook (YAML or JSON) as a transient
 * document, runs every `mainSteps` step end-to-end against AWS with the
 * caller-provided parameters, reports per-step status and outputs, and
 * deletes the document. The fast inner loop for full runbooks — no
 * `npm run build`, no `deploy-dev.sh`.
 *
 * When `skip_execution` is true the tool only registers + deletes the
 * document, which validates that SSM accepts the schema without running
 * anything.
 *
 * This tool is also the write side of the test-first deployment gate. Pass
 * `runbook_id` and `version` and a full run records PASSED or FAILED on that
 * version, which is the only way `deploy_runbook` will promote it. A
 * `skip_execution` run proves nothing was executed, so it never records a pass.
 *
 * A document left behind by `cleanup: false` or an interrupted run is tagged
 * but not automatically reaped — it counts against the account's SSM
 * document quota until something deletes it.
 */
export const TestRunbookYamlSchema = z
  .object({
    runbook_yaml: z
      .string()
      .min(20)
      .max(65536)
      .describe(
        "Full SSM Automation document content (YAML by default). Capped at 65536 — SSM's " +
          'CreateDocument content quota — since this is registered as-is, with no wrapper around it.',
      ),
    input_parameters: z
      .record(z.string(), z.unknown())
      .optional()
      .describe(
        'Parameters passed to StartAutomationExecution. Non-string values are JSON-encoded automatically. ' +
          'For a registered-version test, AutomationAssumeRole is set to the bounded test role.',
      ),
    document_name: z.string().optional().describe('Explicit document name to use; otherwise one is generated.'),
    document_format: z.enum(['YAML', 'JSON']).optional().describe('Format of runbook_yaml. Defaults to YAML.'),
    control_id: z.string().optional().describe('Optional control ID used to name the transient document.'),
    runbook_id: z
      .uuid()
      .optional()
      .describe(
        'Registered runbook this test belongs to (UUID, as returned by deploy_runbook register). Supply with ' +
          '`version` and `required_iam_actions` to provision its version-and-permission-set-scoped test role and ' +
          'record the outcome. Omit all three for a throwaway test run.',
      ),
    version: z
      .number()
      .int()
      .positive()
      .optional()
      .describe('Registered version being tested. Required alongside `runbook_id` and `required_iam_actions`.'),
    required_iam_actions: z
      .array(z.string())
      .min(1)
      .optional()
      .superRefine((actions, context) => {
        actions?.forEach((action, index) => {
          const message = checkIamAction(action, 'required_iam_actions');
          if (message) context.addIssue({ code: 'custom', message, path: [index] });
        });
      })
      .describe(
        'Exact IAM actions the registered runbook needs. Required with runbook_id/version. ASR provisions a ' +
          'bounded test role scoped to this version and permission set; deploy_runbook later requires the same set.',
      ),
    timeout_seconds: z
      .number()
      .int()
      .min(30)
      .max(800)
      .optional()
      .describe(
        'Hard timeout for the whole execution. Defaults to 600 seconds. This bounds the overall ' +
          "multi-step Automation execution, not a single step's own timeoutSeconds — a runbook using " +
          'aws:waitForAwsResourceProperty or aws:runCommand can legitimately run well past the 600s ' +
          'cap that applies specifically to a single aws:executeScript step. Capped at 800s because ' +
          'this tool polls to completion inside the MCP Lambda: the poll budget is timeout_seconds + 30, ' +
          'and the Lambda is bounded at 900s by both Lambda and AgentCore synchronous-request limits, ' +
          'leaving the remainder for document create/delete. An Automation that genuinely needs longer ' +
          'cannot be observed synchronously and needs an async execute-then-poll path instead.',
      ),
    cleanup: z.boolean().optional().describe('Delete the transient SSM document after execution. Defaults to true.'),
    skip_execution: z
      .boolean()
      .optional()
      .describe(
        'If true, only register the document (to verify SSM accepts it) and then delete it. No execution is started.',
      ),
  })
  .superRefine((params, context) => {
    const registrationFields = [params.runbook_id, params.version, params.required_iam_actions];
    const suppliedCount = registrationFields.filter((value) => value !== undefined).length;
    if (suppliedCount !== 0 && suppliedCount !== registrationFields.length) {
      context.addIssue({
        code: 'custom',
        message:
          'runbook_id, version, and required_iam_actions must be supplied together for a recorded test, ' +
          'or all omitted for a throwaway test.',
      });
    }
  });
export type TestRunbookYamlParams = z.infer<typeof TestRunbookYamlSchema>;

/**
 * Schema for the `check_runbook_drift` tool.
 *
 * Compares the caller-provided runbook content against the SSM Automation
 * document already deployed under `document_name` in the current account and
 * region. Returns a structured diff report so the caller can tell whether the
 * local file matches what is live in AWS.
 *
 * The comparison is performed on parsed YAML (with fallback to plain text)
 * so reformatting, trailing whitespace, and key ordering do not register as
 * drift. Either `runbook_yaml` (inline) or `runbook_path` (path relative to
 * the workspace) must be provided.
 */
export const CheckRunbookDriftSchema = z
  .object({
    document_name: z.string().min(1).describe('SSM Automation document name to compare against.'),
    runbook_yaml: z
      .string()
      .min(1)
      .optional()
      // Wording matters: the mutual exclusion below is a Zod `.refine`, which JSON Schema
      // cannot express, so the advertised description is the only place a caller learns
      // that supplying both is rejected. A test asserts both fields say "exactly one".
      .describe('Inline runbook content. Provide exactly one of runbook_yaml or runbook_path.'),
    runbook_path: z
      .string()
      .optional()
      .describe(
        'Path to a runbook file, relative to the workspace root. Provide exactly one of ' +
          'runbook_yaml or runbook_path. Requires a configured workspace (ASR_WORKSPACE_ROOT); ' +
          'use runbook_yaml (inline content) when none is configured.',
      ),
    document_format: z.enum(['YAML', 'JSON']).optional().describe('Format hint. Defaults to YAML.'),
  })
  .refine((data) => Boolean(data.runbook_yaml) !== Boolean(data.runbook_path), {
    message: 'Provide exactly one of runbook_yaml or runbook_path.',
  });
export type CheckRunbookDriftParams = z.infer<typeof CheckRunbookDriftSchema>;

/**
 * Central catalog of all tool contracts, organized by domain.
 *
 * Three layers:
 * - AWS_TOOLS: Direct AWS service interactions (Security Hub, Config, SSM, IAM)
 * - REMEDIATION_TOOLS: Authoring, testing, and executing ASR remediations
 * - INFRA_TOOLS: Deploying stacks, debugging CFN, managing infrastructure
 */

// ─── AWS Tools ──────────────────────────────────────────────────────────────
// DEPRECATED: These are fallbacks for environments without a native AWS MCP.
// The asr-remediation-author agent should use @aws/mcp-server instead.
// These will be removed in a future version once all environments have
// native AWS MCP connectivity.

export const AWS_TOOLS = {
  get_finding_history: {
    name: 'get_finding_history',
    description:
      'Get the change history of a Security Hub finding combined with ASR remediation history from DynamoDB. This is ASR-specific (merges two sources) and NOT available from the native AWS MCP.',
    schema: GetFindingHistorySchema,
  },
} as const satisfies Record<string, ToolContract>;

// ─── Remediation Tools ──────────────────────────────────────────────────────
// Author, validate, test, and execute ASR remediations.

export const REMEDIATION_TOOLS = {
  list_findings_without_runbook: {
    name: 'list_findings_without_runbook',
    description:
      'List Security Hub control IDs that have active FAILED findings but no deployed ASR runbook. Returns remediation gaps.',
    schema: ListFindingsWithoutRunbookSchema,
  },
  generate_runbook: {
    name: 'generate_runbook',
    description:
      'Generate an SSM runbook from a Security Hub finding description. Pass dynamic_values (e.g. {"ContactEmail":"sec@acme.com"}) to pre-configure operator-specific defaults in the generated YAML.',
    schema: GenerateRunbookSchema,
  },
  validate_runbook: {
    name: 'validate_runbook',
    description:
      'Return the ASR runbook validation ruleset to apply to an SSM runbook YAML document. This returns ' +
      'the rules for the caller to check against; it does not inspect the YAML server-side or emit a ' +
      'pass/fail verdict.',
    schema: ValidateRunbookSchema,
  },
  list_runbooks: {
    name: 'list_runbooks',
    description: 'List available ASR runbooks (SSM Automation documents).',
    schema: ListRunbooksSchema,
  },
  get_runbook: {
    name: 'get_runbook',
    description: 'Get a runbook definition (YAML content and parameters).',
    schema: GetRunbookSchema,
  },
  test_remediation_script: {
    name: 'test_remediation_script',
    description:
      'Fast inner-loop test for a candidate Python remediation script. Creates a transient SSM document, runs it, returns output, and deletes.',
    schema: TestRemediationScriptSchema,
  },
  test_runbook_yaml: {
    name: 'test_runbook_yaml',
    description:
      'End-to-end test for a full SSM Automation runbook YAML. Set skip_execution=true to only validate SSM accepts the schema.',
    schema: TestRunbookYamlSchema,
  },
  check_runbook_drift: {
    name: 'check_runbook_drift',
    description: 'Diff a local runbook against the document currently deployed under the same name.',
    schema: CheckRunbookDriftSchema,
  },
  execute_runbook: {
    name: 'execute_runbook',
    description: 'Execute a runbook against a finding via the ASR Orchestrator Step Function.',
    schema: ExecuteRunbookSchema,
  },
  execute_rollback: {
    name: 'execute_rollback',
    description:
      'Roll back a previous remediation. Starts the Orchestrator with Rollback=ROLLBACK, restoring the resource to its pre-remediation state from the S3 snapshot.',
    schema: ExecuteRollbackSchema,
  },
  get_execution_status: {
    name: 'get_execution_status',
    description: 'Get Orchestrator execution status for a finding (searches Step Functions).',
    schema: GetExecutionStatusSchema,
  },
} as const satisfies Record<string, ToolContract>;

// ─── Infrastructure Tools ───────────────────────────────────────────────────
// Deploy stacks, manage IAM roles, debug CloudFormation failures.

export const INFRA_TOOLS = {
  deploy_runbook: {
    name: 'deploy_runbook',
    description: 'Deploy (create/update) an SSM Automation document. Use service_name for child docs (ASR-{Name}).',
    schema: DeployRunbookSchema,
  },
  check_deploy_readiness: {
    name: 'check_deploy_readiness',
    description: 'Verify all deployment artifacts exist: child SSM document, IAM role, and SC wrapper.',
    schema: CheckDeployReadinessSchema,
  },
  source_deploy: {
    name: 'source_deploy',
    description: 'Build and deploy the ASR solution to the dev account. Runs deploy-dev.sh (10-15 minutes).',
    schema: SourceDeploySchema,
  },
} as const satisfies Record<string, ToolContract>;

// ─── Discovery & Triage Tools ───────────────────────────────────────────────

export const DISCOVERY_TOOLS = {
  findings: {
    name: 'findings',
    description:
      'Search Security Hub findings by control, severity, account, and compliance status; or export them as CSV/JSON when `format` is set (merges the former search_findings + export_findings).',
    schema: FindingsSchema,
  },
  list_controls: {
    name: 'list_controls',
    description: 'List all ASR controls with their auto-remediation status and configuration.',
    schema: ListControlsSchema,
  },
} as const satisfies Record<string, ToolContract>;

// ─── Policy Tools (Resource Filters + Intent-based) ─────────────────────────

export const POLICY_TOOLS = {
  list_filters: {
    name: 'list_filters',
    description: 'List all resource filters (exclusions/inclusions) configured in ASR.',
    schema: ListFiltersSchema,
  },
  create_filter: {
    name: 'create_filter',
    description: 'Create a resource filter to include or exclude resources from auto-remediation.',
    schema: CreateFilterSchema,
  },
  update_filter: {
    name: 'update_filter',
    description: 'Update an existing resource filter by ID.',
    schema: UpdateFilterSchema,
  },
  delete_filter: {
    name: 'delete_filter',
    description: 'Delete a resource filter by ID.',
    schema: DeleteFilterSchema,
  },
  update_controls: {
    name: 'update_controls',
    description:
      'Bulk enable or disable auto-remediation for one or more controls, or apply/remove a filter across all ' +
      'of them. For `operation: "update"` pass `data`: the controls to write, each carrying its current ' +
      '`version` from list_controls. For `applyFilterToAll` / `removeFilterFromAll` pass `filterId` (from ' +
      'list_filters) instead of `data`. Entries are applied independently: an entry whose `version` is stale ' +
      'is rejected and the others are still written. HTTP 200 means every entry was applied; 207 means some ' +
      'were and lists the rest in `failedControlIds`; 409 means none were. `failedControlIds` also includes ' +
      'the ids in `rejectedControlIds` when present: those are controls served by a custom runbook, which ' +
      'cannot have automated remediation enabled and are refused identically on every retry — do not retry ' +
      'them. Refresh versions and retry only the failed ids that are not in `rejectedControlIds`.',
    schema: UpdateControlsToolSchema,
  },
  // Intent-based policy — declared for the next release. Both are absent from
  // toolSchema.json and have no API route yet (`/policies/preview`, `/policies/apply`),
  // so neither is advertised and neither holds an access tier. Wiring them up means
  // adding the routes, the schema entries, and the tiers in one change. The descriptions
  // are prefixed "(Planned, not yet available)" so the placeholder status is clear even
  // when a description is read on its own, apart from this comment.
  preview_policy_change: {
    name: 'preview_policy_change',
    description:
      '(Planned, not yet available.) Translate a natural language policy intent into a structured filter ' +
      'config preview. Does not mutate state.',
    schema: PreviewPolicyChangeSchema,
  },
  apply_policy_change: {
    name: 'apply_policy_change',
    description:
      '(Planned, not yet available.) Apply a previously previewed policy change. Requires preview_id from ' +
      'preview_policy_change.',
    schema: ApplyPolicyChangeSchema,
  },
} as const satisfies Record<string, ToolContract>;

// ─── Reporting Tools ────────────────────────────────────────────────────────

export const REPORTING_TOOLS = {
  remediations: {
    name: 'remediations',
    description:
      'Search ASR remediation history by control, account, status; or export it as CSV/JSON when `format` is set (merges the former search_remediations + export_remediations). Findings export is served by the `findings` tool.',
    schema: RemediationsSchema,
  },
} as const satisfies Record<string, ToolContract>;

// ─── Notification Tools ─────────────────────────────────────────────────────

export const NOTIFICATION_TOOLS = {
  list_notifications: {
    name: 'list_notifications',
    description: 'List notification configurations with their channels, scope, and type.',
    schema: ListNotificationsSchema,
  },
  create_notification: {
    name: 'create_notification',
    description:
      'Create a notification configuration (channel, recipients, scope, delivery). Grantable to Account Operators; subject to the per-user MCP grant and the account/creator scoping the API enforces.',
    schema: CreateNotificationSchema,
  },
  update_notification: {
    name: 'update_notification',
    description:
      'Update an existing notification configuration by ID. Grantable to Account Operators; subject to the per-user MCP grant and the account/creator scoping the API enforces.',
    schema: UpdateNotificationSchema,
  },
  delete_notification: {
    name: 'delete_notification',
    description:
      'Delete a notification configuration by ID. Idempotent: a configuration that does not exist is still a 200, so the status code alone does not confirm that anything was removed; read the configuration first if that matters. Grantable to Account Operators; subject to the per-user MCP grant and the account/creator scoping the API enforces.',
    schema: DeleteNotificationSchema,
  },
  test_notification: {
    name: 'test_notification',
    description:
      'Send a test notification through a configuration to all its enabled channels. This proves channel ' +
      "connectivity only: the synthetic event is delivered without evaluating the configuration's " +
      'severityFilter, accountIds, controlIds, or resource filters, so a success here does not mean any real ' +
      'finding will match. Grantable to Account Operators; subject to the per-user MCP grant and the ' +
      'account/creator scoping the API enforces.',
    schema: TestNotificationSchema,
  },
} as const satisfies Record<string, ToolContract>;

/** Combined catalog — all tools in one map for registry binding. */
export const TOOL_CONTRACTS = {
  ...AWS_TOOLS,
  ...REMEDIATION_TOOLS,
  ...INFRA_TOOLS,
  ...DISCOVERY_TOOLS,
  ...POLICY_TOOLS,
  ...REPORTING_TOOLS,
  ...NOTIFICATION_TOOLS,
} as const satisfies Record<string, ToolContract>;

export type ToolName = keyof typeof TOOL_CONTRACTS;

// ─── Tool categories (grouping for the grantable-tool catalog) ──────────────
//
// A category is presentation grouping, not authorization: it is what the Web UI's
// tool-permission list groups rows under so an Admin reviews a bounded set of
// related tools at a time instead of one flat list of every tool. Authorization
// remains entirely a function of the tier lists below.

/** Category a grantable tool is grouped under in the tool-permission catalog. */
export type ToolCategory =
  | 'Discovery'
  | 'Reporting'
  | 'Notifications'
  | 'Remediation'
  | 'Infrastructure'
  | 'Policy'
  | 'Other';

// Categories are derived from the declared tool groups above, so a tool added to
// one of those maps is categorized in the same edit rather than needing a second
// list kept in sync. `execute_finding_action` and `drift_detection` are advertised
// and tiered but declared only as proxy routes in mcpServerHandler — not in
// TOOL_CONTRACTS — so they are named here explicitly. AWS_TOOLS holds only
// finding-history lookup, which belongs with the other read-and-triage tools
// rather than in a category of its own.
const TOOLS_BY_CATEGORY: readonly (readonly [ToolCategory, readonly string[]])[] = [
  ['Discovery', [...Object.keys(DISCOVERY_TOOLS), ...Object.keys(AWS_TOOLS)]],
  ['Reporting', Object.keys(REPORTING_TOOLS)],
  ['Notifications', Object.keys(NOTIFICATION_TOOLS)],
  ['Remediation', [...Object.keys(REMEDIATION_TOOLS), 'execute_finding_action', 'drift_detection']],
  ['Infrastructure', Object.keys(INFRA_TOOLS)],
  ['Policy', Object.keys(POLICY_TOOLS)],
];

/** Tool name → category. Complete for every tiered tool; asserted by a test. */
export const TOOL_CATEGORIES: Readonly<Record<string, ToolCategory>> = Object.fromEntries(
  TOOLS_BY_CATEGORY.flatMap(([category, toolNames]) => toolNames.map((toolName) => [toolName, category])),
);

/**
 * Category for one tool. A tool with no mapping falls back to 'Other' so it still
 * appears in the catalog and stays grantable — an uncategorized tool is a grouping
 * gap, not a reason to hide it from the Admin managing grants. A test asserts every
 * tiered tool has a real category, so 'Other' should never be reached in practice.
 */
export const categoryForTool = (toolName: string): ToolCategory => TOOL_CATEGORIES[toolName] ?? 'Other';

// ─── Tool access tiers (Cognito group → allowed tools) ──────────────────────
//
// Single source of truth for which tools each access tier may call. The MCP
// server Lambda behind the AgentCore Gateway derives its authorization from this
// map, so access policy lives in one place instead of in the entry point.
//
// These lists cover exactly the tools the gateway ADVERTISES (toolSchema.json),
// which is a subset of the tools DECLARED in TOOL_CONTRACTS above. A declared
// tool that is not yet advertised has no route and cannot be invoked, so giving
// it a tier would grant access to nothing while making the authorization surface
// look wider than it is — and would let a later change advertise it and silently
// inherit that tier without anyone reviewing the access decision. Tiers are
// therefore granted only when a tool is actually reachable; adding one to
// toolSchema.json means adding it here in the same change. `toolSchema.json`
// parity is enforced by a test in __tests__/toolContract.test.ts.
//
// Capability ceilings are cumulative:
// ADMIN = DELEGATED_ADMIN ⊇ ACCOUNT_OPERATOR.
//
//   AccountOperator (AccountOperatorGroup) — explicitly granted tools that the
//                                            API can account/creator-scope
//   DelegatedAdmin  (DelegatedAdminGroup)  — explicitly granted tools, all accounts
//   Admin           (AdminGroup)           — every tool automatically
//
// Only these existing Cognito groups are mapped; no new group is introduced.
// Any other group (or none) has no tier and is denied.

/**
 * Tools available to Account Operators, subject to their explicit per-user MCP
 * grant and the account/creator authorization enforced by the underlying API.
 */
export const ACCOUNT_OPERATOR_TOOLS: readonly string[] = [
  'list_runbooks',
  'get_runbook',
  'list_findings_without_runbook',
  'get_finding_history',
  'get_execution_status',
  'check_runbook_drift',
  'check_deploy_readiness',
  'list_controls',
  'list_filters',
  'list_notifications',
  'findings',
  'remediations',
  'validate_runbook',
  'execute_finding_action',
  'create_notification',
  'update_notification',
  'delete_notification',
  'test_notification',
];

/**
 * Remediation-authoring tools — the authoring lifecycle that produces/tests/deploys
 * runbooks. There is no separate "Author" access tier: these tools fold into ADMIN_TOOLS,
 * and because TOOLS_BY_TIER maps DelegatedAdmin to ADMIN_TOOLS as well, they are reachable
 * at both the Admin and Delegated Admin tiers (McpToolGrantService.listGrantableTools labels
 * them tier 'DelegatedAdmin'). They are never in the AccountOperator ceiling. The grouping is
 * kept so the account-operator surface and the authoring surface stay explicit and testable.
 *
 * Deliberately includes four tools that mutate state (`deploy_runbook`,
 * `source_deploy`, `test_remediation_script`, `test_runbook_yaml` — the two test tools register
 * and execute real SSM Automation against live AWS, not just inspect).
 */
export const AUTHOR_TOOLS: readonly string[] = [
  ...ACCOUNT_OPERATOR_TOOLS,
  'generate_runbook',
  'test_remediation_script',
  'test_runbook_yaml',
  'deploy_runbook',
];

/** Admin tools — full surface: execution, policy, controls, notifications. */
export const ADMIN_TOOLS: readonly string[] = [
  ...AUTHOR_TOOLS,
  'execute_runbook',
  'create_filter',
  'update_filter',
  'delete_filter',
  'update_controls',
  'drift_detection',
];

export type AccessTier = 'AccountOperator' | 'DelegatedAdmin' | 'Admin';

/** Tools allowed for each access tier. */
export const TOOLS_BY_TIER: Readonly<Record<AccessTier, readonly string[]>> = {
  AccountOperator: ACCOUNT_OPERATOR_TOOLS,
  DelegatedAdmin: ADMIN_TOOLS,
  Admin: ADMIN_TOOLS,
};

/**
 * Cognito group → access tier. Maps the existing ASR Web UI groups to tool tiers.
 * Only the three shipped groups are recognized; no new group is introduced.
 */
export const GROUP_TO_TIER: Readonly<Record<string, AccessTier>> = {
  AdminGroup: 'Admin',
  DelegatedAdminGroup: 'DelegatedAdmin',
  AccountOperatorGroup: 'AccountOperator',
};

/** Tiers highest → lowest, for resolving the strongest tier a caller holds. */
const TIER_PRECEDENCE: readonly AccessTier[] = ['Admin', 'DelegatedAdmin', 'AccountOperator'];

/** Resolve the highest recognized tier across a caller's groups. */
export function tierForGroups(groups: readonly string[]): AccessTier | undefined {
  for (const tier of TIER_PRECEDENCE) {
    if (groups.some((g) => GROUP_TO_TIER[g] === tier)) return tier;
  }
  return undefined;
}

/** True if the caller's groups grant access to `toolName`. */
export function isToolAllowedForGroups(toolName: string, groups: readonly string[]): boolean {
  const tier = tierForGroups(groups);
  return tier ? TOOLS_BY_TIER[tier].includes(toolName) : false;
}

/**
 * Match a tool name against an allowlist pattern. Supports only `*` (match all)
 * or a single TRAILING `*` prefix-wildcard (e.g. `list_*` matches `list_runbooks`).
 * A `*` anywhere other than the end is treated as a literal character (no
 * mid/leading wildcard support), so `*_runbook` matches nothing. Otherwise exact.
 */
export function matchesToolPattern(toolName: string, pattern: string): boolean {
  if (pattern === '*') return true;
  if (pattern.endsWith('*')) return toolName.startsWith(pattern.slice(0, -1));
  return toolName === pattern;
}

/**
 * Resolve a human user's effective MCP access.
 *
 * AdminGroup is the root role and receives every tool in its capability ceiling
 * automatically. Delegated Admins and Account Operators require an explicit
 * per-user grant, which can only narrow their role ceiling.
 */
export function resolveUserToolAccess(
  toolName: string,
  groups: readonly string[],
  allowedTools: readonly string[] | undefined,
): boolean {
  if (!isToolAllowedForGroups(toolName, groups)) return false;
  if (tierForGroups(groups) === 'Admin') return true;
  if (!allowedTools) return false;
  return allowedTools.some((pattern) => matchesToolPattern(toolName, pattern));
}
