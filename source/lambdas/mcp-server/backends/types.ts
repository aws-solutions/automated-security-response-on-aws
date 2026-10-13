// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * Runtime context passed to each tool executor.
 *
 * Executors run inside the MCP server Lambda and call AWS with the Lambda's own
 * role. `workspaceRoot` locates a repository checkout for the executors that
 * read source files; `region` and `requestId` are shared by all of them for SDK
 * calls, logging, and tracing.
 */
export interface ExecutionContext {
  /** Absolute path to the ASR repository root. Used by source-reading executors. */
  readonly workspaceRoot?: string;
  /** AWS region for SDK calls in common executors. */
  readonly region: string;
  /** Correlation ID for logs and traces. */
  readonly requestId: string;
  /**
   * Remediation history table, injected by the MCP gateway construct (which also grants the
   * scoped query permission). Absent when a host runs the tools outside the deployed Lambda,
   * in which case executors that read it fall back to their AWS-only data.
   */
  readonly remediationHistoryTableName?: string;
  /**
   * Custom runbook table, injected by the MCP gateway construct (which also grants the scoped
   * read/update permission). `test_runbook_yaml` verifies and writes a version's test result here, which is what
   * later opens the deployment gate. Absent when a host runs the tools outside the deployed
   * Lambda; the tool then reports the outcome without recording it.
   */
  readonly customRunbookTableName?: string;
  /**
   * Permissions boundary for the version-scoped role that executes a registered
   * runbook test. Injected by the MCP gateway construct.
   */
  readonly customRunbookTestBoundaryArn?: string;
  /**
   * Accounts this caller is allowed to see finding data for, or `undefined` for an
   * unrestricted caller.
   *
   * The direct-execution tools run inside the MCP Lambda under its own role, which
   * holds organization-wide `securityhub:GetFindings` — there is no API hop behind
   * them, so nothing else applies the per-account rules the REST API enforces via
   * `createAccessRules`. Without this, an Account Operator (the lowest tier) read
   * findings for every account in the organization.
   *
   * `undefined` means "do not filter" and is used for Admin and Delegated Admin
   * callers. An empty array means "no accounts", which correctly yields no finding
   * data for an Account Operator without assignments. Machine tokens never reach MCP.
   */
  readonly authorizedAccountIds?: readonly string[];
  /**
   * Account this executor is running in, derived from the Lambda's own invoked ARN rather than
   * from anything the caller sent. Recorded as the test result's provenance. Absent outside the
   * deployed Lambda.
   */
  readonly accountId?: string;
  /**
   * AWS partition this executor is running in (`aws`, `aws-cn`, `aws-us-gov`, `aws-iso`,
   * `aws-eusc`, …), read from the Lambda's own invoked ARN. Taken from the ARN rather than
   * inferred from the region prefix because the region→partition mapping is an open set:
   * every new isolated or sovereign partition would silently fall back to `aws` and produce
   * ARNs that do not resolve. Absent outside the deployed Lambda, where callers should pass
   * an explicit ARN instead.
   */
  readonly partition?: string;
}

/** Function signature implementing a tool. */
export type Executor<TArgs, TResult = unknown> = (args: TArgs, context: ExecutionContext) => Promise<TResult>;
