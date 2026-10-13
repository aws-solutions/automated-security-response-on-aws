// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * Shared interface defining the environment variables passed from CDK to the
 * MCP Server Lambda. Both the CDK construct and the Lambda accessor reference
 * this type so the compiler catches any drift between the two sides.
 */
export interface McpServerEnvironmentConfig {
  readonly SOLUTION_ID: string;
  readonly SOLUTION_VERSION: string;
  /** Existing ASR API Lambda invoked synchronously for proxied runbook tools. */
  readonly API_FUNCTION_NAME: string;
  /**
   * The Cognito user pool ID. Used to resolve the access token's username to the
   * canonical email key stored in UserAccountMapping.
   */
  readonly COGNITO_USER_POOL_ID: string;
  /**
   * The Cognito app client the gateway is allowed to accept tokens from. The gateway's
   * JWT authorizer pins the same value via `allowedClients`; the Lambda re-checks it so a
   * caller who invokes the function directly, bypassing the gateway, cannot present a
   * token minted for a different client in the same pool.
   */
  readonly MCP_GATEWAY_CLIENT_ID: string;
  /**
   * The user/account-mapping table, which also holds per-user MCP tool grants.
   */
  readonly USER_ACCOUNT_MAPPING_TABLE_NAME: string;
  /**
   * The remediation history table, queried by `get_finding_history` so it can return ASR's
   * own remediation attempts alongside the Security Hub history. Absent when the tool runs
   * outside the deployed Lambda, in which case only Security Hub history is returned.
   */
  readonly REMEDIATION_HISTORY_TABLE_NAME?: string;
  /**
   * The custom runbook table, updated by `test_runbook_yaml` to record whether a version passed
   * its test-account run. Absent when the tool runs outside the deployed Lambda, in which case no
   * result is recorded — and, because `deploy_runbook` gates on that record, a runbook tested
   * outside the deployment cannot be promoted on the strength of that run.
   */
  readonly CUSTOM_RUNBOOK_TABLE_NAME?: string;
  /**
   * Permissions boundary attached to bounded custom-runbook test roles.
   * Absent outside the deployed MCP Lambda, where recorded tests are unavailable.
   */
  readonly CUSTOM_RUNBOOK_TEST_BOUNDARY_ARN?: string;
}
