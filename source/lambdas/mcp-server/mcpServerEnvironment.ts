// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { McpServerEnvironmentConfig } from '@asr/data-models';
import { readOptionalEnvironmentVariables, requireEnvironmentVariables } from '../common/utils/env-variables';

let cached: McpServerEnvironmentConfig | undefined;

const REQUIRED_KEYS: readonly (keyof McpServerEnvironmentConfig)[] = [
  'SOLUTION_ID',
  'SOLUTION_VERSION',
  'API_FUNCTION_NAME',
  'COGNITO_USER_POOL_ID',
  'MCP_GATEWAY_CLIENT_ID',
  'USER_ACCOUNT_MAPPING_TABLE_NAME',
] as const;

const OPTIONAL_KEYS: readonly (keyof McpServerEnvironmentConfig)[] = [
  'REMEDIATION_HISTORY_TABLE_NAME',
  'CUSTOM_RUNBOOK_TABLE_NAME',
  'CUSTOM_RUNBOOK_TEST_BOUNDARY_ARN',
] as const;

/** Read, validate, and cache the MCP Lambda environment. */
export function mcpServerEnvironment(): McpServerEnvironmentConfig {
  if (cached) return cached;
  cached = {
    ...requireEnvironmentVariables(REQUIRED_KEYS),
    ...readOptionalEnvironmentVariables(OPTIONAL_KEYS),
  };
  return cached;
}

/** Clear the cached environment for tests that change process variables. */
export function resetMcpServerEnvironmentCache(): void {
  cached = undefined;
}

/**
 * Read the Lambda runtime's reserved variables. AWS_REGION is set automatically
 * by the Lambda runtime and must not be declared in McpServerEnvironmentConfig
 * or the CDK environment block (CloudFormation rejects a deploy that overrides a
 * reserved variable), so it is read here rather than through mcpServerEnvironment.
 */
export function mcpServerRuntimeEnvironment(): { readonly AWS_REGION: string } {
  return requireEnvironmentVariables(['AWS_REGION'] as const);
}
