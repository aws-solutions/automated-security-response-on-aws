// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

export const KIRO_CLI_OAUTH_CALLBACK_URL = 'http://localhost:8770';
export const KIRO_IDE_OAUTH_CALLBACK_URL = 'http://localhost:8770/oauth/callback';
export const CLAUDE_CODE_OAUTH_CALLBACK_URL = 'http://localhost:8772/callback';
export const CODEX_OAUTH_CALLBACK_BASE_URL = 'http://127.0.0.1:8780/callback';

/**
 * The OAuth scopes native MCP clients request during the authorization-code login, and the
 * exact set the gateway authorizer validates. Single source of truth: the Cognito app
 * client's `oAuth.scopes`, the AgentCore authorizer's `allowedScopes`, and the
 * `McpGatewayScopes` stack output all derive from this list, so a client cannot request a
 * scope the gateway rejects (`invalid_scope`).
 *
 * Kept as bare scope names (not `cognito.OAuthScope`) so non-CDK consumers — the setup
 * command that reads the stack output, tests, and docs — share the same literal without
 * depending on the CDK library.
 */
export const NATIVE_CLIENT_OAUTH_SCOPE_NAMES: readonly string[] = ['openid', 'email', 'profile'];

/**
 * OAuth callback URLs for the MCP clients ASR supports out of the box. Registered on the
 * gateway's Cognito app client so a user of any of these CLIs can complete the login
 * redirect with no deployment-time configuration. Each is a fixed loopback address the
 * client listens on locally during its authorization-code flow.
 *
 * Codex is deliberately excluded: its redirect URI carries a per-deployment callback id
 * derived from the gateway URL (which AgentCore assigns at deploy time), so it cannot be a
 * fixed literal. The nativeClientCallbackRegistrar custom resource computes and registers
 * the exact Codex URL after the gateway exists, using CODEX_OAUTH_CALLBACK_BASE_URL.
 */
export const FIXED_NATIVE_CLIENT_CALLBACK_URLS: readonly string[] = [
  KIRO_CLI_OAUTH_CALLBACK_URL,
  KIRO_IDE_OAUTH_CALLBACK_URL,
  CLAUDE_CODE_OAUTH_CALLBACK_URL,
];
