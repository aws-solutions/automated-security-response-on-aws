// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import * as cdk from 'aws-cdk-lib';
import * as cognito from 'aws-cdk-lib/aws-cognito';
import * as s3 from 'aws-cdk-lib/aws-s3';
import { Construct } from 'constructs';
import { McpGatewayConstruct } from './mcp/mcp-gateway-construct';

export const MCP_CALLBACK_URL_NESTED_STACK_DELIMITER = '\n';

/**
 * Props for the optional, parameter-gated AgentCore Gateway nested stack.
 *
 * The Cognito user pool and the user/account-mapping table live in the WebUI nested
 * stack; only their IDs, names, and ARNs cross the stack boundary, so they are
 * imported here rather than passed as objects. This keeps the ACG stack decoupled
 * from the core constructs — it consumes only stable string outputs.
 */
export interface McpGatewayNestedStackProps extends cdk.NestedStackProps {
  readonly solutionId: string;
  readonly solutionVersion: string;
  readonly solutionTMN: string;
  readonly solutionsBucket: s3.IBucket;
  readonly resourceNamePrefix: string;

  /** Cognito user pool ID (from the WebUI nested stack output). */
  readonly userPoolId: string;
  /**
   * Name of the ASR API Lambda (from the WebUI nested stack). The MCP Lambda invokes it
   * directly for proxied tool calls, so the gateway does not need the API Gateway stage —
   * that stage is part of the Web UI frontend and is absent in an MCP-only deployment.
   */
  readonly apiFunctionName: string;
  /**
   * Name of the user/account-mapping table (from the WebUI nested stack), which also
   * holds the per-client MCP tool allowlists the Lambda reads at authorization time.
   */
  readonly userAccountMappingTableName: string;
  /** ARN of the same table, to scope the Lambda's read-only DynamoDB grant. */
  readonly userAccountMappingTableARN: string;
  /** Name of the remediation history table, queried by the `get_finding_history` tool. */
  readonly remediationHistoryTableName: string;
  /** ARN of the history table, to scope the Lambda's query grant. */
  readonly remediationHistoryTableARN: string;
  /**
   * Name of the custom runbook table. `test_runbook_yaml` records each version's test-account
   * result there, which is what `deploy_runbook` later gates on.
   */
  readonly customRunbookTableName: string;
  /** ARN of the custom runbook table, to scope the Lambda's update grant. */
  readonly customRunbookTableARN: string;
  /** ARN of the CMK the table is encrypted with — reads need `kms:Decrypt` on it. */
  readonly kmsKeyARN: string;
  /**
   * ARN of the ASR remediation permissions boundary in the admin account. Attached to the
   * short-lived roles that recorded custom-runbook testing (test_runbook_yaml) creates.
   */
  readonly remediationBoundaryPolicyArn: string;
}

/**
 * Optional AgentCore Gateway (ACG-native) delivery, isolated in its own nested
 * stack so it can be deployed only when an enable parameter is set — adding
 * nothing to the base solution when off, with no compile-time coupling to core.
 */
export class McpGatewayNestedStack extends cdk.NestedStack {
  /** MCP server endpoint URL, surfaced so the parent stack can output it. */
  public readonly gatewayUrl: string;
  /** Public Cognito app client ID, surfaced for native MCP client configuration. */
  public readonly gatewayClientId: string;
  /** Space-delimited OAuth scope names native MCP clients must request during login. */
  public readonly gatewayScopes: string;
  /** Exact deployment-specific Codex OAuth callback URL. */
  public readonly codexCallbackUrl: string;

  constructor(scope: Construct, id: string, props: McpGatewayNestedStackProps) {
    super(scope, id, props);

    this.templateOptions.description = `(${props.solutionId}G) - Automated Security Response on AWS - AgentCore Gateway (ACG-native) nested stack. ${props.solutionVersion}`;

    const userPool = cognito.UserPool.fromUserPoolId(this, 'ImportedUserPool', props.userPoolId);
    const additionalCallbackUrls = new cdk.CfnParameter(this, 'AdditionalMcpCallbackUrls', {
      type: 'String',
      description: 'Newline-delimited additional OAuth callback URLs supplied by the parent stack.',
      default: '',
    });

    const mcpGateway = new McpGatewayConstruct(this, 'McpGateway', {
      resourceNamePrefix: props.resourceNamePrefix,
      solutionId: props.solutionId,
      solutionVersion: props.solutionVersion,
      solutionTMN: props.solutionTMN,
      solutionsBucket: props.solutionsBucket,
      userPool,
      additionalCallbackUrls: additionalCallbackUrls.valueAsString,
      apiFunctionName: props.apiFunctionName,
      userAccountMappingTableName: props.userAccountMappingTableName,
      userAccountMappingTableARN: props.userAccountMappingTableARN,
      remediationHistoryTableName: props.remediationHistoryTableName,
      remediationHistoryTableARN: props.remediationHistoryTableARN,
      customRunbookTableName: props.customRunbookTableName,
      customRunbookTableARN: props.customRunbookTableARN,
      kmsKeyARN: props.kmsKeyARN,
      remediationBoundaryPolicyArn: props.remediationBoundaryPolicyArn,
    });

    this.gatewayUrl = mcpGateway.gatewayUrl;
    this.gatewayClientId = mcpGateway.gatewayClientId;
    this.gatewayScopes = mcpGateway.gatewayScopes;
    this.codexCallbackUrl = mcpGateway.codexCallbackUrl;

    new cdk.CfnOutput(this, 'McpGatewayUrl', {
      description: 'MCP server endpoint URL',
      value: this.gatewayUrl,
    });

    new cdk.CfnOutput(this, 'McpGatewayClientId', {
      description: 'Public Cognito OAuth client ID for native MCP clients',
      value: this.gatewayClientId,
    });

    new cdk.CfnOutput(this, 'McpGatewayScopes', {
      description: 'Space-delimited OAuth scopes native MCP clients must request during login',
      value: this.gatewayScopes,
    });

    new cdk.CfnOutput(this, 'McpCodexCallbackUrl', {
      description: 'Exact Codex OAuth callback URL registered for this deployment',
      value: this.codexCallbackUrl,
    });
  }
}
