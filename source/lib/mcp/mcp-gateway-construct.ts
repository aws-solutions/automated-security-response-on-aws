// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import * as cdk from 'aws-cdk-lib';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as cognito from 'aws-cdk-lib/aws-cognito';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as s3 from 'aws-cdk-lib/aws-s3';
import * as agentcore from '@aws-cdk/aws-bedrock-agentcore-alpha';
import { CUSTOM_RUNBOOK_CONTROL_STATUS_GSI } from '@asr/data-models';
import { Construct } from 'constructs';
import { addCfnGuardSuppression } from '../cdk-helper/add-cfn-guard-suppression';
import { getLambdaCode } from '../cdk-helper/lambda-code-manifest';
import {
  CODEX_OAUTH_CALLBACK_BASE_URL,
  FIXED_NATIVE_CLIENT_CALLBACK_URLS,
  NATIVE_CLIENT_OAUTH_SCOPE_NAMES,
} from './mcp-native-client-callbacks';

export interface McpGatewayConstructProps {
  readonly resourceNamePrefix: string;
  readonly solutionId: string;
  readonly solutionVersion: string;
  readonly solutionTMN: string;
  readonly solutionsBucket: s3.IBucket;

  /** Cognito User Pool — used to build the OIDC discovery URL. */
  readonly userPool: cognito.IUserPool;

  /**
   * Newline-delimited OAuth callback URLs registered by the deployment-time custom resource.
   * Keeping this as a string prevents CloudFormation list tokens from crossing the nested-stack
   * parameter boundary.
   */
  readonly additionalCallbackUrls: string;

  /**
   * Name of the existing ASR API Lambda. The MCP Lambda invokes it synchronously for
   * proxied tool calls rather than calling the REST API over HTTP, so the gateway does
   * not depend on the API Gateway stage existing — that stage is part of the Web UI
   * frontend and is absent in an MCP-only deployment.
   */
  readonly apiFunctionName: string;

  /**
   * Name of the user/account-mapping table, which also holds the per-client MCP tool
   * allowlists the Lambda reads to narrow a caller's access tier.
   */
  readonly userAccountMappingTableName: string;
  /** ARN of the same table, used to scope the Lambda's read-only DynamoDB grant. */
  readonly userAccountMappingTableARN: string;
  /**
   * Name of the remediation history table. The `get_finding_history` tool queries it
   * to return ASR's own remediation attempts alongside the Security Hub history.
   */
  readonly remediationHistoryTableName: string;
  /** ARN of the history table, used to scope the Lambda's query grant. */
  readonly remediationHistoryTableARN: string;
  /**
   * Name of the custom runbook table. `test_runbook_yaml` records each version's test-account
   * result here, which is what `deploy_runbook` later gates on.
   */
  readonly customRunbookTableName: string;
  /** ARN of the custom runbook table, used to scope the Lambda's update grant. */
  readonly customRunbookTableARN: string;
  /** ARN of the CMK the table is encrypted with — reads need `kms:Decrypt` on it. */
  readonly kmsKeyARN: string;
  /**
   * ARN of the ASR remediation permissions boundary (SO0111-ASR-Remediation-Boundary) in
   * THIS (admin) account. Recorded custom-runbook testing (test_runbook_yaml) creates a
   * short-lived test role per execution and attaches this boundary to it; the tool refuses
   * to run without the ARN, and the Lambda is only permitted to create a test role that
   * carries exactly this boundary. Same construct as the member-account boundary.
   */
  readonly remediationBoundaryPolicyArn: string;
}

/**
 * Creates the MCP server Lambda plus an Amazon Bedrock AgentCore Gateway that fronts it
 * with Cognito JWT authorization.
 */
export class McpGatewayConstruct extends Construct {
  /** The MCP server Lambda function. */
  public readonly mcpLambda: lambda.Function;
  /** The AgentCore Gateway identifier. */
  public readonly gatewayId: string;
  /** The MCP server endpoint URL callers connect to. */
  public readonly gatewayUrl: string;
  /** Public Cognito app client ID used by native MCP clients for OAuth login. */
  public readonly gatewayClientId: string;
  /** Space-delimited OAuth scope names native MCP clients must request during login. */
  public readonly gatewayScopes: string;
  /** Exact Codex OAuth callback URL registered for this deployment (derived from the gateway URL). */
  public readonly codexCallbackUrl: string;

  constructor(scope: Construct, id: string, props: McpGatewayConstructProps) {
    super(scope, id);

    const stack = cdk.Stack.of(this);
    const testRoleNamePrefix = `${props.resourceNamePrefix}-Remediate-Custom-Test-`;
    const testRoleArnPattern = `arn:${stack.partition}:iam::${stack.account}:role/${testRoleNamePrefix}*`;

    // --- MCP server Lambda ---------------------------------------------------

    this.mcpLambda = new lambda.Function(this, 'McpServerFunction', {
      functionName: `${props.resourceNamePrefix}-ASR-MCP-Server`,
      runtime: lambda.Runtime.NODEJS_24_X,
      handler: 'mcp-server/mcpServerHandler.handler',
      code: getLambdaCode(props.solutionsBucket, props.solutionTMN, props.solutionVersion, 'asr_lambdas.zip'),
      description: 'ASR MCP server — tool dispatcher for AgentCore Gateway',
      environment: {
        SOLUTION_ID: props.solutionId,
        SOLUTION_VERSION: props.solutionVersion,
        API_FUNCTION_NAME: props.apiFunctionName,
        COGNITO_USER_POOL_ID: props.userPool.userPoolId,
        USER_ACCOUNT_MAPPING_TABLE_NAME: props.userAccountMappingTableName,
        REMEDIATION_HISTORY_TABLE_NAME: props.remediationHistoryTableName,
        CUSTOM_RUNBOOK_TABLE_NAME: props.customRunbookTableName,
        // Attached to every custom-runbook test role the Lambda creates; recorded testing
        // (test_runbook_yaml) refuses to run without it.
        CUSTOM_RUNBOOK_TEST_BOUNDARY_ARN: props.remediationBoundaryPolicyArn,
        POWERTOOLS_LOG_LEVEL: 'INFO',
        POWERTOOLS_LOGGER_LOG_EVENT: 'false',
      },
      memorySize: 512,
      timeout: cdk.Duration.seconds(60),
      tracing: lambda.Tracing.ACTIVE,
    });

    addCfnGuardSuppression(this.mcpLambda, 'LAMBDA_INSIDE_VPC');
    addCfnGuardSuppression(this.mcpLambda, 'LAMBDA_CONCURRENCY_CHECK');

    // Read a single `client#<clientId>` record to narrow the caller's access tier.
    // GetItem only: mutating allowlists and listing them stay with the admin CRUD API.
    this.mcpLambda.addToRolePolicy(
      new iam.PolicyStatement({
        effect: iam.Effect.ALLOW,
        actions: ['dynamodb:GetItem'],
        resources: [props.userAccountMappingTableARN],
      }),
    );

    // `get_finding_history` queries remediation attempts for one finding, using the
    // findingId GSI and falling back to the table's own key — hence both resources.
    // Query only: the tool reads history, it never records it.
    this.mcpLambda.addToRolePolicy(
      new iam.PolicyStatement({
        effect: iam.Effect.ALLOW,
        actions: ['dynamodb:Query'],
        resources: [props.remediationHistoryTableARN, `${props.remediationHistoryTableARN}/index/*`],
      }),
    );

    // `test_runbook_yaml` reads the already-registered version to enforce the
    // content-digest gate (findRegisteredVersion issues a GetItem), then stamps
    // the test-account outcome onto that same version (UpdateItem). Both on the
    // table itself, by primary key.
    this.mcpLambda.addToRolePolicy(
      new iam.PolicyStatement({
        effect: iam.Effect.ALLOW,
        actions: ['dynamodb:GetItem', 'dynamodb:UpdateItem'],
        resources: [props.customRunbookTableARN],
      }),
    );

    // `list_findings_without_runbook` confirms each custom-runbook claim against the
    // controlId-status GSI (CustomRunbookRepository.findByControlId), so it needs Query
    // on the INDEX — a table-level grant does not cover an index query. Without it the
    // confirmation read is denied and the tool takes its fail-open path: unconfirmed
    // claims are counted as coverage, so a control whose only runbook is DRAFT or failed
    // is reported as covered and the gap is hidden. Query on the index alone, because
    // the tool reads no other records and writes nothing.
    this.mcpLambda.addToRolePolicy(
      new iam.PolicyStatement({
        effect: iam.Effect.ALLOW,
        actions: ['dynamodb:Query'],
        resources: [`${props.customRunbookTableARN}/index/${CUSTOM_RUNBOOK_CONTROL_STATUS_GSI}`],
      }),
    );

    // The table is encrypted with a customer-managed key, so reading it also
    // requires Decrypt on that key. Decrypt only — the Lambda never writes.
    this.mcpLambda.addToRolePolicy(
      new iam.PolicyStatement({
        effect: iam.Effect.ALLOW,
        actions: ['kms:Decrypt'],
        resources: [props.kmsKeyARN],
      }),
    );

    // Access tokens carry the Cognito username, not the email. resolveHumanUserEmail
    // resolves it to the email that keys UserAccountMapping via AdminGetUser — required
    // for every human caller (Delegated Admin and Account Operator tiers in particular),
    // so without this grant their tool calls fail with a 503. Scoped to this pool.
    this.mcpLambda.addToRolePolicy(
      new iam.PolicyStatement({
        effect: iam.Effect.ALLOW,
        actions: ['cognito-idp:AdminGetUser'],
        resources: [props.userPool.userPoolArn],
      }),
    );

    // --- Custom-runbook recorded-testing permissions ------------------------
    // test_runbook_yaml provisions a short-lived, boundary-capped IAM role per execution,
    // registers the candidate runbook as a transient ASR-Custom-* SSM document, runs it
    // under that role, then reaps both. These grants are scoped to the custom-runbook
    // test-role name space and the ASR-Custom-* document name space so the Lambda can never
    // touch the solution's own roles or built-in documents.

    // Lifecycle of the per-execution test role (customRunbookTestRoleService). The Lambda
    // must also be allowed to attach the boundary it created, which is what makes the
    // created role safe.
    this.mcpLambda.addToRolePolicy(
      new iam.PolicyStatement({
        sid: 'ManageCustomRunbookTestRoles',
        effect: iam.Effect.ALLOW,
        actions: [
          'iam:CreateRole',
          'iam:DeleteRole',
          'iam:GetRole',
          'iam:PutRolePolicy',
          'iam:DeleteRolePolicy',
          'iam:TagRole',
          'iam:PutRolePermissionsBoundary',
          'iam:UpdateAssumeRolePolicy',
        ],
        resources: [testRoleArnPattern],
      }),
    );
    // Every test role must be created WITH this boundary attached: the condition forces
    // iam:PermissionsBoundary on CreateRole/PutRolePermissionsBoundary so the Lambda can
    // never mint an unbounded role in the test-role name space.
    this.mcpLambda.addToRolePolicy(
      new iam.PolicyStatement({
        sid: 'RequireBoundaryOnTestRoles',
        effect: iam.Effect.DENY,
        actions: ['iam:CreateRole', 'iam:PutRolePermissionsBoundary'],
        resources: [testRoleArnPattern],
        conditions: {
          StringNotEquals: { 'iam:PermissionsBoundary': props.remediationBoundaryPolicyArn },
        },
      }),
    );
    // Hand the test role to SSM Automation (StartAutomationExecution runs under it).
    this.mcpLambda.addToRolePolicy(
      new iam.PolicyStatement({
        sid: 'PassCustomRunbookTestRoleToSsm',
        effect: iam.Effect.ALLOW,
        actions: ['iam:PassRole'],
        resources: [testRoleArnPattern],
        conditions: { StringEquals: { 'iam:PassedToService': 'ssm.amazonaws.com' } },
      }),
    );
    // Register/run/reap the transient test document, scoped to the two transient-test
    // prefixes that generateDocumentName enforces on every name (including caller-supplied
    // ones). Deployed custom runbooks live under the broader ASR-Custom-* name space, so
    // scoping to the test prefixes — not ASR-Custom-* — is what keeps DeleteDocument here
    // unable to reach a deployed runbook document.
    //
    // StartAutomationExecution authorizes against the automation-definition ARN, which is
    // derived from the document name, so it is scoped to the same prefixes as the document
    // itself: testRunbookYaml and testRemediationScript only ever run a document they just
    // created. An unscoped `automation-definition/*` would let this Lambda start any
    // automation in the account, and an `arn:...:ssm:*::automation-definition/*` entry
    // would add every AWS-owned runbook — neither is reachable from either tool.
    //
    // automation-execution/* stays unscoped: SSM assigns the execution id, so it cannot be
    // known or patterned in advance. ListDocuments is granted separately because it has no
    // resource-level scoping at all.
    this.mcpLambda.addToRolePolicy(
      new iam.PolicyStatement({
        sid: 'CustomRunbookTestDocuments',
        effect: iam.Effect.ALLOW,
        actions: [
          'ssm:CreateDocument',
          'ssm:DeleteDocument',
          'ssm:AddTagsToResource',
          'ssm:StartAutomationExecution',
          'ssm:GetAutomationExecution',
          'ssm:DescribeAutomationStepExecutions',
          // Stops an execution this tool can no longer observe: after a poll times out or
          // errors, testRunbookYaml/testRemediationScript cancel the run so an abandoned
          // remediation is not left acting on live resources. Like GetAutomationExecution,
          // it authorizes against the execution ARN SSM assigns, so it needs the unscoped
          // automation-execution/* resource below rather than the ASR-Custom-* definition.
          'ssm:StopAutomationExecution',
        ],
        resources: [
          `arn:${stack.partition}:ssm:*:${stack.account}:document/ASR-Custom-TestRunbook-*`,
          `arn:${stack.partition}:ssm:*:${stack.account}:document/ASR-Custom-TestRemediation-*`,
          `arn:${stack.partition}:ssm:*:${stack.account}:automation-definition/ASR-Custom-TestRunbook-*`,
          `arn:${stack.partition}:ssm:*:${stack.account}:automation-definition/ASR-Custom-TestRemediation-*`,
          `arn:${stack.partition}:ssm:*:${stack.account}:automation-execution/*`,
        ],
      }),
    );
    this.mcpLambda.addToRolePolicy(
      new iam.PolicyStatement({
        sid: 'ListSsmDocuments',
        effect: iam.Effect.ALLOW,
        // ListDocuments has no resource-level permissions; the handler's own filters restrict
        // results to self-owned Automation documents.
        actions: ['ssm:ListDocuments'],
        resources: ['*'],
      }),
    );
    this.mcpLambda.addToRolePolicy(
      new iam.PolicyStatement({
        sid: 'ReadControlRemapParameters',
        effect: iam.Effect.ALLOW,
        // `list_findings_without_runbook` resolves controls that ASR remediates through
        // ANOTHER control's runbook (S3.9 executes CloudTrail.7), which no document name
        // reveals. The mapping lives in the same parameters the Orchestrator reads at
        // execution time, so both sides agree by construction. Read-only, and scoped to the
        // solution's own namespace: without it the tool reports those controls as gaps and
        // sends a customer to author a custom runbook a built-in would always outrank.
        // Use resourceNamePrefix (the DEV- prefix stripped), because the remap parameters
        // are written under that normalized prefix; scoping to the raw solutionId would deny
        // the read on DEV builds, where solutionId still carries the DEV- prefix.
        actions: ['ssm:GetParametersByPath'],
        resources: [`arn:${stack.partition}:ssm:*:${stack.account}:parameter/Solutions/${props.resourceNamePrefix}/*`],
      }),
    );
    this.mcpLambda.addToRolePolicy(
      new iam.PolicyStatement({
        sid: 'ReadSsmDocuments',
        effect: iam.Effect.ALLOW,
        // DescribeDocument/GetDocument DO support resource-level scoping, so bound them to the
        // ASR-* name space (built-in ASR-* and custom ASR-Custom-* documents) rather than '*'.
        actions: ['ssm:DescribeDocument', 'ssm:GetDocument'],
        resources: [`arn:${stack.partition}:ssm:*:${stack.account}:document/ASR-*`],
      }),
    );
    // `check_deploy_readiness` confirms a control's remediation role exists by name
    // (SO0111-{remediationName}-{namespace}). That role is outside the
    // SO0111-Remediate-Custom-Test-* name space the test-role statement above covers, so
    // without this the readiness check fails with AccessDenied on iam:GetRole and surfaces
    // as an opaque 500 — the tool could never report on any control. GetRole only: the
    // check reads the role's existence and never modifies it.
    this.mcpLambda.addToRolePolicy(
      new iam.PolicyStatement({
        sid: 'ReadRemediationRolesForReadiness',
        effect: iam.Effect.ALLOW,
        actions: ['iam:GetRole'],
        resources: [`arn:${stack.partition}:iam::${stack.account}:role/${props.resourceNamePrefix}-*`],
      }),
    );
    // Read-only Security Hub: list_findings_without_runbook (GetFindings) and
    // get_finding_history (GetFindingHistory). Neither has resource-level permissions.
    this.mcpLambda.addToRolePolicy(
      new iam.PolicyStatement({
        sid: 'ReadSecurityHubFindings',
        effect: iam.Effect.ALLOW,
        actions: ['securityhub:GetFindings', 'securityhub:GetFindingHistory'],
        resources: ['*'],
      }),
    );

    // Proxied tool calls invoke the ASR API Lambda directly (not over HTTP), so the
    // gateway is independent of the API Gateway stage — which lets the API Gateway be
    // gated to the Web UI frontend while the gateway still deploys MCP-only.
    const apiFunction = lambda.Function.fromFunctionName(this, 'ImportedApiFunction', props.apiFunctionName);
    apiFunction.grantInvoke(this.mcpLambda);

    // --- Pass-through interceptor to forward Authorization header -----------

    const interceptorLambda = new lambda.Function(this, 'McpInterceptorFunction', {
      functionName: `${props.resourceNamePrefix}-ASR-MCP-Interceptor`,
      runtime: lambda.Runtime.NODEJS_24_X,
      // Use the hardened, unit-tested interceptor (mcp-server/mcpInterceptor.ts) rather than
      // an inline copy. The inline version only SET __authorizationHeader when a real header
      // was present and never deleted a caller-supplied one, so a forged __authorizationHeader
      // survived when no real header was sent — and cognitoAuthorizer decodes the JWT without
      // verifying its signature, so that was a privilege-escalation path. mcpInterceptor.handler
      // is unconditionally authoritative over the field (overwrite-or-delete, case-insensitive
      // header match).
      handler: 'mcp-server/mcpInterceptor.handler',
      code: getLambdaCode(props.solutionsBucket, props.solutionTMN, props.solutionVersion, 'asr_lambdas.zip'),
      description: 'ASR MCP gateway REQUEST interceptor (pass-through, forwards headers)',
      memorySize: 128,
      timeout: cdk.Duration.seconds(10),
      tracing: lambda.Tracing.ACTIVE,
    });

    addCfnGuardSuppression(interceptorLambda, 'LAMBDA_INSIDE_VPC');
    addCfnGuardSuppression(interceptorLambda, 'LAMBDA_CONCURRENCY_CHECK');

    // --- Own Cognito app client (authorization-code / login redirect) -------
    // ACG-native ships its own client rather than reusing the web-UI / DevOps
    // clients. It uses the OAuth **authorization-code** grant (user login with a
    // redirect), NOT client_credentials/M2M — the MCP client triggers the login
    // flow on a 401 and Cognito redirects back to a callback URL. Token-based
    // access carries the user's identity (so downstream tier/allowlist authz
    // reflects the real user). This is a PUBLIC client (no secret): the supported
    // MCP clients are native CLIs (Kiro, Claude Code, Codex) that use PKCE and
    // cannot keep or submit a client secret. No implicit/M2M flows enabled.
    // Native-client OAuth scopes, derived from the single source of truth so the app
    // client's issued scopes, the gateway authorizer's accepted scopes, and the
    // McpGatewayScopes stack output can never disagree.
    const nativeClientOAuthScopeNames = [...NATIVE_CLIENT_OAUTH_SCOPE_NAMES];
    const nativeClientOAuthScopes = nativeClientOAuthScopeNames.map((scopeName) =>
      cognito.OAuthScope.custom(scopeName),
    );
    // Space-delimited so the value survives as a plain CloudFormation output string and a
    // setup command can split it with no escaping. This is the format an OAuth `scope`
    // parameter uses on the wire.
    this.gatewayScopes = nativeClientOAuthScopeNames.join(' ');
    const gatewayClient = new cognito.UserPoolClient(this, 'McpGatewayClient', {
      userPool: props.userPool,
      userPoolClientName: `${props.resourceNamePrefix}-ASR-MCP-Gateway-Client`,
      generateSecret: false,
      authFlows: { userSrp: false, userPassword: false, adminUserPassword: false },
      oAuth: {
        flows: { authorizationCodeGrant: true },
        // Keep CloudFormation list tokens out of this synth-time property. Additional
        // callbacks are validated and appended by the registrar after deployment.
        callbackUrls: [...FIXED_NATIVE_CLIENT_CALLBACK_URLS],
        scopes: nativeClientOAuthScopes,
      },
    });
    this.gatewayClientId = gatewayClient.userPoolClientId;

    // The Lambda re-checks this client id on every request, so the direct-invoke path
    // enforces the same client restriction as the gateway authorizer's allowedClients
    // below. Set here rather than in the environment block above because the client does
    // not exist until this point.
    this.mcpLambda.addEnvironment('MCP_GATEWAY_CLIENT_ID', gatewayClient.userPoolClientId);

    // Managed Login v2 renders a hosted login page only after branding exists for
    // the app client. Default Cognito branding is sufficient for this CLI login flow.
    new cognito.CfnManagedLoginBranding(this, 'McpGatewayManagedLoginBranding', {
      userPoolId: props.userPool.userPoolId,
      clientId: gatewayClient.userPoolClientId,
      useCognitoProvidedValues: true,
    });

    // OIDC discovery URL for the pool (inbound JWT validation).
    const discoveryUrl = `https://cognito-idp.${cdk.Stack.of(this).region}.amazonaws.com/${props.userPool.userPoolId}/.well-known/openid-configuration`;

    // --- AgentCore Gateway (L2 construct) -----------------------------------

    const gateway = new agentcore.Gateway(this, 'McpGateway', {
      gatewayName: `${props.resourceNamePrefix.toLowerCase()}-mcp-gateway`,
      description: 'ASR MCP server gateway — Cognito JWT authorizer (dedicated client)',
      authorizerConfiguration: agentcore.GatewayAuthorizer.usingCustomJwt({
        discoveryUrl,
        // Native MCP clients bind OAuth authorization to the AgentCore gateway resource.
        // Advertise the same standard scopes accepted by Cognito so clients do not
        // omit scopes or invent a fallback scope during authorization-code login.
        allowedClients: [gatewayClient.userPoolClientId],
        allowedScopes: nativeClientOAuthScopes.map((scope) => scope.scopeName),
      }),
      // AUTHZ NOTE: this request interceptor forwards the caller's Authorization
      // header into tool args so the MCP Lambda reads the caller's real Cognito
      // claims (tier + per-client allowlist run unchanged). The finalized design
      // targets OBO token exchange instead, but the installed AgentCore CDK
      // module exposes no OBO/token-exchange outbound provider (only API_KEY /
      // OAUTH / GATEWAY_IAM_ROLE), so OBO is a documented follow-up.
      interceptorConfigurations: [
        agentcore.LambdaInterceptor.forRequest(interceptorLambda, { passRequestHeaders: true }),
      ],
    });
    gateway.node.addDependency(gatewayClient);

    this.gatewayId = gateway.gatewayId;
    const gatewayUrl = `https://${this.gatewayId}.gateway.bedrock-agentcore.${stack.region}.amazonaws.com/mcp`;
    this.gatewayUrl = gatewayUrl;

    // MCP clients send the gateway URL as the OAuth resource indicator. Cognito
    // issues a code for an unregistered resource but rejects its token exchange
    // with invalid_grant, so bind the exact deployment-specific gateway URL.
    new cognito.CfnUserPoolResourceServer(this, 'McpGatewayResourceServer', {
      userPoolId: props.userPool.userPoolId,
      identifier: gatewayUrl,
      name: `${props.resourceNamePrefix}-ASR-MCP-Gateway-Resource`,
      scopes: [
        {
          scopeName: 'gateway',
          scopeDescription: 'Binds OAuth tokens to the deployed ASR MCP gateway',
        },
      ],
    });

    // --- Gateway target: the MCP Lambda with its tool schema ----------------

    const toolSchemaJson = JSON.parse(
      fs.readFileSync(path.join(__dirname, '../../lambdas/mcp-server/toolSchema.json'), 'utf-8'),
    );
    gateway.addLambdaTarget('McpGatewayTarget', {
      gatewayTargetName: `${props.resourceNamePrefix.toLowerCase()}-mcp-tools`,
      description: 'ASR MCP tools — runbook authoring, findings, config evaluation',
      lambdaFunction: this.mcpLambda,
      toolSchema: agentcore.ToolSchema.fromInline(toolSchemaJson),
    });

    // --- Codex native-client callback registrar -----------------------------
    // Codex derives a stable callback id from the full MCP gateway URL, which AgentCore
    // only assigns during deployment — after the Cognito app client must already exist for
    // the gateway authorizer. This post-gateway custom resource computes the exact Codex
    // callback and adds it to the client's callback list (alongside the fixed Kiro/Claude
    // Code loopbacks), resolving the dependency without a manual two-pass deployment. The
    // handler module documents the full rationale.
    const callbackRegistrar = new lambda.Function(this, 'McpNativeClientCallbackRegistrar', {
      runtime: lambda.Runtime.NODEJS_24_X,
      handler: 'mcp-server/nativeClientCallbackRegistrar.handler',
      code: getLambdaCode(props.solutionsBucket, props.solutionTMN, props.solutionVersion, 'asr_lambdas.zip'),
      description: 'Adds the deployed ASR gateway callback URL to its Cognito native-client app',
      memorySize: 128,
      timeout: cdk.Duration.seconds(30),
      tracing: lambda.Tracing.ACTIVE,
    });
    callbackRegistrar.addToRolePolicy(
      new iam.PolicyStatement({
        effect: iam.Effect.ALLOW,
        actions: ['cognito-idp:DescribeUserPoolClient', 'cognito-idp:UpdateUserPoolClient'],
        resources: [props.userPool.userPoolArn],
      }),
    );
    addCfnGuardSuppression(callbackRegistrar, 'LAMBDA_INSIDE_VPC');
    addCfnGuardSuppression(callbackRegistrar, 'LAMBDA_CONCURRENCY_CHECK');
    callbackRegistrar.addPermission('AllowCloudFormationInvoke', {
      principal: new iam.ServicePrincipal('cloudformation.amazonaws.com'),
      // Confused-deputy guard: scope the invoke to CloudFormation in this account only, so a
      // stack in another account cannot invoke this registrar with arbitrary
      // ResourceProperties (it updates a Cognito app client's callbacks).
      sourceAccount: stack.account,
    });

    const callbackRegistration = new cdk.CustomResource(this, 'McpNativeClientCallbackRegistration', {
      serviceToken: callbackRegistrar.functionArn,
      properties: {
        UserPoolId: props.userPool.userPoolId,
        ClientId: gatewayClient.userPoolClientId,
        GatewayUrl: gatewayUrl,
        CodexCallbackBaseUrl: CODEX_OAUTH_CALLBACK_BASE_URL,
        FixedCallbackUrls: [...FIXED_NATIVE_CLIENT_CALLBACK_URLS],
        AdditionalCallbackUrls: props.additionalCallbackUrls,
        // UpdateUserPoolClient replaces the whole CallbackURLs list, so the registrar must
        // re-run on every stack update to reassert the ASR callbacks — otherwise a registrar
        // logic change, or callbacks reset by an out-of-band client update, would not be
        // reapplied. None of the properties above changes value between deploys on its own,
        // so this timestamp is the only thing that forces the resource to run.
        Timestamp: Date.now().toString(),
      },
    });
    callbackRegistration.node.addDependency(gateway);
    callbackRegistration.node.addDependency(gatewayClient);
    this.codexCallbackUrl = callbackRegistration.getAttString('CodexCallbackUrl');

    // --- Outputs -------------------------------------------------------------

    new cdk.CfnOutput(this, 'McpGatewayUrl', {
      description: 'MCP server endpoint URL — register this in the DevOps Agent console',
      value: gatewayUrl,
    });

    new cdk.CfnOutput(this, 'McpGatewayId', {
      description: 'AgentCore Gateway identifier',
      value: this.gatewayId,
    });

    new cdk.CfnOutput(this, 'McpGatewayClientId', {
      description:
        'Cognito app client ID for the MCP AgentCore Gateway (authorization-code / ' +
        'login redirect). Configure the MCP client with this client ID to start the ' +
        'user login flow; the gateway is login-only (no M2M/headless path).',
      value: this.gatewayClientId,
    });

    new cdk.CfnOutput(this, 'McpGatewayScopes', {
      description:
        'Space-delimited OAuth scopes native MCP clients must request during login. ' +
        'The ASR setup command inserts these as the client oauthScopes; Kiro in ' +
        'particular requires them explicitly because its default scope list includes ' +
        'offline_access, which Cognito rejects.',
      value: this.gatewayScopes,
    });

    new cdk.CfnOutput(this, 'McpCodexCallbackUrl', {
      description: 'Exact Codex OAuth callback URL registered for this MCP gateway deployment',
      value: this.codexCallbackUrl,
    });
  }
}
