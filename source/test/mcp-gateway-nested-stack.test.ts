// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import * as cdk from 'aws-cdk-lib';
import { Match, Template } from 'aws-cdk-lib/assertions';
import * as s3 from 'aws-cdk-lib/aws-s3';
import { McpGatewayNestedStack, McpGatewayNestedStackProps } from '../lib/mcp-gateway-nested-stack';

const USER_ACCOUNT_MAPPING_TABLE_ARN = 'arn:aws:dynamodb:us-east-1:123456789012:table/test-user-account-mapping';
const REMEDIATION_HISTORY_TABLE_ARN = 'arn:aws:dynamodb:us-east-1:123456789012:table/test-remediation-history';
const CUSTOM_RUNBOOK_TABLE_ARN = 'arn:aws:dynamodb:us-east-1:123456789012:table/test-custom-runbook';
const KMS_KEY_ARN = 'arn:aws:kms:us-east-1:123456789012:key/my-key';
const REMEDIATION_BOUNDARY_ARN = 'arn:aws:iam::123456789012:policy/SO0111-ASR-Custom-Runbook-Test-Boundary';

describe('McpGatewayNestedStack', () => {
  let template: Template;

  beforeEach(() => {
    const app = new cdk.App();
    const parentStack = new cdk.Stack(app, 'TestStack');
    const props: McpGatewayNestedStackProps = {
      solutionId: 'SO0111',
      solutionVersion: '1.0.0',
      solutionTMN: 'automated-security-response-on-aws',
      solutionsBucket: s3.Bucket.fromBucketName(parentStack, 'MockBucket', 'test-bucket'),
      resourceNamePrefix: 'SO0111',
      userPoolId: 'us-east-1_testpool',
      apiFunctionName: 'SO0111-ASR-APIs',
      userAccountMappingTableName: 'test-user-account-mapping',
      userAccountMappingTableARN: USER_ACCOUNT_MAPPING_TABLE_ARN,
      remediationHistoryTableName: 'test-remediation-history',
      remediationHistoryTableARN: REMEDIATION_HISTORY_TABLE_ARN,
      customRunbookTableName: 'test-custom-runbook',
      customRunbookTableARN: CUSTOM_RUNBOOK_TABLE_ARN,
      kmsKeyARN: KMS_KEY_ARN,
      remediationBoundaryPolicyArn: REMEDIATION_BOUNDARY_ARN,
    };

    const nestedStack = new McpGatewayNestedStack(parentStack, 'McpGatewayNestedStack', props);
    template = Template.fromStack(nestedStack);
  });

  /**
   * Actions granted on the resources a predicate selects, across every IAM policy in
   * the template. Selecting by resource (rather than asserting one statement) is what
   * makes an over-broad grant visible: a second statement widening the same resource
   * shows up in this list.
   */
  const statementsForResource = (matches: (resource: string) => boolean): string[] =>
    Object.values(template.findResources('AWS::IAM::Policy'))
      .flatMap((policy) => policy.Properties.PolicyDocument.Statement as { Action: unknown; Resource: unknown }[])
      .filter((statement) => matches(JSON.stringify(statement.Resource)))
      .flatMap((statement) => (Array.isArray(statement.Action) ? statement.Action : [statement.Action]) as string[]);

  it('requests only standard OIDC scopes for native clients', () => {
    template.hasResourceProperties('AWS::Cognito::UserPoolClient', {
      AllowedOAuthFlows: ['code'],
      AllowedOAuthScopes: Match.arrayWith(['openid', 'email', 'profile']),
    });

    const clients = template.findResources('AWS::Cognito::UserPoolClient');
    const scopes = Object.values(clients).flatMap((client) => client.Properties.AllowedOAuthScopes);
    expect(scopes).not.toContain('asr-api/gateway');
    expect(scopes).not.toContain('asr-api/api');
  });

  it('surfaces native-client connection values as stable stack outputs', () => {
    // The three native-client connection outputs are present with their exact shapes.
    expect(Object.keys(template.findOutputs('*'))).toEqual(
      expect.arrayContaining(['McpGatewayUrl', 'McpGatewayClientId', 'McpCodexCallbackUrl']),
    );
    template.hasOutput('McpGatewayUrl', {
      Description: 'MCP server endpoint URL',
      Value: Match.anyValue(),
    });
    template.hasOutput('McpGatewayClientId', {
      Description: 'Public Cognito OAuth client ID for native MCP clients',
      Value: Match.anyValue(),
    });
    template.hasOutput('McpGatewayScopes', {
      Description: 'Space-delimited OAuth scopes native MCP clients must request during login',
      Value: Match.anyValue(),
    });
    template.hasOutput('McpCodexCallbackUrl', {
      Description: 'Exact Codex OAuth callback URL registered for this deployment',
      Value: Match.anyValue(),
    });
  });

  it('enables only the authorization-code grant — no client_credentials/M2M path', () => {
    const clients = template.findResources('AWS::Cognito::UserPoolClient');
    const flows = Object.values(clients).flatMap((client) => client.Properties.AllowedOAuthFlows);
    expect(flows).not.toContain('client_credentials');
    expect(flows).not.toContain('implicit');
  });

  it('restricts inbound tokens to the dedicated gateway app client', () => {
    const clients = template.findResources('AWS::Cognito::UserPoolClient');
    const clientLogicalId = Object.keys(clients)[0];
    const gateways = template.findResources('AWS::BedrockAgentCore::Gateway');
    const gateway = Object.values(gateways)[0];

    expect(gateway.Properties.AuthorizerConfiguration.CustomJWTAuthorizer).toEqual({
      AllowedClients: [{ Ref: clientLogicalId }],
      AllowedScopes: ['openid', 'email', 'profile'],
      // Region is a token in a nested stack, so the URL renders as an Fn::Join.
      DiscoveryUrl: {
        'Fn::Join': [
          '',
          expect.arrayContaining([expect.stringMatching('us-east-1_testpool/\\.well-known/openid-configuration$')]),
        ],
      },
    });
  });

  it('registers the deployed gateway URL as the Cognito OAuth resource', () => {
    const gateways = template.findResources('AWS::BedrockAgentCore::Gateway');
    const gatewayLogicalId = Object.keys(gateways)[0];

    // Exactly one resource server, whose identifier binds to the deployed gateway id.
    expect(Object.keys(template.findResources('AWS::Cognito::UserPoolResourceServer'))).toHaveLength(1);
    template.hasResourceProperties('AWS::Cognito::UserPoolResourceServer', {
      UserPoolId: 'us-east-1_testpool',
      Identifier: {
        'Fn::Join': ['', Match.arrayWith([{ 'Fn::GetAtt': [gatewayLogicalId, 'GatewayIdentifier'] }])],
      },
      Name: 'SO0111-ASR-MCP-Gateway-Resource',
      Scopes: [
        {
          ScopeName: 'gateway',
          ScopeDescription: 'Binds OAuth tokens to the deployed ASR MCP gateway',
        },
      ],
    });
  });

  it('creates default managed-login branding for the gateway app client', () => {
    const clients = template.findResources('AWS::Cognito::UserPoolClient');
    const clientLogicalId = Object.keys(clients)[0];

    expect(Object.keys(template.findResources('AWS::Cognito::ManagedLoginBranding'))).toHaveLength(1);
    template.hasResourceProperties('AWS::Cognito::ManagedLoginBranding', {
      ClientId: { Ref: clientLogicalId },
      UserPoolId: 'us-east-1_testpool',
      UseCognitoProvidedValues: true,
    });
  });

  it('lets the MCP Lambda read per-client allowlists with GetItem only, plus Decrypt on the table key', () => {
    template.hasResourceProperties('AWS::IAM::Policy', {
      PolicyDocument: {
        Statement: Match.arrayWith([
          { Action: 'dynamodb:GetItem', Effect: 'Allow', Resource: USER_ACCOUNT_MAPPING_TABLE_ARN },
          { Action: 'kms:Decrypt', Effect: 'Allow', Resource: KMS_KEY_ARN },
        ]),
      },
    });
  });

  it('lets the MCP Lambda query remediation history on the table and its indexes, read-only', () => {
    template.hasResourceProperties('AWS::IAM::Policy', {
      PolicyDocument: {
        Statement: Match.arrayWith([
          {
            Action: 'dynamodb:Query',
            Effect: 'Allow',
            Resource: [REMEDIATION_HISTORY_TABLE_ARN, `${REMEDIATION_HISTORY_TABLE_ARN}/index/*`],
          },
        ]),
      },
    });
  });

  it('lets the MCP Lambda resolve a caller email via AdminGetUser, scoped to the user pool', () => {
    // Access tokens carry the username, not the email; resolveHumanUserEmail calls
    // AdminGetUser to map it to the UserAccountMapping key. Without this grant, human
    // callers (Delegated Admin / Account Operator) fail with a 503.
    template.hasResourceProperties('AWS::IAM::Policy', {
      PolicyDocument: {
        Statement: Match.arrayWith([
          Match.objectLike({
            Action: 'cognito-idp:AdminGetUser',
            Effect: 'Allow',
            Resource: {
              'Fn::Join': ['', Match.arrayWith([Match.stringLikeRegexp('userpool/us-east-1_testpool$')])],
            },
          }),
        ]),
      },
    });
  });

  describe('custom-runbook recorded-testing permissions', () => {
    it('sets the permissions-boundary ARN as an env var so test_runbook_yaml can run', () => {
      template.hasResourceProperties('AWS::Lambda::Function', {
        FunctionName: 'SO0111-ASR-MCP-Server',
        Environment: {
          Variables: Match.objectLike({ CUSTOM_RUNBOOK_TEST_BOUNDARY_ARN: REMEDIATION_BOUNDARY_ARN }),
        },
      });
    });

    it('lets the MCP Lambda manage test roles only within the custom-runbook test-role name space', () => {
      template.hasResourceProperties('AWS::IAM::Policy', {
        PolicyDocument: {
          Statement: Match.arrayWith([
            Match.objectLike({
              Sid: 'ManageCustomRunbookTestRoles',
              Effect: 'Allow',
              Action: Match.arrayWith(['iam:CreateRole', 'iam:DeleteRole', 'iam:PutRolePermissionsBoundary']),
              Resource: {
                'Fn::Join': ['', Match.arrayWith([Match.stringLikeRegexp('role/SO0111-Remediate-Custom-Test-\\*$')])],
              },
            }),
          ]),
        },
      });
    });

    it('denies creating a test role that does not carry the ASR remediation boundary', () => {
      template.hasResourceProperties('AWS::IAM::Policy', {
        PolicyDocument: {
          Statement: Match.arrayWith([
            Match.objectLike({
              Sid: 'RequireBoundaryOnTestRoles',
              Effect: 'Deny',
              Action: ['iam:CreateRole', 'iam:PutRolePermissionsBoundary'],
              Condition: { StringNotEquals: { 'iam:PermissionsBoundary': REMEDIATION_BOUNDARY_ARN } },
            }),
          ]),
        },
      });
    });

    it('passes the test role to SSM only', () => {
      template.hasResourceProperties('AWS::IAM::Policy', {
        PolicyDocument: {
          Statement: Match.arrayWith([
            Match.objectLike({
              Sid: 'PassCustomRunbookTestRoleToSsm',
              Effect: 'Allow',
              Action: 'iam:PassRole',
              Condition: { StringEquals: { 'iam:PassedToService': 'ssm.amazonaws.com' } },
            }),
          ]),
        },
      });
    });

    it('scopes transient test-document lifecycle to the transient-test name spaces', () => {
      template.hasResourceProperties('AWS::IAM::Policy', {
        PolicyDocument: {
          Statement: Match.arrayWith([
            Match.objectLike({
              Sid: 'CustomRunbookTestDocuments',
              Effect: 'Allow',
              Action: Match.arrayWith(['ssm:CreateDocument', 'ssm:DeleteDocument', 'ssm:StartAutomationExecution']),
            }),
          ]),
        },
      });
    });

    it('scopes StartAutomationExecution to the transient-test definitions, not every automation', () => {
      // Asserting the actions alone let an unscoped `automation-definition/*` (plus the
      // AWS-owned `ssm:*::automation-definition/*`) sit here unnoticed, which allowed this
      // Lambda to start any automation in the account and every AWS-managed runbook. Both
      // test tools only ever run a document they just created under the transient-test
      // prefixes generateDocumentName enforces, so the definition ARN is bounded to those
      // prefixes — a broader ASR-Custom-* grant would also cover DEPLOYED custom runbook
      // documents, letting DeleteDocument here reach one. automation-execution/* stays
      // unscoped — SSM assigns the execution id, so it cannot be patterned in advance.
      const statements = Object.values(template.findResources('AWS::IAM::Policy'))
        .flatMap(
          (policy) =>
            policy.Properties.PolicyDocument.Statement as { Sid?: string; Action: unknown; Resource: unknown }[],
        )
        .filter((statement) => statement.Sid === 'CustomRunbookTestDocuments');
      expect(statements).toHaveLength(1);

      // The account is a token in a nested stack, so each ARN renders as an Fn::Join;
      // assert on the rendered suffixes rather than literal ARNs.
      const resources = JSON.stringify(statements[0].Resource);
      expect(resources).toContain('automation-definition/ASR-Custom-TestRunbook-*');
      expect(resources).toContain('automation-definition/ASR-Custom-TestRemediation-*');
      expect(resources).toContain('automation-execution/*');
      expect(resources).toContain('document/ASR-Custom-TestRunbook-*');
      expect(resources).toContain('document/ASR-Custom-TestRemediation-*');
      // No unscoped definition wildcard, nothing in the AWS-owned (empty account) space,
      // and no grant broad enough to reach deployed ASR-Custom-* runbook documents.
      expect(resources).not.toContain('automation-definition/*');
      expect(resources).not.toContain(':ssm:*::');
      expect(resources).not.toContain('document/ASR-Custom-*"');

      // The abandonment-cancellation path (tryStopExecution) calls StopAutomationExecution
      // after a poll times out or errors; without this action the cancel is AccessDenied and
      // a remediation is left running against live resources unwatched.
      expect(statements[0].Action).toContain('ssm:StopAutomationExecution');
    });

    it('lets check_deploy_readiness read a control remediation role outside the test name space', () => {
      // The readiness check calls iam:GetRole on SO0111-{remediationName}-{namespace}, which
      // the SO0111-Remediate-Custom-Test-* test-role statement does not cover. Without a
      // grant for it the tool always failed with AccessDenied behind an opaque 500. GetRole
      // only — the check reads existence and never modifies the role.
      const statements = Object.values(template.findResources('AWS::IAM::Policy'))
        .flatMap((policy) => policy.Properties.PolicyDocument.Statement as { Sid?: string; Action: unknown }[])
        .filter((statement) => statement.Sid === 'ReadRemediationRolesForReadiness');
      expect(statements).toHaveLength(1);
      expect(statements[0].Action).toBe('iam:GetRole');
      template.hasResourceProperties('AWS::IAM::Policy', {
        PolicyDocument: {
          Statement: Match.arrayWith([
            Match.objectLike({
              Sid: 'ReadRemediationRolesForReadiness',
              Effect: 'Allow',
              Resource: { 'Fn::Join': ['', Match.arrayWith([Match.stringLikeRegexp('role/SO0111-\\*$')])] },
            }),
          ]),
        },
      });
    });

    it('scopes DescribeDocument/GetDocument to the ASR-* name space, with ListDocuments alone on *', () => {
      // ListDocuments has no resource-level permissions, but DescribeDocument/GetDocument do —
      // so only the list action is granted on '*'; the reads are bounded to ASR-* documents.
      template.hasResourceProperties('AWS::IAM::Policy', {
        PolicyDocument: {
          Statement: Match.arrayWith([
            Match.objectLike({ Sid: 'ListSsmDocuments', Effect: 'Allow', Action: 'ssm:ListDocuments', Resource: '*' }),
            Match.objectLike({
              Sid: 'ReadSsmDocuments',
              Effect: 'Allow',
              Action: ['ssm:DescribeDocument', 'ssm:GetDocument'],
              Resource: {
                'Fn::Join': ['', Match.arrayWith([Match.stringLikeRegexp(':document/ASR-\\*$')])],
              },
            }),
          ]),
        },
      });
    });

    it('grants read-only Security Hub for finding lookup and history', () => {
      template.hasResourceProperties('AWS::IAM::Policy', {
        PolicyDocument: {
          Statement: Match.arrayWith([
            Match.objectLike({
              Sid: 'ReadSecurityHubFindings',
              Effect: 'Allow',
              Action: ['securityhub:GetFindings', 'securityhub:GetFindingHistory'],
              Resource: '*',
            }),
          ]),
        },
      });
    });
  });

  it('passes the allowlist and remediation history table names to the MCP Lambda', () => {
    template.hasResourceProperties('AWS::Lambda::Function', {
      FunctionName: 'SO0111-ASR-MCP-Server',
      Environment: {
        Variables: Match.objectLike({
          USER_ACCOUNT_MAPPING_TABLE_NAME: 'test-user-account-mapping',
          REMEDIATION_HISTORY_TABLE_NAME: 'test-remediation-history',
        }),
      },
    });
  });

  it('lets the MCP Lambda read then stamp a test result on a runbook version', () => {
    template.hasResourceProperties('AWS::IAM::Policy', {
      PolicyDocument: {
        Statement: Match.arrayWith([
          {
            Action: ['dynamodb:GetItem', 'dynamodb:UpdateItem'],
            Effect: 'Allow',
            Resource: CUSTOM_RUNBOOK_TABLE_ARN,
          },
        ]),
      },
    });
  });

  it('grants only key reads and the test-outcome write on the custom runbook table itself', () => {
    const runbookTableActions = statementsForResource(
      (resource) => resource.includes(CUSTOM_RUNBOOK_TABLE_ARN) && !resource.includes('/index/'),
    );
    // GetItem for the content-digest gate, UpdateItem to stamp the outcome; nothing
    // more — no PutItem/DeleteItem, and no table-level Query/Scan.
    expect(runbookTableActions).toEqual(['dynamodb:GetItem', 'dynamodb:UpdateItem']);
  });

  it('grants Query on the controlId-status index, which the coverage-gap tool reads', () => {
    // list_findings_without_runbook confirms custom-runbook coverage through
    // findByControlId, which queries the GSI. A table-level grant does not authorize an
    // index query, and when the query is denied the tool fails OPEN — unconfirmed
    // claims count as coverage, hiding a control whose runbook is only DRAFT. Scoped to
    // the index so the tool still cannot query the base table.
    const indexActions = statementsForResource((resource) =>
      resource.includes(`${CUSTOM_RUNBOOK_TABLE_ARN}/index/controlId-status-index`),
    );
    expect(indexActions).toEqual(['dynamodb:Query']);
  });

  it('tells the MCP Lambda which table to record custom-runbook test results in', () => {
    template.hasResourceProperties('AWS::Lambda::Function', {
      FunctionName: 'SO0111-ASR-MCP-Server',
      Environment: {
        Variables: Match.objectLike({
          CUSTOM_RUNBOOK_TABLE_NAME: 'test-custom-runbook',
        }),
      },
    });
  });

  it('invokes the ASR API Lambda directly rather than over HTTP, so it does not need the API Gateway', () => {
    // The gateway calls the API by function name (not URL), which is what lets the API
    // Gateway stage be gated to the Web UI frontend while the gateway still deploys MCP-only.
    const functions = template.findResources('AWS::Lambda::Function', {
      Properties: { FunctionName: 'SO0111-ASR-MCP-Server' },
    });
    const mcpFunction = Object.values(functions)[0];
    const envVars = mcpFunction.Properties?.Environment?.Variables ?? {};
    expect(envVars).toHaveProperty('API_FUNCTION_NAME', 'SO0111-ASR-APIs');
    expect(envVars).not.toHaveProperty('API_GATEWAY_ENDPOINT');
  });

  it('grants the MCP Lambda permission to invoke the ASR API Lambda', () => {
    template.hasResourceProperties('AWS::IAM::Policy', {
      PolicyDocument: {
        Statement: Match.arrayWith([
          Match.objectLike({
            Action: 'lambda:InvokeFunction',
            Effect: 'Allow',
          }),
        ]),
      },
    });
  });

  it('passes the built-in CLI callbacks to the callback registrar for deploy-time registration', () => {
    // Kiro and Claude Code use fixed loopback redirect URLs, passed to the custom resource
    // as FixedCallbackUrls. Codex's callback is derived from the gateway URL at deploy time
    // (CodexCallbackBaseUrl), so it is not a synth-time literal on the app client.
    template.hasResourceProperties('AWS::CloudFormation::CustomResource', {
      FixedCallbackUrls: Match.arrayWith([
        'http://localhost:8770',
        'http://localhost:8770/oauth/callback',
        'http://localhost:8772/callback',
      ]),
      AdditionalCallbackUrls: { Ref: 'AdditionalMcpCallbackUrls' },
      CodexCallbackBaseUrl: 'http://127.0.0.1:8780/callback',
    });
  });

  it('keeps additional callbacks out of the synth-time Cognito client', () => {
    const clients = template.findResources('AWS::Cognito::UserPoolClient', {
      Properties: { ClientName: 'SO0111-ASR-MCP-Gateway-Client' },
    });
    const callbackUrls = Object.values(clients)[0].Properties?.CallbackURLs;

    expect(callbackUrls).toEqual([
      'http://localhost:8770',
      'http://localhost:8770/oauth/callback',
      'http://localhost:8772/callback',
    ]);
    expect(callbackUrls).not.toContain('https://example.com/oauth/callback');
  });

  it('creates the gateway app client as a public PKCE client with no secret', () => {
    // The supported MCP clients are native CLIs (Kiro, Claude Code, Codex) that use PKCE
    // and cannot submit a client secret, so the app client must be public. GenerateSecret
    // absent (or false) keeps it public; a generated secret would reject those CLIs at
    // token exchange.
    const clients = template.findResources('AWS::Cognito::UserPoolClient', {
      Properties: { ClientName: 'SO0111-ASR-MCP-Gateway-Client' },
    });
    expect(Object.keys(clients)).toHaveLength(1);
    expect(Object.values(clients)[0].Properties?.GenerateSecret ?? false).toBe(false);
  });
});
