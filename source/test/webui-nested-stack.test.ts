// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import * as cdk from 'aws-cdk-lib';
import { Match, Template } from 'aws-cdk-lib/assertions';
import * as s3 from 'aws-cdk-lib/aws-s3';
import * as dynamodb from 'aws-cdk-lib/aws-dynamodb';
import { WebUINestedStack, WebUINestedStackProps } from '../lib/webui-nested-stack';

jest.mock('../lib/cdk-helper/lambda-code-manifest', () => {
  const original = jest.requireActual('../lib/cdk-helper/lambda-code-manifest');
  return {
    ...original,
    getWebUIManifestHash: () => 'mock-webui-manifest-hash',
  };
});

describe('WebUINestedStack', () => {
  let app: cdk.App;
  let stack: cdk.Stack;
  let mockBucket: s3.IBucket;
  let props: WebUINestedStackProps;

  beforeEach(() => {
    app = new cdk.App();
    stack = new cdk.Stack(app, 'TestStack');

    mockBucket = s3.Bucket.fromBucketName(stack, 'MockBucket', 'test-bucket');
    const mockCsvExportBucket = s3.Bucket.fromBucketName(stack, 'MockCsvExportBucket', 'test-csv-export-bucket');
    const mockRemediationConfigTable = new dynamodb.Table(stack, 'MockRemediationConfigTable', {
      partitionKey: { name: 'controlId', type: dynamodb.AttributeType.STRING },
    });
    const mockResourceFiltersTable = new dynamodb.Table(stack, 'MockResourceFiltersTable', {
      partitionKey: { name: 'filterId', type: dynamodb.AttributeType.STRING },
    });
    const mockNotificationConfigTable = new dynamodb.Table(stack, 'MockNotificationConfigTable', {
      partitionKey: { name: 'configId', type: dynamodb.AttributeType.STRING },
    });
    const mockNotificationBatchesTable = new dynamodb.Table(stack, 'MockNotificationBatchesTable', {
      partitionKey: { name: 'configId', type: dynamodb.AttributeType.STRING },
      sortKey: { name: 'windowEnd', type: dynamodb.AttributeType.STRING },
    });
    const mockCustomRunbookTable = new dynamodb.Table(stack, 'MockCustomRunbookTable', {
      partitionKey: { name: 'runbookId', type: dynamodb.AttributeType.STRING },
      sortKey: { name: 'version', type: dynamodb.AttributeType.NUMBER },
    });
    const mockCustomRunbookBucket = s3.Bucket.fromBucketName(stack, 'MockCustomRunbookBucket', 'test-runbook-bucket');
    props = {
      solutionId: 'SO0111',
      solutionVersion: '1.0.0',
      solutionTMN: 'automated-security-response-on-aws',
      solutionsBucket: mockBucket,
      resourceNamePrefix: 'SO0111',
      findingsTable: 'arn:aws:dynamodb:us-east-1:123456789012:table/test-findings-table',
      remediationHistoryTable: 'arn:aws:dynamodb:us-east-1:123456789012:table/test-remediation-history-table',
      remediationConfigTable: mockRemediationConfigTable,
      resourceFiltersTable: mockResourceFiltersTable,
      apiFunctionName: 'SO0111-ASR-API',
      stackName: 'TestStack',
      adminUserEmail: 'test@example.com',
      kmsKeyARN: 'arn:aws:kms:us-east-1:123456789012:key/my-key',
      orchestratorArn: 'arn:aws:states:us-east-1:123456789012:stateMachine:test-orchestrator',
      csvExportBucket: mockCsvExportBucket,
      presignedUrlTTLDays: 7,
      ticketingGenFunction: 'test-ticketing-function',
      securityHubV2Enabled: 'True',
      notificationConfigTable: mockNotificationConfigTable,
      notificationBatchesTable: mockNotificationBatchesTable,
      iacTemplatesBucket: mockBucket,
      customRunbookTable: mockCustomRunbookTable,
      customRunbookBucket: mockCustomRunbookBucket,
      enableRollback: 'no',
      findingsTtlDays: '8',
      mfaConfiguration: 'OFF',
      deployFrontend: 'yes',
      mcpEnabled: 'no',
    };
  });

  test('WebUINestedStack creates API and WebUI components', () => {
    // Act
    const webUINestedStack = new WebUINestedStack(stack, 'WebUINestedStack', props);

    // Assert
    const template = Template.fromStack(webUINestedStack);

    // Verify API Gateway is created
    template.hasResourceProperties('AWS::ApiGateway::RestApi', {
      Name: 'AutomatedSecurityResponseApi',
      Description: 'Automated Security Response on AWS solution APIs',
    });

    // Verify Findings Lambda function is created
    template.hasResourceProperties('AWS::Lambda::Function', {
      Runtime: 'nodejs24.x',
      Handler: 'api/handlers/apiHandler.handler',
    });

    // Verify WebUI deployment Lambda function is created with the CloudFront
    // distribution id wired in so it can invalidate the cache after a redeploy.
    template.hasResourceProperties('AWS::Lambda::Function', {
      Handler: 'api/handlers/deployWebui.lambdaHandler',
      Runtime: 'nodejs24.x',
      Environment: {
        Variables: Match.objectLike({
          CLOUDFRONT_DISTRIBUTION_ID: Match.anyValue(),
        }),
      },
    });

    // Verify the deploy lambda role is granted cloudfront:CreateInvalidation
    // (scoped to a distribution) so the post-deploy cache invalidation works.
    template.hasResourceProperties('AWS::IAM::Policy', {
      PolicyDocument: {
        Statement: Match.arrayWith([
          Match.objectLike({
            Action: 'cloudfront:CreateInvalidation',
            Effect: 'Allow',
          }),
        ]),
      },
    });

    // Verify the API lambda role can publish to KMS-encrypted (SSE) customer SNS channel topics:
    // sns:Publish alone is insufficient, so kms:GenerateDataKey + kms:Decrypt are granted and
    // constrained to use through SNS via the kms:ViaService condition. The region resolves to a
    // token in the nested stack, so assert the condition key is present rather than its literal value.
    template.hasResourceProperties('AWS::IAM::Policy', {
      PolicyDocument: {
        Statement: Match.arrayWith([
          Match.objectLike({
            Action: ['kms:GenerateDataKey', 'kms:Decrypt'],
            Effect: 'Allow',
            Condition: {
              StringEquals: { 'kms:ViaService': Match.anyValue() },
            },
          }),
        ]),
      },
    });

    // Verify CloudFront distribution is created (part of WebUIHostingConstruct)
    template.hasResourceProperties('AWS::CloudFront::Distribution', {});

    // Verify S3 bucket is created for WebUI hosting
    template.hasResourceProperties('AWS::S3::Bucket', {
      VersioningConfiguration: {
        Status: 'Enabled',
      },
    });

    // Verify WAF WebACL is created
    template.hasResourceProperties('AWS::WAFv2::WebACL', {
      Scope: 'REGIONAL',
      DefaultAction: {
        Allow: {},
      },
    });
  });

  test('CloudFront response headers policy sets HSTS max-age to the security-guidance-required 47304000s', () => {
    // The "Set secure HTTP headers for websites" security guidance requires
    // Strict-Transport-Security: max-age=47304000; includeSubDomains. Assert the
    // rendered CloudFront ResponseHeadersPolicy carries exactly that max-age (in
    // seconds) with subdomains included, so a future edit cannot silently
    // regress the value.
    const webUINestedStack = new WebUINestedStack(stack, 'WebUINestedStack', props);
    const template = Template.fromStack(webUINestedStack);

    const policies = template.findResources('AWS::CloudFront::ResponseHeadersPolicy');
    const hsts =
      Object.values(policies)[0].Properties.ResponseHeadersPolicyConfig.SecurityHeadersConfig.StrictTransportSecurity;

    expect(hsts.AccessControlMaxAgeSec).toBe(47304000);
    expect(hsts.IncludeSubdomains).toBe(true);
    expect(hsts.Override).toBe(true);
  });

  test('WebUINestedStack omits enabled MFA methods when the deployment parameter is OFF', () => {
    // GIVEN
    const mfaConfiguration = new cdk.CfnParameter(stack, 'MFAConfiguration', {
      type: 'String',
      default: 'OFF',
    });
    props.mfaConfiguration = mfaConfiguration.valueAsString;

    // WHEN
    const webUINestedStack = new WebUINestedStack(stack, 'WebUINestedStack', props);
    const template = Template.fromStack(webUINestedStack);
    const userPools = template.findResources('AWS::Cognito::UserPool');
    const userPool = Object.values(userPools)[0];

    // THEN
    expect(userPool.Properties.EnabledMfas).toEqual({
      'Fn::If': [
        expect.stringContaining('IsMultiFactorAuthenticationOff'),
        { Ref: 'AWS::NoValue' },
        ['SOFTWARE_TOKEN_MFA'],
      ],
    });
  });

  test('WebUINestedStack maps the REQUIRED MFA parameter to the CloudFormation-valid ON value', () => {
    // GIVEN a tokenized MFAConfiguration parameter (allowedValues OFF | OPTIONAL | REQUIRED).
    const mfaConfiguration = new cdk.CfnParameter(stack, 'MFAConfiguration', {
      type: 'String',
      default: 'OFF',
    });
    props.mfaConfiguration = mfaConfiguration.valueAsString;

    // WHEN
    const webUINestedStack = new WebUINestedStack(stack, 'WebUINestedStack', props);
    const template = Template.fromStack(webUINestedStack);
    const userPool = Object.values(template.findResources('AWS::Cognito::UserPool'))[0];

    // THEN MfaConfiguration translates REQUIRED -> ON at deploy time (CloudFormation only
    // accepts OFF | ON | OPTIONAL), passing OFF/OPTIONAL through unchanged.
    expect(userPool.Properties.MfaConfiguration).toEqual({
      'Fn::If': [expect.stringContaining('IsMultiFactorAuthenticationRequired'), 'ON', { Ref: expect.any(String) }],
    });
  });

  test('WebUINestedStack applies account-wide stage-level API throttling', () => {
    // Act
    const webUINestedStack = new WebUINestedStack(stack, 'WebUINestedStack', props);

    // Assert: the prod stage carries the configured global throttle ceiling
    const template = Template.fromStack(webUINestedStack);
    expect(Object.keys(template.findResources('AWS::ApiGateway::Stage')).length).toBeGreaterThan(0);
    template.hasResourceProperties('AWS::ApiGateway::Stage', {
      MethodSettings: [
        {
          HttpMethod: '*',
          ResourcePath: '/*',
          ThrottlingRateLimit: 500,
          ThrottlingBurstLimit: 1000,
        },
      ],
    });
  });

  test('WebUINestedStack adds WAF rate-based rules for sensitive writes, per-user, and per-IP limits', () => {
    // Act
    const webUINestedStack = new WebUINestedStack(stack, 'WebUINestedStack', props);

    // Assert: the WebACL carries the three rate-based rules with the configured
    // limits, a 60s window, JWT-header aggregation for the per-user rules, a
    // scope-down on the sensitive-write rule, and Block mode returning HTTP 429.
    const template = Template.fromStack(webUINestedStack);
    expect(Object.keys(template.findResources('AWS::WAFv2::WebACL')).length).toBeGreaterThan(0);
    template.hasResourceProperties('AWS::WAFv2::WebACL', {
      // Rate-limited requests are answered with 429 (not the WAF default 403).
      CustomResponseBodies: { ASRRateLimited: Match.objectLike({ ContentType: 'APPLICATION_JSON' }) },
      Rules: Match.arrayWith([
        Match.objectLike({
          Name: 'ASRSensitiveWriteRateLimit',
          Action: {
            Block: {
              CustomResponse: Match.objectLike({
                ResponseCode: 429,
                CustomResponseBodyKey: 'ASRRateLimited',
                // CORS headers so the browser can read the 429 WAF returns ahead of API Gateway.
                ResponseHeaders: Match.arrayWith([{ Name: 'Access-Control-Allow-Origin', Value: '*' }]),
              }),
            },
          },
          Statement: {
            RateBasedStatement: Match.objectLike({
              Limit: 300,
              EvaluationWindowSec: 60,
              AggregateKeyType: 'CUSTOM_KEYS',
              CustomKeys: Match.arrayWith([Match.objectLike({ Header: Match.objectLike({ Name: 'authorization' }) })]),
              ScopeDownStatement: { OrStatement: Match.anyValue() },
            }),
          },
        }),
        Match.objectLike({
          Name: 'ASRPerUserRateLimit',
          Statement: {
            RateBasedStatement: Match.objectLike({ Limit: 1000, AggregateKeyType: 'CUSTOM_KEYS' }),
          },
        }),
        Match.objectLike({
          Name: 'ASRPerIpRateLimit',
          Statement: {
            RateBasedStatement: Match.objectLike({ Limit: 2000, AggregateKeyType: 'IP' }),
          },
        }),
      ]),
    });
  });

  test('AdminProtection skips the user-management routes, whose path carries a user email', () => {
    // A user whose address contains "admin" (admin@example.com) otherwise matched the
    // managed group and was blocked with a bare WAF 403 before reaching the API, leaving
    // that user impossible to edit or delete.
    const webUINestedStack = new WebUINestedStack(stack, 'WebUINestedStack', props);
    const template = Template.fromStack(webUINestedStack);

    // The synthesized shape of the one scope-down statement this test is about; anything
    // outside it is left unknown so a drift in the template fails loudly rather than being
    // papered over by a cast.
    interface SynthesizedScopeDownRule {
      Name: string;
      Statement: {
        ManagedRuleGroupStatement: {
          ScopeDownStatement?: {
            NotStatement: {
              Statement: {
                ByteMatchStatement: {
                  SearchString: string;
                  PositionalConstraint: string;
                  FieldToMatch: { UriPath: Record<string, never> };
                  TextTransformations: Array<{ Priority: number; Type: string }>;
                };
              };
            };
          };
        };
      };
    }

    const webAcls = template.findResources('AWS::WAFv2::WebACL');
    const rules = Object.values(webAcls)[0].Properties.Rules as SynthesizedScopeDownRule[];
    const adminProtection = rules.find((rule) => rule.Name === 'AWS-AWSManagedRulesAdminProtectionRuleSet');
    expect(adminProtection).toBeDefined();
    const scopeDown = adminProtection?.Statement.ManagedRuleGroupStatement.ScopeDownStatement;
    expect(scopeDown).toBeDefined();

    const byteMatch = scopeDown?.NotStatement.Statement.ByteMatchStatement;
    expect(byteMatch?.SearchString).toBe('/users');
    expect(byteMatch?.PositionalConstraint).toBe('CONTAINS');
    expect(byteMatch?.FieldToMatch.UriPath).toEqual({});
    expect(byteMatch?.TextTransformations.map((t) => t.Type)).toEqual(['URL_DECODE', 'LOWERCASE']);
  });

  test('WAF sensitive-write scope-down URL-decodes and normalizes the path before matching', () => {
    // Arrange
    const webUINestedStack = new WebUINestedStack(stack, 'WebUINestedStack', props);
    const template = Template.fromStack(webUINestedStack);

    // Act: pull the sensitive-write rule's scope-down route statements.
    const webAcls = template.findResources('AWS::WAFv2::WebACL');
    const rules = Object.values(webAcls)[0].Properties.Rules as Array<Record<string, unknown>>;
    const sensitiveWriteRule = rules.find((rule) => rule.Name === 'ASRSensitiveWriteRateLimit');
    const routeStatements = (
      sensitiveWriteRule!.Statement as {
        RateBasedStatement: { ScopeDownStatement: { OrStatement: { Statements: Array<Record<string, unknown>> } } };
      }
    ).RateBasedStatement.ScopeDownStatement.OrStatement.Statements;

    const uriPathTransforms = routeStatements
      .flatMap((route) => (route.AndStatement as { Statements: Array<Record<string, unknown>> }).Statements)
      .filter((statement) => {
        const byteMatch = statement.ByteMatchStatement as { FieldToMatch?: Record<string, unknown> } | undefined;
        return byteMatch?.FieldToMatch?.UriPath !== undefined;
      })
      .map(
        (statement) =>
          (statement.ByteMatchStatement as { TextTransformations: Array<{ Type: string }> }).TextTransformations,
      );

    // Assert: every uriPath match decodes then normalizes the path; none rely on NONE.
    expect(uriPathTransforms.length).toBeGreaterThan(0);
    for (const transforms of uriPathTransforms) {
      const types = transforms.map((transform) => transform.Type);
      expect(types).toContain('URL_DECODE');
      expect(types).toContain('NORMALIZE_PATH');
      expect(types).not.toContain('NONE');
    }
  });

  test('WebUINestedStack downgrades Bot Control rules that block non-browser API callers to Count', () => {
    // Act
    const webUINestedStack = new WebUINestedStack(stack, 'WebUINestedStack', props);

    // Assert: the Bot Control managed rule group keeps its group-level default
    // (overrideAction None) but downgrades the rules that block legitimate
    // non-browser callers — machine-to-machine (client_credentials) clients and
    // the MCP server Lambda, which present non-browser User-Agents from
    // datacenter IPs — to Count, so their requests reach the Cognito authorizer
    // instead of being blocked by WAF first.
    const template = Template.fromStack(webUINestedStack);
    expect(Object.keys(template.findResources('AWS::WAFv2::WebACL')).length).toBeGreaterThan(0);
    template.hasResourceProperties('AWS::WAFv2::WebACL', {
      Rules: Match.arrayWith([
        Match.objectLike({
          Name: 'AWS-AWSManagedRulesBotControlRuleSet',
          OverrideAction: { None: {} },
          Statement: {
            ManagedRuleGroupStatement: Match.objectLike({
              Name: 'AWSManagedRulesBotControlRuleSet',
              RuleActionOverrides: Match.arrayWith([
                { Name: 'SignalNonBrowserUserAgent', ActionToUse: { Count: {} } },
                { Name: 'SignalKnownBotDataCenter', ActionToUse: { Count: {} } },
                { Name: 'CategoryHttpLibrary', ActionToUse: { Count: {} } },
              ]),
            }),
          },
        }),
      ]),
    });
  });

  test('WebUINestedStack exposes correct public properties', () => {
    // Act
    const webUINestedStack = new WebUINestedStack(stack, 'WebUINestedStack', props);

    // Assert
    expect(webUINestedStack.api).toBeDefined();
    expect(webUINestedStack.webUIBucket).toBeDefined();
    expect(webUINestedStack.distributionDomainName).toBeDefined();
  });

  test('WebUINestedStack creates resources with correct naming convention', () => {
    // Act
    const webUINestedStack = new WebUINestedStack(stack, 'WebUINestedStack', props);

    // Assert
    const template = Template.fromStack(webUINestedStack);
    expect(Object.keys(template.findResources('AWS::Lambda::Function')).length).toBeGreaterThan(0);

    // Verify API Lambda function uses correct naming
    template.hasResourceProperties('AWS::Lambda::Function', {
      Handler: 'api/handlers/apiHandler.handler',
    });

    // Verify IAM roles are created for Lambda functions
    template.hasResourceProperties('AWS::IAM::Role', {
      AssumeRolePolicyDocument: {
        Statement: [
          {
            Action: 'sts:AssumeRole',
            Effect: 'Allow',
            Principal: {
              Service: 'lambda.amazonaws.com',
            },
          },
        ],
        Version: '2012-10-17',
      },
    });

    // Verify WAF WebACL uses correct naming
    template.hasResourceProperties('AWS::WAFv2::WebACL', {
      Name: 'SO0111-ASR-WebACL',
    });
  });

  test('WebUIDeploymentResource CustomResource has UIManifestHash property for triggering updates on UI changes', () => {
    const webUINestedStack = new WebUINestedStack(stack, 'WebUINestedStack', props);
    const template = Template.fromStack(webUINestedStack);
    const resources = template.findResources('AWS::CloudFormation::CustomResource');

    const customResourceKeys = Object.keys(resources);
    const webUIDeploymentResource = customResourceKeys.find(
      (key) => resources[key].Properties?.SolutionVersion === props.solutionVersion,
    );

    expect(webUIDeploymentResource).toBeDefined();
    const resourceProps = resources[webUIDeploymentResource!].Properties;

    expect(resourceProps.UIManifestHash).toBeDefined();
    expect(typeof resourceProps.UIManifestHash).toBe('string');
    expect(resourceProps.UIManifestHash.length).toBeGreaterThan(0);
  });

  test('WebUIDeploymentResource has all required properties for update triggers', () => {
    const webUINestedStack = new WebUINestedStack(stack, 'WebUINestedStack', props);
    const template = Template.fromStack(webUINestedStack);
    const resources = template.findResources('AWS::CloudFormation::CustomResource');

    const customResourceKeys = Object.keys(resources);
    const webUIDeploymentResource = customResourceKeys.find(
      (key) => resources[key].Properties?.SolutionVersion === props.solutionVersion,
    );

    expect(webUIDeploymentResource).toBeDefined();
    const resourceProps = resources[webUIDeploymentResource!].Properties;

    expect(resourceProps.SolutionVersion).toBe(props.solutionVersion);
    expect(resourceProps.DeploymentTimestamp).toBeDefined();
    expect(resourceProps.UIManifestHash).toBeDefined();
    expect(resourceProps.TicketingGenFunction).toBe(props.ticketingGenFunction);
  });

  // --- M2M Full Access via asr-api/full-access scope -------------------------
  // The customer creates the M2M client post-deploy; the deployment only adds the
  // scope. These tests guard against regressing to the original (unbuildable)
  // CDK-provisioned client.

  test('the asr-api resource server declares both the api and full-access scopes', () => {
    const webUINestedStack = new WebUINestedStack(stack, 'WebUINestedStack', props);
    const template = Template.fromStack(webUINestedStack);

    expect(Object.keys(template.findResources('AWS::Cognito::UserPoolResourceServer')).length).toBeGreaterThan(0);
    template.hasResourceProperties('AWS::Cognito::UserPoolResourceServer', {
      Identifier: 'asr-api',
      Scopes: Match.arrayWith([Match.objectLike({ ScopeName: 'api' }), Match.objectLike({ ScopeName: 'full-access' })]),
    });
  });

  test('no client_credentials UserPoolClient is provisioned', () => {
    const webUINestedStack = new WebUINestedStack(stack, 'WebUINestedStack', props);
    const template = Template.fromStack(webUINestedStack);

    // Every app client in the template must be an interactive (human) client; none
    // may use the client_credentials grant, which the customer creates themselves.
    const clients = template.findResources('AWS::Cognito::UserPoolClient');
    for (const client of Object.values(clients)) {
      const flows: string[] = client.Properties?.AllowedOAuthFlows ?? [];
      expect(flows).not.toContain('client_credentials');
    }
  });

  test('no M2M client id is exposed as a CloudFormation output', () => {
    const webUINestedStack = new WebUINestedStack(stack, 'WebUINestedStack', props);
    const template = Template.fromStack(webUINestedStack);

    const outputs = template.findOutputs('*');
    for (const key of Object.keys(outputs)) {
      expect(key).not.toMatch(/FullAccessM2M/i);
    }
  });

  test('the API Lambda has no FULL_ACCESS_M2M_CLIENT_ID environment variable', () => {
    const webUINestedStack = new WebUINestedStack(stack, 'WebUINestedStack', props);
    const template = Template.fromStack(webUINestedStack);

    const functions = template.findResources('AWS::Lambda::Function', {
      Properties: { Handler: 'api/handlers/apiHandler.handler' },
    });
    expect(Object.keys(functions)).toHaveLength(1);
    const apiFunction = Object.values(functions)[0];
    const envVars = apiFunction.Properties?.Environment?.Variables ?? {};
    expect(envVars).not.toHaveProperty('FULL_ACCESS_M2M_CLIENT_ID');
  });

  describe('with the frontend disabled (MCP-only deployment)', () => {
    // The nested stack still deploys — the parent gates it on coreServicesEnabled
    // (Web UI OR AgentCore Gateway) — but only the shared core services should be
    // created unconditionally; every frontend-only resource is gated on frontendEnabled.
    let template: Template;

    beforeEach(() => {
      const mcpOnlyStack = new WebUINestedStack(stack, 'McpOnlyWebUINestedStack', {
        ...props,
        deployFrontend: 'no',
      });
      template = Template.fromStack(mcpOnlyStack);
    });

    test('shared core services (Cognito pool, API Lambda, mapping table) stay unconditional', () => {
      // These are consumed by the MCP gateway, so they must exist with no condition
      // even when the browser frontend is absent.
      const userPools = template.findResources('AWS::Cognito::UserPool');
      expect(Object.keys(userPools)).toHaveLength(1);
      expect(Object.values(userPools)[0].Condition).toBeUndefined();

      const apiFunctions = template.findResources('AWS::Lambda::Function', {
        Properties: { Handler: 'api/handlers/apiHandler.handler' },
      });
      expect(Object.keys(apiFunctions)).toHaveLength(1);
      expect(Object.values(apiFunctions)[0].Condition).toBeUndefined();

      const mappingTables = template.findResources('AWS::DynamoDB::Table', {
        Properties: { KeySchema: [{ AttributeName: 'userId', KeyType: 'HASH' }] },
      });
      expect(Object.keys(mappingTables)).toHaveLength(1);
      expect(Object.values(mappingTables)[0].Condition).toBeUndefined();
    });

    test('the API Gateway and CloudFront distribution are gated on frontendEnabled', () => {
      const restApis = template.findResources('AWS::ApiGateway::RestApi');
      expect(Object.keys(restApis)).toHaveLength(1);
      expect(Object.values(restApis)[0].Condition).toBe('frontendEnabled');

      const distributions = template.findResources('AWS::CloudFront::Distribution');
      expect(Object.keys(distributions)).toHaveLength(1);
      expect(Object.values(distributions)[0].Condition).toBe('frontendEnabled');
    });

    test('the Web ACL and its API-stage association are both gated on frontendEnabled', () => {
      // The Web ACL's only association is to the API Gateway stage, so with the frontend
      // (and stage) absent there is nothing for it to protect. Gating it avoids stranding an
      // unassociated Web ACL and its managed-rule costs in an MCP-only deployment.
      const webAcls = template.findResources('AWS::WAFv2::WebACL');
      expect(Object.keys(webAcls)).toHaveLength(1);
      expect(Object.values(webAcls)[0].Condition).toBe('frontendEnabled');

      const associations = template.findResources('AWS::WAFv2::WebACLAssociation');
      expect(Object.keys(associations)).toHaveLength(1);
      expect(Object.values(associations)[0].Condition).toBe('frontendEnabled');
    });

    test('the Web UI SPA app client and its login branding are gated on frontendEnabled', () => {
      // Its OAuth callback/logout URLs derive from the CloudFront domain, which is empty
      // in MCP-only mode, so the client must not be created there.
      const clients = template.findResources('AWS::Cognito::UserPoolClient');
      expect(Object.keys(clients)).toHaveLength(1);
      expect(Object.values(clients)[0].Condition).toBe('frontendEnabled');

      const branding = template.findResources('AWS::Cognito::ManagedLoginBranding');
      expect(Object.keys(branding)).toHaveLength(1);
      expect(Object.values(branding)[0].Condition).toBe('frontendEnabled');
    });

    test('no invalid empty-host OAuth callback/logout URL is emitted', () => {
      // Regression: with the distribution domain resolving to '', the callback rendered as
      // "https:///callback" and the logout as "https://", both of which Cognito rejects.
      // Gating the client removes them from the template entirely.
      expect(JSON.stringify(template.toJSON())).not.toContain('https:///callback');
    });

    test('the Cognito hosted-UI domain stays unconditional so the MCP login redirect still works', () => {
      // Native MCP CLIs complete their login against the hosted UI, so the pool domain
      // must exist even without the browser frontend.
      const domains = template.findResources('AWS::Cognito::UserPoolDomain');
      expect(Object.keys(domains)).toHaveLength(1);
      expect(Object.values(domains)[0].Condition).toBeUndefined();
    });

    test('the invitation email drops the Web UI link and tells the user to sign in from their MCP client', () => {
      // The user pool (and its invitation email) is unconditional, so it is sent even in
      // MCP-only mode where distributionDomainName is ''. The whole body is chosen at deploy
      // time via Fn::If on frontendEnabled: the frontend-off branch carries no Web UI link
      // (a bare hosted-UI /login is not a usable login URL) and instructs MCP-client sign-in.
      const userPools = template.findResources('AWS::Cognito::UserPool');
      const emailMessage =
        Object.values(userPools)[0].Properties.AdminCreateUserConfig.InviteMessageTemplate.EmailMessage;
      const serialized = JSON.stringify(emailMessage);
      // Body is selected by the frontend condition.
      expect(serialized).toContain('frontendEnabled');
      // The MCP-only branch instructs the user to sign in from their MCP client...
      expect(serialized).toContain('Sign in from your MCP client');
      // ...and never emits a broken empty-host link or a bare hosted-UI /login URL.
      expect(serialized).not.toContain('href=\\"https://\\"');
      expect(serialized).not.toContain('/login');
    });

    test('the API endpoint is exposed only through a frontendEnabled-conditioned output', () => {
      // The parent reads the API URL via this output's Fn::GetAtt. It must carry the
      // frontendEnabled condition so it is absent (like the API itself) in an MCP-only
      // deployment; an unconditioned output over the gated API is the exact failure that
      // aborts the nested stack with "Unresolved resource dependencies [...Api]".
      const apiEndpointOutput = Object.values(template.findOutputs('ApiEndpoint'))[0];
      expect(apiEndpointOutput.Condition).toBe('frontendEnabled');

      // No other output may reference the REST API or its stage without a condition, which
      // is what a raw parent api.url reference would generate.
      const outputs = template.findOutputs('*');
      for (const [key, output] of Object.entries(outputs)) {
        const serialized = JSON.stringify(output.Value ?? '');
        if (/ApiConstruct\w*Api\w*Ref|DeploymentStageprod/.test(serialized)) {
          expect(output.Condition).toBe('frontendEnabled');
          expect(key).toBeDefined();
        }
      }
    });

    test('WEB_UI_URL resolves to an empty string on the API Lambda when the frontend is off', () => {
      // Notification/IaC-link builders treat an empty WEB_UI_URL as "no Web UI" and skip
      // links; a bare "https://" would be truthy and slip past that guard, so it must be ''.
      const apiFunctions = template.findResources('AWS::Lambda::Function', {
        Properties: { Handler: 'api/handlers/apiHandler.handler' },
      });
      const webUiUrl = Object.values(apiFunctions)[0].Properties.Environment.Variables.WEB_UI_URL;
      expect(webUiUrl).toEqual({ 'Fn::If': ['frontendEnabled', { 'Fn::Join': expect.anything() }, ''] });
    });
  });
});
