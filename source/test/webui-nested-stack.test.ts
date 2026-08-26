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

  test('WebUINestedStack downgrades M2M-blocking Bot Control rules to Count', () => {
    // Act
    const webUINestedStack = new WebUINestedStack(stack, 'WebUINestedStack', props);

    // Assert: the Bot Control managed rule group keeps its group-level default
    // (overrideAction None) but downgrades the two rules that block legitimate
    // machine-to-machine (client_credentials) callers — which present non-browser
    // User-Agents from cloud IPs — to Count, so a valid full-access token reaches
    // the Cognito authorizer instead of being blocked by WAF first.
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
});
