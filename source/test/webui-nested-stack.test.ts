// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import * as cdk from 'aws-cdk-lib';
import { Template } from 'aws-cdk-lib/assertions';
import * as s3 from 'aws-cdk-lib/aws-s3';
import { WebUINestedStack, WebUINestedStackProps } from '../lib/webui-nested-stack';

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
    props = {
      solutionId: 'SO0111',
      solutionVersion: '1.0.0',
      solutionTMN: 'automated-security-response-on-aws',
      solutionsBucket: mockBucket,
      resourceNamePrefix: 'SO0111',
      findingsTable: 'arn:aws:dynamodb:us-east-1:123456789012:table/test-findings-table',
      remediationHistoryTable: 'arn:aws:dynamodb:us-east-1:123456789012:table/test-remediation-history-table',
      apiFunctionName: 'SO0111-ASR-API',
      stackName: 'TestStack',
      adminUserEmail: 'test@example.com',
      kmsKeyARN: 'arn:aws:kms:us-east-1:123456789012:key/my-key',
      orchestratorArn: 'arn:aws:states:us-east-1:123456789012:stateMachine:test-orchestrator',
      csvExportBucket: mockCsvExportBucket,
      presignedUrlTTLDays: 7,
      ticketingGenFunction: 'test-ticketing-function',
      securityHubV2Enabled: 'True',
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
      Runtime: 'nodejs22.x',
      Handler: 'api/handlers/apiHandler.handler',
    });

    // Verify WebUI deployment Lambda function is created
    template.hasResourceProperties('AWS::Lambda::Function', {
      Handler: 'api/handlers/deployWebui.lambdaHandler',
      Runtime: 'nodejs22.x',
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
});
