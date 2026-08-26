// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { APIGatewayProxyEvent, Context } from 'aws-lambda';
import { FindingTableItem, ASFFFinding } from '@asr/data-models';
import { deflate } from 'pako';
import { asFindingId } from '../../common/__tests__/utils';

export { asFindingId };

export const TEST_REQUEST_CONTEXT = {
  accountId: '123456789012',
  apiId: 'test-api',
  authorizer: {
    claims: {},
  },
  httpMethod: 'GET',
  identity: {
    accessKey: null,
    accountId: null,
    apiKey: null,
    apiKeyId: null,
    caller: null,
    clientCert: null,
    cognitoAuthenticationProvider: null,
    cognitoAuthenticationType: null,
    cognitoIdentityId: null,
    cognitoIdentityPoolId: null,
    principalOrgId: null,
    sourceIp: '127.0.0.1',
    user: null,
    userAgent: 'test-agent',
    userArn: null,
  },
  path: '/users',
  protocol: 'HTTP/1.1',
  requestId: 'test-request-id',
  requestTime: '01/Jan/2023:00:00:00 +0000',
  requestTimeEpoch: 1672531200,
  resourceId: 'test-resource',
  resourcePath: '/users',
  stage: 'test',
};

export const createMockEvent = (overrides: Partial<APIGatewayProxyEvent> = {}): APIGatewayProxyEvent => ({
  body: null,
  headers: {},
  multiValueHeaders: {},
  httpMethod: 'GET',
  isBase64Encoded: false,
  path: '/users',
  pathParameters: null,
  queryStringParameters: null,
  multiValueQueryStringParameters: null,
  stageVariables: null,
  requestContext: TEST_REQUEST_CONTEXT,
  resource: '/users',
  ...overrides,
});

export const createMockContext = (): Context => ({
  callbackWaitsForEmptyEventLoop: false,
  functionName: 'test-function',
  functionVersion: '1',
  invokedFunctionArn: 'arn:aws:lambda:us-east-1:123456789012:function:test-function',
  memoryLimitInMB: '128',
  awsRequestId: 'test-request-id',
  logGroupName: '/aws/lambda/test-function',
  logStreamName: '2023/01/01/[$LATEST]test-stream',
  getRemainingTimeInMillis: () => 30000,
  done: () => {},
  fail: () => {},
  succeed: () => {},
});

/**
 * Build a Security Hub finding ARN that matches a given findingType. Service
 * code derives the controlId from the ARN, so tests that override findingType
 * must keep the findingId consistent with it (otherwise extractControlIdFromArn
 * returns the wrong value).
 */
export function buildFindingIdForType(findingType: string, uuid = '11111111-2222-3333-4444-555555555555'): string {
  return `arn:aws:securityhub:us-east-1:123456789012:${findingType}/finding/${uuid}`;
}

export const createMockFinding = (overrides: Partial<FindingTableItem> = {}): FindingTableItem => {
  const findingType = overrides.findingType ?? 'security-control/Lambda.3';
  // Default findingId is a valid Security Hub finding ARN so service code
  // that extracts the controlId from the ARN (rather than the findingType
  // column) sees a parseable input. Caller-supplied `findingId` overrides win.
  const defaultFinding = {
    findingType,
    findingId: asFindingId(buildFindingIdForType(findingType)),
    findingDescription: 'Test finding description',
    accountId: '123456789012',
    resourceId: 'arn:aws:s3:::test-bucket',
    resourceType: 'AWS::S3::Bucket',
    resourceTypeNormalized: 'awss3bucket',
    severity: 'HIGH',
    severityNormalized: 3,
    region: 'us-east-1',
    remediationStatus: 'NOT_STARTED' as const,
    securityHubUpdatedAtTime: '2023-01-01T00:00:00Z',
    lastUpdatedTime: '2023-01-01T00:00:00Z',
    'securityHubUpdatedAtTime#findingId': '2023-01-01T00:00:00Z#test-finding-id',
    'severityNormalized#securityHubUpdatedAtTime#findingId': '3#2023-01-01T00:00:00Z#test-finding-id',
    findingIdControl: 'Lambda.3',
    FINDING_CONSTANT: 'finding' as const,
    suppressed: false,
    creationTime: '2023-01-01T00:00:00Z',
    expireAt: Math.floor(Date.now() / 1000) + 8 * 24 * 60 * 60, // 8 days from now
    ...overrides,
  };

  // Create a valid ASFF finding structure
  const asffFinding: ASFFFinding = {
    SchemaVersion: '2018-10-08',
    Id: defaultFinding.findingId,
    ProductArn: 'arn:aws:securityhub:us-east-1::product/aws/securityhub',
    GeneratorId: 'security-control',
    AwsAccountId: defaultFinding.accountId,
    Types: ['Sensitive Data Identifications/PII'],
    CreatedAt: defaultFinding.creationTime,
    UpdatedAt: defaultFinding.lastUpdatedTime,
    Severity: {
      Label: defaultFinding.severity as 'HIGH' | 'MEDIUM' | 'LOW' | 'CRITICAL' | 'INFORMATIONAL',
    },
    Title: 'Test Security Finding',
    Description: defaultFinding.findingDescription,
    Resources: [
      {
        Type: defaultFinding.resourceType || 'AWS::S3::Bucket',
        Id: defaultFinding.resourceId,
        Region: defaultFinding.region,
      },
    ],
    Compliance: {
      Status: 'FAILED',
      SecurityControlId: defaultFinding.findingIdControl || 'Lambda.3',
    },
    Region: defaultFinding.region,
  };

  // Compress the ASFF finding JSON
  const compressedFindingJSON = deflate(JSON.stringify(asffFinding));

  return {
    ...defaultFinding,
    findingJSON: compressedFindingJSON,
  };
};
