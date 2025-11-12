// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import {
  AdminGetUserCommand,
  AdminListGroupsForUserCommand,
  CognitoIdentityProviderClient,
} from '@aws-sdk/client-cognito-identity-provider';
import { SFNClient, StartExecutionCommand } from '@aws-sdk/client-sfn';
import { BatchWriteCommand, DynamoDBDocumentClient, PutCommand } from '@aws-sdk/lib-dynamodb';
import { mockClient } from 'aws-sdk-client-mock';
import { DynamoDBTestSetup } from '../../../common/__tests__/dynamodbSetup';
import { findingsTableName } from '../../../common/__tests__/envSetup';
import { API_HEADERS } from '../../handlers/apiHandler';
import { executeFindingAction, searchFindings } from '../../handlers/findings';
import { createMockContext, createMockEvent, createMockFinding, TEST_REQUEST_CONTEXT } from '../utils';

const cognitoMock = mockClient(CognitoIdentityProviderClient);
const sfnMock = mockClient(SFNClient);

const expectedFindingsHeaders = API_HEADERS.FINDINGS;

describe('FindingsHandler Integration Tests', () => {
  let dynamoDBDocumentClient: DynamoDBDocumentClient;
  const remediationHistoryTableName = 'test-remediation-history-table';
  const userAccountMappingTableName = 'test-user-account-mapping-table';

  beforeAll(async () => {
    await DynamoDBTestSetup.initialize();
    dynamoDBDocumentClient = DynamoDBTestSetup.getDocClient();
    await DynamoDBTestSetup.createFindingsTable(findingsTableName);
    await DynamoDBTestSetup.createRemediationHistoryTable(remediationHistoryTableName);
    await DynamoDBTestSetup.createUserAccountMappingTable(userAccountMappingTableName);
  });

  afterAll(async () => {
    await DynamoDBTestSetup.deleteTable(findingsTableName);
    await DynamoDBTestSetup.deleteTable(remediationHistoryTableName);
    await DynamoDBTestSetup.deleteTable(userAccountMappingTableName);
  });

  beforeEach(async () => {
    await DynamoDBTestSetup.clearTable(findingsTableName, 'findings');
    await DynamoDBTestSetup.clearTable(remediationHistoryTableName, 'remediationHistory');
    await DynamoDBTestSetup.clearTable(userAccountMappingTableName, 'userAccountMapping');
    process.env.FINDINGS_TABLE_NAME = findingsTableName;
    process.env.REMEDIATION_HISTORY_TABLE_NAME = remediationHistoryTableName;
    process.env.USER_ACCOUNT_MAPPING_TABLE_NAME = userAccountMappingTableName;
    process.env.USER_POOL_ID = 'test-user-pool-id';
    process.env.ORCHESTRATOR_ARN = 'arn:aws:states:us-east-1:123456789012:stateMachine:test-orchestrator';

    cognitoMock.reset();
    cognitoMock.on(AdminGetUserCommand).resolves({
      Username: 'admin-user@example.com',
      UserAttributes: [
        { Name: 'email', Value: 'admin-user@example.com' },
        { Name: 'custom:invitedBy', Value: 'system@example.com' },
      ],
      UserCreateDate: new Date(),
      UserStatus: 'CONFIRMED',
    });

    cognitoMock.on(AdminListGroupsForUserCommand).resolves({
      Groups: [{ GroupName: 'AdminGroup' }],
    });

    sfnMock.reset();
    sfnMock.on(StartExecutionCommand).resolves({
      executionArn: 'arn:aws:states:us-east-1:123456789012:execution:test-orchestrator:test-execution-id',
    });
  });

  afterEach(() => {
    delete process.env.FINDINGS_TABLE_NAME;
    delete process.env.REMEDIATION_HISTORY_TABLE_NAME;
    delete process.env.ORCHESTRATOR_ARN;
    cognitoMock.reset();
    sfnMock.reset();
  });

  describe('searchFindings', () => {
    beforeEach(async () => {
      const testFindings = [
        createMockFinding({
          findingId: 'finding-1',
          accountId: '123456789012',
          resourceId: 'arn:aws:s3:::bucket-1',
          severity: 'HIGH',
          findingDescription: 'Critical S3 bucket issue',
          'securityHubUpdatedAtTime#findingId': '2023-01-01T00:00:00Z#finding-1',
        }),
        createMockFinding({
          findingId: 'finding-2',
          accountId: '123456789012',
          resourceId: 'arn:aws:ec2:us-east-1:123456789012:instance/i-1234567890abcdef0',
          resourceType: 'AWS::EC2::Instance',
          severity: 'MEDIUM',
          findingDescription: 'EC2 security group issue',
          'securityHubUpdatedAtTime#findingId': '2023-01-02T00:00:00Z#finding-2',
        }),
        createMockFinding({
          findingId: 'finding-3',
          accountId: '987654321098',
          resourceId: 'arn:aws:rds:us-west-2:987654321098:db:mydb',
          resourceType: 'AWS::RDS::DBInstance',
          severity: 'LOW',
          findingDescription: 'RDS configuration issue',
          'securityHubUpdatedAtTime#findingId': '2023-01-03T00:00:00Z#finding-3',
        }),
      ];

      for (const finding of testFindings) {
        await dynamoDBDocumentClient.send(
          new PutCommand({
            TableName: findingsTableName,
            Item: finding,
          }),
        );
      }
    });

    it('should return 200 with all findings when no filters are provided', async () => {
      const event = createMockEvent({
        httpMethod: 'POST',
        path: '/findings',
        headers: {
          'Content-Type': 'application/json',
          authorization: 'Bearer valid-token',
        },
        body: JSON.stringify({}),
        requestContext: {
          ...TEST_REQUEST_CONTEXT,
          authorizer: {
            claims: {
              'cognito:groups': ['AdminGroup'],
              username: 'admin-user@example.com',
            },
          },
        },
      });
      const context = createMockContext();

      const result = await searchFindings(event, context);

      expect(result.statusCode).toBe(200);

      const body = JSON.parse(result.body);
      expect(body.Findings).toHaveLength(3);
      expect(body.Findings[0]).toHaveProperty('findingId');
      expect(body.Findings[0]).toHaveProperty('accountId');
      expect(body.Findings[0]).toHaveProperty('severity');

      expect(result.headers).toEqual(expectedFindingsHeaders);
    });

    it('should filter findings by accountId', async () => {
      const requestBody = {
        Filters: {
          CompositeFilters: [
            {
              Operator: 'AND',
              StringFilters: [
                {
                  FieldName: 'accountId',
                  Filter: {
                    Value: '123456789012',
                    Comparison: 'EQUALS',
                  },
                },
              ],
            },
          ],
        },
      };

      const event = createMockEvent({
        httpMethod: 'POST',
        path: '/findings',
        headers: {
          'Content-Type': 'application/json',
          authorization: 'Bearer valid-token',
        },
        body: JSON.stringify(requestBody),
        requestContext: {
          ...TEST_REQUEST_CONTEXT,
          authorizer: {
            claims: {
              'cognito:groups': ['AdminGroup'],
              username: 'admin-user@example.com',
            },
          },
        },
      });
      const context = createMockContext();

      const result = await searchFindings(event, context);

      expect(result.statusCode).toBe(200);
      const body = JSON.parse(result.body);
      expect(body.Findings).toHaveLength(2);
      expect(body.Findings.every((f: any) => f.accountId === '123456789012')).toBe(true);
    });

    it('should filter findings by severity', async () => {
      const requestBody = {
        Filters: {
          CompositeFilters: [
            {
              Operator: 'AND',
              StringFilters: [
                {
                  FieldName: 'severity',
                  Filter: {
                    Value: 'HIGH',
                    Comparison: 'EQUALS',
                  },
                },
              ],
            },
          ],
        },
      };

      const event = createMockEvent({
        httpMethod: 'POST',
        path: '/findings',
        headers: {
          'Content-Type': 'application/json',
          authorization: 'Bearer valid-token',
        },
        body: JSON.stringify(requestBody),
        requestContext: {
          ...TEST_REQUEST_CONTEXT,
          authorizer: {
            claims: {
              'cognito:groups': ['AdminGroup'],
              username: 'admin-user@example.com',
            },
          },
        },
      });
      const context = createMockContext();

      const result = await searchFindings(event, context);

      expect(result.statusCode).toBe(200);
      const body = JSON.parse(result.body);
      expect(body.Findings).toHaveLength(1);
      expect(body.Findings[0].severity).toBe('HIGH');
    });

    it('should handle complex filter requests with multiple criteria', async () => {
      const requestBody = {
        Filters: {
          CompositeFilters: [
            {
              Operator: 'AND',
              StringFilters: [
                {
                  FieldName: 'accountId',
                  Filter: {
                    Value: '123456789012',
                    Comparison: 'EQUALS',
                  },
                },
                {
                  FieldName: 'severity',
                  Filter: {
                    Value: 'HIGH',
                    Comparison: 'EQUALS',
                  },
                },
              ],
            },
          ],
        },
        SortCriteria: [
          {
            Field: 'securityHubUpdatedAtTime',
            SortOrder: 'desc',
          },
        ],
      };

      const event = createMockEvent({
        httpMethod: 'POST',
        path: '/findings',
        headers: {
          'Content-Type': 'application/json',
          authorization: 'Bearer valid-token',
        },
        body: JSON.stringify(requestBody),
        requestContext: {
          ...TEST_REQUEST_CONTEXT,
          authorizer: {
            claims: {
              'cognito:groups': ['AdminGroup'],
              username: 'admin-user@example.com',
            },
          },
        },
      });
      const context = createMockContext();

      const result = await searchFindings(event, context);

      expect(result.statusCode).toBe(200);
      const body = JSON.parse(result.body);
      expect(body.Findings).toHaveLength(1);
      expect(body.Findings[0].accountId).toBe('123456789012');
      expect(body.Findings[0].severity).toBe('HIGH');
    });

    it('should throw BadRequestError when request validation fails', async () => {
      const invalidRequestBody = {
        Filters: {
          CompositeFilters: [
            {
              Operator: 'INVALID_OPERATOR',
              StringFilters: [
                {
                  FieldName: 'accountId',
                  Filter: {
                    Value: '123456789012',
                    Comparison: 'EQUALS',
                  },
                },
              ],
            },
          ],
        },
      };

      const event = createMockEvent({
        httpMethod: 'POST',
        path: '/findings',
        headers: {
          'Content-Type': 'application/json',
          authorization: 'Bearer valid-token',
        },
        body: JSON.stringify(invalidRequestBody),
        requestContext: {
          ...TEST_REQUEST_CONTEXT,
          authorizer: {
            claims: {
              'cognito:groups': ['AdminGroup'],
              username: 'admin-user@example.com',
            },
          },
        },
      });
      const context = createMockContext();

      await expect(searchFindings(event, context)).rejects.toThrow(
        "Invalid request: Filters.CompositeFilters.0.Operator: Invalid enum value. Expected 'AND' | 'OR', received 'INVALID_OPERATOR'",
      );
    });

    it('should handle sort criteria correctly', async () => {
      const requestBody = {
        SortCriteria: [
          {
            Field: 'securityHubUpdatedAtTime',
            SortOrder: 'desc',
          },
        ],
      };

      const event = createMockEvent({
        httpMethod: 'POST',
        path: '/findings',
        headers: {
          'Content-Type': 'application/json',
          authorization: 'Bearer valid-token',
        },
        body: JSON.stringify(requestBody),
        requestContext: {
          ...TEST_REQUEST_CONTEXT,
          authorizer: {
            claims: {
              'cognito:groups': ['AdminGroup'],
              username: 'admin-user@example.com',
            },
          },
        },
      });
      const context = createMockContext();

      const result = await searchFindings(event, context);

      expect(result.statusCode).toBe(200);
      const body = JSON.parse(result.body);
      expect(body.Findings).toHaveLength(3);
      // Should be sorted by lastUpdatedTime descending
      expect(body.Findings[0].findingId).toBe('finding-3'); // 2023-01-03
      expect(body.Findings[1].findingId).toBe('finding-2'); // 2023-01-02
      expect(body.Findings[2].findingId).toBe('finding-1'); // 2023-01-01
    });

    it('should filter findings by resourceType AWS::S3::Bucket using normalized search', async () => {
      // Clear existing findings and create specific test data
      await DynamoDBTestSetup.clearTable(findingsTableName, 'findings');

      const testFindings = [
        createMockFinding({
          findingId: 'finding-s3-1',
          accountId: '123456789012',
          resourceId: 'arn:aws:s3:::bucket-1',
          resourceType: 'AWS::S3::Bucket',
          resourceTypeNormalized: 'awss3bucket',
          severity: 'HIGH',
          findingDescription: 'S3 bucket issue 1',
          'securityHubUpdatedAtTime#findingId': '2023-01-01T00:00:00Z#finding-s3-1',
        }),
        createMockFinding({
          findingId: 'finding-s3-2',
          accountId: '123456789012',
          resourceId: 'arn:aws:s3:::bucket-2',
          resourceType: 'AwsS3Bucket',
          resourceTypeNormalized: 'awss3bucket',
          severity: 'MEDIUM',
          findingDescription: 'S3 bucket issue 2',
          'securityHubUpdatedAtTime#findingId': '2023-01-02T00:00:00Z#finding-s3-2',
        }),
        createMockFinding({
          findingId: 'finding-ec2-1',
          accountId: '123456789012',
          resourceId: 'arn:aws:ec2:us-east-1:123456789012:instance/i-1234567890abcdef0',
          resourceType: 'AWS::EC2::Instance',
          resourceTypeNormalized: 'awsec2instance',
          severity: 'LOW',
          findingDescription: 'EC2 instance issue',
          'securityHubUpdatedAtTime#findingId': '2023-01-03T00:00:00Z#finding-ec2-1',
        }),
      ];

      for (const finding of testFindings) {
        await dynamoDBDocumentClient.send(
          new PutCommand({
            TableName: findingsTableName,
            Item: finding,
          }),
        );
      }

      const requestBody = {
        Filters: {
          CompositeFilters: [
            {
              Operator: 'AND',
              StringFilters: [
                {
                  FieldName: 'resourceType',
                  Filter: {
                    Value: 'AWS::S3::Bucket',
                    Comparison: 'EQUALS',
                  },
                },
              ],
            },
          ],
        },
      };

      const event = createMockEvent({
        httpMethod: 'POST',
        path: '/findings',
        headers: {
          'Content-Type': 'application/json',
          authorization: 'Bearer valid-token',
        },
        body: JSON.stringify(requestBody),
        requestContext: {
          ...TEST_REQUEST_CONTEXT,
          authorizer: {
            claims: {
              'cognito:groups': ['AdminGroup'],
              username: 'admin-user@example.com',
            },
          },
        },
      });
      const context = createMockContext();

      const result = await searchFindings(event, context);

      expect(result.statusCode).toBe(200);
      const body = JSON.parse(result.body);
      expect(body.Findings).toHaveLength(2);
      expect(body.Findings.every((f: any) => f.resourceTypeNormalized === 'awss3bucket')).toBe(true);
    });

    it('should filter findings by resourceType AwsS3Bucket using normalized search', async () => {
      // Clear existing findings and create specific test data
      await DynamoDBTestSetup.clearTable(findingsTableName, 'findings');

      const testFindings = [
        createMockFinding({
          findingId: 'finding-s3-3',
          accountId: '123456789012',
          resourceId: 'arn:aws:s3:::bucket-3',
          resourceType: 'AWS::S3::Bucket',
          resourceTypeNormalized: 'awss3bucket',
          severity: 'HIGH',
          findingDescription: 'S3 bucket issue 3',
          'securityHubUpdatedAtTime#findingId': '2023-01-01T00:00:00Z#finding-s3-3',
        }),
        createMockFinding({
          findingId: 'finding-s3-4',
          accountId: '123456789012',
          resourceId: 'arn:aws:s3:::bucket-4',
          resourceType: 'AwsS3Bucket',
          resourceTypeNormalized: 'awss3bucket',
          severity: 'MEDIUM',
          findingDescription: 'S3 bucket issue 4',
          'securityHubUpdatedAtTime#findingId': '2023-01-02T00:00:00Z#finding-s3-4',
        }),
        createMockFinding({
          findingId: 'finding-rds-1',
          accountId: '123456789012',
          resourceId: 'arn:aws:rds:us-west-2:123456789012:db:mydb',
          resourceType: 'AWS::RDS::DBInstance',
          resourceTypeNormalized: 'awsrdsdbinstance',
          severity: 'LOW',
          findingDescription: 'RDS configuration issue',
          'securityHubUpdatedAtTime#findingId': '2023-01-03T00:00:00Z#finding-rds-1',
        }),
      ];

      for (const finding of testFindings) {
        await dynamoDBDocumentClient.send(
          new PutCommand({
            TableName: findingsTableName,
            Item: finding,
          }),
        );
      }

      const requestBody = {
        Filters: {
          CompositeFilters: [
            {
              Operator: 'AND',
              StringFilters: [
                {
                  FieldName: 'resourceType',
                  Filter: {
                    Value: 'AwsS3Bucket',
                    Comparison: 'EQUALS',
                  },
                },
              ],
            },
          ],
        },
      };

      const event = createMockEvent({
        httpMethod: 'POST',
        path: '/findings',
        headers: {
          'Content-Type': 'application/json',
          authorization: 'Bearer valid-token',
        },
        body: JSON.stringify(requestBody),
        requestContext: {
          ...TEST_REQUEST_CONTEXT,
          authorizer: {
            claims: {
              'cognito:groups': ['AdminGroup'],
              username: 'admin-user@example.com',
            },
          },
        },
      });
      const context = createMockContext();

      const result = await searchFindings(event, context);

      expect(result.statusCode).toBe(200);
      const body = JSON.parse(result.body);
      expect(body.Findings).toHaveLength(2);
      expect(body.Findings.every((f: any) => f.resourceTypeNormalized === 'awss3bucket')).toBe(true);
    });

    it('should handle CONTAINS comparison', async () => {
      const requestBody = {
        Filters: {
          CompositeFilters: [
            {
              Operator: 'AND',
              StringFilters: [
                {
                  FieldName: 'findingDescription',
                  Filter: {
                    Value: 'S3',
                    Comparison: 'CONTAINS',
                  },
                },
              ],
            },
          ],
        },
      };

      const event = createMockEvent({
        httpMethod: 'POST',
        path: '/findings',
        headers: {
          'Content-Type': 'application/json',
          authorization: 'Bearer valid-token',
        },
        body: JSON.stringify(requestBody),
        requestContext: {
          ...TEST_REQUEST_CONTEXT,
          authorizer: {
            claims: {
              'cognito:groups': ['AdminGroup'],
              username: 'admin-user@example.com',
            },
          },
        },
      });
      const context = createMockContext();

      const result = await searchFindings(event, context);

      expect(result.statusCode).toBe(200);
      const body = JSON.parse(result.body);
      expect(body.Findings).toHaveLength(1);
      expect(body.Findings[0].findingDescription).toContain('S3');
    });

    it('should handle empty request body', async () => {
      const event = createMockEvent({
        httpMethod: 'POST',
        path: '/findings',
        headers: {
          'Content-Type': 'application/json',
          authorization: 'Bearer valid-token',
        },
        body: null,
        requestContext: {
          ...TEST_REQUEST_CONTEXT,
          authorizer: {
            claims: {
              'cognito:groups': ['AdminGroup'],
              username: 'admin-user@example.com',
            },
          },
        },
      });
      const context = createMockContext();

      const result = await searchFindings(event, context);

      expect(result.statusCode).toBe(200);
      const body = JSON.parse(result.body);
      expect(body.Findings).toHaveLength(3);
    });
  });

  describe('Pagination', () => {
    beforeEach(async () => {
      // Clear existing data first
      await DynamoDBTestSetup.clearTable(findingsTableName, 'findings');

      // Create 60 findings to test pagination (default page size is 50)
      const testFindings = [];
      for (let i = 1; i <= 60; i++) {
        let severity: string;
        if (i % 3 === 0) {
          severity = 'HIGH';
        } else if (i % 2 === 0) {
          severity = 'MEDIUM';
        } else {
          severity = 'LOW';
        }

        testFindings.push(
          createMockFinding({
            findingId: `finding-${i.toString().padStart(3, '0')}`,
            accountId: '123456789012',
            resourceId: `arn:aws:s3:::bucket-${i}`,
            severity,
            findingDescription: `Test finding ${i}`,
            'securityHubUpdatedAtTime#findingId': `2023-01-${i.toString().padStart(2, '0')}T00:00:00Z#finding-${i.toString().padStart(3, '0')}`,
          }),
        );
      }

      for (let i = 0; i < testFindings.length; i += 25) {
        const batch = testFindings.slice(i, i + 25);
        await dynamoDBDocumentClient.send(
          new BatchWriteCommand({
            RequestItems: {
              [findingsTableName]: batch.map((finding) => ({
                PutRequest: {
                  Item: finding,
                },
              })),
            },
          }),
        );
      }
    });

    it('should return first page of results with NextToken when there are more than 50 findings', async () => {
      const event = createMockEvent({
        httpMethod: 'POST',
        path: '/findings',
        headers: {
          'Content-Type': 'application/json',
          authorization: 'Bearer valid-token',
        },
        body: JSON.stringify({}),
        requestContext: {
          ...TEST_REQUEST_CONTEXT,
          authorizer: {
            claims: {
              'cognito:groups': ['AdminGroup'],
              username: 'admin-user@example.com',
            },
          },
        },
      });
      const context = createMockContext();

      const result = await searchFindings(event, context);

      expect(result.statusCode).toBe(200);
      const body = JSON.parse(result.body);

      // Should return exactly 50 findings (default page size)
      expect(body.Findings).toHaveLength(50);

      // Should have NextToken since there are more results
      expect(body.NextToken).toBeDefined();
      expect(typeof body.NextToken).toBe('string');

      // Verify findings are properly formatted
      expect(body.Findings[0]).toHaveProperty('findingId');
      expect(body.Findings[0]).toHaveProperty('accountId');
      expect(body.Findings[0]).toHaveProperty('severity');
    });

    it('should return second page of results when NextToken is provided', async () => {
      // First request to get NextToken
      const firstEvent = createMockEvent({
        httpMethod: 'POST',
        path: '/findings',
        headers: {
          'Content-Type': 'application/json',
          authorization: 'Bearer valid-token',
        },
        body: JSON.stringify({}),
        requestContext: {
          ...TEST_REQUEST_CONTEXT,
          authorizer: {
            claims: {
              'cognito:groups': ['AdminGroup'],
              username: 'admin-user@example.com',
            },
          },
        },
      });
      const context = createMockContext();

      const firstResult = await searchFindings(firstEvent, context);
      const firstBody = JSON.parse(firstResult.body);

      expect(firstBody.NextToken).toBeDefined();

      // Second request with NextToken
      const secondEvent = createMockEvent({
        httpMethod: 'POST',
        path: '/findings',
        headers: {
          'Content-Type': 'application/json',
          authorization: 'Bearer valid-token',
        },
        body: JSON.stringify({
          NextToken: firstBody.NextToken,
        }),
        requestContext: {
          ...TEST_REQUEST_CONTEXT,
          authorizer: {
            claims: {
              'cognito:groups': ['AdminGroup'],
              username: 'admin-user@example.com',
            },
          },
        },
      });

      const secondResult = await searchFindings(secondEvent, context);
      const secondBody = JSON.parse(secondResult.body);

      expect(secondResult.statusCode).toBe(200);

      // Should return remaining 10 findings
      expect(secondBody.Findings).toHaveLength(10);

      // Should not have NextToken since this is the last page
      expect(secondBody.NextToken).toBeUndefined();

      // Verify no duplicate findings between pages
      const firstPageIds = firstBody.Findings.map((f: any) => f.findingId);
      const secondPageIds = secondBody.Findings.map((f: any) => f.findingId);
      const intersection = firstPageIds.filter((id: string) => secondPageIds.includes(id));
      expect(intersection).toHaveLength(0);
    });

    it('should handle pagination with filters', async () => {
      // Create additional findings with different account IDs
      const additionalFindings = [];
      for (let i = 61; i <= 80; i++) {
        additionalFindings.push(
          createMockFinding({
            findingId: `finding-${i.toString().padStart(3, '0')}`,
            accountId: '987654321098', // Different account ID
            resourceId: `arn:aws:s3:::bucket-${i}`,
            severity: 'HIGH',
            findingDescription: `Test finding ${i}`,
            'securityHubUpdatedAtTime#findingId': `2023-01-${(i - 60).toString().padStart(2, '0')}T00:00:00Z#finding-${i.toString().padStart(3, '0')}`,
          }),
        );
      }

      await Promise.all(
        additionalFindings.map((finding) =>
          dynamoDBDocumentClient.send(
            new PutCommand({
              TableName: findingsTableName,
              Item: finding,
            }),
          ),
        ),
      );

      // Filter by original account ID
      const requestBody = {
        Filters: {
          CompositeFilters: [
            {
              Operator: 'AND',
              StringFilters: [
                {
                  FieldName: 'accountId',
                  Filter: {
                    Value: '123456789012',
                    Comparison: 'EQUALS',
                  },
                },
              ],
            },
          ],
        },
      };

      const event = createMockEvent({
        httpMethod: 'POST',
        path: '/findings',
        headers: {
          'Content-Type': 'application/json',
          authorization: 'Bearer valid-token',
        },
        body: JSON.stringify(requestBody),
        requestContext: {
          ...TEST_REQUEST_CONTEXT,
          authorizer: {
            claims: {
              'cognito:groups': ['AdminGroup'],
              username: 'admin-user@example.com',
            },
          },
        },
      });
      const context = createMockContext();

      const result = await searchFindings(event, context);
      const body = JSON.parse(result.body);

      expect(result.statusCode).toBe(200);

      // Should return 50 findings (first page) all with the filtered account ID
      expect(body.Findings).toHaveLength(50);
      expect(body.Findings.every((f: any) => f.accountId === '123456789012')).toBe(true);

      // Should have NextToken since there are 60 total findings with this account ID
      expect(body.NextToken).toBeDefined();
    });
  });

  describe('Input Validation', () => {
    it('should reject invalid comparison operators', async () => {
      const invalidRequestBody = {
        Filters: {
          CompositeFilters: [
            {
              Operator: 'AND',
              StringFilters: [
                {
                  FieldName: 'accountId',
                  Filter: {
                    Value: '123456789012',
                    Comparison: 'INVALID_COMPARISON', // Invalid comparison
                  },
                },
              ],
            },
          ],
        },
      };

      const event = createMockEvent({
        httpMethod: 'POST',
        path: '/findings',
        headers: {
          'Content-Type': 'application/json',
          authorization: 'Bearer valid-token',
        },
        body: JSON.stringify(invalidRequestBody),
        requestContext: {
          ...TEST_REQUEST_CONTEXT,
          authorizer: {
            claims: {
              'cognito:groups': ['AdminGroup'],
              username: 'admin-user@example.com',
            },
          },
        },
      });
      const context = createMockContext();

      await expect(searchFindings(event, context)).rejects.toThrow(
        "Invalid request: Filters.CompositeFilters.0.StringFilters.0.Filter.Comparison: Invalid enum value. Expected 'EQUALS' | 'NOT_EQUALS' | 'CONTAINS' | 'NOT_CONTAINS' | 'GREATER_THAN_OR_EQUAL' | 'LESS_THAN_OR_EQUAL', received 'INVALID_COMPARISON'",
      );
    });

    it('should reject invalid sort order', async () => {
      const invalidRequestBody = {
        SortCriteria: [
          {
            Field: 'securityHubUpdatedAtTime',
            SortOrder: 'invalid', // Invalid sort order
          },
        ],
      };

      const event = createMockEvent({
        httpMethod: 'POST',
        path: '/findings',
        headers: {
          'Content-Type': 'application/json',
          authorization: 'Bearer valid-token',
        },
        body: JSON.stringify(invalidRequestBody),
        requestContext: {
          ...TEST_REQUEST_CONTEXT,
          authorizer: {
            claims: {
              'cognito:groups': ['AdminGroup'],
              username: 'admin-user@example.com',
            },
          },
        },
      });
      const context = createMockContext();

      await expect(searchFindings(event, context)).rejects.toThrow(
        "Invalid request: SortCriteria.0.SortOrder: Invalid enum value. Expected 'asc' | 'desc', received 'invalid'",
      );
    });

    it('should accept comparison operators GREATER_THAN_OR_EQUAL and LESS_THAN_OR_EQUAL', async () => {
      const requestBody = {
        Filters: {
          CompositeFilters: [
            {
              Operator: 'AND',
              StringFilters: [
                {
                  FieldName: 'securityHubUpdatedAtTime',
                  Filter: {
                    Value: '2023-01-01T00:00:00Z',
                    Comparison: 'GREATER_THAN_OR_EQUAL',
                  },
                },
                {
                  FieldName: 'securityHubUpdatedAtTime',
                  Filter: {
                    Value: '2023-12-31T23:59:59Z',
                    Comparison: 'LESS_THAN_OR_EQUAL',
                  },
                },
              ],
            },
          ],
        },
      };

      const event = createMockEvent({
        httpMethod: 'POST',
        path: '/findings',
        headers: {
          'Content-Type': 'application/json',
          authorization: 'Bearer valid-token',
        },
        body: JSON.stringify(requestBody),
        requestContext: {
          ...TEST_REQUEST_CONTEXT,
          authorizer: {
            claims: {
              'cognito:groups': ['AdminGroup'],
              username: 'admin-user@example.com',
            },
          },
        },
      });
      const context = createMockContext();

      // Should not throw an error - the new operators should be accepted
      const response = await searchFindings(event, context);
      expect(response.statusCode).toBe(200);
    });
  });

  describe('executeFindingAction', () => {
    beforeEach(async () => {
      // Create test findings for action testing
      const testFindings = [
        createMockFinding({
          findingId: 'finding-1',
          findingType: 'cis-aws-foundations-benchmark/v/1.4.0/4.8',
          accountId: '123456789012',
          resourceId: 'arn:aws:s3:::test-bucket-1',
          severity: 'HIGH',
          findingDescription: 'Test finding 1',
          suppressed: false,
          'securityHubUpdatedAtTime#findingId': '2023-01-01T00:00:00Z#finding-1',
        }),
        createMockFinding({
          findingId: 'finding-2',
          findingType: 'cis-aws-foundations-benchmark/v/1.4.0/4.9',
          accountId: '123456789012',
          resourceId: 'arn:aws:s3:::test-bucket-2',
          severity: 'MEDIUM',
          findingDescription: 'Test finding 2',
          suppressed: false,
          'securityHubUpdatedAtTime#findingId': '2023-01-02T00:00:00Z#finding-2',
        }),
        createMockFinding({
          findingId: 'finding-3',
          findingType: 'cis-aws-foundations-benchmark/v/1.4.0/4.10',
          accountId: '123456789012',
          resourceId: 'arn:aws:s3:::test-bucket-3',
          severity: 'LOW',
          findingDescription: 'Test finding 3',
          suppressed: true,
          'securityHubUpdatedAtTime#findingId': '2023-01-03T00:00:00Z#finding-3',
        }),
      ];

      for (const finding of testFindings) {
        await dynamoDBDocumentClient.send(
          new PutCommand({
            TableName: findingsTableName,
            Item: finding,
          }),
        );
      }
    });

    describe('Suppress Action', () => {
      it('should return 200 and suppress single finding', async () => {
        const suppressSingleFindingId =
          'arn:aws:securityhub:us-east-1:123456789012:security-control/Lambda.3/finding/suppress-single-test';
        const testFinding = createMockFinding({
          findingId: suppressSingleFindingId,
          findingType: 'security-control/Lambda.3',
          accountId: '123456789012',
          resourceId: 'arn:aws:lambda:us-east-1:123456789012:function:suppress-single-test',
          severity: 'HIGH',
          findingDescription: 'Test finding for single suppress test',
          suppressed: false,
          'securityHubUpdatedAtTime#findingId': `2023-01-01T00:00:00Z#${suppressSingleFindingId}`,
        });

        await dynamoDBDocumentClient.send(
          new PutCommand({
            TableName: findingsTableName,
            Item: testFinding,
          }),
        );

        const requestBody = {
          actionType: 'Suppress',
          findingIds: [suppressSingleFindingId],
        };

        const event = createMockEvent({
          httpMethod: 'POST',
          path: '/findings/action',
          headers: {
            'Content-Type': 'application/json',
            authorization: 'Bearer valid-token',
          },
          body: JSON.stringify(requestBody),
          requestContext: {
            ...TEST_REQUEST_CONTEXT,
            authorizer: {
              claims: {
                'cognito:groups': ['AdminGroup'],
                username: 'admin-user@example.com',
              },
            },
          },
        });
        const context = createMockContext();

        const result = await executeFindingAction(event, context);

        expect(result.statusCode).toBe(200);
        expect(result.headers).toEqual(expectedFindingsHeaders);
      });

      it('should return 200 and suppress multiple findings', async () => {
        const suppressFinding1Id =
          'arn:aws:securityhub:us-east-1:123456789012:security-control/Lambda.3/finding/suppress-multiple-test-1';
        const suppressFinding2Id =
          'arn:aws:securityhub:us-east-1:123456789012:security-control/Lambda.3/finding/suppress-multiple-test-2';

        const additionalFindings = [
          createMockFinding({
            findingId: suppressFinding1Id,
            findingType: 'security-control/Lambda.3',
            accountId: '123456789012',
            resourceId: 'arn:aws:lambda:us-east-1:123456789012:function:suppress-multiple-test-1',
            severity: 'HIGH',
            findingDescription: 'Test finding for suppress multiple test 1',
            suppressed: false,
            'securityHubUpdatedAtTime#findingId': `2023-01-01T00:00:00Z#${suppressFinding1Id}`,
          }),
          createMockFinding({
            findingId: suppressFinding2Id,
            findingType: 'security-control/Lambda.3',
            accountId: '123456789012',
            resourceId: 'arn:aws:lambda:us-east-1:123456789012:function:suppress-multiple-test-2',
            severity: 'MEDIUM',
            findingDescription: 'Test finding for suppress multiple test 2',
            suppressed: false,
            'securityHubUpdatedAtTime#findingId': `2023-01-02T00:00:00Z#${suppressFinding2Id}`,
          }),
        ];

        for (const finding of additionalFindings) {
          await dynamoDBDocumentClient.send(
            new PutCommand({
              TableName: findingsTableName,
              Item: finding,
            }),
          );
        }

        const requestBody = {
          actionType: 'Suppress',
          findingIds: [suppressFinding1Id, suppressFinding2Id],
        };

        const event = createMockEvent({
          httpMethod: 'POST',
          path: '/findings/action',
          headers: {
            'Content-Type': 'application/json',
            authorization: 'Bearer valid-token',
          },
          body: JSON.stringify(requestBody),
          requestContext: {
            ...TEST_REQUEST_CONTEXT,
            authorizer: {
              claims: {
                'cognito:groups': ['AdminGroup'],
                username: 'admin-user@example.com',
              },
            },
          },
        });
        const context = createMockContext();

        const result = await executeFindingAction(event, context);

        expect(result.statusCode).toBe(200);
        expect(result.headers).toEqual(expectedFindingsHeaders);
      });

      it('should return 500 error for non-existent finding', async () => {
        const requestBody = {
          actionType: 'Suppress',
          findingIds: ['non-existent-finding'],
        };

        const event = createMockEvent({
          httpMethod: 'POST',
          path: '/findings/action',
          headers: {
            'Content-Type': 'application/json',
            authorization: 'Bearer valid-token',
          },
          body: JSON.stringify(requestBody),
          requestContext: {
            ...TEST_REQUEST_CONTEXT,
            authorizer: {
              claims: {
                'cognito:groups': ['AdminGroup'],
                username: 'admin-user@example.com',
              },
            },
          },
        });
        const context = createMockContext();

        await expect(executeFindingAction(event, context)).rejects.toThrow('No findings found for the provided IDs');
      });
    });

    describe('Unsuppress Action', () => {
      it('should return 200 and unsuppress single finding', async () => {
        const unsuppressSingleFindingId =
          'arn:aws:securityhub:us-east-1:123456789012:security-control/Lambda.3/finding/unsuppress-single-test';
        const testFinding = createMockFinding({
          findingId: unsuppressSingleFindingId,
          findingType: 'security-control/Lambda.3',
          accountId: '123456789012',
          resourceId: 'arn:aws:lambda:us-east-1:123456789012:function:unsuppress-single-test',
          severity: 'LOW',
          findingDescription: 'Test finding for single unsuppress test',
          suppressed: true,
          'securityHubUpdatedAtTime#findingId': `2023-01-03T00:00:00Z#${unsuppressSingleFindingId}`,
        });

        await dynamoDBDocumentClient.send(
          new PutCommand({
            TableName: findingsTableName,
            Item: testFinding,
          }),
        );

        const requestBody = {
          actionType: 'Unsuppress',
          findingIds: [unsuppressSingleFindingId],
        };

        const event = createMockEvent({
          httpMethod: 'POST',
          path: '/findings/action',
          headers: {
            'Content-Type': 'application/json',
            authorization: 'Bearer valid-token',
          },
          body: JSON.stringify(requestBody),
          requestContext: {
            ...TEST_REQUEST_CONTEXT,
            authorizer: {
              claims: {
                'cognito:groups': ['AdminGroup'],
                username: 'admin-user@example.com',
              },
            },
          },
        });
        const context = createMockContext();

        const result = await executeFindingAction(event, context);

        expect(result.statusCode).toBe(200);
        expect(result.headers).toEqual(expectedFindingsHeaders);
      });

      it('should return 200 and unsuppress multiple findings', async () => {
        const unsuppressFinding1Id =
          'arn:aws:securityhub:us-east-1:123456789012:security-control/Lambda.3/finding/unsuppress-test-1';
        const unsuppressFinding2Id =
          'arn:aws:securityhub:us-east-1:123456789012:security-control/Lambda.3/finding/unsuppress-test-2';

        const additionalFindings = [
          createMockFinding({
            findingId: unsuppressFinding1Id,
            findingType: 'security-control/Lambda.3',
            accountId: '123456789012',
            resourceId: 'arn:aws:lambda:us-east-1:123456789012:function:unsuppress-test-1',
            severity: 'HIGH',
            findingDescription: 'Test finding for unsuppress test 1',
            suppressed: true,
            'securityHubUpdatedAtTime#findingId': `2023-01-01T00:00:00Z#${unsuppressFinding1Id}`,
          }),
          createMockFinding({
            findingId: unsuppressFinding2Id,
            findingType: 'security-control/Lambda.3',
            accountId: '123456789012',
            resourceId: 'arn:aws:lambda:us-east-1:123456789012:function:unsuppress-test-2',
            severity: 'LOW',
            findingDescription: 'Test finding for unsuppress test 2',
            suppressed: true,
            'securityHubUpdatedAtTime#findingId': `2023-01-03T00:00:00Z#${unsuppressFinding2Id}`,
          }),
        ];

        for (const finding of additionalFindings) {
          await dynamoDBDocumentClient.send(
            new PutCommand({
              TableName: findingsTableName,
              Item: finding,
            }),
          );
        }

        const requestBody = {
          actionType: 'Unsuppress',
          findingIds: [unsuppressFinding1Id, unsuppressFinding2Id],
        };

        const event = createMockEvent({
          httpMethod: 'POST',
          path: '/findings/action',
          headers: {
            'Content-Type': 'application/json',
            authorization: 'Bearer valid-token',
          },
          body: JSON.stringify(requestBody),
          requestContext: {
            ...TEST_REQUEST_CONTEXT,
            authorizer: {
              claims: {
                'cognito:groups': ['AdminGroup'],
                username: 'admin-user@example.com',
              },
            },
          },
        });
        const context = createMockContext();

        const result = await executeFindingAction(event, context);

        expect(result.statusCode).toBe(200);
        expect(result.headers).toEqual(expectedFindingsHeaders);
      });
    });

    describe('Input Validation', () => {
      it('should throw BadRequestError when actionType is missing', async () => {
        const requestBody = {
          findingIds: ['finding-1'],
        };

        const event = createMockEvent({
          httpMethod: 'POST',
          path: '/findings/action',
          headers: {
            'Content-Type': 'application/json',
            authorization: 'Bearer valid-token',
          },
          body: JSON.stringify(requestBody),
        });
        const context = createMockContext();

        await expect(executeFindingAction(event, context)).rejects.toThrow('Invalid request:');
      });

      it('should throw BadRequestError when findingIds is missing', async () => {
        const requestBody = {
          actionType: 'Suppress',
        };

        const event = createMockEvent({
          httpMethod: 'POST',
          path: '/findings/action',
          headers: {
            'Content-Type': 'application/json',
            authorization: 'Bearer valid-token',
          },
          body: JSON.stringify(requestBody),
          requestContext: {
            ...TEST_REQUEST_CONTEXT,
            authorizer: {
              claims: {
                'cognito:groups': ['AdminGroup'],
                username: 'admin-user@example.com',
              },
            },
          },
        });
        const context = createMockContext();

        await expect(executeFindingAction(event, context)).rejects.toThrow('Invalid request:');
      });

      it('should throw BadRequestError when findingIds is empty array', async () => {
        const requestBody = {
          actionType: 'Suppress',
          findingIds: [],
        };

        const event = createMockEvent({
          httpMethod: 'POST',
          path: '/findings/action',
          headers: {
            'Content-Type': 'application/json',
            authorization: 'Bearer valid-token',
          },
          body: JSON.stringify(requestBody),
          requestContext: {
            ...TEST_REQUEST_CONTEXT,
            authorizer: {
              claims: {
                'cognito:groups': ['AdminGroup'],
                username: 'admin-user@example.com',
              },
            },
          },
        });
        const context = createMockContext();

        await expect(executeFindingAction(event, context)).rejects.toThrow('Invalid request:');
      });

      it('should throw BadRequestError when actionType is invalid', async () => {
        const requestBody = {
          actionType: 'InvalidAction',
          findingIds: ['finding-1'],
        };

        const event = createMockEvent({
          httpMethod: 'POST',
          path: '/findings/action',
          headers: {
            'Content-Type': 'application/json',
            authorization: 'Bearer valid-token',
          },
          body: JSON.stringify(requestBody),
          requestContext: {
            ...TEST_REQUEST_CONTEXT,
            authorizer: {
              claims: {
                'cognito:groups': ['AdminGroup'],
                username: 'admin-user@example.com',
              },
            },
          },
        });
        const context = createMockContext();

        await expect(executeFindingAction(event, context)).rejects.toThrow('Invalid request:');
      });

      it('should throw BadRequestError when findingIds contains non-string values', async () => {
        const requestBody = {
          actionType: 'Suppress',
          findingIds: ['finding-1', 123, null],
        };

        const event = createMockEvent({
          httpMethod: 'POST',
          path: '/findings/action',
          headers: {
            'Content-Type': 'application/json',
            authorization: 'Bearer valid-token',
          },
          body: JSON.stringify(requestBody),
          requestContext: {
            ...TEST_REQUEST_CONTEXT,
            authorizer: {
              claims: {
                'cognito:groups': ['AdminGroup'],
                username: 'admin-user@example.com',
              },
            },
          },
        });
        const context = createMockContext();

        await expect(executeFindingAction(event, context)).rejects.toThrow('Invalid request:');
      });

      it('should handle empty request body', async () => {
        const event = createMockEvent({
          httpMethod: 'POST',
          path: '/findings/action',
          headers: {
            'Content-Type': 'application/json',
            authorization: 'Bearer valid-token',
          },
          body: null,
          requestContext: {
            ...TEST_REQUEST_CONTEXT,
            authorizer: {
              claims: {
                'cognito:groups': ['AdminGroup'],
                username: 'admin-user@example.com',
              },
            },
          },
        });
        const context = createMockContext();

        await expect(executeFindingAction(event, context)).rejects.toThrow('Invalid request:');
      });

      it('should handle malformed JSON in request body', async () => {
        const event = createMockEvent({
          httpMethod: 'POST',
          path: '/findings/action',
          headers: {
            'Content-Type': 'application/json',
            authorization: 'Bearer valid-token',
          },
          body: '{"actionType": "Suppress", "findingIds": [',
          requestContext: {
            ...TEST_REQUEST_CONTEXT,
            authorizer: {
              claims: {
                'cognito:groups': ['AdminGroup'],
                username: 'admin-user@example.com',
              },
            },
          },
        });
        const context = createMockContext();

        await expect(executeFindingAction(event, context)).rejects.toThrow();
      });
    });

    describe('Batch Operations', () => {
      it('should handle large batch of finding IDs', async () => {
        // Create a large batch of finding IDs
        const findingIds = [];
        for (let i = 1; i <= 100; i++) {
          findingIds.push(`finding-batch-${i}`);
        }

        const requestBody = {
          actionType: 'Suppress',
          findingIds,
        };

        const event = createMockEvent({
          httpMethod: 'POST',
          path: '/findings/action',
          headers: {
            'Content-Type': 'application/json',
            authorization: 'Bearer valid-token',
          },
          body: JSON.stringify(requestBody),
          requestContext: {
            ...TEST_REQUEST_CONTEXT,
            authorizer: {
              claims: {
                'cognito:groups': ['AdminGroup'],
                username: 'admin-user@example.com',
              },
            },
          },
        });
        const context = createMockContext();

        await expect(executeFindingAction(event, context)).rejects.toThrow('No findings found for the provided IDs');
      });

      it('should handle mixed existing and non-existing finding IDs', async () => {
        const existingFinding1Id =
          'arn:aws:securityhub:us-east-1:123456789012:security-control/Lambda.3/finding/mixed-test-1';
        const existingFinding2Id =
          'arn:aws:securityhub:us-east-1:123456789012:security-control/Lambda.3/finding/mixed-test-2';

        const additionalFindings = [
          createMockFinding({
            findingId: existingFinding1Id,
            findingType: 'security-control/Lambda.3',
            accountId: '123456789012',
            resourceId: 'arn:aws:lambda:us-east-1:123456789012:function:mixed-test-1',
            severity: 'HIGH',
            findingDescription: 'Test finding for mixed test 1',
            suppressed: false,
            'securityHubUpdatedAtTime#findingId': `2023-01-01T00:00:00Z#${existingFinding1Id}`,
          }),
          createMockFinding({
            findingId: existingFinding2Id,
            findingType: 'security-control/Lambda.3',
            accountId: '123456789012',
            resourceId: 'arn:aws:lambda:us-east-1:123456789012:function:mixed-test-2',
            severity: 'MEDIUM',
            findingDescription: 'Test finding for mixed test 2',
            suppressed: false,
            'securityHubUpdatedAtTime#findingId': `2023-01-02T00:00:00Z#${existingFinding2Id}`,
          }),
        ];

        for (const finding of additionalFindings) {
          await dynamoDBDocumentClient.send(
            new PutCommand({
              TableName: findingsTableName,
              Item: finding,
            }),
          );
        }

        const requestBody = {
          actionType: 'Suppress',
          findingIds: [
            existingFinding1Id,
            'arn:aws:securityhub:us-east-1:123456789012:security-control/Lambda.3/finding/non-existent-1',
            existingFinding2Id,
            'arn:aws:securityhub:us-east-1:123456789012:security-control/Lambda.3/finding/non-existent-2',
          ],
        };

        const event = createMockEvent({
          httpMethod: 'POST',
          path: '/findings/action',
          headers: {
            'Content-Type': 'application/json',
            authorization: 'Bearer valid-token',
          },
          body: JSON.stringify(requestBody),
          requestContext: {
            ...TEST_REQUEST_CONTEXT,
            authorizer: {
              claims: {
                'cognito:groups': ['AdminGroup'],
                username: 'admin-user@example.com',
              },
            },
          },
        });
        const context = createMockContext();

        const result = await executeFindingAction(event, context);

        expect(result.statusCode).toBe(200);
      });
    });

    describe('Response Format', () => {
      it('should return correct headers', async () => {
        const findingId =
          'arn:aws:securityhub:us-east-1:123456789012:security-control/Lambda.3/finding/12345678-1234-1234-1234-123456789013';
        const testFinding = createMockFinding({
          findingId,
          findingType: 'security-control/Lambda.3',
          accountId: '123456789012',
          resourceId: 'arn:aws:lambda:us-east-1:123456789012:function:test-function-headers',
          severity: 'HIGH',
          findingDescription: 'Test finding for headers test',
          suppressed: false,
          'securityHubUpdatedAtTime#findingId': `2023-01-01T00:00:00Z#${findingId}`,
        });

        await dynamoDBDocumentClient.send(
          new PutCommand({
            TableName: findingsTableName,
            Item: testFinding,
          }),
        );

        const requestBody = {
          actionType: 'Suppress',
          findingIds: [findingId],
        };

        const event = createMockEvent({
          httpMethod: 'POST',
          path: '/findings/action',
          headers: {
            'Content-Type': 'application/json',
            authorization: 'Bearer valid-token',
          },
          body: JSON.stringify(requestBody),
          requestContext: {
            ...TEST_REQUEST_CONTEXT,
            authorizer: {
              claims: {
                'cognito:groups': ['AdminGroup'],
                username: 'admin-user@example.com',
              },
            },
          },
        });
        const context = createMockContext();

        const result = await executeFindingAction(event, context);

        expect(result.statusCode).toBe(200);
        expect(result.headers).toEqual(expectedFindingsHeaders);
      });

      it('should return empty body for successful action', async () => {
        const findingId =
          'arn:aws:securityhub:us-east-1:123456789012:security-control/Lambda.3/finding/12345678-1234-1234-1234-123456789012';
        const testFinding = createMockFinding({
          findingId,
          findingType: 'security-control/Lambda.3',
          accountId: '123456789012',
          resourceId: 'arn:aws:lambda:us-east-1:123456789012:function:test-function',
          severity: 'HIGH',
          findingDescription: 'Test finding for response format',
          suppressed: false,
          'securityHubUpdatedAtTime#findingId': `2023-01-01T00:00:00Z#${findingId}`,
        });

        await dynamoDBDocumentClient.send(
          new PutCommand({
            TableName: findingsTableName,
            Item: testFinding,
          }),
        );

        const requestBody = {
          actionType: 'Suppress',
          findingIds: [findingId],
        };

        const event = createMockEvent({
          httpMethod: 'POST',
          path: '/findings/action',
          headers: {
            'Content-Type': 'application/json',
            authorization: 'Bearer valid-token',
          },
          body: JSON.stringify(requestBody),
          requestContext: {
            ...TEST_REQUEST_CONTEXT,
            authorizer: {
              claims: {
                'cognito:groups': ['AdminGroup'],
                username: 'admin-user@example.com',
              },
            },
          },
        });
        const context = createMockContext();

        const result = await executeFindingAction(event, context);

        expect(result.statusCode).toBe(200);
        const body = JSON.parse(result.body);
        expect(body).toBe('');
      });
    });

    describe('Remediate Action', () => {
      it('should return 202 and initiate remediation for single finding', async () => {
        const remediateFindingId =
          'arn:aws:securityhub:us-east-1:123456789012:security-control/Lambda.3/finding/test-finding-remediate';

        const testFinding = createMockFinding({
          findingId: remediateFindingId,
          findingType: 'security-control/Lambda.3',
          accountId: '123456789012',
          resourceId: 'arn:aws:lambda:us-east-1:123456789012:function:test-function-remediate',
          severity: 'HIGH',
          findingDescription: 'Test finding for remediation',
          suppressed: false,
          'securityHubUpdatedAtTime#findingId': `2023-01-01T00:00:00Z#${remediateFindingId}`,
        });

        await dynamoDBDocumentClient.send(
          new PutCommand({
            TableName: findingsTableName,
            Item: testFinding,
          }),
        );

        const requestBody = {
          actionType: 'Remediate',
          findingIds: [remediateFindingId],
        };

        const event = createMockEvent({
          httpMethod: 'POST',
          path: '/findings/action',
          headers: {
            'Content-Type': 'application/json',
            authorization: 'Bearer valid-token',
          },
          body: JSON.stringify(requestBody),
          requestContext: {
            ...TEST_REQUEST_CONTEXT,
            authorizer: {
              claims: {
                'cognito:groups': ['AdminGroup'],
                username: 'admin-user@example.com',
              },
            },
          },
        });
        const context = createMockContext();

        const result = await executeFindingAction(event, context);

        expect(result.statusCode).toBe(202);
        const responseBody = JSON.parse(result.body);
        expect(responseBody.status).toBe('IN_PROGRESS');
      });

      it('should return 202 and initiate remediation with ticket generation', async () => {
        const remediateFindingId =
          'arn:aws:securityhub:us-east-1:123456789012:security-control/Lambda.3/finding/test-finding-remediate-ticket';

        const testFinding = createMockFinding({
          findingId: remediateFindingId,
          findingType: 'security-control/Lambda.3',
          accountId: '123456789012',
          resourceId: 'arn:aws:lambda:us-east-1:123456789012:function:test-function-remediate-ticket',
          severity: 'HIGH',
          findingDescription: 'Test finding for remediation with ticket',
          suppressed: false,
          'securityHubUpdatedAtTime#findingId': `2023-01-01T00:00:00Z#${remediateFindingId}`,
        });

        await dynamoDBDocumentClient.send(
          new PutCommand({
            TableName: findingsTableName,
            Item: testFinding,
          }),
        );

        const requestBody = {
          actionType: 'RemediateAndGenerateTicket',
          findingIds: [remediateFindingId],
        };

        const event = createMockEvent({
          httpMethod: 'POST',
          path: '/findings/action',
          headers: {
            'Content-Type': 'application/json',
            authorization: 'Bearer valid-token',
          },
          body: JSON.stringify(requestBody),
          requestContext: {
            ...TEST_REQUEST_CONTEXT,
            authorizer: {
              claims: {
                'cognito:groups': ['AdminGroup'],
                username: 'admin-user@example.com',
              },
            },
          },
        });
        const context = createMockContext();

        const result = await executeFindingAction(event, context);

        expect(result.statusCode).toBe(202);
        const responseBody = JSON.parse(result.body);
        expect(responseBody.status).toBe('IN_PROGRESS');
      });
    });
  });
});
