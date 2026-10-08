// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import {
  AdminGetUserCommand,
  AdminListGroupsForUserCommand,
  CognitoIdentityProviderClient,
} from '@aws-sdk/client-cognito-identity-provider';
import { SFNClient, StartExecutionCommand } from '@aws-sdk/client-sfn';
import { BatchWriteCommand, DynamoDBDocumentClient, PutCommand, ScanCommand } from '@aws-sdk/lib-dynamodb';
import { mockClient } from 'aws-sdk-client-mock';
import { DynamoDBTestSetup } from '../../../common/__tests__/dynamodbSetup';
import { findingsTableName, remediationConfigTableName } from '../../../common/__tests__/envSetup';
import { API_HEADERS } from '../../handlers/apiHandler';
import { executeFindingAction, searchFindings } from '../../handlers/findings';
import { createMockContext, createMockEvent, createMockFinding, TEST_REQUEST_CONTEXT, asFindingId } from '../utils';

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
    await DynamoDBTestSetup.createConfigTable(remediationConfigTableName);
  });

  afterAll(async () => {
    await DynamoDBTestSetup.deleteTable(findingsTableName);
    await DynamoDBTestSetup.deleteTable(remediationHistoryTableName);
    await DynamoDBTestSetup.deleteTable(userAccountMappingTableName);
    await DynamoDBTestSetup.deleteTable(remediationConfigTableName);
  });

  beforeEach(async () => {
    await DynamoDBTestSetup.clearTable(findingsTableName, 'findings');
    await DynamoDBTestSetup.clearTable(remediationHistoryTableName, 'remediationHistory');
    await DynamoDBTestSetup.clearTable(userAccountMappingTableName, 'userAccountMapping');
    await DynamoDBTestSetup.clearTable(remediationConfigTableName, 'config');
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
          findingId: asFindingId('finding-1'),
          accountId: '123456789012',
          resourceId: 'arn:aws:s3:::bucket-1',
          severity: 'HIGH',
          findingDescription: 'Critical S3 bucket issue',
          'securityHubUpdatedAtTime#findingId': '2023-01-01T00:00:00Z#finding-1',
        }),
        createMockFinding({
          findingId: asFindingId('finding-2'),
          accountId: '123456789012',
          resourceId: 'arn:aws:ec2:us-east-1:123456789012:instance/i-1234567890abcdef0',
          resourceType: 'AWS::EC2::Instance',
          severity: 'MEDIUM',
          findingDescription: 'EC2 security group issue',
          'securityHubUpdatedAtTime#findingId': '2023-01-02T00:00:00Z#finding-2',
        }),
        createMockFinding({
          findingId: asFindingId('finding-3'),
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
        'Invalid request: Filters.CompositeFilters.0.Operator: Invalid option: expected one of "AND"|"OR"',
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
          findingId: asFindingId('finding-s3-1'),
          accountId: '123456789012',
          resourceId: 'arn:aws:s3:::bucket-1',
          resourceType: 'AWS::S3::Bucket',
          resourceTypeNormalized: 'awss3bucket',
          severity: 'HIGH',
          findingDescription: 'S3 bucket issue 1',
          'securityHubUpdatedAtTime#findingId': '2023-01-01T00:00:00Z#finding-s3-1',
        }),
        createMockFinding({
          findingId: asFindingId('finding-s3-2'),
          accountId: '123456789012',
          resourceId: 'arn:aws:s3:::bucket-2',
          resourceType: 'AwsS3Bucket',
          resourceTypeNormalized: 'awss3bucket',
          severity: 'MEDIUM',
          findingDescription: 'S3 bucket issue 2',
          'securityHubUpdatedAtTime#findingId': '2023-01-02T00:00:00Z#finding-s3-2',
        }),
        createMockFinding({
          findingId: asFindingId('finding-ec2-1'),
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
          findingId: asFindingId('finding-s3-3'),
          accountId: '123456789012',
          resourceId: 'arn:aws:s3:::bucket-3',
          resourceType: 'AWS::S3::Bucket',
          resourceTypeNormalized: 'awss3bucket',
          severity: 'HIGH',
          findingDescription: 'S3 bucket issue 3',
          'securityHubUpdatedAtTime#findingId': '2023-01-01T00:00:00Z#finding-s3-3',
        }),
        createMockFinding({
          findingId: asFindingId('finding-s3-4'),
          accountId: '123456789012',
          resourceId: 'arn:aws:s3:::bucket-4',
          resourceType: 'AwsS3Bucket',
          resourceTypeNormalized: 'awss3bucket',
          severity: 'MEDIUM',
          findingDescription: 'S3 bucket issue 4',
          'securityHubUpdatedAtTime#findingId': '2023-01-02T00:00:00Z#finding-s3-4',
        }),
        createMockFinding({
          findingId: asFindingId('finding-rds-1'),
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
            findingId: asFindingId(`finding-${i.toString().padStart(3, '0')}`),
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
            findingId: asFindingId(`finding-${i.toString().padStart(3, '0')}`),
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
        'Invalid request: Filters.CompositeFilters.0.StringFilters.0.Filter.Comparison: Invalid option: expected one of "EQUALS"|"NOT_EQUALS"|"CONTAINS"|"NOT_CONTAINS"|"GREATER_THAN_OR_EQUAL"|"LESS_THAN_OR_EQUAL"',
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
        'Invalid request: SortCriteria.0.SortOrder: Invalid option: expected one of "asc"|"desc"',
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
          findingId: asFindingId('finding-1'),
          findingType: 'cis-aws-foundations-benchmark/v/1.4.0/4.8',
          accountId: '123456789012',
          resourceId: 'arn:aws:s3:::test-bucket-1',
          severity: 'HIGH',
          findingDescription: 'Test finding 1',
          suppressed: false,
          'securityHubUpdatedAtTime#findingId': '2023-01-01T00:00:00Z#finding-1',
        }),
        createMockFinding({
          findingId: asFindingId('finding-2'),
          findingType: 'cis-aws-foundations-benchmark/v/1.4.0/4.9',
          accountId: '123456789012',
          resourceId: 'arn:aws:s3:::test-bucket-2',
          severity: 'MEDIUM',
          findingDescription: 'Test finding 2',
          suppressed: false,
          'securityHubUpdatedAtTime#findingId': '2023-01-02T00:00:00Z#finding-2',
        }),
        createMockFinding({
          findingId: asFindingId('finding-3'),
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
        const suppressSingleFindingId = asFindingId(
          'arn:aws:securityhub:us-east-1:123456789012:security-control/Lambda.3/finding/suppress-single-test',
        );
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
        const suppressFinding1Id = asFindingId(
          'arn:aws:securityhub:us-east-1:123456789012:security-control/Lambda.3/finding/suppress-multiple-test-1',
        );
        const suppressFinding2Id = asFindingId(
          'arn:aws:securityhub:us-east-1:123456789012:security-control/Lambda.3/finding/suppress-multiple-test-2',
        );

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
        const unsuppressSingleFindingId = asFindingId(
          'arn:aws:securityhub:us-east-1:123456789012:security-control/Lambda.3/finding/unsuppress-single-test',
        );
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
        expect(JSON.parse(result.body)).toEqual({ status: 'UNSUPPRESSED', processedCount: 1 });
      });

      it('should return 200 and unsuppress multiple findings', async () => {
        const unsuppressFinding1Id = asFindingId(
          'arn:aws:securityhub:us-east-1:123456789012:security-control/Lambda.3/finding/unsuppress-test-1',
        );
        const unsuppressFinding2Id = asFindingId(
          'arn:aws:securityhub:us-east-1:123456789012:security-control/Lambda.3/finding/unsuppress-test-2',
        );

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
        const existingFinding1Id = asFindingId(
          'arn:aws:securityhub:us-east-1:123456789012:security-control/Lambda.3/finding/mixed-test-1',
        );
        const existingFinding2Id = asFindingId(
          'arn:aws:securityhub:us-east-1:123456789012:security-control/Lambda.3/finding/mixed-test-2',
        );

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
        const findingId = asFindingId(
          'arn:aws:securityhub:us-east-1:123456789012:security-control/Lambda.3/finding/12345678-1234-1234-1234-123456789013',
        );
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

      it('should return a terminal status and processed count for a successful Suppress', async () => {
        const findingId = asFindingId(
          'arn:aws:securityhub:us-east-1:123456789012:security-control/Lambda.3/finding/12345678-1234-1234-1234-123456789012',
        );
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
        expect(body).toEqual({ status: 'SUPPRESSED', processedCount: 1 });
      });
    });

    describe('Remediate Action', () => {
      it('should return 202 and initiate remediation for single finding', async () => {
        const remediateFindingId = asFindingId(
          'arn:aws:securityhub:us-east-1:123456789012:security-control/Lambda.3/finding/test-finding-remediate',
        );

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

      it('should not write a remediation history row when the orchestrator returns no execution ID', async () => {
        // The orchestrator invocation "succeeds" at the API level but yields no executionArn,
        // which mirrors a failed Step Functions start. Without an executionId we must not
        // persist a history row, because the composite key `findingId#executionId` would be
        // malformed (`findingId#`) and corrupt later lookups.
        sfnMock.reset();
        sfnMock.on(StartExecutionCommand).resolves({});

        const remediateFindingId = asFindingId(
          'arn:aws:securityhub:us-east-1:123456789012:security-control/Lambda.3/finding/test-finding-no-exec-id',
        );

        const testFinding = createMockFinding({
          findingId: remediateFindingId,
          findingType: 'security-control/Lambda.3',
          accountId: '123456789012',
          resourceId: 'arn:aws:lambda:us-east-1:123456789012:function:test-function-no-exec-id',
          severity: 'HIGH',
          findingDescription: 'Test finding with no execution id',
          suppressed: false,
          'securityHubUpdatedAtTime#findingId': `2023-01-01T00:00:00Z#${remediateFindingId}`,
        });

        await dynamoDBDocumentClient.send(
          new PutCommand({
            TableName: findingsTableName,
            Item: testFinding,
          }),
        );

        const event = createMockEvent({
          httpMethod: 'POST',
          path: '/findings/action',
          headers: {
            'Content-Type': 'application/json',
            authorization: 'Bearer valid-token',
          },
          body: JSON.stringify({
            actionType: 'Remediate',
            findingIds: [remediateFindingId],
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

        const result = await executeFindingAction(event, createMockContext());

        expect(result.statusCode).toBe(202);
        expect(JSON.parse(result.body).status).toBe('IN_PROGRESS');

        // Observable outcome: no history row was written for the finding.
        const historyScan = await dynamoDBDocumentClient.send(
          new ScanCommand({ TableName: remediationHistoryTableName }),
        );
        expect(historyScan.Items ?? []).toHaveLength(0);
      });

      it('should return 202 and initiate remediation with ticket generation', async () => {
        const remediateFindingId = asFindingId(
          'arn:aws:securityhub:us-east-1:123456789012:security-control/Lambda.3/finding/test-finding-remediate-ticket',
        );

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

      it('should return 202 and initiate rollback for eligible GuardDuty finding', async () => {
        // Seed the config table so filterByRollbackEnabled finds the control
        await dynamoDBDocumentClient.send(
          new PutCommand({
            TableName: remediationConfigTableName,
            Item: { controlId: 'GuardDuty.IAMUser', rollbackEnabled: true, automatedRemediationEnabled: true },
          }),
        );

        const rollbackFindingId = asFindingId(
          'arn:aws:securityhub:us-east-1:123456789012:security-control/GuardDuty.IAMUser/finding/test-rollback-001',
        );

        const testFinding = createMockFinding({
          findingId: rollbackFindingId,
          findingType: 'security-control/GuardDuty.IAMUser',
          accountId: '123456789012',
          resourceId: 'arn:aws:iam::123456789012:user/test-compromised-user',
          severity: 'HIGH',
          remediationStatus: 'SUCCESS',
          findingDescription: 'GuardDuty IAM credential compromise',
          suppressed: false,
          'securityHubUpdatedAtTime#findingId': `2023-01-01T00:00:00Z#${rollbackFindingId}`,
        });

        await dynamoDBDocumentClient.send(
          new PutCommand({
            TableName: findingsTableName,
            Item: testFinding,
          }),
        );

        const requestBody = {
          actionType: 'Rollback',
          findingIds: [rollbackFindingId],
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

        // Verify the orchestrator was invoked with Action=Restore in docParameters
        const sfnCalls = sfnMock.commandCalls(StartExecutionCommand);
        expect(sfnCalls).toHaveLength(1);
        const rawInput = sfnCalls[0].args[0].input.input;
        expect(rawInput).toBeDefined();
        const orchestratorInput = JSON.parse(rawInput!);
        expect(orchestratorInput.detail.docParameters).toEqual({ Action: 'Restore' });
      });

      it('refuses a Rollback from an Account Operator while still allowing that tier other actions', async () => {
        // Per ADR 0011 rollback is restricted to administrator roles, which the handler
        // implements by swapping createAccessRules for createAdminOnlyAccessRules when
        // actionType is Rollback. Nothing asserted that swap, and it is the only thing
        // enforcing it: MCP tool grants are per TOOL, not per action type, so an Account
        // Operator granted execute_finding_action reaches this route and can name Rollback.
        //
        // The operator is deliberately given a real account mapping covering the finding's
        // account. Without it the request fails on "No authorized accounts" instead, and the
        // test would pass with the rollback restriction deleted.
        const operatorEmail = 'operator-user@example.com';
        // The suite's shared stub answers every AdminGetUser with the admin's email, and a
        // narrower behaviour registered here would be shadowed by it. Resolve the email from
        // the requested username instead, so the account lookup keys off THIS caller.
        cognitoMock.on(AdminGetUserCommand).callsFake((input) => ({
          Username: String(input.Username),
          // Both attributes are required: getUserById returns null unless email AND
          // custom:invitedBy are present, and a null user surfaces as "Invalid user"
          // long before the rollback rule this test is about.
          UserAttributes: [
            { Name: 'email', Value: String(input.Username) },
            { Name: 'custom:invitedBy', Value: 'system@example.com' },
          ],
          UserCreateDate: new Date(),
          UserStatus: 'CONFIRMED',
        }));
        cognitoMock.on(AdminListGroupsForUserCommand).resolves({ Groups: [{ GroupName: 'AccountOperatorGroup' }] });
        await dynamoDBDocumentClient.send(
          new PutCommand({
            TableName: userAccountMappingTableName,
            Item: { userId: operatorEmail, accountIds: ['123456789012'] },
          }),
        );
        await dynamoDBDocumentClient.send(
          new PutCommand({
            TableName: remediationConfigTableName,
            Item: { controlId: 'GuardDuty.IAMUser', rollbackEnabled: true, automatedRemediationEnabled: true },
          }),
        );

        const findingId = asFindingId(
          'arn:aws:securityhub:us-east-1:123456789012:security-control/GuardDuty.IAMUser/finding/operator-rollback-001',
        );
        await dynamoDBDocumentClient.send(
          new PutCommand({
            TableName: findingsTableName,
            Item: createMockFinding({
              findingId,
              findingType: 'security-control/GuardDuty.IAMUser',
              accountId: '123456789012',
              resourceId: 'arn:aws:iam::123456789012:user/test-compromised-user',
              severity: 'HIGH',
              remediationStatus: 'SUCCESS',
              findingDescription: 'GuardDuty IAM credential compromise',
              suppressed: false,
            }),
          }),
        );

        const operatorEvent = (actionType: string) =>
          createMockEvent({
            httpMethod: 'POST',
            path: '/findings/action',
            headers: { 'Content-Type': 'application/json', authorization: 'Bearer valid-token' },
            body: JSON.stringify({ actionType, findingIds: [findingId] }),
            requestContext: {
              ...TEST_REQUEST_CONTEXT,
              authorizer: {
                claims: { 'cognito:groups': ['AccountOperatorGroup'], username: operatorEmail },
              },
            },
          });

        // Rollback is refused for the tier, and nothing is started — a refusal that had
        // already invoked the state machine would have restored the resource anyway.
        await expect(executeFindingAction(operatorEvent('Rollback'), createMockContext())).rejects.toThrow(
          /authorization|authorized|forbidden/i,
        );
        expect(sfnMock.commandCalls(StartExecutionCommand)).toHaveLength(0);

        // The same caller is still allowed a non-rollback action, so the restriction is
        // specific to Rollback rather than the route being closed to the tier outright.
        const suppressResult = await executeFindingAction(operatorEvent('Suppress'), createMockContext());
        expect(suppressResult.statusCode).toBeLessThan(400);
      });

      it('rolls back both a live finding and an archived (history-only) finding in one request', async () => {
        // Seed config table for rollback eligibility
        await dynamoDBDocumentClient.send(
          new PutCommand({
            TableName: remediationConfigTableName,
            Item: { controlId: 'GuardDuty.IAMUser', rollbackEnabled: true, automatedRemediationEnabled: true },
          }),
        );
        // GIVEN one GuardDuty finding that still exists in the findings table (live)...
        const liveFindingId = asFindingId(
          'arn:aws:securityhub:us-east-1:123456789012:security-control/GuardDuty.IAMUser/finding/test-rollback-live',
        );
        const liveFinding = createMockFinding({
          findingId: liveFindingId,
          findingType: 'security-control/GuardDuty.IAMUser',
          resourceId: 'arn:aws:iam::123456789012:user/live-user',
          remediationStatus: 'SUCCESS',
          'securityHubUpdatedAtTime#findingId': `2023-01-01T00:00:00Z#${liveFindingId}`,
        });
        await dynamoDBDocumentClient.send(new PutCommand({ TableName: findingsTableName, Item: liveFinding }));

        // ...and one GuardDuty finding that has been archived from the findings table but whose
        // findingJSON was preserved in remediation history (history-only).
        const archivedFindingId = asFindingId(
          'arn:aws:securityhub:us-east-1:123456789012:security-control/GuardDuty.IAMUser/finding/test-rollback-archived',
        );
        const archivedSource = createMockFinding({
          findingId: archivedFindingId,
          findingType: 'security-control/GuardDuty.IAMUser',
          resourceId: 'arn:aws:iam::123456789012:user/archived-user',
          remediationStatus: 'SUCCESS',
        });
        const executionId = 'arn:aws:states:us-east-1:123456789012:execution:SM:exec-archived';
        await dynamoDBDocumentClient.send(
          new PutCommand({
            TableName: remediationHistoryTableName,
            Item: {
              findingType: archivedSource.findingType,
              'findingId#executionId': `${archivedFindingId}#${executionId}`,
              findingId: archivedFindingId,
              accountId: archivedSource.accountId,
              resourceId: archivedSource.resourceId,
              resourceType: archivedSource.resourceType,
              resourceTypeNormalized: archivedSource.resourceTypeNormalized,
              severity: archivedSource.severity,
              region: archivedSource.region,
              remediationStatus: 'SUCCESS',
              lastUpdatedTime: '2023-02-01T00:00:00Z',
              'lastUpdatedTime#findingId': `2023-02-01T00:00:00Z#${archivedFindingId}`,
              REMEDIATION_CONSTANT: 'remediation',
              lastUpdatedBy: 'admin-user@example.com',
              executionId,
              findingJSON: archivedSource.findingJSON,
            },
          }),
        );

        const event = createMockEvent({
          httpMethod: 'POST',
          path: '/findings/action',
          headers: { 'Content-Type': 'application/json', authorization: 'Bearer valid-token' },
          body: JSON.stringify({ actionType: 'Rollback', findingIds: [liveFindingId, archivedFindingId] }),
          requestContext: {
            ...TEST_REQUEST_CONTEXT,
            authorizer: {
              claims: { 'cognito:groups': ['AdminGroup'], username: 'admin-user@example.com' },
            },
          },
        });

        const result = await executeFindingAction(event, createMockContext());

        expect(result.statusCode).toBe(202);
        expect(JSON.parse(result.body).status).toBe('IN_PROGRESS');

        // THEN the orchestrator is invoked for BOTH findings — the history-only finding is not
        // silently dropped just because the live finding was resolvable.
        const sfnCalls = sfnMock.commandCalls(StartExecutionCommand);
        expect(sfnCalls).toHaveLength(2);
        const restoredResourceIds = sfnCalls.map((call) => {
          const input = JSON.parse(call.args[0].input.input!);
          return input.detail.findings[0].Resources[0].Id;
        });
        expect(restoredResourceIds).toEqual(
          expect.arrayContaining([
            'arn:aws:iam::123456789012:user/live-user',
            'arn:aws:iam::123456789012:user/archived-user',
          ]),
        );
      });

      it('should return 400 when rollback is attempted on a control without config table entry', async () => {
        // GIVEN a rollback-eligible control that has no entry in the config table, so the
        // per-control toggle lookup finds nothing and the finding is skipped.
        const findingId = asFindingId(
          'arn:aws:securityhub:us-east-1:123456789012:security-control/KMS.4/finding/test-rollback-no-config',
        );
        await dynamoDBDocumentClient.send(
          new PutCommand({
            TableName: findingsTableName,
            Item: createMockFinding({
              findingId,
              findingType: 'security-control/KMS.4',
              remediationStatus: 'SUCCESS',
              'securityHubUpdatedAtTime#findingId': `2023-01-01T00:00:00Z#${findingId}`,
            }),
          }),
        );

        const event = createMockEvent({
          httpMethod: 'POST',
          path: '/findings/action',
          headers: { 'Content-Type': 'application/json', authorization: 'Bearer valid-token' },
          body: JSON.stringify({ actionType: 'Rollback', findingIds: [findingId] }),
          requestContext: {
            ...TEST_REQUEST_CONTEXT,
            authorizer: { claims: { 'cognito:groups': ['AdminGroup'], username: 'admin-user@example.com' } },
          },
        });

        await expect(executeFindingAction(event, createMockContext())).rejects.toThrow(
          /Rollback is disabled for all requested controls/,
        );
      });

      it('resolves a rollback finding whose id is not a derivable ARN when findingKeys are supplied', async () => {
        // ARRANGE — a rollback-eligible finding that exists only in the findings table (no history
        // entry), whose findingId is not a parseable Security Hub ARN. The partition key therefore
        // cannot be derived from the id, so the table-fallback leg needs an explicit key.
        const bareHashFindingId = asFindingId('9f8e7d6c5b4a392817060f1e2d3c4b5a');
        const findingType = 'security-control/GuardDuty.IAMUser';
        await dynamoDBDocumentClient.send(
          new PutCommand({
            TableName: remediationConfigTableName,
            Item: { controlId: 'GuardDuty.IAMUser', rollbackEnabled: true, automatedRemediationEnabled: true },
          }),
        );
        await dynamoDBDocumentClient.send(
          new PutCommand({
            TableName: findingsTableName,
            Item: createMockFinding({
              findingId: bareHashFindingId,
              findingType,
              resourceId: 'arn:aws:iam::123456789012:user/bare-hash-user',
              remediationStatus: 'SUCCESS',
              ssmExecutionId: 'exec-original-remediation',
              'securityHubUpdatedAtTime#findingId': `2023-01-01T00:00:00Z#${bareHashFindingId}`,
            }),
          }),
        );

        const rollbackEvent = (body: Record<string, unknown>) =>
          createMockEvent({
            httpMethod: 'POST',
            path: '/findings/action',
            headers: { 'Content-Type': 'application/json', authorization: 'Bearer valid-token' },
            body: JSON.stringify(body),
            requestContext: {
              ...TEST_REQUEST_CONTEXT,
              authorizer: { claims: { 'cognito:groups': ['AdminGroup'], username: 'admin-user@example.com' } },
            },
          });

        // ACT / ASSERT — without keys the id cannot be derived to a partition key, so nothing resolves
        await expect(
          executeFindingAction(
            rollbackEvent({ actionType: 'Rollback', findingIds: [bareHashFindingId] }),
            createMockContext(),
          ),
        ).rejects.toThrow(/No findings found for the provided IDs/);

        // ACT — the same request supplying the explicit key
        const result = await executeFindingAction(
          rollbackEvent({
            actionType: 'Rollback',
            findingIds: [bareHashFindingId],
            findingKeys: [{ findingId: bareHashFindingId, findingType }],
          }),
          createMockContext(),
        );

        // ASSERT — the finding resolves and the rollback is dispatched
        expect(result.statusCode).toBe(202);
        expect(JSON.parse(result.body).status).toBe('IN_PROGRESS');
      });

      it('should return 400 when rollback is attempted on a control not in ROLLBACK_ELIGIBLE_FINDING_TYPES', async () => {
        // Seed config table with a control that has rollbackEnabled but is NOT in the eligible set
        await dynamoDBDocumentClient.send(
          new PutCommand({
            TableName: remediationConfigTableName,
            Item: { controlId: 'CloudFormation.1', rollbackEnabled: true, automatedRemediationEnabled: true },
          }),
        );
        const findingId = asFindingId(
          'arn:aws:securityhub:us-east-1:123456789012:security-control/CloudFormation.1/finding/test-rollback-not-eligible',
        );
        await dynamoDBDocumentClient.send(
          new PutCommand({
            TableName: findingsTableName,
            Item: createMockFinding({
              findingId,
              findingType: 'security-control/CloudFormation.1',
              remediationStatus: 'SUCCESS',
              'securityHubUpdatedAtTime#findingId': `2023-01-01T00:00:00Z#${findingId}`,
            }),
          }),
        );

        const event = createMockEvent({
          httpMethod: 'POST',
          path: '/findings/action',
          headers: { 'Content-Type': 'application/json', authorization: 'Bearer valid-token' },
          body: JSON.stringify({ actionType: 'Rollback', findingIds: [findingId] }),
          requestContext: {
            ...TEST_REQUEST_CONTEXT,
            authorizer: { claims: { 'cognito:groups': ['AdminGroup'], username: 'admin-user@example.com' } },
          },
        });

        // The refusal must name the finding and the control so a batch caller knows what to drop.
        await expect(executeFindingAction(event, createMockContext())).rejects.toThrow(
          new RegExp(
            `Rollback is only supported for eligible controls\\. Not eligible for rollback: ${findingId.replaceAll('.', '\\.')} \\(CloudFormation\\.1\\)`,
          ),
        );
      });

      it('should return 400 when a rollback-eligible finding has no recorded SSM execution id', async () => {
        // A snapshot-based rollback needs the original execution id to locate its snapshot. Without it
        // buildOrchestratorInput emits no rollback docParameters and the orchestrator would run the
        // remediation forward, so the finding must be skipped before the lock is taken.
        await dynamoDBDocumentClient.send(
          new PutCommand({
            TableName: remediationConfigTableName,
            Item: { controlId: 'KMS.4', rollbackEnabled: true, automatedRemediationEnabled: true },
          }),
        );
        const findingId = asFindingId(
          'arn:aws:securityhub:us-east-1:123456789012:security-control/KMS.4/finding/test-rollback-no-exec-id',
        );
        await dynamoDBDocumentClient.send(
          new PutCommand({
            TableName: findingsTableName,
            Item: createMockFinding({
              findingId,
              findingType: 'security-control/KMS.4',
              remediationStatus: 'SUCCESS',
              'securityHubUpdatedAtTime#findingId': `2023-01-01T00:00:00Z#${findingId}`,
            }),
          }),
        );

        const event = createMockEvent({
          httpMethod: 'POST',
          path: '/findings/action',
          headers: { 'Content-Type': 'application/json', authorization: 'Bearer valid-token' },
          body: JSON.stringify({ actionType: 'Rollback', findingIds: [findingId] }),
          requestContext: {
            ...TEST_REQUEST_CONTEXT,
            authorizer: { claims: { 'cognito:groups': ['AdminGroup'], username: 'admin-user@example.com' } },
          },
        });

        await expect(executeFindingAction(event, createMockContext())).rejects.toThrow(
          /pre-remediation snapshot cannot be located/,
        );

        // No execution started, so the rollback could not have become a re-remediation.
        expect(sfnMock.commandCalls(StartExecutionCommand)).toHaveLength(0);
      });

      it('should dispatch a rollback with snapshot docParameters when the finding has an SSM execution id', async () => {
        await dynamoDBDocumentClient.send(
          new PutCommand({
            TableName: remediationConfigTableName,
            Item: { controlId: 'KMS.4', rollbackEnabled: true, automatedRemediationEnabled: true },
          }),
        );
        const findingId = asFindingId(
          'arn:aws:securityhub:us-east-1:123456789012:security-control/KMS.4/finding/test-rollback-with-exec-id',
        );
        await dynamoDBDocumentClient.send(
          new PutCommand({
            TableName: findingsTableName,
            Item: createMockFinding({
              findingId,
              findingType: 'security-control/KMS.4',
              remediationStatus: 'SUCCESS',
              ssmExecutionId: 'exec-original-remediation',
              'securityHubUpdatedAtTime#findingId': `2023-01-01T00:00:00Z#${findingId}`,
            }),
          }),
        );

        const event = createMockEvent({
          httpMethod: 'POST',
          path: '/findings/action',
          headers: { 'Content-Type': 'application/json', authorization: 'Bearer valid-token' },
          body: JSON.stringify({ actionType: 'Rollback', findingIds: [findingId] }),
          requestContext: {
            ...TEST_REQUEST_CONTEXT,
            authorizer: { claims: { 'cognito:groups': ['AdminGroup'], username: 'admin-user@example.com' } },
          },
        });

        const result = await executeFindingAction(event, createMockContext());

        expect(result.statusCode).toBe(202);
        const sfnCalls = sfnMock.commandCalls(StartExecutionCommand);
        expect(sfnCalls).toHaveLength(1);
        const orchestratorInput = JSON.parse(sfnCalls[0].args[0].input.input!);
        expect(orchestratorInput.detail.docParameters).toMatchObject({
          Rollback: 'ROLLBACK',
          ExecutionId: 'exec-original-remediation',
        });
      });

      it('rolls back an unconsolidated finding using its stored config table key', async () => {
        // With consolidated control findings off, findingType carries the standard's own number (3.8),
        // not the SecurityControlId the config table is keyed by. Deriving it would skip the rollback.
        await dynamoDBDocumentClient.send(
          new PutCommand({
            TableName: remediationConfigTableName,
            Item: { controlId: 'KMS.4', rollbackEnabled: true, automatedRemediationEnabled: true },
          }),
        );
        const findingId = asFindingId(
          'arn:aws:securityhub:us-east-1:123456789012:subscription/cis-aws-foundations-benchmark/v/1.4.0/3.8/finding/unconsolidated',
        );
        await dynamoDBDocumentClient.send(
          new PutCommand({
            TableName: findingsTableName,
            Item: createMockFinding({
              findingId,
              findingType: 'cis-aws-foundations-benchmark/v/1.4.0/3.8',
              remediationConfigTableKey: 'KMS.4',
              remediationStatus: 'SUCCESS',
              ssmExecutionId: 'exec-unconsolidated',
              'securityHubUpdatedAtTime#findingId': `2023-01-01T00:00:00Z#${findingId}`,
            }),
          }),
        );

        const event = createMockEvent({
          httpMethod: 'POST',
          path: '/findings/action',
          headers: { 'Content-Type': 'application/json', authorization: 'Bearer valid-token' },
          body: JSON.stringify({ actionType: 'Rollback', findingIds: [findingId] }),
          requestContext: {
            ...TEST_REQUEST_CONTEXT,
            authorizer: { claims: { 'cognito:groups': ['AdminGroup'], username: 'admin-user@example.com' } },
          },
        });

        const result = await executeFindingAction(event, createMockContext());

        expect(result.statusCode).toBe(202);
        expect(sfnMock.commandCalls(StartExecutionCommand)).toHaveLength(1);
      });

      it('should return 400 when rollback is attempted on a GuardDuty finding that is not SUCCESS', async () => {
        // Seed config table
        await dynamoDBDocumentClient.send(
          new PutCommand({
            TableName: remediationConfigTableName,
            Item: { controlId: 'GuardDuty.IAMUser', rollbackEnabled: true, automatedRemediationEnabled: true },
          }),
        );
        // GIVEN a GuardDuty finding with IN_PROGRESS status
        const findingId = asFindingId(
          'arn:aws:securityhub:us-east-1:123456789012:security-control/GuardDuty.IAMUser/finding/test-rollback-wrong-status',
        );
        await dynamoDBDocumentClient.send(
          new PutCommand({
            TableName: findingsTableName,
            Item: createMockFinding({
              findingId,
              findingType: 'security-control/GuardDuty.IAMUser',
              remediationStatus: 'IN_PROGRESS',
              'securityHubUpdatedAtTime#findingId': `2023-01-01T00:00:00Z#${findingId}`,
            }),
          }),
        );

        const event = createMockEvent({
          httpMethod: 'POST',
          path: '/findings/action',
          headers: { 'Content-Type': 'application/json', authorization: 'Bearer valid-token' },
          body: JSON.stringify({ actionType: 'Rollback', findingIds: [findingId] }),
          requestContext: {
            ...TEST_REQUEST_CONTEXT,
            authorizer: { claims: { 'cognito:groups': ['AdminGroup'], username: 'admin-user@example.com' } },
          },
        });

        await expect(executeFindingAction(event, createMockContext())).rejects.toThrow(
          `Not eligible: ${findingId} (remediation still in progress)`,
        );
      });
    });
  });
});
