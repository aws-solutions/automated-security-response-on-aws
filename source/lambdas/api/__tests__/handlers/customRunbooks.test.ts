// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Mock tsimportlib to avoid --experimental-vm-modules requirement
jest.mock('tsimportlib', () => ({
  dynamicImport: jest.fn(async (moduleName: string) => {
    if (moduleName === '@middy/core') {
      type MockHandler = (event: { body?: unknown }, context: unknown) => Promise<unknown>;
      return {
        default: (handler: MockHandler) => {
          const wrapped = async (event: { body?: unknown }, context: unknown) => {
            if (typeof event.body === 'string') {
              event.body = JSON.parse(event.body);
            }
            return handler(event, context);
          };
          wrapped.use = () => wrapped;
          return wrapped;
        },
      };
    }
    if (moduleName === '@middy/http-json-body-parser') {
      return { default: () => ({}) };
    }
    return {};
  }),
}));

// Mock the SSM client module so we can control responses
const mockSsmSend = jest.fn();
jest.mock('@aws-sdk/client-ssm', () => {
  const actual = jest.requireActual('@aws-sdk/client-ssm');
  return {
    ...actual,
    SSMClient: jest.fn().mockImplementation(() => ({
      send: mockSsmSend,
    })),
  };
});

// Mock Cognito so validateAccess doesn't make real calls
const mockCognitoSend = jest.fn();
jest.mock('@aws-sdk/client-cognito-identity-provider', () => {
  const actual = jest.requireActual('@aws-sdk/client-cognito-identity-provider');
  return {
    ...actual,
    CognitoIdentityProviderClient: jest.fn().mockImplementation(() => ({ send: mockCognitoSend })),
  };
});

// Mock STS for member-account credential chain (drift detection)
const mockStsSend = jest.fn();
jest.mock('@aws-sdk/client-sts', () => {
  const actual = jest.requireActual('@aws-sdk/client-sts');
  return {
    ...actual,
    STSClient: jest.fn().mockImplementation(() => ({ send: mockStsSend })),
  };
});

// Mock IAM for the cross-account remediation-role provisioning in the deploy path
const mockIamSend = jest.fn();
jest.mock('@aws-sdk/client-iam', () => {
  const actual = jest.requireActual('@aws-sdk/client-iam');
  return {
    ...actual,
    IAMClient: jest.fn().mockImplementation(() => ({ send: mockIamSend })),
  };
});

// Mock SecurityHub for drift detection execute path
const mockSecurityHubSend = jest.fn();
jest.mock('@aws-sdk/client-securityhub', () => {
  const actual = jest.requireActual('@aws-sdk/client-securityhub');
  return {
    ...actual,
    SecurityHubClient: jest.fn().mockImplementation(() => ({ send: mockSecurityHubSend })),
  };
});

import {
  ListDocumentsCommand,
  GetDocumentCommand,
  CreateDocumentCommand,
  DescribeDocumentCommand,
  UpdateDocumentCommand,
  UpdateDocumentDefaultVersionCommand,
  DuplicateDocumentContent,
  GetAutomationExecutionCommand,
  AutomationExecutionNotFoundException,
  GetParameterCommand,
  ParameterNotFound,
  SSMClient,
} from '@aws-sdk/client-ssm';
import { GetObjectCommand, GetObjectCommandOutput, S3Client } from '@aws-sdk/client-s3';
import {
  CreateRoleCommand,
  GetRoleCommand,
  NoSuchEntityException,
  PutRolePolicyCommand,
  TagRoleCommand,
} from '@aws-sdk/client-iam';
import { createHash } from 'node:crypto';
import { DynamoDBDocumentClient, ScanCommand } from '@aws-sdk/lib-dynamodb';
import { mockClient } from 'aws-sdk-client-mock';
import { listRunbooks, getRunbook, driftDetection, deployRunbook } from '../../handlers/customRunbooks';
import { DEPLOY_RUNBOOK_PARTIAL_FAILURE_METRIC } from '../../../common/utils/cloudWatchMetrics';
import type { MemberDeploymentState, RunbookId, RunbookMetadata } from '@asr/data-models';
import { CustomRunbookRepository } from '../../../common/repositories/customRunbookRepository';
import { createDynamoDBClient } from '../../../common/utils/dynamodb';
import { DynamoDBTestSetup } from '../../../common/__tests__/dynamodbSetup';
import { customRunbookTableName } from '../../../common/__tests__/envSetup';
import { pollAutomationExecution } from '../../services/driftDetectionService';
import {
  buildExecuteRunbookEnvelope,
  CustomRunbookExecutionService,
} from '../../services/customRunbookExecutionService';
import { APIGatewayProxyEvent } from 'aws-lambda';
import { createMockContext, createMockEvent } from '../utils';
import { resetApiLambdaEnvironmentCache } from '../../apiLambdaEnvironment';

// Mock S3 and DynamoDB to prevent real calls
const s3Mock = mockClient(S3Client);
const dynamoMock = mockClient(DynamoDBDocumentClient);
dynamoMock.resolves({ Items: [], Count: 0 });

/**
 * Creates an event authenticated as an AdminGroup user. With Option 2 auth,
 * MCP calls always arrive with Cognito claims (the MCP Lambda forwards the
 * user's JWT), so tests must include claims too.
 */
function createIamEvent(body: Record<string, unknown>) {
  return createMockEvent({
    body: JSON.stringify(body),
    requestContext: {
      ...createMockEvent().requestContext,
      authorizer: {
        claims: {
          'cognito:groups': 'AdminGroup',
          'cognito:username': 'test-admin',
          sub: 'test-admin-sub',
          email: 'test-admin@example.com',
        },
      },
    } as unknown as APIGatewayProxyEvent['requestContext'],
  });
}

describe('customRunbooks builtin runbook support', () => {
  beforeEach(() => {
    mockSsmSend.mockReset();
    mockCognitoSend.mockReset();
    dynamoMock.reset();
    dynamoMock.resolves({ Items: [], Count: 0 });
    process.env.CUSTOM_RUNBOOK_BUCKET_NAME = 'test-custom-runbook-bucket';
    process.env.CUSTOM_RUNBOOK_TABLE_NAME = 'test-custom-runbook-table';
    resetApiLambdaEnvironmentCache();

    // Cognito mock: getUserById calls AdminGetUser then AdminListGroupsForUser
    // Return a response that satisfies both — extra fields are ignored
    mockCognitoSend.mockResolvedValue({
      Username: 'test-admin',
      UserAttributes: [
        { Name: 'email', Value: 'test-admin@example.com' },
        { Name: 'custom:invitedBy', Value: 'system@example.com' },
      ],
      UserCreateDate: new Date(),
      UserStatus: 'CONFIRMED',
      Groups: [{ GroupName: 'AdminGroup' }],
    });
  });

  describe('listRunbooks with type=builtin', () => {
    it('returns 501 for custom-only listing when MCP blueprint is absent', async () => {
      delete process.env.CUSTOM_RUNBOOK_BUCKET_NAME;
      delete process.env.CUSTOM_RUNBOOK_TABLE_NAME;
      resetApiLambdaEnvironmentCache();

      await expect(listRunbooks(createIamEvent({ type: 'custom' }), createMockContext())).rejects.toMatchObject({
        statusCode: 501,
      });
    });

    it('should return builtin runbooks from SSM without the MCP blueprint', async () => {
      delete process.env.CUSTOM_RUNBOOK_BUCKET_NAME;
      delete process.env.CUSTOM_RUNBOOK_TABLE_NAME;
      resetApiLambdaEnvironmentCache();

      mockSsmSend.mockResolvedValueOnce({
        DocumentIdentifiers: [
          {
            Name: 'ASR-SC_1.0_IAM.1',
            DocumentVersion: '3',
            DisplayName: 'Remediate IAM.1',
            CreatedDate: new Date('2024-01-01'),
          },
          {
            Name: 'ASR-SC_1.0_S3.1',
            DocumentVersion: '1',
            DisplayName: 'Remediate S3.1',
            CreatedDate: new Date('2024-02-01'),
          },
        ],
      });

      const result = await listRunbooks(createIamEvent({ type: 'builtin' }), createMockContext());
      const body = JSON.parse(result.body);

      expect(result.statusCode).toBe(200);
      expect(body.runbooks).toHaveLength(2);
      expect(body.runbooks[0]).toMatchObject({
        runbook_id: 'ASR-SC_1.0_IAM.1',
        control_id: 'IAM.1',
        type: 'builtin',
        status: 'DEPLOYED',
        service_name: 'IAM',
      });
      expect(body.runbooks[1]).toMatchObject({
        runbook_id: 'ASR-SC_1.0_S3.1',
        control_id: 'S3.1',
        type: 'builtin',
      });
    });

    it('should omit shared remediation documents that carry no control segment', async () => {
      // ASR-EnableVPCFlowLogs and ASR-Orchestrator-* are solution-owned SSM documents that
      // control runbooks delegate to. They are not control runbooks and have no control to
      // report, so they must not appear with their own name masquerading as a control_id.
      mockSsmSend.mockResolvedValueOnce({
        DocumentIdentifiers: [
          { Name: 'ASR-EnableVPCFlowLogs', DocumentVersion: '2', CreatedDate: new Date('2024-01-01') },
          { Name: 'ASR-Orchestrator-Member', DocumentVersion: '1', CreatedDate: new Date('2024-01-01') },
          { Name: 'ASR-SC_2.0.0_EC2.6', DocumentVersion: '1', CreatedDate: new Date('2024-01-01') },
        ],
      });

      const result = await listRunbooks(createIamEvent({ type: 'builtin' }), createMockContext());
      const body = JSON.parse(result.body);

      expect(result.statusCode).toBe(200);
      expect(
        body.runbooks.map((r: { runbook_id: string; control_id: string }) => [r.runbook_id, r.control_id]),
      ).toEqual([['ASR-SC_2.0.0_EC2.6', 'EC2.6']]);
    });

    it('should not call SSM when status filter is DRAFT', async () => {
      const result = await listRunbooks(createIamEvent({ status: 'DRAFT' }), createMockContext());
      const body = JSON.parse(result.body);

      expect(result.statusCode).toBe(200);
      expect(mockSsmSend).not.toHaveBeenCalled();
      expect(body.runbooks.every((r: { type: string }) => r.type !== 'builtin')).toBe(true);
    });

    it('should not call SSM when type is custom', async () => {
      const result = await listRunbooks(createIamEvent({ type: 'custom' }), createMockContext());

      expect(result.statusCode).toBe(200);
      expect(mockSsmSend).not.toHaveBeenCalled();
    });

    it('should filter builtin runbooks by control_id client-side', async () => {
      mockSsmSend.mockResolvedValueOnce({
        DocumentIdentifiers: [
          {
            Name: 'ASR-SC_1.0_IAM.1',
            DocumentVersion: '1',
            CreatedDate: new Date(),
          },
          {
            Name: 'ASR-SC_2.0.0_S3.1',
            DocumentVersion: '2',
            CreatedDate: new Date(),
          },
        ],
      });

      const result = await listRunbooks(createIamEvent({ type: 'builtin', control_id: 'IAM.1' }), createMockContext());
      const body = JSON.parse(result.body);

      expect(result.statusCode).toBe(200);
      expect(mockSsmSend).toHaveBeenCalledTimes(1);
      // Filters no longer include a Name filter — filtering is client-side
      const sentCommand = mockSsmSend.mock.calls[0][0];
      expect(sentCommand).toBeInstanceOf(ListDocumentsCommand);
      expect(sentCommand.input.Filters).not.toContainEqual(expect.objectContaining({ Key: 'Name' }));
      // Only IAM.1 is returned despite S3.1 also being in the SSM response
      expect(body.runbooks).toHaveLength(1);
      expect(body.runbooks[0].control_id).toBe('IAM.1');
    });

    it('should paginate through SSM ListDocuments', async () => {
      mockSsmSend
        .mockResolvedValueOnce({
          DocumentIdentifiers: [
            {
              Name: 'ASR-SC_1.0_IAM.1',
              DocumentVersion: '1',
              CreatedDate: new Date(),
            },
          ],
          NextToken: 'page2',
        })
        .mockResolvedValueOnce({
          DocumentIdentifiers: [
            {
              Name: 'ASR-SC_1.0_S3.1',
              DocumentVersion: '1',
              CreatedDate: new Date(),
            },
          ],
        });

      const result = await listRunbooks(createIamEvent({ type: 'builtin' }), createMockContext());
      const body = JSON.parse(result.body);

      expect(result.statusCode).toBe(200);
      expect(body.runbooks).toHaveLength(2);
      expect(mockSsmSend).toHaveBeenCalledTimes(2);
    });

    it('should ignore non-ASR documents returned by SSM', async () => {
      mockSsmSend.mockResolvedValueOnce({
        DocumentIdentifiers: [
          {
            Name: 'ASR-SC_1.0_IAM.1',
            DocumentVersion: '1',
            CreatedDate: new Date(),
          },
          {
            Name: 'SomeOtherDocument',
            DocumentVersion: '1',
            CreatedDate: new Date(),
          },
        ],
      });

      const result = await listRunbooks(createIamEvent({ type: 'builtin' }), createMockContext());
      const body = JSON.parse(result.body);

      expect(body.runbooks).toHaveLength(1);
      expect(body.runbooks[0].runbook_id).toBe('ASR-SC_1.0_IAM.1');
    });

    it('collapses multiple versions of a custom runbook to its latest version', async () => {
      // The custom-runbook table is keyed by (runbookId, version), so a scan
      // returns every version. list_runbooks must emit one row per runbook — the
      // latest version — not one row per version.
      dynamoMock.on(ScanCommand).resolves({
        Items: [
          {
            runbookId: 'rb-1',
            version: 1,
            controlId: 'S3.9',
            status: 'DEPLOYED',
            description: 'v1',
            serviceName: 'S3',
            createdAt: '2026-01-01T00:00:00Z',
          },
          {
            runbookId: 'rb-1',
            version: 3,
            controlId: 'S3.9',
            status: 'DEPLOYED',
            description: 'v3',
            serviceName: 'S3',
            createdAt: '2026-01-03T00:00:00Z',
          },
          {
            runbookId: 'rb-1',
            version: 2,
            controlId: 'S3.9',
            status: 'DEPLOYED',
            description: 'v2',
            serviceName: 'S3',
            createdAt: '2026-01-02T00:00:00Z',
          },
        ],
        Count: 3,
      });

      const result = await listRunbooks(createIamEvent({ type: 'custom' }), createMockContext());
      const body = JSON.parse(result.body);

      expect(body.runbooks).toHaveLength(1);
      expect(body.runbooks[0]).toMatchObject({ runbook_id: 'rb-1', version: 3, description: 'v3' });
    });

    it('with a status filter, returns the latest version that matches — not the absolute newest', async () => {
      // v1 is DEPLOYED, v3 is DRAFT. A status=DEPLOYED filter must return v1 (the
      // latest matching version), even though v3 is the runbook's newest version.
      dynamoMock.on(ScanCommand).resolves({
        Items: [
          {
            runbookId: 'rb-1',
            version: 1,
            controlId: 'S3.9',
            status: 'DEPLOYED',
            description: 'v1-deployed',
            serviceName: 'S3',
            createdAt: '2026-01-01T00:00:00Z',
          },
          {
            runbookId: 'rb-1',
            version: 3,
            controlId: 'S3.9',
            status: 'DRAFT',
            description: 'v3-draft',
            serviceName: 'S3',
            createdAt: '2026-01-03T00:00:00Z',
          },
        ],
        Count: 2,
      });

      const result = await listRunbooks(createIamEvent({ type: 'custom', status: 'DEPLOYED' }), createMockContext());
      const body = JSON.parse(result.body);

      expect(body.runbooks).toHaveLength(1);
      expect(body.runbooks[0]).toMatchObject({ runbook_id: 'rb-1', version: 1, status: 'DEPLOYED' });
    });
  });

  describe('getRunbook with builtin SSM document', () => {
    it('should return a builtin runbook by SSM document name without the MCP blueprint', async () => {
      delete process.env.CUSTOM_RUNBOOK_BUCKET_NAME;
      delete process.env.CUSTOM_RUNBOOK_TABLE_NAME;
      resetApiLambdaEnvironmentCache();

      mockSsmSend.mockResolvedValueOnce({
        Content: 'description: Remediate IAM.1\nschemaVersion: "0.3"',
        DocumentVersion: '5',
        CreatedDate: new Date('2024-01-01'),
        Name: 'ASR-SC_1.0_IAM.1',
      });

      const result = await getRunbook(createIamEvent({ runbook_id: 'ASR-SC_1.0_IAM.1' }), createMockContext());
      const body = JSON.parse(result.body);

      expect(result.statusCode).toBe(200);
      expect(body.metadata).toMatchObject({
        runbook_id: 'ASR-SC_1.0_IAM.1',
        control_id: 'IAM.1',
        type: 'builtin',
        status: 'DEPLOYED',
        service_name: 'IAM',
      });
      expect(body.yaml_content).toContain('schemaVersion');
      expect(body.python_script).toBeUndefined();
    });

    it('returns a shared document by name with an empty control_id, not the document name', async () => {
      // ASR-EnableVPCFlowLogs has no <standard>_<version>_<control> segment. The listing omits
      // it (it is not a control runbook); get_runbook still serves it, but control_id must say
      // "no control" rather than repeat the document name as if it were one.
      delete process.env.CUSTOM_RUNBOOK_BUCKET_NAME;
      delete process.env.CUSTOM_RUNBOOK_TABLE_NAME;
      resetApiLambdaEnvironmentCache();

      mockSsmSend.mockResolvedValueOnce({
        Content: 'description: Enable VPC flow logs\nschemaVersion: "0.3"',
        DocumentVersion: '2',
        CreatedDate: new Date('2024-01-01'),
        Name: 'ASR-EnableVPCFlowLogs',
      });

      const result = await getRunbook(createIamEvent({ runbook_id: 'ASR-EnableVPCFlowLogs' }), createMockContext());
      const body = JSON.parse(result.body);

      expect(result.statusCode).toBe(200);
      expect(body.metadata).toMatchObject({
        runbook_id: 'ASR-EnableVPCFlowLogs',
        control_id: '',
        service_name: '',
        type: 'builtin',
      });
    });

    it('should throw NotFoundError for a non-existent non-ASR runbook', async () => {
      await expect(
        getRunbook(createIamEvent({ runbook_id: '00000000-0000-4000-8000-000000000000' }), createMockContext()),
      ).rejects.toThrow('Runbook not found: 00000000-0000-4000-8000-000000000000');
    });

    it('maps a malformed (non-uuid, non-ASR) runbook_id to NotFoundError, not a raw 500', async () => {
      // "foo" passes GetRunbookSchema (.min(1)) but is not a valid RunbookId, so it
      // must surface as a clean 404 rather than a ZodError from RunbookIdSchema.parse.
      await expect(getRunbook(createIamEvent({ runbook_id: 'foo' }), createMockContext())).rejects.toThrow(
        'Runbook not found: foo',
      );
    });

    it('should throw NotFoundError when builtin SSM document has no content', async () => {
      mockSsmSend.mockResolvedValueOnce({ Content: undefined });

      await expect(
        getRunbook(createIamEvent({ runbook_id: 'ASR-SC_1.0_IAM.99' }), createMockContext()),
      ).rejects.toThrow('Built-in runbook not found: ASR-SC_1.0_IAM.99');
    });
  });
});

// --- executeRunbook envelope helper tests ---

import { AwsSecurityFinding } from '@aws-sdk/client-securityhub';

function createMinimalFinding(overrides: Partial<AwsSecurityFinding> = {}): AwsSecurityFinding {
  return {
    SchemaVersion: '2018-10-08',
    Id: 'arn:aws:securityhub:us-east-1:123456789012:security-control/Inspector.1/finding/test-id',
    ProductArn: 'arn:aws:securityhub:us-east-1::product/aws/securityhub',
    GeneratorId: 'security-control/Inspector.1',
    AwsAccountId: '123456789012',
    CreatedAt: '2024-01-01T00:00:00.000Z',
    UpdatedAt: '2024-01-01T00:00:00.000Z',
    Title: 'Inspector.1 finding',
    Description: 'Test finding description',
    Resources: [{ Type: 'AwsEc2Instance', Id: 'arn:aws:ec2:us-east-1:123456789012:instance/i-1234567890abcdef0' }],
    Compliance: { SecurityControlId: 'Inspector.1' },
    ...overrides,
  };
}

describe('buildExecuteRunbookEnvelope', () => {
  it('wraps a finding in the EventBridge Custom Action envelope', () => {
    const finding = createMinimalFinding();

    const envelope = buildExecuteRunbookEnvelope(finding, 'Remediate');

    expect(envelope['detail-type']).toBe('Security Hub Findings - Custom Action');
    expect(envelope.source).toBe('aws.securityhub');
    expect(envelope.detail.actionName).toBe('Remediate');
    expect(envelope.detail.actionDescription).toBe('MCP execute_runbook - Remediate');
    expect(envelope.detail.findings).toEqual([finding]);
  });

  it('uses the supplied action_type verbatim', () => {
    const finding = createMinimalFinding();
    const envelope = buildExecuteRunbookEnvelope(finding, 'RemediateAndGenerateTicket');

    expect(envelope.detail.actionName).toBe('RemediateAndGenerateTicket');
  });
});

describe('executeRunbook account boundary', () => {
  it('rejects a finding outside the caller authorized accounts without starting an execution', async () => {
    const securityHubSend = jest
      .fn()
      .mockResolvedValue({ Findings: [createMinimalFinding({ AwsAccountId: '999999999999' })] });
    const stepFunctionsSend = jest.fn();
    const service = new CustomRunbookExecutionService(
      { warn: jest.fn(), info: jest.fn(), error: jest.fn(), debug: jest.fn() } as never,
      () => ({ send: stepFunctionsSend }) as never,
      () => ({ send: securityHubSend }) as never,
    );

    // Same 404 as an unknown finding — the response must not confirm that a
    // foreign finding exists, nor echo its owning account.
    await expect(service.executeRunbook('finding-1', 'Remediate', ['111111111111'])).rejects.toThrow(
      'Finding not found: finding-1',
    );
    expect(stepFunctionsSend).not.toHaveBeenCalled();
  });

  it('starts the execution for an unscoped admin (authorizedAccounts undefined)', async () => {
    const securityHubSend = jest.fn().mockResolvedValue({ Findings: [createMinimalFinding()] });
    const stepFunctionsSend = jest.fn().mockResolvedValue({ executionArn: 'arn:aws:states:::execution/test' });
    const service = new CustomRunbookExecutionService(
      { warn: jest.fn(), info: jest.fn(), error: jest.fn(), debug: jest.fn() } as never,
      () => ({ send: stepFunctionsSend }) as never,
      () => ({ send: securityHubSend }) as never,
    );

    const result = await service.executeRunbook('finding-1', 'Remediate', undefined);

    expect(result.status).toBe('STARTED');
    expect(stepFunctionsSend).toHaveBeenCalledTimes(1);
  });
});

describe('drift detection', () => {
  beforeEach(() => {
    mockSsmSend.mockReset();
    mockCognitoSend.mockReset();
    mockStsSend.mockReset();
    mockSecurityHubSend.mockReset();
    dynamoMock.reset();
    dynamoMock.resolves({ Items: [], Count: 0 });
    process.env.CUSTOM_RUNBOOK_BUCKET_NAME = 'test-custom-runbook-bucket';
    process.env.CUSTOM_RUNBOOK_TABLE_NAME = 'test-custom-runbook-table';
    // The dev-loop push/execute writes are gated behind this enablement flag.
    process.env.CUSTOM_RUNBOOK_DEV_LOOP_ENABLED = 'true';
    resetApiLambdaEnvironmentCache();

    mockStsSend.mockResolvedValue({
      Credentials: { AccessKeyId: 'ak', SecretAccessKey: 'sk', SessionToken: 'st', Expiration: new Date() },
    });

    mockCognitoSend.mockResolvedValue({
      Username: 'test-admin',
      UserAttributes: [
        { Name: 'email', Value: 'test-admin@example.com' },
        { Name: 'custom:invitedBy', Value: 'system@example.com' },
      ],
      UserCreateDate: new Date(),
      UserStatus: 'CONFIRMED',
      Groups: [{ GroupName: 'AdminGroup' }],
    });
  });

  it('refuses push/execute when the dev-loop is disabled (403)', async () => {
    delete process.env.CUSTOM_RUNBOOK_DEV_LOOP_ENABLED;
    resetApiLambdaEnvironmentCache();

    await expect(
      driftDetection(
        createIamEvent({
          action: 'push',
          control_id: 'S3.9',
          runbook_yaml: 'schemaVersion: "0.3"',
          account_id: '111111111111',
        }),
        createMockContext(),
      ),
    ).rejects.toMatchObject({ statusCode: 403 });

    const createCalls = mockSsmSend.mock.calls.filter(([cmd]) => cmd instanceof CreateDocumentCommand);
    expect(createCalls).toHaveLength(0);
  });

  it('push propagates a throttling error from ListDocuments instead of creating a document', async () => {
    mockSsmSend.mockRejectedValue(Object.assign(new Error('Rate exceeded'), { name: 'ThrottlingException' }));

    await expect(
      driftDetection(
        createIamEvent({
          action: 'push',
          control_id: 'S3.9',
          runbook_yaml: 'schemaVersion: "0.3"',
          account_id: '111111111111',
        }),
        createMockContext(),
      ),
    ).rejects.toThrow('Rate exceeded');

    const createCalls = mockSsmSend.mock.calls.filter(([cmd]) => cmd instanceof CreateDocumentCommand);
    expect(createCalls).toHaveLength(0);
  });

  it('push rejects with truncation error when ListDocuments exceeds MAX_PAGES without exhausting inventory', async () => {
    mockSsmSend.mockImplementation((command) => {
      if (command instanceof ListDocumentsCommand) {
        return Promise.resolve({
          DocumentIdentifiers: [{ Name: 'UnrelatedDoc' }],
          NextToken: 'always-more',
        });
      }
      return Promise.resolve({});
    });

    await expect(
      driftDetection(
        createIamEvent({
          action: 'push',
          control_id: 'S3.9',
          runbook_yaml: 'schemaVersion: "0.3"',
          account_id: '111111111111',
        }),
        createMockContext(),
      ),
    ).rejects.toThrow(/Stopped searching for control S3\.9 after 10 pages/);

    const createCalls = mockSsmSend.mock.calls.filter(([cmd]) => cmd instanceof CreateDocumentCommand);
    expect(createCalls).toHaveLength(0);
  });

  it('resolveDocumentName prefers the ASR-Custom- document over a built-in with the same control suffix', async () => {
    mockSsmSend.mockImplementation((command) => {
      if (command instanceof ListDocumentsCommand) {
        return Promise.resolve({
          DocumentIdentifiers: [{ Name: 'ASR-SC_2.0.0_S3.9' }, { Name: 'ASR-Custom-SC_2.0.0_S3.9' }],
        });
      }
      if (command instanceof DescribeDocumentCommand) {
        return Promise.resolve({ Document: { DocumentVersion: '3' } });
      }
      if (command instanceof UpdateDocumentCommand) {
        return Promise.resolve({ DocumentDescription: { DocumentVersion: '4' } });
      }
      if (command instanceof UpdateDocumentDefaultVersionCommand) {
        return Promise.resolve({});
      }
      return Promise.resolve({});
    });

    const result = await driftDetection(
      createIamEvent({
        action: 'push',
        control_id: 'S3.9',
        runbook_yaml: 'schemaVersion: "0.3"',
        account_id: '111111111111',
      }),
      createMockContext(),
    );

    const body = JSON.parse(result.body);
    expect(body.document_name).toBe('ASR-Custom-SC_2.0.0_S3.9');
  });

  it('execute rejects a finding whose AwsAccountId differs from the target account', async () => {
    mockSecurityHubSend.mockResolvedValue({
      Findings: [{ AwsAccountId: '999999999999', Id: 'finding-1' }],
    });

    await expect(
      driftDetection(
        createIamEvent({
          action: 'execute',
          control_id: 'S3.9',
          account_id: '111111111111',
          finding_id: 'finding-1',
        }),
        createMockContext(),
      ),
      // The message must not echo the finding's true owning account back to the
      // caller — that would disclose foreign account ownership.
    ).rejects.toThrow(/does not belong to the requested account/);
  });

  it('push promotes the current version to default when content is unchanged (DuplicateDocumentContent)', async () => {
    mockSsmSend.mockImplementation((command) => {
      if (command instanceof ListDocumentsCommand) {
        return Promise.resolve({
          DocumentIdentifiers: [{ Name: 'ASR-Custom-SC_2.0.0_S3.9' }],
        });
      }
      if (command instanceof DescribeDocumentCommand) {
        // The second DescribeDocument (after DuplicateDocumentContent) asks for $LATEST
        if (command.input.DocumentVersion === '$LATEST') {
          return Promise.resolve({ Document: { DocumentVersion: '7' } });
        }
        // First DescribeDocument is the existence check
        return Promise.resolve({ Document: { DocumentVersion: '6' } });
      }
      if (command instanceof UpdateDocumentCommand) {
        return Promise.reject(new DuplicateDocumentContent({ message: 'identical', $metadata: {} }));
      }
      if (command instanceof UpdateDocumentDefaultVersionCommand) {
        return Promise.resolve({});
      }
      return Promise.resolve({});
    });

    const result = await driftDetection(
      createIamEvent({
        action: 'push',
        control_id: 'S3.9',
        runbook_yaml: 'schemaVersion: "0.3"',
        account_id: '111111111111',
      }),
      createMockContext(),
    );

    const body = JSON.parse(result.body);
    expect(body.document_version).toBe('7');

    const updateDefaultCalls = mockSsmSend.mock.calls.filter(
      ([cmd]) => cmd instanceof UpdateDocumentDefaultVersionCommand,
    );
    expect(updateDefaultCalls).toHaveLength(1);
    expect(updateDefaultCalls[0][0].input.DocumentVersion).toBe('7');
  });

  it('status maps an unknown execution id to a 404 naming the execution and account', async () => {
    mockSsmSend.mockImplementation((command) => {
      if (command instanceof GetAutomationExecutionCommand) {
        return Promise.reject(
          new AutomationExecutionNotFoundException({ message: 'Automation execution not found', $metadata: {} }),
        );
      }
      return Promise.resolve({});
    });

    // Without the mapping this surfaced as a generic 400 "unexpected error", which a
    // caller could not tell apart from a broken cross-account credential chain.
    await expect(
      driftDetection(
        createIamEvent({
          action: 'status',
          execution_id: 'no-such-execution',
          account_id: '111111111111',
        }),
        createMockContext(),
      ),
    ).rejects.toMatchObject({
      statusCode: 404,
      message: expect.stringContaining('no-such-execution'),
    });
  });
});

// --- pollAutomationExecution: injectable Clock + Sleeper ---

describe('pollAutomationExecution', () => {
  // A fake Sleeper that advances a fake Clock instead of waiting on wall-clock,
  // so the loop's terminal-state and timeout exits run in microseconds.
  function controllableTime() {
    let nowMs = 0;
    return {
      clock: { now: () => new Date(nowMs) },
      sleeper: {
        sleep: async (ms: number) => {
          nowMs += ms;
        },
      },
    };
  }

  it('stops as soon as the execution reaches a terminal state', async () => {
    const send = jest
      .fn()
      .mockResolvedValueOnce({ AutomationExecution: { AutomationExecutionStatus: 'InProgress', StepExecutions: [] } })
      .mockResolvedValueOnce({
        AutomationExecution: {
          AutomationExecutionStatus: 'Success',
          StepExecutions: [{ StepName: 'Remediate', StepStatus: 'Success' }],
        },
      });
    const ssm = { send } as unknown as SSMClient;
    const { clock, sleeper } = controllableTime();

    const result = await pollAutomationExecution(ssm, 'exec-1', { clock, sleeper });

    expect(result.status).toBe('Success');
    expect(send).toHaveBeenCalledTimes(2);
    expect(result.steps).toEqual([{ name: 'Remediate', status: 'Success' }]);
  });

  it('polls until the timeout elapses, then returns the last status', async () => {
    const send = jest
      .fn()
      .mockResolvedValue({ AutomationExecution: { AutomationExecutionStatus: 'InProgress', StepExecutions: [] } });
    const ssm = { send } as unknown as SSMClient;
    const { clock, sleeper } = controllableTime();

    // 6000ms budget, 2000ms interval → sleeps land at 2000/4000/6000; the 6000
    // check fails the while condition, so exactly 3 polls and durationMs === 6000.
    const result = await pollAutomationExecution(ssm, 'exec-1', { timeoutMs: 6000, intervalMs: 2000, clock, sleeper });

    expect(result.status).toBe('InProgress');
    expect(send).toHaveBeenCalledTimes(3);
    expect(result.durationMs).toBe(6000);
  });
});

// A deploy can succeed for the version metadata yet leave some member accounts failed, so it
// used to return 200 — indistinguishable from a clean success in the REST write metrics and the
// MCP tool metrics, which key on the status code. These drive the REAL RunbookDeploymentService
// (mocking only the AWS SDK boundary — STS/IAM/SSM/S3/DynamoDB — per unit-testing.md) and assert
// the handler maps a real partial rollout to 207 + the DeployRunbookPartialFailure EMF metric,
// and a clean/consistent fleet to 200. Per-account outcomes are expressed at the natural seam:
// the member SSM CreateDocument (one account installs, the other throws).
describe('deployRunbook partial-failure signalling', () => {
  const ACCOUNT_A = '111111111111';
  const ACCOUNT_B = '222222222222';
  const RUNBOOK_ID = 'a3f9c1e2-0000-4000-8000-000000000001';
  const YAML = 'schemaVersion: "0.3"';
  const YAML_DIGEST = createHash('sha256').update(YAML, 'utf8').digest('hex');
  const NOW = '2026-01-01T00:00:00.000Z';
  const ADMIN_DOC_VERSION = '4';

  let stdoutSpy: jest.SpyInstance;
  let repository: CustomRunbookRepository;

  function deployEvent(memberAccountIds: string[]) {
    return createIamEvent({
      action: 'deploy',
      runbook_id: RUNBOOK_ID,
      control_id: 'S3.9',
      security_standard: 'SC',
      standard_version: '2.0.0',
      required_iam_actions: ['s3:PutBucketLogging'],
      member_account_ids: memberAccountIds,
    });
  }

  // A registered version that already passed the test-before-deploy gate: the test outcome is
  // bound to the registered content digest and the exact requested IAM action set, so execute()
  // proceeds to the member rollout instead of rejecting at the gate. `deployedAccounts` seeds the
  // prior fleet state the version-consistency report is computed against.
  function metadata(deployedAccounts?: Record<string, MemberDeploymentState>): RunbookMetadata {
    return {
      runbookId: RUNBOOK_ID as RunbookId,
      version: 2,
      controlId: 'S3.9',
      serviceName: 'S3',
      description: 'test',
      remediationAction: 'test',
      status: 'DRAFT',
      s3Key: 'runbooks/rb-1/v2/runbook.yaml',
      createdBy: 'test',
      createdAt: NOW,
      deployedAccounts,
      testStatus: 'PASSED',
      testedAt: NOW,
      registeredContentDigest: YAML_DIGEST,
      testedContentDigest: YAML_DIGEST,
      testedIamActions: ['s3:PutBucketLogging'],
    } as RunbookMetadata;
  }

  // Writes the gate-passing version record to the real custom-runbook table so the handler's
  // repository resolves it via its actual QueryCommand (partition key + ScanIndexForward),
  // rather than a stubbed return.
  async function seedRunbook(deployedAccounts?: Record<string, MemberDeploymentState>): Promise<void> {
    await repository.put(metadata(deployedAccounts));
  }

  function yamlBody(): GetObjectCommandOutput['Body'] {
    return { transformToString: () => Promise.resolve(YAML) } as unknown as GetObjectCommandOutput['Body'];
  }

  // The EMF documents emitMetric writes to stdout during the call.
  function emittedMetricNames(): string[] {
    return stdoutSpy.mock.calls
      .map((call) => {
        try {
          return JSON.parse((call[0] as string).trim());
        } catch {
          return undefined;
        }
      })
      .filter((doc): doc is { _aws?: { CloudWatchMetrics: { Namespace: string; Metrics: { Name: string }[] }[] } } =>
        Boolean(doc && doc._aws),
      )
      .flatMap((doc) => doc._aws!.CloudWatchMetrics.flatMap((directive) => directive.Metrics.map((m) => m.Name)));
  }

  // Routes the shared SSM mock through the deploy flow: built-in preflight misses (no control
  // remap, no existing ASR-* documents), admin-account CreateDocument (no Tags) returns the admin
  // version, and each member-account CreateDocument (carries Tags) is decided by `memberCreate`.
  function setupSsmMock(memberCreate: (callIndex: number) => { DocumentDescription: { DocumentVersion: string } }) {
    let memberCreateCount = 0;
    mockSsmSend.mockImplementation((command) => {
      if (command instanceof GetParameterCommand) {
        return Promise.reject(new ParameterNotFound({ message: 'not found', $metadata: {} }));
      }
      if (command instanceof ListDocumentsCommand) {
        return Promise.resolve({ DocumentIdentifiers: [] });
      }
      if (command instanceof UpdateDocumentDefaultVersionCommand) {
        return Promise.resolve({});
      }
      if (command instanceof CreateDocumentCommand) {
        if (!command.input.Tags) {
          return Promise.resolve({ DocumentDescription: { DocumentVersion: ADMIN_DOC_VERSION } });
        }
        memberCreateCount += 1;
        return Promise.resolve(memberCreate(memberCreateCount));
      }
      return Promise.resolve({});
    });
  }

  // The deploy path reads and writes the custom-runbook table through the repository, so this
  // suite runs it against DynamoDB Local (per unit-testing.md / ADR 0003 — the DynamoDB client is
  // not an accepted mock boundary) and seeds the version record through the repository. The
  // module-level mockClient(DynamoDBDocumentClient) is restored for this (final) describe so the
  // service's createDynamoDBClient() reaches the real local endpoint. Only the true AWS SDK
  // boundaries (STS/IAM/SSM/S3) stay mocked.
  beforeAll(async () => {
    dynamoMock.restore();
    await DynamoDBTestSetup.initialize();
    await DynamoDBTestSetup.createCustomRunbookTable(customRunbookTableName);
    repository = new CustomRunbookRepository(customRunbookTableName, createDynamoDBClient());
  });

  afterAll(async () => {
    await DynamoDBTestSetup.deleteTable(customRunbookTableName);
    await DynamoDBTestSetup.cleanup();
  });

  beforeEach(async () => {
    mockSsmSend.mockReset();
    mockStsSend.mockReset();
    mockIamSend.mockReset();
    s3Mock.reset();
    await DynamoDBTestSetup.clearTable(customRunbookTableName, 'customRunbook');

    process.env.CUSTOM_RUNBOOK_BUCKET_NAME = 'test-custom-runbook-bucket';
    process.env.CUSTOM_RUNBOOK_TABLE_NAME = customRunbookTableName;
    resetApiLambdaEnvironmentCache();

    mockCognitoSend.mockResolvedValue({
      Username: 'test-admin',
      UserAttributes: [
        { Name: 'email', Value: 'test-admin@example.com' },
        { Name: 'custom:invitedBy', Value: 'system@example.com' },
      ],
      UserCreateDate: new Date(),
      UserStatus: 'CONFIRMED',
      Groups: [{ GroupName: 'AdminGroup' }],
    });

    // Cross-account chain: every admin/member hop assumes successfully.
    mockStsSend.mockResolvedValue({
      Credentials: { AccessKeyId: 'ak', SecretAccessKey: 'sk', SessionToken: 'st', Expiration: new Date() },
    });

    // Remediation role does not exist yet → CreateRole path succeeds in every account.
    mockIamSend.mockImplementation((command) => {
      if (command instanceof GetRoleCommand) {
        return Promise.reject(new NoSuchEntityException({ message: 'not found', $metadata: {} }));
      }
      if (
        command instanceof CreateRoleCommand ||
        command instanceof PutRolePolicyCommand ||
        command instanceof TagRoleCommand
      ) {
        return Promise.resolve({});
      }
      return Promise.resolve({});
    });

    s3Mock.on(GetObjectCommand).resolves({ Body: yamlBody() });

    stdoutSpy = jest.spyOn(process.stdout, 'write').mockImplementation(() => true);
  });

  afterEach(() => {
    stdoutSpy?.mockRestore();
  });

  it('returns 207 and emits a partial-failure metric when a member account install failed', async () => {
    // Both accounts previously ran v1 and are PENDING the v2 release.
    await seedRunbook({
      [ACCOUNT_A]: { runbookVersion: 1, ssmDocumentVersion: '1', status: 'PENDING', attemptedAt: NOW },
      [ACCOUNT_B]: { runbookVersion: 1, ssmDocumentVersion: '1', status: 'PENDING', attemptedAt: NOW },
    });
    // ACCOUNT_A installs the member document; ACCOUNT_B's install throws, so the real service
    // reports it under document_deployment.failed and the released version is not fleet-wide.
    setupSsmMock((callIndex) => {
      if (callIndex === 1) return { DocumentDescription: { DocumentVersion: '7' } };
      throw new Error('AccessDenied installing document');
    });

    const response = await deployRunbook(deployEvent([ACCOUNT_A, ACCOUNT_B]), createMockContext());

    expect(response.statusCode).toBe(207);
    // The failing account is in the body so the caller can act on it...
    const body = JSON.parse(response.body);
    expect(body.document_deployment.failed).toEqual([
      { accountId: ACCOUNT_B, error: 'AccessDenied installing document' },
    ]);
    // ...and the partial is observable in metrics independently of the status code.
    expect(emittedMetricNames()).toContain(DEPLOY_RUNBOOK_PARTIAL_FAILURE_METRIC);
  });

  it('returns 200 and emits no partial-failure metric when every named account installs cleanly', async () => {
    // Only the account named in the deploy was previously known, and its install succeeds, so the
    // fleet is consistent on the target version.
    await seedRunbook({
      [ACCOUNT_A]: { runbookVersion: 1, ssmDocumentVersion: '1', status: 'PENDING', attemptedAt: NOW },
    });
    setupSsmMock(() => ({ DocumentDescription: { DocumentVersion: '7' } }));

    const response = await deployRunbook(deployEvent([ACCOUNT_A]), createMockContext());

    expect(response.statusCode).toBe(200);
    expect(JSON.parse(response.body).version_consistency.consistent).toBe(true);
    expect(emittedMetricNames()).not.toContain(DEPLOY_RUNBOOK_PARTIAL_FAILURE_METRIC);
  });

  it('treats an account still pending release as a backlog, not a failure (stays 200)', async () => {
    // ACCOUNT_B stays on v1 (never named in this deploy) → accounts_pending_release, which is a
    // backlog item rather than a failed rollout. ACCOUNT_A installs cleanly, so no account failed.
    await seedRunbook({
      [ACCOUNT_A]: { runbookVersion: 1, ssmDocumentVersion: '1', status: 'PENDING', attemptedAt: NOW },
      [ACCOUNT_B]: { runbookVersion: 1, ssmDocumentVersion: '1', status: 'PENDING', attemptedAt: NOW },
    });
    setupSsmMock(() => ({ DocumentDescription: { DocumentVersion: '7' } }));

    const response = await deployRunbook(deployEvent([ACCOUNT_A]), createMockContext());

    expect(response.statusCode).toBe(200);
    const body = JSON.parse(response.body);
    expect(body.version_consistency.consistent).toBe(false);
    expect(body.version_consistency.accounts_pending_release).toEqual([{ accountId: ACCOUNT_B, runbookVersion: 1 }]);
    expect(body.version_consistency.accounts_failed).toEqual([]);
    expect(emittedMetricNames()).not.toContain(DEPLOY_RUNBOOK_PARTIAL_FAILURE_METRIC);
  });
});
