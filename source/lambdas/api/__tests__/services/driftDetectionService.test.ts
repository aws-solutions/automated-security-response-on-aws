// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { SECURITY_CONTROL_STANDARD_VERSION } from '@asr/data-models';
import { Logger } from '@aws-lambda-powertools/logger';
import { AwsSecurityFinding, GetFindingsCommand, SecurityHubClient } from '@aws-sdk/client-securityhub';
import {
  CreateDocumentCommand,
  DescribeDocumentCommand,
  DuplicateDocumentContent,
  GetAutomationExecutionCommand,
  InvalidDocument,
  ListDocumentsCommand,
  SSMClient,
  StartAutomationExecutionCommand,
  UpdateDocumentCommand,
  UpdateDocumentDefaultVersionCommand,
} from '@aws-sdk/client-ssm';
import { AssumeRoleCommand, STSClient } from '@aws-sdk/client-sts';
import { mockClient } from 'aws-sdk-client-mock';
import { resetApiLambdaEnvironmentCache } from '../../apiLambdaEnvironment';
import { NotFoundError } from '../../../common/utils/httpErrors';
import { DriftDetectionService } from '../../services/driftDetectionService';
import { MemberAccountCredentialsProvider } from '../../services/memberAccountCredentials';

const ACCOUNT = '123456789012';
const CONTROL_ID = 'S3.1';
const FINDING_ID = 'arn:aws:securityhub:us-east-1:123456789012:finding/abc';
const CUSTOM_DOCUMENT = `ASR-Custom-SC_2.0.0_${CONTROL_ID}`;
const RUNBOOK_YAML = 'schemaVersion: "0.3"\nmainSteps: []\n';

const ssmMock = mockClient(SSMClient);
const stsMock = mockClient(STSClient);
const securityHubMock = mockClient(SecurityHubClient);

const sdkError = <T extends Error>(ErrorClass: new (init: { message: string; $metadata: object }) => T): T =>
  new ErrorClass({ message: 'test', $metadata: {} });

const securityFinding = (overrides: Partial<AwsSecurityFinding> = {}): AwsSecurityFinding => ({
  SchemaVersion: '2018-10-08',
  Id: FINDING_ID,
  ProductArn: 'arn:aws:securityhub:us-east-1::product/aws/securityhub',
  GeneratorId: 'security-control/S3.1',
  AwsAccountId: ACCOUNT,
  CreatedAt: '2026-01-01T00:00:00Z',
  UpdatedAt: '2026-01-01T00:00:00Z',
  Title: 'S3 bucket allows public access',
  Description: 'Test finding',
  Resources: [{ Type: 'AwsS3Bucket', Id: 'arn:aws:s3:::test-bucket' }],
  ...overrides,
});

describe('DriftDetectionService', () => {
  const logger = new Logger({ serviceName: 'test', logLevel: 'SILENT' });
  let service: DriftDetectionService;
  let nowMs: number;

  const listDocuments = (...names: string[]) =>
    ssmMock.on(ListDocumentsCommand).resolves({ DocumentIdentifiers: names.map((Name) => ({ Name })) });

  beforeEach(() => {
    ssmMock.reset();
    stsMock.reset();
    securityHubMock.reset();
    process.env.CUSTOM_RUNBOOK_DEV_LOOP_ENABLED = 'true';
    resetApiLambdaEnvironmentCache();
    stsMock.on(AssumeRoleCommand).resolves({
      Credentials: {
        AccessKeyId: 'AKIATEST',
        SecretAccessKey: 'secret',
        SessionToken: 'token',
        Expiration: new Date(),
      },
    });
    nowMs = 0;
    service = new DriftDetectionService(
      logger,
      new MemberAccountCredentialsProvider(() => new STSClient({})),
      () => new SecurityHubClient({}),
      { now: () => new Date(nowMs) },
      {
        sleep: async (ms: number) => {
          nowMs += ms;
        },
      },
    );
  });

  afterEach(() => {
    delete process.env.CUSTOM_RUNBOOK_DEV_LOOP_ENABLED;
    resetApiLambdaEnvironmentCache();
  });

  describe('push', () => {
    it('reports version 1 when SSM does not return a version for a new document', async () => {
      listDocuments();
      ssmMock.on(DescribeDocumentCommand).rejects(sdkError(InvalidDocument));
      ssmMock.on(CreateDocumentCommand).resolves({});

      const result = await service.push(CONTROL_ID, RUNBOOK_YAML, ACCOUNT);

      expect(result.document_version).toBe('1');
    });

    it('falls back to version 1 when neither the update nor the lookup names a version', async () => {
      listDocuments(CUSTOM_DOCUMENT);
      ssmMock.on(DescribeDocumentCommand).resolves({});
      ssmMock.on(UpdateDocumentCommand).resolves({});
      ssmMock.on(UpdateDocumentDefaultVersionCommand).resolves({});

      const withoutUpdateVersion = await service.push(CONTROL_ID, RUNBOOK_YAML, ACCOUNT);

      ssmMock.on(UpdateDocumentCommand).rejects(sdkError(DuplicateDocumentContent));
      const withoutDescribeVersion = await service.push(CONTROL_ID, RUNBOOK_YAML, ACCOUNT);

      expect(withoutUpdateVersion.document_version).toBe('1');
      expect(withoutDescribeVersion.document_version).toBe('1');
    });

    it('passes on any other update error instead of treating it as identical content', async () => {
      listDocuments(CUSTOM_DOCUMENT);
      ssmMock.on(DescribeDocumentCommand).resolves({});
      ssmMock.on(UpdateDocumentCommand).rejects(new Error('AccessDenied'));

      await expect(service.push(CONTROL_ID, RUNBOOK_YAML, ACCOUNT)).rejects.toThrow('AccessDenied');
      expect(ssmMock.commandCalls(UpdateDocumentDefaultVersionCommand)).toHaveLength(0);
    });

    it('passes on a lookup error that does not mean the document is missing', async () => {
      listDocuments(CUSTOM_DOCUMENT);
      ssmMock.on(DescribeDocumentCommand).rejects(new Error('Throttling'));

      await expect(service.push(CONTROL_ID, RUNBOOK_YAML, ACCOUNT)).rejects.toThrow('Throttling');
      expect(ssmMock.commandCalls(CreateDocumentCommand)).toHaveLength(0);
    });

    it('creates the document under the standard custom name when none exists yet', async () => {
      listDocuments();
      ssmMock.on(DescribeDocumentCommand).rejects(sdkError(InvalidDocument));
      ssmMock.on(CreateDocumentCommand).resolves({ DocumentDescription: { DocumentVersion: '1' } });

      const result = await service.push(CONTROL_ID, RUNBOOK_YAML, ACCOUNT);

      expect(result).toMatchObject({
        document_name: `ASR-Custom-SC_${SECURITY_CONTROL_STANDARD_VERSION}_${CONTROL_ID}`,
        document_version: '1',
        document_status: 'created',
      });
      expect(ssmMock.commandCalls(CreateDocumentCommand)[0].args[0].input).toEqual({
        Name: `ASR-Custom-SC_${SECURITY_CONTROL_STANDARD_VERSION}_${CONTROL_ID}`,
        Content: RUNBOOK_YAML,
        DocumentType: 'Automation',
        DocumentFormat: 'YAML',
      });
    });
  });

  describe('execute', () => {
    const stubFinding = (finding: AwsSecurityFinding | undefined) =>
      securityHubMock.on(GetFindingsCommand).resolves({ Findings: finding ? [finding] : [] });

    const stubExecution = (executionStatus: string = 'Success') => {
      ssmMock.on(StartAutomationExecutionCommand).resolves({ AutomationExecutionId: 'exec-1' });
      ssmMock.on(GetAutomationExecutionCommand).resolves({
        AutomationExecution: {
          AutomationExecutionStatus: executionStatus as 'Success',
          StepExecutions: [
            { StepName: 'Step1', StepStatus: 'Success' },
            { StepStatus: 'Failed', FailureMessage: 'boom' },
          ],
        },
      });
    };

    it('uses the standard role name when the document name does not carry a standard and version', async () => {
      stubFinding(securityFinding());
      listDocuments(`ASR-Custom-SC_${CONTROL_ID}`);
      stubExecution();

      await service.execute(CONTROL_ID, ACCOUNT, FINDING_ID);

      const started = ssmMock.commandCalls(StartAutomationExecutionCommand)[0].args[0].input;
      expect(started.Parameters?.AutomationAssumeRole).toEqual([
        `arn:aws:iam::${ACCOUNT}:role/SO0111-Remediate-SC-${SECURITY_CONTROL_STANDARD_VERSION}-${CONTROL_ID}`,
      ]);
    });

    it('reports an unknown finding as not found, before touching the member account', async () => {
      stubFinding(undefined);

      await expect(service.execute(CONTROL_ID, ACCOUNT, FINDING_ID)).rejects.toThrow(NotFoundError);
      expect(stsMock.commandCalls(AssumeRoleCommand)).toHaveLength(0);
    });

    it('fails when SSM does not return an execution id', async () => {
      stubFinding(securityFinding());
      listDocuments(CUSTOM_DOCUMENT);
      ssmMock.on(StartAutomationExecutionCommand).resolves({});

      await expect(service.execute(CONTROL_ID, ACCOUNT, FINDING_ID)).rejects.toThrow(
        'SSM StartAutomationExecution returned no execution ID',
      );
    });

    it('runs the custom document against the finding with the matching remediation role', async () => {
      stubFinding(securityFinding());
      listDocuments(CUSTOM_DOCUMENT);
      stubExecution();

      const result = await service.execute(CONTROL_ID, ACCOUNT, FINDING_ID, 'alice');

      expect(result).toEqual({
        action: 'execute',
        execution_id: 'exec-1',
        status: 'Success',
        duration_ms: 2000,
        steps: [
          { name: 'Step1', status: 'Success', error: undefined },
          { name: '', status: 'Failed', error: 'boom' },
        ],
      });
      const started = ssmMock.commandCalls(StartAutomationExecutionCommand)[0].args[0].input;
      expect(started.DocumentName).toBe(CUSTOM_DOCUMENT);
      expect(started.Parameters).toEqual({
        AutomationAssumeRole: [`arn:aws:iam::${ACCOUNT}:role/SO0111-Remediate-Custom-SC-2.0.0-S3.1`],
        Finding: [JSON.stringify(securityFinding())],
      });
    });

    it('requires a custom document to be deployed for the control', async () => {
      stubFinding(securityFinding());
      listDocuments();

      await expect(service.execute(CONTROL_ID, ACCOUNT, FINDING_ID)).rejects.toThrow(
        /No custom SSM Automation document found for control S3\.1/,
      );
      expect(ssmMock.commandCalls(StartAutomationExecutionCommand)).toHaveLength(0);
    });
  });

  describe('status', () => {
    it('reports the execution status, its steps and its outputs', async () => {
      ssmMock.on(GetAutomationExecutionCommand).resolves({
        AutomationExecution: {
          AutomationExecutionStatus: 'Success',
          StepExecutions: [{ StepName: 'Step1', StepStatus: 'Success' }],
          Outputs: { 'Step1.Result': ['ok'] },
        },
      });

      const result = await service.status('exec-1', ACCOUNT);

      expect(result).toEqual({
        action: 'status',
        execution_id: 'exec-1',
        status: 'Success',
        steps: [{ name: 'Step1', status: 'Success', error: undefined }],
        outputs: { 'Step1.Result': ['ok'] },
      });
    });

    it('reports Unknown with no steps when SSM returns no execution', async () => {
      ssmMock.on(GetAutomationExecutionCommand).resolves({});

      const result = await service.status('exec-1', ACCOUNT);

      expect(result).toMatchObject({ status: 'Unknown', steps: [], outputs: undefined });
    });

    it('passes on any other error', async () => {
      ssmMock.on(GetAutomationExecutionCommand).rejects(new Error('AccessDenied'));

      await expect(service.status('exec-1', ACCOUNT)).rejects.toThrow('AccessDenied');
    });

    it('does not need the dev loop to be enabled, because it only reads', async () => {
      delete process.env.CUSTOM_RUNBOOK_DEV_LOOP_ENABLED;
      resetApiLambdaEnvironmentCache();
      ssmMock
        .on(GetAutomationExecutionCommand)
        .resolves({ AutomationExecution: { AutomationExecutionStatus: 'Failed' } });

      const result = await service.status('exec-1', ACCOUNT);

      expect(result.status).toBe('Failed');
    });
  });
});
