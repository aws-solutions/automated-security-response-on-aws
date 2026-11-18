// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { RunbookId, RunbookMetadata } from '@asr/data-models';
import { Logger } from '@aws-lambda-powertools/logger';
import { GetObjectCommand, S3Client } from '@aws-sdk/client-s3';
import {
  DocumentIdentifier,
  GetDocumentCommand,
  InvalidDocument,
  ListDocumentsCommand,
  SSMClient,
} from '@aws-sdk/client-ssm';
import { sdkStreamMixin } from '@smithy/util-stream';
import { mockClient } from 'aws-sdk-client-mock';
import { Readable } from 'node:stream';
import { DynamoDBTestSetup } from '../../../common/__tests__/dynamodbSetup';
import { customRunbookTableName } from '../../../common/__tests__/envSetup';
import { CustomRunbookRepository } from '../../../common/repositories/customRunbookRepository';
import { resetApiLambdaEnvironmentCache } from '../../apiLambdaEnvironment';
import { CustomRunbookQueryService } from '../../services/customRunbookQueryService';

const BUCKET = 'test-custom-runbook-bucket';
const RUNBOOK_A = '123e4567-e89b-42d3-a456-426614174001' as RunbookId;
const RUNBOOK_B = '123e4567-e89b-42d3-a456-426614174002' as RunbookId;

const ssmMock = mockClient(SSMClient);
const s3Mock = mockClient(S3Client);

const body = (content: string) => sdkStreamMixin(Readable.from([content]));

const runbook = (runbookId: RunbookId, version: number, overrides: Partial<RunbookMetadata> = {}): RunbookMetadata => ({
  runbookId,
  version,
  controlId: 'S3.9',
  serviceName: 'S3',
  description: `runbook ${runbookId} v${version}`,
  remediationAction: 'test',
  status: 'DRAFT',
  s3Key: `runbooks/${runbookId}/v${version}/runbook.yaml`,
  createdBy: 'test',
  createdAt: '2026-01-01T00:00:00Z',
  ...overrides,
});

describe('CustomRunbookQueryService', () => {
  const logger = new Logger({ serviceName: 'test', logLevel: 'SILENT' });
  let service: CustomRunbookQueryService;
  let repository: CustomRunbookRepository;

  const documents = (...docs: DocumentIdentifier[]) =>
    ssmMock.on(ListDocumentsCommand).resolves({ DocumentIdentifiers: docs });

  const configureCustomRunbooks = () => {
    process.env.CUSTOM_RUNBOOK_BUCKET_NAME = BUCKET;
    process.env.CUSTOM_RUNBOOK_TABLE_NAME = customRunbookTableName;
    resetApiLambdaEnvironmentCache();
  };

  beforeAll(async () => {
    await DynamoDBTestSetup.initialize();
    await DynamoDBTestSetup.createCustomRunbookTable(customRunbookTableName);
    repository = new CustomRunbookRepository(customRunbookTableName, DynamoDBTestSetup.getDocClient());
  });

  afterAll(async () => {
    await DynamoDBTestSetup.deleteTable(customRunbookTableName);
    delete process.env.CUSTOM_RUNBOOK_BUCKET_NAME;
    delete process.env.CUSTOM_RUNBOOK_TABLE_NAME;
    resetApiLambdaEnvironmentCache();
  });

  beforeEach(async () => {
    ssmMock.reset();
    s3Mock.reset();
    await DynamoDBTestSetup.clearTable(customRunbookTableName, 'customRunbook');
    configureCustomRunbooks();
    service = new CustomRunbookQueryService(
      logger,
      () => new SSMClient({}),
      () => new S3Client({}),
    );
  });

  describe('listRunbooks', () => {
    // The handler tests (customRunbooks.test.ts) already cover which documents are listed, skipped and
    // filtered. This covers only what they leave out: documents for which SSM returns very little.
    it('fills in the version, description and creation date that SSM leaves out, and skips a document with no name', async () => {
      documents({ Name: 'ASR-AFSBP_1.0.0_IAM.7' }, {});

      const result = await service.listRunbooks({ type: 'builtin' });

      expect(result.runbooks).toEqual([
        {
          runbook_id: 'ASR-AFSBP_1.0.0_IAM.7',
          control_id: 'IAM.7',
          type: 'builtin',
          status: 'DEPLOYED',
          version: 1,
          description: 'ASR-AFSBP_1.0.0_IAM.7',
          service_name: 'IAM',
          created_at: '',
          ssm_document_name: 'ASR-AFSBP_1.0.0_IAM.7',
        },
      ]);
    });

    it('stops at the page cap and logs that the listing is truncated', async () => {
      ssmMock
        .on(ListDocumentsCommand)
        .resolves({ DocumentIdentifiers: [{ Name: 'ASR-SC_2.0.0_S3.1' }], NextToken: 'more' });
      const warn = jest.spyOn(logger, 'warn');

      const result = await service.listRunbooks({ type: 'builtin' });

      expect(ssmMock.commandCalls(ListDocumentsCommand)).toHaveLength(20);
      expect(result.runbooks).toHaveLength(20);
      expect(warn).toHaveBeenCalledWith('Truncating built-in runbook listing after reaching the page cap', {
        MAX_PAGES: 20,
      });
      warn.mockRestore();
    });

    it('filters custom runbooks by control', async () => {
      await repository.createVersion(runbook(RUNBOOK_A, 1));
      await repository.createVersion(runbook(RUNBOOK_B, 1, { controlId: 'IAM.7', serviceName: 'IAM' }));

      const result = await service.listRunbooks({ type: 'custom', control_id: 'IAM.7' });

      expect(result.runbooks.map((r) => r.runbook_id)).toEqual([RUNBOOK_B]);
    });
  });

  describe('getRunbook', () => {
    describe('built-in runbooks', () => {
      it('fills in the version and creation date that SSM leaves out', async () => {
        ssmMock.on(GetDocumentCommand).resolves({ Content: 'schemaVersion: "0.3"' });

        const result = await service.getRunbook('ASR-SC_2.0.0_S3.1');

        expect(result.metadata).toMatchObject({ control_id: 'S3.1', version: 1, created_at: '' });
      });

      it('reports a document SSM does not know as not found', async () => {
        ssmMock.on(GetDocumentCommand).rejects(new InvalidDocument({ message: 'nope', $metadata: {} }));

        await expect(service.getRunbook('ASR-SC_2.0.0_S3.1')).rejects.toThrow(
          'Built-in runbook not found: ASR-SC_2.0.0_S3.1',
        );
      });

      it('passes on any other SSM error', async () => {
        ssmMock.on(GetDocumentCommand).rejects(new Error('AccessDenied'));

        await expect(service.getRunbook('ASR-SC_2.0.0_S3.1')).rejects.toThrow('AccessDenied');
      });
    });

    describe('custom runbooks', () => {
      it('returns the latest version with its YAML', async () => {
        await repository.createVersion(runbook(RUNBOOK_A, 1));
        await repository.createVersion(runbook(RUNBOOK_A, 2, { status: 'DEPLOYED', ssmDocumentName: 'ASR-Custom-X' }));
        s3Mock.on(GetObjectCommand).resolves({ Body: body('yaml: v2') });

        const result = await service.getRunbook(RUNBOOK_A);

        expect(result.yaml_content).toBe('yaml: v2');
        expect(result.python_script).toBeUndefined();
        expect(result.metadata).toMatchObject({
          runbook_id: RUNBOOK_A,
          version: 2,
          type: 'custom',
          status: 'DEPLOYED',
          ssm_document_name: 'ASR-Custom-X',
        });
        expect(s3Mock.commandCalls(GetObjectCommand)).toHaveLength(1);
        expect(s3Mock.commandCalls(GetObjectCommand)[0].args[0].input).toEqual({
          Bucket: BUCKET,
          Key: `runbooks/${RUNBOOK_A}/v2/runbook.yaml`,
        });
      });

      it('returns empty content when S3 returns no body', async () => {
        await repository.createVersion(runbook(RUNBOOK_A, 1, { scriptS3Key: `runbooks/${RUNBOOK_A}/v1/script.py` }));
        s3Mock.on(GetObjectCommand).resolves({});

        const result = await service.getRunbook(RUNBOOK_A);

        expect(result.yaml_content).toBe('');
        expect(result.python_script).toBeUndefined();
      });

      it('also returns the python script when the runbook has one', async () => {
        await repository.createVersion(runbook(RUNBOOK_A, 1, { scriptS3Key: `runbooks/${RUNBOOK_A}/v1/script.py` }));
        s3Mock
          .on(GetObjectCommand, { Key: `runbooks/${RUNBOOK_A}/v1/runbook.yaml` })
          .resolves({ Body: body('yaml: v1') })
          .on(GetObjectCommand, { Key: `runbooks/${RUNBOOK_A}/v1/script.py` })
          .resolves({ Body: body('print("hi")') });

        const result = await service.getRunbook(RUNBOOK_A);

        expect(result.yaml_content).toBe('yaml: v1');
        expect(result.python_script).toBe('print("hi")');
      });
    });
  });
});
