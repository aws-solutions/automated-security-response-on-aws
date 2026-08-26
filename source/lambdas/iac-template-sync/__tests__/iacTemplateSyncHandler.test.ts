// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

const mockLogger = {
  info: jest.fn(),
  debug: jest.fn(),
  warn: jest.fn(),
  error: jest.fn(),
  injectLambdaContext: () => (_target: unknown, _propertyName: string, descriptor: PropertyDescriptor) => descriptor,
};

jest.mock('../../common/utils/logger', () => ({
  getLogger: jest.fn(() => mockLogger),
}));

global.fetch = jest.fn();

const mockTracer = {
  captureLambdaHandler: () => (_target: unknown, _propertyName: string, descriptor: PropertyDescriptor) => descriptor,
  captureAWSv3Client: jest.fn((client: unknown) => client),
};

jest.mock('../../common/utils/tracer', () => ({
  getTracer: jest.fn(() => mockTracer),
}));

import { CloudFormationCustomResourceEvent, Context } from 'aws-lambda';
import { mockClient } from 'aws-sdk-client-mock';
import {
  CopyObjectCommand,
  DeleteObjectCommand,
  GetObjectCommand,
  GetObjectCommandOutput,
  PutObjectCommand,
  S3Client,
} from '@aws-sdk/client-s3';
import { createHash } from 'crypto';
import * as fc from 'fast-check';
import { IaCTemplateSyncHandler } from '../iacTemplateSyncHandler';
import { diffManifests } from '../manifestDiff';
import { Manifest, TemplateEntry } from '../types';

const s3Mock = mockClient(S3Client);

const mockContext: Context = {
  callbackWaitsForEmptyEventLoop: false,
  functionName: 'test-function',
  functionVersion: '1',
  invokedFunctionArn: 'arn:aws:lambda:us-east-1:123456789012:function:test-function',
  memoryLimitInMB: '128',
  awsRequestId: 'test-aws-request-id',
  logGroupName: '/aws/lambda/test-function',
  logStreamName: '2023/01/01/[$LATEST]test-stream',
  getRemainingTimeInMillis: () => 30000,
  done: jest.fn(),
  fail: jest.fn(),
  succeed: jest.fn(),
};

const solutionsBucket = 'solutions-bucket-us-east-1';
const customerBucket = 'asr-iac-templates-ns-us-east-1-123456789012';
const manifestKey = 'automated-security-response-on-aws/v4.0.0/iac-templates/.metadata/manifest.json';
const templatePrefix = 'automated-security-response-on-aws/v4.0.0/iac-templates/';
const solutionVersion = 'v4.0.0';

function createEvent(requestType: 'Create' | 'Update' | 'Delete'): CloudFormationCustomResourceEvent {
  const baseEvent = {
    RequestType: requestType,
    ResponseURL: 'https://cloudformation-custom-resource-response-useast1.s3.amazonaws.com/test',
    StackId: 'arn:aws:cloudformation:us-east-1:123456789012:stack/test-stack/12345',
    RequestId: 'test-request-id',
    ResourceType: 'Custom::IaCTemplateSync',
    LogicalResourceId: 'IaCTemplateSync',
    ServiceToken: 'arn:aws:lambda:us-east-1:123456789012:function:test-provider',
    ResourceProperties: {
      ServiceToken: 'arn:aws:lambda:us-east-1:123456789012:function:test-provider',
      SolutionsBucketName: solutionsBucket,
      CustomerBucketName: customerBucket,
      ManifestKey: manifestKey,
      SolutionVersion: solutionVersion,
      TemplatePrefix: templatePrefix,
    },
  };

  if (requestType === 'Update' || requestType === 'Delete') {
    return {
      ...baseEvent,
      PhysicalResourceId: 'IaCTemplateSync',
    } as CloudFormationCustomResourceEvent;
  }

  return baseEvent as CloudFormationCustomResourceEvent;
}

/**
 * Creates a partial GetObjectCommandOutput with a Body that supports
 * transformToString(). Cast to GetObjectCommandOutput['Body'] because
 * the real SDK type (SdkStream<IncomingMessage>) is not constructible
 * in unit tests — this is the minimal subset the handler uses.
 */
function s3BodyFrom(content: string): GetObjectCommandOutput['Body'] {
  return {
    transformToString: async () => content,
  } as GetObjectCommandOutput['Body'];
}

const twoTemplateManifest: Manifest = {
  schemaVersion: '1.0',
  generatedAt: '2025-01-15T00:00:00.000Z',
  solutionVersion: 'v4.0.0',
  templates: [
    {
      controlId: 'S3.1',
      iacFormat: 'cloudformation',
      s3Key: 'S3.1/cloudformation/S3.1.yaml',
      sha256: 'abc123',
    },
    {
      controlId: 'IAM.1',
      iacFormat: 'terraform',
      s3Key: 'IAM.1/terraform/IAM.1.tf',
      sha256: 'def456',
    },
  ],
};

function parseCfnResponseBody(fetchMock: jest.Mock): Record<string, unknown> {
  const call = fetchMock.mock.calls[0];
  return JSON.parse(String(call[1].body));
}

describe('IaCTemplateSyncHandler', () => {
  let handler: IaCTemplateSyncHandler;

  beforeEach(() => {
    jest.clearAllMocks();
    s3Mock.reset();
    (global.fetch as jest.Mock).mockResolvedValue({ status: 200, statusText: 'OK' });
    handler = new IaCTemplateSyncHandler();
  });

  describe('DELETE event', () => {
    it('GIVEN a DELETE event WHEN the handler is invoked THEN it returns SUCCESS without any S3 operations', async () => {
      // GIVEN
      const event = createEvent('Delete');

      // WHEN
      await handler.handler(event, mockContext);

      // THEN
      const responseBody = parseCfnResponseBody(global.fetch as jest.Mock);
      expect(responseBody.Status).toBe('SUCCESS');
      expect(s3Mock.commandCalls(GetObjectCommand)).toHaveLength(0);
      expect(s3Mock.commandCalls(PutObjectCommand)).toHaveLength(0);
    });
  });

  describe('CREATE event', () => {
    it('GIVEN a 2-template manifest WHEN a CREATE event is received THEN both templates are copied and manifest is written', async () => {
      // GIVEN
      const event = createEvent('Create');

      s3Mock
        .on(GetObjectCommand, { Bucket: solutionsBucket, Key: manifestKey })
        .resolves({ Body: s3BodyFrom(JSON.stringify(twoTemplateManifest)) });

      s3Mock
        .on(GetObjectCommand, {
          Bucket: solutionsBucket,
          Key: `${templatePrefix}S3.1/cloudformation/S3.1.yaml`,
        })
        .resolves({ Body: s3BodyFrom('template-content-s3') });

      s3Mock
        .on(GetObjectCommand, {
          Bucket: solutionsBucket,
          Key: `${templatePrefix}IAM.1/terraform/IAM.1.tf`,
        })
        .resolves({ Body: s3BodyFrom('template-content-iam') });

      s3Mock.on(PutObjectCommand).resolves({});

      // WHEN
      await handler.handler(event, mockContext);

      // THEN
      const responseBody = parseCfnResponseBody(global.fetch as jest.Mock);
      expect(responseBody.Status).toBe('SUCCESS');

      const putCalls = s3Mock.commandCalls(PutObjectCommand);
      // 2 template copies + 1 manifest = 3 PutObject calls
      expect(putCalls).toHaveLength(3);

      // Verify template copies to customer bucket
      const putInputs = putCalls.map((call) => call.args[0].input);
      expect(putInputs).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            Bucket: customerBucket,
            Key: 'S3.1/cloudformation/S3.1.yaml',
            Body: 'template-content-s3',
          }),
          expect.objectContaining({
            Bucket: customerBucket,
            Key: 'IAM.1/terraform/IAM.1.tf',
            Body: 'template-content-iam',
          }),
          expect.objectContaining({
            Bucket: customerBucket,
            Key: '.metadata/manifest.json',
          }),
        ]),
      );
    });

    it('GIVEN S3 GetObject fails WHEN a CREATE event is received THEN FAILED is returned to CloudFormation', async () => {
      // GIVEN
      const event = createEvent('Create');
      s3Mock.on(GetObjectCommand).rejects(new Error('Access Denied'));

      // WHEN
      await handler.handler(event, mockContext);

      // THEN
      const responseBody = parseCfnResponseBody(global.fetch as jest.Mock);
      expect(responseBody.Status).toBe('FAILED');
      expect((responseBody.Data as { Message: string }).Message).toContain('Access Denied');
    });

    it('GIVEN an invalid manifest WHEN a CREATE event is received THEN FAILED is returned with a validation error', async () => {
      // GIVEN
      const event = createEvent('Create');
      const invalidManifest = { schemaVersion: '2.0', templates: 'not-an-array' };
      s3Mock
        .on(GetObjectCommand, { Bucket: solutionsBucket, Key: manifestKey })
        .resolves({ Body: s3BodyFrom(JSON.stringify(invalidManifest)) });

      // WHEN
      await handler.handler(event, mockContext);

      // THEN
      const responseBody = parseCfnResponseBody(global.fetch as jest.Mock);
      expect(responseBody.Status).toBe('FAILED');
      expect((responseBody.Data as { Message: string }).Message).toContain('Invalid manifest');
    });
  });

  describe('UPDATE event', () => {
    const existingManifest: Manifest = {
      schemaVersion: '1.0',
      generatedAt: '2025-01-01T00:00:00.000Z',
      solutionVersion: 'v3.0.0',
      templates: [
        {
          controlId: 'S3.1',
          iacFormat: 'cloudformation',
          s3Key: 'S3.1/cloudformation/S3.1.yaml',
          sha256: 'oldsha_s3',
        },
        {
          controlId: 'EC2.1',
          iacFormat: 'cloudformation',
          s3Key: 'EC2.1/cloudformation/EC2.1.yaml',
          sha256: 'oldsha_ec2',
        },
      ],
    };

    const incomingManifest: Manifest = {
      schemaVersion: '1.0',
      generatedAt: '2025-01-15T00:00:00.000Z',
      solutionVersion: 'v4.0.0',
      templates: [
        {
          controlId: 'S3.1',
          iacFormat: 'cloudformation',
          s3Key: 'S3.1/cloudformation/S3.1.yaml',
          sha256: 'newsha_s3',
        },
        {
          controlId: 'RDS.1',
          iacFormat: 'cloudformation',
          s3Key: 'RDS.1/cloudformation/RDS.1.yaml',
          sha256: 'newsha_rds',
        },
      ],
    };

    function setupUpdateMocks(customerTemplateContent: string): void {
      // Existing manifest in customer bucket
      s3Mock
        .on(GetObjectCommand, { Bucket: customerBucket, Key: '.metadata/manifest.json' })
        .resolves({ Body: s3BodyFrom(JSON.stringify(existingManifest)) });

      // Incoming manifest in solutions bucket
      s3Mock
        .on(GetObjectCommand, { Bucket: solutionsBucket, Key: manifestKey })
        .resolves({ Body: s3BodyFrom(JSON.stringify(incomingManifest)) });

      // S3.1 template in customer bucket (for checksum comparison)
      s3Mock
        .on(GetObjectCommand, { Bucket: customerBucket, Key: 'S3.1/cloudformation/S3.1.yaml' })
        .resolves({ Body: s3BodyFrom(customerTemplateContent) });

      // S3.1 template in solutions bucket (for copy)
      s3Mock
        .on(GetObjectCommand, {
          Bucket: solutionsBucket,
          Key: `${templatePrefix}S3.1/cloudformation/S3.1.yaml`,
        })
        .resolves({ Body: s3BodyFrom('new-s3-template-content') });

      // RDS.1 template in solutions bucket (added template)
      s3Mock
        .on(GetObjectCommand, {
          Bucket: solutionsBucket,
          Key: `${templatePrefix}RDS.1/cloudformation/RDS.1.yaml`,
        })
        .resolves({ Body: s3BodyFrom('rds-template-content') });

      s3Mock.on(PutObjectCommand).resolves({});
      s3Mock.on(CopyObjectCommand).resolves({});
      s3Mock.on(DeleteObjectCommand).resolves({});
    }

    it('GIVEN an UPDATE event with added templates WHEN handler is invoked THEN new templates are copied and SUCCESS is returned', async () => {
      // GIVEN — S3.1 is unmodified (checksum matches existing manifest)
      const unmodifiedContent = 'original-s3-content';
      const unmodifiedChecksum = createHash('sha256').update(unmodifiedContent).digest('hex');
      const existingWithChecksum: Manifest = {
        ...existingManifest,
        templates: existingManifest.templates.map((t) =>
          t.controlId === 'S3.1' ? { ...t, sha256: unmodifiedChecksum } : t,
        ),
      };

      s3Mock
        .on(GetObjectCommand, { Bucket: customerBucket, Key: '.metadata/manifest.json' })
        .resolves({ Body: s3BodyFrom(JSON.stringify(existingWithChecksum)) });
      s3Mock
        .on(GetObjectCommand, { Bucket: solutionsBucket, Key: manifestKey })
        .resolves({ Body: s3BodyFrom(JSON.stringify(incomingManifest)) });
      s3Mock
        .on(GetObjectCommand, { Bucket: customerBucket, Key: 'S3.1/cloudformation/S3.1.yaml' })
        .resolves({ Body: s3BodyFrom(unmodifiedContent) });
      s3Mock
        .on(GetObjectCommand, {
          Bucket: solutionsBucket,
          Key: `${templatePrefix}S3.1/cloudformation/S3.1.yaml`,
        })
        .resolves({ Body: s3BodyFrom('new-s3-template-content') });
      s3Mock
        .on(GetObjectCommand, {
          Bucket: solutionsBucket,
          Key: `${templatePrefix}RDS.1/cloudformation/RDS.1.yaml`,
        })
        .resolves({ Body: s3BodyFrom('rds-template-content') });
      s3Mock.on(PutObjectCommand).resolves({});
      s3Mock.on(CopyObjectCommand).resolves({});
      s3Mock.on(DeleteObjectCommand).resolves({});

      const event = createEvent('Update');

      // WHEN
      await handler.handler(event, mockContext);

      // THEN
      const responseBody = parseCfnResponseBody(global.fetch as jest.Mock);
      expect(responseBody.Status).toBe('SUCCESS');

      // RDS.1 (added) + S3.1 (updated, unmodified) should be copied
      const putCalls = s3Mock.commandCalls(PutObjectCommand);
      const putKeys = putCalls.map((c) => c.args[0].input.Key);
      expect(putKeys).toContain('RDS.1/cloudformation/RDS.1.yaml');
      expect(putKeys).toContain('S3.1/cloudformation/S3.1.yaml');
      expect(putKeys).toContain('.metadata/manifest.json');
    });

    it('GIVEN an UPDATE event with updated templates WHEN handler is invoked THEN all updated templates are overwritten and SUCCESS is returned', async () => {
      setupUpdateMocks('any-content-doesnt-matter');

      const event = createEvent('Update');

      // WHEN
      await handler.handler(event, mockContext);

      // THEN
      const responseBody = parseCfnResponseBody(global.fetch as jest.Mock);
      expect(responseBody.Status).toBe('SUCCESS');

      // RDS.1 (added) + S3.1 (updated) should both be copied — no skipping
      const putCalls = s3Mock.commandCalls(PutObjectCommand);
      const putKeys = putCalls.map((c) => c.args[0].input.Key);
      expect(putKeys).toContain('RDS.1/cloudformation/RDS.1.yaml');
      expect(putKeys).toContain('S3.1/cloudformation/S3.1.yaml');
      expect(putKeys).toContain('.metadata/manifest.json');
    });

    it('GIVEN an UPDATE event with a deprecated template WHEN handler is invoked THEN the template is archived and deleted', async () => {
      // GIVEN — EC2.1 is in existing but not in incoming (deprecated)
      const unmodifiedContent = 'original-s3-content';
      const unmodifiedChecksum = createHash('sha256').update(unmodifiedContent).digest('hex');
      const existingWithChecksum: Manifest = {
        ...existingManifest,
        templates: existingManifest.templates.map((t) =>
          t.controlId === 'S3.1' ? { ...t, sha256: unmodifiedChecksum } : t,
        ),
      };

      s3Mock
        .on(GetObjectCommand, { Bucket: customerBucket, Key: '.metadata/manifest.json' })
        .resolves({ Body: s3BodyFrom(JSON.stringify(existingWithChecksum)) });
      s3Mock
        .on(GetObjectCommand, { Bucket: solutionsBucket, Key: manifestKey })
        .resolves({ Body: s3BodyFrom(JSON.stringify(incomingManifest)) });
      s3Mock
        .on(GetObjectCommand, { Bucket: customerBucket, Key: 'S3.1/cloudformation/S3.1.yaml' })
        .resolves({ Body: s3BodyFrom(unmodifiedContent) });
      s3Mock
        .on(GetObjectCommand, {
          Bucket: solutionsBucket,
          Key: `${templatePrefix}S3.1/cloudformation/S3.1.yaml`,
        })
        .resolves({ Body: s3BodyFrom('new-s3-template-content') });
      s3Mock
        .on(GetObjectCommand, {
          Bucket: solutionsBucket,
          Key: `${templatePrefix}RDS.1/cloudformation/RDS.1.yaml`,
        })
        .resolves({ Body: s3BodyFrom('rds-template-content') });
      s3Mock.on(PutObjectCommand).resolves({});
      s3Mock.on(CopyObjectCommand).resolves({});
      s3Mock.on(DeleteObjectCommand).resolves({});

      const event = createEvent('Update');

      // WHEN
      await handler.handler(event, mockContext);

      // THEN
      const responseBody = parseCfnResponseBody(global.fetch as jest.Mock);
      expect(responseBody.Status).toBe('SUCCESS');

      // EC2.1 should be archived
      const copyCalls = s3Mock.commandCalls(CopyObjectCommand);
      expect(copyCalls).toHaveLength(1);
      expect(copyCalls[0].args[0].input).toEqual(
        expect.objectContaining({
          Bucket: customerBucket,
          CopySource: `${customerBucket}/EC2.1/cloudformation/EC2.1.yaml`,
          Key: '.deprecated/EC2.1/cloudformation/EC2.1.yaml',
        }),
      );

      // EC2.1 should be deleted from active path
      const deleteCalls = s3Mock.commandCalls(DeleteObjectCommand);
      expect(deleteCalls).toHaveLength(1);
      expect(deleteCalls[0].args[0].input).toEqual(
        expect.objectContaining({
          Bucket: customerBucket,
          Key: 'EC2.1/cloudformation/EC2.1.yaml',
        }),
      );
    });

    it('GIVEN an UPDATE event WHEN the existing manifest is missing THEN it falls back to CREATE behavior', async () => {
      // GIVEN
      s3Mock
        .on(GetObjectCommand, { Bucket: customerBucket, Key: '.metadata/manifest.json' })
        .rejects(new Error('NoSuchKey'));
      s3Mock
        .on(GetObjectCommand, { Bucket: solutionsBucket, Key: manifestKey })
        .resolves({ Body: s3BodyFrom(JSON.stringify(twoTemplateManifest)) });
      s3Mock
        .on(GetObjectCommand, {
          Bucket: solutionsBucket,
          Key: `${templatePrefix}S3.1/cloudformation/S3.1.yaml`,
        })
        .resolves({ Body: s3BodyFrom('template-content-s3') });
      s3Mock
        .on(GetObjectCommand, {
          Bucket: solutionsBucket,
          Key: `${templatePrefix}IAM.1/terraform/IAM.1.tf`,
        })
        .resolves({ Body: s3BodyFrom('template-content-iam') });
      s3Mock.on(PutObjectCommand).resolves({});

      const event = createEvent('Update');

      // WHEN
      await handler.handler(event, mockContext);

      // THEN
      const responseBody = parseCfnResponseBody(global.fetch as jest.Mock);
      expect(responseBody.Status).toBe('SUCCESS');

      // Should have logged the fallback warning
      expect(mockLogger.warn).toHaveBeenCalledWith(expect.stringContaining('falling back to CREATE behavior'));

      // Should have copied all templates (CREATE behavior)
      const putCalls = s3Mock.commandCalls(PutObjectCommand);
      expect(putCalls).toHaveLength(3); // 2 templates + 1 manifest
    });

    it('GIVEN an UPDATE event WHEN fetching existing manifest fails with a non-NoSuchKey error THEN it fails loudly instead of falling back to CREATE', async () => {
      // GIVEN
      s3Mock
        .on(GetObjectCommand, { Bucket: solutionsBucket, Key: manifestKey })
        .resolves({ Body: s3BodyFrom(JSON.stringify(incomingManifest)) });
      s3Mock
        .on(GetObjectCommand, { Bucket: customerBucket, Key: '.metadata/manifest.json' })
        .rejects(new Error('Access Denied'));

      const event = createEvent('Update');

      // WHEN
      await handler.handler(event, mockContext);

      // THEN
      const responseBody = parseCfnResponseBody(global.fetch as jest.Mock);
      expect(responseBody.Status).toBe('FAILED');
      expect((responseBody.Data as { Message: string }).Message).toContain('Cannot read existing manifest');
      expect((responseBody.Data as { Message: string }).Message).toContain('Access Denied');

      expect(mockLogger.error).toHaveBeenCalledWith(
        'Failed to fetch existing manifest — refusing destructive fallback',
        expect.objectContaining({ error: 'Access Denied' }),
      );
    });

    it('GIVEN an UPDATE event WHEN S3 fails during sync THEN FAILED is returned to CloudFormation', async () => {
      // GIVEN
      s3Mock
        .on(GetObjectCommand, { Bucket: customerBucket, Key: '.metadata/manifest.json' })
        .resolves({ Body: s3BodyFrom(JSON.stringify(existingManifest)) });
      s3Mock
        .on(GetObjectCommand, { Bucket: solutionsBucket, Key: manifestKey })
        .resolves({ Body: s3BodyFrom(JSON.stringify(incomingManifest)) });
      // Fail when trying to copy the added RDS.1 template
      s3Mock
        .on(GetObjectCommand, {
          Bucket: solutionsBucket,
          Key: `${templatePrefix}RDS.1/cloudformation/RDS.1.yaml`,
        })
        .rejects(new Error('Internal Server Error'));

      const event = createEvent('Update');

      // WHEN
      await handler.handler(event, mockContext);

      // THEN
      const responseBody = parseCfnResponseBody(global.fetch as jest.Mock);
      expect(responseBody.Status).toBe('FAILED');
      expect((responseBody.Data as { Message: string }).Message).toContain('Internal Server Error');
    });

    it('GIVEN an UPDATE event WHEN archive copy fails for a deprecated template THEN the template is not deleted and processing continues', async () => {
      // GIVEN — set up so EC2.1 is deprecated but archive copy fails
      const unmodifiedContent = 'original-s3-content';
      const unmodifiedChecksum = createHash('sha256').update(unmodifiedContent).digest('hex');
      const existingWithChecksum: Manifest = {
        ...existingManifest,
        templates: existingManifest.templates.map((t) =>
          t.controlId === 'S3.1' ? { ...t, sha256: unmodifiedChecksum } : t,
        ),
      };

      s3Mock
        .on(GetObjectCommand, { Bucket: customerBucket, Key: '.metadata/manifest.json' })
        .resolves({ Body: s3BodyFrom(JSON.stringify(existingWithChecksum)) });
      s3Mock
        .on(GetObjectCommand, { Bucket: solutionsBucket, Key: manifestKey })
        .resolves({ Body: s3BodyFrom(JSON.stringify(incomingManifest)) });
      s3Mock
        .on(GetObjectCommand, { Bucket: customerBucket, Key: 'S3.1/cloudformation/S3.1.yaml' })
        .resolves({ Body: s3BodyFrom(unmodifiedContent) });
      s3Mock
        .on(GetObjectCommand, {
          Bucket: solutionsBucket,
          Key: `${templatePrefix}S3.1/cloudformation/S3.1.yaml`,
        })
        .resolves({ Body: s3BodyFrom('new-s3-template-content') });
      s3Mock
        .on(GetObjectCommand, {
          Bucket: solutionsBucket,
          Key: `${templatePrefix}RDS.1/cloudformation/RDS.1.yaml`,
        })
        .resolves({ Body: s3BodyFrom('rds-template-content') });
      s3Mock.on(PutObjectCommand).resolves({});
      s3Mock.on(CopyObjectCommand).rejects(new Error('Access Denied'));
      s3Mock.on(DeleteObjectCommand).resolves({});

      const event = createEvent('Update');

      // WHEN
      await handler.handler(event, mockContext);

      // THEN — should still succeed overall
      const responseBody = parseCfnResponseBody(global.fetch as jest.Mock);
      expect(responseBody.Status).toBe('SUCCESS');

      // Delete should NOT have been called since copy failed
      const deleteCalls = s3Mock.commandCalls(DeleteObjectCommand);
      expect(deleteCalls).toHaveLength(0);

      // Error should have been logged
      expect(mockLogger.error).toHaveBeenCalledWith(
        'Failed to archive deprecated template — skipping deletion',
        expect.objectContaining({ controlId: 'EC2.1' }),
      );
    });
  });

  describe('CloudFormation response contract', () => {
    it('GIVEN any event WHEN the handler responds THEN the response includes all required fields', async () => {
      // GIVEN
      const event = createEvent('Delete');

      // WHEN
      await handler.handler(event, mockContext);

      // THEN
      const responseBody = parseCfnResponseBody(global.fetch as jest.Mock);
      expect(responseBody).toEqual(
        expect.objectContaining({
          Status: expect.stringMatching(/^(SUCCESS|FAILED)$/),
          PhysicalResourceId: expect.any(String),
          StackId: event.StackId,
          RequestId: event.RequestId,
          LogicalResourceId: event.LogicalResourceId,
        }),
      );
    });

    it('GIVEN an unhandled exception WHEN the handler is invoked THEN a FAILED response is still sent', async () => {
      // GIVEN — force an error by making processEvent throw via a broken event
      const event = createEvent('Create');
      // Remove ResourceProperties to cause an error in processEvent
      (event as unknown as Record<string, unknown>).ResourceProperties = undefined;

      // WHEN
      await handler.handler(event, mockContext);

      // THEN
      const responseBody = parseCfnResponseBody(global.fetch as jest.Mock);
      expect(responseBody.Status).toBe('FAILED');
      expect(responseBody.StackId).toBe(event.StackId);
      expect(responseBody.RequestId).toBe(event.RequestId);
      expect(responseBody.LogicalResourceId).toBe(event.LogicalResourceId);
      expect(responseBody.PhysicalResourceId).toBeDefined();
    });
  });
});

function makeManifest(templates: TemplateEntry[]): Manifest {
  return {
    schemaVersion: '1.0',
    generatedAt: '2025-01-15T00:00:00.000Z',
    solutionVersion: 'v4.0.0',
    templates,
  };
}

function makeEntry(s3Key: string, sha256: string): TemplateEntry {
  return { controlId: s3Key.split('/')[0], iacFormat: 'cloudformation', s3Key, sha256 };
}

describe('diffManifests', () => {
  it('GIVEN an entry only in incoming WHEN diffManifests is called THEN it appears in added', () => {
    // GIVEN
    const existing = makeManifest([]);
    const incoming = makeManifest([makeEntry('S3.1/cloudformation/S3.1.yaml', 'abc123')]);

    // WHEN
    const result = diffManifests(existing, incoming);

    // THEN
    expect(result.added).toHaveLength(1);
    expect(result.added[0].s3Key).toBe('S3.1/cloudformation/S3.1.yaml');
    expect(result.deprecated).toHaveLength(0);
    expect(result.updated).toHaveLength(0);
    expect(result.unchanged).toHaveLength(0);
  });

  it('GIVEN an entry only in existing WHEN diffManifests is called THEN it appears in deprecated', () => {
    // GIVEN
    const existing = makeManifest([makeEntry('IAM.1/terraform/IAM.1.tf', 'def456')]);
    const incoming = makeManifest([]);

    // WHEN
    const result = diffManifests(existing, incoming);

    // THEN
    expect(result.deprecated).toHaveLength(1);
    expect(result.deprecated[0].s3Key).toBe('IAM.1/terraform/IAM.1.tf');
    expect(result.added).toHaveLength(0);
    expect(result.updated).toHaveLength(0);
    expect(result.unchanged).toHaveLength(0);
  });

  it('GIVEN an entry in both with same sha256 WHEN diffManifests is called THEN it appears in unchanged', () => {
    // GIVEN
    const entry = makeEntry('S3.1/cloudformation/S3.1.yaml', 'abc123');
    const existing = makeManifest([entry]);
    const incoming = makeManifest([entry]);

    // WHEN
    const result = diffManifests(existing, incoming);

    // THEN
    expect(result.unchanged).toHaveLength(1);
    expect(result.unchanged[0].s3Key).toBe('S3.1/cloudformation/S3.1.yaml');
    expect(result.added).toHaveLength(0);
    expect(result.updated).toHaveLength(0);
    expect(result.deprecated).toHaveLength(0);
  });

  it('GIVEN an entry in both with different sha256 WHEN diffManifests is called THEN it appears in updated', () => {
    // GIVEN
    const existing = makeManifest([makeEntry('S3.1/cloudformation/S3.1.yaml', 'abc123')]);
    const incoming = makeManifest([makeEntry('S3.1/cloudformation/S3.1.yaml', 'xyz789')]);

    // WHEN
    const result = diffManifests(existing, incoming);

    // THEN
    expect(result.updated).toHaveLength(1);
    expect(result.updated[0].s3Key).toBe('S3.1/cloudformation/S3.1.yaml');
    expect(result.added).toHaveLength(0);
    expect(result.unchanged).toHaveLength(0);
    expect(result.deprecated).toHaveLength(0);
  });

  it('GIVEN entries across all categories WHEN diffManifests is called THEN the union covers all unique s3Keys with no duplicates', () => {
    // GIVEN
    const existing = makeManifest([
      makeEntry('S3.1/cloudformation/S3.1.yaml', 'aaa'),
      makeEntry('IAM.1/terraform/IAM.1.tf', 'bbb'),
      makeEntry('EC2.1/cloudformation/EC2.1.yaml', 'ccc'),
    ]);
    const incoming = makeManifest([
      makeEntry('S3.1/cloudformation/S3.1.yaml', 'aaa'), // unchanged
      makeEntry('IAM.1/terraform/IAM.1.tf', 'bbb-new'), // updated
      makeEntry('RDS.1/cloudformation/RDS.1.yaml', 'ddd'), // added
    ]);
    // EC2.1 is deprecated (only in existing)

    // WHEN
    const result = diffManifests(existing, incoming);

    // THEN
    const allKeys = [
      ...result.added.map((e) => e.s3Key),
      ...result.updated.map((e) => e.s3Key),
      ...result.unchanged.map((e) => e.s3Key),
      ...result.deprecated.map((e) => e.s3Key),
    ];
    const uniqueKeys = new Set(allKeys);
    expect(allKeys).toHaveLength(uniqueKeys.size); // no duplicates
    expect(uniqueKeys.size).toBe(4); // all 4 unique s3Keys covered
  });

  it('GIVEN empty manifests WHEN diffManifests is called THEN all categories are empty', () => {
    // GIVEN
    const existing = makeManifest([]);
    const incoming = makeManifest([]);

    // WHEN
    const result = diffManifests(existing, incoming);

    // THEN
    expect(result.added).toHaveLength(0);
    expect(result.updated).toHaveLength(0);
    expect(result.unchanged).toHaveLength(0);
    expect(result.deprecated).toHaveLength(0);
  });

  /**
   * **Validates: Requirements 2.3**
   *
   * Property test: for any two randomly generated manifests, the four
   * categories (added, updated, unchanged, deprecated) partition all
   * unique s3Keys without overlap or omission.
   */
  it('GIVEN random manifest pairs WHEN diffManifests is called THEN the four categories partition all s3Keys without overlap or omission', () => {
    const templateEntryArb = fc.record({
      controlId: fc.stringMatching(/^[A-Z]{2,6}\.\d{1,3}$/),
      iacFormat: fc.constantFrom('cloudformation', 'terraform', 'cdk'),
      s3Key: fc.stringMatching(
        /^[A-Z]{2,6}\.\d{1,3}\/(cloudformation|terraform|cdk)\/[A-Z]{2,6}\.\d{1,3}\.(yaml|tf|ts)$/,
      ),
      sha256: fc.stringMatching(/^[0-9a-f]{64}$/),
    });

    const manifestArb = fc.record({
      schemaVersion: fc.constant('1.0'),
      generatedAt: fc.constant('2025-01-15T00:00:00.000Z'),
      solutionVersion: fc.constant('v4.0.0'),
      templates: fc.array(templateEntryArb, { minLength: 0, maxLength: 20 }),
    });

    fc.assert(
      fc.property(manifestArb, manifestArb, (existing, incoming) => {
        const result = diffManifests(existing as Manifest, incoming as Manifest);

        // Collect all s3Keys from both manifests
        const existingKeys = new Set(existing.templates.map((t) => t.s3Key));
        const incomingKeys = new Set(incoming.templates.map((t) => t.s3Key));
        const allExpectedKeys = new Set([...existingKeys, ...incomingKeys]);

        // Collect all s3Keys from the result
        const resultKeys = [
          ...result.added.map((e) => e.s3Key),
          ...result.updated.map((e) => e.s3Key),
          ...result.unchanged.map((e) => e.s3Key),
          ...result.deprecated.map((e) => e.s3Key),
        ];

        // No duplicates in result
        const resultKeySet = new Set(resultKeys);
        expect(resultKeys.length).toBe(resultKeySet.size);

        // Result covers all unique keys
        expect(resultKeySet.size).toBe(allExpectedKeys.size);
        for (const key of allExpectedKeys) {
          expect(resultKeySet.has(key)).toBe(true);
        }

        // Verify categorization correctness
        for (const entry of result.added) {
          expect(incomingKeys.has(entry.s3Key)).toBe(true);
          expect(existingKeys.has(entry.s3Key)).toBe(false);
        }
        for (const entry of result.deprecated) {
          expect(existingKeys.has(entry.s3Key)).toBe(true);
          expect(incomingKeys.has(entry.s3Key)).toBe(false);
        }
        for (const entry of result.updated) {
          expect(existingKeys.has(entry.s3Key)).toBe(true);
          expect(incomingKeys.has(entry.s3Key)).toBe(true);
        }
        for (const entry of result.unchanged) {
          expect(existingKeys.has(entry.s3Key)).toBe(true);
          expect(incomingKeys.has(entry.s3Key)).toBe(true);
        }
      }),
      { numRuns: 100 },
    );
  });
});
