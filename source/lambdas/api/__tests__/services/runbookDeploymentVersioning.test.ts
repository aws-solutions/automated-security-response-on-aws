// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { Logger } from '@aws-lambda-powertools/logger';
import { S3Client, PutObjectCommand, DeleteObjectCommand } from '@aws-sdk/client-s3';
import { DynamoDBDocumentClient, QueryCommand, PutCommand, DeleteCommand } from '@aws-sdk/lib-dynamodb';
import { RunbookId } from '@asr/data-models';
import { mockClient } from 'aws-sdk-client-mock';
import { RunbookDeploymentService } from '../../services/runbookDeploymentService';
import { resetApiLambdaEnvironmentCache } from '../../apiLambdaEnvironment';
import type { Clock } from '../../../common/utils/clock';
import type { IdGenerator } from '../../../common/utils/idGenerator';

const s3Mock = mockClient(S3Client);
const dynamoMock = mockClient(DynamoDBDocumentClient);

const fixedClock: Clock = { now: () => new Date('2026-01-01T00:00:00Z') };
let nextId = 0;
const fakeIdGenerator: IdGenerator = { randomUUID: () => `uuid-${++nextId}` };

function service(): RunbookDeploymentService {
  return new RunbookDeploymentService(new Logger({ serviceName: 'test' }), fixedClock, fakeIdGenerator);
}

describe('RunbookDeploymentService — versioned register', () => {
  beforeEach(() => {
    s3Mock.reset();
    dynamoMock.reset();
    s3Mock.resolves({});
    nextId = 0;
    process.env.CUSTOM_RUNBOOK_BUCKET_NAME = 'test-bucket';
    process.env.CUSTOM_RUNBOOK_TABLE_NAME = 'test-table';
    resetApiLambdaEnvironmentCache();
  });

  it('starts a brand-new runbook at version 1 with a fresh runbookId', async () => {
    dynamoMock.on(QueryCommand).resolves({ Items: [], Count: 0 });
    dynamoMock.on(PutCommand).resolves({});

    const result = await service().execute({
      action: 'register',
      runbook_yaml: 'schemaVersion: "0.3"',
      control_id: 'S3.9',
    });

    expect(result.version).toBe(1);
    expect(result.runbook_id).toBe('uuid-1');
    expect(result.status).toBe('DRAFT');
  });

  it('registering against an existing runbook_id increments that runbook’s version', async () => {
    // Latest version for the supplied runbookId is 2 → next is 3.
    dynamoMock.on(QueryCommand).resolves({
      Items: [{ runbookId: 'abc12300-0000-4000-8000-000000000123', version: 2, controlId: 'S3.9' }],
      Count: 1,
    });
    dynamoMock.on(PutCommand).resolves({});

    const result = await service().execute({
      action: 'register',
      runbook_id: 'abc12300-0000-4000-8000-000000000123' as RunbookId,
      runbook_yaml: 'schemaVersion: "0.3"',
      control_id: 'S3.9',
    });

    expect(result.runbook_id).toBe('abc12300-0000-4000-8000-000000000123'); // reused, NOT a new UUID
    expect(result.version).toBe(3);
  });

  it('rejects reusing a runbook_id under a different control', async () => {
    // The existing latest version of this runbook is control S3.9; registering
    // the same id under EC2.1 would corrupt the one-runbook-one-control mapping.
    dynamoMock.on(QueryCommand).resolves({
      Items: [{ runbookId: 'abc12300-0000-4000-8000-000000000123', version: 1, controlId: 'S3.9' }],
      Count: 1,
    });

    await expect(
      service().execute({
        action: 'register',
        runbook_id: 'abc12300-0000-4000-8000-000000000123' as RunbookId,
        runbook_yaml: 'x: 1',
        control_id: 'EC2.1',
      }),
    ).rejects.toThrow(/registered under control S3\.9, not EC2\.1/);

    // Nothing was written — the mismatch is caught before any create.
    expect(dynamoMock.commandCalls(PutCommand)).toHaveLength(0);
  });

  it('uses a conditional create so the version slot cannot be silently overwritten', async () => {
    dynamoMock.on(QueryCommand).resolves({ Items: [], Count: 0 });
    dynamoMock.on(PutCommand).resolves({});

    await service().execute({ action: 'register', runbook_yaml: 'x: 1', control_id: 'S3.9' });

    const putCall = dynamoMock.commandCalls(PutCommand)[0];
    expect(putCall.args[0].input.ConditionExpression).toContain('attribute_not_exists(runbookId)');
    expect(putCall.args[0].input.ConditionExpression).toContain('attribute_not_exists(#version)');
    expect(putCall.args[0].input.ExpressionAttributeNames).toMatchObject({ '#version': 'version' });
  });

  it('retries with the next version when a concurrent register took the slot', async () => {
    // First QueryCommand → latest v1 (so it tries v2); the v2 PutCommand fails the
    // condition (slot taken); retry re-queries → latest v2 → tries v3, succeeds.
    dynamoMock
      .on(QueryCommand)
      .resolvesOnce({
        Items: [{ runbookId: 'abc12300-0000-4000-8000-000000000123', version: 1, controlId: 'S3.9' }],
        Count: 1,
      })
      .resolvesOnce({
        Items: [{ runbookId: 'abc12300-0000-4000-8000-000000000123', version: 2, controlId: 'S3.9' }],
        Count: 1,
      });
    const conflict = new Error('exists');
    conflict.name = 'ConditionalCheckFailedException';
    dynamoMock.on(PutCommand).rejectsOnce(conflict).resolvesOnce({});

    const result = await service().execute({
      action: 'register',
      runbook_id: 'abc12300-0000-4000-8000-000000000123' as RunbookId,
      runbook_yaml: 'x: 1',
      control_id: 'S3.9',
    });

    expect(result.version).toBe(3); // recomputed after the conflict
    expect(dynamoMock.commandCalls(PutCommand)).toHaveLength(2); // first failed, retry succeeded
  });

  it('writes the YAML to the version-scoped S3 key', async () => {
    dynamoMock.on(QueryCommand).resolves({ Items: [], Count: 0 });
    dynamoMock.on(PutCommand).resolves({});

    await service().execute({ action: 'register', runbook_yaml: 'x: 1', control_id: 'S3.9' });

    const s3Put = s3Mock.commandCalls(PutObjectCommand)[0];
    expect(s3Put.args[0].input.Key).toBe('runbooks/uuid-1/v1/runbook.yaml');
  });

  it('cleans up the uploaded YAML and the DynamoDB record when the script upload fails', async () => {
    dynamoMock.on(QueryCommand).resolves({ Items: [], Count: 0 });
    dynamoMock.on(PutCommand).resolves({});
    dynamoMock.on(DeleteCommand).resolves({});
    // First PutObject (YAML) succeeds, second (script) fails — leaving the YAML
    // orphaned unless the compensating action removes it.
    s3Mock.on(PutObjectCommand).resolvesOnce({}).rejectsOnce(new Error('AccessDenied'));

    await expect(
      service().execute({
        action: 'register',
        runbook_yaml: 'x: 1',
        python_script: 'print(1)',
        control_id: 'S3.9',
      }),
    ).rejects.toThrow('AccessDenied');

    // Both the YAML object and the just-created DynamoDB version record are removed.
    const deletedKeys = s3Mock.commandCalls(DeleteObjectCommand).map((call) => call.args[0].input.Key);
    expect(deletedKeys).toContain('runbooks/uuid-1/v1/runbook.yaml');
    expect(deletedKeys).toContain('runbooks/uuid-1/v1/script.py');
    expect(dynamoMock.commandCalls(DeleteCommand)).toHaveLength(1);
  });

  it('registers a brand-new runbook with no member accounts staged', async () => {
    dynamoMock.on(QueryCommand).resolves({ Items: [], Count: 0 });
    dynamoMock.on(PutCommand).resolves({});

    await service().execute({ action: 'register', runbook_yaml: 'x: 1', control_id: 'S3.9' });

    expect(dynamoMock.commandCalls(PutCommand)[0].args[0].input.Item?.deployedAccounts).toBeUndefined();
  });

  // Registering must not change what any account runs — a new version is staged
  // for release, and only a later deploy naming an account installs it there.
  it('carries the previous version’s accounts onto the new version as PENDING', async () => {
    dynamoMock.on(QueryCommand).resolves({
      Items: [
        {
          runbookId: 'abc12300-0000-4000-8000-000000000123',
          version: 1,
          controlId: 'S3.9',
          deployedAccounts: {
            '111111111111': {
              runbookVersion: 1,
              ssmDocumentVersion: '3',
              status: 'DEPLOYED',
              attemptedAt: '2025-12-01T00:00:00.000Z',
            },
          },
        },
      ],
      Count: 1,
    });
    dynamoMock.on(PutCommand).resolves({});

    await service().execute({
      action: 'register',
      runbook_id: 'abc12300-0000-4000-8000-000000000123' as RunbookId,
      runbook_yaml: 'x: 1',
      control_id: 'S3.9',
    });

    expect(dynamoMock.commandCalls(PutCommand)[0].args[0].input.Item?.deployedAccounts).toEqual({
      '111111111111': {
        runbookVersion: 1, // still running v1 — nothing was pushed
        ssmDocumentVersion: '3',
        status: 'PENDING',
        attemptedAt: '2025-12-01T00:00:00.000Z',
      },
    });
  });

  it('keeps a previously failed account marked FAILED on the new version', async () => {
    const failedState = {
      runbookVersion: 1,
      ssmDocumentVersion: '1',
      status: 'FAILED',
      attemptedAt: '2025-12-01T00:00:00.000Z',
      error: 'AccessDenied',
    };
    dynamoMock.on(QueryCommand).resolves({
      Items: [
        {
          runbookId: 'abc12300-0000-4000-8000-000000000123',
          version: 1,
          controlId: 'S3.9',
          deployedAccounts: { '222222222222': failedState },
        },
      ],
      Count: 1,
    });
    dynamoMock.on(PutCommand).resolves({});

    await service().execute({
      action: 'register',
      runbook_id: 'abc12300-0000-4000-8000-000000000123' as RunbookId,
      runbook_yaml: 'x: 1',
      control_id: 'S3.9',
    });

    // The failure stays visible across versions instead of being reset to pending.
    expect(dynamoMock.commandCalls(PutCommand)[0].args[0].input.Item?.deployedAccounts).toEqual({
      '222222222222': failedState,
    });
  });
});
