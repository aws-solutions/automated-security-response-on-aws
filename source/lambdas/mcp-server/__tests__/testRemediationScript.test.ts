// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import * as yaml from 'js-yaml';
import { mockClient } from 'aws-sdk-client-mock';
import {
  SSMClient,
  CreateDocumentCommand,
  StartAutomationExecutionCommand,
  GetAutomationExecutionCommand,
  DeleteDocumentCommand,
} from '@aws-sdk/client-ssm';
import { createTestRemediationScript } from '../backends/common/testRemediationScript';
import type { Clock } from '../../common/utils/clock';
import type { Sleeper } from '../../common/utils/sleeper';
import type { ExecutionContext } from '../backends/common/../types';

/** Typed shape of the SSM document the executor generates, avoiding inline `as` casts. */
interface GeneratedDocument {
  schemaVersion: string;
  description: string;
  assumeRole: string;
  parameters: Record<string, unknown>;
  mainSteps: Array<{
    name: string;
    action: string;
    inputs: { Script: string; InputPayload?: Record<string, string> };
    timeoutSeconds: number;
    onFailure: string;
    onCancel: string;
    maxAttempts: number;
  }>;
}

function getFirstStep(doc: GeneratedDocument) {
  return doc.mainSteps[0];
}

const ssmMock = mockClient(SSMClient);

const FIXED_NOW = new Date('2024-01-01T00:00:00.000Z');
const fixedClock: Clock = { now: () => FIXED_NOW };
const noopSleeper: Sleeper = { sleep: () => Promise.resolve() };

function context(overrides: Partial<ExecutionContext> = {}): ExecutionContext {
  return { region: 'us-east-1', requestId: 'test-request', ...overrides };
}

beforeEach(() => {
  ssmMock.reset();
  ssmMock.on(StartAutomationExecutionCommand).resolves({ AutomationExecutionId: 'exec-1' });
  ssmMock.on(GetAutomationExecutionCommand).resolves({
    AutomationExecution: { AutomationExecutionStatus: 'Success', StepExecutions: [] },
  });
  ssmMock.on(DeleteDocumentCommand).resolves({});
});

/** Captures the document content CreateDocument was called with and parses it back to an object. */
function capturedDocument(): GeneratedDocument {
  const call = ssmMock.commandCalls(CreateDocumentCommand)[0];
  const content = call.args[0].input.Content as string;
  return yaml.load(content) as GeneratedDocument;
}

describe('testRemediationScript — generated document is valid, safe YAML', () => {
  const testRemediationScript = createTestRemediationScript(fixedClock, noopSleeper);

  beforeEach(() => {
    ssmMock.on(CreateDocumentCommand).resolves({});
  });

  test('a script containing YAML-structural characters round-trips as a literal string, not as structure', async () => {
    // Every one of these would have corrupted the old hand-rolled block-scalar
    // indenter: an embedded "key: value" line, CRLF line endings, and a line
    // that looks like a YAML mapping key at the same indentation as the script.
    const trickyScript =
      'def handler(event, context):\r\n' +
      '    x = "a: b"\n' +
      '    evil_key: not_a_real_document_key\n' +
      '    return {"ok": True}\n';

    await testRemediationScript(
      {
        python_script: trickyScript,
        automation_assume_role: 'arn:aws:iam::123456789012:role/SO0111-Remediate-Custom-Test-unit',
      },
      context(),
    );

    const doc = capturedDocument();
    const script = getFirstStep(doc).inputs.Script;
    expect(script).toBe(trickyScript);
    // The document must still be a well-formed single mapping — not split into
    // extra top-level keys by an unescaped colon in the script body.
    expect(Object.keys(doc)).toEqual(['schemaVersion', 'description', 'assumeRole', 'parameters', 'mainSteps']);
  });

  test('rejects the reserved AutomationAssumeRole key in input_payload', async () => {
    await expect(
      testRemediationScript(
        {
          python_script: 'def handler(event, context):\n    return {}\n',
          automation_assume_role: 'arn:aws:iam::123456789012:role/SO0111-Remediate-Custom-Test-unit',
          input_payload: { AutomationAssumeRole: 'sneaky' },
        },
        context(),
      ),
    ).rejects.toThrow(/is reserved/);
  });

  test('rejects an input_payload key that is not a safe SSM parameter name', async () => {
    const attempts = ['bad key', 'bad:key', 'bad\nkey', '1leadingdigit', 'has-hyphen', ''];
    for (const key of attempts) {
      await expect(
        testRemediationScript(
          {
            python_script: 'def handler(event, context):\n    return {}\n',
            automation_assume_role: 'arn:aws:iam::123456789012:role/SO0111-Remediate-Custom-Test-unit',
            input_payload: { [key]: 'value' },
          },
          context(),
        ),
      ).rejects.toThrow(/must start with a letter/);
    }
  });

  test('allows an underscore in an input_payload key — the natural Python-kwarg authoring style', async () => {
    await testRemediationScript(
      {
        python_script: 'def handler(event, context):\n    return {}\n',
        automation_assume_role: 'arn:aws:iam::123456789012:role/SO0111-Remediate-Custom-Test-unit',
        input_payload: { bucket_name: 'my-bucket', finding_id: 'abc-123' },
      },
      context(),
    );

    const doc = capturedDocument();
    const parameters = doc.parameters as Record<string, unknown>;
    expect(parameters.bucket_name).toBeDefined();
    expect(parameters.finding_id).toBeDefined();
  });

  test('validateInputKeys failures use a specific ValidationError, not a generic Error', async () => {
    await expect(
      testRemediationScript(
        {
          python_script: 'def handler(event, context):\n    return {}\n',
          automation_assume_role: 'arn:aws:iam::123456789012:role/SO0111-Remediate-Custom-Test-unit',
          input_payload: { AutomationAssumeRole: 'sneaky' },
        },
        context(),
      ),
    ).rejects.toMatchObject({ name: 'ValidationError' });

    await expect(
      testRemediationScript(
        {
          python_script: 'def handler(event, context):\n    return {}\n',
          automation_assume_role: 'arn:aws:iam::123456789012:role/SO0111-Remediate-Custom-Test-unit',
          input_payload: { 'bad key': 'value' },
        },
        context(),
      ),
    ).rejects.toMatchObject({ name: 'ValidationError' });
  });

  test('a well-formed input_payload key becomes a document parameter and an InputPayload reference', async () => {
    await testRemediationScript(
      {
        python_script: 'def handler(event, context):\n    return {}\n',
        automation_assume_role: 'arn:aws:iam::123456789012:role/SO0111-Remediate-Custom-Test-unit',
        input_payload: { BucketName: 'my-bucket' },
      },
      context(),
    );

    const doc = capturedDocument();
    const parameters = doc.parameters as Record<string, unknown>;
    expect(parameters.BucketName).toBeDefined();
    const step = getFirstStep(doc);
    expect(step.inputs.InputPayload?.BucketName).toBe('{{ BucketName }}');
  });

  test('timeout_seconds is capped at 600 regardless of what the caller asked for', async () => {
    await testRemediationScript(
      {
        python_script: 'def handler(event, context):\n    return {}\n',
        automation_assume_role: 'arn:aws:iam::123456789012:role/SO0111-Remediate-Custom-Test-unit',
        timeout_seconds: 3600,
      },
      context(),
    );

    const doc = capturedDocument();
    const step = getFirstStep(doc);
    expect(step.timeoutSeconds).toBe(600);
  });

  test('the generated step declares onFailure/onCancel/maxAttempts (references/ssm-best-practices.md rules)', async () => {
    await testRemediationScript(
      {
        python_script: 'def handler(event, context):\n    return {}\n',
        automation_assume_role: 'arn:aws:iam::123456789012:role/SO0111-Remediate-Custom-Test-unit',
      },
      context(),
    );

    const doc = capturedDocument();
    const step = getFirstStep(doc);
    expect(step.onFailure).toBe('Abort');
    expect(step.onCancel).toBe('Abort');
    expect(step.maxAttempts).toBe(1);
  });

  test('every parameter declares an allowedPattern (references/ssm-best-practices.md rule)', async () => {
    await testRemediationScript(
      {
        python_script: 'def handler(event, context):\n    return {}\n',
        automation_assume_role: 'arn:aws:iam::123456789012:role/SO0111-Remediate-Custom-Test-unit',
        input_payload: { BucketName: 'my-bucket' },
      },
      context(),
    );

    const doc = capturedDocument();
    const parameters = doc.parameters as Record<string, { allowedPattern?: string }>;
    for (const definition of Object.values(parameters)) {
      expect(definition.allowedPattern).toBeDefined();
      expect(typeof definition.allowedPattern).toBe('string');
    }
  });

  test('requires automation_assume_role, and ignores an env var that is never set on the Lambda', async () => {
    // ASR_TEST_ASSUME_ROLE is deliberately absent from the deployed Lambda, so telling a remote
    // caller to set it is advice they cannot act on. Setting it must not satisfy the requirement,
    // and the message must not mention it.
    const originalEnv = process.env.ASR_TEST_ASSUME_ROLE;
    process.env.ASR_TEST_ASSUME_ROLE = 'arn:aws:iam::123456789012:role/SO0111-Remediate-Custom-Test-fromEnv';
    try {
      const attempt = testRemediationScript(
        { python_script: 'def handler(event, context):\n    return {}\n' },
        context(),
      );
      await expect(attempt).rejects.toThrow(/AutomationAssumeRole is required/);
      await expect(attempt).rejects.not.toThrow(/ASR_TEST_ASSUME_ROLE/);
      expect(ssmMock.commandCalls(CreateDocumentCommand)).toHaveLength(0);
    } finally {
      if (originalEnv === undefined) delete process.env.ASR_TEST_ASSUME_ROLE;
      else process.env.ASR_TEST_ASSUME_ROLE = originalEnv;
    }
  });

  test('rejects a role outside the only prefix the server may PassRole, before creating a document', async () => {
    // The MCP server's role scopes iam:PassRole to SO0111-Remediate-Custom-Test-*. Anything else is
    // refused by StartAutomationExecution with a raw IAM AccessDenied, which the executor records as
    // failureMessage on an HTTP 200 — a caller-side mistake reported as a failed script.
    await expect(
      testRemediationScript(
        {
          python_script: 'def handler(event, context):\n    return {}\n',
          automation_assume_role: 'arn:aws:iam::123456789012:role/SO0111-Remediate-Custom-SC-2.0.0-DynamoDB.2',
        },
        context(),
      ),
    ).rejects.toThrow(/must begin with "SO0111-Remediate-Custom-Test-"/);
    expect(ssmMock.commandCalls(CreateDocumentCommand)).toHaveLength(0);
  });

  test('rejects a permitted-prefix role belonging to another account', async () => {
    await expect(
      testRemediationScript(
        {
          python_script: 'def handler(event, context):\n    return {}\n',
          automation_assume_role: 'arn:aws:iam::999988887777:role/SO0111-Remediate-Custom-Test-unit',
        },
        context({ accountId: '123456789012' }),
      ),
    ).rejects.toThrow(/must be a role in account 123456789012, got 999988887777/);
    expect(ssmMock.commandCalls(CreateDocumentCommand)).toHaveLength(0);
  });
});

describe('testRemediationScript — rendered document size guard', () => {
  const testRemediationScript = createTestRemediationScript(fixedClock, noopSleeper);

  test('rejects a script whose rendered document exceeds the 64 KB SSM quota, before calling CreateDocument', async () => {
    // A near-max-length script alone fits the schema's own max(60000), but once wrapped in a
    // literal block scalar every line picks up 2 spaces of indentation from js-yaml — with
    // enough short lines that overhead alone is what pushes the rendered document over SSM's
    // 64 KB CreateDocument quota.
    const line = '# x\n'; // 4 chars/line — maximizes line count (and indentation overhead) per char budget.
    const oversizedScript = 'def handler(event, context):\n' + line.repeat(14_900) + '    return {}\n';
    expect(oversizedScript.length).toBeLessThanOrEqual(60000);

    await expect(
      testRemediationScript(
        {
          python_script: oversizedScript,
          automation_assume_role: 'arn:aws:iam::123456789012:role/SO0111-Remediate-Custom-Test-unit',
        },
        context(),
      ),
    ).rejects.toThrow(/exceeding SSM's 65536-byte CreateDocument quota/);

    expect(ssmMock.commandCalls(CreateDocumentCommand)).toHaveLength(0);
  });

  test('accepts a script whose rendered document stays under the quota', async () => {
    const result = await testRemediationScript(
      {
        python_script: 'def handler(event, context):\n    return {}\n',
        automation_assume_role: 'arn:aws:iam::123456789012:role/SO0111-Remediate-Custom-Test-unit',
      },
      context(),
    );

    expect(result.status).toBe('Success');
  });
});

describe('testRemediationScript — input value length guard', () => {
  const testRemediationScript = createTestRemediationScript(fixedClock, noopSleeper);

  test("rejects an input_payload value that would fail the document's own 10,000-char allowedPattern, before calling CreateDocument", async () => {
    await expect(
      testRemediationScript(
        {
          python_script: 'def handler(event, context):\n    return {}\n',
          automation_assume_role: 'arn:aws:iam::123456789012:role/SO0111-Remediate-Custom-Test-unit',
          input_payload: { BucketName: 'x'.repeat(10001) },
        },
        context(),
      ),
    ).rejects.toThrow(/longer than 10000 characters or contains a control character/);

    expect(ssmMock.commandCalls(CreateDocumentCommand)).toHaveLength(0);
  });

  test('accepts an input_payload value at exactly the 10,000-char bound', async () => {
    const result = await testRemediationScript(
      {
        python_script: 'def handler(event, context):\n    return {}\n',
        automation_assume_role: 'arn:aws:iam::123456789012:role/SO0111-Remediate-Custom-Test-unit',
        input_payload: { BucketName: 'x'.repeat(10000) },
      },
      context(),
    );

    expect(result.status).toBe('Success');
  });

  test('checks the JSON-stringified length of a non-string value, not the raw value', async () => {
    // A large object serializes to well over 10,000 characters even though the raw
    // input_payload value itself is a small array of short numbers.
    await expect(
      testRemediationScript(
        {
          python_script: 'def handler(event, context):\n    return {}\n',
          automation_assume_role: 'arn:aws:iam::123456789012:role/SO0111-Remediate-Custom-Test-unit',
          input_payload: { Numbers: Array.from({ length: 3000 }, (_, i) => i) },
        },
        context(),
      ),
    ).rejects.toThrow(/longer than 10000 characters or contains a control character/);
  });
});

describe('testRemediationScript — AutomationAssumeRole partition tolerance', () => {
  const testRemediationScript = createTestRemediationScript(fixedClock, noopSleeper);

  test('accepts a role ARN in a partition other than aws/aws-cn/aws-us-gov', async () => {
    // The partition is read from the ARN rather than matched against a fixed list —
    // the generated document's allowedPattern must not silently reject an ARN valid
    // in a partition it doesn't enumerate.
    const result = await testRemediationScript(
      {
        python_script: 'def handler(event, context):\n    return {}\n',
        automation_assume_role: 'arn:aws-iso:iam::123456789012:role/SO0111-Remediate-Custom-Test-iso',
      },
      context(),
    );

    expect(result.status).toBe('Success');
    const doc = capturedDocument();
    const parameters = doc.parameters as Record<string, { allowedPattern: string }>;
    expect(
      new RegExp(parameters.AutomationAssumeRole.allowedPattern).test(
        'arn:aws-iso:iam::123456789012:role/SO0111-Remediate-Custom-Test-iso',
      ),
    ).toBe(true);
  });

  test('rejects a path-qualified role ARN before creating the document, naming the constraint', async () => {
    // The server's PassRole grant is a resource match on `role/SO0111-Remediate-Custom-Test-*`.
    // A path-qualified role (`role/service-role/<prefix>x`) carries the prefix in its final
    // segment but does not match that resource, so accepting it here only deferred the refusal
    // to an opaque IAM denial inside StartAutomationExecution.
    const pathQualifiedRole = 'arn:aws:iam::123456789012:role/service-role/SO0111-Remediate-Custom-Test-path';

    await expect(
      testRemediationScript(
        {
          python_script: 'def handler(event, context):\n    return {}\n',
          automation_assume_role: pathQualifiedRole,
        },
        context(),
      ),
    ).rejects.toThrow(/carries an IAM path/);
    expect(ssmMock.commandCalls(CreateDocumentCommand)).toHaveLength(0);
  });
});
