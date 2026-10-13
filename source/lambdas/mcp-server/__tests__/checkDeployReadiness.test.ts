// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { GetRoleCommand, IAMClient } from '@aws-sdk/client-iam';
import { DescribeDocumentCommand, ListDocumentsCommand, SSMClient } from '@aws-sdk/client-ssm';
import { mockClient } from 'aws-sdk-client-mock';
import { checkDeployReadiness } from '../backends/common/checkDeployReadiness';
import type { ExecutionContext } from '../backends/types';

const iamMock = mockClient(IAMClient);
const ssmMock = mockClient(SSMClient);

const context: ExecutionContext = {
  region: 'us-east-1',
  requestId: 'request-1',
};

const args = {
  control_id: 'S3.9',
  remediation_name: 'BlockPublicAccess',
  namespace: 'asr',
};

function namedError(name: string): Error {
  return Object.assign(new Error(name), { name });
}

beforeEach(() => {
  iamMock.reset();
  ssmMock.reset();
});

afterAll(() => {
  iamMock.restore();
  ssmMock.restore();
});

describe('checkDeployReadiness', () => {
  test('passes when the child document, role, and Security Control wrapper are active', async () => {
    // GIVEN
    iamMock.on(GetRoleCommand).resolves({});
    ssmMock.on(DescribeDocumentCommand, { Name: 'ASR-BlockPublicAccess' }).resolves({
      Document: { Status: 'Active' },
    });
    ssmMock.on(ListDocumentsCommand).resolves({
      DocumentIdentifiers: [{ Name: 'ASR-SC_1.0.0_S3.9' }],
    });
    ssmMock.on(DescribeDocumentCommand, { Name: 'ASR-SC_1.0.0_S3.9' }).resolves({
      Document: { Status: 'Active' },
    });

    // WHEN
    const result = await checkDeployReadiness(args, context);

    // THEN
    expect(result.isReady).toBe(true);
    expect(result.checks).toEqual([
      expect.objectContaining({ check: 'child-document', status: 'PASS' }),
      expect.objectContaining({ check: 'iam-role', status: 'PASS' }),
      expect.objectContaining({ check: 'sc-wrapper', status: 'PASS' }),
    ]);
  });

  test('reports missing child documents and roles as actionable failures', async () => {
    // GIVEN
    ssmMock.on(DescribeDocumentCommand, { Name: 'ASR-BlockPublicAccess' }).rejects(namedError('InvalidDocument'));
    iamMock.on(GetRoleCommand).rejects(namedError('NoSuchEntityException'));

    // WHEN
    const result = await checkDeployReadiness({ ...args, check_sc_wrapper: false }, context);

    // THEN
    expect(result.isReady).toBe(false);
    expect(result.checks).toHaveLength(2);
    expect(result.checks[0]).toMatchObject({ check: 'child-document', status: 'FAIL' });
    expect(result.checks[0].detail).toContain('deploy_runbook');
    expect(result.checks[1]).toMatchObject({ check: 'iam-role', status: 'FAIL' });
  });

  test('reports a wrapper that disappears after listing as a failure instead of throwing', async () => {
    // GIVEN
    iamMock.on(GetRoleCommand).resolves({});
    ssmMock.on(DescribeDocumentCommand, { Name: 'ASR-BlockPublicAccess' }).resolves({
      Document: { Status: 'Active' },
    });
    ssmMock.on(ListDocumentsCommand).resolves({
      DocumentIdentifiers: [{ Name: 'ASR-SC_1.0.0_S3.9' }],
    });
    ssmMock.on(DescribeDocumentCommand, { Name: 'ASR-SC_1.0.0_S3.9' }).rejects(namedError('InvalidDocument'));

    // WHEN
    const result = await checkDeployReadiness(args, context);

    // THEN
    expect(result.isReady).toBe(false);
    expect(result.checks[2]).toMatchObject({ check: 'sc-wrapper', status: 'FAIL' });
    expect(result.checks[2].detail).toContain('no longer exists');
  });

  test('does not treat non-active documents as deploy-ready', async () => {
    // GIVEN
    iamMock.on(GetRoleCommand).resolves({});
    ssmMock.on(DescribeDocumentCommand, { Name: 'ASR-BlockPublicAccess' }).resolves({
      Document: { Status: 'Creating' },
    });
    ssmMock.on(ListDocumentsCommand).resolves({
      DocumentIdentifiers: [{ Name: 'ASR-SC_1.0.0_S3.9' }],
    });
    ssmMock.on(DescribeDocumentCommand, { Name: 'ASR-SC_1.0.0_S3.9' }).resolves({
      Document: { Status: 'Failed', StatusInformation: 'Invalid content' },
    });

    // WHEN
    const result = await checkDeployReadiness(args, context);

    // THEN
    expect(result.isReady).toBe(false);
    expect(result.checks[0].detail).toContain('Creating');
    expect(result.checks[2].detail).toContain('Invalid content');
  });

  test('reports a fully scanned account with no matching wrapper', async () => {
    // GIVEN
    iamMock.on(GetRoleCommand).resolves({});
    ssmMock.on(DescribeDocumentCommand, { Name: 'ASR-BlockPublicAccess' }).resolves({
      Document: { Status: 'Active' },
    });
    ssmMock.on(ListDocumentsCommand).resolves({ DocumentIdentifiers: [] });

    // WHEN
    const result = await checkDeployReadiness(args, context);

    // THEN
    expect(result.isReady).toBe(false);
    expect(result.checks[2]).toMatchObject({ check: 'sc-wrapper', status: 'FAIL', truncated: false });
  });

  test('requires the deployment namespace', async () => {
    // WHEN / THEN
    await expect(
      checkDeployReadiness(
        {
          control_id: args.control_id,
          remediation_name: args.remediation_name,
        },
        context,
      ),
    ).rejects.toMatchObject({ name: 'MissingParameterError' });
    expect(ssmMock.commandCalls(DescribeDocumentCommand)).toHaveLength(0);
    expect(iamMock.commandCalls(GetRoleCommand)).toHaveLength(0);
  });
});
