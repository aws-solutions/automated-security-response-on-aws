// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { mockClient } from 'aws-sdk-client-mock';
import { SecurityHubClient, GetFindingHistoryCommand } from '@aws-sdk/client-securityhub';
import { DynamoDBClient } from '@aws-sdk/client-dynamodb';
import { DynamoDBDocumentClient, QueryCommand } from '@aws-sdk/lib-dynamodb';
import { getFindingHistory } from '../backends/common/securityHub';
import type { ExecutionContext } from '../backends/common/../types';
import { ValidationError } from '../backends/common/errors';

const securityHubMock = mockClient(SecurityHubClient);
const ddbMock = mockClient(DynamoDBDocumentClient);

function context(overrides: Partial<ExecutionContext> = {}): ExecutionContext {
  return { region: 'us-east-1', requestId: 'test-request', ...overrides };
}

const FINDING_ID = 'arn:aws:securityhub:us-east-1:123456789012:security-control/S3.1/finding/aaaa-bbbb-cccc-dddd';

beforeEach(() => {
  securityHubMock.reset();
  ddbMock.reset();
  securityHubMock.on(GetFindingHistoryCommand).resolves({ Records: [] });
});

/** Key condition of the findingType fallback: the control partition, narrowed to one finding's rows. */
const FALLBACK_KEY_CONDITION = 'findingType = :ft AND begins_with(#sk, :fidPrefix)';

describe('getFindingHistory — cross-finding leakage', () => {
  // Which rows the findingType fallback returns — only this finding's, found even on a busy
  // control, newest-first — is covered against DynamoDB Local in
  // common/__tests__/findingRemediationHistoryRepository.test.ts rather than by asserting the
  // query's shape here.

  test('the derived findingType is bounded by the /finding segment, not just the presence of "security-control/"', async () => {
    ddbMock.on(QueryCommand, { IndexName: 'findingId-lastUpdatedTime-GSI' }).resolves({ Items: [] });
    ddbMock.on(QueryCommand, { KeyConditionExpression: FALLBACK_KEY_CONDITION }).resolves({ Items: [] });

    await getFindingHistory({ finding_id: FINDING_ID }, context({ remediationHistoryTableName: 'history-table' }));

    const fallbackCall = ddbMock.commandCalls(QueryCommand, { KeyConditionExpression: FALLBACK_KEY_CONDITION })[0];
    expect(fallbackCall.args[0].input.ExpressionAttributeValues).toMatchObject({ ':ft': 'security-control/S3.1' });
  });

  test('a subscription-format (unconsolidated) finding ID has no security-control/.../finding segment and skips the fallback query entirely', async () => {
    const unconsolidatedFindingId =
      'arn:aws:securityhub:us-east-1:123456789012:subscription/cis-aws-foundations-benchmark/v/1.2.0/2.1/finding/aaaa';
    ddbMock.on(QueryCommand, { IndexName: 'findingId-lastUpdatedTime-GSI' }).resolves({ Items: [] });

    const result = await getFindingHistory(
      { finding_id: unconsolidatedFindingId },
      context({ remediationHistoryTableName: 'history-table' }),
    );

    expect(result.remediationHistory).toEqual([]);
    expect(ddbMock.commandCalls(QueryCommand, { KeyConditionExpression: FALLBACK_KEY_CONDITION })).toHaveLength(0);
  });

  test('a fallback query matching nothing for this finding returns an empty array', async () => {
    ddbMock.on(QueryCommand, { IndexName: 'findingId-lastUpdatedTime-GSI' }).resolves({ Items: [] });
    ddbMock.on(QueryCommand, { KeyConditionExpression: FALLBACK_KEY_CONDITION }).resolves({ Items: [] });

    const result = await getFindingHistory(
      { finding_id: FINDING_ID },
      context({ remediationHistoryTableName: 'history-table' }),
    );

    expect(result.remediationHistory).toEqual([]);
  });

  test('the GSI query already being finding-scoped needs no extra filtering', async () => {
    ddbMock.on(QueryCommand, { IndexName: 'findingId-lastUpdatedTime-GSI' }).resolves({
      Items: [{ findingId: FINDING_ID, executionId: 'exec-1', remediationStatus: 'SUCCESS' }],
    });

    const result = await getFindingHistory(
      { finding_id: FINDING_ID },
      context({ remediationHistoryTableName: 'history-table' }),
    );

    expect(result.remediationHistory).toHaveLength(1);
    expect(ddbMock.commandCalls(QueryCommand, { KeyConditionExpression: FALLBACK_KEY_CONDITION })).toHaveLength(0);
  });
});

describe('getFindingHistory — AccessDenied distinct from empty', () => {
  let warnSpy: jest.SpyInstance;

  /** The structured record the Powertools logger emitted, parsed from its single JSON argument. */
  const loggedWarning = (): Record<string, unknown> =>
    JSON.parse(warnSpy.mock.calls[0][0] as string) as Record<string, unknown>;

  beforeEach(() => {
    warnSpy = jest.spyOn(console, 'warn').mockImplementation();
  });

  afterEach(() => {
    warnSpy.mockRestore();
  });

  test('AccessDeniedException surfaces as remediationHistoryAccessDenied=true, not a silent empty result', async () => {
    ddbMock.on(QueryCommand).rejects(Object.assign(new Error('denied'), { name: 'AccessDeniedException' }));

    const result = await getFindingHistory(
      { finding_id: FINDING_ID },
      context({ remediationHistoryTableName: 'history-table' }),
    );

    expect(result.remediationHistory).toEqual([]);
    expect(result.remediationHistoryAccessDenied).toBe(true);
    expect(warnSpy).toHaveBeenCalledTimes(1);
    expect(loggedWarning()).toMatchObject({
      level: 'WARN',
      message: 'DynamoDB remediation history query failed',
      error: 'denied',
    });
  });

  test('a genuinely empty history is remediationHistoryAccessDenied=false', async () => {
    ddbMock.on(QueryCommand).resolves({ Items: [] });

    const result = await getFindingHistory(
      { finding_id: FINDING_ID },
      context({ remediationHistoryTableName: 'history-table' }),
    );

    expect(result.remediationHistory).toEqual([]);
    expect(result.remediationHistoryAccessDenied).toBe(false);
    expect(warnSpy).not.toHaveBeenCalled();
  });

  test('a missing table (ResourceNotFoundException) is treated as no history, not thrown', async () => {
    ddbMock.on(QueryCommand).rejects(Object.assign(new Error('no table'), { name: 'ResourceNotFoundException' }));

    const result = await getFindingHistory(
      { finding_id: FINDING_ID },
      context({ remediationHistoryTableName: 'history-table' }),
    );

    expect(result.remediationHistory).toEqual([]);
    expect(result.remediationHistoryAccessDenied).toBe(false);
    expect(warnSpy).toHaveBeenCalledTimes(1);
    expect(loggedWarning()).toMatchObject({
      level: 'WARN',
      message: 'DynamoDB remediation history query failed',
      error: 'no table',
    });
  });

  test('no table configured for this host is also remediationHistoryAccessDenied=false', async () => {
    const result = await getFindingHistory({ finding_id: FINDING_ID }, context());

    expect(result.remediationHistory).toEqual([]);
    expect(result.remediationHistoryAccessDenied).toBe(false);
    expect(ddbMock.calls()).toHaveLength(0);
  });

  test('an unexpected DynamoDB error is not swallowed', async () => {
    ddbMock.on(QueryCommand).rejects(Object.assign(new Error('boom'), { name: 'InternalServerError' }));

    await expect(
      getFindingHistory({ finding_id: FINDING_ID }, context({ remediationHistoryTableName: 'history-table' })),
    ).rejects.toThrow('boom');
  });

  test('ProvisionedThroughputExceededException (throttling) propagates rather than being reported as empty', async () => {
    ddbMock
      .on(QueryCommand)
      .rejects(Object.assign(new Error('throttled'), { name: 'ProvisionedThroughputExceededException' }));

    await expect(
      getFindingHistory({ finding_id: FINDING_ID }, context({ remediationHistoryTableName: 'history-table' })),
    ).rejects.toThrow('throttled');
  });

  test('ValidationException (malformed query) propagates rather than being reported as empty', async () => {
    ddbMock.on(QueryCommand).rejects(Object.assign(new Error('bad query'), { name: 'ValidationException' }));

    await expect(
      getFindingHistory({ finding_id: FINDING_ID }, context({ remediationHistoryTableName: 'history-table' })),
    ).rejects.toThrow('bad query');
  });
});

describe('getFindingHistory — max_results', () => {
  test('honors a caller-supplied max_results instead of a hardcoded 10 for remediation history', async () => {
    const items = Array.from({ length: 30 }, (_, i) => ({
      findingId: FINDING_ID,
      executionId: `exec-${i}`,
      remediationStatus: 'SUCCESS',
    }));
    ddbMock.on(QueryCommand, { IndexName: 'findingId-lastUpdatedTime-GSI' }).resolves({ Items: items });

    const result = await getFindingHistory(
      { finding_id: FINDING_ID, max_results: 25 },
      context({ remediationHistoryTableName: 'history-table' }),
    );

    expect(result.remediationHistory).toHaveLength(25);
    const call = ddbMock.commandCalls(QueryCommand, { IndexName: 'findingId-lastUpdatedTime-GSI' })[0];
    expect(call.args[0].input.Limit).toBe(25);
  });

  test('defaults remediation history to 10 when max_results is not supplied', async () => {
    ddbMock
      .on(QueryCommand, { IndexName: 'findingId-lastUpdatedTime-GSI' })
      .resolves({ Items: [{ findingId: FINDING_ID, executionId: 'exec-1', remediationStatus: 'SUCCESS' }] });

    await getFindingHistory({ finding_id: FINDING_ID }, context({ remediationHistoryTableName: 'history-table' }));

    const call = ddbMock.commandCalls(QueryCommand, { IndexName: 'findingId-lastUpdatedTime-GSI' })[0];
    expect(call.args[0].input.Limit).toBe(10);
  });
});

// This tool runs directly in the MCP Lambda under its own organization-wide Security
// Hub permissions, so the per-account rules the REST API enforces never run for it. The
// restriction below is the only thing scoping an Account Operator to their own accounts.
describe('getFindingHistory — per-account authorization', () => {
  beforeEach(() => {
    securityHubMock.reset();
    securityHubMock.on(GetFindingHistoryCommand).resolves({ Records: [] });
  });

  it('reads history for a finding in an account the caller is authorized for', async () => {
    const result = await getFindingHistory(
      { finding_id: FINDING_ID },
      context({ authorizedAccountIds: ['123456789012'] }),
    );

    expect(result.findingId).toBe(FINDING_ID);
    expect(securityHubMock.commandCalls(GetFindingHistoryCommand)).toHaveLength(1);
  });

  it('refuses a finding in an account the caller is not authorized for', async () => {
    await expect(
      getFindingHistory({ finding_id: FINDING_ID }, context({ authorizedAccountIds: ['999999999999'] })),
    ).rejects.toThrow(/not authorized for account 123456789012/);

    // Denied before the call, so no finding data is fetched at all.
    expect(securityHubMock.commandCalls(GetFindingHistoryCommand)).toHaveLength(0);
  });

  it('refuses when the finding id encodes no account, rather than allowing it through', async () => {
    // Per ADR 0010 not every finding id is an ARN. An id that proves no ownership must
    // not become a way around the restriction.
    await expect(
      getFindingHistory({ finding_id: 'bare-macie-finding-uid' }, context({ authorizedAccountIds: ['123456789012'] })),
    ).rejects.toThrow(/cannot determine which account/);

    expect(securityHubMock.commandCalls(GetFindingHistoryCommand)).toHaveLength(0);
  });

  it('applies no restriction when the caller is unrestricted', async () => {
    // undefined means Admin tier or a machine principal — both see every account, as
    // they do through the REST API.
    const result = await getFindingHistory({ finding_id: FINDING_ID }, context({ authorizedAccountIds: undefined }));

    expect(result.findingId).toBe(FINDING_ID);
    expect(securityHubMock.commandCalls(GetFindingHistoryCommand)).toHaveLength(1);
  });
});

describe('getFindingHistory — the finding’s region, not the host region', () => {
  const CROSS_REGION_FINDING_ID =
    'arn:aws:securityhub:us-west-2:123456789012:security-control/EC2.10/finding/eeee-ffff-0000-1111';

  beforeEach(() => {
    securityHubMock.reset();
    securityHubMock.on(GetFindingHistoryCommand).resolves({ Records: [] });
  });

  it('addresses the region named in the finding ARN and builds the product ARN for it', async () => {
    // A findings search returns rows from every aggregated region, so this ARN is
    // ordinary input for a us-east-1 deployment. Matched against a us-east-1 product
    // ARN, Security Hub refuses a finding that exists.
    await getFindingHistory({ finding_id: CROSS_REGION_FINDING_ID }, context({ region: 'us-east-1' }));

    const call = securityHubMock.commandCalls(GetFindingHistoryCommand)[0];
    expect(call.args[0].input.FindingIdentifier?.ProductArn).toBe(
      'arn:aws:securityhub:us-west-2::product/aws/securityhub',
    );
    await expect(call.thisValue.config.region()).resolves.toBe('us-west-2');
  });

  it('keeps the host region for a finding id that encodes none', async () => {
    await getFindingHistory({ finding_id: 'bare-macie-finding-uid' }, context({ region: 'eu-west-1' }));

    const call = securityHubMock.commandCalls(GetFindingHistoryCommand)[0];
    expect(call.args[0].input.FindingIdentifier?.ProductArn).toBe(
      'arn:aws:securityhub:eu-west-1::product/aws/securityhub',
    );
    await expect(call.thisValue.config.region()).resolves.toBe('eu-west-1');
  });

  it('lets an explicit product_arn override the derived one', async () => {
    await getFindingHistory(
      { finding_id: CROSS_REGION_FINDING_ID, product_arn: 'arn:aws:securityhub:us-west-2::product/custom/scanner' },
      context({ region: 'us-east-1' }),
    );

    const call = securityHubMock.commandCalls(GetFindingHistoryCommand)[0];
    expect(call.args[0].input.FindingIdentifier?.ProductArn).toBe(
      'arn:aws:securityhub:us-west-2::product/custom/scanner',
    );
  });

  it('reports a finding Security Hub will not serve as a validation error, not a server error', async () => {
    const invalidAccess = new Error('Unable to access history for given finding id');
    invalidAccess.name = 'InvalidAccessException';
    securityHubMock.on(GetFindingHistoryCommand).rejects(invalidAccess);

    await expect(getFindingHistory({ finding_id: CROSS_REGION_FINDING_ID }, context())).rejects.toThrow(
      ValidationError,
    );
    await expect(getFindingHistory({ finding_id: CROSS_REGION_FINDING_ID }, context())).rejects.toThrow(
      /product ARN arn:aws:securityhub:us-west-2::product\/aws\/securityhub/,
    );
  });

  it('leaves any other Security Hub failure untouched so it is not mistaken for bad input', async () => {
    const throttled = new Error('Rate exceeded');
    throttled.name = 'ThrottlingException';
    securityHubMock.on(GetFindingHistoryCommand).rejects(throttled);

    await expect(getFindingHistory({ finding_id: CROSS_REGION_FINDING_ID }, context())).rejects.toThrow(throttled);
  });
});
