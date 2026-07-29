// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Integration test for the finding-synchronization Lambda.
//
// The Lambda serves only the sweep state machine, so every test drives the exported handler() with one
// of the three Step Functions tasks (enumerate-accounts / sync-account-slice / mark-sweep-done). It runs
// end-to-end — through the slice engine, the finding data service, and the cursor/finding repositories —
// down to a REAL DynamoDB Local table. Only true external boundaries are mocked: Security Hub
// (GetFindings / ListMembers), SSM/filter config, the tracer, and the metrics HTTP endpoint. DynamoDB is
// never mocked, so key schemas, conditional writes, cursor isolation, and resume behaviour are all
// exercised against real database semantics.

import { DynamoDBTestSetup } from '../../common/__tests__/dynamodbSetup';
// Import after mocks so module-scope wiring in the handler picks them up.
import { Context } from 'aws-lambda';
import {
  AwsSecurityFinding,
  GetFindingsCommand,
  GetFindingsCommandInput,
  GetFindingsCommandOutput,
  ListMembersCommand,
  ListMembersCommandOutput,
  RecordState,
  SecurityHubClient,
  SeverityLabel,
} from '@aws-sdk/client-securityhub';
import { GetCommand, PutCommand, QueryCommand, ScanCommand } from '@aws-sdk/lib-dynamodb';
import { mockClient } from 'aws-sdk-client-mock';
import { configTableName, findingsTableName, mockAccountId } from '../../common/__tests__/envSetup';
import { handler } from '../synchronizationHandler';

// The handler builds its DynamoDB client at request time via createDynamoDBClient(); point that at the
// DynamoDB Local test client. initialize() is synchronous in practice (it only constructs the client).
void DynamoDBTestSetup.initialize();
const testClient = DynamoDBTestSetup.getDocClient();

// Each jest.mock factory references its `mock*` const LAZILY (through an arrow), never directly. Jest
// hoists these factories above the top-level `import { handler }`, whose module-scope imports resolve
// these mocked modules at load time — before the `const mock*` declarations below have initialized.
// A direct reference would hit the temporal dead zone ('Cannot access mock* before initialization');
// wrapping it defers the read until the mocked function is actually called, by which point the const
// exists. This keeps the plain top-level import (no require()) while staying hoist-order-safe.
const mockCreateDynamoDBClient = jest.fn(() => testClient);
jest.mock('../../common/utils/dynamodb', () => ({
  createDynamoDBClient: () => mockCreateDynamoDBClient(),
}));

// Filter config comes from SSM; mock the SSM cache so applyFilters() sees "all filters disabled"
// (every finding passes) without reaching a real parameter store.
const mockGetCachedParametersByPath = jest.fn();
jest.mock('../../common/utils/ssmCache', () => ({
  getCachedParameter: jest.fn(() => Promise.resolve('test-uuid')),
  getCachedParametersByPath: (path: unknown) => mockGetCachedParametersByPath(path),
  clearSSMCache: jest.fn(),
  getSSMClient: jest.fn(() => ({})),
}));

const mockCaptureAWSv3Client = jest.fn((client) => client);
jest.mock('../../common/utils/tracer', () => ({
  getTracer: jest.fn(() => ({
    captureAWSv3Client: (client: unknown) => mockCaptureAWSv3Client(client),
    captureLambdaHandler: () => (_t: any, _k: string, descriptor: PropertyDescriptor) => descriptor,
  })),
}));

// Silence real metric emission (HTTPS to the solutions endpoint).
const mockSendMetrics = jest.fn((_metricsData?: unknown) => Promise.resolve());
jest.mock('../../common/utils/metricsUtils', () => ({
  sendMetrics: (metricsData: unknown) => mockSendMetrics(metricsData),
  buildFailureMetric: jest.fn(() => ({ status: 'FAILED' })),
}));

const securityHubMock = mockClient(SecurityHubClient);

// The cursor and sweep live in the findings table under these partitions; readers never touch them. The
// cursor is scoped by the enumerated member account id.
const CURSOR_PARTITION = 'SYNC_CURSOR';
const SWEEP_PARTITION = 'SYNC_SWEEP';
const SWEEP_KEY = 'global';
// The sync-account-slice tests below key their cursor under mockAccountId.
const SYNC_SCOPE = mockAccountId;

describe('Synchronization Lambda (integration, DynamoDB Local)', () => {
  let context: Context;

  const createMockFinding = (id: string, overrides: Partial<AwsSecurityFinding> = {}): AwsSecurityFinding =>
    ({
      SchemaVersion: '2018-10-08',
      Id: `arn:aws:securityhub:us-east-1:123456789012:security-control/Lambda.3/finding/${id}`,
      ProductArn: 'arn:aws:securityhub:us-east-1::product/aws/securityhub',
      GeneratorId: 'security-control/Lambda.3',
      AwsAccountId: '123456789012',
      Region: 'us-east-1',
      Title: `Test Finding ${id}`,
      Description: `Test description for ${id}`,
      Severity: { Label: SeverityLabel.HIGH, Normalized: 70 },
      Types: ['Software and Configuration Checks'],
      Resources: [{ Id: `arn:aws:lambda:us-east-1:123456789012:function:${id}`, Type: 'AwsLambdaFunction' }],
      CreatedAt: '2023-01-01T12:00:00Z',
      UpdatedAt: '2023-01-01T12:00:00Z',
      Compliance: { Status: 'FAILED', SecurityControlId: 'Lambda.3' },
      RecordState: RecordState.ACTIVE,
      ...overrides,
    }) as AwsSecurityFinding;

  // ListMembers drives the enumerate-accounts task. Defaults to a single member; override to test
  // multi-account and empty-org paths.
  const stubMemberAccounts = (...accountIds: string[]) => {
    securityHubMock.on(ListMembersCommand).resolves({
      Members: accountIds.map((AccountId) => ({ AccountId })),
    } as ListMembersCommandOutput);
  };

  // Seed the remediation-config table so getSupportedControlIds() returns real controlIds to sync.
  const seedControls = async (...controlIds: string[]) => {
    for (const controlId of controlIds) {
      await testClient.send(
        new PutCommand({ TableName: configTableName, Item: { controlId, automatedRemediationEnabled: true } }),
      );
    }
  };

  // GetFindings responses keyed only by page order (the engine issues one paginated walk per chunk;
  // with a single control the whole run is one chunk).
  const stubFindingsPages = (...pages: Array<{ findings: AwsSecurityFinding[]; nextToken?: string }>) => {
    let call = 0;
    securityHubMock.on(GetFindingsCommand).callsFake((): GetFindingsCommandOutput => {
      const page = pages[Math.min(call, pages.length - 1)];
      call++;
      return { Findings: page.findings, NextToken: page.nextToken } as GetFindingsCommandOutput;
    });
  };

  // Runs one account-slice task for the given account (default: mockAccountId scope).
  const runSlice = (accountId: string = SYNC_SCOPE) => handler({ task: 'sync-account-slice', accountId }, context);

  const getCursor = async (accountId: string = SYNC_SCOPE) => {
    const result = await testClient.send(
      new GetCommand({
        TableName: findingsTableName,
        Key: { findingType: CURSOR_PARTITION, findingId: accountId },
      }),
    );
    return result.Item;
  };

  const getSweepRecord = async () =>
    (
      await testClient.send(
        new GetCommand({ TableName: findingsTableName, Key: { findingType: SWEEP_PARTITION, findingId: SWEEP_KEY } }),
      )
    ).Item;

  const countStoredFindings = async () => {
    const result = await testClient.send(
      new QueryCommand({
        TableName: findingsTableName,
        IndexName: 'allFindings-securityHubUpdatedAtTime-GSI',
        KeyConditionExpression: 'FINDING_CONSTANT = :c',
        ExpressionAttributeValues: { ':c': 'finding' },
      }),
    );
    return result.Items ?? [];
  };

  beforeAll(async () => {
    await DynamoDBTestSetup.createFindingsTable(findingsTableName);
    await DynamoDBTestSetup.createConfigTable(configTableName);
  });

  afterAll(async () => {
    await DynamoDBTestSetup.deleteTable(findingsTableName);
    await DynamoDBTestSetup.deleteTable(configTableName);
  });

  beforeEach(async () => {
    await DynamoDBTestSetup.clearTable(findingsTableName, 'findings');
    await DynamoDBTestSetup.clearTable(configTableName, 'config');

    securityHubMock.reset();
    mockSendMetrics.mockClear();
    mockCaptureAWSv3Client.mockImplementation((client) => client ?? testClient);
    mockCreateDynamoDBClient.mockReturnValue(testClient);

    // All filters disabled → every finding passes applyFilters().
    mockGetCachedParametersByPath.mockResolvedValue([]);

    // Default to a single member account so enumerate-accounts yields one account.
    stubMemberAccounts(mockAccountId);

    // Plenty of time so a slice runs to completion (well above the 30s safety margin).
    context = {
      callbackWaitsForEmptyEventLoop: false,
      functionName: 'SO0111-ASR-SynchronizationFindingsLambda',
      functionVersion: '1',
      invokedFunctionArn: 'arn:aws:lambda:us-east-1:123456789012:function:sync',
      memoryLimitInMB: '512',
      awsRequestId: 'test-request-id',
      logGroupName: '/aws/lambda/sync',
      logStreamName: 'test',
      getRemainingTimeInMillis: () => 300_000,
      done: jest.fn(),
      fail: jest.fn(),
      succeed: jest.fn(),
    };
  });

  describe('Task validation', () => {
    it('rejects an unknown task without touching the database', async () => {
      // The Lambda only accepts the three known state-machine tasks; anything else is malformed input.
      await expect(handler({ task: 'nope' } as any, context)).rejects.toThrow(/Unknown synchronization task/);
      expect(securityHubMock.commandCalls(GetFindingsCommand)).toHaveLength(0);
    });
  });

  describe('Importing findings end-to-end (sync-account-slice)', () => {
    it('writes fetched findings to the table and reports completion', async () => {
      await seedControls('Lambda.3');
      stubFindingsPages({ findings: [createMockFinding('f1'), createMockFinding('f2')] });

      const result = await runSlice('444455556666');

      expect(result.done).toBe(true);
      expect(result.madeProgress).toBe(true);
      expect(result.processedFindings).toBe(2);

      // The findings are actually persisted and queryable via the reader GSI.
      const stored = await countStoredFindings();
      expect(stored).toHaveLength(2);
      // findingType is derived from the finding's control (GeneratorId 'security-control/Lambda.3').
      expect(stored.map((f) => f.findingType)).toEqual(['security-control/Lambda.3', 'security-control/Lambda.3']);

      expect(mockSendMetrics).toHaveBeenCalledWith(
        expect.objectContaining({ synchronization_status: 'SUCCESS', total_processed: 2, sync_done: true }),
      );
    });

    it('paginates Security Hub and imports every page', async () => {
      await seedControls('Lambda.3');
      stubFindingsPages(
        { findings: [createMockFinding('p1a'), createMockFinding('p1b')], nextToken: 'page-2' },
        { findings: [createMockFinding('p2a')] },
      );

      const result = await runSlice();

      expect(result.done).toBe(true);
      expect(result.processedFindings).toBe(3);
      expect(await countStoredFindings()).toHaveLength(3);
      expect(securityHubMock.commandCalls(GetFindingsCommand).length).toBeGreaterThanOrEqual(2);
    });

    it('skips archived / passed findings (no row written)', async () => {
      await seedControls('Lambda.3');
      stubFindingsPages({
        findings: [createMockFinding('active'), createMockFinding('archived', { RecordState: RecordState.ARCHIVED })],
      });

      const result = await runSlice();

      expect(result.done).toBe(true);
      // Only the active finding lands in the table; archived is a no-op on a fresh table.
      const stored = await countStoredFindings();
      expect(stored).toHaveLength(1);
      expect(stored[0].findingId).toContain('active');
    });
  });

  describe('Cursor persistence and resume', () => {
    it('marks the cursor done when the whole backlog is imported', async () => {
      await seedControls('Lambda.3');
      stubFindingsPages({ findings: [createMockFinding('f1')] });

      await runSlice();

      const cursor = await getCursor();
      expect(cursor?.done).toBe(true);
      expect(cursor?.completedControlIds).toEqual(['Lambda.3']);
      expect(cursor?.processedFindings).toBe(1);
    });

    it('resumes an unfinished pass on the next slice instead of restarting', async () => {
      await seedControls('A.1', 'B.1');

      // First slice: after the first page the budget collapses, so the engine stops before the next page
      // — mid-chunk, leaving the pass unfinished and resumable. The page returns a nextToken so there IS a
      // next page for the budget check to guard.
      let remaining = 300_000;
      context.getRemainingTimeInMillis = () => remaining;
      securityHubMock.on(GetFindingsCommand).callsFake((): GetFindingsCommandOutput => {
        // Collapse budget below the 30s margin so the next shouldStop() check halts the slice.
        remaining = 1_000;
        return { Findings: [createMockFinding('first')], NextToken: 'more-pages' } as GetFindingsCommandOutput;
      });

      const first = await runSlice();
      // Not done but progressing → the state machine's Choice would loop this same account.
      expect(first.done).toBe(false);
      expect(first.madeProgress).toBe(true);

      const midCursor = await getCursor();
      expect(midCursor?.done).toBe(false);
      // At least one control is not yet completed.
      expect((midCursor?.completedControlIds as string[]).length).toBeLessThan(2);

      // Second slice: full budget, drains the rest and completes.
      remaining = 300_000;
      context.getRemainingTimeInMillis = () => 300_000;
      securityHubMock.reset();
      stubFindingsPages({ findings: [createMockFinding('rest')] });

      const second = await runSlice();
      expect(second.done).toBe(true);

      const finalCursor = await getCursor();
      expect((finalCursor?.completedControlIds as string[]).sort()).toEqual(['A.1', 'B.1']);
    });

    it('starts a fresh pass when the previous pass was already done', async () => {
      await seedControls('Lambda.3');
      stubFindingsPages({ findings: [createMockFinding('f1')] });
      await runSlice();
      const firstCursor = await getCursor();
      expect(firstCursor?.done).toBe(true);
      const firstVersion = firstCursor?.version as number;

      // Second slice after done → cursor reset then re-driven to done again.
      securityHubMock.reset();
      stubFindingsPages({ findings: [createMockFinding('f2')] });
      await runSlice();

      const secondCursor = await getCursor();
      expect(secondCursor?.done).toBe(true);
      // A reset restarts versioning below where the prior finished pass left off.
      expect(secondCursor?.version as number).toBeLessThanOrEqual(firstVersion);
    });
  });

  describe('Cursor isolation from finding reads', () => {
    it('keeps the cursor item out of the findings reader GSI', async () => {
      await seedControls('Lambda.3');
      stubFindingsPages({ findings: [createMockFinding('f1')] });

      await runSlice();

      // The reader GSI is keyed on FINDING_CONSTANT='finding'; the cursor carries no such attribute,
      // so a real query returns only the finding, never the cursor.
      const readerVisible = await countStoredFindings();
      expect(readerVisible).toHaveLength(1);
      expect(readerVisible.every((item) => item.findingType !== CURSOR_PARTITION)).toBe(true);

      // But the cursor really is in the base table (a full scan sees it).
      const all = await testClient.send(new ScanCommand({ TableName: findingsTableName }));
      expect((all.Items ?? []).some((item) => item.findingType === CURSOR_PARTITION)).toBe(true);
    });
  });

  describe('Per-finding result accounting', () => {
    it('counts a stale (older) update as FAILED via the real conditional write', async () => {
      await seedControls('Lambda.3');

      // First slice stores a finding updated at 2023-06.
      stubFindingsPages({ findings: [createMockFinding('dup', { UpdatedAt: '2023-06-01T00:00:00Z' })] });
      await runSlice();

      // Second slice offers the SAME finding with an OLDER timestamp → putIfNewer condition fails.
      securityHubMock.reset();
      stubFindingsPages({ findings: [createMockFinding('dup', { UpdatedAt: '2023-01-01T00:00:00Z' })] });
      await runSlice();

      expect(mockSendMetrics).toHaveBeenLastCalledWith(
        expect.objectContaining({ total_processed: 1, total_failed: 1, total_successful: 0 }),
      );
      // Still exactly one row; the stale update did not overwrite.
      expect(await countStoredFindings()).toHaveLength(1);
    });

    it('counts a finding missing a required field as ERROR and writes no row', async () => {
      await seedControls('Lambda.3');

      // Severity.Label is required to build the finding-table item; a finding without it survives the
      // archived/filter checks but fails construction, so the data service classifies it ERROR (distinct
      // from a FAILED conditional write). This is the only path that exercises the error bucket.
      stubFindingsPages({
        findings: [createMockFinding('broken', { Severity: { Normalized: 70 } })],
      });

      const result = await runSlice();

      // The slice still completes — a single unprocessable finding is tallied, not thrown.
      expect(result.done).toBe(true);
      expect(mockSendMetrics).toHaveBeenLastCalledWith(
        expect.objectContaining({
          synchronization_status: 'SUCCESS',
          total_processed: 1,
          total_error: 1,
          total_successful: 0,
          total_failed: 0,
        }),
      );
      // Nothing was persisted for the unprocessable finding.
      expect(await countStoredFindings()).toHaveLength(0);
    });
  });

  describe('Error handling', () => {
    it('rethrows so the state machine can catch and tolerate the failure', async () => {
      await seedControls('Lambda.3');
      securityHubMock.on(GetFindingsCommand).rejects(new Error('Security Hub API error'));

      await expect(runSlice()).rejects.toThrow('Security Hub API error');

      // A failed slice emits a FAILED metric so a tolerated account is still observable.
      expect(mockSendMetrics).toHaveBeenCalledWith(expect.objectContaining({ synchronization_status: 'FAILED' }));
    });
  });

  // The state machine invokes the Lambda with `task`-typed payloads. These tasks carry no orchestration
  // themselves (no self-invoke, no next-account, no sweep lock) — the state machine owns fan-out and the
  // resume loop. Each task returns a plain object the state machine branches on.
  describe('State machine tasks (Step Functions driven)', () => {
    it('enumerate-accounts lists members and initializes the sweep denominator', async () => {
      stubMemberAccounts('111111111111', '222222222222', '333333333333');

      const result = await handler({ task: 'enumerate-accounts' }, context);

      expect(result.accountIds).toEqual(['111111111111', '222222222222', '333333333333']);
      expect(result.totalAccounts).toBe(3);
      const sweep = await getSweepRecord();
      expect(sweep?.totalAccounts).toBe(3);
      expect(sweep?.done).toBe(false);
    });

    it('enumerate-accounts reports a zero-account denominator for an empty organization', async () => {
      stubMemberAccounts(); // empty organization

      const result = await handler({ task: 'enumerate-accounts' }, context);

      expect(result.accountIds).toEqual([]);
      expect(result.totalAccounts).toBe(0);
      expect(securityHubMock.commandCalls(GetFindingsCommand)).toHaveLength(0);
    });

    it('sync-account-slice scopes GetFindings to the requested account and reports branch-able flags', async () => {
      await seedControls('Lambda.3');
      stubFindingsPages({ findings: [createMockFinding('f1')] });

      const result = await handler({ task: 'sync-account-slice', accountId: '444455556666' }, context);

      expect(result.accountId).toBe('444455556666');
      expect(result.done).toBe(true);
      expect(result.madeProgress).toBe(true);
      // The finding pull was scoped to the requested account.
      const getFindingsInputs = securityHubMock
        .commandCalls(GetFindingsCommand)
        .map((call) => call.args[0].input as GetFindingsCommandInput);
      expect(getFindingsInputs[0].Filters?.AwsAccountId).toEqual([{ Value: '444455556666', Comparison: 'EQUALS' }]);
      // ...and ordered highest-severity-then-most-recent so the most important findings land first even
      // when a slice runs out of budget partway through. This ordering is the wiring the state machine
      // relies on; assert it survives the delegation from the handler through to the GetFindings call.
      expect(getFindingsInputs[0].SortCriteria).toEqual([
        { Field: 'SeverityNormalized', SortOrder: 'desc' },
        { Field: 'UpdatedAt', SortOrder: 'desc' },
      ]);
      // The slice checkpoints its own cursor under that account's scope.
      expect((await getCursor('444455556666'))?.done).toBe(true);
    });

    it('sync-account-slice reports not-done with progress when the account is cut short', async () => {
      await seedControls('A.1', 'B.1');
      let remaining = 300_000;
      context.getRemainingTimeInMillis = () => remaining;
      securityHubMock.on(GetFindingsCommand).callsFake((): GetFindingsCommandOutput => {
        remaining = 1_000; // collapse the budget so the slice stops mid-account
        return { Findings: [createMockFinding('first')], NextToken: 'more-pages' } as GetFindingsCommandOutput;
      });

      const result = await handler({ task: 'sync-account-slice', accountId: '444455556666' }, context);

      // The state machine's Choice loops this same account because it is not done but made progress.
      expect(result.done).toBe(false);
      expect(result.madeProgress).toBe(true);
    });

    it('sync-account-slice emits the current account and sweep progress in metrics', async () => {
      await seedControls('Lambda.3');
      stubMemberAccounts('111111111111', '222222222222', '333333333333');
      await handler({ task: 'enumerate-accounts' }, context);
      stubFindingsPages({ findings: [createMockFinding('f1')] });

      await handler({ task: 'sync-account-slice', accountId: '111111111111' }, context);

      // The first account completed, so the derived sweep count read into metrics is 1 of 3.
      expect(mockSendMetrics).toHaveBeenCalledWith(
        expect.objectContaining({
          synchronization_status: 'SUCCESS',
          account_id: '111111111111',
          completed_accounts: 1,
          total_accounts: 3,
        }),
      );
    });

    it('mark-sweep-done flags the sweep complete', async () => {
      stubMemberAccounts('111111111111');
      await handler({ task: 'enumerate-accounts' }, context);

      const result = await handler({ task: 'mark-sweep-done' }, context);

      expect(result.done).toBe(true);
      expect((await getSweepRecord())?.done).toBe(true);
    });
  });
});
