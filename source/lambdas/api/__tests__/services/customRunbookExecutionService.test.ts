// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { FindingTableItem } from '@asr/data-models';
import { Logger } from '@aws-lambda-powertools/logger';
import { AwsSecurityFinding, GetFindingsCommand, SecurityHubClient } from '@aws-sdk/client-securityhub';
import {
  DescribeExecutionCommand,
  GetExecutionHistoryCommand,
  HistoryEvent,
  SFNClient,
  StartExecutionCommand,
} from '@aws-sdk/client-sfn';
import { mockClient } from 'aws-sdk-client-mock';
import { DynamoDBTestSetup } from '../../../common/__tests__/dynamodbSetup';
import { findingsTableName, remediationHistoryTableName } from '../../../common/__tests__/envSetup';
import { asFindingId } from '../../../common/__tests__/utils';
import { RemediationHistoryRepository } from '../../../common/repositories/remediationHistoryRepository';
import { NotFoundError } from '../../../common/utils/httpErrors';
import { CustomRunbookExecutionService } from '../../services/customRunbookExecutionService';

const EXECUTION_ARN = 'arn:aws:states:us-east-1:123456789012:execution:orchestrator:run-1';
const OTHER_EXECUTION_ARN = 'arn:aws:states:us-east-1:123456789012:execution:orchestrator:run-0';
const FINDING_ID = 'arn:aws:securityhub:us-east-1:123456789012:finding/abc';
const ACCOUNT = '123456789012';

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

const sfnMock = mockClient(SFNClient);
const securityHubMock = mockClient(SecurityHubClient);

describe('CustomRunbookExecutionService', () => {
  const logger = new Logger({ serviceName: 'test', logLevel: 'SILENT' });
  let service: CustomRunbookExecutionService;
  let historyWriter: RemediationHistoryRepository;
  let now: Date;

  const createFinding = (overrides: Partial<FindingTableItem> = {}): FindingTableItem => ({
    findingType: 'security-control/S3.1',
    findingId: asFindingId(FINDING_ID),
    findingDescription: 'Test finding',
    accountId: ACCOUNT,
    resourceId: 'arn:aws:s3:::test-bucket',
    resourceType: 'AWS::S3::Bucket',
    resourceTypeNormalized: 'awss3bucket',
    severity: 'HIGH',
    severityNormalized: 3,
    region: 'us-east-1',
    remediationStatus: 'SUCCESS',
    securityHubUpdatedAtTime: '2026-01-01T00:00:00Z',
    lastUpdatedTime: '2026-01-01T00:00:00Z',
    'securityHubUpdatedAtTime#findingId': `2026-01-01T00:00:00Z#${FINDING_ID}`,
    'severityNormalized#securityHubUpdatedAtTime#findingId': `3#2026-01-01T00:00:00Z#${FINDING_ID}`,
    findingJSON: new Uint8Array(),
    findingIdControl: 'security-control/S3.1',
    FINDING_CONSTANT: 'finding' as const,
    creationTime: '2026-01-01T00:00:00Z',
    suppressed: false,
    expireAt: 0,
    ...overrides,
  });

  async function addHistory(time: string, executionId: string, overrides: Partial<FindingTableItem> = {}) {
    now = new Date(time);
    await historyWriter.createRemediationHistory(createFinding(overrides), executionId);
  }

  const event = (type: string, extra: Partial<HistoryEvent> = {}): HistoryEvent => ({
    id: 1,
    type: type as HistoryEvent['type'],
    timestamp: new Date('2026-02-01T00:00:00Z'),
    ...extra,
  });

  beforeAll(async () => {
    await DynamoDBTestSetup.initialize();
    await DynamoDBTestSetup.createRemediationHistoryTable(remediationHistoryTableName);
    await DynamoDBTestSetup.createFindingsTable(findingsTableName);
  });

  afterAll(async () => {
    await DynamoDBTestSetup.deleteTable(remediationHistoryTableName);
    await DynamoDBTestSetup.deleteTable(findingsTableName);
  });

  beforeEach(async () => {
    sfnMock.reset();
    securityHubMock.reset();
    await DynamoDBTestSetup.clearTable(remediationHistoryTableName, 'remediationHistory');
    now = new Date('2026-02-01T00:00:00Z');
    historyWriter = new RemediationHistoryRepository(
      'test-writer',
      remediationHistoryTableName,
      DynamoDBTestSetup.getDocClient(),
      findingsTableName,
      { now: () => now },
    );
    service = new CustomRunbookExecutionService(
      logger,
      () => new SFNClient({}),
      () => new SecurityHubClient({}),
    );
  });

  describe('executeRunbook', () => {
    const stubFinding = (finding: AwsSecurityFinding | undefined) =>
      securityHubMock.on(GetFindingsCommand).resolves({ Findings: finding ? [finding] : [] });

    it('reports an unknown finding as not found without starting anything', async () => {
      stubFinding(undefined);

      await expect(service.executeRunbook(FINDING_ID, 'Remediate', undefined)).rejects.toThrow(NotFoundError);
      await expect(service.executeRunbook(FINDING_ID, 'Remediate', undefined)).rejects.toThrow(
        `Finding not found: ${FINDING_ID}`,
      );
      expect(sfnMock.commandCalls(StartExecutionCommand)).toHaveLength(0);
    });

    it('refuses a finding that names no account to a caller limited to some accounts', async () => {
      // Security Hub types the account as required, but the guard must still hold if a finding omits it.
      const { AwsAccountId: _omitted, ...withoutAccount } = securityFinding();
      stubFinding(withoutAccount as AwsSecurityFinding);

      await expect(service.executeRunbook(FINDING_ID, 'Remediate', [ACCOUNT])).rejects.toThrow(NotFoundError);
      expect(sfnMock.commandCalls(StartExecutionCommand)).toHaveLength(0);
    });
  });

  describe('getExecutionStatus', () => {
    it('returns nothing, and calls no Step Functions API, when none of the executions are in the callers accounts', async () => {
      await addHistory('2026-02-01T00:00:00Z', EXECUTION_ARN);

      const result = await service.getExecutionStatus(FINDING_ID, ['999999999999']);

      expect(result).toEqual({ executions: [], count: 0 });
      expect(sfnMock.commandCalls(DescribeExecutionCommand)).toHaveLength(0);
    });

    it('keeps failure events only, newest ten, and reads their details from whichever record the event carries', async () => {
      await addHistory('2026-02-01T00:00:00Z', EXECUTION_ARN);
      sfnMock.on(DescribeExecutionCommand).resolves({ status: 'ABORTED' });
      const filler = Array.from({ length: 12 }, () => event('LambdaFunctionFailed'));
      sfnMock.on(GetExecutionHistoryCommand).resolves({
        events: [
          event('TaskFailed', {
            taskFailedEventDetails: {
              resourceType: 'lambda',
              resource: 'invoke',
              error: 'task-error',
              cause: 'task-cause',
            },
          }),
          event('LambdaFunctionFailed', {
            lambdaFunctionFailedEventDetails: { error: 'lambda-error', cause: 'lambda-cause' },
          }),
          event('ExecutionAborted'),
          event('TaskTimedOut', { stateEnteredEventDetails: { name: 'RunSsm', input: '{}' } }),
          event('TaskSucceeded'),
          event('ExecutionStarted'),
          ...filler,
        ],
      });

      const result = await service.getExecutionStatus(FINDING_ID, undefined);

      const failures = result.executions[0].step_function_details?.failure_events ?? [];
      expect(failures).toHaveLength(10);
      expect(failures.slice(0, 4)).toEqual([
        {
          timestamp: '2026-02-01T00:00:00.000Z',
          type: 'TaskFailed',
          error: 'task-error',
          cause: 'task-cause',
          state: undefined,
        },
        {
          timestamp: '2026-02-01T00:00:00.000Z',
          type: 'LambdaFunctionFailed',
          error: 'lambda-error',
          cause: 'lambda-cause',
          state: undefined,
        },
        {
          timestamp: '2026-02-01T00:00:00.000Z',
          type: 'ExecutionAborted',
          error: undefined,
          cause: undefined,
          state: undefined,
        },
        {
          timestamp: '2026-02-01T00:00:00.000Z',
          type: 'TaskTimedOut',
          error: undefined,
          cause: undefined,
          state: 'RunSsm',
        },
      ]);
      expect(failures.map((f) => f.type)).not.toContain('TaskSucceeded');
      expect(failures.map((f) => f.type)).not.toContain('ExecutionStarted');
    });

    it('shows an execution without a timestamp or stop date, and with no failure events', async () => {
      await addHistory('2026-02-01T00:00:00Z', EXECUTION_ARN);
      sfnMock.on(DescribeExecutionCommand).resolves({ status: 'RUNNING' });
      sfnMock.on(GetExecutionHistoryCommand).resolves({});

      const result = await service.getExecutionStatus(FINDING_ID, undefined);

      expect(result.executions[0].step_function_details).toEqual({
        execution_status: 'RUNNING',
        stopped_at: undefined,
        failure_events: [],
      });
    });

    it('still lists the executions, without details, when Step Functions cannot be read', async () => {
      await addHistory('2026-02-01T00:00:00Z', EXECUTION_ARN);
      sfnMock.on(DescribeExecutionCommand).rejects(new Error('AccessDenied'));
      sfnMock.on(GetExecutionHistoryCommand).resolves({ events: [] });
      const warn = jest.spyOn(logger, 'warn');

      const result = await service.getExecutionStatus(FINDING_ID, undefined);

      expect(result.count).toBe(1);
      expect(result.executions[0]).not.toHaveProperty('step_function_details');
      expect(warn).toHaveBeenCalledWith('Failed to fetch Step Functions execution details', {
        executionArn: EXECUTION_ARN,
        error: 'AccessDenied',
      });
      warn.mockRestore();
    });

    it('reports a failure that is not an Error object by its text', async () => {
      await addHistory('2026-02-01T00:00:00Z', EXECUTION_ARN);
      sfnMock.on(DescribeExecutionCommand).callsFake(() => Promise.reject('throttled'));
      sfnMock.on(GetExecutionHistoryCommand).resolves({ events: [] });
      const warn = jest.spyOn(logger, 'warn');

      await service.getExecutionStatus(FINDING_ID, undefined);

      expect(warn).toHaveBeenCalledWith(
        'Failed to fetch Step Functions execution details',
        expect.objectContaining({ error: 'throttled' }),
      );
      warn.mockRestore();
    });

    it('returns nothing for a finding with no history, without calling Step Functions', async () => {
      const result = await service.getExecutionStatus(FINDING_ID, undefined);

      expect(result).toEqual({ executions: [], count: 0 });
      expect(sfnMock.commandCalls(DescribeExecutionCommand)).toHaveLength(0);
    });

    it('lists the executions newest first and adds Step Functions failure details to the newest only', async () => {
      await addHistory('2026-02-01T00:00:00Z', OTHER_EXECUTION_ARN, { remediationStatus: 'SUCCESS' });
      await addHistory('2026-02-02T00:00:00Z', EXECUTION_ARN, { remediationStatus: 'FAILED', error: 'boom' });
      sfnMock.on(DescribeExecutionCommand).resolves({
        status: 'FAILED',
        stopDate: new Date('2026-02-02T00:05:00Z'),
      });
      sfnMock.on(GetExecutionHistoryCommand).resolves({
        events: [
          event('ExecutionFailed', {
            executionFailedEventDetails: { error: 'States.TaskFailed', cause: 'the cause' },
          }),
          event('TaskSucceeded'),
        ],
      });

      const result = await service.getExecutionStatus(FINDING_ID, undefined);

      expect(result.count).toBe(2);
      expect(result.executions.map((e) => e.execution_id)).toEqual([EXECUTION_ARN, OTHER_EXECUTION_ARN]);
      expect(result.executions[0]).toMatchObject({
        finding_id: FINDING_ID,
        status: 'FAILED',
        account_id: ACCOUNT,
        region: 'us-east-1',
        resource_id: 'arn:aws:s3:::test-bucket',
        error: 'boom',
        step_function_details: {
          execution_status: 'FAILED',
          stopped_at: '2026-02-02T00:05:00.000Z',
          failure_events: [
            {
              timestamp: '2026-02-01T00:00:00.000Z',
              type: 'ExecutionFailed',
              error: 'States.TaskFailed',
              cause: 'the cause',
              state: undefined,
            },
          ],
        },
      });
      expect(result.executions[1]).not.toHaveProperty('step_function_details');
      expect(sfnMock.commandCalls(DescribeExecutionCommand)[0].args[0].input).toEqual({ executionArn: EXECUTION_ARN });
      expect(sfnMock.commandCalls(GetExecutionHistoryCommand)[0].args[0].input).toEqual({
        executionArn: EXECUTION_ARN,
        reverseOrder: true,
        maxResults: 50,
      });
    });

    it('only shows executions in the callers accounts', async () => {
      await addHistory('2026-02-01T00:00:00Z', OTHER_EXECUTION_ARN, { accountId: '111111111111' });
      await addHistory('2026-02-02T00:00:00Z', EXECUTION_ARN);
      sfnMock.on(DescribeExecutionCommand).resolves({ status: 'SUCCEEDED' });
      sfnMock.on(GetExecutionHistoryCommand).resolves({ events: [] });

      const result = await service.getExecutionStatus(FINDING_ID, ['111111111111']);

      expect(result.executions.map((e) => e.execution_id)).toEqual([OTHER_EXECUTION_ARN]);
      expect(sfnMock.commandCalls(DescribeExecutionCommand)[0].args[0].input).toEqual({
        executionArn: OTHER_EXECUTION_ARN,
      });
    });
  });
});
