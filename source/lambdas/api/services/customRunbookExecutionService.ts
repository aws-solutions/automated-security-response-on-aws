// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { Logger } from '@aws-lambda-powertools/logger';
import {
  SFNClient,
  StartExecutionCommand,
  DescribeExecutionCommand,
  GetExecutionHistoryCommand,
} from '@aws-sdk/client-sfn';
import { SecurityHubClient, GetFindingsCommand, AwsSecurityFinding } from '@aws-sdk/client-securityhub';
import { FindingId, remediationStatus } from '@asr/data-models';
import { RemediationHistoryRepository } from '../../common/repositories/remediationHistoryRepository';
import { createDynamoDBClient } from '../../common/utils/dynamodb';
import { apiLambdaEnvironment } from '../apiLambdaEnvironment';
import { NotFoundError } from '../../common/utils/httpErrors';

/** Response body for the execute_runbook action. */
export interface ExecuteRunbookResult {
  status: 'STARTED';
  execution_arn?: string;
  finding_id: string;
}

export interface StepFunctionFailureDetails {
  execution_status?: string;
  stopped_at?: string;
  failure_events?: Array<{
    timestamp?: string;
    type?: string;
    error?: string;
    cause?: string;
    state?: string;
  }>;
}

/**
 * One remediation execution for a finding, as returned by `getExecutionStatus`.
 * Mirrors the remediation-history record projected for the API, with the most
 * recent execution optionally enriched with Step Functions failure details.
 */
export interface ExecutionStatusItem {
  finding_id: FindingId;
  execution_id?: string;
  status: remediationStatus;
  resource_id: string;
  account_id: string;
  region: string;
  last_updated: string;
  error?: string;
  step_function_details?: StepFunctionFailureDetails;
}

/** Action verbs the Orchestrator Custom Action envelope accepts for a runbook execution. */
export type RemediationActionType = 'Remediate' | 'RemediateAndGenerateTicket';

/** EventBridge "Security Hub Findings - Custom Action" envelope the Orchestrator consumes. */
export interface ExecuteRunbookEnvelope {
  'detail-type': 'Security Hub Findings - Custom Action';
  source: 'aws.securityhub';
  detail: {
    actionName: RemediationActionType;
    actionDescription: string;
    findings: AwsSecurityFinding[];
  };
}

/**
 * Builds the EventBridge envelope the Orchestrator Step Function expects. The
 * Step Function's first state extracts `$.detail-type`, `$.detail.findings`, and
 * `$.detail.actionName`. Exported for unit testing.
 */
export function buildExecuteRunbookEnvelope(
  finding: AwsSecurityFinding,
  actionType: RemediationActionType,
): ExecuteRunbookEnvelope {
  return {
    'detail-type': 'Security Hub Findings - Custom Action',
    source: 'aws.securityhub',
    detail: {
      actionName: actionType,
      actionDescription: `MCP execute_runbook - ${actionType}`,
      findings: [finding],
    },
  };
}

/**
 * Execution side of the custom-runbook API: starts a remediation through the
 * Orchestrator Step Function and reports execution status from the remediation
 * history table (enriched with Step Functions failure details). Owns its own SFN
 * and Security Hub clients and the history repository.
 */
export class CustomRunbookExecutionService {
  private stepFunctionsClient: SFNClient | undefined;
  private securityHubClient: SecurityHubClient | undefined;
  private remediationHistoryRepository: RemediationHistoryRepository | undefined;

  constructor(
    private readonly logger: Logger,
    private readonly stepFunctionsClientFactory: () => SFNClient = () => new SFNClient({ maxAttempts: 3 }),
    private readonly securityHubClientFactory: () => SecurityHubClient = () =>
      new SecurityHubClient({ maxAttempts: 3 }),
  ) {}

  private getStepFunctionsClient(): SFNClient {
    this.stepFunctionsClient ??= this.stepFunctionsClientFactory();
    return this.stepFunctionsClient;
  }

  private getSecurityHubClient(): SecurityHubClient {
    this.securityHubClient ??= this.securityHubClientFactory();
    return this.securityHubClient;
  }

  private getRemediationHistoryRepository(): RemediationHistoryRepository {
    if (!this.remediationHistoryRepository) {
      const env = apiLambdaEnvironment();
      this.remediationHistoryRepository = new RemediationHistoryRepository(
        'CustomRunbookExecutionService',
        env.REMEDIATION_HISTORY_TABLE_NAME,
        createDynamoDBClient({ maxAttempts: 10 }),
        env.FINDINGS_TABLE_NAME,
      );
    }
    return this.remediationHistoryRepository;
  }

  /**
   * Starts the Orchestrator Step Function for a finding and returns the execution ARN.
   * `authorizedAccounts` binds this mutation to the caller's account boundary
   * (undefined = admin, all accounts), mirroring `getExecutionStatus`.
   */
  async executeRunbook(
    findingId: string,
    actionType: RemediationActionType,
    authorizedAccounts: string[] | undefined,
  ): Promise<ExecuteRunbookResult> {
    const securityHub = this.getSecurityHubClient();
    const env = apiLambdaEnvironment();

    // Fetch the full ASFF finding — the orchestrator Step Function needs it.
    const findingRes = await securityHub.send(
      new GetFindingsCommand({
        Filters: { Id: [{ Value: findingId, Comparison: 'EQUALS' }] },
        MaxResults: 1,
      }),
    );
    const finding = findingRes.Findings?.[0];
    if (!finding) throw new NotFoundError(`Finding not found: ${findingId}`);

    if (authorizedAccounts && !authorizedAccounts.includes(finding.AwsAccountId ?? '')) {
      // Same 404 as the miss above so the response cannot be used to probe
      // whether a finding outside the caller's accounts exists.
      this.logger.warn('executeRunbook rejected: finding outside authorized accounts', {
        findingId,
        findingAccountId: finding.AwsAccountId,
      });
      throw new NotFoundError(`Finding not found: ${findingId}`);
    }

    const input = JSON.stringify(buildExecuteRunbookEnvelope(finding, actionType));

    const result = await this.getStepFunctionsClient().send(
      new StartExecutionCommand({
        stateMachineArn: env.ORCHESTRATOR_ARN,
        input,
      }),
    );

    return { status: 'STARTED', execution_arn: result.executionArn, finding_id: findingId };
  }

  /**
   * Returns recent executions for a finding, account-scoped to the caller's
   * authorized accounts (undefined = admin, all accounts), with the most recent
   * execution enriched with Step Functions failure details.
   */
  async getExecutionStatus(
    findingId: string,
    authorizedAccounts: string[] | undefined,
  ): Promise<{ executions: ExecutionStatusItem[]; count: number }> {
    const historyRepo = this.getRemediationHistoryRepository();
    const allItems = await historyRepo.findRecentByFindingId(findingId);

    // Account-scope the results: Account Operators may only see executions in
    // their authorized accounts. Admins and Delegated Admins see all.
    const items = authorizedAccounts
      ? allItems.filter((item) => authorizedAccounts.includes(item.accountId))
      : allItems;

    // Enrich the most recent execution with Step Functions failure details so the caller
    // can see the failed step and error cause without opening the console.
    const mostRecentExecutionArn = items[0]?.executionId;
    const stepFunctionDetails = await this.fetchStepFunctionFailureDetails(mostRecentExecutionArn);

    const executions = items.map(
      (item, idx): ExecutionStatusItem => ({
        finding_id: item.findingId,
        execution_id: item.executionId,
        status: item.remediationStatus,
        resource_id: item.resourceId,
        account_id: item.accountId,
        region: item.region,
        last_updated: item.lastUpdatedTime,
        error: item.error,
        ...(idx === 0 && stepFunctionDetails ? { step_function_details: stepFunctionDetails } : {}),
      }),
    );

    return { executions, count: executions.length };
  }

  /**
   * Fetches Step Functions execution history (most recent failure events) for a given execution ARN.
   * Returns undefined if the ARN is missing or the call fails — the status response still lists the execution.
   */
  private async fetchStepFunctionFailureDetails(
    executionArn: string | undefined,
  ): Promise<StepFunctionFailureDetails | undefined> {
    if (!executionArn) return undefined;

    try {
      const sfn = this.getStepFunctionsClient();

      const [describe, history] = await Promise.all([
        sfn.send(new DescribeExecutionCommand({ executionArn })),
        sfn.send(
          new GetExecutionHistoryCommand({
            executionArn,
            reverseOrder: true,
            maxResults: 50,
          }),
        ),
      ]);

      const failureEvents = (history.events ?? [])
        .filter((e) => {
          const type = e.type ?? '';
          return type.includes('Failed') || type.includes('Aborted') || type.includes('TimedOut');
        })
        .slice(0, 10)
        .map((e) => {
          const details =
            e.executionFailedEventDetails ??
            e.taskFailedEventDetails ??
            e.lambdaFunctionFailedEventDetails ??
            e.stateEnteredEventDetails ??
            {};
          return {
            timestamp: e.timestamp?.toISOString?.(),
            type: e.type,
            error: 'error' in details ? details.error : undefined,
            cause: 'cause' in details ? details.cause : undefined,
            state: 'name' in details ? details.name : undefined,
          };
        });

      return {
        execution_status: describe.status,
        stopped_at: describe.stopDate?.toISOString(),
        failure_events: failureEvents,
      };
    } catch (error) {
      this.logger.warn('Failed to fetch Step Functions execution details', {
        executionArn,
        error: error instanceof Error ? error.message : String(error),
      });
      return undefined;
    }
  }
}
