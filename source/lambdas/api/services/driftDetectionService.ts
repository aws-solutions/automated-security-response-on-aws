// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { Logger } from '@aws-lambda-powertools/logger';
import {
  SSMClient,
  ListDocumentsCommand,
  DescribeDocumentCommand,
  CreateDocumentCommand,
  UpdateDocumentCommand,
  UpdateDocumentDefaultVersionCommand,
  StartAutomationExecutionCommand,
  GetAutomationExecutionCommand,
  InvalidDocument,
  DuplicateDocumentContent,
  AutomationExecutionNotFoundException,
} from '@aws-sdk/client-ssm';
import { SecurityHubClient, GetFindingsCommand } from '@aws-sdk/client-securityhub';
import { SECURITY_CONTROL_STANDARD_VERSION, TERMINAL_AUTOMATION_STATUSES } from '@asr/data-models';
import { Clock, getClock } from '../../common/utils/clock';
import { Sleeper, getSleeper } from '../../common/utils/sleeper';
import { MemberAccountCredentialsProvider, buildMemberSessionName } from './memberAccountCredentials';
import { apiLambdaEnvironment, isCustomRunbookDevLoopEnabled } from '../apiLambdaEnvironment';
import { NotFoundError, BadRequestError, ForbiddenError } from '../../common/utils/httpErrors';

const SOLUTION_PREFIX = 'SO0111';

const TERMINAL_STATUSES = TERMINAL_AUTOMATION_STATUSES;

/** One step of an SSM Automation execution, projected for the API response. */
export interface AutomationStep {
  name: string;
  status: string;
  error?: string;
}

export interface ExecutionPollResult {
  status: string;
  steps: AutomationStep[];
  durationMs: number;
}

interface PushDocumentResult {
  documentStatus: 'created' | 'updated';
  documentVersion: string;
}

/** Response body for the drift-detection `push` action. */
export interface DriftPushResult {
  action: 'push';
  control_id: string;
  account_id: string;
  document_name: string;
  document_version: string;
  document_status: 'created' | 'updated';
}

/** Response body for the drift-detection `execute` action. */
export interface DriftExecuteResult {
  action: 'execute';
  execution_id: string;
  status: string;
  duration_ms: number;
  steps: AutomationStep[];
}

/** Response body for the drift-detection `status` action. */
export interface DriftStatusResult {
  action: 'status';
  execution_id: string;
  status: string;
  steps: AutomationStep[];
  outputs?: Record<string, string[]>;
}

/**
 * Polls an SSM Automation execution until it reaches a terminal state or the
 * timeout elapses. Kept as a standalone export (rather than only a private
 * method) so it can be unit-tested in isolation.
 *
 * `Clock` and `Sleeper` are injected so the loop is testable without real
 * wall-clock waits: a test passes a fake `Sleeper` that advances a fake `Clock`,
 * exercising both the terminal-state and timeout exits in milliseconds.
 */
export async function pollAutomationExecution(
  ssmClient: SSMClient,
  executionId: string,
  {
    timeoutMs = 25_000,
    intervalMs = 2000,
    clock = getClock(),
    sleeper = getSleeper(),
  }: { timeoutMs?: number; intervalMs?: number; clock?: Clock; sleeper?: Sleeper } = {},
): Promise<ExecutionPollResult> {
  const startTime = clock.now().getTime();
  let status = 'InProgress';
  let steps: AutomationStep[] = [];

  while (clock.now().getTime() - startTime < timeoutMs) {
    await sleeper.sleep(intervalMs);
    const execResult = await ssmClient.send(new GetAutomationExecutionCommand({ AutomationExecutionId: executionId }));
    const execution = execResult.AutomationExecution;
    status = execution?.AutomationExecutionStatus ?? 'Unknown';
    steps =
      execution?.StepExecutions?.map((s) => ({
        name: s.StepName ?? '',
        status: s.StepStatus ?? '',
        error: s.FailureMessage,
      })) ?? [];

    if (TERMINAL_STATUSES.has(status)) break;
  }

  return { status, steps, durationMs: clock.now().getTime() - startTime };
}

/**
 * Developer fast-loop "drift detection" tool: push a runbook's SSM document into
 * a member account, execute it directly against a finding, and check status —
 * over the same Orchestrator Admin → Member credential chain the deployment path
 * uses. Extracted from the API handler so the handler stays thin and this
 * multi-step AWS orchestration is owned by a service.
 */
export class DriftDetectionService {
  private securityHubClient: SecurityHubClient | undefined;

  constructor(
    private readonly logger: Logger,
    private readonly credentialsProvider: MemberAccountCredentialsProvider = new MemberAccountCredentialsProvider(),
    private readonly securityHubClientFactory: () => SecurityHubClient = () =>
      new SecurityHubClient({ maxAttempts: 3 }),
    private readonly clock: Clock = getClock(),
    private readonly sleeper: Sleeper = getSleeper(),
  ) {}

  private getSecurityHubClient(): SecurityHubClient {
    this.securityHubClient ??= this.securityHubClientFactory();
    return this.securityHubClient;
  }

  /**
   * Fails closed unless the drift-detection dev-loop is explicitly enabled.
   *
   * `push`/`execute` write an SSM document and start an automation directly in a
   * member account, bypassing the versioned register/deploy path (no DynamoDB
   * record, no version, no test-status gate). A single enablement flag (unset in
   * production) keeps this developer fast-loop from becoming an unaudited
   * production write path. Every authorized use is logged as an audit line since
   * there is no dedicated audit table yet.
   */
  private authorizeDevLoopWrite(action: 'push' | 'execute', accountId: string, actor?: string): void {
    if (!isCustomRunbookDevLoopEnabled()) {
      throw new ForbiddenError(
        `drift_detection ${action} is a developer fast-loop tool and is disabled by default. ` +
          'Set CUSTOM_RUNBOOK_DEV_LOOP_ENABLED=true in a non-production deployment to enable it.',
      );
    }
    this.logger.info('AUDIT: custom-runbook dev-loop write authorized', {
      audit: true,
      action,
      accountId,
      actor: actor ?? 'unknown',
    });
  }

  /**
   * Returns an SSM client for the target member account, over the same Orchestrator
   * Admin → Member chain that role provisioning and document release use.
   */
  private async getMemberSsmClient(accountId: string, actor?: string): Promise<SSMClient> {
    const credentials = await this.credentialsProvider.getCredentials(
      accountId,
      buildMemberSessionName('drift-detection', actor),
    );
    return new SSMClient({ credentials, maxAttempts: 3 });
  }

  /**
   * Resolves the SSM Automation document name for a control ID by searching for
   * deployed ASR-Custom- documents in the target account. Avoids hardcoding the
   * standard or version — finds whatever custom document is deployed for this control.
   */
  private async resolveDocumentName(ssmClient: SSMClient, controlId: string): Promise<string> {
    // Only resolve ASR-Custom- documents — never return a built-in ASR- doc name,
    // otherwise a push would overwrite a shipped runbook.
    let nextToken: string | undefined;
    let pageCount = 0;
    const MAX_PAGES = 10;
    do {
      const result = await ssmClient.send(
        new ListDocumentsCommand({
          Filters: [
            { Key: 'Owner', Values: ['Self'] },
            { Key: 'DocumentType', Values: ['Automation'] },
          ],
          MaxResults: 50,
          NextToken: nextToken,
        }),
      );

      for (const doc of result.DocumentIdentifiers ?? []) {
        const name = doc.Name ?? '';
        if (name.startsWith('ASR-Custom-') && name.endsWith(`_${controlId}`)) {
          return name;
        }
      }
      nextToken = result.NextToken;
      pageCount++;
      if (pageCount >= MAX_PAGES && nextToken) {
        // Truncation must not masquerade as a genuine miss — push falls back to
        // creating a new document on NotFoundError, which would duplicate the
        // control's document if the real one is on an unvisited page.
        throw new Error(
          `Stopped searching for control ${controlId} after ${MAX_PAGES} pages of SSM documents ` +
            'without exhausting the inventory. Cannot determine whether a custom document already exists.',
        );
      }
    } while (nextToken);

    throw new NotFoundError(
      `No custom SSM Automation document found for control ${controlId}. Deploy the runbook first with deploy_runbook.`,
    );
  }

  /** Updates an existing document (promoting the version to default) — the document must exist. */
  private async updateExistingDocument(
    memberSsmClient: SSMClient,
    documentName: string,
    runbookYaml: string,
  ): Promise<PushDocumentResult> {
    let documentVersion: string;
    try {
      const updateResult = await memberSsmClient.send(
        new UpdateDocumentCommand({
          Name: documentName,
          Content: runbookYaml,
          DocumentVersion: '$LATEST',
          DocumentFormat: 'YAML',
        }),
      );
      documentVersion = updateResult.DocumentDescription?.DocumentVersion ?? '1';
    } catch (updateError: unknown) {
      if (!(updateError instanceof DuplicateDocumentContent)) throw updateError;
      // Content is identical — resolve the current version so promotion still runs.
      const described = await memberSsmClient.send(
        new DescribeDocumentCommand({ Name: documentName, DocumentVersion: '$LATEST' }),
      );
      documentVersion = described.Document?.DocumentVersion ?? '1';
    }

    // Promotion is what makes the version live — an unqualified execution runs the default.
    await memberSsmClient.send(
      new UpdateDocumentDefaultVersionCommand({
        Name: documentName,
        DocumentVersion: documentVersion,
      }),
    );
    return { documentStatus: 'updated', documentVersion };
  }

  /** Creates the document in the member account — for when it does not exist yet. */
  private async createNewDocument(
    memberSsmClient: SSMClient,
    documentName: string,
    runbookYaml: string,
  ): Promise<PushDocumentResult> {
    const createResult = await memberSsmClient.send(
      new CreateDocumentCommand({
        Name: documentName,
        Content: runbookYaml,
        DocumentType: 'Automation',
        DocumentFormat: 'YAML',
      }),
    );
    return { documentStatus: 'created', documentVersion: createResult.DocumentDescription?.DocumentVersion ?? '1' };
  }

  async push(controlId: string, runbookYaml: string, accountId: string, actor?: string): Promise<DriftPushResult> {
    this.authorizeDevLoopWrite('push', accountId, actor);
    const memberSsmClient = await this.getMemberSsmClient(accountId, actor);

    // Resolve existing custom document, or create with the standard custom naming convention.
    let documentName: string;
    try {
      documentName = await this.resolveDocumentName(memberSsmClient, controlId);
    } catch (error) {
      if (!(error instanceof NotFoundError)) throw error;
      documentName = `ASR-Custom-SC_${SECURITY_CONTROL_STANDARD_VERSION}_${controlId}`;
    }

    let documentExists: boolean;
    try {
      await memberSsmClient.send(new DescribeDocumentCommand({ Name: documentName }));
      documentExists = true;
    } catch (error: unknown) {
      if (!(error instanceof InvalidDocument)) {
        throw error;
      }
      documentExists = false;
    }

    const { documentStatus, documentVersion } = documentExists
      ? await this.updateExistingDocument(memberSsmClient, documentName, runbookYaml)
      : await this.createNewDocument(memberSsmClient, documentName, runbookYaml);

    return {
      action: 'push',
      control_id: controlId,
      account_id: accountId,
      document_name: documentName,
      document_version: documentVersion,
      document_status: documentStatus,
    };
  }

  async execute(controlId: string, accountId: string, findingId: string, actor?: string): Promise<DriftExecuteResult> {
    this.authorizeDevLoopWrite('execute', accountId, actor);

    // Fetch the finding from Security Hub
    const securityHub = this.getSecurityHubClient();
    const findingResult = await securityHub.send(
      new GetFindingsCommand({
        Filters: { Id: [{ Value: findingId, Comparison: 'EQUALS' }] },
        MaxResults: 1,
      }),
    );
    const finding = findingResult.Findings?.[0];
    if (!finding) throw new NotFoundError(`Finding not found: ${findingId}`);

    if (finding.AwsAccountId !== accountId) {
      // Log the true owner internally only — echoing finding.AwsAccountId to the
      // caller would disclose which account a foreign finding belongs to.
      this.logger.warn('Drift execute rejected: finding does not belong to the requested account', {
        findingId,
        requestedAccountId: accountId,
        findingAccountId: finding.AwsAccountId,
      });
      throw new BadRequestError(`Finding ${findingId} does not belong to the requested account`);
    }

    // Start the SSM execution in the member account
    const memberSsmClient = await this.getMemberSsmClient(accountId, actor);
    const documentName = await this.resolveDocumentName(memberSsmClient, controlId);

    // Derive the remediation role from the document name (ASR-{std}_{ver}_{ctrl} → SO0111-Remediate-{std}-{ver}-{ctrl})
    const documentParts = documentName.replace('ASR-', '').split('_');
    const remediationRoleName =
      documentParts.length >= 3
        ? `${SOLUTION_PREFIX}-Remediate-${documentParts.join('-')}`
        : `${SOLUTION_PREFIX}-Remediate-SC-${SECURITY_CONTROL_STANDARD_VERSION}-${controlId}`;
    const { AWS_PARTITION } = apiLambdaEnvironment();
    const remediationRoleArn = `arn:${AWS_PARTITION}:iam::${accountId}:role/${remediationRoleName}`;

    const startResult = await memberSsmClient.send(
      new StartAutomationExecutionCommand({
        DocumentName: documentName,
        Parameters: {
          AutomationAssumeRole: [remediationRoleArn],
          Finding: [JSON.stringify(finding)],
        },
      }),
    );

    const executionId = startResult.AutomationExecutionId;
    if (!executionId) {
      throw new Error('SSM StartAutomationExecution returned no execution ID');
    }

    const { status, steps, durationMs } = await pollAutomationExecution(memberSsmClient, executionId, {
      clock: this.clock,
      sleeper: this.sleeper,
    });

    return { action: 'execute', execution_id: executionId, status, duration_ms: durationMs, steps };
  }

  async status(executionId: string, accountId: string): Promise<DriftStatusResult> {
    const memberSsmClient = await this.getMemberSsmClient(accountId);

    let execResult;
    try {
      execResult = await memberSsmClient.send(
        new GetAutomationExecutionCommand({ AutomationExecutionId: executionId }),
      );
    } catch (error) {
      // Without this mapping an unknown execution id surfaces as a generic 400, which
      // a caller cannot tell apart from a broken cross-account credential chain.
      if (error instanceof AutomationExecutionNotFoundException) {
        throw new NotFoundError(
          `SSM Automation execution ${executionId} was not found in account ${accountId}. ` +
            'Check the execution id, and that it belongs to this member account and region.',
        );
      }
      throw error;
    }
    const execution = execResult.AutomationExecution;

    return {
      action: 'status',
      execution_id: executionId,
      status: execution?.AutomationExecutionStatus ?? 'Unknown',
      steps:
        execution?.StepExecutions?.map((s) => ({
          name: s.StepName ?? '',
          status: s.StepStatus ?? '',
          error: s.FailureMessage,
        })) ?? [],
      outputs: execution?.Outputs,
    };
  }
}
