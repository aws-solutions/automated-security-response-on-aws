// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import {
  ActionResult,
  RemediationResult,
  SuppressionResult,
  FindingsActionRequest,
  FindingsRequest,
} from '@asr/data-models';
import { Logger } from '@aws-lambda-powertools/logger';
import crypto from 'crypto';
import { inflate } from 'pako';
import { SCOPE_NAME } from '../../common/constants/apiConstant';
import { FindingRepository } from '../../common/repositories/findingRepository';
import { RemediationHistoryRepository } from '../../common/repositories/remediationHistoryRepository';
import type { ASFFFinding, FindingApiResponse, FindingTableItem } from '@asr/data-models';
import { ErrorUtils } from '../../common/utils/errorUtils';
import { getSecurityHubConsoleUrl } from '../../common/utils/findingUtils';
import { BadRequestError } from '../../common/utils/httpErrors';
import { sendMetrics } from '../../common/utils/metricsUtils';
import { executeOrchestrator } from '../../common/utils/orchestrator';
import { mapRemediationStatus } from '../../common/utils/remediationStatusMapper';
import { AuthenticatedUser } from './authorization';
import { BaseSearchService } from './baseSearchService';

export class FindingsService extends BaseSearchService {
  private readonly findingRepository: FindingRepository;
  private readonly remediationHistoryRepository: RemediationHistoryRepository;

  constructor(logger: Logger) {
    super(logger);

    this.findingRepository = new FindingRepository(SCOPE_NAME, process.env.FINDINGS_TABLE_NAME!, this.dynamoDBClient);

    this.remediationHistoryRepository = new RemediationHistoryRepository(
      SCOPE_NAME,
      process.env.REMEDIATION_HISTORY_TABLE_NAME!,
      this.dynamoDBClient,
      process.env.FINDINGS_TABLE_NAME!,
    );
  }

  async searchFindings(
    authenticatedUser: AuthenticatedUser,
    request: FindingsRequest,
  ): Promise<{ Findings: FindingApiResponse[]; NextToken?: string }> {
    try {
      const modifiedRequest = this.applyAccountFilteringForAccountOperators(authenticatedUser, request);
      const searchCriteria = await this.convertToSearchCriteria(modifiedRequest, 'Findings');
      const searchResult = await this.findingRepository.searchFindings(searchCriteria);

      return {
        Findings: searchResult.items.map((item) => this.convertToApiResponse(item)),
        NextToken: searchResult.nextToken,
      };
    } catch (error) {
      this.logger.error('Error searching findings', {
        request: {
          ...request,
          NextToken: request.NextToken ? `${request.NextToken.substring(0, 20)}...` : undefined,
        },
        error: error instanceof Error ? error.message : String(error),
        stack: error instanceof Error ? error.stack : undefined,
      });
      throw error;
    }
  }

  async executeAction(request: FindingsActionRequest, principal: string): Promise<void> {
    try {
      const findings = await this.findingRepository.findByFindingIds(request.findingIds);

      if (findings.length === 0) {
        throw new BadRequestError('No findings found for the provided IDs');
      }

      const fieldUpdates = await this.getFieldUpdatesForAction(request.actionType, findings);

      if (request.actionType === 'Remediate' || request.actionType === 'RemediateAndGenerateTicket') {
        await this.executeRemediationWithHistory(findings, fieldUpdates, principal);
      } else {
        if (this.isSuppressionResult(fieldUpdates)) {
          const updatedFindings = this.prepareUpdatedFindings(principal, findings, fieldUpdates);
          await this.findingRepository.putAll(...updatedFindings);
        } else {
          throw new Error('Invalid field updates for suppression action');
        }
      }
    } catch (error) {
      this.logger.error('Error executing action', {
        actionType: request.actionType,
        error: ErrorUtils.formatErrorMessage(error),
      });

      if (error instanceof BadRequestError) throw error;
      throw new BadRequestError('Failed to execute action on findings');
    }
  }

  private async executeRemediationWithHistory(
    findings: FindingTableItem[],
    fieldUpdates: ActionResult,
    principal: string,
  ): Promise<void> {
    const { remediationStatus, executionIdsByFindingId = new Map() } = fieldUpdates as RemediationResult;

    for (const finding of findings) {
      const executionId = executionIdsByFindingId.get(finding.findingId);
      const updatedFinding = {
        ...finding,
        remediationStatus: mapRemediationStatus(remediationStatus),
        ...(executionId && { executionId }),
        lastUpdatedBy: principal,
      };

      await this.remediationHistoryRepository.createRemediationHistoryWithFindingUpdate(updatedFinding, executionId);
    }
  }

  private prepareUpdatedFindings(
    principal: string,
    findings: FindingTableItem[],
    fieldUpdates: SuppressionResult,
  ): FindingTableItem[] {
    return findings.map((finding) => ({
      ...finding,
      ...fieldUpdates,
      lastUpdatedBy: principal,
      lastUpdatedTime: new Date().toISOString(),
    }));
  }

  private isSuppressionResult(result: ActionResult): result is SuppressionResult {
    return 'suppressed' in result;
  }

  private async getFieldUpdatesForAction(actionType: string, findings: FindingTableItem[]): Promise<ActionResult> {
    switch (actionType) {
      case 'Suppress':
        await sendMetrics({ finding_suppressed: 1 });
        return { suppressed: true };
      case 'Unsuppress':
        return { suppressed: false };
      case 'Remediate':
        return await this.executeRemediationWithTracking('Remediate', findings);
      case 'RemediateAndGenerateTicket':
        return await this.executeRemediationWithTracking('RemediateAndGenerateTicket', findings);
      default:
        throw new Error(`Unsupported action type: ${actionType}`);
    }
  }

  private static extractASFFFinding(findingTableItem: FindingTableItem): ASFFFinding {
    try {
      if (!findingTableItem.findingJSON) {
        throw new Error('No findingJSON data available');
      }
      const decompressed = inflate(findingTableItem.findingJSON, { to: 'string' });
      return JSON.parse(decompressed);
    } catch (error) {
      throw new Error(`Failed to extract ASFF finding: ${ErrorUtils.formatErrorMessage(error)}`);
    }
  }

  private static buildOrchestratorInput(asffFinding: ASFFFinding, actionType: string): string {
    const actionName = actionType === 'RemediateAndGenerateTicket' ? 'ASR:Remediate&Ticket' : 'Remediate with ASR';

    return JSON.stringify({
      version: '0',
      id: crypto.randomUUID(),
      'detail-type': 'Security Hub Findings - API Action',
      source: 'aws.securityhub',
      account: asffFinding.AwsAccountId,
      region: asffFinding.Region,
      time: new Date().toISOString(),
      resources: [
        `arn:aws:securityhub:${asffFinding.Region}:${asffFinding.AwsAccountId}:action/custom/api-${actionType.toLowerCase()}`,
      ],
      detail: {
        findings: [asffFinding],
        actionName,
        actionDescription: `API-triggered ${actionType}`,
      },
    });
  }

  /**
   * Common method for executing remediation actions
   */
  private async executeRemediationWithTracking(
    actionType: string,
    findings: FindingTableItem[],
  ): Promise<RemediationResult> {
    const findingCount = findings.length || 0;

    this.logger.debug(`Starting ${actionType} async process`, {
      findingCount,
    });

    try {
      const executionIdsByFindingId = new Map<string, string>();

      for (const findingTableItem of findings) {
        const asffFinding = FindingsService.extractASFFFinding(findingTableItem);
        const orchestratorInput = FindingsService.buildOrchestratorInput(asffFinding, actionType);
        const executionId = await executeOrchestrator(orchestratorInput, this.logger);

        if (executionId) {
          executionIdsByFindingId.set(findingTableItem.findingId, executionId);
        } else {
          this.logger.warn('Failed to get execution ID for finding', {
            findingId: findingTableItem.findingId,
            actionType,
          });
        }
      }

      return {
        remediationStatus: 'IN_PROGRESS',
        executionIdsByFindingId,
      };
    } catch (error) {
      const errorMessage = ErrorUtils.formatErrorMessage(error);

      this.logger.error(`Failed to execute ${actionType} orchestrator`, {
        error: errorMessage,
        findingCount,
      });

      return {
        remediationStatus: 'FAILED',
        error: errorMessage,
      };
    }
  }

  private convertToApiResponse(item: FindingTableItem): FindingApiResponse {
    // Remove internal fields and return only API-relevant data
    const {
      'securityHubUpdatedAtTime#findingId': _lsiSortKey,
      findingJSON: _findingJSON,
      findingIdControl: _findingIdControl,
      FINDING_CONSTANT: _findingConstant,
      lastUpdatedBy: _lastUpdatedBy,
      expireAt: _expireAt,
      ...baseApiResponse
    } = item;

    const consoleLink = getSecurityHubConsoleUrl(baseApiResponse.findingId);

    return {
      ...baseApiResponse,
      consoleLink,
    };
  }
}
