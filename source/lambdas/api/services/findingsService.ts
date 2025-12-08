// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import {
  ActionResult,
  RemediationResult,
  SuppressionResult,
  FindingsActionRequest,
  FindingsRequest,
  ExportRequest,
  SearchCriteria,
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
import { ASRS3Client } from '../clients/ASRS3Client';

export class FindingsService extends BaseSearchService {
  private readonly findingRepository: FindingRepository;
  private readonly remediationHistoryRepository: RemediationHistoryRepository;
  private readonly s3Client: ASRS3Client;

  constructor(logger: Logger) {
    super(logger);

    this.findingRepository = new FindingRepository(SCOPE_NAME, process.env.FINDINGS_TABLE_NAME!, this.dynamoDBClient);

    this.remediationHistoryRepository = new RemediationHistoryRepository(
      SCOPE_NAME,
      process.env.REMEDIATION_HISTORY_TABLE_NAME!,
      this.dynamoDBClient,
      process.env.FINDINGS_TABLE_NAME!,
    );

    this.s3Client = new ASRS3Client();
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

  async exportFindings(
    authenticatedUser: AuthenticatedUser,
    request: ExportRequest,
  ): Promise<{
    downloadUrl: string;
    status: 'complete' | 'partial';
    totalExported: number;
    message?: string;
  }> {
    this.logger.debug('Starting findings export', {
      request,
      username: authenticatedUser.username,
      hasFilters: !!request.Filters,
    });

    try {
      const searchCriteria = await this.buildExportSearchCriteria(authenticatedUser, request);

      const exportResult = await this.fetchAllFindingsForExport(searchCriteria);

      this.logger.debug('Findings data prepared for export', {
        totalFindings: exportResult.findings.length,
        status: exportResult.status,
        hasFilters: !!request.Filters,
      });

      const csvContent = this.convertFindingsToCSV(exportResult.findings);

      const downloadUrl = await this.uploadToS3AndGenerateUrl(csvContent);

      this.logger.debug('Findings export completed successfully', {
        totalFindings: exportResult.findings.length,
        status: exportResult.status,
        csvSizeBytes: csvContent.length,
        hasDownloadUrl: !!downloadUrl,
      });

      return {
        downloadUrl,
        status: exportResult.status,
        totalExported: exportResult.findings.length,
        message: exportResult.reason,
      };
    } catch (error) {
      this.logger.error('Error exporting findings', {
        request,
        error: error instanceof Error ? error.message : String(error),
        stack: error instanceof Error ? error.stack : undefined,
      });
      throw error;
    }
  }

  private async buildExportSearchCriteria(
    authenticatedUser: AuthenticatedUser,
    request: ExportRequest,
  ): Promise<SearchCriteria> {
    const modifiedRequest = this.applyAccountFilteringForAccountOperators(authenticatedUser, request);

    const searchCriteria = await this.convertToSearchCriteria(modifiedRequest, 'Findings');

    return {
      ...searchCriteria,
      nextToken: undefined, // Always start from beginning for export
      pageSize: 100, // Large page size for export
    };
  }

  private async fetchAllFindingsForExport(searchCriteria: SearchCriteria): Promise<{
    findings: FindingTableItem[];
    status: 'complete' | 'partial';
    reason?: string;
  }> {
    const allFindings: FindingTableItem[] = [];
    let nextToken: string | undefined;
    let batchCount = 0;

    const startTime = Date.now();
    const MAX_TIME = Number(process.env.EXPORT_MAX_TIME_MS) || 26000;
    const MAX_RECORDS = Number(process.env.EXPORT_MAX_RECORDS) || 50000;

    this.logger.debug('Starting export data fetch with safety limits', {
      totalFilters: searchCriteria.filters.length,
      maxTime: MAX_TIME,
      maxRecords: MAX_RECORDS,
    });

    do {
      const elapsedTime = Date.now() - startTime;

      if (elapsedTime > MAX_TIME) {
        this.logger.warn('Export stopped due to time limit', {
          batchCount,
          totalRecords: allFindings.length,
          elapsedTime,
        });
        return {
          findings: allFindings,
          status: 'partial',
          reason: 'Time limit reached. Apply filters to reduce dataset.',
        };
      }

      const result = await this.findingRepository.searchFindings({
        ...searchCriteria,
        nextToken,
      });

      allFindings.push(...result.items);
      nextToken = result.nextToken;
      batchCount++;

      this.logger.debug('Fetched batch for export', {
        batchNumber: batchCount,
        batchSize: result.items.length,
        totalSoFar: allFindings.length,
        hasMore: !!nextToken,
        elapsedTime: Date.now() - startTime,
      });

      if (allFindings.length >= MAX_RECORDS) {
        this.logger.warn('Export stopped due to record limit', {
          batchCount,
          totalRecords: allFindings.length,
        });
        return {
          findings: allFindings,
          status: 'partial',
          reason: 'Maximum export size reached. Apply filters to reduce dataset.',
        };
      }
    } while (nextToken);

    this.logger.info('Export data fetch completed', {
      totalBatches: batchCount,
      totalRecords: allFindings.length,
      status: 'complete',
    });

    return {
      findings: allFindings,
      status: 'complete',
    };
  }

  private convertFindingsToCSV(findings: FindingTableItem[]): string {
    const displayHeaders = [
      'Finding ID',
      'Finding Type',
      'Finding Title',
      'Account',
      'Resource ID',
      'Resource Type',
      'Severity',
      'Region',
      'Remediation Status',
      'Security Hub Updated Time',
      'Suppressed',
    ];

    const fieldNames = [
      'findingId',
      'findingType',
      'findingDescription',
      'accountId',
      'resourceId',
      'resourceTypeNormalized',
      'severity',
      'region',
      'remediationStatus',
      'securityHubUpdatedAtTime',
      'suppressed',
    ];

    const csvRows = [displayHeaders.join(',')];

    if (findings.length === 0) {
      this.logger.info('No findings data found for export - returning empty CSV with headers only');
      return csvRows.join('\n');
    }

    for (const finding of findings) {
      const row = fieldNames.map((fieldName) => {
        const value = finding[fieldName as keyof FindingTableItem];
        if (value === null || value === undefined) {
          return '';
        }
        const stringValue = String(value);
        if (stringValue.includes(',') || stringValue.includes('"') || stringValue.includes('\n')) {
          return `"${stringValue.replace(/"/g, '""')}"`;
        }
        return stringValue;
      });
      csvRows.push(row.join(','));
    }

    this.logger.debug('CSV conversion completed', {
      totalRows: csvRows.length - 1, // Exclude header row
      totalColumns: displayHeaders.length,
    });

    return csvRows.join('\n');
  }

  private async uploadToS3AndGenerateUrl(csvContent: string): Promise<string> {
    const bucketName = process.env.CSV_EXPORT_BUCKET_NAME;
    if (!bucketName) {
      throw new Error('CSV_EXPORT_BUCKET_NAME environment variable not set');
    }

    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const fileName = `findings-export-${timestamp}.csv`;

    const presignedUrl = await this.s3Client.uploadCsvAndGeneratePresignedUrl(bucketName, fileName, csvContent);

    this.logger.debug('Successfully uploaded to S3 and generated pre-signed URL', {
      fileName,
      bucketName,
      urlGenerated: true,
    });

    return presignedUrl;
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
