// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { Logger } from '@aws-lambda-powertools/logger';
import { ASRS3Client } from '../clients/ASRS3Client';
import { RemediationHistoryRepository } from '../../common/repositories/remediationHistoryRepository';
import type { RemediationHistoryApiResponse, RemediationHistoryTableItem } from '@asr/data-models';
import { RemediationsRequest, ExportRequest, SearchCriteria, ROLLBACK_ELIGIBLE_FINDING_TYPE } from '@asr/data-models';
import { AuthenticatedUser } from './authorization';
import { SCOPE_NAME } from '../../common/constants/apiConstant';
import { BaseSearchService } from './baseSearchService';
import { getStepFunctionsConsoleUrl } from '../../common/utils/findingUtils';
import { apiLambdaEnvironment } from '../apiLambdaEnvironment';

export class RemediationService extends BaseSearchService {
  private readonly remediationHistoryRepository: RemediationHistoryRepository;
  private readonly s3Client: ASRS3Client;

  constructor(logger: Logger) {
    super(logger);

    const env = apiLambdaEnvironment();
    this.remediationHistoryRepository = new RemediationHistoryRepository(
      SCOPE_NAME,
      env.REMEDIATION_HISTORY_TABLE_NAME,
      this.dynamoDBClient,
      env.FINDINGS_TABLE_NAME,
    );

    this.s3Client = new ASRS3Client();
  }

  async searchRemediations(
    authenticatedUser: AuthenticatedUser,
    request: RemediationsRequest,
  ): Promise<{ Remediations: RemediationHistoryApiResponse[]; NextToken?: string }> {
    this.logger.debug('Searching remediations with request', { remediationsRequest: request });

    try {
      const modifiedRequest = this.applyAccountFilteringForAccountOperators(authenticatedUser, request);
      const searchCriteria = await this.convertToSearchCriteria(modifiedRequest, 'Remediations');

      this.logger.debug('Executing remediation search with criteria', {
        filtersCount: searchCriteria.filters.length,
        sortOrder: searchCriteria.sortOrder,
        pageSize: searchCriteria.pageSize,
        hasNextToken: !!searchCriteria.nextToken,
      });

      const searchResult = await this.remediationHistoryRepository.searchRemediations(searchCriteria);

      this.logger.debug('Remediation search completed successfully', {
        remediationsCount: searchResult.items.length,
        hasNextToken: !!searchResult.nextToken,
      });

      return {
        Remediations: this.markRollbackEligibility(searchResult.items.map((item) => this.convertToApiResponse(item))),
        NextToken: searchResult.nextToken,
      };
    } catch (error) {
      this.logger.error('Error searching remediations', {
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

  private convertToApiResponse(item: RemediationHistoryTableItem): RemediationHistoryApiResponse {
    const {
      'findingId#executionId': _compositeKey,
      'lastUpdatedTime#findingId': _lsiSortKey,
      REMEDIATION_CONSTANT: _remediationConstant,
      expireAt: _expireAt,
      findingJSON,
      ...baseApiResponse
    } = item;

    const consoleLink = getStepFunctionsConsoleUrl(baseApiResponse.executionId);

    return {
      ...baseApiResponse,
      consoleLink,
      // Rollback is offered for the original successful containment (SUCCESS) and
      // to retry a previously failed rollback (ROLLBACK_FAILED). It is never
      // offered for a failed remediation, an in-progress run, or a rollback that
      // already succeeded. markRollbackEligibility further narrows to the newest
      // such entry per finding.
      isRollbackEligible:
        !!(findingJSON && findingJSON.length > 0) &&
        (baseApiResponse.remediationStatus === 'SUCCESS' || baseApiResponse.remediationStatus === 'ROLLBACK_FAILED') &&
        baseApiResponse.findingType.endsWith(ROLLBACK_ELIGIBLE_FINDING_TYPE),
    };
  }

  /**
   * Rollback is offered on at most one row per finding: the single most recent
   * remediation entry, and only when that entry is itself rollback-eligible
   * (SUCCESS or a prior ROLLBACK_FAILED on a GuardDuty.IAMUser).
   *
   * Keying off the newest row *overall* — rather than the newest eligible row —
   * is deliberate: if a finding has already been rolled back (its newest row is
   * ROLLBACK_SUCCESS / ROLLBACK_IN_PROGRESS), no button should appear at all.
   * The older eligible SUCCESS row must NOT keep the button alive.
   *
   * Uses in-page timestamp comparison — cross-page duplicates are harmless
   * because the server re-validates eligibility (via the optimistic lock) on
   * rollback execution.
   */
  private markRollbackEligibility(items: RemediationHistoryApiResponse[]): RemediationHistoryApiResponse[] {
    // Newest row per finding, regardless of status.
    const newestPerFinding = new Map<string, string>();
    for (const item of items) {
      const existing = newestPerFinding.get(item.findingId);
      if (!existing || item.lastUpdatedTime > existing) {
        newestPerFinding.set(item.findingId, item.lastUpdatedTime);
      }
    }
    return items.map((item) => {
      if (!item.isRollbackEligible) return item;
      // Only the newest row for the finding keeps eligibility; any older row
      // (including an older SUCCESS shadowed by a newer ROLLBACK_* row) loses it.
      if (item.lastUpdatedTime === newestPerFinding.get(item.findingId)) return item;
      return { ...item, isRollbackEligible: false };
    });
  }

  async exportRemediationHistory(
    authenticatedUser: AuthenticatedUser,
    request: ExportRequest,
  ): Promise<{
    downloadUrl: string;
    status: 'complete' | 'partial';
    totalExported: number;
    message?: string;
  }> {
    this.logger.debug('Starting remediation history export', {
      request,
      username: authenticatedUser.username,
      hasFilters: !!request.Filters,
    });

    try {
      const searchCriteria = await this.buildExportSearchCriteria(authenticatedUser, request);

      const exportResult = await this.fetchAllRemediationsForExport(searchCriteria);

      this.logger.debug('Remediation data prepared for export', {
        totalRemediations: exportResult.remediations.length,
        status: exportResult.status,
        hasFilters: !!request.Filters,
      });

      const csvContent = this.convertRemediationsToCSV(exportResult.remediations);

      const downloadUrl = await this.uploadToS3AndGenerateUrl(csvContent);

      this.logger.debug('Remediation history export completed successfully', {
        totalRemediations: exportResult.remediations.length,
        status: exportResult.status,
        csvSizeBytes: csvContent.length,
        hasDownloadUrl: !!downloadUrl,
      });

      return {
        downloadUrl,
        status: exportResult.status,
        totalExported: exportResult.remediations.length,
        message: exportResult.reason,
      };
    } catch (error) {
      this.logger.error('Error exporting remediation history', {
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

    const searchCriteria = await this.convertToSearchCriteria(modifiedRequest, 'Remediations');

    return {
      ...searchCriteria,
      nextToken: undefined, // Always start from beginning for export
      pageSize: 100, // Large page size for export
    };
  }

  private async fetchAllRemediationsForExport(searchCriteria: SearchCriteria): Promise<{
    remediations: RemediationHistoryTableItem[];
    status: 'complete' | 'partial';
    reason?: string;
  }> {
    const allRemediations: RemediationHistoryTableItem[] = [];
    let nextToken: string | undefined;
    let batchCount = 0;

    const startTime = Date.now();
    const MAX_TIME = Number(apiLambdaEnvironment().EXPORT_MAX_TIME_MS) || 26000;
    const MAX_RECORDS = Number(apiLambdaEnvironment().EXPORT_MAX_RECORDS) || 50000;

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
          totalRecords: allRemediations.length,
          elapsedTime,
        });
        return {
          remediations: allRemediations,
          status: 'partial',
          reason: 'Time limit reached. Apply filters to reduce dataset.',
        };
      }

      const result = await this.remediationHistoryRepository.searchRemediations({
        ...searchCriteria,
        nextToken,
      });

      allRemediations.push(...result.items);
      nextToken = result.nextToken;
      batchCount++;

      this.logger.debug('Fetched batch for export', {
        batchNumber: batchCount,
        batchSize: result.items.length,
        totalSoFar: allRemediations.length,
        hasMore: !!nextToken,
        elapsedTime: Date.now() - startTime,
      });

      if (allRemediations.length >= MAX_RECORDS) {
        this.logger.warn('Export stopped due to record limit', {
          batchCount,
          totalRecords: allRemediations.length,
        });
        return {
          remediations: allRemediations,
          status: 'partial',
          reason: 'Maximum export size reached. Apply filters to reduce dataset.',
        };
      }
    } while (nextToken);

    this.logger.info('Export data fetch completed', {
      totalBatches: batchCount,
      totalRecords: allRemediations.length,
      status: 'complete',
    });

    return {
      remediations: allRemediations,
      status: 'complete',
    };
  }

  private convertRemediationsToCSV(remediations: RemediationHistoryTableItem[]): string {
    const displayHeaders = [
      'Finding ID',
      'Account',
      'Resource ID',
      'Resource Type',
      'Finding Type',
      'Severity',
      'Region',
      'Status',
      'Execution Timestamp',
      'Executed By',
      'Execution ID',
      'Error',
    ];

    const fieldNames = [
      'findingId',
      'accountId',
      'resourceId',
      'resourceTypeNormalized',
      'findingType',
      'severity',
      'region',
      'remediationStatus',
      'lastUpdatedTime',
      'lastUpdatedBy',
      'executionId',
      'error',
    ];

    const csvRows = [displayHeaders.join(',')];

    if (remediations.length === 0) {
      this.logger.info('No remediation data found for export - returning empty CSV with headers only');
      return csvRows.join('\n');
    }

    for (const remediation of remediations) {
      const row = fieldNames.map((fieldName) => {
        const value = remediation[fieldName as keyof RemediationHistoryTableItem];
        if (value === null || value === undefined) {
          return '';
        }
        const stringValue = String(value);
        if (stringValue.includes(',') || stringValue.includes('"') || stringValue.includes('\n')) {
          return `"${stringValue.replaceAll('"', '""')}"`;
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
    const bucketName = apiLambdaEnvironment().CSV_EXPORT_BUCKET_NAME;

    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const fileName = `remediation-history-export-${timestamp}.csv`;

    const presignedUrl = await this.s3Client.uploadCsvAndGeneratePresignedUrl(bucketName, fileName, csvContent);

    this.logger.debug('Successfully uploaded to S3 and generated pre-signed URL', {
      fileName,
      bucketName,
      urlGenerated: true,
    });

    return presignedUrl;
  }
}
