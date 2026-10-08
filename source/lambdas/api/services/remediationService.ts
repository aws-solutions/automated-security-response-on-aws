// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { Logger } from '@aws-lambda-powertools/logger';
import { ASRS3Client } from '../clients/ASRS3Client';
import { RemediationHistoryRepository } from '../../common/repositories/remediationHistoryRepository';
import type { RemediationHistoryApiResponse, RemediationHistoryTableItem } from '@asr/data-models';
import {
  RemediationsRequest,
  ExportRequest,
  SearchCriteria,
  isRemediationRollbackEligible,
  narrowRollbackEligibilityToNewestPerFinding,
} from '@asr/data-models';
import { AuthenticatedUser } from './authorization';
import { SCOPE_NAME } from '../../common/constants/apiConstant';
import { BaseSearchService } from './baseSearchService';
import { getStepFunctionsConsoleUrl } from '../../common/utils/findingUtils';
import { calculateTtlTimestamp } from '../../common/utils/ttlUtils';
import { apiLambdaEnvironment } from '../apiLambdaEnvironment';
import { CsvColumn, toCsv } from '../../common/utils/csvExport';

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
      findingJSON: _findingJSON,
      rollbackAvailable: _rollbackAvailable,
      rollbackDescription: _rollbackDescription,
      ...baseApiResponse
    } = item;

    const consoleLink = getStepFunctionsConsoleUrl(baseApiResponse.executionId);

    return {
      ...baseApiResponse,
      consoleLink,
      // Shared predicate (also used by the MCP get_finding_history tool) so the two views of
      // the same history row cannot disagree. markRollbackEligibility further narrows to the
      // newest such entry per finding.
      isRollbackEligible: isRemediationRollbackEligible(item),
      // Derived from the durable history record, not the transient live finding
      // row (deleted once the finding goes PASSED). The UI hides a past value.
      // TTL days are supplied from the typed env accessor rather than read from
      // process.env inside the utility.
      reRemediationEligibleAt: calculateTtlTimestamp(
        baseApiResponse.lastUpdatedTime,
        Number(apiLambdaEnvironment().FINDINGS_TTL_DAYS),
      ),
      ...(_rollbackDescription ? { rollbackDescription: _rollbackDescription } : {}),
    };
  }

  /**
   * Rollback is offered on at most one row per finding — see
   * {@link narrowRollbackEligibilityToNewestPerFinding}, which the MCP `get_finding_history`
   * tool applies to the same rows so the two views agree.
   */
  private markRollbackEligibility(items: RemediationHistoryApiResponse[]): RemediationHistoryApiResponse[] {
    return narrowRollbackEligibilityToNewestPerFinding(items);
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
    const columns: readonly CsvColumn[] = [
      { header: 'Finding ID', field: 'findingId' },
      { header: 'Account', field: 'accountId' },
      { header: 'Resource ID', field: 'resourceId' },
      { header: 'Resource Type', field: 'resourceTypeNormalized' },
      { header: 'Finding Type', field: 'findingType' },
      { header: 'Severity', field: 'severity' },
      { header: 'Region', field: 'region' },
      { header: 'Status', field: 'remediationStatus' },
      { header: 'Execution Timestamp', field: 'lastUpdatedTime' },
      { header: 'Executed By', field: 'lastUpdatedBy' },
      { header: 'Execution ID', field: 'executionId' },
      { header: 'Error', field: 'error' },
    ];

    if (remediations.length === 0) {
      this.logger.info('No remediation data found for export - returning empty CSV with headers only');
    }

    const csvContent = toCsv(remediations, columns);

    this.logger.debug('CSV conversion completed', {
      totalRows: remediations.length,
      totalColumns: columns.length,
    });

    return csvContent;
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
