// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { Logger } from '@aws-lambda-powertools/logger';
import { ASRS3Client } from '../clients/ASRS3Client';
import { RemediationHistoryRepository } from '../../common/repositories/remediationHistoryRepository';
import type { RemediationHistoryApiResponse, RemediationHistoryTableItem } from '@asr/data-models';
import { RemediationsRequest, ExportRequest, SearchCriteria } from '@asr/data-models';
import { AuthenticatedUser } from './authorization';
import { SCOPE_NAME } from '../../common/constants/apiConstant';
import { BaseSearchService } from './baseSearchService';
import { getStepFunctionsConsoleUrl } from '../../common/utils/findingUtils';

export class RemediationService extends BaseSearchService {
  private readonly remediationHistoryRepository: RemediationHistoryRepository;
  private readonly s3Client: ASRS3Client;

  constructor(logger: Logger) {
    super(logger);

    this.remediationHistoryRepository = new RemediationHistoryRepository(
      SCOPE_NAME,
      process.env.REMEDIATION_HISTORY_TABLE_NAME!,
      this.dynamoDBClient,
      process.env.FINDINGS_TABLE_NAME!,
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
        Remediations: searchResult.items.map((item) => this.convertToApiResponse(item)),
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
    // Remove internal fields and return only API-relevant data
    const {
      'findingId#executionId': _compositeKey,
      'lastUpdatedTime#findingId': _lsiSortKey,
      REMEDIATION_CONSTANT: _remediationConstant,
      expireAt: _expireAt,
      ...baseApiResponse
    } = item;

    const consoleLink = getStepFunctionsConsoleUrl(baseApiResponse.executionId);

    return {
      ...baseApiResponse,
      consoleLink,
    };
  }

  async exportRemediationHistory(
    authenticatedUser: AuthenticatedUser,
    request: ExportRequest,
  ): Promise<{ downloadUrl: string }> {
    this.logger.debug('Starting remediation history export', {
      request,
      username: authenticatedUser.username,
      hasFilters: !!request.Filters,
    });

    try {
      const searchCriteria = await this.buildExportSearchCriteria(authenticatedUser, request);

      const allRemediations = await this.fetchAllRemediationsForExport(searchCriteria);

      this.logger.debug('Remediation data prepared for export', {
        totalRemediations: allRemediations.length,
        hasFilters: !!request.Filters,
      });

      const csvContent = this.convertRemediationsToCSV(allRemediations);

      const downloadUrl = await this.uploadToS3AndGenerateUrl(csvContent);

      this.logger.debug('Remediation history export completed successfully', {
        totalRemediations: allRemediations.length,
        csvSizeBytes: csvContent.length,
        hasDownloadUrl: !!downloadUrl,
      });

      return { downloadUrl };
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

  private async fetchAllRemediationsForExport(searchCriteria: SearchCriteria): Promise<RemediationHistoryTableItem[]> {
    const allRemediations: RemediationHistoryTableItem[] = [];
    let nextToken: string | undefined;
    let batchCount = 0;

    this.logger.debug('Starting export data fetch with unlimited size', {
      totalFilters: searchCriteria.filters.length,
    });

    do {
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
      });

      if (batchCount > 100) {
        this.logger.warn('Export reached maximum batch limit', {
          batchCount,
          totalRecords: allRemediations.length,
        });
        break;
      }
    } while (nextToken);

    this.logger.info('Export data fetch completed', {
      totalBatches: batchCount,
      totalRecords: allRemediations.length,
    });

    return allRemediations;
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
