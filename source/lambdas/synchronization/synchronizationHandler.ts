// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import type { LambdaInterface } from '@aws-lambda-powertools/commons/types';
import { Context, EventBridgeEvent, ScheduledEvent } from 'aws-lambda';
import { SecurityHubClient } from '@aws-sdk/client-securityhub';
import { getLogger } from '../common/utils/logger';
import { getTracer } from '../common/utils/tracer';
import { createDynamoDBClient } from '../common/utils/dynamodb';
import { sendMetrics } from '../common/utils/metricsUtils';
import { SecurityHubUtils } from '../common/utils/securityHub';
import { FindingDataService } from '../common/services/findingDataService';
import { ASFFFinding } from '@asr/data-models';
import { applyFilters } from '../common/utils/filterUtils';
import {
  getSupportedControlIdsInChunks,
  getOptimizedFindingFiltersByControlId,
} from '../common/constants/securityStandardFilters';

const BATCH_SIZE = 10;

interface BatchResult {
  successCount: number;
  failedCount: number;
  errorCount: number;
  filteredCount: number;
}

type FindingProcessingStatus = 'SUCCESS' | 'FAILED' | 'ERROR' | 'FILTERED';

const SOLUTION_TRADEMARKEDNAME = process.env.SOLUTION_TRADEMARKEDNAME ?? 'automated-security-response-on-aws';
const FINDINGS_TABLE_ARN = process.env.FINDINGS_TABLE_ARN;
const REMEDIATION_CONFIG_TABLE_ARN = process.env.REMEDIATION_CONFIG_TABLE_ARN;
const FINDINGS_TABLE_NAME = FINDINGS_TABLE_ARN?.split('/')[1];
const REMEDIATION_CONFIG_TABLE_NAME = REMEDIATION_CONFIG_TABLE_ARN?.split('/')[1];

if (!FINDINGS_TABLE_ARN) throw new Error('FINDINGS_TABLE_ARN environment variable is required');
if (!FINDINGS_TABLE_NAME) throw new Error('Unable to extract table name from FINDINGS_TABLE_ARN');
if (!REMEDIATION_CONFIG_TABLE_ARN) throw new Error('REMEDIATION_CONFIG_TABLE_ARN environment variable is required');
if (!REMEDIATION_CONFIG_TABLE_NAME) throw new Error('Unable to extract table name from REMEDIATION_CONFIG_TABLE_ARN');

const tracer = getTracer(SOLUTION_TRADEMARKEDNAME);
const logger = getLogger(SOLUTION_TRADEMARKEDNAME);

export class Synchronization implements LambdaInterface {
  @tracer.captureLambdaHandler()
  @logger.injectLambdaContext()
  async handler(event: ScheduledEvent | EventBridgeEvent<string, any>, _context: Context) {
    try {
      logger.info('Synchronization Lambda invoked', {
        eventSource: event.source || 'unknown',
        detailType: ('detail-type' in event ? event['detail-type'] : 'unknown') || 'unknown',
        syncMode: 'full',
      });

      if (this.isValidSyncEvent(event)) {
        return await this.handleScheduledSync();
      }

      logger.warn('Unknown event type received', { event });
      return {
        statusCode: 400,
        body: JSON.stringify({ message: 'Unknown event type' }),
      };
    } catch (error) {
      logger.error(`Synchronization failed: ${error}`, {
        errorType: error instanceof Error ? error.constructor.name : 'unknown',
        event,
      });
      throw error;
    }
  }

  private isValidSyncEvent(event: ScheduledEvent | EventBridgeEvent<string, any>): boolean {
    const isScheduledEvent =
      event.source === 'aws.events' && 'detail-type' in event && event['detail-type'] === 'Scheduled Event';

    const isCustomResourceEvent =
      event.source === 'custom-resource' &&
      'detail-type' in event &&
      event['detail-type'] === 'Synchronization Trigger';

    return isScheduledEvent || isCustomResourceEvent;
  }

  private async handleScheduledSync() {
    const startTime = Date.now();
    logger.info('Processing scheduled synchronization event', {
      startTime: new Date(startTime).toISOString(),
    });

    const dynamoDBDocumentClient = tracer.captureAWSv3Client(createDynamoDBClient({ maxAttempts: 10 }));
    const securityHubClient = tracer.captureAWSv3Client(new SecurityHubClient({}));
    const securityHubUtils = new SecurityHubUtils(securityHubClient);
    const findingDataService = new FindingDataService(FINDINGS_TABLE_NAME!, dynamoDBDocumentClient, 'synchronization');
    const controlIdChunks = await getSupportedControlIdsInChunks(
      dynamoDBDocumentClient,
      REMEDIATION_CONFIG_TABLE_NAME!,
    );

    let totalSuccessful = 0;
    let totalError = 0;
    let totalFailed = 0;
    let totalFiltered = 0;
    let apiCallCount = 0;
    let totalProcessed = 0;

    try {
      for (let chunkIndex = 0; chunkIndex < controlIdChunks.length; chunkIndex++) {
        const controlIdChunk = controlIdChunks[chunkIndex];

        logger.debug(`Processing control ID chunk ${chunkIndex + 1}/${controlIdChunks.length}`, {
          chunkSize: controlIdChunk.length,
          totalChunks: controlIdChunks.length,
        });

        const filters = await getOptimizedFindingFiltersByControlId(controlIdChunk);

        const result = await securityHubUtils.processAllFindings(async (findings) => {
          const batchResult = await this.processFindingsInBatch(findings, findingDataService);
          totalSuccessful += batchResult.successCount;
          totalFailed += batchResult.failedCount;
          totalError += batchResult.errorCount;
          totalFiltered += batchResult.filteredCount;
        }, filters);

        totalProcessed += result.totalProcessed;
        apiCallCount += result.apiCallCount;

        logger.debug(`Completed chunk ${chunkIndex + 1}/${controlIdChunks.length}`, {
          chunkProcessed: result.totalProcessed,
          chunkApiCalls: result.apiCallCount,
          totalProcessedSoFar: totalProcessed,
        });
      }

      return await this.handleSyncSuccess(
        startTime,
        totalProcessed,
        totalSuccessful,
        totalFailed,
        totalError,
        totalFiltered,
        apiCallCount,
      );
    } catch (error) {
      await this.handleSyncError(
        error,
        startTime,
        totalSuccessful,
        totalFailed,
        totalError,
        totalFiltered,
        apiCallCount,
      );
      throw error;
    }
  }

  /**
   * Process findings using batch operations for better performance
   * Processes findings concurrently in smaller batches to improve throughput
   */
  private async processFindingsInBatch(
    findings: ASFFFinding[],
    findingDataService: FindingDataService,
  ): Promise<BatchResult> {
    let successCount = 0;
    let failedCount = 0;
    let errorCount = 0;
    let filteredCount = 0;

    for (let i = 0; i < findings.length; i += BATCH_SIZE) {
      const batch = findings.slice(i, i + BATCH_SIZE);
      const batchPromises = batch.map((finding) => this.processSingleFinding(finding, findingDataService));
      const batchResults = await Promise.all(batchPromises);

      const batchCounts = this.countBatchResults(batchResults);
      successCount += batchCounts.success;
      failedCount += batchCounts.failed;
      errorCount += batchCounts.error;
      filteredCount += batchCounts.filtered;

      this.logBatchProgress(i, batchCounts);
    }

    return { successCount, failedCount, errorCount, filteredCount };
  }

  private async processSingleFinding(
    finding: ASFFFinding,
    findingDataService: FindingDataService,
  ): Promise<FindingProcessingStatus> {
    try {
      const filterResult = await applyFilters(finding, logger);

      if (!filterResult.passed) {
        logger.debug(`Finding filtered out: ${finding.Id}`, {
          appliedFilter: filterResult.appliedFilter,
          findingId: finding.Id,
        });
        return 'FILTERED';
      }

      return await this.updateFindingData(finding, findingDataService);
    } catch (filterError) {
      return await this.handleFilterError(finding, findingDataService, filterError);
    }
  }

  private async updateFindingData(
    finding: ASFFFinding,
    findingDataService: FindingDataService,
  ): Promise<FindingProcessingStatus> {
    const result = await findingDataService.updateWithIncomingData(finding, undefined, true);
    this.logFindingResult(finding.Id, result.status);
    return result.status;
  }

  private async handleFilterError(
    finding: ASFFFinding,
    findingDataService: FindingDataService,
    filterError: unknown,
  ): Promise<FindingProcessingStatus> {
    if (filterError instanceof Error && filterError.message.includes('filter')) {
      logger.error(`Filter error for finding ${finding.Id}, processing anyway`, {
        error: filterError,
        findingId: finding.Id,
      });
    }

    try {
      const result = await findingDataService.updateWithIncomingData(finding, undefined, true);
      return result.status;
    } catch (error) {
      logger.error(`Failed to process finding ${finding.Id}: ${error}`);
      return 'ERROR';
    }
  }

  private logFindingResult(findingId: string, status: FindingProcessingStatus): void {
    const statusMessages = {
      SUCCESS: `Successfully processed finding ${findingId}`,
      FAILED: `Failed to process finding ${findingId} - result: ${status}`,
      ERROR: `Error processing finding ${findingId} - result: ${status}`,
      FILTERED: `Finding filtered out: ${findingId}`,
    };

    if (statusMessages[status]) {
      logger.debug(statusMessages[status]);
    }
  }

  private countBatchResults(batchResults: FindingProcessingStatus[]): {
    success: number;
    failed: number;
    error: number;
    filtered: number;
  } {
    return {
      success: batchResults.filter((r) => r === 'SUCCESS').length,
      failed: batchResults.filter((r) => r === 'FAILED').length,
      error: batchResults.filter((r) => r === 'ERROR').length,
      filtered: batchResults.filter((r) => r === 'FILTERED').length,
    };
  }

  private logBatchProgress(
    currentIndex: number,
    counts: { success: number; failed: number; error: number; filtered: number },
  ): void {
    const batchNumber = Math.floor(currentIndex / BATCH_SIZE) + 1;
    logger.debug(
      `Batch ${batchNumber}: ${counts.success} successful, ${counts.failed} failed, ${counts.error} error, ${counts.filtered} filtered`,
    );
  }

  private calculateExecutionMetrics(startTime: number, totalProcessed: number, totalFiltered: number) {
    const endTime = Date.now();
    const executionTimeMs = endTime - startTime;
    const executionTimeSeconds = Math.round((executionTimeMs / 1000) * 100) / 100;
    const filterEffectivenessRatio =
      totalProcessed > 0 ? Math.round((totalFiltered / totalProcessed) * 100 * 100) / 100 : 0;

    return {
      endTime,
      executionTimeMs,
      executionTimeSeconds,
      filterEffectivenessRatio,
    };
  }

  private async handleSyncSuccess(
    startTime: number,
    totalProcessed: number,
    totalSuccessful: number,
    totalFailed: number,
    totalError: number,
    totalFiltered: number,
    apiCallCount: number,
  ) {
    const metrics = this.calculateExecutionMetrics(startTime, totalProcessed, totalFiltered);

    logger.info('Synchronization completed successfully', {
      totalProcessed,
      totalSuccessful,
      totalFailed,
      totalError,
      totalFiltered,
      filterEffectivenessRatio: metrics.filterEffectivenessRatio,
      executionTimeMs: metrics.executionTimeMs,
      executionTimeSeconds: metrics.executionTimeSeconds,
      startTime: new Date(startTime).toISOString(),
      endTime: new Date(metrics.endTime).toISOString(),
    });

    await sendMetrics({
      synchronization_status: 'SUCCESS',
      total_processed: totalProcessed,
      total_successful: totalSuccessful,
      total_failed: totalFailed,
      total_error: totalError,
      total_filtered: totalFiltered,
      filter_effectiveness_ratio: metrics.filterEffectivenessRatio,
      api_call_count: apiCallCount,
      execution_time_ms: metrics.executionTimeMs,
      execution_time_seconds: metrics.executionTimeSeconds,
    });

    return {
      statusCode: 200,
      body: JSON.stringify({
        message: 'Synchronization completed successfully',
        totalProcessed,
        totalSuccessful,
        totalFailed,
        totalError,
        totalFiltered,
        filterEffectivenessRatio: metrics.filterEffectivenessRatio,
        executionTimeMs: metrics.executionTimeMs,
        executionTimeSeconds: metrics.executionTimeSeconds,
        timestamp: new Date().toISOString(),
      }),
    };
  }

  private async handleSyncError(
    error: unknown,
    startTime: number,
    totalSuccessful: number,
    totalFailed: number,
    totalError: number,
    totalFiltered: number,
    apiCallCount: number,
  ) {
    const totalProcessed = totalSuccessful + totalFailed + totalError + totalFiltered;
    const metrics = this.calculateExecutionMetrics(startTime, totalProcessed, totalFiltered);

    logger.error(`Scheduled sync failed: ${error}`, {
      totalSuccessful,
      totalFailed,
      totalError,
      totalFiltered,
      filterEffectivenessRatio: metrics.filterEffectivenessRatio,
      apiCallCount,
      executionTimeMs: metrics.executionTimeMs,
      executionTimeSeconds: metrics.executionTimeSeconds,
      startTime: new Date(startTime).toISOString(),
      endTime: new Date(metrics.endTime).toISOString(),
    });

    await sendMetrics({
      synchronization_status: 'FAILED',
      total_processed: totalProcessed,
      total_error: totalError,
      total_successful: totalSuccessful,
      total_failed: totalFailed,
      total_filtered: totalFiltered,
      filter_effectiveness_ratio: metrics.filterEffectivenessRatio,
      api_call_count: apiCallCount,
      execution_time_ms: metrics.executionTimeMs,
      execution_time_seconds: metrics.executionTimeSeconds,
      error_message: error instanceof Error ? error.message : 'Unknown error',
    });
  }
}

const synchronizationClass = new Synchronization();
export const handler = synchronizationClass.handler.bind(synchronizationClass);
