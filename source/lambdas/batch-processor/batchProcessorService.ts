// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { DynamoDBDocumentClient } from '@aws-sdk/lib-dynamodb';
import { SNSClient, PublishCommand } from '@aws-sdk/client-sns';
import { S3Client, PutObjectCommand, GetObjectCommand } from '@aws-sdk/client-s3';
import { getSignedUrl } from '@aws-sdk/s3-request-presigner';
import { Logger } from '@aws-lambda-powertools/logger';
import {
  NotificationConfigurationItem,
  NotificationBatchItem,
  FindingId,
  FindingTableItem,
  RemediationHistoryTableItem,
} from '@asr/data-models';
import { NotificationConfigurationRepository } from '../common/repositories/notificationConfigurationRepository';
import { NotificationBatchRepository } from '../common/repositories/notificationBatchRepository';
import { FindingRepository } from '../common/repositories/findingRepository';
import { RemediationHistoryRepository } from '../common/repositories/remediationHistoryRepository';
import { toCsv, getBatchCsvColumns } from '../common/utils/csvExport';
import { calculateDeadline } from '../notification-channels/format-utils';
import { Clock, getClock } from '../common/utils/clock';
import { sendMetrics } from '../common/utils/metricsUtils';
import { getDisplayRemediationStatus } from '../common/utils/remediationStatusDisplay';
import { isIaCEligible, buildIaCCsvUrls } from '../notification-channels/iac-download-links';
import { batchProcessorEnvironment } from './batchProcessorEnvironment';

const BATCH_PROCESSOR_PRINCIPAL = 'BatchProcessor';
const MAX_BATCH_QUERY_SIZE = 1000; // chunk size for filtering findings

export interface BatchProcessingResult {
  readonly processedCount: number;
  readonly sentCount: number;
  readonly skippedCount: number;
  readonly failedCount: number;
}

/** Shape of a single row in the batch CSV export. */
interface BatchCsvRow {
  readonly configId: string;
  readonly configName: string;
  readonly eventType: string;
  readonly eventId: string;
  readonly controlId: string;
  readonly accountId: string;
  readonly region: string;
  readonly severity: string;
  readonly resourceType: string;
  readonly resourceId: string;
  readonly title: string | undefined;
  readonly description: string | undefined;
  readonly detectedAt: string;
  readonly remediationStatus: string | undefined;
  readonly timestamp: string | undefined;
  readonly manualRemediationUrl?: string;
  readonly controlSettingsUrl?: string;
  readonly iacCloudformationYaml?: string;
  readonly iacCloudformationJson?: string;
  readonly iacTerraform?: string;
  readonly iacCdk?: string;
  readonly remediationDeadlineDate?: string;
  readonly remediationDeadlineDaysRemaining?: string;
}

function formatDaysRemaining(days: number): string {
  if (days > 0) return `${days} days remaining`;
  if (days < 0) return `${Math.abs(days)} days overdue`;
  return 'due today';
}

export class BatchProcessorService {
  private readonly configRepo: NotificationConfigurationRepository;
  private readonly batchRepo: NotificationBatchRepository;
  private readonly findingRepo: FindingRepository;
  private readonly historyRepo: RemediationHistoryRepository;
  private readonly clock: Clock;

  constructor(
    configTableName: string,
    batchesTableName: string,
    findingsTableName: string,
    remediationHistoryTableName: string,
    dynamoDBClient: DynamoDBDocumentClient,
    private readonly logger: Logger,
    private readonly snsClient: SNSClient,
    private readonly channelFanoutTopicArn: string,
    private readonly s3Client: S3Client,
    private readonly csvExportBucketName: string,
    staleProcessingMs?: number,
    clock?: Clock,
  ) {
    this.configRepo = new NotificationConfigurationRepository(configTableName, dynamoDBClient);
    this.batchRepo = new NotificationBatchRepository(BATCH_PROCESSOR_PRINCIPAL, batchesTableName, dynamoDBClient, {
      staleProcessingMs,
      clock,
    });
    this.findingRepo = new FindingRepository(BATCH_PROCESSOR_PRINCIPAL, findingsTableName, dynamoDBClient);
    this.historyRepo = new RemediationHistoryRepository(
      BATCH_PROCESSOR_PRINCIPAL,
      remediationHistoryTableName,
      dynamoDBClient,
      findingsTableName,
    );
    this.clock = clock ?? getClock();
  }

  /**
   * Main entry point: queries all ready batches across all configs and processes them.
   * Called by the EventBridge-triggered Lambda handler.
   */
  async processBatches(): Promise<BatchProcessingResult> {
    const configs = await this.configRepo.findAll();
    const now = this.clock.now().toISOString();

    let processedCount = 0;
    let sentCount = 0;
    let skippedCount = 0;
    let failedCount = 0;

    for (const config of configs) {
      if (!config.batchWindow.enabled) continue;

      const readyBatches = await this.batchRepo.queryOpenBatchesReady(config.configId, now);

      for (const batch of readyBatches) {
        processedCount++;
        try {
          const result = await this.processBatch(config, batch);
          if (result === 'sent') sentCount++;
          else if (result === 'skipped') skippedCount++;
        } catch (error) {
          failedCount++;
          this.logger.error('Failed to process batch', {
            configId: config.configId,
            windowEnd: batch.windowEnd,
            error,
          });
        }
      }
    }

    this.logger.info('Batch processing complete', { processedCount, sentCount, skippedCount, failedCount });
    return { processedCount, sentCount, skippedCount, failedCount };
  }

  private async processBatch(
    config: NotificationConfigurationItem,
    batch: NotificationBatchItem,
  ): Promise<'sent' | 'skipped'> {
    const processingStartMs = this.clock.now().getTime();
    try {
      const result = await this.runBatch(config, batch);
      await this.emitBatchProcessingTimeMetric(config.configId, processingStartMs, 'success');
      return result;
    } catch (error) {
      await this.emitBatchProcessingTimeMetric(config.configId, processingStartMs, 'failed');
      throw error;
    }
  }

  /**
   * Emits a `batch_processing_time` data point (milliseconds) to the
   * SolutionsMetrics API for both successful and failed batch runs, tagged with
   * config_id and a result flag. Best-effort — sendMetrics never rejects.
   */
  private async emitBatchProcessingTimeMetric(
    configId: string,
    startMs: number,
    result: 'success' | 'failed',
  ): Promise<void> {
    await sendMetrics({
      batch_processing_time: this.clock.now().getTime() - startMs,
      config_id: configId,
      result,
    });
  }

  private async runBatch(
    config: NotificationConfigurationItem,
    batch: NotificationBatchItem,
  ): Promise<'sent' | 'skipped'> {
    await this.batchRepo.updateStatus(config.configId, batch.windowEnd, 'processing');

    try {
      const currentConfig = await this.configRepo.findConfigById(config.configId);
      if (!currentConfig) {
        return this.skipBatch(config.configId, batch.windowEnd, 'Config no longer exists, draining orphan batch');
      }

      if (!currentConfig.enabled) {
        return this.skipBatch(config.configId, batch.windowEnd, 'Config disabled, skipping batch');
      }

      const allFindingIds = batch.findingIds ?? [];
      const remediationIds = [...new Set(batch.remediationIds ?? [])];

      const activeFindings = await this.filterActiveFindings(config.configId, allFindingIds);

      if (activeFindings.length === 0 && remediationIds.length === 0) {
        return this.skipBatch(config.configId, batch.windowEnd, 'All findings remediated, completing batch');
      }

      const enabledChannels = currentConfig.deliveryChannels.filter((ch) => ch.enabled);
      if (enabledChannels.length === 0) {
        return this.skipBatch(config.configId, batch.windowEnd, 'No enabled delivery channels, skipping batch');
      }

      // Fetch remediation history items for remediation-only batches (shared by CSV export and event summaries).
      const remediationHistoryItems =
        activeFindings.length === 0 && remediationIds.length > 0
          ? await this.historyRepo.findLatestByFindingIds(remediationIds)
          : [];

      // Generate CSV export URL when the config has batch export enabled (may be undefined otherwise).
      const csvExport = await this.generateCsvExport(currentConfig, batch, activeFindings, remediationHistoryItems);

      const findingCount = currentConfig.notificationType === 'finding' ? activeFindings.length : 0;
      const remediationCount = currentConfig.notificationType === 'remediation' ? remediationIds.length : 0;

      await this.publishToChannels(config.configId, currentConfig, enabledChannels, {
        findingCount,
        remediationCount,
        csvExport,
        activeFindings,
        remediationHistoryItems,
      });

      await this.batchRepo.updateStatus(config.configId, batch.windowEnd, 'dispatched');
      return 'sent';
    } catch (error) {
      await this.batchRepo.rollbackToOpen(config.configId, batch.windowEnd).catch((rollbackErr) =>
        this.logger.error('Failed to roll back batch status', {
          configId: config.configId,
          windowEnd: batch.windowEnd,
          rollbackErr,
        }),
      );
      throw error;
    }
  }

  private async skipBatch(configId: string, windowEnd: string, reason: string): Promise<'skipped'> {
    this.logger.info(reason, { configId, windowEnd });
    await this.batchRepo.updateStatus(configId, windowEnd, 'dispatched');
    return 'skipped';
  }

  /** Filters out already-remediated findings, processing in chunks to respect query limits. */
  private async filterActiveFindings(configId: string, allFindingIds: FindingId[]): Promise<FindingTableItem[]> {
    if (allFindingIds.length > MAX_BATCH_QUERY_SIZE) {
      this.logger.debug('Finding IDs exceed MAX_BATCH_QUERY_SIZE, processing in chunks', {
        configId,
        totalFindings: allFindingIds.length,
        chunkSize: MAX_BATCH_QUERY_SIZE,
      });
    }

    const activeFindings: FindingTableItem[] = [];
    const nonDerivableIds: FindingId[] = [];
    for (let i = 0; i < allFindingIds.length; i += MAX_BATCH_QUERY_SIZE) {
      const chunk = allFindingIds.slice(i, i + MAX_BATCH_QUERY_SIZE);
      const chunkResult = await this.filterRemediatedFindings(chunk);
      activeFindings.push(...chunkResult.findings);
      nonDerivableIds.push(...chunkResult.nonDerivableIds);
    }

    if (nonDerivableIds.length > 0) {
      // These ids were never queried, so their findings are absent from this batch rather than
      // filtered out of it. Logged with configId because the repository warn cannot say which
      // notification config was affected, and the fix is an id the batch cannot derive a key for.
      // See ADR 0010.
      this.logger.warn('Findings omitted from batch: no partition key derivable from the finding id', {
        configId,
        nonDerivableCount: nonDerivableIds.length,
        nonDerivableIds,
      });
    }

    return activeFindings;
  }

  /** Publishes batch payload to all enabled channels via SNS; throws if all channels fail. */
  private async publishToChannels(
    configId: string,
    currentConfig: NotificationConfigurationItem,
    enabledChannels: NotificationConfigurationItem['deliveryChannels'],
    batchContext: {
      findingCount: number;
      remediationCount: number;
      csvExport: { url: string; expiresAt: string } | undefined;
      activeFindings: FindingTableItem[];
      remediationHistoryItems: RemediationHistoryTableItem[];
    },
  ): Promise<void> {
    const MAX_EVENT_SUMMARIES = 10;
    const summaryFindings =
      batchContext.activeFindings.length > 0 ? batchContext.activeFindings : batchContext.remediationHistoryItems;
    const eventSummaries = summaryFindings.slice(0, MAX_EVENT_SUMMARIES).map((f) => ({
      eventId: f.findingId,
      controlId: f.findingType.replace(/^security-control\//, ''),
      accountId: f.accountId,
      region: f.region,
      severity: f.severity,
      resourceId: f.resourceId,
      remediationStatus: getDisplayRemediationStatus(f),
      ...(f.error && { remediationMessage: f.error }),
    }));

    const batchPayload = {
      configId,
      configName: currentConfig.name,
      notificationType: currentConfig.notificationType,
      contentOptions: currentConfig.contentOptions,
      isBatch: true,
      findingCount: batchContext.findingCount,
      remediationCount: batchContext.remediationCount,
      startGenerationTime: this.clock.now().toISOString(),
      ...(eventSummaries.length > 0 && { eventSummaries }),
      ...(batchContext.csvExport?.url && {
        exportUrl: batchContext.csvExport.url,
        linkAccessExpirationTime: batchContext.csvExport.expiresAt,
      }),
    };

    const results = await Promise.allSettled(
      enabledChannels.map((channel) =>
        this.snsClient.send(
          new PublishCommand({
            TopicArn: this.channelFanoutTopicArn,
            Message: JSON.stringify({ ...batchPayload, channel }),
            MessageAttributes: {
              channelType: { DataType: 'String', StringValue: channel.type },
              configId: { DataType: 'String', StringValue: configId },
            },
          }),
        ),
      ),
    );

    const rejected = results.filter((r): r is PromiseRejectedResult => r.status === 'rejected');
    if (rejected.length > 0) {
      for (let i = 0; i < results.length; i++) {
        const result = results[i];
        if (result.status === 'rejected') {
          this.logger.error('Failed to publish to channel', {
            configId,
            channelType: enabledChannels[i].type,
            error: result.reason,
          });
        }
      }
      if (rejected.length === enabledChannels.length) {
        throw rejected[0].reason;
      }
    }
  }

  /**
   * Export batch contents (findings + remediations) to CSV in S3 and return
   * a pre-signed URL plus the URL expiration timestamp. Returns undefined when:
   *   - the export bucket is not configured,
   *   - the user has not opted into batch export for this configuration,
   *   - both the active findings and remediation IDs are empty, or
   *   - the export fails (error is logged).
   */
  private async generateCsvExport(
    currentConfig: NotificationConfigurationItem,
    batch: NotificationBatchItem,
    activeFindings: FindingTableItem[],
    remediationHistoryItems: RemediationHistoryTableItem[],
  ): Promise<{ url: string; expiresAt: string } | undefined> {
    if (!this.csvExportBucketName) return undefined;
    if (!currentConfig.batchExport?.enabled) return undefined;
    if (activeFindings.length === 0 && remediationHistoryItems.length === 0) return undefined;

    try {
      // For remediation batches, export from history table (not findings table)
      // to avoid missing data when findings haven't been ingested by the pre-processor.
      if (activeFindings.length === 0 && remediationHistoryItems.length > 0) {
        return await this.exportRemediationHistoryToCsv(currentConfig, batch, remediationHistoryItems);
      }
      return await this.exportBatchToCsv(currentConfig, batch, activeFindings);
    } catch (err) {
      this.logger.error('CSV export failed, proceeding without export URL', {
        configId: currentConfig.configId,
        error: err,
      });
      return undefined;
    }
  }

  /** Export batch findings to CSV in S3, return pre-signed URL and its expiration timestamp. */
  private async exportBatchToCsv(
    config: NotificationConfigurationItem,
    batch: NotificationBatchItem,
    findings: FindingTableItem[],
  ): Promise<{ url: string; expiresAt: string }> {
    const webUiUrl = batchProcessorEnvironment().WEB_UI_URL;
    const rows = findings.map((finding) => this.buildBatchCsvRow(config, finding, webUiUrl));
    const csvBody = toCsv(rows, getBatchCsvColumns(config.notificationType));

    const batchId = batch.windowEnd.replace(/[^a-zA-Z0-9-]/g, '-');
    const key = `batch-export-${config.notificationType}-${config.configId}-${batchId}.csv`;

    await this.s3Client.send(
      new PutObjectCommand({
        Bucket: this.csvExportBucketName,
        Key: key,
        Body: csvBody,
        ContentType: 'text/csv',
      }),
    );

    const expirationHours = config.batchExport?.presignedUrlExpirationHours ?? 1;
    const expiresInSeconds = expirationHours * 3600;
    const url = await getSignedUrl(
      this.s3Client,
      new GetObjectCommand({ Bucket: this.csvExportBucketName, Key: key }),
      { expiresIn: expiresInSeconds },
    );
    const expiresAt = new Date(this.clock.now().getTime() + expiresInSeconds * 1000).toISOString();

    this.logger.info('Exported batch to CSV', {
      configId: config.configId,
      key,
      findingCount: findings.length,
      expiresAt,
    });
    return { url, expiresAt };
  }

  /** Export remediation history items to CSV. Used for remediation batches where findings may not exist in the findings table. */
  private async exportRemediationHistoryToCsv(
    config: NotificationConfigurationItem,
    batch: NotificationBatchItem,
    historyItems: RemediationHistoryTableItem[],
  ): Promise<{ url: string; expiresAt: string }> {
    const webUiUrl = batchProcessorEnvironment().WEB_UI_URL;
    const rows = historyItems.map((item) => this.buildHistoryCsvRow(config, item, webUiUrl));
    const csvBody = toCsv(rows, getBatchCsvColumns(config.notificationType));

    const batchId = batch.windowEnd.replace(/[^a-zA-Z0-9-]/g, '-');
    const key = `batch-export-${config.notificationType}-${config.configId}-${batchId}.csv`;

    await this.s3Client.send(
      new PutObjectCommand({
        Bucket: this.csvExportBucketName,
        Key: key,
        Body: csvBody,
        ContentType: 'text/csv',
      }),
    );

    const expirationHours = config.batchExport?.presignedUrlExpirationHours ?? 1;
    const expiresInSeconds = expirationHours * 3600;
    const url = await getSignedUrl(
      this.s3Client,
      new GetObjectCommand({ Bucket: this.csvExportBucketName, Key: key }),
      { expiresIn: expiresInSeconds },
    );
    const expiresAt = new Date(this.clock.now().getTime() + expiresInSeconds * 1000).toISOString();

    this.logger.info('Exported remediation history batch to CSV', {
      configId: config.configId,
      key,
      remediationCount: historyItems.length,
      expiresAt,
    });
    return { url, expiresAt };
  }

  private async filterRemediatedFindings(
    findingIds: FindingId[],
  ): Promise<{ findings: FindingTableItem[]; nonDerivableIds: FindingId[] }> {
    if (findingIds.length === 0) return { findings: [], nonDerivableIds: [] };

    const { findings, nonDerivableIds } = await this.findingRepo.findByFindingIds(findingIds);
    const activeFindings = findings.filter((f) => f.remediationStatus !== 'SUCCESS');

    return { findings: activeFindings, nonDerivableIds };
  }

  /**
   * Build a CSV row mirroring the immediate-notification JSON payload shape
   * (see sns-channel.ts deliver). Fields that apply only to remediation events
   * (remediationMessage, findingLink, etc.) are not stored on FindingTableItem,
   * so they are emitted as empty strings here and can be populated in future
   * iterations once remediation history is joined in.
   */
  private buildBatchCsvRow(
    config: NotificationConfigurationItem,
    finding: FindingTableItem,
    webUiUrl: string | undefined,
  ): BatchCsvRow {
    const eventType = config.notificationType;
    const controlId = finding.findingType.replace(/^security-control\//, '');
    const detectedAt = finding.creationTime;

    const deadlineDays = config.contentOptions?.includeRemediationDeadline
      ? config.contentOptions.remediationDeadlineDays
      : undefined;
    const deadline = deadlineDays && detectedAt ? calculateDeadline(detectedAt, deadlineDays, this.clock) : undefined;

    const linkPath = eventType === 'remediation' ? '/history' : '/findings';

    return {
      configId: config.configId,
      configName: config.name,
      eventType,
      eventId: finding.findingId,
      controlId,
      accountId: finding.accountId,
      region: finding.region,
      severity: finding.severity,
      resourceType: finding.resourceType,
      resourceId: finding.resourceId,
      title: finding.findingDescription,
      description: finding.findingDescription,
      detectedAt,
      remediationStatus: getDisplayRemediationStatus(finding),
      timestamp: finding.lastUpdatedTime,
      ...(webUiUrl && {
        manualRemediationUrl: `${webUiUrl}${linkPath}?findingId=${encodeURIComponent(finding.findingId)}`,
        controlSettingsUrl: `${webUiUrl}/controls?controlId=${encodeURIComponent(controlId)}`,
        ...(isIaCEligible(eventType, finding.remediationStatus) && buildIaCCsvUrls(webUiUrl, finding.findingId)),
      }),
      ...(deadline && {
        remediationDeadlineDate: deadline.deadlineDate,
        remediationDeadlineDaysRemaining: formatDaysRemaining(deadline.daysRemaining),
      }),
    };
  }

  private buildHistoryCsvRow(
    config: NotificationConfigurationItem,
    item: RemediationHistoryTableItem,
    webUiUrl: string | undefined,
  ): BatchCsvRow {
    const controlId = item.findingType;

    return {
      configId: config.configId,
      configName: config.name,
      eventType: 'remediation',
      eventId: item.findingId,
      controlId,
      accountId: item.accountId,
      region: item.region,
      severity: item.severity,
      resourceType: item.resourceType,
      resourceId: item.resourceId,
      title: controlId,
      description: item.error || '',
      detectedAt: item.lastUpdatedTime,
      remediationStatus: item.remediationStatus,
      timestamp: item.lastUpdatedTime,
      ...(webUiUrl && {
        manualRemediationUrl: `${webUiUrl}/history?findingId=${encodeURIComponent(item.findingId)}`,
        controlSettingsUrl: `${webUiUrl}/controls?controlId=${encodeURIComponent(controlId)}`,
        ...(isIaCEligible('remediation', item.remediationStatus) && buildIaCCsvUrls(webUiUrl, item.findingId)),
      }),
    };
  }
}
