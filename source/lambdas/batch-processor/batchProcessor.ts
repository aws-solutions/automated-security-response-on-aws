// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import type { LambdaInterface } from '@aws-lambda-powertools/commons/types';
import type { ScheduledEvent, Context } from 'aws-lambda';
import { BatchProcessorService } from './batchProcessorService';
import { OverdueRemediationService } from './overdueRemediationService';
import { ReconciliationService } from './reconciliationService';
import { ReconciliationTaskRunner } from './reconciliationTaskRunner';
import { batchProcessorEnvironment } from './batchProcessorEnvironment';
import { createDynamoDBClient } from '../common/utils/dynamodb';
import { getLogger } from '../common/utils/logger';
import { getTracer } from '../common/utils/tracer';
import { getClock } from '../common/utils/clock';
import {
  computeStaleProcessingMs,
  NotificationBatchRepository,
} from '../common/repositories/notificationBatchRepository';
import { FindingRepository } from '../common/repositories/findingRepository';
import { RemediationHistoryRepository } from '../common/repositories/remediationHistoryRepository';
import { NotificationConfigurationRepository } from '../common/repositories/notificationConfigurationRepository';
import { FiltersRepository } from '../common/repositories/filtersRepository';
import { ResourceFilterEvaluator } from '../pre-processor/ResourceFilterEvaluator';
import { ErrorUtils } from '../common/utils/errorUtils';
import { SNSClient } from '@aws-sdk/client-sns';
import { S3Client } from '@aws-sdk/client-s3';

const BATCH_PROCESSOR_PRINCIPAL = 'BatchProcessor';
const DEFAULT_ENFORCEMENT_PER_RUN_CAP = 50;

/**
 * Parses the per-run cap for overdue remediation enforcement from its env value, falling back to
 * the default when the variable is unset or not a positive integer.
 */
export function parseEnforcementPerRunCap(raw: string | undefined): number {
  const parsed = Number(raw);
  return Number.isInteger(parsed) && parsed > 0 ? parsed : DEFAULT_ENFORCEMENT_PER_RUN_CAP;
}

const env = batchProcessorEnvironment();

const configTableName = env.NOTIFICATION_CONFIG_TABLE_NAME;
const batchesTableName = env.NOTIFICATION_BATCHES_TABLE_NAME;
const findingsTableName = env.FINDINGS_TABLE_NAME;
const remediationHistoryTableName = env.REMEDIATION_HISTORY_TABLE_NAME;

const tracer = getTracer(env.SOLUTION_TRADEMARKEDNAME);
const logger = getLogger(env.SOLUTION_TRADEMARKEDNAME);

const dynamoDBClient = tracer.captureAWSv3Client(createDynamoDBClient({ maxAttempts: 10 }));
const snsClient = tracer.captureAWSv3Client(new SNSClient({}));
const s3Client = tracer.captureAWSv3Client(new S3Client({}));

const batchProcessorService = new BatchProcessorService(
  configTableName,
  batchesTableName,
  findingsTableName,
  remediationHistoryTableName,
  dynamoDBClient,
  logger,
  snsClient,
  env.CHANNEL_FANOUT_TOPIC_ARN,
  s3Client,
  env.CSV_EXPORT_BUCKET_NAME,
  // Validated by requireEnvironmentVariables(); optional in interface for stacked-CR build compatibility
  computeStaleProcessingMs(env.LAMBDA_TIMEOUT_SECONDS || ''),
);

const findingRepository = new FindingRepository(BATCH_PROCESSOR_PRINCIPAL, findingsTableName, dynamoDBClient);
const remediationHistoryRepository = new RemediationHistoryRepository(
  BATCH_PROCESSOR_PRINCIPAL,
  remediationHistoryTableName,
  dynamoDBClient,
  findingsTableName,
);

const overdueRemediationService = new OverdueRemediationService(
  findingRepository,
  remediationHistoryRepository,
  logger,
  getClock(),
  parseEnforcementPerRunCap(env.ENFORCEMENT_PER_RUN_CAP),
);

const notificationConfigurationRepository = new NotificationConfigurationRepository(configTableName, dynamoDBClient);
const filtersRepository = new FiltersRepository(env.RESOURCE_FILTERS_TABLE_NAME, dynamoDBClient);
const resourceFilterEvaluator = new ResourceFilterEvaluator(filtersRepository, logger);

const reconciliationService = new ReconciliationService(
  findingRepository,
  notificationConfigurationRepository,
  resourceFilterEvaluator,
  logger,
  getClock(),
);

const notificationBatchRepository = new NotificationBatchRepository(
  BATCH_PROCESSOR_PRINCIPAL,
  batchesTableName,
  dynamoDBClient,
);

const reconciliationTaskRunner = new ReconciliationTaskRunner(
  reconciliationService,
  notificationBatchRepository,
  logger,
);

export class BatchProcessorHandler implements LambdaInterface {
  @tracer.captureLambdaHandler()
  @logger.injectLambdaContext()
  async handler(_event: ScheduledEvent, _context: Context): Promise<void> {
    const result = await batchProcessorService.processBatches();
    logger.info('Batch processor invocation complete', { result });

    // Reconciliation runs before overdue remediation so config-change updates to remediationDueBy
    // are applied before this invocation scans for overdue findings. It is best-effort: any failure
    // is logged but must not prevent overdue remediation or the handler from completing.
    try {
      await reconciliationTaskRunner.runOutstandingReconciliationTasks();
    } catch (error) {
      logger.error('Reconciliation task processing failed; continuing with overdue remediation', {
        error: ErrorUtils.formatErrorMessage(error),
      });
    }

    // Enforcement runs after batch processing and is best-effort: any failure is logged but must
    // not prevent the handler from completing, so batch notification processing is never blocked.
    try {
      const enforcementResult = await overdueRemediationService.remediateOverdueFindings();
      logger.info('Overdue remediation enforcement complete', { enforcementResult });
    } catch (error) {
      logger.error('Overdue remediation enforcement failed; batch processing result is unaffected', {
        error: ErrorUtils.formatErrorMessage(error),
      });
    }
  }
}

const instance = new BatchProcessorHandler();
export const handler = instance.handler.bind(instance);
