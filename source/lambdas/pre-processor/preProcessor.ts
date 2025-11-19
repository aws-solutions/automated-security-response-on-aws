// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import type { LambdaInterface } from '@aws-lambda-powertools/commons/types';
import { Context, SQSEvent, SQSHandler, SQSRecord } from 'aws-lambda';
import { BatchProcessor, EventType, processPartialResponse } from '@aws-lambda-powertools/batch';
import { FindingEventNormalizer } from './Normalizer/findingEventNormalizer';
import { RemediationConfigChecker } from './RemediationConfigChecker';
import { ASFFFinding, FindingTableItem, InvalidFindingSchemaError, SEVERITY_MAPPING } from '@asr/data-models';
import { FindingDataService, normalizeResourceType } from '../common/services/findingDataService';
import { RemediationHistoryRepository } from '../common/repositories/remediationHistoryRepository';
import { createDynamoDBClient } from '../common/utils/dynamodb';
import { executeOrchestrator } from '../common/utils/orchestrator';
import { buildFailureMetric, buildFilteringMetric, sendMetrics } from '../common/utils/metricsUtils';
import { applyFilters, FilterResult } from '../common/utils/filterUtils';
import { getLogger } from '../common/utils/logger';
import { getTracer } from '../common/utils/tracer';
import { getControlIdFromFindingId, sanitizeControlId } from '../common/utils/findingUtils';
import { FINDING_PRINCIPAL } from '../common/constants/apiConstant';

// Fetch required lambda environment variables
const SOLUTION_TRADEMARKEDNAME = process.env.SOLUTION_TRADEMARKEDNAME ?? 'unknown';
const FINDINGS_TABLE_NAME = process.env.FINDINGS_TABLE_ARN?.split('/')[1];
const REMEDIATION_CONFIG_TABLE_NAME = process.env.REMEDIATION_CONFIG_TABLE_ARN?.split('/')[1];
const REMEDIATION_HISTORY_TABLE_NAME = process.env.REMEDIATION_HISTORY_TABLE_ARN?.split('/')[1];

if (!FINDINGS_TABLE_NAME) throw new Error('FINDINGS_TABLE_ARN environment variable is required');

if (!REMEDIATION_CONFIG_TABLE_NAME) throw new Error('REMEDIATION_CONFIG_TABLE_ARN environment variable is required');

if (!REMEDIATION_HISTORY_TABLE_NAME) throw new Error('REMEDIATION_HISTORY_TABLE_ARN environment variable is required');

const tracer = getTracer(SOLUTION_TRADEMARKEDNAME);
const logger = getLogger(SOLUTION_TRADEMARKEDNAME);
const processor = new BatchProcessor(EventType.SQS);

const dynamoDBClient = tracer.captureAWSv3Client(
  createDynamoDBClient({
    maxAttempts: 10,
  }),
);

const findingDataService = new FindingDataService(FINDINGS_TABLE_NAME!, dynamoDBClient, FINDING_PRINCIPAL);

const remediationHistoryRepository = new RemediationHistoryRepository(
  FINDING_PRINCIPAL,
  REMEDIATION_HISTORY_TABLE_NAME!,
  dynamoDBClient,
  FINDINGS_TABLE_NAME!,
);

export class PreProcessor implements LambdaInterface {
  @tracer.captureLambdaHandler()
  @logger.injectLambdaContext()
  async handler(event: SQSEvent, context: Context) {
    return processPartialResponse(event, PreProcessor.recordHandler, processor, {
      context,
    });
  }

  static buildOrchestratorInput(payload: any, finding: ASFFFinding): string {
    const newPayload = {
      ...payload,
      detail: {
        ...payload.detail,
        findings: [finding],
        actionName: 'None', // no Custom Action was used
      },
    };
    return JSON.stringify(newPayload);
  }

  private static async determineRemediationConfigForFindingType(
    findingType: string,
  ): Promise<{ isSupported: boolean; autoRemediationEnabled: boolean }> {
    const remediationConfigChecker = new RemediationConfigChecker(
      findingType,
      dynamoDBClient,
      REMEDIATION_CONFIG_TABLE_NAME!,
      logger,
    );

    const remediationIsSupported = await remediationConfigChecker.isSupported();
    if (!remediationIsSupported) return { isSupported: false, autoRemediationEnabled: false }; // unsupported finding type - do not continue processing this record

    const autoRemediationEnabled = await remediationConfigChecker.isAutomatedRemediationEnabled();
    return { isSupported: true, autoRemediationEnabled };
  }

  private static async applyFiltersAndSendMetrics(finding: ASFFFinding): Promise<FilterResult> {
    let filterResult: FilterResult = { passed: true, appliedFilter: 'none' };

    try {
      filterResult = await applyFilters(finding, logger);
      await sendMetrics(buildFilteringMetric(filterResult.appliedFilter));

      if (!filterResult.passed) {
        logger.info('Finding blocked by filters, skipping remediation', {
          findingId: finding.Id,
          appliedFilter: filterResult.appliedFilter,
        });
      }
    } catch (error) {
      logger.error('Error applying filters, allowing remediation to proceed as fail-safe', {
        findingId: finding.Id,
        error,
      });
      await sendMetrics(buildFilteringMetric(filterResult.appliedFilter));
    }

    return filterResult;
  }

  private static shouldTriggerRemediation(
    finding: ASFFFinding,
    autoRemediationEnabled: boolean,
    hasBeenTriggered?: boolean,
    hasPreviouslyFailedRemediation?: boolean,
  ): boolean {
    const baseRequirements =
      autoRemediationEnabled && finding.Compliance.Status === 'FAILED' && finding.RecordState !== 'ARCHIVED';

    return baseRequirements && (!hasBeenTriggered || !!hasPreviouslyFailedRemediation);
  }

  /**
   * Checks if finding should preserve current remediation status without database updates
   * @param finding - The ASFF finding object
   * @param orchestratorInput
   * @returns true if finding should keep current status and skip database updates
   */
  private static isNotified(finding: ASFFFinding, orchestratorInput: string): boolean {
    if (finding.Workflow?.Status !== 'NOTIFIED') {
      return false;
    }

    try {
      const payload = JSON.parse(orchestratorInput);
      const detailType = payload['detail-type'];

      if (
        detailType === 'Security Hub Findings - Custom Action' ||
        detailType === 'Security Hub Findings - API Action'
      ) {
        logger.debug('NOTIFIED workflow detected but detail-type indicates custom/API action - not preserving status', {
          findingId: finding.Id,
          detailType: detailType,
        });
        return false;
      }

      logger.debug('NOTIFIED workflow detected - preserving current remediation status', {
        findingId: finding.Id,
        workflowStatus: finding.Workflow.Status,
        detailType: detailType,
      });
    } catch (error) {
      logger.warn('Failed to parse orchestrator input for detail-type check, defaulting to preserve NOTIFIED status', {
        findingId: finding.Id,
        error: error,
      });
    }
    return true;
  }

  /**
   * Prepares finding and orchestrator input for NOTIFIED status preservation
   * Updates the finding workflow status to NEW and modifies the orchestrator input payload
   * @param finding - The ASFF finding object
   * @param orchestratorInput - The orchestrator input JSON string
   * @returns Object containing updated finding and orchestrator input
   */
  private static mapNotifiedFindingForOrchestrator(
    finding: ASFFFinding,
    orchestratorInput: string,
  ): { finding: ASFFFinding; orchestratorInput: string } {
    const updatedFinding = {
      ...finding,
      Workflow: {
        ...finding.Workflow,
        Status: 'NEW' as const,
      },
    };

    const payload = JSON.parse(orchestratorInput);
    const newPayload = {
      ...payload,
      detail: {
        ...payload.detail,
        findings: [updatedFinding],
      },
    };

    return {
      finding: updatedFinding,
      orchestratorInput: JSON.stringify(newPayload),
    };
  }

  /**
   * Handles orchestrator execution for NOTIFIED findings
   * Executes the orchestrator directly without creating history items
   * @param finding - The ASFF finding object
   * @param orchestratorInput - The orchestrator input JSON string
   * @returns true if orchestrator was executed successfully, false otherwise
   */
  private static async handleNotifiedFindingOrchestration(
    finding: ASFFFinding,
    orchestratorInput: string,
  ): Promise<boolean> {
    const executionId = await executeOrchestrator(orchestratorInput, logger);
    if (!executionId) {
      logger.error(`Failed to start orchestrator execution for finding ${finding.Id}`, {
        findingId: finding.Id,
        orchestratorInput,
      });
      return false;
    }

    logger.debug(`Orchestrator execution started for NOTIFIED finding`, {
      executionId,
      findingId: finding.Id,
    });
    return true;
  }

  /**
   * Creates minimal FindingTableItem for history creation fallback
   * @param finding - The ASFF finding object
   * @returns Minimal FindingTableItem for history creation
   */
  private static convertToMinimalFindingForHistory(finding: ASFFFinding): FindingTableItem {
    const timestamp = new Date().toISOString();

    const controlIdFromFindingId = getControlIdFromFindingId(finding.Id) ?? finding.Compliance.SecurityControlId;
    const sanitizedControlId = sanitizeControlId(controlIdFromFindingId);

    const resourceType = finding.Resources[0]?.Type || '';
    const resourceTypeNormalized = normalizeResourceType(resourceType);

    const severity = finding.Severity.Label || 'MEDIUM';
    const severityNormalized = SEVERITY_MAPPING[severity] ?? 0;

    return {
      findingType: sanitizedControlId,
      findingId: finding.Id,
      accountId: finding.AwsAccountId,
      resourceId: finding.Resources[0]?.Id || '',
      resourceType: resourceType,
      resourceTypeNormalized: resourceTypeNormalized,
      severity: severity,
      severityNormalized: severityNormalized,
      region: finding.Region || 'us-east-1',
      remediationStatus: 'IN_PROGRESS',
      lastUpdatedTime: timestamp,
      lastUpdatedBy: FINDING_PRINCIPAL,
      executionId: '',
      error: undefined,
      // Minimal required fields for interface compliance
      findingDescription: '',
      securityHubUpdatedAtTime: timestamp,
      suppressed: false,
      creationTime: finding.CreatedAt || timestamp,
      'securityHubUpdatedAtTime#findingId': `${timestamp}#${finding.Id}`,
      'severityNormalized#securityHubUpdatedAtTime#findingId': `${severityNormalized}#${timestamp}#${finding.Id}`,
      findingJSON: new Uint8Array(0),
      findingIdControl: `${finding.Id}#${sanitizedControlId}`,
      FINDING_CONSTANT: 'finding',
      expireAt: 0,
    };
  }

  /**
   * Executes orchestrator with proper logging and history creation
   * @param orchestratorInput - The input for the orchestrator
   * @param context - Additional context for logging
   * @param historyItem - The finding table item for history creation
   */
  private static async executeOrchestrator(
    orchestratorInput: string,
    context: 'new' | 'existing',
    historyItem: FindingTableItem,
  ): Promise<void> {
    const findingId = historyItem.findingId;

    const executionId = await executeOrchestrator(orchestratorInput, logger);
    if (!executionId) {
      logger.error(`Failed to start orchestrator execution for ${context} finding`, { findingId });
      return;
    }

    logger.debug('Orchestrator execution started', { executionId, findingId, context });

    try {
      historyItem.remediationStatus = 'IN_PROGRESS';

      await remediationHistoryRepository.createRemediationHistory(historyItem, executionId);
      logger.debug('Remediation history created successfully', {
        findingId,
        executionId,
        context,
        historyItem: historyItem,
      });
    } catch (error) {
      logger.error('Failed to create remediation history, but orchestrator execution will continue', {
        findingId,
        executionId,
        context,
        error: error instanceof Error ? error.message : String(error),
      });
    }
  }

  private static async processNewFinding(
    finding: ASFFFinding,
    autoRemediationEnabled: boolean,
    orchestratorInput: string,
  ): Promise<void> {
    const triggerRemediation = this.shouldTriggerRemediation(finding, autoRemediationEnabled);

    const status = triggerRemediation ? 'IN_PROGRESS' : 'NOT_STARTED';

    const isNotified = this.isNotified(finding, orchestratorInput);

    let updatedFinding = finding;
    let updatedOrchestratorInput = orchestratorInput;

    if (isNotified) {
      const prepared = this.mapNotifiedFindingForOrchestrator(finding, orchestratorInput);
      updatedFinding = prepared.finding;
      updatedOrchestratorInput = prepared.orchestratorInput;
    }

    const syncResult = await findingDataService.updateWithIncomingData(updatedFinding, status);

    if (triggerRemediation && syncResult.status === 'SUCCESS') {
      const historyItem = syncResult.findingTableItem || this.convertToMinimalFindingForHistory(updatedFinding);
      await this.executeOrchestrator(updatedOrchestratorInput, 'new', historyItem);
    }
    logger.debug(`New entry created in Findings table for ${updatedFinding.Id}`);
  }

  private static async processExistingFinding(
    finding: ASFFFinding,
    autoRemediationEnabled: boolean,
    orchestratorInput: string,
  ): Promise<void> {
    const [hasBeenTriggered, hasPreviouslyFailedRemediation] = await Promise.all([
      findingDataService.hasBeenTriggered(finding),
      findingDataService.hasPreviouslyFailedRemediation(finding),
    ]);

    const triggerRemediation = this.shouldTriggerRemediation(
      finding,
      autoRemediationEnabled,
      hasBeenTriggered,
      hasPreviouslyFailedRemediation,
    );

    const isNotified = this.isNotified(finding, orchestratorInput);

    const status = triggerRemediation && !isNotified ? 'IN_PROGRESS' : undefined;
    const syncResult = await findingDataService.updateWithIncomingData(finding, status);

    if (triggerRemediation && syncResult.status === 'SUCCESS') {
      logger.debug(
        `Auto-remediation enabled for ${finding.Compliance.SecurityControlId}. Finding ${!hasBeenTriggered ? 'not yet sent' : 'previously failed'} for remediation.`,
        { findingId: finding.Id },
      );

      if (isNotified) {
        await this.handleNotifiedFindingOrchestration(finding, orchestratorInput);
        return;
      }

      const historyItem = syncResult.findingTableItem || this.convertToMinimalFindingForHistory(finding);
      await this.executeOrchestrator(orchestratorInput, 'existing', historyItem);
    } else {
      logger.debug(
        `Remediation for finding ${finding.Id} is either IN_PROGRESS, SUCCESS, or disabled - skipping orchestrator execution.`,
      );
    }

    logger.info(`Findings table updated for finding ${finding.Id}`);
  }

  static async recordHandler(record: SQSRecord): Promise<void> {
    let unprocessedFinding: Record<any, any> = {};
    let payload: any;

    try {
      payload = JSON.parse(record.body);
      unprocessedFinding = payload.detail.findings[0];
    } catch (error: unknown) {
      logger.info('Received malformed SQS record that is not eligible for a retry, hence skipping this record.', {
        messageId: record?.messageId,
        recordBody: record?.body,
        error: error,
      });

      const truncatedBody = record?.body?.substring(0, 500) ?? '';
      await sendMetrics(buildFailureMetric(error, truncatedBody, unprocessedFinding));
      return;
    }
    try {
      const findingNormalizer = new FindingEventNormalizer(logger);
      const finding: ASFFFinding = await findingNormalizer.normalizeFinding(unprocessedFinding);

      const {
        Id: findingId,
        Compliance: { SecurityControlId: securityControlId },
      } = finding;

      const { isSupported, autoRemediationEnabled } =
        await PreProcessor.determineRemediationConfigForFindingType(securityControlId);
      if (!isSupported) return; // unsupported finding type - do not continue processing this record

      const passFilters = await PreProcessor.applyFiltersAndSendMetrics(finding);
      if (!passFilters.passed) {
        logger.info(`Finding filtered out, skipping remediation for SQS Record ${record.messageId}`, {
          findingId: unprocessedFinding?.Id ?? unprocessedFinding?.finding_info?.uid ?? 'unknown',
          sqsMessageId: record.messageId,
          appliedFilter: passFilters.appliedFilter,
        });
        return;
      }

      const isNewFinding = await findingDataService.isNew(finding);
      logger.debug(`Finding ${findingId} is ${isNewFinding ? 'new' : 'existing'}`);

      const orchestratorInput = PreProcessor.buildOrchestratorInput(payload, finding);

      if (isNewFinding) {
        await PreProcessor.processNewFinding(finding, autoRemediationEnabled, orchestratorInput);
      } else {
        await PreProcessor.processExistingFinding(finding, autoRemediationEnabled, orchestratorInput);
      }
    } catch (error) {
      await sendMetrics(buildFailureMetric(error, undefined, unprocessedFinding));

      logger.error(`Error processing finding from SQS Record ${record.messageId}`, {
        findingId: unprocessedFinding?.Id ?? unprocessedFinding?.finding_info?.uid ?? 'unknown',
        sqsMessageId: record.messageId,
      });

      if (error instanceof InvalidFindingSchemaError) {
        return; // do not waste time retrying findings with an invalid schema
      }

      throw error;
    }
  }
}

const preProcessorClass = new PreProcessor();
export const handler: SQSHandler = preProcessorClass.handler.bind(preProcessorClass);
