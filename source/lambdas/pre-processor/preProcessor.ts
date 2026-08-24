// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import type { LambdaInterface } from '@aws-lambda-powertools/commons/types';
import { Context, SQSEvent, SQSHandler, SQSRecord } from 'aws-lambda';
import { BatchProcessor, EventType, processPartialResponse } from '@aws-lambda-powertools/batch';
import { FindingEventNormalizer, FindingSchema } from './Normalizer/findingEventNormalizer';
import {
  asffToNormalized,
  ocsfComplianceToNormalized,
  ocsfVulnerabilityToNormalized,
  ocsfDetectionToNormalized,
} from './Normalizer/findingMappers';
import { toAsffShape, getRemediationIdentifier, resolveFindingType } from './Normalizer/normalizedFindingAdapter';
import { RemediationConfigChecker, ControlConfig } from './RemediationConfigChecker';
import { evaluateAutoRemediation, getRetryPolicy, isResourceAutoRemediable } from './autoRemediationPolicy';
import { ResourceFilterEvaluator } from './ResourceFilterEvaluator';
import {
  FindingNotificationConfigEvaluator,
  EligibilityResult,
  FindingConfigEvaluation,
  emptyFindingConfigEvaluation,
} from './findingNotificationConfigEvaluator';
import { mapFindingType, UnverifiedProductArnError } from './findingTypeMapper';
import {
  ASFFFinding,
  FindingTableItem,
  InvalidFindingSchemaError,
  NormalizedFinding,
  NotificationEvent,
  OCSFComplianceFinding,
  OCSFVulnerabilityFinding,
  OCSFDetectionFinding,
  OCSFDataSecurityFinding,
  normalizeSeverity,
  ResolvedFindingType,
} from '@asr/data-models';
import { SQSClient, SendMessageCommand } from '@aws-sdk/client-sqs';
import {
  FindingDataService,
  FindingMetricEnrichment,
  normalizeResourceType,
} from '../common/services/findingDataService';
import { RemediationHistoryRepository } from '../common/repositories/remediationHistoryRepository';
import { FiltersRepository } from '../common/repositories/filtersRepository';
import { FindingRepository } from '../common/repositories/findingRepository';
import { NotificationConfigurationRepository } from '../common/repositories/notificationConfigurationRepository';
import { createDynamoDBClient } from '../common/utils/dynamodb';
import { executeOrchestrator } from '../common/utils/orchestrator';
import { triggerRemediationForFinding } from '../common/utils/remediationTrigger';
import { buildFailureMetric, sendMetrics } from '../common/utils/metricsUtils';
import { emitMetric } from '../common/utils/cloudWatchMetrics';
import { getClock } from '../common/utils/clock';
import { getLogger } from '../common/utils/logger';
import { getTracer } from '../common/utils/tracer';
import { sanitizeControlId, sanitizeFindingId } from '../common/utils/findingUtils';
import { FINDING_PRINCIPAL } from '../common/constants/apiConstant';
import { preProcessorEnvironment } from './preProcessorEnvironment';

const env = preProcessorEnvironment();

const tracer = getTracer(env.SOLUTION_TRADEMARKEDNAME);
const logger = getLogger(env.SOLUTION_TRADEMARKEDNAME);
const processor = new BatchProcessor(EventType.SQS);

const dynamoDBClient = tracer.captureAWSv3Client(createDynamoDBClient({ maxAttempts: 10 }));

const sqsClient = tracer.captureAWSv3Client(new SQSClient({}));
const findingDataService = new FindingDataService(env.FINDINGS_TABLE_NAME, dynamoDBClient, FINDING_PRINCIPAL);

const remediationHistoryRepository = new RemediationHistoryRepository(
  FINDING_PRINCIPAL,
  env.REMEDIATION_HISTORY_TABLE_NAME,
  dynamoDBClient,
  env.FINDINGS_TABLE_NAME,
);

const filtersRepository = new FiltersRepository(env.RESOURCE_FILTERS_TABLE_NAME, dynamoDBClient);
const resourceFilterEvaluator = new ResourceFilterEvaluator(filtersRepository, logger);

const findingRepository = new FindingRepository(FINDING_PRINCIPAL, env.FINDINGS_TABLE_NAME, dynamoDBClient);
const notificationConfigurationRepository = new NotificationConfigurationRepository(
  env.NOTIFICATION_CONFIG_TABLE_NAME,
  dynamoDBClient,
);
const findingNotificationConfigEvaluator = new FindingNotificationConfigEvaluator(
  notificationConfigurationRepository,
  resourceFilterEvaluator,
  getClock(),
  logger,
);

export class PreProcessor implements LambdaInterface {
  @tracer.captureLambdaHandler()
  @logger.injectLambdaContext()
  async handler(event: SQSEvent, context: Context) {
    return processPartialResponse(event, PreProcessor.recordHandler, processor, { context });
  }

  /**
   * Builds orchestrator input payload from a NormalizedFinding.
   * The `raw` field is sent to the Orchestrator so it receives the finding in its native format.
   */
  static buildOrchestratorInput(normalized: NormalizedFinding, payload: any): string {
    const remediationIdentifier = getRemediationIdentifier(normalized);
    const existingDetail = typeof payload?.detail === 'object' && payload.detail !== null ? payload.detail : {};
    return JSON.stringify({
      ...payload,
      detail: {
        ...existingDetail,
        findings: [normalized.raw],
        actionName: 'None',
        findingFormat: normalized.format,
        // Always present so Step Functions can extract it without hitting a missing-path error.
        // For Config findings this is the control ID (e.g. "AutoScaling.1"), for multi-service
        // findings this is the remediation identifier (e.g. "Inspector.InstanceVulnerability").
        remediationId: remediationIdentifier,
        findingType: normalized.findingTypeIdentifier.type,
      },
    });
  }

  private static async determineRemediationConfigForFindingType(
    findingType: string,
  ): Promise<{ isSupported: false } | { isSupported: true; controlConfig: ControlConfig }> {
    const checker = new RemediationConfigChecker(
      findingType,
      dynamoDBClient,
      env.REMEDIATION_CONFIG_TABLE_NAME,
      logger,
    );
    const isSupported = await checker.isSupported();
    if (!isSupported) return { isSupported: false };
    const controlConfig = await checker.getControlConfig();
    if (!controlConfig) return { isSupported: false };
    return { isSupported: true, controlConfig };
  }

  private static async applyResourceFilters(
    normalized: NormalizedFinding,
    controlConfig: ControlConfig,
  ): Promise<{ passed: boolean; reason: string }> {
    try {
      const result = await resourceFilterEvaluator.evaluateFilters(
        normalized,
        controlConfig.filters,
        controlConfig.filterMode,
      );
      if (!result.passed) {
        logger.info('Finding blocked by resource filters, skipping remediation', {
          findingId: normalized.id,
          reason: result.reason,
          filterMode: controlConfig.filterMode,
          filterCount: controlConfig.filters.length,
        });
      }
      return result;
    } catch (error) {
      logger.error('Error applying resource filters, blocking remediation as fail-safe', {
        findingId: normalized.id,
        error,
      });
      return { passed: false, reason: 'error_failsafe' };
    }
  }

  /**
   * Returns true when the finding should be skipped because it was filtered out
   * by the control's resource filters. Returns false when there are no filters
   * or the finding passes them.
   */
  private static async shouldSkipForResourceFilters(
    normalized: NormalizedFinding,
    controlConfig: ControlConfig,
    messageId: string,
  ): Promise<boolean> {
    if (controlConfig.filters.length === 0) {
      return false;
    }
    const resourceFilterResult = await PreProcessor.applyResourceFilters(normalized, controlConfig);
    if (resourceFilterResult.passed) {
      return false;
    }
    logger.info(`Finding filtered out by resource filters, skipping remediation for SQS Record ${messageId}`, {
      findingId: normalized.id,
      sqsMessageId: messageId,
      reason: resourceFilterResult.reason,
    });
    return true;
  }

  /**
   * Resolves the EventBridge event time to use for downstream timestamps.
   * Returns the raw `payload.time` when it is a valid parseable date string,
   * otherwise undefined (warning once when a non-empty value fails to parse so
   * the pipeline falls back to ASFF timestamps).
   */
  private static resolveEventBridgeTime(payload: { time?: unknown }, findingId: string): string | undefined {
    const rawEventBridgeTime = typeof payload?.time === 'string' ? payload.time : undefined;
    // Treat empty/missing as "no EventBridge time" so callers fall back to ASFF
    // timestamps. Guarding here (rather than only inside the malformed check)
    // keeps the return matching the doc contract: an empty string never leaks out.
    if (!rawEventBridgeTime) return undefined;
    if (Number.isNaN(Date.parse(rawEventBridgeTime))) {
      logger.warn('Ignoring malformed EventBridge time, falling back to ASFF timestamps', {
        findingId,
        eventBridgeTime: rawEventBridgeTime,
      });
      return undefined;
    }
    return rawEventBridgeTime;
  }

  /**
   * Records one auto-remediation attempt (atomic increment + timestamp) so the
   * retry-cap gate can bound future retries.
   *
   * Called at the point the trigger decision is made — i.e. BEFORE the orchestrator
   * is actually started (and before the NOTIFIED early-return path). This is
   * intentional: the cap must count the *decision to remediate*, not a confirmed
   * launch. If the launch itself fails repeatedly, counting only successful
   * launches would let a broken finding re-trigger forever, defeating the cap.
   * Erring toward cap safety, a failed launch still consumes an attempt.
   *
   * Failures of this write are logged and swallowed — a bookkeeping write must
   * never undo or block the remediation already in flight.
   */
  private static async recordRemediationAttempt(historyItem: FindingTableItem): Promise<void> {
    try {
      await findingRepository.recordRemediationAttempt(
        historyItem.findingId,
        historyItem.findingType,
        getClock().now().toISOString(),
      );
    } catch (error) {
      logger.warn('Failed to record remediation attempt count, continuing', {
        findingId: historyItem.findingId,
        error,
      });
    }
  }

  private static isNotified(normalized: NormalizedFinding, orchestratorInput: string): boolean {
    if (normalized.workflowStatus !== 'NOTIFIED') return false;
    try {
      const detailType = JSON.parse(orchestratorInput)['detail-type'];
      if (
        detailType === 'Security Hub Findings - Custom Action' ||
        detailType === 'Security Hub Findings - API Action'
      ) {
        logger.debug('NOTIFIED workflow detected but detail-type indicates custom/API action - not preserving status', {
          findingId: normalized.id,
          detailType,
        });
        return false;
      }
      logger.debug('NOTIFIED workflow detected - preserving current remediation status', {
        findingId: normalized.id,
        workflowStatus: normalized.workflowStatus,
        detailType,
      });
    } catch (error) {
      logger.warn('Failed to parse orchestrator input for detail-type check, defaulting to preserve NOTIFIED status', {
        findingId: normalized.id,
        error,
      });
    }
    return true;
  }

  /**
   * Prepares finding and orchestrator input for NOTIFIED status preservation.
   * Updates the workflow status to NEW in the raw payload for the orchestrator.
   */
  static mapNotifiedFindingForOrchestrator(
    normalized: NormalizedFinding,
    orchestratorInput: string,
  ): { normalized: NormalizedFinding; orchestratorInput: string } {
    const updatedNormalized: NormalizedFinding = { ...normalized, workflowStatus: 'NEW' };

    // Update the raw payload for the orchestrator (format-aware)
    const payload = JSON.parse(orchestratorInput);
    const rawFinding = { ...normalized.raw };
    if (normalized.format === 'ASFF') {
      const existingWorkflow = (rawFinding.Workflow as Record<string, unknown> | undefined) ?? {};
      rawFinding.Workflow = { ...existingWorkflow, Status: 'NEW' };
    } else {
      // OCSF findings encode workflow status via status_id (0=New, 2=Notified, 3=Suppressed).
      // The orchestrator reads findingFormat + the normalized fields from the detail envelope,
      // not the raw OCSF status_id, so leaving the raw payload unmodified is safe.
      // Format-specific raw payload updates will be added when OCSF runbooks are implemented.
      logger.debug('OCSF raw payload not modified for NOTIFIED status — orchestrator uses normalized fields', {
        findingId: normalized.id,
        format: normalized.format,
      });
    }
    const newPayload = { ...payload, detail: { ...payload.detail, findings: [rawFinding] } };

    return {
      normalized: updatedNormalized,
      orchestratorInput: JSON.stringify(newPayload),
    };
  }

  private static async handleNotifiedFindingOrchestration(
    normalized: NormalizedFinding,
    orchestratorInput: string,
  ): Promise<boolean> {
    const executionId = await executeOrchestrator(orchestratorInput, logger);
    if (!executionId) {
      logger.error(`Failed to start orchestrator execution for finding ${normalized.id}`, {
        findingId: normalized.id,
        orchestratorInput,
      });
      return false;
    }
    logger.debug('Orchestrator execution started for NOTIFIED finding', { executionId, findingId: normalized.id });
    return true;
  }

  private static async executeOrchestratorWithHistory(
    orchestratorInput: string,
    context: 'new' | 'existing',
    historyItem: FindingTableItem,
  ): Promise<void> {
    const findingId = historyItem.findingId;
    const executionId = await triggerRemediationForFinding({
      orchestratorInput,
      logger,
      // A history-write failure is logged and swallowed so the orchestrator execution (already
      // started) is not undone and ingestion still succeeds.
      persistHistory: async (execId) => {
        try {
          const inProgressItem = { ...historyItem, remediationStatus: 'IN_PROGRESS' as const };
          await remediationHistoryRepository.createRemediationHistory(inProgressItem, execId);
          logger.debug('Remediation history created successfully', { findingId, executionId: execId, context });
        } catch (error) {
          logger.error('Failed to create remediation history, but orchestrator execution will continue', {
            findingId,
            executionId: execId,
            context,
            error: error instanceof Error ? error.message : String(error),
          });
        }
      },
    });
    if (!executionId) {
      logger.error(`Failed to start orchestrator execution for ${context} finding`, { findingId });
      return;
    }
    logger.debug('Orchestrator execution started', { executionId, findingId, context });
  }

  /**
   * Evaluates a finding against enabled finding-type notification configs, producing the
   * metric-enrichment flags (persisted in the finding write) and the deadline enforcement
   * eligibility (stamped after the write). Runs before the write, so failures are swallowed
   * and safe defaults returned to guarantee ingestion always succeeds; a
   * `DeadlineEnforcementStampFailure` metric is emitted so operators can monitor findings
   * ingested without evaluation.
   */
  private static async evaluateFindingConfigsSafely(normalized: NormalizedFinding): Promise<FindingConfigEvaluation> {
    try {
      return await findingNotificationConfigEvaluator.evaluateFindingConfigs(
        normalized,
        getRemediationIdentifier(normalized),
      );
    } catch (error) {
      logger.warn('Finding config evaluation failed, continuing ingestion without metric enrichment or enforcement', {
        findingId: normalized.id,
        error,
      });
      emitMetric('DeadlineEnforcementStampFailure', 1, [{ name: 'Source', value: 'PreProcessor' }]);
      return emptyFindingConfigEvaluation();
    }
  }

  /**
   * Stamps `remediationDueBy` + `enforcementConfigIds` on a freshly written finding when it is
   * eligible for deadline enforcement. Only NOT_STARTED findings are stamped — auto-remediated
   * findings (IN_PROGRESS) are already being handled. Uses the pre-computed enforcement result
   * (no re-evaluation), and swallows write failures so ingestion always succeeds.
   */
  private static async stampEnforcementDeadline(
    findingTableItem: FindingTableItem | undefined,
    enforcement: EligibilityResult,
  ): Promise<void> {
    if (findingTableItem?.remediationStatus !== 'NOT_STARTED') return;
    if (!enforcement.isEligible || !enforcement.remediationDueBy) return;
    try {
      await findingRepository.stampRemediationDueBy(
        findingTableItem.findingId,
        findingTableItem.findingType,
        enforcement.remediationDueBy,
        enforcement.matchingConfigIds,
      );
    } catch (error) {
      logger.warn('Failed to stamp remediation deadline, finding persisted without enforcement stamp', {
        findingId: findingTableItem.findingId,
        error,
      });
      emitMetric('DeadlineEnforcementStampFailure', 1, [{ name: 'Source', value: 'PreProcessor' }]);
    }
  }

  /** Maps a config evaluation to the metric-enrichment attributes persisted on the finding. */
  private static toMetricEnrichment(evaluation: FindingConfigEvaluation): FindingMetricEnrichment {
    return {
      hasFindingNotificationsEnabled: evaluation.hasNotificationsEnabled,
      hasFindingRemediationDeadlineConfigured: evaluation.hasDeadlineConfigured,
    };
  }

  private static async publishNotificationEvent(
    normalized: NormalizedFinding,
    remediationStatus: string,
  ): Promise<void> {
    try {
      const now = getClock().now().toISOString();
      const event: NotificationEvent = {
        eventType: 'finding',
        eventId: normalized.id,
        controlId: getRemediationIdentifier(normalized),
        accountId: normalized.accountId,
        region: normalized.region,
        severity: normalized.severity,
        resourceType: normalized.resources[0]?.type || '',
        resourceId: normalized.resources[0]?.id || '',
        title: normalized.title,
        description: normalized.description,
        detectedAt: normalized.createdAt,
        remediationStatus,
        timestamp: now,
      };
      await sqsClient.send(
        new SendMessageCommand({ QueueUrl: env.NOTIFICATION_QUEUE_URL, MessageBody: JSON.stringify(event) }),
      );
    } catch (error) {
      logger.warn('Failed to publish notification event, continuing processing', { findingId: normalized.id, error });
    }
  }

  private static async processNewFinding(
    normalized: NormalizedFinding,
    autoRemediationEnabled: boolean,
    isResourceRemediable: boolean,
    orchestratorInput: string,
    eventBridgeTime?: string,
  ): Promise<void> {
    const asffShape = toAsffShape(normalized);
    const findingType = resolveFindingType(normalized);
    // A brand-new finding has no prior attempts, so the cap/cooldown never
    // applies here; only the base requirements and resource eligibility gate it.
    const { shouldTrigger: triggerRemediation } = evaluateAutoRemediation({
      normalized,
      autoRemediationEnabled,
      isResourceRemediable,
      hasBeenTriggered: false,
      hasPreviouslyFailedRemediation: false,
      attempts: 0,
      lastAttemptTime: undefined,
      retryPolicy: getRetryPolicy(env),
      now: getClock().now(),
    });
    const status = triggerRemediation ? 'IN_PROGRESS' : 'NOT_STARTED';
    const notified = this.isNotified(normalized, orchestratorInput);

    let currentNormalized = normalized;
    let currentOrchestratorInput = orchestratorInput;

    if (notified) {
      const prepared = this.mapNotifiedFindingForOrchestrator(normalized, orchestratorInput);
      currentNormalized = prepared.normalized;
      currentOrchestratorInput = prepared.orchestratorInput;
    }

    const evaluation = await this.evaluateFindingConfigsSafely(currentNormalized);

    const syncResult = await findingDataService.updateWithIncomingData(
      notified ? toAsffShape(currentNormalized) : asffShape,
      findingType,
      status,
      false,
      eventBridgeTime,
      this.toMetricEnrichment(evaluation),
    );

    if (triggerRemediation && syncResult.status === 'SUCCESS') {
      const historyItem = syncResult.findingTableItem || convertToMinimalFindingForHistory(asffShape, findingType);
      await this.recordRemediationAttempt(historyItem);
      await this.executeOrchestratorWithHistory(currentOrchestratorInput, 'new', historyItem);
    }
    if (syncResult.status === 'SUCCESS') {
      await this.stampEnforcementDeadline(syncResult.findingTableItem, evaluation.enforcement);
    }
    logger.debug(`New entry created in Findings table for ${normalized.id}`);
    await this.publishNotificationEvent(currentNormalized, triggerRemediation ? 'IN_PROGRESS' : 'NOT_STARTED');
  }

  private static async processExistingFinding(
    normalized: NormalizedFinding,
    autoRemediationEnabled: boolean,
    isResourceRemediable: boolean,
    orchestratorInput: string,
    eventBridgeTime?: string,
  ): Promise<void> {
    const asffShape = toAsffShape(normalized);
    const findingType = resolveFindingType(normalized);
    const [hasBeenTriggered, hasPreviouslyFailedRemediation, attemptInfo] = await Promise.all([
      findingDataService.hasBeenTriggered(asffShape, findingType),
      findingDataService.hasPreviouslyFailedRemediation(asffShape, findingType),
      findingDataService.getRemediationAttemptInfo(asffShape, findingType),
    ]);

    const { shouldTrigger: triggerRemediation, capReached } = evaluateAutoRemediation({
      normalized,
      autoRemediationEnabled,
      isResourceRemediable,
      hasBeenTriggered,
      hasPreviouslyFailedRemediation,
      attempts: attemptInfo.attempts,
      lastAttemptTime: attemptInfo.lastAttemptTime,
      retryPolicy: getRetryPolicy(env),
      now: getClock().now(),
    });
    if (capReached) {
      logger.warn('Auto-remediation retry cap reached; not retrying this finding', {
        findingId: normalized.id,
        attempts: attemptInfo.attempts,
      });
      emitMetric('RemediationRetryCapReached', 1, [{ name: 'Source', value: 'PreProcessor' }]);
    }
    const notified = this.isNotified(normalized, orchestratorInput);
    const status = triggerRemediation && !notified ? 'IN_PROGRESS' : undefined;
    const evaluation = await this.evaluateFindingConfigsSafely(normalized);
    const syncResult = await findingDataService.updateWithIncomingData(
      asffShape,
      findingType,
      status,
      false,
      eventBridgeTime,
      this.toMetricEnrichment(evaluation),
    );

    if (triggerRemediation && syncResult.status === 'SUCCESS') {
      const remediationIdentifier = getRemediationIdentifier(normalized);
      logger.debug(
        `Auto-remediation enabled for ${remediationIdentifier}. Finding ${hasBeenTriggered ? 'previously failed' : 'not yet sent'} for remediation.`,
        { findingId: normalized.id },
      );
      const historyItem = syncResult.findingTableItem || convertToMinimalFindingForHistory(asffShape, findingType);
      // Record the attempt before either orchestration path runs — including the
      // NOTIFIED branch below. This is intentional: the NOTIFIED path still
      // launches an orchestrator execution (via handleNotifiedFindingOrchestration),
      // so it is a real remediation attempt and must consume a retry-cap slot.
      // Counting it here (at the trigger decision, before launch) keeps the cap
      // safe against a deterministically-failing finding regardless of which
      // orchestration path is taken.
      await this.recordRemediationAttempt(historyItem);
      if (notified) {
        await this.handleNotifiedFindingOrchestration(normalized, orchestratorInput);
        return;
      }
      await this.executeOrchestratorWithHistory(orchestratorInput, 'existing', historyItem);
    } else {
      logger.debug(
        `Remediation for finding ${normalized.id} is either IN_PROGRESS, SUCCESS, or disabled - skipping orchestrator execution.`,
      );
    }
    if (syncResult.status === 'SUCCESS') {
      await this.stampEnforcementDeadline(syncResult.findingTableItem, evaluation.enforcement);
    }
    logger.info(`Findings table updated for finding ${normalized.id}`);
    await this.publishNotificationEvent(normalized, triggerRemediation ? 'IN_PROGRESS' : 'NOT_STARTED');
  }

  /**
   * Maps a detected multi-service finding to a NormalizedFinding using the
   * schema-specific mapper. OCSF Data Security (Macie) reuses the detection
   * mapper (shared envelope); ASFF-shaped multi-service findings are forced to
   * complianceStatus FAILED so auto-remediation stays reachable even when the
   * finding lacks a Compliance block.
   */
  /**
   * Best-effort finding id for logging, read from a raw (untyped) finding record.
   * Confines the untyped access to a single narrow point: prefers the OCSF
   * `finding_info.uid`, falls back to the ASFF `Id`, then 'unknown'.
   */
  private static rawFindingId(unprocessedFinding: Record<string, unknown>): string {
    const findingInfo = unprocessedFinding.finding_info;
    const ocsfUid =
      typeof findingInfo === 'object' && findingInfo !== null ? (findingInfo as { uid?: unknown }).uid : undefined;
    const id = ocsfUid ?? unprocessedFinding.Id;
    return typeof id === 'string' ? id : 'unknown';
  }

  private static mapMultiServiceFinding(
    unprocessedFinding: Record<string, unknown>,
    schema: FindingSchema,
    multiServiceMapping: NonNullable<ReturnType<typeof mapFindingType>>,
  ): NormalizedFinding {
    if (schema === FindingSchema.OCSF_VULNERABILITY) {
      return ocsfVulnerabilityToNormalized(unprocessedFinding as OCSFVulnerabilityFinding, multiServiceMapping);
    }
    if (schema === FindingSchema.OCSF_DETECTION) {
      return ocsfDetectionToNormalized(unprocessedFinding as OCSFDetectionFinding, multiServiceMapping);
    }
    if (schema === FindingSchema.OCSF_DATA_SECURITY) {
      return ocsfDetectionToNormalized(unprocessedFinding as OCSFDataSecurityFinding, multiServiceMapping);
    }
    if (schema === FindingSchema.ASFF) {
      const normalized = asffToNormalized(unprocessedFinding as ASFFFinding);
      return {
        ...normalized,
        findingTypeIdentifier: { type: 'multiService', value: multiServiceMapping.remediationId },
        complianceStatus: 'FAILED',
      };
    }
    throw new InvalidFindingSchemaError(['ASFF', 'OCSF_VULNERABILITY', 'OCSF_DETECTION', 'OCSF_DATA_SECURITY']);
  }

  /**
   * Resolves an unprocessed finding to a NormalizedFinding based on its detected
   * schema and multi-service mapping. Returns null for an intentionally dropped
   * finding — a multi-service (Inspector/GuardDuty/Macie) OCSF finding whose type
   * has no supported remediation (e.g. an Inspector finding on a Lambda function
   * or ECR image); this is an expected drop, logged here without a failure metric.
   * Throws {@link InvalidFindingSchemaError} for a genuinely unrecognized schema.
   */
  private static async mapRecordToNormalized(
    unprocessedFinding: Record<string, unknown>,
    schema: FindingSchema,
    multiServiceMapping: ReturnType<typeof mapFindingType>,
    findingNormalizer: FindingEventNormalizer,
    sqsMessageId: string | undefined,
  ): Promise<NormalizedFinding | null> {
    if (multiServiceMapping) {
      return PreProcessor.mapMultiServiceFinding(unprocessedFinding, schema, multiServiceMapping);
    }
    if (schema === FindingSchema.OCSF) {
      // OCSF Compliance finding: normalize to ASFF, then map
      const asffNormalized = await findingNormalizer.normalizeFinding(unprocessedFinding);
      return ocsfComplianceToNormalized(unprocessedFinding as OCSFComplianceFinding, asffNormalized);
    }
    if (schema === FindingSchema.ASFF) {
      // Standard ASFF finding
      return asffToNormalized(unprocessedFinding as ASFFFinding);
    }
    if (
      schema === FindingSchema.OCSF_VULNERABILITY ||
      schema === FindingSchema.OCSF_DETECTION ||
      schema === FindingSchema.OCSF_DATA_SECURITY
    ) {
      logger.info('Dropping multi-service finding with no supported remediation for its resource or finding type', {
        findingId: PreProcessor.rawFindingId(unprocessedFinding),
        schema,
        sqsMessageId,
      });
      return null;
    }
    throw new InvalidFindingSchemaError(['ASFF', 'OCSF', 'OCSF_VULNERABILITY', 'OCSF_DETECTION', 'OCSF_DATA_SECURITY']);
  }

  /**
   * Unified record handler. Detects finding schema, maps to NormalizedFinding,
   * then runs a single pipeline regardless of finding format.
   */
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
        error,
      });
      const truncatedBody = record?.body?.substring(0, 500) ?? '';
      await sendMetrics(buildFailureMetric(error, truncatedBody, unprocessedFinding));
      return;
    }

    try {
      const findingNormalizer = new FindingEventNormalizer(logger);
      const findingLogger = {
        info: (msg: string, extra?: Record<string, unknown>) => logger.info(msg, extra ?? {}),
        warn: (msg: string, extra?: Record<string, unknown>) => logger.warn(msg, extra ?? {}),
        debug: (msg: string, extra?: Record<string, unknown>) => logger.debug(msg, extra ?? {}),
      };

      // Step 1: Detect schema and check for multi-service mapping
      const schema = await findingNormalizer.detectFindingSchema(unprocessedFinding);
      const multiServiceMapping = mapFindingType(unprocessedFinding, findingLogger);

      // Step 2: Map to NormalizedFinding based on schema + mapping. Returns null
      // for an intentionally dropped finding (a multi-service OCSF finding with no
      // supported remediation), which the mapper has already logged.
      const normalized = await PreProcessor.mapRecordToNormalized(
        unprocessedFinding,
        schema,
        multiServiceMapping,
        findingNormalizer,
        record.messageId,
      );
      if (!normalized) return;

      // Step 3: Unified pipeline — same for all finding types
      const remediationIdentifier = getRemediationIdentifier(normalized);

      const remediationConfig = await PreProcessor.determineRemediationConfigForFindingType(remediationIdentifier);
      if (!remediationConfig.isSupported) return;

      const { controlConfig } = remediationConfig;

      const autoRemediationEnabled = controlConfig.automatedRemediationEnabled;

      // Apply resource filters
      if (await PreProcessor.shouldSkipForResourceFilters(normalized, controlConfig, record.messageId)) {
        return;
      }

      const asffShape = toAsffShape(normalized);
      const isNewFinding = await findingDataService.isNew(asffShape, resolveFindingType(normalized));
      logger.debug(`Finding ${normalized.id} is ${isNewFinding ? 'new' : 'existing'}`);

      const orchestratorInput = PreProcessor.buildOrchestratorInput(normalized, payload);

      const eventBridgeTime = PreProcessor.resolveEventBridgeTime(payload, normalized.id);

      // Screen out resources this control can never auto-remediate (today:
      // GuardDuty.IAMUser findings on a temporary/assumed-role credential). The
      // finding is still persisted for visibility but is never auto-triggered,
      // so it consumes no executions and cannot feed the re-trigger loop.
      const isResourceRemediable = isResourceAutoRemediable(normalized, remediationIdentifier);
      if (!isResourceRemediable) {
        logger.info(
          'Finding resource is not auto-remediable (temporary/assumed-role credential); persisting without triggering remediation',
          { findingId: normalized.id, remediationId: remediationIdentifier },
        );
        emitMetric('TemporaryCredentialRemediationSkipped', 1, [{ name: 'Source', value: 'PreProcessor' }]);
      }

      if (isNewFinding) {
        await PreProcessor.processNewFinding(
          normalized,
          autoRemediationEnabled,
          isResourceRemediable,
          orchestratorInput,
          eventBridgeTime,
        );
      } else {
        await PreProcessor.processExistingFinding(
          normalized,
          autoRemediationEnabled,
          isResourceRemediable,
          orchestratorInput,
          eventBridgeTime,
        );
      }
    } catch (error) {
      if (error instanceof UnverifiedProductArnError) {
        // The finding claims a multi-service product but its ProductArn is not the reserved
        // AWS service ARN we recognize. Drop it — do NOT fall through to standard
        // SecurityControlId routing, which would otherwise honor an attacker-crafted control id.
        logger.warn(
          'Dropping finding: ProductArn is not the recognized reserved ARN for the claimed multi-service product',
          {
            findingId: unprocessedFinding?.Id ?? unprocessedFinding?.finding_info?.uid ?? 'unknown',
            sqsMessageId: record.messageId,
            productName: error.productName,
            productArn: error.productArn,
            expectedProductArnService: error.expectedProductArnService,
            remediationId: error.remediationId,
          },
        );
        return;
      }
      await sendMetrics(buildFailureMetric(error, undefined, unprocessedFinding));
      logger.error(`Error processing finding from SQS Record ${record.messageId}`, {
        findingId: unprocessedFinding?.Id ?? unprocessedFinding?.finding_info?.uid ?? 'unknown',
        sqsMessageId: record.messageId,
      });
      if (error instanceof InvalidFindingSchemaError) {
        return;
      }
      throw error;
    }
  }
}

const preProcessorClass = new PreProcessor();
export const handler: SQSHandler = preProcessorClass.handler.bind(preProcessorClass);

/** Exported for tests to reset the enforcement-config cache between cases. */
export const __findingNotificationConfigEvaluator = findingNotificationConfigEvaluator;

/**
 * Creates minimal FindingTableItem for history creation fallback
 *
 * @param findingType The resolved partition key, from `resolveFindingType`. Required, because which
 * source it comes from depends on the finding's family and that is not recoverable from the ASFF
 * shape passed here. See ADR 0010.
 */
export const convertToMinimalFindingForHistory = (
  finding: ASFFFinding,
  findingType: ResolvedFindingType,
): FindingTableItem => {
  const timestamp = getClock().now().toISOString();
  const sanitizedControlId = sanitizeControlId(findingType);
  const sanitizedFindingId = sanitizeFindingId(finding.Id, findingType, sanitizedControlId);
  const resourceType = finding.Resources[0]?.Type || '';
  const resourceTypeNormalized = normalizeResourceType(resourceType);
  const severity = finding.Severity.Label || 'MEDIUM';
  const severityNormalized = normalizeSeverity(severity);

  return {
    findingType: sanitizedControlId,
    findingId: sanitizedFindingId,
    accountId: finding.AwsAccountId,
    resourceId: finding.Resources[0]?.Id || '',
    resourceType,
    resourceTypeNormalized,
    severity,
    severityNormalized,
    region: finding.Region || 'us-east-1',
    remediationStatus: 'IN_PROGRESS',
    lastUpdatedTime: timestamp,
    lastUpdatedBy: FINDING_PRINCIPAL,
    executionId: '',
    error: undefined,
    findingDescription: '',
    securityHubUpdatedAtTime: timestamp,
    suppressed: false,
    creationTime: finding.CreatedAt || timestamp,
    'securityHubUpdatedAtTime#findingId': `${timestamp}#${sanitizedFindingId}`,
    'severityNormalized#securityHubUpdatedAtTime#findingId': `${severityNormalized}#${timestamp}#${sanitizedFindingId}`,
    findingJSON: new Uint8Array(0),
    findingIdControl: `${sanitizedFindingId}#${sanitizedControlId}`,
    FINDING_CONSTANT: 'finding',
    expireAt: 0,
  };
};
