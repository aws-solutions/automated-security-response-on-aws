// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import {
  FindingId,
  SuppressionResult,
  FindingsActionRequest,
  FindingsRequest,
  ExportRequest,
  SearchCriteria,
  ACTION_TYPE_TO_ASR_ACTION_NAME,
  ROLLBACK_ELIGIBLE_FINDING_TYPE,
  ROLLBACK_TIMEOUT_MS,
  normalizeSeverity,
  isResourceTypeSupportedForRemediation,
  getSupportedResourceTypes,
} from '@asr/data-models';
import { Logger } from '@aws-lambda-powertools/logger';
import { SCOPE_NAME } from '../../common/constants/apiConstant';
import { FindingRepository } from '../../common/repositories/findingRepository';
import { RemediationHistoryRepository } from '../../common/repositories/remediationHistoryRepository';
import type {
  ASFFFinding,
  FindingApiResponse,
  FindingKey,
  FindingTableItem,
  RemediationHistoryBaseData,
} from '@asr/data-models';
import { ErrorUtils } from '../../common/utils/errorUtils';
import { extractASFFFinding, buildOrchestratorInput } from '../../common/utils/findingExtraction';
import { toCsv, FINDING_CSV_COLUMNS } from '../../common/utils/csvExport';
import { getSecurityHubConsoleUrl, tryFindingKeyFromFindingId } from '../../common/utils/findingUtils';
import { BadRequestError } from '../../common/utils/httpErrors';
import { sendMetrics } from '../../common/utils/metricsUtils';
import { triggerRemediationForFinding } from '../../common/utils/remediationTrigger';
import { calculateTtlTimestamp } from '../../common/utils/ttlUtils';
import { Clock, getClock } from '../../common/utils/clock';
import { IdGenerator, getIdGenerator } from '../../common/utils/idGenerator';
import { AuthenticatedUser } from './authorization';
import { BaseSearchService } from './baseSearchService';
import { ASRS3Client } from '../clients/ASRS3Client';
import { apiLambdaEnvironment } from '../apiLambdaEnvironment';

interface FetchFindingsResult {
  findings: FindingTableItem[];
  unresolvedIds: FindingId[];
}

type PersistHistoryFn = (finding: FindingTableItem, executionId: string) => Promise<void>;

export class FindingsService extends BaseSearchService {
  private readonly findingRepository: FindingRepository;
  private readonly remediationHistoryRepository: RemediationHistoryRepository;
  private readonly s3Client: ASRS3Client;
  private readonly idGenerator: IdGenerator;
  private readonly clock: Clock;

  constructor(
    logger: Logger,
    idGenerator: IdGenerator = getIdGenerator(),
    clock: Clock = getClock(),
    findingRepository?: FindingRepository,
    remediationHistoryRepository?: RemediationHistoryRepository,
  ) {
    super(logger);
    this.idGenerator = idGenerator;
    this.clock = clock;

    const env = apiLambdaEnvironment();
    this.findingRepository =
      findingRepository ?? new FindingRepository(SCOPE_NAME, env.FINDINGS_TABLE_NAME, this.dynamoDBClient);

    this.remediationHistoryRepository =
      remediationHistoryRepository ??
      new RemediationHistoryRepository(
        SCOPE_NAME,
        env.REMEDIATION_HISTORY_TABLE_NAME,
        this.dynamoDBClient,
        env.FINDINGS_TABLE_NAME,
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

  /**
   * Reads the findings targeted by an action from DynamoDB. This is read-only:
   * Rollback reconstructs from remediation history (falling back to the
   * findings table), key-based requests use explicit (findingType, findingId)
   * keys, and everything else derives the partition key from the finding-id
   * ARN. The returned records carry the authoritative `accountId` used for
   * account-scoped authorization; callers pass them straight to
   * {@link executeActionOnFindings} so the findings are fetched only once.
   */
  async fetchFindingsForAction(request: FindingsActionRequest): Promise<FetchFindingsResult> {
    if (request.actionType === 'Rollback') {
      return this.findingsForRollback(request.findingIds, request.findingKeys);
    }
    if (request.findingKeys?.length) {
      return { findings: await this.findingRepository.findByKeys(request.findingKeys), unresolvedIds: [] };
    }
    const { findings, nonDerivableIds } = await this.findingRepository.findByFindingIds(request.findingIds);
    return { findings, unresolvedIds: nonDerivableIds };
  }

  async executeAction(request: FindingsActionRequest, principal: string): Promise<{ unresolvedIds?: FindingId[] }> {
    const { findings, unresolvedIds } = await this.fetchFindingsForAction(request);
    const skippedIds = await this.executeActionOnFindings(request, findings, principal);
    const allSkipped = [...unresolvedIds, ...skippedIds];
    return { unresolvedIds: allSkipped.length > 0 ? allSkipped : undefined };
  }

  /**
   * Executes an action against findings already fetched via
   * {@link fetchFindingsForAction}. Kept separate from the fetch so the API
   * handler can authorize against the fetched records before mutating state
   * (e.g. Rollback acquires its optimistic lock here, after authorization).
   */
  async executeActionOnFindings(
    request: FindingsActionRequest,
    findings: FindingTableItem[],
    principal: string,
  ): Promise<FindingId[]> {
    try {
      if (findings.length === 0) {
        throw new BadRequestError('No findings found for the provided IDs');
      }

      return await this.dispatchAction(request, findings, principal);
    } catch (error) {
      this.logger.error('Error executing action', {
        actionType: request.actionType,
        error: ErrorUtils.formatErrorMessage(error),
      });

      if (error instanceof BadRequestError) throw error;
      throw new BadRequestError('Failed to execute action on findings');
    }
  }

  private async dispatchAction(
    request: FindingsActionRequest,
    findings: FindingTableItem[],
    principal: string,
  ): Promise<FindingId[]> {
    switch (request.actionType) {
      case 'Remediate':
      case 'RemediateAndGenerateTicket':
        return this.executeRemediation(
          request.actionType,
          findings,
          principal,
          this.remediationHistoryRepository.createRemediationHistoryWithFindingUpdate.bind(
            this.remediationHistoryRepository,
          ),
        );
      case 'Rollback': {
        const lockedFindings = await this.acquireRollbackLocks(findings);
        return this.executeRemediation(
          'Rollback',
          lockedFindings,
          principal,
          this.remediationHistoryRepository.createRemediationHistory.bind(this.remediationHistoryRepository),
        );
      }
      case 'Suppress':
      case 'Unsuppress':
        await this.applySuppression(request.actionType, findings, principal);
        return [];
      default:
        throw new Error(`Unsupported action type: ${request.actionType}`);
    }
  }

  /**
   * Invokes the Orchestrator for each finding and persists its remediation-history record inline, as
   * soon as that finding's execution starts. History is written per finding (not in a deferred second
   * pass), so if a finding's orchestrator invocation throws, findings already processed keep their
   * history and IN_PROGRESS status, and the error propagates to the caller. A finding whose
   * invocation returns no execution id is skipped (no history row) and processing continues.
   */
  private async executeRemediation(
    actionType: keyof typeof ACTION_TYPE_TO_ASR_ACTION_NAME,
    findings: FindingTableItem[],
    principal: string,
    persistHistory: PersistHistoryFn,
  ): Promise<FindingId[]> {
    let persistedCount = 0;
    const skippedFindingIds: FindingId[] = [];

    for (const finding of findings) {
      // Resource-type guard (shared source of truth in @asr/data-models). A
      // multi-service remediation can only act on specific resource types (for
      // example Inspector.InstanceVulnerability supports EC2 instances only, not
      // Lambda functions or ECR images). Findings stored under an earlier build
      // that predated this guard could otherwise be manually remediated here and
      // fail deep in the runbook. Skip them with a clear message instead of
      // starting a doomed execution; skipped ids surface to the caller as
      // unresolvedIds.
      if (!isResourceTypeSupportedForRemediation(finding.findingType, finding.resourceType)) {
        const supportedResourceTypes = getSupportedResourceTypes(finding.findingType) ?? [];
        this.logger.warn('Skipping remediation: resource type not supported for this remediation', {
          findingId: finding.findingId,
          remediationId: finding.findingType,
          resourceType: finding.resourceType,
          supportedResourceTypes,
          actionType,
        });
        skippedFindingIds.push(finding.findingId);
        continue;
      }

      const asffFinding = extractASFFFinding(finding);
      const orchestratorInput = this.buildOrchestratorInput(
        finding.findingType,
        asffFinding,
        actionType,
        finding.rollbackBackupKey,
      );
      const executionId = await triggerRemediationForFinding({
        orchestratorInput,
        logger: this.logger,
        persistHistory: (execId) =>
          persistHistory(
            { ...finding, remediationStatus: 'IN_PROGRESS', executionId: execId, lastUpdatedBy: principal },
            execId,
          ),
      });

      // A missing executionId means the orchestrator did not start; skip history for this finding
      // rather than writing a record with a malformed `findingId#` composite key.
      if (!executionId) {
        this.logger.warn('Failed to get execution ID for finding', { findingId: finding.findingId, actionType });
        skippedFindingIds.push(finding.findingId);
        continue;
      }
      persistedCount++;
    }

    if (findings.length > 0 && persistedCount === 0) {
      this.logger.warn('No remediation history persisted — orchestrator returned no executionId for any finding', {
        findingCount: findings.length,
      });
    }
    return skippedFindingIds;
  }

  private async applySuppression(
    actionType: 'Suppress' | 'Unsuppress',
    findings: FindingTableItem[],
    principal: string,
  ): Promise<void> {
    if (actionType === 'Suppress') {
      await sendMetrics({ finding_suppressed: 1 });
    }
    const updatedFindings = this.prepareUpdatedFindings(principal, findings, { suppressed: actionType === 'Suppress' });
    await this.findingRepository.putAll(...updatedFindings);
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

  /**
   * For rollback: reconstruct from history first (history carries the findingJSON needed for
   * rollback), then fall back to the findings table on a per-finding basis for any IDs without a
   * usable history entry. The fallback is per-finding rather than all-or-nothing so findings that
   * only exist in the table aren't silently dropped just because others were reconstructed.
   *
   * Prefers caller-supplied `findingKeys` for the table leg. Deriving the partition key from a
   * finding id only works for Security Hub ARNs, so a finding whose id is not an ARN (for example
   * Macie's bare-hash FindingInfoUid) would be silently dropped by findByFindingIds. No
   * rollback-eligible control has such ids today, so this is hardening rather than a fix, and it
   * removes a correctness dependency on which controls happen to be rollback-eligible. See ADR 0010.
   */
  private async findingsForRollback(findingIds: FindingId[], findingKeys?: FindingKey[]): Promise<FetchFindingsResult> {
    const fromHistory = await this.reconstructFindingsFromHistory(findingIds);
    const reconstructedIds = new Set(fromHistory.map((finding) => finding.findingId));
    const missingIds = findingIds.filter((findingId) => !reconstructedIds.has(findingId));

    if (missingIds.length === 0) {
      return { findings: fromHistory, unresolvedIds: [] };
    }

    // One key per missing finding: the caller's explicit key when supplied, otherwise derived from
    // the id. Deduplicated because BatchGetItem rejects repeated keys and a client may legitimately
    // repeat a findingId. A finding with neither an explicit nor a derivable key cannot be looked up
    // at all, so it is reported. See ADR 0010.
    const suppliedKeys = new Map((findingKeys ?? []).map((key) => [key.findingId, key]));
    const keys: FindingKey[] = [];
    const nonDerivableIds: FindingId[] = [];

    for (const findingId of new Set(missingIds)) {
      const key = suppliedKeys.get(findingId) ?? tryFindingKeyFromFindingId(findingId);
      if (key) {
        keys.push(key);
      } else {
        nonDerivableIds.push(findingId);
      }
    }

    const fromTable = await this.findingRepository.findByKeys(keys);

    const foundInTable = new Set(fromTable.map((f) => f.findingId));
    const unresolvedIds = missingIds.filter((id) => !foundInTable.has(id));
    if (unresolvedIds.length > 0) {
      this.logger.warn(
        'Findings excluded from rollback: not found in history or the findings table. nonDerivableIds is the subset that was never queried and needs an explicit findingKeys entry',
        { unresolvedIds, nonDerivableIds },
      );
    }

    return { findings: [...fromHistory, ...fromTable], unresolvedIds };
  }

  /**
   * Reconstruct minimal FindingTableItems from history entries that have findingJSON.
   * Used for rollback when the finding is not available in the findings table.
   */
  private async reconstructFindingsFromHistory(findingIds: FindingId[]): Promise<FindingTableItem[]> {
    const CONCURRENCY_LIMIT = 25;
    const results: FindingTableItem[] = [];

    for (let i = 0; i < findingIds.length; i += CONCURRENCY_LIMIT) {
      const chunk = findingIds.slice(i, i + CONCURRENCY_LIMIT);
      const chunkResults = await Promise.all(
        chunk.map((findingId) => this.remediationHistoryRepository.findLatestSuccessWithFindingJSON(findingId)),
      );
      for (let j = 0; j < chunk.length; j++) {
        const entry = chunkResults[j];
        if (entry?.findingJSON?.length) {
          results.push(this.buildFindingTableItemFromHistoryEntry({ ...entry, findingJSON: entry.findingJSON }));
        } else {
          this.logger.warn('Could not reconstruct finding from history — no SUCCESS entry with findingJSON', {
            findingId: chunk[j],
          });
        }
      }
    }
    return results;
  }

  /**
   * Maps a history entry (which carries the preserved findingJSON) onto a minimal
   * FindingTableItem suitable for rollback execution.
   *
   * `findingDescription` and `suppressed` are intentionally hardcoded: the history record
   * does not persist these fields, and the rollback path only needs the identifying fields
   * plus findingJSON to invoke the runbook. They are not read by downstream rollback logic.
   */
  private buildFindingTableItemFromHistoryEntry(
    entry: RemediationHistoryBaseData & { findingJSON: Uint8Array },
  ): FindingTableItem {
    const severityNormalized = normalizeSeverity(entry.severity);
    return {
      findingType: entry.findingType,
      findingId: entry.findingId,
      accountId: entry.accountId,
      resourceId: entry.resourceId,
      resourceType: entry.resourceType,
      resourceTypeNormalized: entry.resourceTypeNormalized,
      severity: entry.severity,
      region: entry.region,
      remediationStatus: entry.remediationStatus,
      lastUpdatedTime: entry.lastUpdatedTime,
      findingJSON: entry.findingJSON,
      findingDescription: '',
      securityHubUpdatedAtTime: entry.lastUpdatedTime,
      'securityHubUpdatedAtTime#findingId': `${entry.lastUpdatedTime}#${entry.findingId}`,
      'severityNormalized#securityHubUpdatedAtTime#findingId': `${severityNormalized}#${entry.lastUpdatedTime}#${entry.findingId}`,
      findingIdControl: `${entry.findingId}#${entry.findingType}`,
      severityNormalized,
      suppressed: false,
      creationTime: entry.lastUpdatedTime,
      lastUpdatedBy: entry.lastUpdatedBy,
      FINDING_CONSTANT: 'finding',
      expireAt: calculateTtlTimestamp(entry.lastUpdatedTime),
      // Carry the Contain backup key (if the history entry has it) so the
      // rollback can pass it to the runbook as BackupS3KeyName.
      ...(entry.rollbackBackupKey ? { rollbackBackupKey: entry.rollbackBackupKey } : {}),
    };
  }

  /**
   * Acquires the rollback lock for each GuardDuty.IAMUser finding and returns the
   * findings that the caller may roll back.
   *
   * Validates the finding type, then per finding transitions its status to
   * ROLLBACK_IN_PROGRESS via a conditional write. That write is both the
   * eligibility gate and the double-rollback guard: it only succeeds from
   * SUCCESS / ROLLBACK_FAILED (or a stale in-progress lock). Rejects the whole
   * request if any finding is already rolling back or is not in an initiable
   * state, so a partial rollback is never started.
   */
  private async acquireRollbackLocks(findings: FindingTableItem[]): Promise<FindingTableItem[]> {
    const wrongType = findings.filter((f) => !f.findingType.endsWith(ROLLBACK_ELIGIBLE_FINDING_TYPE));
    if (wrongType.length > 0) {
      const wrongTypeIds = wrongType.map((f) => f.findingId).join(', ');
      throw new BadRequestError(
        `Rollback is only supported for ${ROLLBACK_ELIGIBLE_FINDING_TYPE} findings. Non-eligible finding IDs: ${wrongTypeIds}`,
      );
    }

    const now = this.clock.now();
    const nowIso = now.toISOString();
    const staleBefore = new Date(now.getTime() - ROLLBACK_TIMEOUT_MS).toISOString();

    const lockedFindings: FindingTableItem[] = [];
    const alreadyInProgress: FindingId[] = [];
    const ineligible: FindingId[] = [];

    for (const finding of findings) {
      // History-reconstructed findings may not have a live findings-table row
      // (the original row can TTL-expire). The lock lives on that row, so
      // re-materialise it before acquiring. createIfNotExists is a no-op when
      // the row already exists.
      await this.findingRepository.createIfNotExists(finding);

      const lockResult = await this.findingRepository.tryAcquireRollbackLock(
        finding.findingType,
        finding.findingId,
        nowIso,
        staleBefore,
      );

      if (lockResult === 'ACQUIRED') {
        lockedFindings.push({ ...finding, remediationStatus: 'ROLLBACK_IN_PROGRESS' });
      } else if (lockResult === 'IN_PROGRESS') {
        alreadyInProgress.push(finding.findingId);
      } else {
        ineligible.push(finding.findingId);
      }
    }

    if (alreadyInProgress.length > 0) {
      throw new BadRequestError(`Rollback already in progress for finding(s): ${alreadyInProgress.join(', ')}`);
    }

    if (ineligible.length > 0) {
      throw new BadRequestError(
        `Rollback requires a successful remediation (or a previously failed rollback). Non-eligible finding IDs: ${ineligible.join(', ')}`,
      );
    }

    return lockedFindings;
  }

  private buildOrchestratorInput(
    remediationId: string,
    asffFinding: ASFFFinding,
    actionType: keyof typeof ACTION_TYPE_TO_ASR_ACTION_NAME,
    rollbackBackupKey?: string,
  ): string {
    return buildOrchestratorInput(
      remediationId,
      asffFinding,
      actionType,
      this.idGenerator,
      this.clock,
      rollbackBackupKey,
    );
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
    const csv = toCsv(findings, FINDING_CSV_COLUMNS);

    this.logger.debug('CSV conversion completed', {
      totalRows: findings.length,
      totalColumns: FINDING_CSV_COLUMNS.length,
    });

    return csv;
  }

  private async uploadToS3AndGenerateUrl(csvContent: string): Promise<string> {
    const bucketName = apiLambdaEnvironment().CSV_EXPORT_BUCKET_NAME;

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
      firstDetectedTime: _firstDetectedTime,
      hasFindingNotificationsEnabled: _hasFindingNotificationsEnabled,
      hasFindingRemediationDeadlineConfigured: _hasFindingRemediationDeadlineConfigured,
      ...baseApiResponse
    } = item;

    const consoleLink = getSecurityHubConsoleUrl(baseApiResponse.findingId);

    return {
      ...baseApiResponse,
      consoleLink,
    };
  }
}
