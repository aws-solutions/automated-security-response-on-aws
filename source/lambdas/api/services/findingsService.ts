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
  ROLLBACK_ELIGIBLE_FINDING_TYPES,
  ROLLBACK_TIMEOUT_MS,
  getRemediationConfigBucketName,
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
import { ControlsRepository } from '../../common/repositories/controlsRepository';
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

/** The rollback locks one request holds: the lockable findings plus what each lock replaced. */
interface RollbackLocks {
  findings: FindingTableItem[];
  acquired: { finding: FindingTableItem; previousStatus: string | undefined }[];
  /** The timestamp written into every lock; releasing is conditioned on it. */
  lockedAt: string;
}

/**
 * Human-readable reason a finding could not take the rollback lock, keyed on the
 * remediationStatus observed when the conditional write was refused.
 */
function describeIneligibleStatus(remediationStatus: string | undefined): string {
  switch (remediationStatus) {
    case 'ROLLBACK_SUCCESS':
      return 'already rolled back';
    case 'FAILED':
      return 'remediation did not succeed';
    case 'IN_PROGRESS':
      return 'remediation still in progress';
    case undefined:
      return 'no remediation recorded';
    default:
      return `status ${remediationStatus}`;
  }
}

export class FindingsService extends BaseSearchService {
  private readonly findingRepository: FindingRepository;
  private readonly remediationHistoryRepository: RemediationHistoryRepository;
  private readonly controlsRepository: ControlsRepository;
  private readonly s3Client: ASRS3Client;
  private readonly idGenerator: IdGenerator;
  private readonly clock: Clock;

  constructor(
    logger: Logger,
    idGenerator: IdGenerator = getIdGenerator(),
    clock: Clock = getClock(),
    findingRepository?: FindingRepository,
    remediationHistoryRepository?: RemediationHistoryRepository,
    controlsRepository?: ControlsRepository,
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

    this.controlsRepository =
      controlsRepository ?? new ControlsRepository(env.REMEDIATION_CONFIG_TABLE_NAME, this.dynamoDBClient);

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
        // All three gates run before the lock so a finding that cannot be rolled back is never left
        // in ROLLBACK_IN_PROGRESS.
        const { supported, skippedIds: unsupportedIds, unsupported } = this.partitionByRollbackSupport(findings);
        if (supported.length === 0) {
          // Name what was refused and why: without the ids and controls a caller acting on a
          // batch cannot tell which finding to drop from the request.
          const detail = unsupported.map(({ findingId, controlId }) => `${findingId} (${controlId})`).join(', ');
          throw new BadRequestError(
            `Rollback is only supported for eligible controls. Not eligible for rollback: ${detail}`,
          );
        }
        const { eligible: rollbackEligibleFindings, skippedIds: rollbackSkippedIds } =
          await this.filterByRollbackEnabled(supported);
        if (rollbackEligibleFindings.length === 0) {
          throw new BadRequestError(
            'Rollback is disabled for all requested controls. Check the per-control rollbackEnabled setting.',
          );
        }
        const { dispatchable, skippedIds: noSnapshotIds } =
          this.partitionByRollbackDispatchable(rollbackEligibleFindings);
        if (dispatchable.length === 0) {
          throw new BadRequestError(
            'No requested finding has a recorded remediation execution, so its pre-remediation snapshot cannot be located.',
          );
        }
        const locks = await this.acquireRollbackLocks(dispatchable);
        // Only a lock whose finding was never sent to the Orchestrator is safe to hand back:
        // StartExecution carries no idempotent name, so a call that threw may still have been
        // accepted, and releasing that lock would let a second request start a duplicate
        // rollback. Findings never attempted — skipped ones, and the rest of the batch after
        // one invocation threw — are released; an attempted one whose outcome is unknown stays
        // locked and relies on the stale-lock timeout, as before. The one attempted case we can
        // prove did not start — the Orchestrator returned no executionId — is walked back out of
        // `attempted` so its lock is released like a never-attempted finding, rather than sitting
        // ROLLBACK_IN_PROGRESS until stale while the caller is told the finding was not processed.
        const attempted = new Set<FindingId>();
        const persistHistory: PersistHistoryFn = (item, executionId) =>
          this.remediationHistoryRepository.createRemediationHistory(item, executionId);
        const onDispatchAttempt = (item: FindingTableItem) => attempted.add(item.findingId);
        const onDispatchUnstarted = (item: FindingTableItem) => attempted.delete(item.findingId);
        try {
          const result = await this.executeRemediation(
            'Rollback',
            locks.findings,
            principal,
            persistHistory,
            onDispatchAttempt,
            onDispatchUnstarted,
          );
          await this.releaseUnusedRollbackLocks(locks, attempted);
          return [...unsupportedIds, ...rollbackSkippedIds, ...noSnapshotIds, ...result];
        } catch (error) {
          await this.releaseUnusedRollbackLocks(locks, attempted);
          throw error;
        }
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
    onDispatchAttempt?: (finding: FindingTableItem) => void,
    onDispatchUnstarted?: (finding: FindingTableItem) => void,
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

      // Build rollback params for non-GuardDuty controls that have an SSM execution ID.
      const isGuardDutyRollback = actionType === 'Rollback' && finding.findingType.endsWith('GuardDuty.IAMUser');
      const snapshotRollbackParams =
        actionType === 'Rollback' && !isGuardDutyRollback && finding.ssmExecutionId
          ? {
              executionId: finding.ssmExecutionId,
              remediationConfigBucket: getRemediationConfigBucketName(finding.region, finding.accountId),
              snapshotVersionId: finding.snapshotVersionId,
            }
          : undefined;

      const orchestratorInput = this.buildOrchestratorInput(
        finding.findingType,
        asffFinding,
        actionType,
        finding.rollbackBackupKey,
        snapshotRollbackParams,
      );
      // Marked attempted before the invocation, not after: StartExecution carries no idempotent
      // name, so a call that *throws* may still have been accepted by the Orchestrator. A caller
      // holding locks must keep such a finding locked. The clean no-executionId return below is
      // the one case we can prove did not start, and it is walked back via onDispatchUnstarted.
      onDispatchAttempt?.(finding);
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
      // rather than writing a record with a malformed `findingId#` composite key. Unlike a thrown
      // call, this return proves nothing started, so the finding is walked back out of `attempted`
      // (onDispatchUnstarted) — otherwise its rollback lock would sit in ROLLBACK_IN_PROGRESS until
      // stale while the caller is told the finding was not processed, contradicting an immediate retry.
      if (!executionId) {
        this.logger.warn('Failed to get execution ID for finding', { findingId: finding.findingId, actionType });
        onDispatchUnstarted?.(finding);
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
   * Filters findings to only those whose control has rollbackEnabled !== false, read in one batched
   * lookup. A control absent from the config table has no valid rollback target and is skipped, which
   * is deliberately stricter than the Orchestrator gate, which fails open for unknown controls.
   */
  private async filterByRollbackEnabled(
    findings: FindingTableItem[],
  ): Promise<{ eligible: FindingTableItem[]; skippedIds: FindingId[] }> {
    const eligible: FindingTableItem[] = [];
    const skippedIds: FindingId[] = [];
    const rollbackState = await this.controlsRepository.findRollbackStateByControlIds(
      findings.map((finding) => this.configTableKeyFor(finding)),
    );
    for (const finding of findings) {
      const controlId = this.configTableKeyFor(finding);
      if (rollbackState.get(controlId) ?? false) {
        eligible.push(finding);
      } else {
        skippedIds.push(finding.findingId);
        this.logger.info('Rollback disabled for control — skipping', {
          controlId,
          findingId: finding.findingId,
        });
      }
    }
    return { eligible, skippedIds };
  }

  /**
   * Splits findings by whether a rollback can be dispatched. A snapshot-based rollback needs the
   * original SSM execution id to locate its snapshot; without it the orchestrator would run the
   * remediation forward instead. GuardDuty uses the existing restore path and needs no execution id.
   */
  private partitionByRollbackDispatchable(findings: FindingTableItem[]): {
    dispatchable: FindingTableItem[];
    skippedIds: FindingId[];
  } {
    const dispatchable: FindingTableItem[] = [];
    const skippedIds: FindingId[] = [];
    for (const finding of findings) {
      if (!finding.findingType.endsWith('GuardDuty.IAMUser') && !finding.ssmExecutionId) {
        skippedIds.push(finding.findingId);
        this.logger.warn('Skipping rollback: no SSM execution id, snapshot cannot be located', {
          findingType: finding.findingType,
          findingId: finding.findingId,
        });
        continue;
      }
      dispatchable.push(finding);
    }
    return { dispatchable, skippedIds };
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
    entry: RemediationHistoryBaseData & { findingJSON: Uint8Array; remediationConfigTableKey?: string },
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
      // Carry the SSM execution ID so the rollback can locate the
      // pre-remediation snapshot in S3.
      ...(entry.ssmExecutionId ? { ssmExecutionId: entry.ssmExecutionId } : {}),
      // Carry the S3 version ID for tamper-proof snapshot reads during rollback.
      ...(entry.snapshotVersionId ? { snapshotVersionId: entry.snapshotVersionId } : {}),
      // Carry the config table key so the rollback gates don't derive one from findingType.
      ...(entry.remediationConfigTableKey ? { remediationConfigTableKey: entry.remediationConfigTableKey } : {}),
    };
  }

  /** Config table key: the stamped value, else the ASFF SecurityControlId, else the finding type. */
  private configTableKeyFor(finding: FindingTableItem): string {
    if (finding.remediationConfigTableKey) {
      return finding.remediationConfigTableKey;
    }
    try {
      const securityControlId = extractASFFFinding(finding).Compliance?.SecurityControlId;
      if (securityControlId) {
        return securityControlId;
      }
    } catch {
      // Unreadable ASFF, fall through.
    }
    const lastSlash = finding.findingType.lastIndexOf('/');
    return lastSlash === -1 ? finding.findingType : finding.findingType.slice(lastSlash + 1);
  }

  /** Skips controls with no rollback capability, so they aren't blamed on the per-control toggle. */
  private partitionByRollbackSupport(findings: FindingTableItem[]): {
    supported: FindingTableItem[];
    skippedIds: FindingId[];
    /** The skipped findings paired with the control that lacks rollback, for the refusal message. */
    unsupported: { findingId: FindingId; controlId: string }[];
  } {
    const supported: FindingTableItem[] = [];
    const skippedIds: FindingId[] = [];
    const unsupported: { findingId: FindingId; controlId: string }[] = [];
    for (const finding of findings) {
      const controlId = this.configTableKeyFor(finding);
      if (!ROLLBACK_ELIGIBLE_FINDING_TYPES.has(controlId)) {
        skippedIds.push(finding.findingId);
        unsupported.push({ findingId: finding.findingId, controlId });
        this.logger.info('Skipping rollback: control does not support rollback', {
          controlId,
          findingId: finding.findingId,
        });
        continue;
      }
      supported.push(finding);
    }
    return { supported, skippedIds, unsupported };
  }

  /**
   * Acquires the rollback lock for each eligible finding and returns the
   * findings that the caller may roll back.
   *
   * Per finding, transitions its status to ROLLBACK_IN_PROGRESS via a
   * conditional write. That write is both the eligibility gate and the
   * double-rollback guard: it only succeeds from SUCCESS / ROLLBACK_FAILED (or a
   * stale in-progress lock). Rejects the whole request if any finding is already
   * rolling back or is not in an initiable state, so a partial rollback is never
   * started — and on rejection the locks already taken are released back to the
   * status they replaced, so a rejected batch does not leave findings parked in
   * ROLLBACK_IN_PROGRESS with no rollback running until the lock goes stale.
   */
  private async acquireRollbackLocks(findings: FindingTableItem[]): Promise<RollbackLocks> {
    const now = this.clock.now();
    const nowIso = now.toISOString();
    const staleBefore = new Date(now.getTime() - ROLLBACK_TIMEOUT_MS).toISOString();

    const lockedFindings: FindingTableItem[] = [];
    const acquired: { finding: FindingTableItem; previousStatus: string | undefined }[] = [];
    const alreadyInProgress: FindingId[] = [];
    const ineligible: { findingId: FindingId; remediationStatus: string | undefined }[] = [];

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

      switch (lockResult.outcome) {
        case 'ACQUIRED':
          lockedFindings.push({ ...finding, remediationStatus: 'ROLLBACK_IN_PROGRESS' });
          acquired.push({ finding, previousStatus: lockResult.previousStatus });
          break;
        case 'IN_PROGRESS':
          alreadyInProgress.push(finding.findingId);
          break;
        case 'INELIGIBLE':
          ineligible.push({ findingId: finding.findingId, remediationStatus: lockResult.remediationStatus });
          break;
      }
    }

    const locks: RollbackLocks = { findings: lockedFindings, acquired, lockedAt: nowIso };
    if (alreadyInProgress.length > 0 || ineligible.length > 0) {
      await this.releaseUnusedRollbackLocks(locks, new Set());
    }

    if (alreadyInProgress.length > 0) {
      throw new BadRequestError(`Rollback already in progress for finding(s): ${alreadyInProgress.join(', ')}`);
    }

    if (ineligible.length > 0) {
      // Say what was actually observed per finding. The generic "requires a successful
      // remediation" was misleading for the common case — a finding that had already been rolled
      // back *did* have a successful remediation.
      const detail = ineligible
        .map(({ findingId, remediationStatus }) => `${findingId} (${describeIneligibleStatus(remediationStatus)})`)
        .join(', ');
      throw new BadRequestError(
        `Rollback is only possible after a successful remediation or a previously failed rollback. Not eligible: ${detail}`,
      );
    }

    return locks;
  }

  /**
   * Hands back every acquired lock whose finding is not in `attempted`. Best-effort: a lock that
   * cannot be released is logged, not thrown — the caller is already on a rejection or failure
   * path, and an unreleased lock still expires as stale.
   */
  private async releaseUnusedRollbackLocks(locks: RollbackLocks, attempted: ReadonlySet<FindingId>): Promise<void> {
    const nowIso = this.clock.now().toISOString();
    for (const { finding, previousStatus } of locks.acquired) {
      if (attempted.has(finding.findingId)) continue;
      try {
        const released = await this.findingRepository.releaseRollbackLock(
          finding.findingType,
          finding.findingId,
          locks.lockedAt,
          previousStatus,
          nowIso,
        );
        if (!released) {
          this.logger.warn('Rollback lock changed hands before it could be released', { findingId: finding.findingId });
        }
      } catch (error) {
        this.logger.error('Failed to release an unused rollback lock; it will expire as stale', {
          findingId: finding.findingId,
          error: error instanceof Error ? error.message : String(error),
        });
      }
    }
  }

  private buildOrchestratorInput(
    remediationId: string,
    asffFinding: ASFFFinding,
    actionType: keyof typeof ACTION_TYPE_TO_ASR_ACTION_NAME,
    rollbackBackupKey?: string,
    snapshotRollbackParams?: { executionId: string; remediationConfigBucket: string; snapshotVersionId?: string },
  ): string {
    return buildOrchestratorInput(
      remediationId,
      asffFinding,
      actionType,
      this.idGenerator,
      this.clock,
      rollbackBackupKey,
      snapshotRollbackParams,
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

      this.logger.info('Findings export completed', {
        username: authenticatedUser.username,
        totalExported: exportResult.findings.length,
        status: exportResult.status,
        timestamp: this.clock.now().toISOString(),
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
