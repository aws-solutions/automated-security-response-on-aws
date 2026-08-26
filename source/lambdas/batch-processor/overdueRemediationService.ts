// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import type { Logger } from '@aws-lambda-powertools/logger';
import type { ASFFFinding, FindingTableItem } from '@asr/data-models';
import { FindingRepository, OverdueFindingProjection } from '../common/repositories/findingRepository';
import { RemediationHistoryRepository } from '../common/repositories/remediationHistoryRepository';
import { Clock } from '../common/utils/clock';
import { IdGenerator, getIdGenerator } from '../common/utils/idGenerator';
import { extractASFFFinding, buildOrchestratorInput } from '../common/utils/findingExtraction';
import { triggerRemediationForFinding } from '../common/utils/remediationTrigger';
import { ErrorUtils } from '../common/utils/errorUtils';

/**
 * Tally of what happened during a single overdue-remediation scan. Every overdue
 * finding examined contributes to exactly one of the skip/trigger counters, except
 * `findingsRemaining`, which reports eligible findings left unprocessed because the
 * per-run cap was reached.
 */
export interface RemediationResult {
  findingsEvaluated: number;
  remediationsTriggered: number;
  // Skipped at the GSI projection (pre-fetch) because suppressed === true (ASR-level suppression).
  findingsSkippedSuppressedASR: number;
  // Skipped after decompression because Workflow.Status === 'SUPPRESSED' (Security Hub-level suppression).
  findingsSkippedSuppressedSH: number;
  // Skipped at the GSI projection (pre-fetch) because remediationStatus !== 'NOT_STARTED'.
  findingsSkippedIneligible: number;
  // Skipped because the finding payload was corrupt, the orchestrator invocation failed, or the
  // full item could not be retrieved from BatchGetItem (the finding retains its deadline and retries).
  findingsSkippedError: number;
  // Lower bound on eligible findings left untriggered because the per-run cap was reached. Paging
  // stops once the cap is met, so additional eligible findings may remain in unscanned GSI pages.
  findingsRemaining: number;
}

// Overdue findings are remediated through the same execution path as the manual remediation API.
const OVERDUE_REMEDIATION_ACTION_TYPE = 'Remediate' as const;

// Principal recorded as `lastUpdatedBy` on deadline-enforced remediations. Set explicitly so the
// audit trail distinguishes enforcement-triggered remediations from Pre-Processor auto-remediations
// (which use 'Automated'); otherwise the finding's inherited `lastUpdatedBy` would mask the source.
const DEADLINE_ENFORCEMENT_PRINCIPAL = 'DeadlineEnforcement';

/** A finding that has passed every eligibility check, paired with its decompressed ASFF payload. */
interface RemediableFinding {
  finding: FindingTableItem;
  asffFinding: ASFFFinding;
}

/**
 * Outcome of evaluating a single fetched finding for remediation:
 * - `remediable`: passed every check; carries the decompressed ASFF payload ready to trigger.
 * - `suppressedSH`: Security Hub has the finding suppressed, so it must not be remediated.
 * - `error`: the payload could not be decompressed; carries the cause for logging.
 */
type FindingEligibility =
  | { status: 'remediable'; asffFinding: ASFFFinding }
  | { status: 'suppressedSH' }
  | { status: 'error'; error: unknown };

/**
 * Queries the sparse `remediationDueBy-GSI` for findings whose deadline has elapsed and triggers
 * remediation for those still eligible. All filter evaluation happens at write time, so this scan
 * is purely: query GSI → in-memory eligibility → batch-get full items → filter out decompression
 * failures and SH-suppressed findings → trigger → clear stamp.
 */
export class OverdueRemediationService {
  constructor(
    private readonly findingRepository: FindingRepository,
    private readonly remediationHistoryRepository: RemediationHistoryRepository,
    private readonly logger: Logger,
    private readonly clock: Clock,
    private readonly perRunCap: number,
    private readonly idGenerator: IdGenerator = getIdGenerator(),
  ) {}

  async remediateOverdueFindings(): Promise<RemediationResult> {
    const result: RemediationResult = {
      findingsEvaluated: 0,
      remediationsTriggered: 0,
      findingsSkippedSuppressedASR: 0,
      findingsSkippedSuppressedSH: 0,
      findingsSkippedIneligible: 0,
      findingsSkippedError: 0,
      findingsRemaining: 0,
    };

    let eligibleFindings: OverdueFindingProjection[];
    try {
      eligibleFindings = await this.queryOverdueFindings(result);
    } catch (error) {
      // A query failure is contained to this invocation; the next scheduled scan retries automatically.
      this.logger.error('Failed to query overdue findings; skipping enforcement for this invocation', {
        error: ErrorUtils.formatErrorMessage(error),
      });
      return result;
    }

    const fullItems = await this.fetchFullItems(eligibleFindings, result);
    const remediableFindings = await this.filterRemediableFindings(fullItems, result);

    for (const remediableFinding of remediableFindings) {
      const outcome = await this.triggerRemediation(remediableFinding);
      switch (outcome) {
        case 'triggered':
          result.remediationsTriggered++;
          break;
        case 'error':
          result.findingsSkippedError++;
          break;
      }
    }

    this.logger.info('Overdue remediation scan complete', { ...result });
    return result;
  }

  /**
   * Pages through the `remediationDueBy-GSI` (ascending by `remediationDueBy`, so oldest-overdue
   * first) accumulating findings that pass the pre-fetch eligibility checks until the per-run cap
   * is reached or the GSI is exhausted. Updates the skip counters on `result` as it goes and sets
   * `findingsRemaining` to a lower bound on the eligible findings left unprocessed: paging stops
   * once the cap is met, so only the overflow from the pages already fetched is counted.
   */
  private async queryOverdueFindings(result: RemediationResult): Promise<OverdueFindingProjection[]> {
    const now = this.clock.now().toISOString();
    const eligible: OverdueFindingProjection[] = [];
    let exclusiveStartKey: Record<string, unknown> | undefined;

    do {
      const page = await this.findingRepository.queryFindingsByDueBy(now, { exclusiveStartKey });

      for (const item of page.items) {
        result.findingsEvaluated++;

        if (item.remediationStatus !== 'NOT_STARTED') {
          result.findingsSkippedIneligible++;
          continue;
        }
        if (item.suppressed === true) {
          result.findingsSkippedSuppressedASR++;
          continue;
        }

        eligible.push(item);
      }

      exclusiveStartKey = page.lastEvaluatedKey;
    } while (exclusiveStartKey && eligible.length < this.perRunCap);

    const toProcess = eligible.slice(0, this.perRunCap);
    result.findingsRemaining = eligible.length - toProcess.length;

    if (result.findingsRemaining > 0) {
      this.logger.info('Per-run cap reached; deferring remaining overdue findings to the next invocation', {
        perRunCap: this.perRunCap,
        findingsRemaining: result.findingsRemaining,
      });
    }

    return toProcess;
  }

  /**
   * Retrieves full finding items (including `findingJSON`) for the eligible findings via
   * BatchGetItem, keyed by the `findingType`/`findingId` projected on each GSI result. BatchGetItem
   * does not guarantee response order, so the results are re-ordered to match the GSI sequence
   * (oldest-overdue-first) before triggering. Returns best-effort results: any items not retrieved
   * retain their `remediationDueBy` and are picked up on the next invocation. Each unretrieved
   * finding is tallied into `findingsSkippedError` so the per-finding accounting stays balanced.
   */
  private async fetchFullItems(
    eligibleFindings: OverdueFindingProjection[],
    result: RemediationResult,
  ): Promise<FindingTableItem[]> {
    if (eligibleFindings.length === 0) {
      return [];
    }

    const keys = eligibleFindings.map((finding) => ({
      findingType: finding.findingType,
      findingId: finding.findingId,
    }));

    const items = await this.findingRepository.findByKeys(keys);

    const itemsByKey = new Map(items.map((item) => [this.compositeKey(item.findingType, item.findingId), item]));
    const orderedItems = eligibleFindings
      .map((finding) => itemsByKey.get(this.compositeKey(finding.findingType, finding.findingId)))
      .filter((item): item is FindingTableItem => item !== undefined);

    const unretrieved = eligibleFindings.length - orderedItems.length;
    if (unretrieved > 0) {
      result.findingsSkippedError += unretrieved;
      this.logger.warn('BatchGetItem returned fewer findings than requested; missing findings will be retried', {
        requested: eligibleFindings.length,
        retrieved: orderedItems.length,
      });
    }

    return orderedItems;
  }

  // Joins the partition and sort key with a '#' separator. Finding IDs are sanitized to strip '#'
  // (see toDbFindingId in findingUtils), so the separator cannot collide with either value.
  private compositeKey(findingType: string, findingId: string): string {
    return `${findingType}#${findingId}`;
  }

  /**
   * Evaluates a single fetched finding for remediation without throwing or mutating state. Reports
   * `error` when the payload cannot be decompressed, `suppressedSH` when Security Hub has the finding
   * suppressed, and `remediable` (with the decompressed ASFF payload) otherwise. The caller is
   * responsible for the resulting side effects (counters, stamp-clearing, logging).
   */
  private checkFindingEligibility(finding: FindingTableItem): FindingEligibility {
    try {
      const asffFinding = extractASFFFinding(finding);

      if (asffFinding.Workflow?.Status === 'SUPPRESSED') {
        return { status: 'suppressedSH' };
      }

      return { status: 'remediable', asffFinding };
    } catch (error) {
      return { status: 'error', error };
    }
  }

  /**
   * Vets each fetched finding before it reaches {@link triggerRemediation}, so that method only ever
   * handles findings that should actually be remediated. Applies {@link checkFindingEligibility} and
   * acts on its outcome: findings that fail to decompress are tallied as errors (retaining their
   * deadline so they retry); SH-suppressed findings have their enforcement stamp cleared so they
   * leave the sparse GSI (a failed stamp-clearing write is itself tallied as an error). Returns the
   * survivors paired with their decompressed ASFF payload, preserving the oldest-overdue-first input
   * order.
   */
  private async filterRemediableFindings(
    fullItems: FindingTableItem[],
    result: RemediationResult,
  ): Promise<RemediableFinding[]> {
    const remediableFindings: RemediableFinding[] = [];

    for (const finding of fullItems) {
      const eligibility = this.checkFindingEligibility(finding);

      if (eligibility.status === 'error') {
        result.findingsSkippedError++;
        this.logger.error('Failed to decompress overdue finding; it retains its deadline', {
          findingId: finding.findingId,
          error: ErrorUtils.formatErrorMessage(eligibility.error),
        });
        continue;
      }

      if (eligibility.status === 'suppressedSH') {
        try {
          // Clear the enforcement stamp so an SH-suppressed finding drops out of the sparse GSI.
          // Otherwise it stays eligible at the projection and is re-fetched and re-decompressed on
          // every future scan, only to be skipped here again.
          await this.findingRepository.clearRemediationDueBy(finding.findingId, finding.findingType);
        } catch (error) {
          result.findingsSkippedError++;
          this.logger.error('Failed to clear enforcement stamp for SH-suppressed finding; it retains its deadline', {
            findingId: finding.findingId,
            error: ErrorUtils.formatErrorMessage(error),
          });
          continue;
        }
        result.findingsSkippedSuppressedSH++;
        this.logger.info('Skipping overdue finding suppressed in Security Hub; cleared its enforcement stamp', {
          findingId: finding.findingId,
        });
        continue;
      }

      remediableFindings.push({ finding, asffFinding: eligibility.asffFinding });
    }

    return remediableFindings;
  }

  /**
   * Invokes the orchestrator for an already-vetted finding. On a successful trigger the
   * status-change transaction atomically writes IN_PROGRESS status, a history record, and clears the
   * enforcement stamp. Any failure (orchestrator error, missing execution id, or status-write
   * failure) leaves `remediationDueBy` intact so the finding is retried on the next scan.
   */
  private async triggerRemediation({ finding, asffFinding }: RemediableFinding): Promise<'triggered' | 'error'> {
    try {
      const orchestratorInput = buildOrchestratorInput(
        finding.findingType,
        asffFinding,
        OVERDUE_REMEDIATION_ACTION_TYPE,
        this.idGenerator,
        this.clock,
      );
      const executionId = await triggerRemediationForFinding({
        orchestratorInput,
        logger: this.logger,
        persistHistory: (execId) =>
          this.remediationHistoryRepository.createRemediationHistoryWithFindingUpdate(
            {
              ...finding,
              lastUpdatedBy: DEADLINE_ENFORCEMENT_PRINCIPAL,
              remediationStatus: 'IN_PROGRESS',
              executionId: execId,
            },
            execId,
          ),
      });

      if (!executionId) {
        this.logger.warn('Orchestrator returned no execution id; leaving finding for the next scan', {
          findingId: finding.findingId,
        });
        return 'error';
      }

      this.logger.info('Triggered remediation for overdue finding', {
        findingId: finding.findingId,
        executionId,
      });
      return 'triggered';
    } catch (error) {
      this.logger.error('Failed to trigger remediation for overdue finding; it retains its deadline', {
        findingId: finding.findingId,
        error: ErrorUtils.formatErrorMessage(error),
      });
      return 'error';
    }
  }
}
