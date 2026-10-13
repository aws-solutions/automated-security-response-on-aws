// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import {
  DescribeSecurityHubV2Command,
  GetFindingsCommand,
  GetFindingsCommandInput,
  GetFindingsV2Command,
  InvalidAccessException,
  ResourceNotFoundException,
  SecurityHubClient,
} from '@aws-sdk/client-securityhub';
import { createOptimizedGetFindingsInputByControlId } from '../constants/securityStandardFilters';
import { ASFFFinding } from '@asr/data-models';
import { z } from 'zod';
import { getLogger } from './logger';

const RATE_LIMIT_DELAY_MS = 120; // 120ms between API calls = ~8 calls/sec
const MAX_RESULTS_PER_REQUEST = 100;
const MAX_FINDING_IDS_PER_LOOKUP = 10;
const OCSF_SUPPRESSED_STATUS_ID = 3;

/** A finding whose live Security Hub status should be read, and which Security Hub views to read it from. */
export interface SuppressionLookupTarget {
  findingId: string;
  /** Read the Security Hub CSPM (ASFF) Workflow.Status. */
  shouldCheckCspm: boolean;
  /** Read the Security Hub V2 (OCSF) status_id. */
  shouldCheckSecurityHubV2: boolean;
}

export interface SuppressionLookupResult {
  suppressedFindingIds: Set<string>;
  /** Findings that no requested view returned, so their live status is unknown. */
  unresolvedFindingIds: Set<string>;
}

/** Optional controls that make a {@link SecurityHubUtils.processAllFindings} run resumable and time-bounded. */
export interface ProcessAllFindingsOptions {
  /** Security Hub pagination token to resume from (omit to start at the first page). */
  startToken?: string;
  /**
   * Checked BEFORE each page request. When it returns true the run stops cleanly and returns
   * `wasStopped: true` with the token needed to resume; the in-flight page is never abandoned mid-write.
   */
  shouldStop?: () => boolean;
  /**
   * Invoked after each page is processed, with the token for the NEXT page (undefined when the
   * source is exhausted) and the number of findings in the page just processed. Used to checkpoint
   * a cursor. Awaited, so a persistence failure surfaces to the caller.
   */
  onPageProcessed?: (nextToken: string | undefined, pageCount: number) => Promise<void>;
}

export interface ProcessAllFindingsResult {
  totalProcessed: number;
  apiCallCount: number;
  /** Token to resume from. Defined only when the run was cut short by `shouldStop`. */
  nextToken?: string;
  /** True when the run stopped on the budget predicate rather than exhausting the source. */
  wasStopped: boolean;
}

export class SecurityHubUtils {
  private readonly client: SecurityHubClient;
  private readonly logger = getLogger('SecurityHubUtils');
  private securityHubV2EnabledLookup: Promise<boolean> | undefined;

  constructor(client: SecurityHubClient) {
    this.client = client;
  }

  /**
   * Process all findings from Security Hub with automatic pagination and rate limiting.
   *
   * With no options this walks every page to exhaustion (the original behaviour). With
   * {@link ProcessAllFindingsOptions} it can resume from a token, stop cleanly when a time budget is
   * nearly spent, and checkpoint progress after each page — the primitives the resumable sync engine
   * needs.
   *
   * @param processBatch - Callback function to process each batch of findings
   * @param filters The filters to apply to the GetFindings request
   * @param options Optional resume/stop/checkpoint controls
   * @returns Processing results: total processed, API call count, resume token, and whether it stopped early
   */
  async processAllFindings(
    processBatch: (findings: ASFFFinding[]) => Promise<void>,
    filters: NonNullable<GetFindingsCommandInput['Filters']>,
    options?: ProcessAllFindingsOptions,
  ): Promise<ProcessAllFindingsResult> {
    const { startToken, shouldStop, onPageProcessed } = options ?? {};
    let totalProcessed = 0;
    let apiCallCount = 0;
    let nextToken: string | undefined = startToken;
    let wasStopped = false;

    try {
      do {
        // Check the budget before spending an API call so we never start a page we can't afford.
        if (shouldStop?.()) {
          wasStopped = true;
          break;
        }

        apiCallCount++;

        const input = await createOptimizedGetFindingsInputByControlId(filters, nextToken, MAX_RESULTS_PER_REQUEST);
        const response = await this.client.send(new GetFindingsCommand(input));
        const findings = (response.Findings || []) as ASFFFinding[];

        if (findings.length > 0) {
          await processBatch(findings);
          totalProcessed += findings.length;
        }

        nextToken = response.NextToken;

        if (onPageProcessed) {
          await onPageProcessed(nextToken, findings.length);
        }

        if (nextToken) {
          await new Promise((resolve) => setTimeout(resolve, RATE_LIMIT_DELAY_MS));
        }
      } while (nextToken);

      this.logger.info(
        `Processed ${totalProcessed} findings with ${apiCallCount} API calls${wasStopped ? ' (stopped on budget)' : ''}`,
      );
      // On a clean exhaustion nextToken is undefined; only surface it as a resume point when we stopped early.
      return { totalProcessed, apiCallCount, nextToken: wasStopped ? nextToken : undefined, wasStopped };
    } catch (error) {
      this.logger.error('Failed to process findings from Security Hub', {
        error: error instanceof Error ? error.message : 'Unknown error',
        totalProcessed,
        apiCallCount,
      });
      throw error;
    }
  }

  /**
   * Reports which findings are suppressed in Security Hub CSPM or Security Hub V2, read live because an event
   * can carry a stale status. SDK errors propagate so callers can tell transient failures from permission problems.
   */
  async findSuppressedFindings(targets: SuppressionLookupTarget[]): Promise<SuppressionLookupResult> {
    const cspmIds = targets.filter((target) => target.shouldCheckCspm).map((target) => target.findingId);
    const securityHubV2Ids = targets
      .filter((target) => target.shouldCheckSecurityHubV2)
      .map((target) => target.findingId);

    const [cspmStatuses, securityHubV2Statuses] = await Promise.all([
      this.readCspmSuppression(cspmIds),
      this.readSecurityHubV2Suppression(securityHubV2Ids),
    ]);

    const suppressedFindingIds = new Set<string>();
    const unresolvedFindingIds = new Set<string>();
    for (const target of targets) {
      const isCspmSuppressed = target.shouldCheckCspm ? cspmStatuses.get(target.findingId) : undefined;
      const isSecurityHubV2Suppressed = target.shouldCheckSecurityHubV2
        ? securityHubV2Statuses.get(target.findingId)
        : undefined;
      if (isCspmSuppressed === true || isSecurityHubV2Suppressed === true) {
        suppressedFindingIds.add(target.findingId);
      } else if (
        (target.shouldCheckCspm || target.shouldCheckSecurityHubV2) &&
        isCspmSuppressed === undefined &&
        isSecurityHubV2Suppressed === undefined
      ) {
        unresolvedFindingIds.add(target.findingId);
      }
    }
    return { suppressedFindingIds, unresolvedFindingIds };
  }

  /** Whether Security Hub V2 (OCSF) is enabled in this account and Region. Only a definite answer is cached. */
  async isSecurityHubV2Enabled(): Promise<boolean> {
    this.securityHubV2EnabledLookup ??= this.client.send(new DescribeSecurityHubV2Command({})).then(
      (response) => Boolean(response.HubV2Arn),
      (error: unknown) => {
        // ResourceNotFoundException: Security Hub V2 is not subscribed in this account.
        // AccessDeniedException: the Lambda role lacks securityhub:DescribeSecurityHubV2.
        //   This happens in aws-us-gov and aws-cn where Security Hub V2 is unavailable
        //   and the IAM action is intentionally not granted (see pre-processor-construct
        //   and batch-processor-construct). Treating it as "V2 unavailable" keeps the
        //   caller on the Security Hub CSPM path rather than failing the whole lookup.
        if (
          error instanceof ResourceNotFoundException ||
          (error instanceof Error && error.name === 'AccessDeniedException')
        ) {
          return false;
        }
        this.securityHubV2EnabledLookup = undefined;
        throw error;
      },
    );
    return this.securityHubV2EnabledLookup;
  }

  /**
   * Maps each returned finding id to whether its CSPM Workflow.Status is SUPPRESSED. Returns an empty map
   * when Security Hub CSPM is not enabled, since that view then holds no status to honor.
   */
  private async readCspmSuppression(findingIds: string[]): Promise<Map<string, boolean>> {
    try {
      return await this.readEnabledCspmSuppression(findingIds);
    } catch (error) {
      if (!(error instanceof InvalidAccessException)) throw error;
      this.logger.info('Security Hub CSPM is not enabled; reading suppression from Security Hub V2 only', {
        error: error.message,
      });
      return new Map();
    }
  }

  private async readEnabledCspmSuppression(findingIds: string[]): Promise<Map<string, boolean>> {
    const statuses = new Map<string, boolean>();
    for (const chunk of chunkFindingIds(findingIds)) {
      let nextToken: string | undefined;
      do {
        const response = await this.client.send(
          new GetFindingsCommand({
            Filters: { Id: chunk.map((findingId) => ({ Value: findingId, Comparison: 'EQUALS' })) },
            MaxResults: MAX_RESULTS_PER_REQUEST,
            NextToken: nextToken,
          }),
        );
        for (const finding of response.Findings ?? []) {
          if (finding.Id) statuses.set(finding.Id, finding.Workflow?.Status === 'SUPPRESSED');
        }
        nextToken = response.NextToken;
      } while (nextToken);
    }
    return statuses;
  }

  /** Maps each returned finding uid to whether its Security Hub V2 status_id is Suppressed. */
  private async readSecurityHubV2Suppression(findingIds: string[]): Promise<Map<string, boolean>> {
    const statuses = new Map<string, boolean>();
    for (const chunk of chunkFindingIds(findingIds)) {
      let nextToken: string | undefined;
      do {
        const response = await this.client.send(
          new GetFindingsV2Command({
            Filters: {
              CompositeFilters: [
                {
                  Operator: 'OR',
                  StringFilters: chunk.map((findingId) => ({
                    FieldName: 'finding_info.uid',
                    Filter: { Value: findingId, Comparison: 'EQUALS' },
                  })),
                },
              ],
            },
            MaxResults: MAX_RESULTS_PER_REQUEST,
            NextToken: nextToken,
          }),
        );
        for (const finding of response.Findings ?? []) {
          const status = readOcsfStatus(finding);
          if (status) statuses.set(status.findingId, status.statusId === OCSF_SUPPRESSED_STATUS_ID);
        }
        nextToken = response.NextToken;
      } while (nextToken);
    }
    return statuses;
  }
}

function chunkFindingIds(findingIds: string[]): string[][] {
  const uniqueIds = [...new Set(findingIds)];
  return Array.from({ length: Math.ceil(uniqueIds.length / MAX_FINDING_IDS_PER_LOOKUP) }, (_, index) =>
    uniqueIds.slice(index * MAX_FINDING_IDS_PER_LOOKUP, (index + 1) * MAX_FINDING_IDS_PER_LOOKUP),
  );
}

// GetFindingsV2 returns untyped documents; only the two fields this lookup needs are validated.
const ocsfStatusSchema = z.object({ finding_info: z.object({ uid: z.string() }), status_id: z.number() });

function readOcsfStatus(finding: unknown): { findingId: string; statusId: number } | undefined {
  const parsed = ocsfStatusSchema.safeParse(finding);
  return parsed.success ? { findingId: parsed.data.finding_info.uid, statusId: parsed.data.status_id } : undefined;
}
