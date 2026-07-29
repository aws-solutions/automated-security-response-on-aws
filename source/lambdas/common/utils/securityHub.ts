// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { GetFindingsCommand, GetFindingsCommandInput, SecurityHubClient } from '@aws-sdk/client-securityhub';
import { createOptimizedGetFindingsInputByControlId } from '../constants/securityStandardFilters';
import { ASFFFinding } from '@asr/data-models';
import { getLogger } from './logger';

const RATE_LIMIT_DELAY_MS = 120; // 120ms between API calls = ~8 calls/sec
const MAX_RESULTS_PER_REQUEST = 100;

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
}
