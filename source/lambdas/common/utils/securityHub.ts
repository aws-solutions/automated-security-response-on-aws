// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { SecurityHubClient, GetFindingsCommand, GetFindingsCommandInput } from '@aws-sdk/client-securityhub';
import { createOptimizedGetFindingsInputByControlId } from '../constants/securityStandardFilters';
import { ASFFFinding } from '@asr/data-models';
import { getLogger } from './logger';

const RATE_LIMIT_DELAY_MS = 120; // 120ms between API calls = ~8 calls/sec
const MAX_RESULTS_PER_REQUEST = 100;

export class SecurityHubUtils {
  private readonly client: SecurityHubClient;
  private readonly logger = getLogger('SecurityHubUtils');

  constructor(client: SecurityHubClient) {
    this.client = client;
  }

  /**
   * Process all findings from Security Hub with automatic pagination and rate limiting
   * @param processBatch - Callback function to process each batch of findings
   * @param filters The filters to apply to the GetFindings request
   * @returns Promise resolving to processing results with total processed count, filtered count, and API call count
   */
  async processAllFindings(
    processBatch: (findings: ASFFFinding[]) => Promise<void>,
    filters: NonNullable<GetFindingsCommandInput['Filters']>,
  ): Promise<{ totalProcessed: number; apiCallCount: number }> {
    let totalProcessed = 0;
    let apiCallCount = 0;
    let nextToken: string | undefined;

    try {
      do {
        apiCallCount++;

        const input = await createOptimizedGetFindingsInputByControlId(filters, nextToken, MAX_RESULTS_PER_REQUEST);
        const response = await this.client.send(new GetFindingsCommand(input));
        const findings = (response.Findings || []) as ASFFFinding[];

        if (findings.length > 0) {
          await processBatch(findings);
          totalProcessed += findings.length;
        }

        nextToken = response.NextToken;

        if (nextToken) {
          await new Promise((resolve) => setTimeout(resolve, RATE_LIMIT_DELAY_MS));
        }
      } while (nextToken);

      this.logger.info(`Processed ${totalProcessed} findings with ${apiCallCount} API calls`);
      return { totalProcessed, apiCallCount };
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
