// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { FindingApiResponse, FindingId, FindingsActionRequest } from '@data-models';
import { FindingsActionResponse } from '../../../store/findingsApiSlice.ts';
import { getErrorMessage } from '../../../utils/error.ts';

// WAF SizeRestrictions_BODY blocks requests larger than 8 KB. Each finding is
// sent twice in an action request — once in findingIds and once in findingKeys
// ({ findingId, findingType }) — at roughly 300 bytes worst case, so 15 findings
// per request (~4.5 KB) stays safely under the limit. Batching keeps every
// request small regardless of how many findings the user selected.
export const FINDINGS_ACTION_BATCH_SIZE = 15;

// Split an array into consecutive chunks of at most `batchSize`, preserving
// order. Used to break a findings action into WAF-safe requests.
export function batchItems<ItemType>(items: readonly ItemType[], batchSize: number): ItemType[][] {
  const batches: ItemType[][] = [];
  for (let start = 0; start < items.length; start += batchSize) {
    batches.push(items.slice(start, start + batchSize));
  }
  return batches;
}

// Outcome of running a findings action across batches, aggregated in display
// order: `submittedIds` were accepted, `unresolvedIds` were returned by the API
// as skipped, `failedIds` belonged to batches whose request failed, and
// `errorMessage` is a representative message from the first failing batch.
export interface BatchedActionOutcome {
  submittedIds: FindingId[];
  unresolvedIds: FindingId[];
  failedIds: FindingId[];
  errorMessage?: string;
}

// Run a findings action over the selected items in WAF-safe batches. Each batch
// carries the same request shape as a single-call action ({ actionType,
// findingIds, findingKeys }); batches run in parallel (the sensitive-write WAF
// limit of 600/60s leaves ample headroom for the handful of requests a capped
// selection produces). Results are aggregated in display order: a fulfilled
// batch with no error contributes its findingIds minus its own unresolvedIds to
// submittedIds, while a rejected batch or one carrying an error contributes its
// findingIds to failedIds and a representative errorMessage.
export async function executeFindingActionInBatches(
  executeAction: (req: FindingsActionRequest) => Promise<{ data?: FindingsActionResponse; error?: unknown }>,
  actionType: FindingsActionRequest['actionType'],
  items: readonly FindingApiResponse[],
): Promise<BatchedActionOutcome> {
  const batches = batchItems(items, FINDINGS_ACTION_BATCH_SIZE);

  const settledResults = await Promise.allSettled(
    batches.map((batch) =>
      executeAction({
        actionType,
        findingIds: batch.map((item) => item.findingId),
        findingKeys: batch.map((item) => ({ findingId: item.findingId, findingType: item.findingType })),
      }),
    ),
  );

  const outcome: BatchedActionOutcome = { submittedIds: [], unresolvedIds: [], failedIds: [] };

  settledResults.forEach((settled, index) => {
    const batchFindingIds = batches[index].map((item) => item.findingId);

    if (settled.status === 'fulfilled' && !settled.value.error) {
      const batchUnresolvedIds = settled.value.data?.unresolvedIds ?? [];
      const batchUnresolvedSet = new Set<string>(batchUnresolvedIds);
      outcome.unresolvedIds.push(...batchUnresolvedIds);
      outcome.submittedIds.push(...batchFindingIds.filter((id) => !batchUnresolvedSet.has(id)));
    } else {
      outcome.failedIds.push(...batchFindingIds);
      const reason = settled.status === 'rejected' ? settled.reason : settled.value.error;
      // Keep the first NON-EMPTY message so a later real message replaces an
      // empty/undefined one from an earlier failing batch.
      outcome.errorMessage = outcome.errorMessage || getErrorMessage(reason);
    }
  });

  return outcome;
}

// Partial/total failure sentence shared by the batched action handlers when one
// or more batches fail. Kept behavior-consistent across suppress and remediate.
export function buildFailedFindingsMessage(
  actionType: string,
  failedCount: number,
  errorMessage: string | undefined,
): string {
  const findingText = `${failedCount} finding${failedCount === 1 ? '' : 's'}`;
  const detail = errorMessage ? `: ${errorMessage}` : '. Please try again.';
  return `Failed to ${actionType} ${findingText}${detail}`;
}
