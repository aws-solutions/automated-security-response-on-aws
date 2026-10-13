// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { DynamoDBDocumentClient, QueryCommand } from '@aws-sdk/lib-dynamodb';
import { isRemediationRollbackEligible, narrowRollbackEligibilityToNewestPerFinding } from '@asr/data-models';
import { getLogger } from '../utils/logger';

const logger = getLogger('FindingRemediationHistoryRepository');

/**
 * Read-only access to the ASR remediation-history table for a single finding.
 *
 * ADR 0003 keeps DynamoDB query construction out of business logic. The
 * get_finding_history MCP tool needs a narrow read — "the remediation history
 * for this one finding" — that the write-oriented `RemediationHistoryRepository`
 * (which requires a findings table for its create/transact flows) does not
 * expose. This repository encapsulates that read: the GSI-first query, the
 * findingType fallback, and the exact finding-id filter, so the executor deals
 * only in domain objects.
 */

const FINDING_ID_GSI = 'findingId-lastUpdatedTime-GSI';

/** One remediation-history record, as returned to the caller. */
export interface RemediationHistoryEntry {
  readonly executionId: string;
  readonly status: string;
  readonly time: string;
  readonly resourceId: string;
  readonly updatedBy: string | undefined;
  readonly error: string | undefined;
  /**
   * Whether this record can be rolled back, computed with the same predicate and the same
   * newest-row-per-finding narrowing the REST `remediations` search uses for its
   * `isRollbackEligible` column. The row stores a bare `rollbackAvailable` capability flag; that
   * alone is not eligibility — an already-rolled-back or failed remediation stays
   * `rollbackAvailable: true` in storage but cannot be rolled back, and an older SUCCESS attempt
   * loses eligibility once a newer attempt (of any status) exists.
   */
  readonly isRollbackEligible: boolean;
}

/** Distinguishes "the query was refused" from "this finding has no history". */
export interface FindByFindingIdResult {
  readonly entries: readonly RemediationHistoryEntry[];
  /**
   * True when the query was refused with AccessDenied rather than simply
   * returning nothing. Collapsing the two would tell the caller a finding has
   * no remediation history when the truth is the query was never allowed to run.
   */
  readonly accessDenied: boolean;
}

interface RemediationHistoryItem {
  readonly findingId?: string;
  readonly executionId?: string;
  readonly remediationStatus?: string;
  readonly lastUpdatedTime?: string;
  readonly resourceId?: string;
  readonly lastUpdatedBy?: string;
  readonly error?: string;
  readonly rollbackAvailable?: boolean;
  readonly rollbackBackupKey?: string;
  readonly findingJSON?: Uint8Array;
}

export class FindingRemediationHistoryRepository {
  constructor(
    private readonly tableName: string,
    private readonly dynamoDBClient: DynamoDBDocumentClient,
  ) {}

  /**
   * Return up to `maxResults` remediation-history records for `findingId`, newest first.
   *
   * Queries the `findingId-lastUpdatedTime-GSI` first; if that returns nothing,
   * falls back to a primary-key query by the finding's control-scoped
   * `findingType`, filtered down to this exact finding (that key groups every
   * resource remediated for the control, so an unfiltered result would leak
   * other findings' history). AccessDenied and a missing table are reported as
   * an empty result (with `accessDenied` distinguishing the former); every other
   * DynamoDB error — a malformed query, throttling — propagates, since swallowing
   * those would misreport a transient failure as "no data".
   */
  async findByFindingId(findingId: string, maxResults: number): Promise<FindByFindingIdResult> {
    try {
      const gsiResponse = await this.dynamoDBClient.send(
        new QueryCommand({
          TableName: this.tableName,
          IndexName: FINDING_ID_GSI,
          KeyConditionExpression: 'findingId = :fid',
          ExpressionAttributeValues: { ':fid': findingId },
          ScanIndexForward: false,
          Limit: maxResults,
        }),
      );
      // Rows are typed at the query boundary; the DocumentClient returns `Record<string, any>`, which
      // satisfies the all-optional item shape without a cast.
      const items: RemediationHistoryItem[] = gsiResponse.Items?.length
        ? gsiResponse.Items
        : await this.queryByFindingType(findingId);

      return { entries: toEntries(items.slice(0, maxResults)), accessDenied: false };
    } catch (err) {
      const isAccessDenied = err instanceof Error && err.name === 'AccessDeniedException';
      // A missing table (ResourceNotFoundException) is a legitimate "no history" outcome for a
      // host that has not been fully wired up. ValidationException and
      // ProvisionedThroughputExceededException are not — they mean the query itself is malformed
      // or was throttled, and swallowing them would misreport a transient failure as "no data".
      const isMissingTable = err instanceof Error && err.name === 'ResourceNotFoundException';
      if (isAccessDenied || isMissingTable) {
        logger.warn('DynamoDB remediation history query failed', {
          error: err instanceof Error ? err.message : err,
        });
        return { entries: [], accessDenied: isAccessDenied };
      }
      throw err;
    }
  }

  /**
   * Fallback query used when the GSI query by `findingId` returns no results:
   * derives the `findingType` (the table's primary key) from the finding ID and
   * queries by that, narrowed to this finding's rows.
   *
   * `findingType` is control-scoped, not finding-scoped — it groups every
   * resource ASR has ever remediated for that control, not just this finding.
   * The sort key is `findingId#executionId`, so a `begins_with` on
   * `<findingId>#` restricts the query to this finding's rows without reading
   * the rest of the control's history, and without depending on a `Limit`
   * that a busy control could exhaust before reaching this finding at all.
   *
   * Rows are paged until the finding's history is exhausted (a finding has one
   * row per execution, so this is bounded) and returned newest-first. The base
   * table orders them by executionId, not time, and the caller slices to
   * `maxResults` and then narrows rollback eligibility to the newest row per
   * finding: if the slice dropped the true newest row (a ROLLBACK_SUCCESS) but
   * kept an older SUCCESS, that older row would be mistaken for the newest and
   * keep advertising rollback. Reading everything and sorting first makes the
   * slice keep the same rows the time-ordered GSI path would.
   */
  private async queryByFindingType(findingId: string): Promise<RemediationHistoryItem[]> {
    // Matches findingEventNormalizer.ts's own FINDING_ID_PATTERNS entry for
    // consolidated (Security Control) findings — bounded by the trailing
    // `/finding` segment, not just the presence of `security-control/` anywhere
    // in the ARN, so a subscription/unconsolidated finding ID (where
    // "security-control/" never appears) falls through to an empty result rather
    // than matching the wrong segment.
    const typeMatch = findingId.match(/security-control\/[^/]+\/finding/);
    if (!typeMatch) return [];

    const findingType = typeMatch[0].replace(/\/finding$/, '');
    const items: RemediationHistoryItem[] = [];
    let exclusiveStartKey: Record<string, unknown> | undefined;
    do {
      const response = await this.dynamoDBClient.send(
        new QueryCommand({
          TableName: this.tableName,
          KeyConditionExpression: 'findingType = :ft AND begins_with(#sk, :fidPrefix)',
          ExpressionAttributeNames: { '#sk': 'findingId#executionId' },
          ExpressionAttributeValues: { ':ft': findingType, ':fidPrefix': `${findingId}#` },
          ExclusiveStartKey: exclusiveStartKey,
        }),
      );
      items.push(...(response.Items ?? []));
      exclusiveStartKey = response.LastEvaluatedKey;
    } while (exclusiveStartKey);

    return items.sort((a, b) => (b.lastUpdatedTime ?? '').localeCompare(a.lastUpdatedTime ?? ''));
  }
}

/**
 * Projects the raw rows to entries, with rollback eligibility narrowed to the newest row per
 * finding. Evaluating each row alone marked an old SUCCESS attempt eligible even after a later
 * rollback had undone it — a caller acting on that would have been refused by the lock, but the
 * history read was still reporting something the REST search had already stopped claiming.
 */
function toEntries(items: readonly RemediationHistoryItem[]): RemediationHistoryEntry[] {
  const evaluated = items.map((record) => {
    return {
      findingId: record.findingId ?? '',
      lastUpdatedTime: record.lastUpdatedTime ?? '',
      executionId: record.executionId ?? '',
      isRollbackEligible: isRemediationRollbackEligible(record),
      entry: toEntry(record),
    };
  });
  return narrowRollbackEligibilityToNewestPerFinding(evaluated).map(({ entry, isRollbackEligible }) => ({
    ...entry,
    isRollbackEligible,
  }));
}

function toEntry(record: RemediationHistoryItem): Omit<RemediationHistoryEntry, 'isRollbackEligible'> {
  return {
    executionId: record.executionId ?? '',
    status: record.remediationStatus ?? '',
    time: record.lastUpdatedTime ?? '',
    resourceId: record.resourceId ?? '',
    updatedBy: record.lastUpdatedBy,
    error: record.error,
  };
}
