// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import {
  SecurityHubClient,
  GetFindingHistoryCommand,
  type GetFindingHistoryCommandOutput,
} from '@aws-sdk/client-securityhub';
import { createDynamoDBClient } from '../../../common/utils/dynamodb';
import type { Executor } from '../types';
import type { GetFindingHistoryParams } from '@asr/data-models';
import { tryAccountIdFromFindingId, tryRegionFromFindingId } from '../../../common/utils/findingUtils';
import {
  FindingRemediationHistoryRepository,
  type RemediationHistoryEntry,
} from '../../../common/repositories/findingRemediationHistoryRepository';
import { AccountAuthorizationError, ValidationError } from './errors';

/**
 * Partition to build the default Security Hub product ARN in.
 *
 * Prefers `context.partition`, which the handler reads from the Lambda's own invoked
 * ARN and is therefore correct in every partition without a lookup table. The
 * region-prefix fallback only applies outside the deployed Lambda (local
 * authoring), and covers just the three commercial-adjacent partitions whose
 * prefixes are stable — it deliberately does not guess for isolated or sovereign
 * regions (`us-iso-`, `us-isob-`, `eu-isoe-`, `us-isof-`, `eusc-`), because a
 * wrong partition yields an ARN that silently matches no findings. Those callers
 * get an explicit error telling them to pass `product_arn`.
 */
function resolvePartition(context: { readonly partition?: string; readonly region: string }): string {
  if (context.partition) return context.partition;
  if (context.region.startsWith('cn-')) return 'aws-cn';
  if (context.region.startsWith('us-gov-')) return 'aws-us-gov';
  if (/^(us-iso|us-isob|eu-isoe|us-isof|eusc)-/.test(context.region)) {
    throw new ValidationError(
      `get_finding_history: cannot derive the Security Hub product ARN for region ${context.region} — ` +
        'its partition is not inferable from the region name. Pass product_arn explicitly.',
    );
  }
  return 'aws';
}

/**
 * Region to address Security Hub in for a finding, and to name in the default product ARN.
 *
 * The finding's own region, not the region ASR runs in. A findings search returns rows from
 * every region Security Hub aggregates, so a caller following `findings` →
 * `get_finding_history` routinely holds an ARN from another region; addressing the host
 * region for it makes Security Hub reject a finding that exists, because the ProductArn it
 * is matched against names the wrong region.
 *
 * Falls back to the host region for an id that encodes no region — per ADR 0010 not every
 * finding id is an ARN, and the host region is the only region such a caller can mean.
 */
function resolveFindingRegion(findingId: string, hostRegion: string): string {
  return tryRegionFromFindingId(findingId) ?? hostRegion;
}

/**
 * Security Hub answers `InvalidAccessException` when it cannot serve history for the
 * identified finding — the finding is not visible to this account, or the ProductArn does
 * not match it. Both are the caller's request, not a server fault, so this maps to a
 * validation error (400) that names the region actually addressed. Left unmapped it reached
 * the handler's catch-all and surfaced as `500 Internal server error`, which tells the
 * caller nothing they can act on.
 */
async function fetchSecurityHubHistory(
  client: SecurityHubClient,
  findingId: string,
  productArn: string,
  maxResults: number,
): Promise<GetFindingHistoryCommandOutput> {
  try {
    return await client.send(
      new GetFindingHistoryCommand({
        FindingIdentifier: { Id: findingId, ProductArn: productArn },
        MaxResults: maxResults,
      }),
    );
  } catch (error) {
    if (error instanceof Error && error.name === 'InvalidAccessException') {
      throw new ValidationError(
        `get_finding_history: Security Hub cannot serve history for finding ${findingId} using ` +
          `product ARN ${productArn}. Confirm the finding exists in this account and, if it is not ` +
          'a Security Hub ARN, pass product_arn explicitly.',
      );
    }
    throw error;
  }
}

/**
 * Reads the ASR remediation history for a finding through the repository, which
 * owns the GSI-first / findingType-fallback query and the finding-id filter
 * (ADR 0003 — no DynamoDB query construction in this executor).
 *
 * Returns `accessDenied: true` rather than throwing when the query is refused —
 * "I could not read the table" and "this finding has no history" are both
 * legitimate outcomes for `getFindingHistory` to keep working (Security Hub
 * history is still returned), but they are not the same fact, and collapsing
 * them into a silent empty array would tell the caller a finding has no
 * remediation history when the truth is the query was never allowed to run.
 */
/**
 * Repositories are cached per (region, table) rather than rebuilt on every call.
 * Constructing a `DynamoDBClient` per invocation discards the connection pool and
 * credential cache the SDK maintains, so each call paid for a fresh TLS handshake
 * and credential resolution. The key set is tiny and stable for a warm Lambda —
 * in practice a single entry — so this is a bounded memo, not an unbounded cache.
 */
const remediationHistoryRepositories = new Map<string, FindingRemediationHistoryRepository>();

function getRemediationHistoryRepository(region: string, tableName: string): FindingRemediationHistoryRepository {
  const cacheKey = `${region}|${tableName}`;
  const cached = remediationHistoryRepositories.get(cacheKey);
  if (cached) return cached;

  // Built through the shared factory rather than a bare DynamoDBClient so this
  // repository gets the same connection pooling as every other DynamoDB caller and
  // honors DYNAMODB_ENDPOINT. Without the endpoint override this was the one table
  // read that could not be exercised against DynamoDB Local, so a handler-level
  // test of get_finding_history reached real AWS and failed on credentials.
  const repository = new FindingRemediationHistoryRepository(tableName, createDynamoDBClient({ region }));
  remediationHistoryRepositories.set(cacheKey, repository);
  return repository;
}

async function queryRemediationHistory(
  context: { readonly region: string; readonly remediationHistoryTableName?: string },
  findingId: string,
  maxResults: number,
): Promise<{ readonly items: readonly RemediationHistoryEntry[]; readonly accessDenied: boolean }> {
  const tableName = context.remediationHistoryTableName;
  // When the host does not supply a table — e.g. a run outside the deployed
  // Lambda, where the query grant does not exist either — Security Hub history
  // is returned alone.
  if (!tableName) return { items: [], accessDenied: false };

  const repository = getRemediationHistoryRepository(context.region, tableName);
  const { entries, accessDenied } = await repository.findByFindingId(findingId, maxResults);
  return { items: entries, accessDenied };
}

/**
 * Refuse a finding that belongs to an account the caller is not authorized for.
 *
 * This tool runs directly in the MCP Lambda under its own organization-wide Security
 * Hub permissions, so there is no API hop applying the per-account rules the REST API
 * enforces. Without this check the lowest tier could read history for any account.
 *
 * Fails closed when the account cannot be derived: per ADR 0010 not every finding id is
 * an ARN, and an id that encodes no account cannot be proven to belong to the caller.
 * Allowing it would make an unparseable id a way around the restriction.
 */
function assertFindingIsInAuthorizedAccount(
  findingId: string,
  authorizedAccountIds: readonly string[] | undefined,
): void {
  if (!authorizedAccountIds) return;

  const accountId = tryAccountIdFromFindingId(findingId);
  if (!accountId) {
    throw new AccountAuthorizationError(
      'get_finding_history: cannot determine which account this finding belongs to, so access ' +
        'cannot be authorized. Ask an administrator to run this, or supply a Security Hub finding ARN.',
    );
  }
  if (!authorizedAccountIds.includes(accountId)) {
    throw new AccountAuthorizationError(`get_finding_history: not authorized for account ${accountId}.`);
  }
}

export const getFindingHistory: Executor<
  GetFindingHistoryParams,
  {
    readonly findingId: string;
    readonly securityHubHistory: readonly {
      updateTime: string | undefined;
      findingCreated: boolean;
      updateSource: string | undefined;
      updates: readonly { field: string; oldValue: string | undefined; newValue: string | undefined }[];
    }[];
    readonly remediationHistory: readonly {
      executionId: string;
      status: string;
      time: string;
      resourceId: string;
      updatedBy: string | undefined;
      error: string | undefined;
      /**
       * Whether this row can be rolled back, by the same rule the REST remediations search
       * applies (`isRemediationRollbackEligible`, narrowed to the newest row per finding).
       */
      isRollbackEligible: boolean;
    }[];
    /**
     * True when the ASR remediation history query was refused (AccessDenied)
     * rather than simply empty. Distinguishes "this finding has no
     * remediation history" from "the host lacks permission to look" —
     * `remediationHistory` is `[]` in both cases.
     */
    readonly remediationHistoryAccessDenied: boolean;
  }
> = async (args, context) => {
  assertFindingIsInAuthorizedAccount(args.finding_id, context.authorizedAccountIds);
  const findingRegion = resolveFindingRegion(args.finding_id, context.region);
  const client = new SecurityHubClient({ region: findingRegion });
  const productArn =
    args.product_arn ?? `arn:${resolvePartition(context)}:securityhub:${findingRegion}::product/aws/securityhub`;

  // 1. Security Hub finding history
  const resp = await fetchSecurityHubHistory(client, args.finding_id, productArn, args.max_results ?? 10);
  const securityHubHistory = (resp.Records ?? []).map((r) => ({
    updateTime: r.UpdateTime?.toISOString(),
    findingCreated: r.FindingCreated ?? false,
    updateSource: r.UpdateSource?.Identity,
    updates: (r.Updates ?? []).map((u) => ({
      field: u.UpdatedField ?? '',
      oldValue: u.OldValue,
      newValue: u.NewValue,
    })),
  }));

  // 2. ASR remediation history from DynamoDB
  const { items: remediationHistory, accessDenied: remediationHistoryAccessDenied } = await queryRemediationHistory(
    context,
    args.finding_id,
    args.max_results ?? 10,
  );

  return { findingId: args.finding_id, securityHubHistory, remediationHistory, remediationHistoryAccessDenied };
};
