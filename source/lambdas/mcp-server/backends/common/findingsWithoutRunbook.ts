// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { SecurityHubClient, GetFindingsCommand } from '@aws-sdk/client-securityhub';
import { SSMClient, ListDocumentsCommand, GetParametersByPathCommand } from '@aws-sdk/client-ssm';
import type { Executor, ExecutionContext } from '../types';
import type { ListFindingsWithoutRunbookParams, RunbookMetadata } from '@asr/data-models';
import { CustomRunbookRepository } from '../../../common/repositories/customRunbookRepository';
import { createDynamoDBClient } from '../../../common/utils/dynamodb';
import { getLogger } from '../../../common/utils/logger';

const logger = getLogger('McpServerFindingsWithoutRunbook');

interface ControlGap {
  readonly controlId: string;
  readonly title: string;
  readonly resourceCount: number;
  /**
   * True when this entry is listed as a gap but could not be confirmed as one, for either
   * reason: the runbook-coverage scan was truncated before this control's name could have
   * appeared on an unread page (a runbook may exist past the page ceiling), or the Custom
   * Runbook table was unreadable and this control has an unverified custom-document claim (a
   * deploy may have succeeded). Absent (or `false`) when coverage was fully verified, in
   * which case every listed entry is a confirmed gap.
   */
  readonly runbookCoverageUnconfirmed?: boolean;
}

/**
 * Page ceiling for the Security Hub findings scan. A Lambda executor with no budget would
 * walk `do/while (nextToken)` until the account runs out of findings or the Lambda times
 * out, with no partial result either way. 50 pages is generous (5,000 findings at 100/page)
 * while still bounding worst case; `truncated` tells the caller the ceiling was hit rather
 * than that the account genuinely has no more data.
 */
const MAX_FINDING_PAGES = 50;

/**
 * Page ceiling for the runbook (ListDocuments) scan. Kept higher than the findings ceiling
 * because a busy account can hold many self-owned Automation documents and undercounting
 * coverage would report a control as an unconfirmed gap; a runbook coverage scan that stops
 * too early is the more damaging truncation here.
 */
const MAX_DOCUMENT_PAGES = 100;

/**
 * Security Hub caps a single filter attribute at 20 values, so a caller authorized
 * for more accounts than that cannot be expressed as one `AwsAccountId` criterion —
 * the request is rejected outright. The account list is therefore split into chunks
 * of this size and queried once per chunk, with the per-control counts merged.
 *
 * The data model allows well over 20 accounts per user, so this is reachable in
 * normal use, not an edge case.
 *
 * @see https://docs.aws.amazon.com/securityhub/1.0/APIReference/API_GetFindings.html
 */
const MAX_FILTER_VALUES = 20;

function chunkAccountIds(accountIds: readonly string[]): readonly (readonly string[])[] {
  const chunks: string[][] = [];
  for (let start = 0; start < accountIds.length; start += MAX_FILTER_VALUES) {
    chunks.push([...accountIds.slice(start, start + MAX_FILTER_VALUES)]);
  }
  return chunks;
}

/**
 * Fetch active findings matching the given filters, grouped by control ID.
 *
 * `authorizedAccountIds` restricts the query to accounts the caller may see. It runs
 * server-side as an `AwsAccountId` filter rather than a post-filter, so an
 * unauthorized account's findings are never returned to this Lambda at all — and the
 * page budget is not consumed by records that would be discarded. `undefined` means
 * unrestricted; an empty list yields nothing, which is the correct answer for a
 * caller mapped to no accounts.
 *
 * A caller with more than {@link MAX_FILTER_VALUES} accounts is queried in chunks
 * (Security Hub's per-attribute value cap) and the results merged. The page budget
 * applies per chunk, so `truncated` is true if any chunk hit the ceiling.
 */
async function getFindingsByControl(
  securityHubClient: SecurityHubClient,
  args: ListFindingsWithoutRunbookParams,
  authorizedAccountIds: readonly string[] | undefined,
): Promise<{ readonly byControl: Map<string, { title: string; count: number }>; readonly truncated: boolean }> {
  const byControl = new Map<string, { title: string; count: number }>();
  // `undefined` (unrestricted) is modeled as a single chunk with no account filter,
  // so the pagination logic below has exactly one shape to handle.
  const accountChunks = authorizedAccountIds ? chunkAccountIds(authorizedAccountIds) : [undefined];
  let isTruncated = false;

  for (const accountChunk of accountChunks) {
    let nextToken: string | undefined;
    let pages = 0;
    do {
      const findingsResponse = await securityHubClient.send(
        new GetFindingsCommand({
          Filters: {
            ComplianceStatus: [{ Value: args.compliance_status ?? 'FAILED', Comparison: 'EQUALS' }],
            WorkflowStatus: [{ Value: args.workflow_status ?? 'NEW', Comparison: 'EQUALS' }],
            RecordState: [{ Value: 'ACTIVE', Comparison: 'EQUALS' }],
            ...(accountChunk
              ? { AwsAccountId: accountChunk.map((id) => ({ Value: id, Comparison: 'EQUALS' as const })) }
              : {}),
          },
          MaxResults: 100,
          NextToken: nextToken,
        }),
      );

      for (const finding of findingsResponse.Findings ?? []) {
        const controlId = finding.Compliance?.SecurityControlId;
        if (!controlId) continue;
        const existing = byControl.get(controlId);
        if (existing) existing.count++;
        else byControl.set(controlId, { title: finding.Title ?? '', count: 1 });
      }

      nextToken = findingsResponse.NextToken;
      pages++;
    } while (nextToken && pages < MAX_FINDING_PAGES);
    if (nextToken) isTruncated = true;
  }

  return { byControl, truncated: isTruncated };
}

/**
 * Extracts the control ID from an ASR runbook document name, e.g.
 * `ASR-SC_2.0.0_S3.9` or `ASR-Custom-SC_2.0.0_Inspector.InstanceVulnerability`.
 *
 * The `ASR-` anchor matters: `ListDocuments` is filtered only to self-owned
 * Automation documents, so without it any customer document ending in
 * `_Word.Something` (`MyTeam_Backup_S3.9`) would register that control as
 * covered and hide a real remediation gap — the opposite of what this tool
 * reports.
 *
 * The suffix is alphanumeric rather than digits-only because ASR ships controls
 * whose IDs are not numeric (`Inspector.InstanceVulnerability`,
 * `GuardDuty.IAMUser`, `Macie.SensitiveDataS3Object`). A digits-only pattern
 * never matched their documents, so those controls were always reported as gaps
 * even when a runbook was deployed.
 */
const ASR_RUNBOOK_CONTROL_ID = /^ASR-.*_([A-Za-z0-9]+\.[A-Za-z0-9]+)$/;

/**
 * Custom-runbook documents. Their presence in this account proves only that the
 * FIRST step of a deploy ran: the admin-account document is created before any
 * member deployment, and a deploy in which every member failed throws while
 * leaving this document behind with the record still `DRAFT`. Treating that
 * orphan as coverage hid a control that nothing, anywhere, can remediate — a
 * false negative in a gap-detection tool, which is the worst direction to err.
 * These names are therefore treated as unconfirmed claims to be checked against
 * the Custom Runbook table rather than as evidence of deployment.
 */
const ASR_CUSTOM_RUNBOOK_NAME_PREFIX = 'ASR-Custom-';

/**
 * Built-in document name split into the standard shortname, standard version, and control:
 * `ASR-SC_2.0.0_S3.9`. Needed because ASR maps some controls onto ANOTHER control's
 * remediation, and the mapping is published per standard and version.
 */
const ASR_BUILTIN_DOCUMENT_NAME = /^ASR-([A-Za-z0-9]+)_([0-9.]+)_([A-Za-z0-9]+\.[A-Za-z0-9]+)$/;

/** Root of the solution's SSM parameter namespace, where control remaps are published. */
const SOLUTION_PARAMETER_ROOT = '/Solutions/SO0111';

/**
 * Controls whose remediation is a DIFFERENT control's runbook, keyed by the finding's own
 * control id.
 *
 * ASR ships some remediations once and points several controls at them — `S3.9` executes
 * `CloudTrail.7`'s runbook (`playbooks/SC/lib/sc_remediations.ts`), so the deployed document
 * is named `ASR-SC_2.0.0_CloudTrail.7` and no document mentions `S3.9` at all. Scanning
 * document names alone therefore reports S3.9 as having no runbook, which is how this tool
 * told customers to author a custom runbook for a control ASR already remediates — and
 * because a built-in always wins resolution, that runbook would then never run.
 *
 * The mapping is read from the same SSM parameters the Orchestrator uses at execution time
 * (`{root}/{shortname}/{version}/{control}/remap`, see `layer/sechub_findings.py`), so the
 * two agree by construction rather than by a duplicated table.
 */
async function getControlRemaps(
  ssmClient: SSMClient,
  standards: ReadonlySet<string>,
): Promise<{ readonly remapByControlId: Map<string, string>; readonly unresolved: boolean }> {
  const remapByControlId = new Map<string, string>();
  let unresolved = false;

  for (const standard of standards) {
    // A standard whose remaps could not be fully read (error or page cap) leaves its
    // controls looking like gaps, so flag the whole answer unverified rather than present a
    // possibly-false gap as certain. Per-standard read extracted so this loop stays flat.
    const complete = await readStandardRemaps(ssmClient, standard, remapByControlId);
    if (!complete) unresolved = true;
  }

  return { remapByControlId, unresolved };
}

/**
 * Read one standard's `{control}/remap` parameters into `remapByControlId`, following
 * pagination up to the page cap. Returns false when the read failed or was truncated at the
 * cap — either case means the standard's remap set is only partially known.
 */
async function readStandardRemaps(
  ssmClient: SSMClient,
  standard: string,
  remapByControlId: Map<string, string>,
): Promise<boolean> {
  let nextToken: string | undefined;
  let pages = 0;
  try {
    do {
      const response = await ssmClient.send(
        new GetParametersByPathCommand({
          Path: `${SOLUTION_PARAMETER_ROOT}/${standard}/`,
          Recursive: true,
          MaxResults: 10,
          NextToken: nextToken,
        }),
      );
      for (const parameter of response.Parameters ?? []) {
        // `{root}/{shortname}/{version}/{control}/remap`
        const match = /\/([A-Za-z0-9]+\.[A-Za-z0-9]+)\/remap$/.exec(parameter.Name ?? '');
        if (match && parameter.Value) remapByControlId.set(match[1], parameter.Value);
      }
      nextToken = response.NextToken;
      pages++;
    } while (nextToken && pages < MAX_DOCUMENT_PAGES);

    if (nextToken) {
      logger.warn('Control remap parameters exceeded the page cap; mapped coverage is unverified', {
        standard,
        pages,
      });
      return false;
    }
    return true;
  } catch (error) {
    logger.warn('Could not read control remap parameters; mapped coverage is unverified', {
      standard,
      error: error instanceof Error ? error.message : String(error),
    });
    return false;
  }
}

/**
 * Transient documents created by `test_runbook_yaml` / `test_remediation_script`.
 * They are deliberately short-lived and never a remediation path, so they must
 * never register as coverage. Generated names end in `-{suffix}` and so do not
 * match {@link ASR_RUNBOOK_CONTROL_ID} by accident, but an explicitly-named test
 * document can (`ASR-Custom-Test_S3.9` does). The prefix is matched without
 * requiring a following separator so it covers every such name — the same
 * `ASR-Custom-Test*` shape the Lambda's document IAM policy is scoped to.
 */
const ASR_TRANSIENT_TEST_DOCUMENT_PREFIX = 'ASR-Custom-Test';

/**
 * Control IDs covered by a runbook in this account, split by how much the
 * document name actually proves.
 *
 * `builtInControlIds` — shipped `ASR-{standard}_{version}_{control}` wrappers.
 * These are deployed with the solution's own stacks, so presence here is as
 * strong a signal as this account-scoped scan can give.
 *
 * `customClaimControlIds` — `ASR-Custom-*` documents, which may be orphans from
 * a failed deploy. The caller must confirm these against the Custom Runbook
 * table before treating them as coverage.
 */
async function getDeployedRunbookControlIds(ssmClient: SSMClient): Promise<{
  readonly builtInControlIds: Set<string>;
  readonly customClaimControlIds: Set<string>;
  /** `{shortname}/{version}` pairs seen among built-in documents, for the remap lookup. */
  readonly standards: Set<string>;
  readonly truncated: boolean;
}> {
  const builtInControlIds = new Set<string>();
  const customClaimControlIds = new Set<string>();
  const standards = new Set<string>();
  let nextToken: string | undefined;
  let pages = 0;
  do {
    const listDocumentsResponse = await ssmClient.send(
      new ListDocumentsCommand({
        Filters: [
          { Key: 'DocumentType', Values: ['Automation'] },
          { Key: 'Owner', Values: ['Self'] },
          // Server-side prefix filter so the page budget is spent on ASR documents, not
          // every self-owned Automation document in the account. The finer ASR-Custom vs
          // ASR-Custom-Test vs built-in distinctions still happen client-side below, since
          // ListDocuments' Name filter is a prefix match and cannot express them.
          { Key: 'Name', Values: ['ASR-'] },
        ],
        MaxResults: 50,
        NextToken: nextToken,
      }),
    );
    for (const documentIdentifier of listDocumentsResponse.DocumentIdentifiers ?? []) {
      classifyAsrDocument(documentIdentifier.Name, builtInControlIds, customClaimControlIds, standards);
    }
    nextToken = listDocumentsResponse.NextToken;
    pages++;
  } while (nextToken && pages < MAX_DOCUMENT_PAGES);
  return { builtInControlIds, customClaimControlIds, standards, truncated: Boolean(nextToken) };
}

/**
 * Sort one `ASR-*` document name into the built-in or custom-claim sets, ignoring transient
 * test documents and anything without a control-id suffix. A built-in also records its
 * `{shortname}/{version}` standard so remaps are read only for standards actually deployed
 * here. Extracted from the list loop to keep that loop's cognitive complexity in bounds.
 */
function classifyAsrDocument(
  documentName: string | undefined,
  builtInControlIds: Set<string>,
  customClaimControlIds: Set<string>,
  standards: Set<string>,
): void {
  if (!documentName || documentName.startsWith(ASR_TRANSIENT_TEST_DOCUMENT_PREFIX)) return;
  const controlIdMatch = ASR_RUNBOOK_CONTROL_ID.exec(documentName);
  if (!controlIdMatch) return;
  const controlId = controlIdMatch[1];

  if (documentName.startsWith(ASR_CUSTOM_RUNBOOK_NAME_PREFIX)) {
    customClaimControlIds.add(controlId);
    return;
  }

  builtInControlIds.add(controlId);
  const builtInMatch = ASR_BUILTIN_DOCUMENT_NAME.exec(documentName);
  if (builtInMatch) standards.add(`${builtInMatch[1]}/${builtInMatch[2]}`);
}

/**
 * Confirm which `ASR-Custom-*` document claims correspond to a runbook that was
 * actually deployed somewhere, by reading the Custom Runbook table.
 *
 * A claim is confirmed only when a record for the control is `DEPLOYED` AND at
 * least one member account reports `DEPLOYED`. A `DRAFT` record, or a record
 * whose every member entry is `PENDING`/`FAILED`, means no account can run the
 * runbook — so the control is still a gap no matter what documents exist here.
 *
 * Returns the confirmed control IDs plus `unverifiable`, which is true when the
 * table could not be consulted (not configured, or the read was refused —
 * querying by control ID uses a GSI whose grant is provisioned separately). In
 * that case the caller keeps the claims as coverage but marks them unconfirmed:
 * degrading to "might be a gap" is safe, while dropping a control silently
 * because a read failed would reintroduce the false negative this guards.
 */
async function confirmCustomRunbookCoverage(
  customClaimControlIds: ReadonlySet<string>,
  context: ExecutionContext,
): Promise<{ readonly confirmedControlIds: Set<string>; readonly unverifiable: boolean }> {
  if (customClaimControlIds.size === 0) return { confirmedControlIds: new Set(), unverifiable: false };
  if (!context.customRunbookTableName) return { confirmedControlIds: new Set(), unverifiable: true };

  const repository = new CustomRunbookRepository(
    context.customRunbookTableName,
    createDynamoDBClient({ region: context.region }),
  );

  const confirmedControlIds = new Set<string>();
  for (const controlId of customClaimControlIds) {
    try {
      const records = await repository.findByControlId(controlId);
      if (records.some(isDeployedSomewhere)) confirmedControlIds.add(controlId);
    } catch (error) {
      logger.warn('Could not confirm custom runbook deployment; reporting coverage as unconfirmed', {
        controlId,
        errorName: error instanceof Error ? error.name : 'Unknown',
      });
      return { confirmedControlIds: new Set(), unverifiable: true };
    }
  }
  return { confirmedControlIds, unverifiable: false };
}

/** A runbook version is live only if the record is DEPLOYED and some member account holds it. */
function isDeployedSomewhere(record: RunbookMetadata): boolean {
  if (record.status !== 'DEPLOYED') return false;
  const memberStates = Object.values(record.deployedAccounts ?? {});
  return memberStates.some((state) => state.status === 'DEPLOYED');
}

/**
 * Human-readable caveat attached to every result. The runbook-coverage half of
 * this cross-reference (`getDeployedRunbookControlIds`) is a single
 * `ListDocuments` in the MCP server Lambda's OWN account. Custom runbooks are
 * deployed per member account, so a runbook present here (the admin/server
 * account, or wherever the server runs) marks its control "covered" for the
 * whole result — even if that control still has NO runbook in some other member
 * account where the finding actually lives. A reported gap is therefore
 * authoritative (the runbook is absent even in the server's own account), but
 * the ABSENCE of a gap is not: it means "covered in the server account", not
 * "covered everywhere". Confirming per-member coverage needs a cross-account
 * document scan, which is a separate change.
 */
const RUNBOOK_COVERAGE_CAVEAT =
  'Runbook coverage is checked only in the account this MCP server runs in. Custom runbooks are ' +
  'deployed per member account, so a control shown as covered here may still lack a runbook in ' +
  'another member account. Reported gaps are reliable; the absence of a gap is not authoritative per-member.';

/**
 * Appended when the Custom Runbook table could not be consulted. Custom-document claims
 * were NOT treated as coverage in that case, so any control resting on such a claim stays
 * in the results as a gap marked `runbookCoverageUnconfirmed`. The caller needs to know the
 * table read failed so it can weigh those flagged entries — a listed control may in fact
 * have a live custom runbook whose deploy state could not be read.
 */
const UNVERIFIED_CUSTOM_COVERAGE_CAVEAT =
  'Custom runbook deployment state could not be verified for this result, so controls whose only ' +
  'coverage is a custom runbook are still listed as gaps and marked runbookCoverageUnconfirmed; such a ' +
  'control may already have a deployed custom runbook.';

const UNRESOLVED_CONTROL_REMAP_CAVEAT =
  'Control-to-runbook remaps could not be read, so a control that ASR remediates through ANOTHER ' +
  "control's runbook may be reported here as a gap. Verify against the deployed ASR documents before " +
  'authoring a custom runbook for one of these controls.';

interface ListFindingsWithoutRunbookResult {
  readonly count: number;
  readonly controls: readonly ControlGap[];
  readonly truncated: boolean;
  /**
   * Scope of the runbook-coverage check. Always `server-account-only` today:
   * coverage is verified only in the server's own account (see
   * {@link RUNBOOK_COVERAGE_CAVEAT}). Modeled as a field rather than left
   * implicit so a future cross-account scan can report a wider scope without a
   * breaking shape change.
   */
  readonly runbookCoverageScope: 'server-account-only';
  /** Verbatim {@link RUNBOOK_COVERAGE_CAVEAT}, so the caller surfaces the limitation rather than over-claiming. */
  readonly runbookCoverageCaveat: string;
}

/**
 * Lists Security Hub control IDs that have active findings but no deployed
 * ASR runbook. Cross-references GetFindings with ListDocuments in one call.
 *
 * The findings query is per authorized account, but the runbook check is a
 * single scan of the server's own account, so it can only prove a gap, not the
 * absence of one, per member — see {@link RUNBOOK_COVERAGE_CAVEAT}. Every result
 * carries that caveat and a `runbookCoverageScope`.
 */
export const listFindingsWithoutRunbook: Executor<
  ListFindingsWithoutRunbookParams,
  ListFindingsWithoutRunbookResult
> = async (args, context) => {
  // Security Hub treats an absent account criterion as unrestricted. Do not send
  // an empty criterion and rely on service-specific empty-list semantics: a caller
  // explicitly authorized for zero accounts must not make an organization-wide
  // findings request at all.
  if (context.authorizedAccountIds?.length === 0) {
    return {
      count: 0,
      controls: [],
      truncated: false,
      runbookCoverageScope: 'server-account-only',
      runbookCoverageCaveat: RUNBOOK_COVERAGE_CAVEAT,
    };
  }

  const securityHubClient = new SecurityHubClient({ region: context.region });
  const ssmClient = new SSMClient({ region: context.region });

  const [
    { byControl, truncated: findingsTruncated },
    { builtInControlIds, customClaimControlIds, standards, truncated: documentsTruncated },
  ] = await Promise.all([
    getFindingsByControl(securityHubClient, args, context.authorizedAccountIds),
    getDeployedRunbookControlIds(ssmClient),
  ]);

  // A custom-runbook document proves only that a deploy started here, so each claim
  // is confirmed against the Custom Runbook table before it can hide a control.
  // The remap read runs alongside it: a control can be covered by ANOTHER control's
  // built-in runbook, which no document name mentions.
  const [{ confirmedControlIds, unverifiable: customCoverageUnverifiable }, { remapByControlId, unresolved }] =
    await Promise.all([
      confirmCustomRunbookCoverage(customClaimControlIds, context),
      getControlRemaps(ssmClient, standards),
    ]);

  // Controls whose remediation is a different control's deployed runbook. Without this
  // the tool reports them as gaps and sends a customer to author a custom runbook that
  // a built-in would then always beat in resolution.
  const remappedCoveredControlIds = [...remapByControlId.entries()]
    .filter(([, executesControlId]) => builtInControlIds.has(executesControlId))
    .map(([controlId]) => controlId);

  // A control is covered only when its coverage is CONFIRMED. When the Custom Runbook
  // table could not be read we do NOT treat unconfirmed custom-document claims as coverage:
  // a stale document from a failed or DRAFT deploy would otherwise hide a genuine gap. Those
  // controls stay in the gap list, each marked runbookCoverageUnconfirmed so the operator
  // sees exactly which entries rest on an unverified custom claim — the same per-control
  // treatment truncation already uses, rather than hiding them behind only a global caveat.
  const coveredControlIds = new Set([...builtInControlIds, ...remappedCoveredControlIds, ...confirmedControlIds]);

  const controls: ControlGap[] = [...byControl.entries()]
    .filter(([controlId]) => !coveredControlIds.has(controlId))
    .map(([controlId, v]) => ({
      controlId,
      title: v.title,
      resourceCount: v.count,
      // This entry may not be a true gap when the runbook scan was truncated (a runbook could
      // exist past the page ceiling), the control-remap read was unresolved (a remap to another
      // control's built-in may have been missed), or the table was unreadable and this control
      // has an unverified custom-document claim (a deploy may have succeeded). All three mean
      // "listed as a gap, but unconfirmed", so they share one per-control marker.
      ...(documentsTruncated || unresolved || (customCoverageUnverifiable && customClaimControlIds.has(controlId))
        ? { runbookCoverageUnconfirmed: true }
        : {}),
    }))
    .sort((a, b) => a.controlId.localeCompare(b.controlId));

  return {
    count: controls.length,
    controls,
    truncated: findingsTruncated || documentsTruncated,
    runbookCoverageScope: 'server-account-only',
    runbookCoverageCaveat: [
      RUNBOOK_COVERAGE_CAVEAT,
      ...(customCoverageUnverifiable ? [UNVERIFIED_CUSTOM_COVERAGE_CAVEAT] : []),
      ...(unresolved ? [UNRESOLVED_CONTROL_REMAP_CAVEAT] : []),
    ].join(' '),
  };
};
