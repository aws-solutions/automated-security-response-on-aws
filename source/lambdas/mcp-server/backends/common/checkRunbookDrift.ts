// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import * as fs from 'node:fs/promises';
import * as path from 'node:path';
import * as yaml from 'js-yaml';
import { SSMClient, GetDocumentCommand, DescribeDocumentCommand } from '@aws-sdk/client-ssm';
import type { Executor, ExecutionContext } from '../types';
import { MissingParameterError, PathContainmentError, ValidationError } from './errors';
import { isDocumentNotFound } from './ssmExecutionHelpers';
import type { CheckRunbookDriftParams } from '../../contract/toolContract';

export interface CheckRunbookDriftResult {
  readonly documentName: string;
  readonly isInSync: boolean;
  readonly reason: 'identical-text' | 'identical-structure' | 'differs' | 'missing-remote';
  readonly localFormat: 'YAML' | 'JSON';
  readonly remoteFormat: 'YAML' | 'JSON' | 'UNKNOWN';
  readonly remoteLatestVersion: string | undefined;
  readonly remoteStatus: string | undefined;
  readonly structuralDiff: readonly DiffEntry[];
  /** True when `structuralDiff` was cut off at 100 entries — there were more differences than shown. */
  readonly structuralDiffTruncated: boolean;
  readonly localSource: 'inline' | 'file';
  readonly localPath: string | undefined;
}

interface DiffEntry {
  readonly path: string;
  readonly changeType: 'added' | 'removed' | 'changed';
  readonly local: unknown;
  readonly remote: unknown;
}

/**
 * Parse a document, returning `{ value }` on success or `undefined` when the content is
 * not valid YAML/JSON.
 *
 * Returns rather than throws because both the caller's content and the remote document are
 * arbitrary text: a malformed document is a normal outcome the caller degrades to a
 * text-level comparison, not an error that should fail check_runbook_drift outright.
 */
function tryParseDoc(content: string, format: 'YAML' | 'JSON'): { readonly value: unknown } | undefined {
  try {
    return { value: format === 'JSON' ? JSON.parse(content) : yaml.load(content, { schema: yaml.CORE_SCHEMA }) };
  } catch {
    return undefined;
  }
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/**
 * Serialize `value` to at most `maxChars` characters WITHOUT first stringifying it
 * whole.
 *
 * A plain `JSON.stringify(value)` fully materializes the object graph before any slice,
 * so a value whose parsed form is an alias DAG (js-yaml resolves `&anchor`/`*alias` into
 * shared references) expands exponentially — the drift tool takes attacker-influenced YAML,
 * so that is a DoS. This decrements a shared character budget inside the replacer and stops
 * emitting once it is spent, and a WeakSet collapses a repeated object reference to a marker
 * so the same shared node is never expanded twice. Bounds total serialization work by the
 * budget regardless of how the graph fans out.
 */
function boundedStringify(value: unknown, maxChars: number): string {
  let remaining = maxChars;
  const alreadySerialized = new WeakSet<object>();
  const serialized = JSON.stringify(value, (_key, candidate: unknown) => {
    if (remaining <= 0) return '…';
    if (typeof candidate === 'string') {
      remaining -= candidate.length;
      return candidate;
    }
    if (candidate !== null && typeof candidate === 'object') {
      if (alreadySerialized.has(candidate)) return '…(repeated reference)';
      alreadySerialized.add(candidate);
      remaining -= 2;
      return candidate;
    }
    remaining -= 4;
    return candidate;
  });
  if (serialized === undefined) return '(unserialisable)';
  return serialized.length > maxChars ? `${serialized.slice(0, maxChars)}… (truncated)` : serialized;
}

function truncate(value: unknown, maxChars = 300): unknown {
  if (value === undefined || value === null) return value;
  if (typeof value === 'string') return value.length > maxChars ? `${value.slice(0, maxChars)}… (truncated)` : value;
  if (typeof value === 'number' || typeof value === 'boolean') return value;
  try {
    const serialised = boundedStringify(value, maxChars);
    try {
      return JSON.parse(serialised);
    } catch {
      // The budget can cut the JSON mid-structure, leaving a string that no longer
      // parses. That is fine: the diff value is for human display, so the bounded
      // string is returned as-is rather than a parsed object.
      return serialised;
    }
  } catch {
    return '(unserialisable)';
  }
}

/**
 * Traversal bounds for `diff`. `runbook_yaml`/`runbook_path` and the remote
 * document are both attacker-influenced YAML, and the traversal is recursive
 * over a shared-reference graph, so it needs stop conditions that do not depend
 * on the input being well-behaved:
 *
 * - The visited-pair memo (see {@link DiffBudget.comparedPairs}) is what actually
 *   terminates the walk. js-yaml resolves anchors and aliases into a shared-reference
 *   DAG, so a node can be reached by many paths, and a self-referential anchor
 *   (`root: &a {child: *a}`) is a genuine cycle. Neither is bounded by depth: a
 *   document that references the same anchor twice per level (`c: [*b, *b]`,
 *   `b: [*a, *a]`, …) stays shallow but re-descends each shared `(local, remote)`
 *   node at every occurrence, so node visits grow *exponentially* in breadth while
 *   depth stays tiny. Memoizing which `(local, remote)` pairs have already been
 *   compared collapses that fan-out to one visit per distinct pair and makes cycles
 *   terminate. The memo is keyed on the PAIR, not on the local node alone: the same
 *   local node can legitimately be compared against different remotes, and skipping
 *   on the local node alone would drop a real difference and report two unequal
 *   documents as identical.
 * - `MAX_NODE_VISITS` is the hard backstop for the case the memo cannot help — a
 *   document whose every `(local, remote)` pair is genuinely distinct, so nothing
 *   is ever deduped. It bounds total work regardless of structure.
 * - `MAX_DIFF_DEPTH` guards recursion (stack) depth. js-yaml caps parse nesting at
 *   100 (`maxDepth`) and throws before the diff sees the document, so this is set
 *   deliberately *above* that parser cap: it never truncates a document YAML would
 *   accept, and only fires on a graph (built via JSON, whose parser has no such cap,
 *   or an alias cycle) that reaches this depth.
 * - Entry count caps the response. The result was already sliced to 100, but only
 *   after the full traversal had run, so a wide document still paid for every node
 *   it would then discard.
 */
const MAX_DIFF_DEPTH = 200;
const MAX_DIFF_ENTRIES = 100;

/**
 * Hard ceiling on the number of `(local, remote)` node pairs the walk will compare.
 *
 * The pair memo (see {@link DiffBudget}) already collapses alias fan-out and
 * terminates cycles, so this only fires for a document whose pairs are all genuinely
 * distinct — the one shape the memo cannot bound. It makes total work independent of
 * the input's structure, and the overflow is reported via `structuralDiffTruncated`
 * rather than silently claiming the documents match.
 */
const MAX_NODE_VISITS = 100_000;

/**
 * Traversal collects up to `MAX_DIFF_ENTRIES + 1` entries, not `MAX_DIFF_ENTRIES`.
 *
 * The result reports `structuralDiffTruncated` as `structuralDiff.length >
 * MAX_DIFF_ENTRIES`. When traversal stopped *at* the cap that comparison could never
 * be true, so a document with 100+ real differences was cut off and still reported as
 * complete. Collecting one extra entry is what makes the overflow observable; the
 * caller is still handed only the first `MAX_DIFF_ENTRIES`.
 */
const MAX_COLLECTED_DIFF_ENTRIES = MAX_DIFF_ENTRIES + 1;

/**
 * Mutable state threaded through the recursive walk.
 *
 * `entries` collects the differences. `depthBudgetExhausted` and
 * `visitBudgetExhausted` record that at least one branch was cut short — at
 * MAX_DIFF_DEPTH and MAX_NODE_VISITS respectively. Both are tracked separately
 * from the entry-count overflow because a diff can be truncated by either bound
 * while producing far fewer than MAX_DIFF_ENTRIES entries (a single narrow chain
 * reaching the depth bound, or a visit-capped walk that pushed no entries), so
 * `entries.length` alone cannot tell the caller the walk was incomplete.
 *
 * `comparedPairs` memoizes which `(local, remote)` object pairs have already been
 * compared, keyed on the local node with a set of the remotes it has been paired
 * with. It both terminates cycles and collapses the DAG fan-out that alias-heavy
 * documents produce — see the {@link MAX_DIFF_DEPTH} block comment. `nodeVisits`
 * counts pairs actually descended into, bounded by MAX_NODE_VISITS.
 */
interface DiffBudget {
  readonly entries: DiffEntry[];
  depthBudgetExhausted: boolean;
  visitBudgetExhausted: boolean;
  readonly comparedPairs: WeakMap<object, WeakSet<object>>;
  nodeVisits: number;
}

function newDiffBudget(): DiffBudget {
  return {
    entries: [],
    depthBudgetExhausted: false,
    visitBudgetExhausted: false,
    comparedPairs: new WeakMap(),
    nodeVisits: 0,
  };
}

/**
 * Whether the `(local, remote)` pair has already been compared, recording it as
 * seen when it has not. Keyed on the pair rather than the local node alone: the
 * same local node may be compared against different remotes, so deduping on the
 * local node would drop a real difference.
 */
function isPairAlreadyCompared(budget: DiffBudget, local: object, remote: object): boolean {
  const seenRemotes = budget.comparedPairs.get(local);
  if (seenRemotes?.has(remote)) return true;
  if (seenRemotes) seenRemotes.add(remote);
  else budget.comparedPairs.set(local, new WeakSet([remote]));
  return false;
}

/** Diffs one key across two plain objects, dispatching on which side has it. */
function diffObjectKey(
  localValue: Record<string, unknown>,
  remoteValue: Record<string, unknown>,
  key: string,
  nextPath: string,
  budget: DiffBudget,
  depth: number,
): void {
  const localHas = Object.hasOwn(localValue, key);
  const remoteHas = Object.hasOwn(remoteValue, key);

  if (localHas && remoteHas) {
    diff(localValue[key], remoteValue[key], nextPath, budget, depth + 1);
  } else if (localHas) {
    budget.entries.push({ path: nextPath, changeType: 'added', local: truncate(localValue[key]), remote: undefined });
  } else {
    budget.entries.push({
      path: nextPath,
      changeType: 'removed',
      local: undefined,
      remote: truncate(remoteValue[key]),
    });
  }
}

function diffObjects(
  localValue: Record<string, unknown>,
  remoteValue: Record<string, unknown>,
  currentPath: string,
  budget: DiffBudget,
  depth: number,
): void {
  const keys = new Set([...Object.keys(localValue), ...Object.keys(remoteValue)]);
  for (const key of keys) {
    if (budget.entries.length >= MAX_COLLECTED_DIFF_ENTRIES) break;
    const nextPath = currentPath ? `${currentPath}.${key}` : key;
    diffObjectKey(localValue, remoteValue, key, nextPath, budget, depth);
  }
}

function diffArrays(
  localValue: unknown[],
  remoteValue: unknown[],
  currentPath: string,
  budget: DiffBudget,
  depth: number,
): void {
  const len = Math.max(localValue.length, remoteValue.length);
  for (let i = 0; i < len; i++) {
    if (budget.entries.length >= MAX_COLLECTED_DIFF_ENTRIES) break;
    const nextPath = `${currentPath}[${i}]`;
    const localHas = i < localValue.length;
    const remoteHas = i < remoteValue.length;

    if (localHas && remoteHas) {
      diff(localValue[i], remoteValue[i], nextPath, budget, depth + 1);
    } else if (localHas) {
      budget.entries.push({ path: nextPath, changeType: 'added', local: truncate(localValue[i]), remote: undefined });
    } else {
      budget.entries.push({
        path: nextPath,
        changeType: 'removed',
        local: undefined,
        remote: truncate(remoteValue[i]),
      });
    }
  }
}

/**
 * Best-effort structural diff. When a value differs, the tool truncates long
 * serialisations before returning. Traversal is bounded on both depth and entry
 * count (see MAX_DIFF_DEPTH / MAX_DIFF_ENTRIES) so that hostile or merely
 * pathological YAML cannot exhaust the stack or do unbounded work.
 */
function diff(localValue: unknown, remoteValue: unknown, currentPath: string, budget: DiffBudget, depth: number): void {
  if (Object.is(localValue, remoteValue)) return;
  if (budget.entries.length >= MAX_COLLECTED_DIFF_ENTRIES) return;

  // Report the cut rather than returning silently: a caller comparing a deeply
  // nested runbook must not read a truncated diff as "no drift below here". The
  // placeholder entry is visible in the diff, but a single such entry stays well
  // under MAX_DIFF_ENTRIES, so the depth cut is ALSO recorded on the budget and
  // OR'd into structuralDiffTruncated — otherwise a depth-truncated walk would be
  // reported as complete.
  if (depth >= MAX_DIFF_DEPTH) {
    budget.depthBudgetExhausted = true;
    budget.entries.push({
      path: currentPath || '(root)',
      changeType: 'changed',
      local: `(not compared: nesting exceeds ${MAX_DIFF_DEPTH} levels)`,
      remote: `(not compared: nesting exceeds ${MAX_DIFF_DEPTH} levels)`,
    });
    return;
  }

  if (isPlainObject(localValue) && isPlainObject(remoteValue)) {
    if (isBudgetExhaustedByVisit(localValue, remoteValue, currentPath, budget)) return;
    diffObjects(localValue, remoteValue, currentPath, budget, depth);
    return;
  }

  if (Array.isArray(localValue) && Array.isArray(remoteValue)) {
    if (isBudgetExhaustedByVisit(localValue, remoteValue, currentPath, budget)) return;
    diffArrays(localValue, remoteValue, currentPath, budget, depth);
    return;
  }

  budget.entries.push({
    path: currentPath || '(root)',
    changeType: 'changed',
    local: truncate(localValue),
    remote: truncate(remoteValue),
  });
}

/**
 * Guards descent into an object/array pair against the DAG fan-out and cycles
 * that alias-heavy documents produce. Returns true (skip the descent) when the
 * pair was already compared, or when the node-visit ceiling has been reached —
 * recording the ceiling hit once so `structuralDiffTruncated` reports it. Only
 * called for the recursing (object/array) cases; primitives never re-descend.
 */
function isBudgetExhaustedByVisit(local: object, remote: object, currentPath: string, budget: DiffBudget): boolean {
  if (isPairAlreadyCompared(budget, local, remote)) return true;

  if (++budget.nodeVisits > MAX_NODE_VISITS) {
    if (!budget.visitBudgetExhausted) {
      budget.visitBudgetExhausted = true;
      const notCompared = `(not compared: exceeded ${MAX_NODE_VISITS} node comparisons)`;
      budget.entries.push({
        path: currentPath || '(root)',
        changeType: 'changed',
        local: notCompared,
        remote: notCompared,
      });
    }
    return true;
  }
  return false;
}

/**
 * Runs the bounded structural walk and reports both the collected entries and
 * whether the walk was cut short — by the entry cap OR the depth bound.
 */
function computeStructuralDiff(
  localValue: unknown,
  remoteValue: unknown,
): { readonly entries: DiffEntry[]; readonly truncated: boolean } {
  const budget = newDiffBudget();
  diff(localValue, remoteValue, '', budget, 0);
  return {
    entries: budget.entries,
    truncated: budget.entries.length > MAX_DIFF_ENTRIES || budget.depthBudgetExhausted || budget.visitBudgetExhausted,
  };
}

/**
 * Re-runs the containment check through `fs.realpath`, catching a symlink that
 * is lexically inside the workspace root but points outside it.
 *
 * `path.resolve` is purely lexical — it does not follow symlinks — so the
 * lexical containment check in {@link resolveLocalSource} passes for such a
 * symlink while opening it would still read arbitrary filesystem content. This
 * resolves the real path of the target and of the workspace root, then compares
 * them, and returns the real absolute path to read.
 *
 * The workspace root is realpath'd too, not just the target: on some hosts the
 * root's own lexical path is a symlink (e.g. macOS's tmpdir under `/var`,
 * symlinked from `/private/var`), and comparing a realpath'd file against a
 * non-realpath'd root would reject every file as "outside" purely from that
 * mismatch. A missing workspace root is a host misconfiguration and propagates
 * as-is; a missing target file is reported as a caller-facing ValidationError
 * (not the raw ENOENT), naming the relative path the caller passed rather than
 * disclosing the resolved absolute location.
 */
async function validateRealpathContainment(
  requestedPath: string,
  lexicalAbsolute: string,
  workspaceRoot: string,
): Promise<string> {
  const realWorkspaceRoot = await fs.realpath(workspaceRoot);

  let realAbsolute: string;
  try {
    realAbsolute = await fs.realpath(lexicalAbsolute);
  } catch (err) {
    const code = (err as NodeJS.ErrnoException).code;
    if (code === 'ENOENT') {
      throw new ValidationError(`check_runbook_drift: runbook_path "${requestedPath}" was not found.`);
    }
    throw err;
  }

  const realRelative = path.relative(realWorkspaceRoot, realAbsolute);
  if (realRelative.startsWith('..') || path.isAbsolute(realRelative)) {
    throw new PathContainmentError(
      `check_runbook_drift: runbook_path resolves (via symlink) outside the workspace root (${workspaceRoot}).`,
    );
  }
  return realAbsolute;
}

/**
 * Resolves `runbook_path` to an absolute path, or throws.
 *
 * The resolved path's content flows straight into the diff output (truncated,
 * but still echoed back to the caller), so this is a read primitive, and it
 * is reachable at AccountOperator tier (see toolContract.ts). `workspaceRoot` is the
 * only boundary available: an absolute `runbook_path` is refused outright,
 * and `path.resolve` collapses any `..` segments before the containment
 * check runs (a raw string check would miss a resolved `..` that escapes the
 * root). The symlink-resolved containment check is factored into
 * {@link validateRealpathContainment}. When `workspaceRoot` is not configured
 * there is no boundary to enforce, so `runbook_path` is refused entirely rather
 * than falling back to an unscoped read of the host's filesystem — the executor
 * runs inside the MCP server Lambda (see ExecutionContext's own doc comment),
 * where an unset `workspaceRoot` is not a "trusted local caller" case to degrade
 * gracefully for, it is the normal case (nothing in this repository sets
 * ASR_WORKSPACE_ROOT on that Lambda). A caller with no workspace configured
 * still has `runbook_yaml` (inline content) available.
 */
async function resolveLocalSource(
  args: CheckRunbookDriftParams,
  context: ExecutionContext,
): Promise<{ content: string; source: 'inline' | 'file'; resolvedPath: string | undefined }> {
  if (args.runbook_yaml) {
    return { content: args.runbook_yaml, source: 'inline', resolvedPath: undefined };
  }
  if (!args.runbook_path) {
    throw new MissingParameterError('check_runbook_drift', 'runbook_path or runbook_yaml');
  }

  if (!context.workspaceRoot) {
    throw new PathContainmentError(
      'check_runbook_drift: runbook_path requires a configured workspace root. Pass runbook_yaml (inline content) instead.',
    );
  }

  const workspaceRoot = path.resolve(context.workspaceRoot);

  if (path.isAbsolute(args.runbook_path)) {
    throw new PathContainmentError(
      'check_runbook_drift: runbook_path must be relative to the workspace root when one is configured.',
    );
  }

  const absolute = path.resolve(workspaceRoot, args.runbook_path);
  const relative = path.relative(workspaceRoot, absolute);
  if (relative.startsWith('..') || path.isAbsolute(relative)) {
    throw new PathContainmentError(
      `check_runbook_drift: runbook_path resolves outside the workspace root (${workspaceRoot}).`,
    );
  }

  const realAbsolute = await validateRealpathContainment(args.runbook_path, absolute, workspaceRoot);
  const content = await fs.readFile(realAbsolute, 'utf8');
  return { content, source: 'file', resolvedPath: realAbsolute };
}

interface RemoteDocument {
  readonly content: string | undefined;
  readonly format: 'YAML' | 'JSON' | 'UNKNOWN';
  readonly latestVersion: string | undefined;
  readonly status: string | undefined;
  readonly missing: boolean;
}

async function fetchRemoteDocument(
  ssm: SSMClient,
  documentName: string,
  localFormat: 'YAML' | 'JSON',
): Promise<RemoteDocument> {
  try {
    const [describeResponse, getDocumentResponse] = await Promise.all([
      ssm.send(new DescribeDocumentCommand({ Name: documentName })),
      ssm.send(new GetDocumentCommand({ Name: documentName, DocumentFormat: localFormat })),
    ]);
    const returnedFormat = getDocumentResponse.DocumentFormat;
    return {
      content: getDocumentResponse.Content,
      format: returnedFormat === 'YAML' || returnedFormat === 'JSON' ? returnedFormat : 'UNKNOWN',
      latestVersion: describeResponse.Document?.LatestVersion,
      status: describeResponse.Document?.Status,
      missing: false,
      // Note: format reflects the *requested* localFormat (SSM converts on fetch),
      // not the document's native storage format. Named `requestedFormat` would be
      // more accurate, but callers only use it for comparison purposes where the
      // requested format is exactly what they need.
    };
  } catch (err) {
    if (isDocumentNotFound(err)) {
      return { content: undefined, format: 'UNKNOWN', latestVersion: undefined, status: undefined, missing: true };
    }
    throw err;
  }
}

function buildResult(
  args: CheckRunbookDriftParams,
  localFormat: 'YAML' | 'JSON',
  source: 'inline' | 'file',
  resolvedPath: string | undefined,
  remote: RemoteDocument,
  isInSync: boolean,
  reason: CheckRunbookDriftResult['reason'],
  structuralDiff: readonly DiffEntry[] = [],
  structuralDiffTruncated = false,
): CheckRunbookDriftResult {
  return {
    documentName: args.document_name,
    isInSync,
    reason,
    localFormat,
    remoteFormat: remote.format,
    remoteLatestVersion: remote.latestVersion,
    remoteStatus: remote.status,
    structuralDiff,
    structuralDiffTruncated,
    localSource: source,
    localPath: resolvedPath,
  };
}

export const checkRunbookDrift: Executor<CheckRunbookDriftParams, CheckRunbookDriftResult> = async (args, context) => {
  const localFormat = args.document_format ?? 'YAML';
  const { content: localContent, source, resolvedPath } = await resolveLocalSource(args, context);

  const ssm = new SSMClient({ region: context.region });
  const remote = await fetchRemoteDocument(ssm, args.document_name, localFormat);

  if (remote.missing || !remote.content) {
    return buildResult(args, localFormat, source, resolvedPath, remote, false, 'missing-remote');
  }

  if (localContent.trim() === remote.content.trim()) {
    return buildResult(args, localFormat, source, resolvedPath, remote, true, 'identical-text');
  }

  const parsedLocal = tryParseDoc(localContent, localFormat);
  const parsedRemoteFormat = remote.format === 'UNKNOWN' ? localFormat : remote.format;
  const parsedRemote = tryParseDoc(remote.content, parsedRemoteFormat);

  // When either side will not parse, fall back to a text-level difference rather than
  // throwing: the documents already differ as text (the identical-text check above failed),
  // and a malformed document is still worth reporting as drift with the offending side
  // flagged, not surfaced as a tool error.
  if (!parsedLocal || !parsedRemote) {
    return buildResult(args, localFormat, source, resolvedPath, remote, false, 'differs', [
      {
        path: '(root)',
        changeType: 'changed',
        local: parsedLocal ? truncate(localContent) : `(not valid ${localFormat}; compared as text)`,
        remote: parsedRemote ? truncate(remote.content) : `(not valid ${parsedRemoteFormat}; compared as text)`,
      },
    ]);
  }

  const { entries: structuralDiff, truncated } = computeStructuralDiff(parsedLocal.value, parsedRemote.value);
  if (structuralDiff.length === 0) {
    return buildResult(args, localFormat, source, resolvedPath, remote, true, 'identical-structure');
  }

  return buildResult(
    args,
    localFormat,
    source,
    resolvedPath,
    remote,
    false,
    'differs',
    structuralDiff.slice(0, MAX_DIFF_ENTRIES),
    truncated,
  );
};
