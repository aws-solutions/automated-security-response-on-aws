// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import * as fs from 'node:fs/promises';
import * as path from 'node:path';
import * as os from 'node:os';
import { mockClient } from 'aws-sdk-client-mock';
import { SSMClient, GetDocumentCommand, DescribeDocumentCommand } from '@aws-sdk/client-ssm';
import { checkRunbookDrift } from '../backends/common/checkRunbookDrift';
import type { ExecutionContext } from '../backends/common/../types';

const ssmMock = mockClient(SSMClient);

function context(overrides: Partial<ExecutionContext> = {}): ExecutionContext {
  return { region: 'us-east-1', requestId: 'test-request', ...overrides };
}

const REMOTE_DOC_YAML = 'schemaVersion: "0.3"\nmainSteps:\n  - name: Step1\n    action: aws:executeAwsApi\n';

beforeEach(() => {
  ssmMock.reset();
});

describe('checkRunbookDrift — path containment', () => {
  let workspaceRoot: string;

  beforeEach(async () => {
    workspaceRoot = await fs.mkdtemp(path.join(os.tmpdir(), 'asr-mcp-drift-test-'));
    await fs.mkdir(path.join(workspaceRoot, 'source', 'remediation_runbooks'), { recursive: true });
    await fs.writeFile(path.join(workspaceRoot, 'source', 'remediation_runbooks', 'Inside.yaml'), REMOTE_DOC_YAML);
    // A file genuinely outside the workspace root, to prove the containment
    // check actually keeps the read inside it rather than merely resolving paths.
    await fs.writeFile(path.join(os.tmpdir(), 'asr-mcp-outside-secret.yaml'), 'top-secret: true\n');
  });

  afterEach(async () => {
    await fs.rm(workspaceRoot, { recursive: true, force: true });
    await fs.rm(path.join(os.tmpdir(), 'asr-mcp-outside-secret.yaml'), { force: true });
  });

  test('a relative path inside the workspace root is read successfully', async () => {
    ssmMock.on(DescribeDocumentCommand).resolves({ Document: { LatestVersion: '1', Status: 'Active' } });
    ssmMock.on(GetDocumentCommand).resolves({ Content: REMOTE_DOC_YAML, DocumentFormat: 'YAML' });

    const result = await checkRunbookDrift(
      { document_name: 'ASR-Test', runbook_path: 'source/remediation_runbooks/Inside.yaml' },
      context({ workspaceRoot }),
    );

    expect(result.isInSync).toBe(true);
    expect(result.localSource).toBe('file');
  });

  test('an absolute runbook_path is refused when workspaceRoot is configured', async () => {
    const outsidePath = path.join(os.tmpdir(), 'asr-mcp-outside-secret.yaml');

    await expect(
      checkRunbookDrift({ document_name: 'ASR-Test', runbook_path: outsidePath }, context({ workspaceRoot })),
    ).rejects.toThrow(/must be relative to the workspace root/);
  });

  test('a "../" escape that resolves outside the workspace root is refused', async () => {
    await expect(
      checkRunbookDrift(
        { document_name: 'ASR-Test', runbook_path: '../asr-mcp-outside-secret.yaml' },
        context({ workspaceRoot }),
      ),
    ).rejects.toThrow(/resolves outside the workspace root/);
  });

  test('containment violations use a specific PathContainmentError, not a generic Error', async () => {
    const outsidePath = path.join(os.tmpdir(), 'asr-mcp-outside-secret.yaml');

    await expect(
      checkRunbookDrift({ document_name: 'ASR-Test', runbook_path: outsidePath }, context({ workspaceRoot })),
    ).rejects.toMatchObject({ name: 'PathContainmentError' });

    await expect(
      checkRunbookDrift(
        { document_name: 'ASR-Test', runbook_path: '../asr-mcp-outside-secret.yaml' },
        context({ workspaceRoot }),
      ),
    ).rejects.toMatchObject({ name: 'PathContainmentError' });
  });

  test('a "../" escape is refused even when heavily nested, once fully resolved', async () => {
    await expect(
      checkRunbookDrift(
        {
          document_name: 'ASR-Test',
          runbook_path: 'source/remediation_runbooks/../../../asr-mcp-outside-secret.yaml',
        },
        context({ workspaceRoot }),
      ),
    ).rejects.toThrow(/resolves outside the workspace root/);
  });

  test('a symlink inside the workspace root pointing outside it is refused, not read', async () => {
    // path.resolve is purely lexical — it never follows symlinks. The lexical
    // path of this symlink is safely inside workspaceRoot, but it points at a
    // file outside it; only resolving through fs.realpath catches this.
    const outsidePath = path.join(os.tmpdir(), 'asr-mcp-outside-secret.yaml');
    const symlinkPath = path.join(workspaceRoot, 'source', 'remediation_runbooks', 'Escape.yaml');
    await fs.symlink(outsidePath, symlinkPath);

    await expect(
      checkRunbookDrift(
        { document_name: 'ASR-Test', runbook_path: 'source/remediation_runbooks/Escape.yaml' },
        context({ workspaceRoot }),
      ),
    ).rejects.toMatchObject({ name: 'PathContainmentError' });
  });

  test('a symlink inside the workspace root pointing to another file inside it is followed normally', async () => {
    const symlinkPath = path.join(workspaceRoot, 'source', 'remediation_runbooks', 'Alias.yaml');
    await fs.symlink(path.join(workspaceRoot, 'source', 'remediation_runbooks', 'Inside.yaml'), symlinkPath);
    ssmMock.on(DescribeDocumentCommand).resolves({ Document: { LatestVersion: '1', Status: 'Active' } });
    ssmMock.on(GetDocumentCommand).resolves({ Content: REMOTE_DOC_YAML, DocumentFormat: 'YAML' });

    const result = await checkRunbookDrift(
      { document_name: 'ASR-Test', runbook_path: 'source/remediation_runbooks/Alias.yaml' },
      context({ workspaceRoot }),
    );

    expect(result.isInSync).toBe(true);
  });

  test('a nonexistent runbook_path reports "not found" without leaking the resolved absolute path', async () => {
    await expect(
      checkRunbookDrift(
        { document_name: 'ASR-Test', runbook_path: 'source/remediation_runbooks/DoesNotExist.yaml' },
        context({ workspaceRoot }),
      ),
    ).rejects.toThrow(
      'check_runbook_drift: runbook_path "source/remediation_runbooks/DoesNotExist.yaml" was not found.',
    );
  });

  test('with no workspaceRoot configured, runbook_path is refused rather than falling back to an unscoped read', async () => {
    const insidePath = path.join(workspaceRoot, 'source', 'remediation_runbooks', 'Inside.yaml');

    await expect(
      checkRunbookDrift({ document_name: 'ASR-Test', runbook_path: insidePath }, context({ workspaceRoot: undefined })),
    ).rejects.toMatchObject({ name: 'PathContainmentError' });
  });
});

describe('checkRunbookDrift — structural diff', () => {
  test('identical text is identical-text, not identical-structure', async () => {
    ssmMock.on(DescribeDocumentCommand).resolves({ Document: { LatestVersion: '1', Status: 'Active' } });
    ssmMock.on(GetDocumentCommand).resolves({ Content: REMOTE_DOC_YAML, DocumentFormat: 'YAML' });

    const result = await checkRunbookDrift({ document_name: 'ASR-Test', runbook_yaml: REMOTE_DOC_YAML }, context());

    expect(result.reason).toBe('identical-text');
    expect(result.isInSync).toBe(true);
    expect(result.structuralDiff).toEqual([]);
  });

  test('same structure with different formatting is identical-structure', async () => {
    ssmMock.on(DescribeDocumentCommand).resolves({ Document: { LatestVersion: '1', Status: 'Active' } });
    ssmMock.on(GetDocumentCommand).resolves({ Content: REMOTE_DOC_YAML, DocumentFormat: 'YAML' });

    // Same document, re-indented — different bytes, same parsed structure.
    const reformatted = 'schemaVersion: "0.3"\nmainSteps:\n    - name: Step1\n      action: aws:executeAwsApi\n';

    const result = await checkRunbookDrift({ document_name: 'ASR-Test', runbook_yaml: reformatted }, context());

    expect(result.reason).toBe('identical-structure');
    expect(result.isInSync).toBe(true);
    expect(result.structuralDiff).toEqual([]);
  });

  test('a changed field is reported as a "changed" entry at the right path', async () => {
    ssmMock.on(DescribeDocumentCommand).resolves({ Document: { LatestVersion: '1', Status: 'Active' } });
    ssmMock.on(GetDocumentCommand).resolves({ Content: REMOTE_DOC_YAML, DocumentFormat: 'YAML' });

    const changed = 'schemaVersion: "0.3"\nmainSteps:\n  - name: StepRenamed\n    action: aws:executeAwsApi\n';

    const result = await checkRunbookDrift({ document_name: 'ASR-Test', runbook_yaml: changed }, context());

    expect(result.reason).toBe('differs');
    expect(result.isInSync).toBe(false);
    expect(result.structuralDiff).toEqual([
      expect.objectContaining({
        path: 'mainSteps[0].name',
        changeType: 'changed',
        local: 'StepRenamed',
        remote: 'Step1',
      }),
    ]);
  });

  // The diff walks two attacker-influenced YAML documents recursively, so it needs
  // a stop condition that does not rely on the input being reasonable.
  //
  // Plain deep nesting is handled upstream of the diff: js-yaml caps parse depth at 100
  // and throws. That parse failure is now caught and degraded to a text-level comparison
  // rather than thrown (a document the parser rejects is reported as drift, not a tool
  // error), so the diff still never sees an over-deep graph. MAX_DIFF_DEPTH stays above
  // the parser's cap so a legal document is never truncated by it.
  test('deeply nested YAML the parser rejects is reported as a text-level difference, not thrown', async () => {
    const deep = (depth: number): string => {
      let doc = 'schemaVersion: "0.3"\nroot:';
      for (let i = 1; i <= depth; i++) doc += `\n${'  '.repeat(i)}a:`;
      return `${doc} leaf\n`;
    };
    ssmMock.on(DescribeDocumentCommand).resolves({ Document: { LatestVersion: '1', Status: 'Active' } });
    ssmMock.on(GetDocumentCommand).resolves({ Content: deep(5000), DocumentFormat: 'YAML' });

    // Must differ from the remote content, or the identical-text short-circuit
    // returns before either side is ever parsed.
    const result = await checkRunbookDrift(
      { document_name: 'ASR-Test', runbook_yaml: deep(5000).replace('leaf', 'other') },
      context(),
    );

    // The local content will not parse (exceeds js-yaml's nesting cap), so it is compared
    // as text and flagged as differing rather than surfacing an unhandled parser error.
    expect(result.isInSync).toBe(false);
    expect(result.reason).toBe('differs');
    expect(JSON.stringify(result.structuralDiff)).toContain('compared as text');
  });

  test('nesting the parser accepts is diffed in full, not truncated by the depth bound', async () => {
    // 90 levels: legal for js-yaml (cap 100), so every level must still be compared.
    const nested = (depth: number, leaf: string): string => {
      let doc = 'schemaVersion: "0.3"\nroot:';
      for (let i = 1; i <= depth; i++) doc += `\n${'  '.repeat(i)}a:`;
      return `${doc} ${leaf}\n`;
    };
    ssmMock.on(DescribeDocumentCommand).resolves({ Document: { LatestVersion: '1', Status: 'Active' } });
    ssmMock.on(GetDocumentCommand).resolves({ Content: nested(90, 'remote'), DocumentFormat: 'YAML' });

    const result = await checkRunbookDrift({ document_name: 'ASR-Test', runbook_yaml: nested(90, 'local') }, context());

    expect(result.reason).toBe('differs');
    // The real leaf change is reported, not a "nesting exceeds" placeholder.
    expect(JSON.stringify(result.structuralDiff)).not.toContain('nesting exceeds');
    expect(result.structuralDiff).toEqual([
      expect.objectContaining({ changeType: 'changed', local: 'local', remote: 'remote' }),
    ]);
  });

  test('a cyclic document (YAML alias) terminates rather than looping forever', async () => {
    // js-yaml resolves an alias into a shared reference, so this is a genuinely
    // cyclic object graph; an unbounded walk never leaves it.
    const cyclic = 'schemaVersion: "0.3"\nroot: &a\n  child: *a\n';
    ssmMock.on(DescribeDocumentCommand).resolves({ Document: { LatestVersion: '1', Status: 'Active' } });
    ssmMock.on(GetDocumentCommand).resolves({ Content: cyclic, DocumentFormat: 'YAML' });

    const result = await checkRunbookDrift(
      { document_name: 'ASR-Test', runbook_yaml: 'schemaVersion: "0.3"\nroot: &b\n  child: *b\n  extra: x\n' },
      context(),
    );

    // Completing at all is the assertion; the depth bound is what makes it finite.
    expect(result.reason).toBeDefined();
  });

  test('two alias-heavy structurally-equal documents complete promptly rather than fanning out exponentially', async () => {
    // The DoS this guards: js-yaml resolves aliases into a shared-reference DAG, so a
    // document that references the same anchor twice per level (`c: [*b, *b]`, `b: [*a, *a]`,
    // …) stays shallow — depth never trips — but a memo-less walk re-descends each shared
    // (local, remote) node at every occurrence, so node visits grow as 2^levels. Both sides
    // are structurally equal, so no diff entry is ever pushed and the entry cap never fires
    // either. Only the visited-pair memo bounds this. A 12-level fixture is ~4096 leaf
    // fan-out paths, which a memo-less walk does not finish in the timeout; the memo collapses
    // it to one visit per distinct pair.
    const aliasHeavy = (leafMarker: string): string => {
      const lines = [`a: &a ["${leafMarker}", "${leafMarker}"]`];
      const names = 'bcdefghijkl'; // 11 more levels → 12 total
      names.split('').forEach((name, index) => {
        const previous = index === 0 ? 'a' : names[index - 1];
        lines.push(`${name}: &${name} [*${previous}, *${previous}]`);
      });
      lines.push(`root: [*${names[names.length - 1]}, *${names[names.length - 1]}]`);
      return `schemaVersion: "0.3"\n${lines.join('\n')}\n`;
    };
    ssmMock.on(DescribeDocumentCommand).resolves({ Document: { LatestVersion: '1', Status: 'Active' } });
    // Reformatted, not changed: re-spacing the arrays parses to the same structure but differs
    // as text, so the identical-text short-circuit cannot fire and the structural walk must run.
    ssmMock.on(GetDocumentCommand).resolves({ Content: aliasHeavy('x').replace(/, /g, ',  '), DocumentFormat: 'YAML' });

    const startedAt = Date.now();
    const result = await checkRunbookDrift({ document_name: 'ASR-Test', runbook_yaml: aliasHeavy('x') }, context());

    expect(Date.now() - startedAt).toBeLessThan(5000);
    expect(result.reason).toBe('identical-structure');
    expect(result.isInSync).toBe(true);
  });

  test('reports a difference between two alias-heavy documents rather than deduping it away', async () => {
    // The memo must not silently equate two unequal documents: it is keyed on the
    // (local, remote) PAIR, not the local node, so a differing leaf is still reported.
    const aliasHeavy = (leafMarker: string): string =>
      `schemaVersion: "0.3"\na: &a ["${leafMarker}", "${leafMarker}"]\nroot: [*a, *a]\n`;
    ssmMock.on(DescribeDocumentCommand).resolves({ Document: { LatestVersion: '1', Status: 'Active' } });
    ssmMock.on(GetDocumentCommand).resolves({ Content: aliasHeavy('remote'), DocumentFormat: 'YAML' });

    const result = await checkRunbookDrift({ document_name: 'ASR-Test', runbook_yaml: aliasHeavy('local') }, context());

    expect(result.reason).toBe('differs');
    expect(result.isInSync).toBe(false);
    expect(result.structuralDiff.length).toBeGreaterThan(0);
    expect(result.structuralDiff.some((entry) => entry.local === 'local' && entry.remote === 'remote')).toBe(true);
  });

  test('the diff stops at the reported entry cap rather than building a huge list first', async () => {
    const wide = (marker: string): string => {
      let doc = 'schemaVersion: "0.3"\n';
      for (let i = 0; i < 500; i++) doc += `key${i}: ${marker}${i}\n`;
      return doc;
    };
    ssmMock.on(DescribeDocumentCommand).resolves({ Document: { LatestVersion: '1', Status: 'Active' } });
    ssmMock.on(GetDocumentCommand).resolves({ Content: wide('remote'), DocumentFormat: 'YAML' });

    const result = await checkRunbookDrift({ document_name: 'ASR-Test', runbook_yaml: wide('local') }, context());

    expect(result.structuralDiff).toHaveLength(100);
  });

  test('a key present only in the local copy is reported as "added"', async () => {
    ssmMock.on(DescribeDocumentCommand).resolves({ Document: { LatestVersion: '1', Status: 'Active' } });
    ssmMock.on(GetDocumentCommand).resolves({ Content: REMOTE_DOC_YAML, DocumentFormat: 'YAML' });

    const withExtraKey =
      'schemaVersion: "0.3"\nmainSteps:\n  - name: Step1\n    action: aws:executeAwsApi\n    timeoutSeconds: 60\n';

    const result = await checkRunbookDrift({ document_name: 'ASR-Test', runbook_yaml: withExtraKey }, context());

    expect(result.reason).toBe('differs');
    expect(result.structuralDiff).toEqual([
      expect.objectContaining({ path: 'mainSteps[0].timeoutSeconds', changeType: 'added', remote: undefined }),
    ]);
  });

  test('a document that does not exist yet in SSM is missing-remote, not an error', async () => {
    ssmMock
      .on(DescribeDocumentCommand)
      .rejects(Object.assign(new Error('does not exist'), { name: 'InvalidDocument' }));
    ssmMock.on(GetDocumentCommand).rejects(Object.assign(new Error('does not exist'), { name: 'InvalidDocument' }));

    const result = await checkRunbookDrift(
      { document_name: 'ASR-DoesNotExist', runbook_yaml: REMOTE_DOC_YAML },
      context(),
    );

    expect(result.reason).toBe('missing-remote');
    expect(result.isInSync).toBe(false);
  });

  test('an unexpected SSM error is not swallowed as missing-remote', async () => {
    ssmMock.on(DescribeDocumentCommand).rejects(Object.assign(new Error('nope'), { name: 'AccessDeniedException' }));
    ssmMock.on(GetDocumentCommand).rejects(Object.assign(new Error('nope'), { name: 'AccessDeniedException' }));

    await expect(
      checkRunbookDrift({ document_name: 'ASR-Test', runbook_yaml: REMOTE_DOC_YAML }, context()),
    ).rejects.toThrow('nope');
  });

  test('requires exactly one of runbook_yaml or runbook_path', async () => {
    await expect(checkRunbookDrift({ document_name: 'ASR-Test' } as never, context())).rejects.toThrow(
      /runbook_path or runbook_yaml is required/,
    );
  });
});

// The result advertises `structuralDiffTruncated` as "True when structuralDiff was cut
// off". Traversal used to stop AT the 100-entry cap, so the report's own
// `length > 100` test could never be true: a document with 100+ real differences was
// silently cut off and reported as complete. Collecting one past the cap is what makes
// the overflow observable.
describe('checkRunbookDrift — truncation is reported, not silently applied', () => {
  /** A document whose parameters differ in `count` places, to force many diff entries. */
  const documentWithParameters = (count: number, valuePrefix: string): string =>
    [
      'schemaVersion: "0.3"',
      'description: drift fixture',
      'assumeRole: "{{ AutomationAssumeRole }}"',
      'parameters:',
      ...Array.from({ length: count }, (_, i) => `  Param${i}:\n    type: String\n    default: "${valuePrefix}${i}"`),
      'mainSteps: []',
    ].join('\n');

  test('flags the diff as truncated when the differences exceed the reported cap', async () => {
    // 150 differing parameters — comfortably past the 100-entry report cap.
    ssmMock.on(DescribeDocumentCommand).resolves({ Document: { LatestVersion: '1', Status: 'Active' } });
    ssmMock
      .on(GetDocumentCommand)
      .resolves({ Content: documentWithParameters(150, 'remote-'), DocumentFormat: 'YAML' });

    const result = await checkRunbookDrift(
      { document_name: 'ASR-Test', runbook_yaml: documentWithParameters(150, 'local-') },
      context(),
    );

    expect(result.isInSync).toBe(false);
    expect(result.structuralDiffTruncated).toBe(true);
    // Still only the first cap-many entries are handed back.
    expect(result.structuralDiff.length).toBe(100);
  });

  test('does not flag truncation for a diff that fits inside the cap', async () => {
    ssmMock.on(DescribeDocumentCommand).resolves({ Document: { LatestVersion: '1', Status: 'Active' } });
    ssmMock.on(GetDocumentCommand).resolves({ Content: documentWithParameters(3, 'remote-'), DocumentFormat: 'YAML' });

    const result = await checkRunbookDrift(
      { document_name: 'ASR-Test', runbook_yaml: documentWithParameters(3, 'local-') },
      context(),
    );

    expect(result.isInSync).toBe(false);
    expect(result.structuralDiffTruncated).toBe(false);
    expect(result.structuralDiff.length).toBeLessThan(100);
  });

  // The depth cut is the case entry-count truncation cannot see: a single narrow
  // chain past MAX_DIFF_DEPTH produces ONE placeholder entry, far under the cap, so
  // structuralDiffTruncated computed from length alone would report the walk as
  // complete. JSON (parsed with JSON.parse, which has no shallow nesting cap like
  // js-yaml's) is the only input that can reach that depth here.
  test('flags truncation when a diff is cut only by the depth bound, not the entry count', async () => {
    const deeplyNested = (depth: number, leaf: string): string => {
      let node = `"${leaf}"`;
      for (let i = 0; i < depth; i++) node = `{"a":${node}}`;
      return `{"root":${node}}`;
    };
    ssmMock.on(DescribeDocumentCommand).resolves({ Document: { LatestVersion: '1', Status: 'Active' } });
    ssmMock.on(GetDocumentCommand).resolves({ Content: deeplyNested(250, 'remote'), DocumentFormat: 'JSON' });

    const result = await checkRunbookDrift(
      { document_name: 'ASR-Test', runbook_yaml: deeplyNested(250, 'local'), document_format: 'JSON' },
      context(),
    );

    expect(result.isInSync).toBe(false);
    // A single placeholder entry — well under the 100-entry cap — yet the walk was
    // cut short, so truncation must still be reported.
    expect(result.structuralDiff.length).toBeLessThan(100);
    expect(result.structuralDiffTruncated).toBe(true);
    expect(JSON.stringify(result.structuralDiff)).toContain('nesting exceeds');
  });
});
