// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { RunbookFactory } from '../lib/runbook_factory';

describe('RunbookFactory.resolveIncludes', () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'runbook-test-'));
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true });
  });

  test('inlines an include directive', () => {
    const includeFile = path.join(tmpDir, 'helper.py');
    fs.writeFileSync(includeFile, 'def helper():\n    pass\n');

    const script = 'line1\n# %%INCLUDE=helper.py%%\nline3';
    const result = RunbookFactory.resolveIncludes(script, tmpDir);

    expect(result).toContain('def helper():');
    expect(result).not.toContain('%%INCLUDE=');
    expect(result).toContain('line1');
    expect(result).toContain('line3');
  });

  test('strips preceding fmt:off/import/fmt:on block', () => {
    const includeFile = path.join(tmpDir, 'utils.py');
    fs.writeFileSync(includeFile, 'INCLUDED_CONTENT = True\n');

    const script = [
      'import json',
      '# fmt: off',
      'from common.utils import something',
      '# fmt: on',
      '# %%INCLUDE=utils.py%%',
      'rest of script',
    ].join('\n');

    const result = RunbookFactory.resolveIncludes(script, tmpDir);

    expect(result).not.toContain('fmt: off');
    expect(result).not.toContain('from common.utils import');
    expect(result).not.toContain('fmt: on');
    expect(result).toContain('INCLUDED_CONTENT = True');
    expect(result).toContain('import json');
    expect(result).toContain('rest of script');
  });

  test('strips a MULTI-LINE (parenthesized) fmt:off/import/fmt:on block', () => {
    // Regression: black wraps a long single-line import into a parenthesized multi-line form. The
    // strip must handle any number of lines between the fences, or the import survives into the built
    // runbook and fails at Lambda runtime with ModuleNotFoundError: No module named 'common'.
    const includeFile = path.join(tmpDir, 'utils.py');
    fs.writeFileSync(includeFile, 'INCLUDED_CONTENT = True\n');

    const script = [
      'import json',
      '# fmt: off',
      'from common.utils import (',
      '    alpha,',
      '    beta,',
      '    gamma,',
      ')',
      '# fmt: on',
      '# %%INCLUDE=utils.py%%',
      'rest of script',
    ].join('\n');

    const result = RunbookFactory.resolveIncludes(script, tmpDir);

    expect(result).not.toContain('fmt: off');
    expect(result).not.toContain('from common.utils import');
    expect(result).not.toContain('alpha,');
    expect(result).not.toContain('fmt: on');
    expect(result).toContain('INCLUDED_CONTENT = True');
    expect(result).toContain('import json');
    expect(result).toContain('rest of script');
  });

  test('resolves common/ prefix using commonScripts path', () => {
    const commonDir = path.join(tmpDir, 'common');
    fs.mkdirSync(commonDir);
    fs.writeFileSync(path.join(commonDir, 'shared.py'), 'SHARED = 1\n');

    const script = '# %%INCLUDE=common/shared.py%%';
    const result = RunbookFactory.resolveIncludes(script, '/unused', commonDir);

    expect(result).toContain('SHARED = 1');
  });

  test('does not strip unrelated fmt:off comments', () => {
    const includeFile = path.join(tmpDir, 'inc.py');
    fs.writeFileSync(includeFile, 'INCLUDED = True\n');

    const script = ['# fmt: off', 'some_unrelated_code = True', '# fmt: on', '', '# %%INCLUDE=inc.py%%'].join('\n');

    const result = RunbookFactory.resolveIncludes(script, tmpDir);

    // The fmt block should NOT be removed because the middle line isn't a common import
    expect(result).toContain('# fmt: off');
    expect(result).toContain('some_unrelated_code = True');
    expect(result).toContain('# fmt: on');
    expect(result).toContain('INCLUDED = True');
  });

  test('does not strip a distant fmt:off fence that merely contains a common import mid-block', () => {
    // Guard: a stray `# fmt: off` far above the %%INCLUDE, with a `from common` line somewhere inside
    // (but not as the first line of the fence), must NOT cause the whole intervening block to be spliced.
    const includeFile = path.join(tmpDir, 'inc.py');
    fs.writeFileSync(includeFile, 'INCLUDED = True\n');

    const script = [
      '# fmt: off',
      'unrelated_a = 1',
      'from common.helper import thing', // import present, but NOT the first line after fmt:off
      'unrelated_b = 2',
      '# fmt: on',
      '# %%INCLUDE=inc.py%%',
    ].join('\n');

    const result = RunbookFactory.resolveIncludes(script, tmpDir);

    // Nothing in the fence is stripped, because the first non-blank fence line is not a common import.
    expect(result).toContain('unrelated_a = 1');
    expect(result).toContain('unrelated_b = 2');
    expect(result).toContain('from common.helper import thing');
    expect(result).toContain('INCLUDED = True');
  });

  test('trims trailing newline from included content', () => {
    const includeFile = path.join(tmpDir, 'trailing.py');
    fs.writeFileSync(includeFile, 'last_line\n');

    const script = '# %%INCLUDE=trailing.py%%\nnext_line';
    const result = RunbookFactory.resolveIncludes(script, tmpDir);

    // Should not have double newline between included content and next_line
    expect(result).not.toContain('last_line\n\nnext_line');
    expect(result).toContain('last_line\nnext_line');
  });

  test('no include directives returns script unchanged', () => {
    const script = 'line1\nline2\nline3';
    const result = RunbookFactory.resolveIncludes(script, tmpDir);
    expect(result).toBe(script);
  });
});
