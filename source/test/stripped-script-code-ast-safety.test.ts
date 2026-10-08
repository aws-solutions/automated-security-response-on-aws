// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import * as path from 'node:path';
import { stripForInlining } from '../lib/stripped-script-code';

// Behavior-safety guarantee for the inline stripper: removing the license header, comments, and
// blank lines must never change what the Python program does. This test exercises the REAL
// stripForInlining (the shipped code, not a re-implementation) and uses `python3.11` — the
// interpreter the solution already requires for its unit tests (see deployment/run-unit-tests.sh)
// — purely as an oracle to compare the Abstract Syntax Tree before and after stripping. If the
// ASTs match, the two sources are the same program, proving the strip only touched non-semantic
// text.

const commonScriptsDir = path.join(__dirname, '..', 'playbooks', 'common');

// The three shared scripts inlined by the SC base control runbook (inherited by NIST/AFSBP).
const inlinedScripts = ['parse_input.py', 'get_input_params.py', 'get_remediation_details.py'];

/** Returns `ast.dump(ast.parse(code))` from python3.11 (a required test-time dependency). */
function pythonAstDump(code: string): string {
  return execFileSync('python3.11', ['-c', 'import ast,sys; print(ast.dump(ast.parse(sys.stdin.read())))'], {
    input: code,
    encoding: 'utf8',
  });
}

describe('stripForInlining preserves the Python AST (behavior safety)', () => {
  it.each(inlinedScripts)('keeps %s AST-identical after stripping', (name) => {
    const source = readFileSync(path.join(commonScriptsDir, name), 'utf8');

    // The stripped output parses (pythonAstDump throws on a syntax error) and is structurally
    // identical to the source.
    expect(pythonAstDump(stripForInlining(source))).toBe(pythonAstDump(source));
  });

  // Adversarial inputs that stress the string-literal lexer. Each must stay AST-identical, proving
  // the strip never removes data lines from inside a string.
  const adversarial: Array<[string, string]> = [
    ['hash-in-string then triple-quote opener', 'url = "http://x/#frag"\nDOC = """body\n\n# inside\nend"""\ny = 1\n'],
    ['backslash line-continuation in a single-line string', 'x = "abc\\\n#def"\ny = 1\n'],
    ['triple-quote sequence inside a normal string', "sep = \"'''\"\n\n# real comment\nx = 1\n"],
    ['docstring containing a blank line and a #-line', 'def f():\n    """d1\n\n    #d2\n    """\n    return 1\n'],
  ];

  it.each(adversarial)('keeps AST identical for: %s', (_label, source) => {
    expect(pythonAstDump(stripForInlining(source))).toBe(pythonAstDump(source));
  });

  // A CRLF checkout (e.g. a contributor with git core.autocrlf=true) must strip to the same program
  // as the LF form. Without up-front line-ending normalization, the trailing `\r` defeats the
  // backslash line-continuation check and the string's data lines get dropped, producing invalid
  // Python. Each adversarial LF source is re-run with CRLF endings and compared to its LF AST.
  it.each(adversarial)('keeps AST identical with CRLF endings for: %s', (_label, lfSource) => {
    const crlfSource = lfSource.replace(/\n/g, '\r\n');
    expect(pythonAstDump(stripForInlining(crlfSource))).toBe(pythonAstDump(lfSource));
  });
});
