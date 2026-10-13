// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { stripForInlining } from '../lib/stripped-script-code';

// stripForInlining shrinks the Python copy embedded inline in an SSM document at build time.
// There is no runtime guard on its output, so these tests pin the behavior that would silently
// corrupt an inlined script or change what ships: it must remove only lines Python ignores
// (license header, full-line comments, blank lines) and never touch a line of code.

describe('stripForInlining', () => {
  it('removes the leading license/SPDX header block', () => {
    const source = [
      '# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.',
      '# SPDX-License-Identifier: Apache-2.0',
      'import json',
    ].join('\n');

    const result = stripForInlining(source);

    expect(result).toBe('import json');
  });

  it('removes full-line comments and blank lines from the body', () => {
    const source = ['import json', '', '# a full-line comment', 'x = 1'].join('\n');

    const result = stripForInlining(source);

    expect(result).toBe('import json\nx = 1');
  });

  it('keeps a code line that has a trailing inline comment intact', () => {
    // A trailing comment must not be stripped: splitting on '#' could corrupt code, and the
    // line is still code. Only lines whose first non-whitespace char is '#' are dropped.
    const source = 'x = 1  # keep this trailing comment';

    const result = stripForInlining(source);

    expect(result).toBe('x = 1  # keep this trailing comment');
  });

  it("does not treat a '#' inside a string literal as a comment", () => {
    // The '#' here is data, not a comment. The whole line is code and must survive verbatim.
    const source = "pattern = '^arn:aws:s3:::#bucket'";

    const result = stripForInlining(source);

    expect(result).toBe("pattern = '^arn:aws:s3:::#bucket'");
  });

  it('preserves indentation of code lines (no reflow)', () => {
    const source = ['def f():', '    if True:', '        return 1'].join('\n');

    const result = stripForInlining(source);

    // Indentation is unchanged — the strip never reflows code.
    expect(result).toBe(source);
  });

  it('leaves a script with no header/comments/blank lines unchanged', () => {
    const source = ['import json', 'x = 1'].join('\n');

    expect(stripForInlining(source)).toBe(source);
  });

  it('preserves blank and #-leading lines inside a triple-quoted string literal', () => {
    // Inside a """...""" block a blank line and a #-leading line are string data, not a comment or
    // filler — dropping them would change the string's runtime value. They must survive verbatim.
    const source = [
      '# license header',
      'TEXT = """line one',
      '',
      '# not a comment - string data',
      'line four"""',
      'x = 1',
    ].join('\n');

    const result = stripForInlining(source);

    // Header removed; the string's interior lines (blank + #-leading) kept exactly.
    expect(result).toBe(
      ['TEXT = """line one', '', '# not a comment - string data', 'line four"""', 'x = 1'].join('\n'),
    );
  });

  it('still strips a real comment on the line after a triple-quoted string closes', () => {
    // Once the string closes, a subsequent full-line # comment is a real comment again and is dropped.
    const source = ['TEXT = """data"""', '# real comment', 'y = 2'].join('\n');

    const result = stripForInlining(source);

    expect(result).toBe(['TEXT = """data"""', 'y = 2'].join('\n'));
  });

  it("handles a single-quoted triple string ('''...''') spanning lines", () => {
    const source = ["TEXT = '''a", '', "b'''", 'z = 3'].join('\n');

    const result = stripForInlining(source);

    // The blank line inside the ''' block is string data and is preserved.
    expect(result).toBe(["TEXT = '''a", '', "b'''", 'z = 3'].join('\n'));
  });

  it('does not treat a triple-quote sequence inside a normal string as a multi-line opener', () => {
    // `"'''"` is a normal single-line string whose content is three quotes — it must NOT flip the
    // scanner into multi-line-string mode, or the following blank + comment lines would be wrongly kept.
    const source = ["sep = \"'''\"", '', '# real comment', 'x = 1'].join('\n');

    const result = stripForInlining(source);

    // Not inside a triple string, so the blank line and the real comment are dropped.
    expect(result).toBe(["sep = \"'''\"", 'x = 1'].join('\n'));
  });

  it('does not treat a # inside a single-line string as a comment when a triple-quote opens later', () => {
    // The `#` in the URL is string data (not a comment), so scanning must continue past it and
    // detect the `"""` opener later on the same line — otherwise the docstring body below is
    // mistaken for code/comments and its blank/#-lines are wrongly dropped.
    const source = ['url = "http://x/#frag"; DOC = """body', '', '# inside doc', 'end"""', 'y = 2'].join('\n');

    const result = stripForInlining(source);

    // The `"""` opened on line 1, so lines 2-4 are string data and are preserved verbatim.
    expect(result).toBe(['url = "http://x/#frag"; DOC = """body', '', '# inside doc', 'end"""', 'y = 2'].join('\n'));
  });

  it('carries a single-line string across a backslash line-continuation', () => {
    // A single-line string continued with a trailing backslash spans the physical line boundary,
    // so the second line (#def"...) is string data — its leading # must NOT be read as a comment
    // (dropping it would leave an unterminated string — invalid Python).
    const source = ['x = "abc\\', '#def"', 'y = 1'].join('\n');

    const result = stripForInlining(source);

    expect(result).toBe(['x = "abc\\', '#def"', 'y = 1'].join('\n'));
  });

  it('treats an even trailing-backslash count as not a line continuation', () => {
    // `"abc\\"` ends in an escaped backslash, so the string closes on line 1 (no continuation);
    // the next line's leading # is then a real comment and is dropped.
    const source = ['x = "abc\\\\"', '# real comment', 'y = 1'].join('\n');

    const result = stripForInlining(source);

    expect(result).toBe(['x = "abc\\\\"', 'y = 1'].join('\n'));
  });
});
