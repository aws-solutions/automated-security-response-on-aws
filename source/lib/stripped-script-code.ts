// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { readFileSync } from 'node:fs';
import { ScriptCode } from '@cdklabs/cdk-ssm-documents';

/**
 * Advance Python string/comment lexer state across one physical line and report whether the line
 * *began* inside a string literal that continues from a previous line.
 *
 * A blank line or a `#`-leading line is only droppable when the line starts outside every string
 * literal; inside a string those characters are data and must be preserved. To carry an accurate
 * "inside a string" state across line boundaries, the scan models all of Python's string forms:
 *  - triple-quoted (`'''`/`"""`) strings, which span lines by design; and
 *  - single-line (`'`/`"`) strings, which normally end at the line but can also span a physical
 *    line boundary via a trailing unescaped backslash (line continuation).
 * A `#` inside any string is data, not a comment, and a `'''`/`"""` sequence inside a normal
 * single-line string is not a triple-quote opener.
 *
 * `carriedString` describes any string open at the start of the line: its `delimiter` (a single
 * quote or a triple quote) and whether it `isTriple`. It is `null` when the line starts in code.
 */
interface OpenString {
  delimiter: string;
  isTriple: boolean;
}

/** One character-scan step while inside a string literal: returns the next index and open state. */
function scanInsideString(line: string, index: number, open: OpenString): { index: number; open: OpenString | null } {
  if (line.startsWith(open.delimiter, index)) {
    return { index: index + open.delimiter.length, open: null };
  }
  // Skip escaped characters so an escaped quote does not falsely close the string.
  return { index: index + (line[index] === '\\' ? 2 : 1), open };
}

/**
 * One character-scan step while outside any string literal: returns the next index and open state,
 * or `null` index to signal a `#` comment (rest of line is ignorable).
 */
function scanOutsideString(line: string, index: number): { index: number | null; open: OpenString | null } {
  const char = line[index];
  // A `#` begins a comment that runs to end of line.
  if (char === '#') {
    return { index: null, open: null };
  }
  // A triple-quote opener must be checked before a single quote so `"""` is not read as `"`.
  if (line.startsWith('"""', index) || line.startsWith("'''", index)) {
    return { index: index + 3, open: { delimiter: line.substring(index, index + 3), isTriple: true } };
  }
  if (char === '"' || char === "'") {
    return { index: index + 1, open: { delimiter: char, isTriple: false } };
  }
  return { index: index + 1, open: null };
}

function advanceStringState(
  line: string,
  carriedString: OpenString | null,
): { startedInString: boolean; openString: OpenString | null } {
  let open: OpenString | null = carriedString;
  let index = 0;

  while (index < line.length) {
    if (open) {
      const step = scanInsideString(line, index, open);
      index = step.index;
      open = step.open;
    } else {
      const step = scanOutsideString(line, index);
      if (step.index === null) {
        break; // `#` comment: nothing after it can open a string
      }
      index = step.index;
      open = step.open ?? open;
    }
  }

  // A single-line string only carries to the next physical line when the line ends inside it with a
  // trailing unescaped backslash (line continuation). Otherwise an unterminated single-line string
  // is a syntax error, so at the boundary only a triple-quoted string can remain open.
  if (open && !open.isTriple && !endsWithLineContinuation(line)) {
    open = null;
  }

  return { startedInString: carriedString !== null, openString: open };
}

/**
 * True when the physical line ends with an unescaped backslash (a Python line continuation). An
 * even number of trailing backslashes means the last one is itself escaped, so the line does not
 * continue.
 */
function endsWithLineContinuation(line: string): boolean {
  let backslashes = 0;
  for (let i = line.length - 1; i >= 0 && line[i] === '\\'; i -= 1) {
    backslashes += 1;
  }
  return backslashes % 2 === 1;
}

/**
 * Strip the leading license/SPDX header block, full-line comments, and blank lines from a Python
 * source string, WITHOUT reflowing any code. Code lines keep their exact text and relative order,
 * so runtime behavior is unchanged and tracebacks stay close to the source. This shrinks the copy
 * embedded inline in an SSM document; the on-disk source file is never modified, so its license
 * header is preserved for attribution scanners.
 *
 * String literals are honored so their data is never altered: a blank line or a `#`-leading line
 * that falls *inside* a string (a `"""`/`'''` block, or a `'`/`"` string continued with a trailing
 * backslash) is string data and is preserved. Only blank lines and full-line comments that occur
 * outside any string literal are removed.
 */
export function stripForInlining(source: string): string {
  // Split on CRLF or LF so a CRLF checkout does not leave a trailing `\r` on every line. A stray
  // `\r` would make endsWithLineContinuation miss a trailing-backslash continuation (the last char
  // is `\r`, not `\`), dropping the string's data lines and corrupting the inlined Python; it would
  // also survive on kept code lines. Rejoining with `\n` yields consistent LF output.
  const lines = source.split(/\r?\n/);
  const kept: string[] = [];
  let inHeaderBlock = true;
  let openString: OpenString | null = null;

  for (const line of lines) {
    const state = advanceStringState(line, openString);
    const startedInString = state.startedInString;
    // Carry any still-open string into the next line before any drop decision.
    openString = state.openString;

    // A line that begins inside a string literal is string data — keep it verbatim,
    // even when it is blank or starts with `#`.
    if (startedInString) {
      kept.push(line);
      continue;
    }

    const trimmed = line.trim();

    // Drop the contiguous leading block of comments/blank lines (the license + SPDX header).
    if (inHeaderBlock) {
      if (trimmed === '' || trimmed.startsWith('#')) {
        continue;
      }
      inHeaderBlock = false;
    }

    // Drop blank lines that are outside any string literal — never semantically significant.
    if (trimmed === '') {
      continue;
    }

    // Drop full-line comments only (a line starting with `#` outside a string). A trailing/inline
    // comment is left intact so we never touch code (splitting on `#` could corrupt a `#` inside
    // a string literal).
    if (trimmed.startsWith('#')) {
      continue;
    }

    kept.push(line);
  }

  return kept.join('\n');
}

/**
 * Drop-in replacement for `ScriptCode.fromFile` that strips the license header and comments from the
 * embedded copy (see {@link stripForInlining}). Keeps the source file untouched.
 */
export function strippedScriptCode(fullPath: string): ScriptCode {
  return ScriptCode.inline(stripForInlining(readFileSync(fullPath, 'utf8')));
}
