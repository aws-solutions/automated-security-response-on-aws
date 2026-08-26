#!/usr/bin/env node
// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Purpose: Minimize log output of test runs, to keep AI agents context clean from unnecessary tokens
//
// Filters test runner output (jest/vitest) to keep only:
//   - Failed test suites and their error details
//   - Coverage lines with uncovered line numbers
//   - Final summary lines
//   - TypeScript compiler errors
//
// Usage:
//   some-test-command 2>&1 | node filter-test-output.js
//
// Preserves the exit code of the piped command when used with pipefail.

const readline = require('readline');

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout,
  terminal: false
});

let inCoverage = false;
let inFailureBlock = false;
let coverageHeaderPrinted = false;
let lastLine = '';

// Strip ANSI escape codes
const stripAnsi = (str) => str.replace(/\x1b\[[0-9;]*[a-zA-Z]/g, '').replace(/\x1b\([a-zA-Z]/g, '').replace(/\r/g, '');

rl.on('line', (line) => {
  const clean = stripAnsi(line);

  // Coverage table
  if (/^-+\|/.test(clean)) {
    inCoverage = true;
    coverageHeaderPrinted = false;
    return;
  }

  if (inCoverage) {
    if (!clean.includes('|')) {
      inCoverage = false;
    } else {
      const uncovered = clean.split('|').pop();
      if (/[0-9]/.test(uncovered)) {
        if (!coverageHeaderPrinted) {
          coverageHeaderPrinted = true;
          console.log(lastLine);
        }
        console.log(line);
      }
      lastLine = clean;
      return;
    }
  }

  lastLine = clean;

  // Failure blocks
  if (/FAIL/.test(clean) || /^\s*●/.test(clean)) {
    inFailureBlock = true;
    console.log(clean);
    return;
  }

  if (inFailureBlock) {
    if (/^\s*$/.test(clean)) {
      inFailureBlock = false;
      console.log('');
      return;
    }
    console.log(clean);
    return;
  }

  // Summary lines
  if (/^Test Suites:/.test(clean) || /^Tests:/.test(clean)) {
    console.log(clean);
    return;
  }
  if (/^\s*Test Files/.test(clean)) {
    console.log(clean);
    return;
  }
  if (/^\s+Tests\s/.test(clean) && /(passed|failed)/.test(clean)) {
    console.log(clean);
    return;
  }

  // TypeScript errors
  if (/error TS[0-9]+/.test(clean) || /Found [0-9]+ error/.test(clean)) {
    console.log(clean);
    return;
  }
});
