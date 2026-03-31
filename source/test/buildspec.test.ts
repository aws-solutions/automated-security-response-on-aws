// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * Tests for the buildspec.yml shell logic that skips unit tests
 * for cross-partition builds (SKIP_UNIT_TESTS).
 *
 * We extract the actual shell block from buildspec.yml and execute it
 * so the test stays in sync with the real buildspec.
 */

import { execSync } from 'child_process';
import * as fs from 'fs';
import * as path from 'path';
import * as yaml from 'js-yaml';

const BUILDSPEC_PATH = path.resolve(__dirname, '..', '..', 'buildspec.yml');

/** Parse buildspec.yml and return the SKIP_UNIT_TESTS shell block from post_build. */
function parseSkipTestsBlock(): string {
  const raw = fs.readFileSync(BUILDSPEC_PATH, 'utf-8');
  const spec = yaml.load(raw) as {
    phases: {
      post_build: { commands: string[] };
    };
  };

  const block = spec.phases.post_build.commands.find(
    (cmd) => typeof cmd === 'string' && cmd.includes('SKIP_UNIT_TESTS'),
  );
  if (!block) throw new Error('Could not find SKIP_UNIT_TESTS block in buildspec.yml post_build phase');

  return block;
}

/**
 * Run the SKIP_UNIT_TESTS block from buildspec and capture stdout.
 */
function runSkipTestsBlock(awsRegion: string, skipUnitTests: string): string {
  const skipTestsBlock = parseSkipTestsBlock();

  const script = `#!/bin/bash
set -euo pipefail
export AWS_REGION="${awsRegion}"
export SKIP_UNIT_TESTS="${skipUnitTests}"
${skipTestsBlock}
`;
  try {
    return execSync(script, { shell: '/bin/bash', encoding: 'utf-8' });
  } catch (e: unknown) {
    // The block may call docker which won't exist locally — that's fine,
    // we only care about the skip/warning logic paths.
    return (e as { stdout?: string }).stdout ?? '';
  }
}

describe('buildspec.yml — SKIP_UNIT_TESTS logic', () => {
  test('GovCloud region with SKIP_UNIT_TESTS=true prints skip message', () => {
    const output = runSkipTestsBlock('us-gov-west-1', 'true');
    expect(output).toContain('Skipping unit tests for cross-partition build');
  });

  test('GCR region with SKIP_UNIT_TESTS=true prints skip message', () => {
    const output = runSkipTestsBlock('cn-north-1', 'true');
    expect(output).toContain('Skipping unit tests for cross-partition build');
  });

  test('commercial region with SKIP_UNIT_TESTS=true prints warning', () => {
    const output = runSkipTestsBlock('us-east-1', 'true');
    expect(output).toContain('WARNING: SKIP_UNIT_TESTS=true in a COMMERCIAL region');
  });
});
