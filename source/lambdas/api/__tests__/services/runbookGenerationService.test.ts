// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * The served authoring guide is assembled from the real bundled files: the
 * path-specific `generation-instructions.md` plus the single-sourced
 * `generation-examples.md` spliced in where the guide's `## Examples` heading
 * stands. These tests read the same files the Lambda ships, so a fragment that
 * fails to splice, or a guide that stops carrying its marker, fails here rather
 * than in a cloud caller's context window.
 */
import * as fs from 'node:fs';
import * as path from 'node:path';
import { RunbookGenerationService } from '../../services/runbookGenerationService';

const INSTRUCTIONS_DIR = path.resolve(__dirname, '../../../mcp-instructions');
const guide = fs.readFileSync(path.join(INSTRUCTIONS_DIR, 'generation-instructions.md'), 'utf-8');
const examples = fs.readFileSync(path.join(INSTRUCTIONS_DIR, 'generation-examples.md'), 'utf-8');

describe('RunbookGenerationService', () => {
  const service = new RunbookGenerationService();

  test('serves one document with the shared examples spliced in place of the marker', async () => {
    // GIVEN the bundled guide carries the include marker, and the fragment exists
    expect(guide).toContain('<!-- include: generation-examples.md -->');
    expect(examples).toContain('<RUNBOOK>');

    // WHEN
    const { rules } = await service.getGenerationContext({ description: 'Enable S3 versioning' });

    // THEN the marker is gone, the four worked examples are present where it was, and
    // the path-specific sections on either side of it survived the splice intact.
    expect(rules).not.toContain('<!-- include:');
    expect(rules.match(/<RUNBOOK>/g)).toHaveLength(4);
    const examplesAt = rules.indexOf('# ASR Runbook Examples');
    expect(examplesAt).toBeGreaterThan(rules.indexOf('## Rules'));
    expect(examplesAt).toBeLessThan(rules.indexOf('## Guardrails'));
    expect(rules).toContain('## Naming Conventions');
  });

  test('carries the fragment byte-for-byte, so its corrections are what cloud callers read', async () => {
    // The fragment is where the shared examples are maintained. Two corrections live only
    // there — the KmsKeyArn alias branch that can never match, and allowedValues for the
    // closed retention-days set — and a splice that re-wrapped or re-encoded the text
    // could reintroduce the stale shapes the old served copy carried.
    //
    // This is the assertion that catches a corrupt splice; the one above does not. The
    // first implementation used a string replacement, and `replace` read the `$'` inside a
    // YAML allowedPattern as "the text after the match", so everything past Example 1's
    // KmsKeyArn was replaced by the tail of the guide. All four <RUNBOOK> tags still
    // counted, because they sit before that point.
    const { rules } = await service.getGenerationContext({ description: 'x' });

    expect(rules).toContain(examples.trimEnd());
  });

  test('returns the caller description unchanged and leaves the split fields unset', async () => {
    const result = await service.getGenerationContext({ description: 'Rotate the access key' });

    expect(result).toEqual({
      rules: expect.any(String),
      examples: undefined,
      guardrails: undefined,
      description: 'Rotate the access key',
    });
  });
});
