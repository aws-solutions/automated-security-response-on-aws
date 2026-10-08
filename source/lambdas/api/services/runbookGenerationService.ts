// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import * as fs from 'node:fs/promises';
import * as path from 'node:path';
import { GenerateRunbookParams, GenerateRunbookResult } from '@asr/data-models';

const INSTRUCTIONS_DIR = path.join(__dirname, '../../mcp-instructions');
const INSTRUCTIONS_PATH = path.join(INSTRUCTIONS_DIR, 'generation-instructions.md');

/**
 * Splice marker for content that is single-sourced with the authoring skill.
 *
 * `generation-instructions.md` is a path-specific guide (managed `deploy_runbook`
 * naming, role provisioning, tool flow), but its worked examples are identical to
 * the skill's and are kept once, in `generation-examples.md` — a byte-identical
 * mirror of `ai-assets/skills/asr-remediation-authoring/references/generation-examples.md`
 * enforced by `test_doc_accuracy.py`. The guide carries this marker where the
 * examples belong and the fragment is spliced in at read time, so a cloud caller
 * sees one document with the examples in their usual place.
 */
const INCLUDE_MARKER = /^<!-- include: ([\w.-]+\.md) -->$/gm;

let cachedInstructions: string | undefined;

/**
 * Resolve every `<!-- include: <file>.md -->` marker in `text` to the named
 * fragment from the instructions directory. A marker whose fragment is missing is
 * an error rather than a silent gap: the marker is the promise that the content
 * ships, and a guide with a hole where its examples should be is worse than a
 * failed tool call.
 */
async function resolveIncludes(text: string): Promise<string> {
  const markers = [...text.matchAll(INCLUDE_MARKER)];
  let resolved = text;
  for (const marker of markers) {
    const fragmentName = marker[1];
    const fragment = await fs.readFile(path.join(INSTRUCTIONS_DIR, fragmentName), 'utf-8');
    // A function replacement, not a string: with a string, `replace` reads `$'`, `$&`
    // and friends as substitution patterns, and the examples contain `]+$'` inside a
    // YAML allowedPattern — which would splice the rest of the guide in at that point
    // and drop everything after it.
    resolved = resolved.replace(marker[0], () => fragment.trimEnd());
  }
  return resolved;
}

/**
 * Reads generation instructions from the bundled filesystem and returns them
 * alongside the user's description so the MCP client can produce a Custom Runbook.
 */
export class RunbookGenerationService {
  /**
   * Returns the static authoring context (rules/examples/guardrails) plus the
   * caller's `description`.
   *
   * The other `GenerateRunbookParams` fields — `control_id`, `service_name`,
   * `dynamic_values`, `guidance` — are intentionally NOT consumed server-side:
   * `generate_runbook` returns authoring context that the IDE model combines
   * with those inputs (which it already holds) when it generates the YAML. They
   * are part of the tool's request contract, not inputs to this server step, so
   * they are accepted-and-passed-through rather than silently dropped.
   */
  async getGenerationContext(params: GenerateRunbookParams): Promise<GenerateRunbookResult> {
    if (!cachedInstructions) {
      cachedInstructions = await resolveIncludes(await fs.readFile(INSTRUCTIONS_PATH, 'utf-8'));
    }
    return {
      rules: cachedInstructions,
      examples: undefined,
      guardrails: undefined,
      description: params.description,
    };
  }
}
