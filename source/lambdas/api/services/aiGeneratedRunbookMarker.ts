// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import * as yaml from 'js-yaml';

/**
 * Provenance line that AI authoring flows write in a runbook's top-level `description`,
 * the same marker the solution's built-in runbooks carry.
 */
const AI_GENERATED_MARKER_LINE = /^[ \t]*AIGenerated:[ \t]*(?:"true"|'true'|true)[ \t]*$/m;

function parseRunbookYaml(runbookYaml: string): unknown {
  try {
    return yaml.load(runbookYaml);
  } catch {
    return undefined;
  }
}

/**
 * Returns false for unparseable YAML instead of throwing, because provenance is only metrics
 * metadata and must not block register. Deploy reports invalid YAML on its own.
 */
export function isAiGeneratedRunbookYaml(runbookYaml: string): boolean {
  const document = parseRunbookYaml(runbookYaml);
  if (typeof document !== 'object' || document === null || !('description' in document)) {
    return false;
  }
  const { description } = document;
  return typeof description === 'string' && AI_GENERATED_MARKER_LINE.test(description);
}
