// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * Exhaustive coverage guard for IaC-supported remediations.
 *
 * For every control that ships an IaC template, this verifies that each
 * placeholder token (`{token}`) embedded in the template is declared in
 * CONTROL_PLACEHOLDER_MAPPINGS for that control. If a template introduces a new
 * `{token}` without a corresponding mapping, the rendered snippet would contain
 * placeholders" scenario asserts per-finding, validated here for all controls.
 */
import * as fs from 'fs';
import * as path from 'path';
import { CONTROL_PLACEHOLDER_MAPPINGS } from '../../services/controlPlaceholderMappings';

const IAC_TEMPLATES_DIR = path.resolve(__dirname, '../../../../iac-templates');

/**
 * Token-extraction regex mirroring the Hydra integration assertion:
 * matches `{word}` not preceded by `#` (ALB `#{host}`) or `$` (CFN/Terraform
 * `${...}` interpolation), with a 2+ char identifier.
 */
const PLACEHOLDER_REGEX = /(?<!#)(?<!\$)\{([a-zA-Z][a-zA-Z0-9]+)\}/g;

/** CloudFormation intrinsic names that can appear as `{...}` but are not ASR placeholders. */
const CFN_INTRINSICS = new Set(['Ref', 'Fn', 'Sub', 'GetAtt', 'Join', 'Select', 'If', 'Condition']);

function listControlDirs(): string[] {
  return fs
    .readdirSync(IAC_TEMPLATES_DIR, { withFileTypes: true })
    .filter((e) => e.isDirectory())
    .map((e) => e.name)
    .sort();
}

function templateFilesForControl(controlId: string): string[] {
  const controlDir = path.join(IAC_TEMPLATES_DIR, controlId);
  const results: string[] = [];
  const walk = (dir: string): void => {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) walk(full);
      else if (entry.isFile() && entry.name.endsWith('.txt')) results.push(full);
    }
  };
  walk(controlDir);
  return results;
}

function extractPlaceholders(content: string): Set<string> {
  const tokens = new Set<string>();
  for (const match of content.matchAll(PLACEHOLDER_REGEX)) {
    const token = match[1];
    if (!CFN_INTRINSICS.has(token)) tokens.add(token);
  }
  return tokens;
}

describe('IaC template placeholder coverage', () => {
  const controlDirs = listControlDirs();

  it('discovers IaC-supported controls', () => {
    expect(controlDirs.length).toBeGreaterThan(0);
  });

  it.each(controlDirs)('%s: every template placeholder has a mapping', (controlId) => {
    const mappedPlaceholders = new Set((CONTROL_PLACEHOLDER_MAPPINGS[controlId] ?? []).map((m) => m.placeholder));

    const templateFiles = templateFilesForControl(controlId);
    const unmapped = new Set<string>();

    for (const file of templateFiles) {
      const content = fs.readFileSync(file, 'utf-8');
      for (const token of extractPlaceholders(content)) {
        if (!mappedPlaceholders.has(token)) unmapped.add(token);
      }
    }

    expect({ controlId, unmapped: [...unmapped] }).toEqual({ controlId, unmapped: [] });
  });

  it('every placeholder mapping corresponds to an existing control directory', () => {
    const controlSet = new Set(controlDirs);
    const orphanMappings = Object.keys(CONTROL_PLACEHOLDER_MAPPINGS).filter((c) => !controlSet.has(c));
    expect(orphanMappings).toEqual([]);
  });
});
