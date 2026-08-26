#!/usr/bin/env node
// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * Generate IaC Template Manifest
 *
 * This script scans a directory of IaC remediation templates, computes SHA-256
 * checksums for each template file, and generates a manifest JSON file.
 *
 * The manifest records each template's S3 key, checksum, control ID, and IaC format.
 * It is consumed by the Custom Resource Lambda during stack CREATE/UPDATE to diff
 * manifests, detect customer modifications, and identify deprecated controls.
 *
 * Usage:
 *   node generate-iac-manifest.js --target <path> --output <path> --version <string>
 *
 * Arguments:
 *   --target   Path to the IaC templates output directory to scan
 *   --output   Path where the manifest JSON file will be written
 *   --version  Solution version string to embed in the manifest
 *
 * Output:
 *   Creates a JSON manifest file at the specified --output path.
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const RECOGNIZED_IAC_FORMATS = ['cloudformation', 'terraform', 'cdk'];

/**
 * Recursively collects all files under a directory.
 * @param {string} dir - Directory to scan
 * @returns {string[]} Array of absolute file paths
 */
function collectFiles(dir) {
  const results = [];
  const entries = fs.readdirSync(dir, { withFileTypes: true });
  for (const entry of entries) {
    const fullPath = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      results.push(...collectFiles(fullPath));
    } else if (entry.isFile()) {
      results.push(fullPath);
    }
  }
  return results;
}

/**
 * Discovers IaC template files under the target directory.
 *
 * Scans for files under recognized {ControlId}/{iacFormat}/ paths.
 * Skips .metadata/ directories and unrecognized second-level subdirectories.
 *
 * @param {string} targetDir - Path to the IaC templates root directory
 * @returns {Array<{controlId: string, iacFormat: string, s3Key: string, filePath: string}>}
 */
function discoverTemplates(targetDir) {
  const templates = [];
  const topLevelEntries = fs.readdirSync(targetDir, { withFileTypes: true });

  for (const controlEntry of topLevelEntries) {
    if (!controlEntry.isDirectory()) continue;
    if (controlEntry.name === '.metadata') continue;

    const controlId = controlEntry.name;
    const controlDir = path.join(targetDir, controlId);
    const secondLevelEntries = fs.readdirSync(controlDir, { withFileTypes: true });

    for (const formatEntry of secondLevelEntries) {
      if (!formatEntry.isDirectory()) continue;
      if (!RECOGNIZED_IAC_FORMATS.includes(formatEntry.name)) continue;

      const iacFormat = formatEntry.name;
      const formatDir = path.join(controlDir, iacFormat);
      const files = collectFiles(formatDir);

      for (const filePath of files) {
        const s3Key = path.relative(targetDir, filePath).split(path.sep).join('/');
        templates.push({ controlId, iacFormat, s3Key, filePath });
      }
    }
  }

  return templates;
}

/**
 * Generates a manifest object for the IaC templates in the target directory.
 *
 * Discovers templates, computes SHA-256 checksums, and assembles the manifest.
 * Does not write to disk.
 *
 * @param {string} targetDir - Path to the IaC templates root directory
 * @param {string} solutionVersion - Solution version string
 * @returns {object} The manifest object
 */
function generateManifest(targetDir, solutionVersion) {
  const discovered = discoverTemplates(targetDir);

  const templates = discovered.map((entry) => {
    const content = fs.readFileSync(entry.filePath);
    const sha256 = crypto.createHash('sha256').update(content).digest('hex');
    return {
      controlId: entry.controlId,
      iacFormat: entry.iacFormat,
      s3Key: entry.s3Key,
      sha256,
    };
  });

  templates.sort((a, b) => a.s3Key.localeCompare(b.s3Key));

  return {
    schemaVersion: '1.0',
    generatedAt: new Date().toISOString(),
    solutionVersion,
    templates,
  };
}

module.exports = { discoverTemplates, generateManifest };

// CLI entry point
if (require.main === module) {
  const args = process.argv.slice(2);

  function getArg(name) {
    const idx = args.indexOf(name);
    return idx !== -1 && idx + 1 < args.length ? args[idx + 1] : undefined;
  }

  const target = getArg('--target');
  const output = getArg('--output');
  const version = getArg('--version');

  if (!target) {
    console.error('Error: --target argument is required');
    process.exit(1);
  }
  if (!output) {
    console.error('Error: --output argument is required');
    process.exit(1);
  }
  if (!version) {
    console.error('Error: --version argument is required');
    process.exit(1);
  }

  const manifest = generateManifest(target, version);

  const outputDir = path.dirname(output);
  fs.mkdirSync(outputDir, { recursive: true });
  fs.writeFileSync(output, JSON.stringify(manifest, null, 2));

  console.log(`Generated manifest with ${manifest.templates.length} templates at ${output}`);
}
