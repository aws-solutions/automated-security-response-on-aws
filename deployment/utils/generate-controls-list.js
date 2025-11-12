#!/usr/bin/env node
// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * Generate Supported Controls List
 *
 * This script extracts the list of supported security controls from the SC playbook's
 * remediations file and generates a JSON file containing all supported controls.
 *
 * The generated JSON file is used to document which security controls are supported
 * by the solution.
 *
 * Usage:
 *   node generate-controls-list.js <solution-version>
 *
 * Arguments:
 *   solution-version - The version of the solution (e.g., "v1.0.0")
 *
 * Output:
 *   Creates a JSON file at ./global-s3-assets/supported-controls.json containing
 *   the solution version and an array of all supported control IDs.
 */

const fs = require('fs');
const path = require('path');

const solutionVersion = process.argv[2];
if (!solutionVersion) {
  console.error('Error: Solution version argument is required');
  console.error('Usage: node generate-controls-list.js <solution-version>');
  process.exit(1);
}

const remediationsFilePath = path.join(__dirname, '../../source/playbooks/SC/lib/sc_remediations.ts');
const outputFilePath = path.join(__dirname, '../global-s3-assets/supported-controls.json');

const fileContent = fs.readFileSync(remediationsFilePath, 'utf8');

// Look for entries like { control: 'ControlID', ... }
const controlRegex = /{\s*control:\s*'([^']+)/g;
const controls = {solutionVersion: solutionVersion, supportedControls: []};
let match;

while ((match = controlRegex.exec(fileContent)) !== null) {
  controls.supportedControls.push(match[1]);
}

fs.writeFileSync(outputFilePath, JSON.stringify(controls, null, 2));

console.log(`Generated controls list with ${controls.supportedControls.length} controls at ${outputFilePath}`);