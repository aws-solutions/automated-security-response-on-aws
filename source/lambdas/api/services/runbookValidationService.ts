// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import * as fs from 'node:fs/promises';
import * as path from 'node:path';

const VALIDATION_RULES_PATH = path.join(__dirname, '../../mcp-instructions/validation-rules.md');

let cachedRules: string | undefined;

/**
 * Reads validation rules from the bundled filesystem so the MCP client can
 * validate a Custom Runbook against ASR guardrails and SSM schema rules.
 */
export class RunbookValidationService {
  async getValidationInstructions(): Promise<string> {
    if (!cachedRules) {
      cachedRules = await fs.readFile(VALIDATION_RULES_PATH, 'utf-8');
    }
    return cachedRules;
  }
}
