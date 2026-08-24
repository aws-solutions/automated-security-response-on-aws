// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import * as fs from 'fs';
import * as path from 'path';

const IAC_TEMPLATES_DIR = path.resolve(__dirname, '../../../iac-templates');
const MAX_TEMPLATE_SIZE = 10_000;

function findTemplateFiles(directory: string): string[] {
  const results: string[] = [];

  for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
    const fullPath = path.join(directory, entry.name);
    if (entry.isDirectory()) {
      results.push(...findTemplateFiles(fullPath));
    } else if (entry.isFile() && entry.name.endsWith('.txt')) {
      results.push(fullPath);
    }
  }

  return results;
}

describe('IaC template size guardrail', () => {
  if (!fs.existsSync(IAC_TEMPLATES_DIR)) {
    throw new Error(
      `IaC templates directory not found at "${IAC_TEMPLATES_DIR}". ` +
        'Ensure the project has been built before running this test.',
    );
  }

  const templateFiles = findTemplateFiles(IAC_TEMPLATES_DIR);

  it('finds at least one template file', () => {
    expect(templateFiles.length).toBeGreaterThan(0);
  });

  it.each(templateFiles.map((filePath) => [path.relative(IAC_TEMPLATES_DIR, filePath), filePath]))(
    '%s is within the 10,000 character limit',
    (_relativePath, filePath) => {
      const content = fs.readFileSync(filePath, 'utf-8');
      expect(content.length).toBeLessThanOrEqual(MAX_TEMPLATE_SIZE);
    },
  );
});
