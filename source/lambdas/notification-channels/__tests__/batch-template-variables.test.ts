// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import * as fastCheck from 'fast-check';
import {
  resolveBatchTemplateVariables,
  BatchTemplateVariableContext,
  BATCH_VARIABLE_MAP,
  TEMPLATE_VARIABLE_PATTERN,
} from '../template-variables';

describe('resolveBatchTemplateVariables', () => {
  const context: BatchTemplateVariableContext = {
    configName: 'Production Alerts',
    notificationType: 'finding',
    findingCount: '42',
    remediationCount: '7',
  };

  it('should resolve all batch-level variables', () => {
    // ARRANGE
    const input = '${CONFIG_NAME} | ${NOTIFICATION_TYPE} | ${FINDING_COUNT} | ${REMEDIATION_COUNT}';

    // ACT
    const result = resolveBatchTemplateVariables(input, context);

    // ASSERT
    expect(result).toBe('Production Alerts | finding | 42 | 7');
  });

  it('should preserve single-event variables as literal syntax', () => {
    // ARRANGE
    const input = '${FINDING_ID} | ${CONTROL_ID} | ${SEVERITY} | ${ACCOUNT_ID} | ${REGION} | ${RESOURCE_ARN}';

    // ACT
    const result = resolveBatchTemplateVariables(input, context);

    // ASSERT
    expect(result).toBe('${FINDING_ID} | ${CONTROL_ID} | ${SEVERITY} | ${ACCOUNT_ID} | ${REGION} | ${RESOURCE_ARN}');
  });

  it('should handle mixed batch and non-batch placeholders', () => {
    // ARRANGE
    const input = 'Config: ${CONFIG_NAME}, Type: ${NOTIFICATION_TYPE}, Control: ${CONTROL_ID}, Severity: ${SEVERITY}';

    // ACT
    const result = resolveBatchTemplateVariables(input, context);

    // ASSERT
    expect(result).toBe('Config: Production Alerts, Type: finding, Control: ${CONTROL_ID}, Severity: ${SEVERITY}');
  });

  it('should pass through strings with no placeholders unchanged', () => {
    // ARRANGE
    const input = 'This is a plain string with no template variables';

    // ACT
    const result = resolveBatchTemplateVariables(input, context);

    // ASSERT
    expect(result).toBe('This is a plain string with no template variables');
  });

  it('should preserve completely unknown variables', () => {
    // ARRANGE
    const input = '${TOTALLY_UNKNOWN} and ${ANOTHER_UNKNOWN}';

    // ACT
    const result = resolveBatchTemplateVariables(input, context);

    // ASSERT
    expect(result).toBe('${TOTALLY_UNKNOWN} and ${ANOTHER_UNKNOWN}');
  });

  it('should apply encodeValue to substituted batch values only, preserving literal single-event placeholders', () => {
    // ARRANGE
    const encode = (value: string): string => `<${value}>`;
    const input = '${CONFIG_NAME} | ${FINDING_ID}';

    // ACT
    const result = resolveBatchTemplateVariables(input, context, encode);

    // ASSERT
    expect(result).toBe('<Production Alerts> | ${FINDING_ID}');
  });
});

// Feature: batch-content-notification-adapters, Property 5: Batch template variable resolution preserves unresolvable variables
describe('Batch template variable resolution preserves unresolvable variables', () => {
  const batchVarNames = Object.keys(BATCH_VARIABLE_MAP);
  const singleEventVarNames = ['FINDING_ID', 'CONTROL_ID', 'SEVERITY', 'ACCOUNT_ID', 'REGION', 'RESOURCE_ARN'];

  const batchPlaceholderArb = fastCheck.constantFrom(...batchVarNames).map((name) => `\${${name}}`);
  const singleEventPlaceholderArb = fastCheck.constantFrom(...singleEventVarNames).map((name) => `\${${name}}`);
  const literalTextArb = fastCheck.string({ minLength: 1, maxLength: 20 }).filter((s) => !s.includes('${'));

  const templateSegmentArb = fastCheck.oneof(batchPlaceholderArb, singleEventPlaceholderArb, literalTextArb);
  const templateArb = fastCheck
    .array(templateSegmentArb, { minLength: 1, maxLength: 10 })
    .map((parts) => parts.join(' '));

  const contextArb = fastCheck.record({
    configName: fastCheck.string({ minLength: 1, maxLength: 50 }).filter((s) => !s.includes('${')),
    notificationType: fastCheck.constantFrom('finding', 'remediation'),
    findingCount: fastCheck.nat({ max: 10000 }).map(String),
    remediationCount: fastCheck.nat({ max: 10000 }).map(String),
  });

  it('resolves batch variables and preserves non-batch placeholders', () => {
    fastCheck.assert(
      fastCheck.property(templateArb, contextArb, (template, context) => {
        const result = resolveBatchTemplateVariables(template, context);

        // Batch variables should be resolved (not present as placeholders)
        for (const varName of batchVarNames) {
          const placeholder = `\${${varName}}`;
          if (template.includes(placeholder)) {
            const contextKey = BATCH_VARIABLE_MAP[varName as keyof typeof BATCH_VARIABLE_MAP];
            expect(result).toContain(context[contextKey]);
            expect(result).not.toContain(placeholder);
          }
        }

        // Single-event variables should remain as literal syntax
        for (const varName of singleEventVarNames) {
          const placeholder = `\${${varName}}`;
          if (template.includes(placeholder)) {
            expect(result).toContain(placeholder);
          }
        }

        // No new ${...} placeholders should be introduced
        const outputPlaceholders = result.match(new RegExp(TEMPLATE_VARIABLE_PATTERN.source, 'g')) ?? [];
        const inputPlaceholders = template.match(new RegExp(TEMPLATE_VARIABLE_PATTERN.source, 'g')) ?? [];
        const inputNonBatchPlaceholders = inputPlaceholders.filter((p) => {
          const name = p.slice(2, -1);
          return !batchVarNames.includes(name);
        });
        expect(outputPlaceholders).toEqual(inputNonBatchPlaceholders);
      }),
      { numRuns: 100 },
    );
  });
});
