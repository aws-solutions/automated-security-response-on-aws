// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { resolveTemplateVariables, TemplateVariableContext } from '../template-variables';

describe('resolveTemplateVariables', () => {
  const context: TemplateVariableContext = {
    findingId: 'arn:aws:securityhub:us-east-1:123456789012:finding/abc-def',
    controlId: 'S3.1',
    severity: 'Critical',
    accountId: '123456789012',
    region: 'us-east-1',
    resourceArn: 'arn:aws:s3:::my-bucket',
    configName: 'Production Alerts',
  };

  it('should replace all 7 known variables', () => {
    // ARRANGE
    const input =
      '${FINDING_ID} | ${CONTROL_ID} | ${SEVERITY} | ${ACCOUNT_ID} | ${REGION} | ${RESOURCE_ARN} | ${CONFIG_NAME}';

    // ACT
    const result = resolveTemplateVariables(input, context);

    // ASSERT
    expect(result).toBe(
      'arn:aws:securityhub:us-east-1:123456789012:finding/abc-def | S3.1 | Critical | 123456789012 | us-east-1 | arn:aws:s3:::my-bucket | Production Alerts',
    );
  });

  it('should leave unrecognized variables unchanged', () => {
    // ARRANGE
    const input = '${UNKNOWN} stays and ${ALSO_UNKNOWN} stays';

    // ACT
    const result = resolveTemplateVariables(input, context);

    // ASSERT
    expect(result).toBe('${UNKNOWN} stays and ${ALSO_UNKNOWN} stays');
  });

  it('should pass through values with no variables unchanged', () => {
    // ARRANGE
    const input = 'This is a plain string with no template variables';

    // ACT
    const result = resolveTemplateVariables(input, context);

    // ASSERT
    expect(result).toBe('This is a plain string with no template variables');
  });

  it('should handle multiple variables in one string', () => {
    // ARRANGE
    const input = 'Finding ${CONTROL_ID} with severity ${SEVERITY} in account ${ACCOUNT_ID} (${REGION})';

    // ACT
    const result = resolveTemplateVariables(input, context);

    // ASSERT
    expect(result).toBe('Finding S3.1 with severity Critical in account 123456789012 (us-east-1)');
  });

  it('should be idempotent — resolving twice produces the same result as resolving once', () => {
    // ARRANGE
    const input = 'Control: ${CONTROL_ID}, Account: ${ACCOUNT_ID}, Resource: ${RESOURCE_ARN}';

    // ACT
    const firstPass = resolveTemplateVariables(input, context);
    const secondPass = resolveTemplateVariables(firstPass, context);

    // ASSERT
    expect(secondPass).toBe(firstPass);
  });

  it('should apply encodeValue to substituted values only, leaving literal text and unknown placeholders untouched', () => {
    // ARRANGE
    const encode = (value: string): string => `<${value}>`;
    const input = '[literal] ${CONTROL_ID} and ${UNKNOWN}';

    // ACT
    const result = resolveTemplateVariables(input, context, encode);

    // ASSERT
    expect(result).toBe('[literal] <S3.1> and ${UNKNOWN}');
  });
});
