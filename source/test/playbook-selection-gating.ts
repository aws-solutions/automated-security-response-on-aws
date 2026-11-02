// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { Template } from 'aws-cdk-lib/assertions';

interface PlaybookSelectionGatingExpectation {
  readonly securityControlParameter: string;
  readonly standardPlaybookParameters: string[];
  readonly gatedNestedStackPrefixes: string[];
}

interface SynthesizedResource {
  readonly DependsOn?: string[];
  readonly Properties?: Record<string, unknown>;
}

/**
 * Asserts that a stack validates its playbook selection before creating the nested stacks whose logical IDs start
 * with a listed prefix. A prefix that matches no nested stack fails, so a renamed stack cannot silently escape.
 */
export function expectPlaybookSelectionValidated(
  template: Template,
  expectation: PlaybookSelectionGatingExpectation,
): void {
  const validators: Record<string, SynthesizedResource> = template.findResources('Custom::PlaybookSelectionValidator');
  const validatorLogicalIds = Object.keys(validators);
  expect(validatorLogicalIds).toHaveLength(1);
  const [validatorLogicalId] = validatorLogicalIds;
  expect(validators[validatorLogicalId].Properties?.SecurityControlPlaybookSelected).toEqual({
    Ref: expectation.securityControlParameter,
  });

  const rulesJson = JSON.stringify(template.toJSON().Rules);
  [expectation.securityControlParameter, ...expectation.standardPlaybookParameters].forEach((parameter) => {
    expect(rulesJson).toContain(`{"Ref":"${parameter}"}`);
  });

  const nestedStacks: Record<string, SynthesizedResource> = template.findResources('AWS::CloudFormation::Stack');
  const gatedNestedStackLogicalIds = Object.keys(nestedStacks).filter((logicalId) =>
    expectation.gatedNestedStackPrefixes.some((prefix) => logicalId.startsWith(prefix)),
  );
  const unmatchedPrefixes = expectation.gatedNestedStackPrefixes.filter(
    (prefix) => !gatedNestedStackLogicalIds.some((logicalId) => logicalId.startsWith(prefix)),
  );
  const ungatedNestedStacks = gatedNestedStackLogicalIds.filter(
    (logicalId) => !(nestedStacks[logicalId].DependsOn ?? []).includes(validatorLogicalId),
  );
  expect({ unmatchedPrefixes, ungatedNestedStacks }).toEqual({ unmatchedPrefixes: [], ungatedNestedStacks: [] });
}
