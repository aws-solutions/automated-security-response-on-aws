// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { Template } from 'aws-cdk-lib/assertions';

/**
 * IAM actions registered only in the aws partition. CloudFormation rejects a policy granting
 * one at CREATE in aws-us-gov and aws-cn and rolls the whole stack back, so every grant must
 * sit on a resource gated by the commercial-partition condition.
 */
const COMMERCIAL_ONLY_IAM_ACTIONS = ['securityhub:DescribeSecurityHubV2'];

const COMMERCIAL_PARTITION_CONDITION = 'IsCommercialPartition';

interface TemplateResource {
  Condition?: string;
  DependsOn?: string | string[];
}

/**
 * Asserts that no resource in `template` grants a commercial-only IAM action outside the
 * commercial-partition condition.
 *
 * Swept over every synthesized resource rather than asserted on named call sites: a named-site
 * check cannot fail for a grant it does not enumerate, and the snapshot records whatever the
 * template emits, so neither catches a newly added ungated grant.
 *
 * Shared so every stack that can carry one of these grants is held to the invariant. Any stack
 * deployed outside commercial is subject to the same rollback, and a sweep that covers only one
 * of them leaves the others unguarded.
 */
export function expectNoUngatedCommercialOnlyGrants(template: Template): void {
  const resources: Record<string, TemplateResource> = template.toJSON().Resources;

  const granting = Object.entries(resources).filter(([, resource]) =>
    COMMERCIAL_ONLY_IAM_ACTIONS.some((action) => JSON.stringify(resource).includes(action)),
  );

  // Non-empty guard: if the actions are ever renamed or the grants move out of the stack under
  // test, the filter would match nothing and the assertion below would pass vacuously,
  // reporting a gate that no longer exists.
  expect(granting.length).toBeGreaterThan(0);

  const ungated = granting
    .filter(([, resource]) => resource.Condition !== COMMERCIAL_PARTITION_CONDITION)
    .map(([logicalId]) => logicalId);

  expect(ungated).toEqual([]);
}

/**
 * Asserts that no ungated resource or output depends on, `Ref`s, `Fn::GetAtt`s or `Fn::Sub`s a
 * commercial-partition-gated resource. Otherwise CreateStack fails with "Unresolved resource
 * dependencies" in aws-us-gov and aws-cn. A reference under an `Fn::If` on the same condition is gated.
 */
export function expectNoUngatedReferencesToCommercialPartitionGatedResources(template: Template): void {
  const templateJson = template.toJSON();
  const resources: Record<string, TemplateResource> = templateJson.Resources;
  const outputs: Record<string, TemplateResource> = templateJson.Outputs ?? {};
  const gatedLogicalIds = new Set(
    Object.entries(resources)
      .filter(([, resource]) => resource.Condition === COMMERCIAL_PARTITION_CONDITION)
      .map(([logicalId]) => logicalId),
  );

  // Non-empty guard: with no gated resource in the stack, the sweep below would pass vacuously.
  expect(gatedLogicalIds.size).toBeGreaterThan(0);

  const ungatedOwners = [...Object.entries(resources), ...Object.entries(outputs)].filter(
    ([, owner]) => owner.Condition !== COMMERCIAL_PARTITION_CONDITION,
  );
  const violations = ungatedOwners.flatMap(([logicalId, owner]) =>
    [...[owner.DependsOn ?? []].flat(), ...collectUngatedReferences(owner)]
      .filter((referencedLogicalId) => gatedLogicalIds.has(referencedLogicalId))
      .map((referencedLogicalId) => `${logicalId} -> ${referencedLogicalId}`),
  );

  expect(violations).toEqual([]);
}

/** Returns the logical ids referenced in `node`, skipping the true branch of a commercial-partition `Fn::If`. */
function collectUngatedReferences(node: unknown): string[] {
  if (Array.isArray(node)) {
    return node.flatMap(collectUngatedReferences);
  }
  if (typeof node !== 'object' || node === null) {
    return [];
  }

  const entries = Object.entries(node);
  return entries.flatMap(([key, value]): string[] => {
    if (key === 'Ref' && typeof value === 'string') {
      return [value];
    }
    if (key === 'Fn::GetAtt') {
      const target = Array.isArray(value) ? value[0] : value;
      return typeof target === 'string' ? [target.split('.')[0]] : [];
    }
    if (key === 'Fn::Sub') {
      const [pattern, variables] = Array.isArray(value) ? value : [value, {}];
      const patternReferences =
        typeof pattern === 'string' ? [...pattern.matchAll(/\$\{([^!}][^}.]*)/g)].map((match) => match[1]) : [];
      return [...patternReferences, ...collectUngatedReferences(variables)];
    }
    if (key === 'Fn::If' && Array.isArray(value) && value[0] === COMMERCIAL_PARTITION_CONDITION) {
      return collectUngatedReferences(value[2]);
    }
    return collectUngatedReferences(value);
  });
}
