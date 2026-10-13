// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { CfnCondition, CfnResource } from 'aws-cdk-lib';
import { IConstruct } from 'constructs';

/**
 * Attaches `condition` to every CloudFormation resource under `root`, leaving any
 * resource that already carries its own condition untouched.
 *
 * Needed for third-party constructs (e.g. `CloudFrontToS3`) that expand into a dozen
 * resources with no single `defaultChild` to gate. `setCondition` handles one resource
 * and throws on a pre-existing condition; here a nested condition is expected — an
 * inner construct may gate a resource on its own feature flag — so the outer condition
 * is only filled in where none is set.
 *
 * Returns the number of resources that were given the condition, so callers can assert
 * a non-empty subtree rather than silently conditioning nothing if a construct's
 * internals change shape.
 */
export function applyConditionToSubtree(root: IConstruct, condition: CfnCondition): number {
  let applied = 0;
  for (const node of root.node.findAll()) {
    if (!CfnResource.isCfnResource(node)) continue;
    if (node.cfnOptions.condition) continue;
    node.cfnOptions.condition = condition;
    applied += 1;
  }
  return applied;
}
