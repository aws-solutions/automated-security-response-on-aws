// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import { Effect, IRole, Policy, PolicyStatement } from 'aws-cdk-lib/aws-iam';
import setCondition from './set-condition';

const IS_COMMERCIAL_PARTITION_CONDITION_ID = 'IsCommercialPartition';

/**
 * Returns the stack-level `CfnCondition` that is true in the aws (commercial)
 * partition and false in aws-us-gov and aws-cn. Attach it via
 * `cfnOptions.condition` (or the `setCondition` helper) to IAM policy resources
 * that grant actions available only in commercial — for example
 * `securityhub:DescribeSecurityHubV2`, which does not exist in GovCloud or
 * China. Without the gate, CloudFormation rejects the policy at CREATE in
 * those partitions and the whole admin stack rolls back.
 *
 * The condition is created once per stack and reused on every call, so every
 * caller references the same `IsCommercialPartition` CFN logical id. The
 * `instanceof` guard on the lookup is defensive — if another construct ever
 * registers a different child under this id, the function creates a fresh
 * condition rather than silently returning the wrong type.
 */
export function getOrCreateIsCommercialPartitionCondition(scope: Construct): cdk.CfnCondition {
  const stack = cdk.Stack.of(scope);
  const existing = stack.node.tryFindChild(IS_COMMERCIAL_PARTITION_CONDITION_ID);
  if (existing instanceof cdk.CfnCondition) {
    return existing;
  }
  return new cdk.CfnCondition(stack, IS_COMMERCIAL_PARTITION_CONDITION_ID, {
    expression: cdk.Fn.conditionEquals(stack.partition, 'aws'),
  });
}

/**
 * Grants `securityhub:DescribeSecurityHubV2` to `role` as its own policy, gated on the
 * commercial partition, and returns that policy.
 *
 * The grant cannot live in an inline policy on the role: a CFN condition applies to a whole
 * resource, so gating an inline statement would gate the role itself. It is a separate
 * `AWS::IAM::Policy` for that reason.
 *
 * `id` is supplied by the caller and forms the resource's logical id, so each caller keeps the
 * one it already deploys under.
 *
 * `role` is typed as possibly undefined because the Lambda callers read `Function.role`, which
 * CDK types as optional even where it auto-creates one. The throw turns a silently unattached
 * policy — the stack would then deploy without the grant — into a synth failure.
 */
export function attachCommercialPartitionSecurityHubV2Policy(
  scope: Construct,
  id: string,
  role: IRole | undefined,
): Policy {
  if (!role) {
    throw new Error(`${id}: expected an execution role to attach the Security Hub V2 policy to`);
  }

  const policy = new Policy(scope, id, {
    statements: [
      new PolicyStatement({
        effect: Effect.ALLOW,
        actions: ['securityhub:DescribeSecurityHubV2'],
        resources: ['*'],
      }),
    ],
  });
  policy.attachToRole(role);
  setCondition(policy, getOrCreateIsCommercialPartitionCondition(scope));

  return policy;
}
