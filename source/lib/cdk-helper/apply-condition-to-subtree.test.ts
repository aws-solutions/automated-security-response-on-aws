// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { App, CfnCondition, CfnResource, Fn, Stack } from 'aws-cdk-lib';
import { Bucket, CfnBucket } from 'aws-cdk-lib/aws-s3';
import { Construct } from 'constructs';
import { applyConditionToSubtree } from './apply-condition-to-subtree';

describe('applyConditionToSubtree', () => {
  let stack: Stack;
  let condition: CfnCondition;

  beforeEach(() => {
    stack = new Stack(new App(), 'TestStack');
    condition = new CfnCondition(stack, 'TestCondition', {
      expression: Fn.conditionEquals('yes', 'yes'),
    });
  });

  it('conditions every resource under the root, however deeply nested', () => {
    const root = new Construct(stack, 'Root');
    const bucket = new Bucket(root, 'Bucket');
    const nested = new Bucket(new Construct(root, 'Inner'), 'DeeperBucket');

    expect(applyConditionToSubtree(root, condition)).toBe(2);
    expect((bucket.node.defaultChild as CfnBucket).cfnOptions.condition).toBe(condition);
    expect((nested.node.defaultChild as CfnBucket).cfnOptions.condition).toBe(condition);
  });

  it('leaves a resource that already carries its own condition untouched', () => {
    // A nested construct may gate a resource on its own feature flag, and CloudFormation
    // allows only one condition per resource — the narrower, pre-existing one wins.
    const root = new Construct(stack, 'Root');
    const alreadyGated = new Bucket(root, 'AlreadyGated');
    const ownCondition = new CfnCondition(stack, 'OwnCondition', {
      expression: Fn.conditionEquals('a', 'b'),
    });
    (alreadyGated.node.defaultChild as CfnBucket).cfnOptions.condition = ownCondition;
    const ungated = new Bucket(root, 'Ungated');

    expect(applyConditionToSubtree(root, condition)).toBe(1);
    expect((alreadyGated.node.defaultChild as CfnBucket).cfnOptions.condition).toBe(ownCondition);
    expect((ungated.node.defaultChild as CfnBucket).cfnOptions.condition).toBe(condition);
  });

  it('conditions the root itself when the root is a resource', () => {
    const bucket = new Bucket(stack, 'RootBucket');
    const cfnBucket = bucket.node.defaultChild as CfnBucket;

    expect(applyConditionToSubtree(cfnBucket, condition)).toBe(1);
    expect(cfnBucket.cfnOptions.condition).toBe(condition);
  });

  it('reports zero for a subtree with no resources, so callers can detect a no-op', () => {
    // Guards against a third-party construct changing shape and silently being left
    // unconditioned.
    expect(applyConditionToSubtree(new Construct(stack, 'Empty'), condition)).toBe(0);
  });

  it('ignores constructs that are not CloudFormation resources', () => {
    const root = new Construct(stack, 'Root');
    new Construct(root, 'PlainConstruct');
    const bucket = new Bucket(root, 'Bucket');

    expect(applyConditionToSubtree(root, condition)).toBe(1);
    expect((bucket.node.defaultChild as CfnResource).cfnOptions.condition).toBe(condition);
  });
});
