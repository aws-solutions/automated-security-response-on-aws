// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { CfnCondition, CfnStack, Stack } from 'aws-cdk-lib';
import { Bucket, CfnBucket } from 'aws-cdk-lib/aws-s3';
import { Construct } from 'constructs';
import setCondition from './set-condition';

describe('set condition', function () {
  it('sets condition on a bucket', function () {
    const stack = new Stack();
    const condition = new CfnCondition(stack, 'Condition');
    const bucket = new Bucket(stack, 'Bucket');
    setCondition(bucket, condition);
    expect((bucket.node.defaultChild as CfnBucket).cfnOptions.condition).toBe(condition);
  });

  it('sets condition on a cfn resource', function () {
    const stack = new Stack();
    const condition = new CfnCondition(stack, 'Condition');
    const nestedStack = new CfnStack(stack, 'NestedStack', {
      templateUrl: 'https://example.com',
    });
    setCondition(nestedStack, condition);
    expect(nestedStack.cfnOptions.condition).toBe(condition);
  });

  it('fails if condition already set', function () {
    const stack = new Stack();
    const firstCondition = new CfnCondition(stack, 'FirstCondition');
    const secondCondition = new CfnCondition(stack, 'SecondCondition');
    const bucket = new Bucket(stack, 'Bucket');
    setCondition(bucket, firstCondition);
    expect(function () {
      setCondition(bucket, secondCondition);
    }).toThrow();
  });

  it('fails for non-CfnResource', function () {
    const stack = new Stack();
    const condition = new CfnCondition(stack, 'Condition');
    const construct = new Construct(stack, 'Construct');
    expect(function () {
      setCondition(construct, condition);
    }).toThrow();
  });
});
