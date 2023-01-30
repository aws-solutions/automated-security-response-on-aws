// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { Stack } from 'aws-cdk-lib';
import { Template } from 'aws-cdk-lib/assertions';
import { Bucket } from 'aws-cdk-lib/aws-s3';
import { Construct } from 'constructs';
import overrideLogicalId from './override-logical-id';

describe('override logical id', function () {
  it('sets id to expected value', function () {
    const stack = new Stack();
    const bucket = new Bucket(stack, 'Bucket');
    const myLogicalId = 'MyLogicalId';
    overrideLogicalId(bucket, myLogicalId);
    Template.fromStack(stack).templateMatches({ Resources: { [myLogicalId]: { Type: 'AWS::S3::Bucket' } } });
  });

  it('fails on non-CfnResource', function () {
    const stack = new Stack();
    const construct = new Construct(stack, 'Construct');
    expect(function () {
      overrideLogicalId(construct, 'MyLogicalId');
    }).toThrow();
  });
});
