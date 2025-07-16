// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { CfnResource, Stack } from 'aws-cdk-lib';
import { Bucket } from 'aws-cdk-lib/aws-s3';
import { addCfnGuardSuppression } from './add-cfn-guard-suppression';

describe('add cfn guard suppression', function () {
  it('adds suppression when none present', function () {
    const stack = new Stack();
    const bucket = new Bucket(stack, 'Bucket');
    const ruleName = 'IAM_NO_INLINE_POLICY_CHECK';
    addCfnGuardSuppression(bucket, 'IAM_NO_INLINE_POLICY_CHECK');
    expect((bucket.node.defaultChild as CfnResource).cfnOptions.metadata?.guard?.SuppressedRules).toStrictEqual(
      expect.arrayContaining([ruleName]),
    );
  });

  it('adds suppression when metadata already exists', function () {
    const stack = new Stack();
    const bucket = new Bucket(stack, 'Bucket');
    const firstSuppression = { id: 'my id', reason: 'my reason' };
    (bucket.node.defaultChild as CfnResource).cfnOptions.metadata = {
      cfn_nag: { rules_to_suppress: [firstSuppression] },
    };
    addCfnGuardSuppression(bucket, 'IAM_NO_INLINE_POLICY_CHECK');
    expect((bucket.node.defaultChild as CfnResource).cfnOptions.metadata?.cfn_nag?.rules_to_suppress).toStrictEqual(
      expect.arrayContaining([firstSuppression]),
    );
    expect((bucket.node.defaultChild as CfnResource).cfnOptions.metadata?.guard?.SuppressedRules).toStrictEqual(
      expect.arrayContaining(['IAM_NO_INLINE_POLICY_CHECK']),
    );
  });
});
