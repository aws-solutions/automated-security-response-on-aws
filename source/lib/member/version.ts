// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { StringParameter } from 'aws-cdk-lib/aws-ssm';
import { Construct } from 'constructs';

export interface MemberVersionProps {
  readonly solutionId: string;
  readonly solutionVersion: string;
}

export class MemberVersion extends Construct {
  constructor(scope: Construct, id: string, props: MemberVersionProps) {
    super(scope, id);

    // Create all resource at `scope` scope rather than `this` to maintain logical IDs

    new StringParameter(scope, 'SHARR Member Version', {
      description: 'Version of the AWS Security Hub Automated Response and Remediation solution',
      parameterName: `/Solutions/${props.solutionId}/member-version`,
      stringValue: props.solutionVersion,
    });
  }
}
