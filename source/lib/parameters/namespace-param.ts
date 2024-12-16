// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { CfnParameter } from 'aws-cdk-lib';
import { Construct } from 'constructs';

export const NAMESPACE_REGEX =
  /(?!(^xn--|^sthree-|^sthree-configurator|^amzn-s3-demo-|.+-s3alias|.+--ol-s3|.+.mrap|.+--x-s3$))^[a-z0-9][a-z0-9-]{1,7}[a-z0-9]$/;

export default class NamespaceParam extends Construct {
  public readonly paramId: string;
  public readonly value: string;

  constructor(scope: Construct, id: string) {
    super(scope, id);

    const param = new CfnParameter(this, 'IAM Role Namespace', {
      description:
        'Choose a unique namespace to be added as a suffix to remediation IAM role names. The same namespace should be used in the Member Roles and Member stacks. This string should be unique for each solution deployment.',
      type: 'String',
      maxLength: 9,
      minLength: 3,
      allowedPattern: NAMESPACE_REGEX.source,
      constraintDescription:
        'The Namespace parameter must follow naming restrictions for S3 buckets and have a minimum length of 3 and a maximum length of 9. https://docs.aws.amazon.com/AmazonS3/latest/userguide/bucketnamingrules.html',
    });
    param.overrideLogicalId(`Namespace`);
    this.paramId = param.logicalId;

    this.value = param.valueAsString;
  }
}
