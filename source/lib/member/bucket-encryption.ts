// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { StringParameter } from 'aws-cdk-lib/aws-ssm';
import { Construct } from 'constructs';

export interface MemberBucketEncryptionProps {
  readonly solutionId: string;
}

export class MemberBucketEncryption extends Construct {
  constructor(scope: Construct, id: string, props: MemberBucketEncryptionProps) {
    super(scope, id);

    // Create all resource at `scope` scope rather than `this` to maintain logical IDs

    new StringParameter(scope, 'SSMParameterForS3.4EncryptionKeyAlias', {
      description:
        'Parameter to store encryption key alias for the PCI.S3.4/FSBP.S3.4, replace the default value with the KMS Key Alias, other wise the remediation will enable the default AES256 encryption for the bucket.',
      parameterName: `/Solutions/${props.solutionId}/afsbp/1.0.0/S3.4/KmsKeyAlias`,
      stringValue: 'default-s3-encryption',
    });
  }
}
