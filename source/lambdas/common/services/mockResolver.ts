// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { TemplateResolver, TemplateType } from './iacGuidanceService';

const templates: Record<string, Record<TemplateType, string>> = {
  'S3.1': {
    cloudformation: `AWSTemplateFormatVersion: "2010-09-09"
Description: Enable S3 Block Public Access
Resources:
  S3BlockPublicAccess:
    Type: AWS::S3::Bucket
    Properties:
      PublicAccessBlockConfiguration:
        BlockPublicAcls: true
        BlockPublicPolicy: true
        IgnorePublicAcls: true
        RestrictPublicBuckets: true
`,
    terraform: `resource "aws_s3_bucket_public_access_block" "s3_1_remediation" {
  bucket = aws_s3_bucket.example.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
`,
    cdk: `import * as s3 from "aws-cdk-lib/aws-s3";

const bucket = new s3.Bucket(this, "S3BlockPublicAccess", {
  blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
});
`,
  },
  'IAM.3': {
    cloudformation: `AWSTemplateFormatVersion: "2010-09-09"
Description: Rotate IAM access keys older than 90 days
Resources:
  IAMAccessKeyRotation:
    Type: AWS::Config::ConfigRule
    Properties:
      ConfigRuleName: access-keys-rotated
      Source:
        Owner: AWS
        SourceIdentifier: ACCESS_KEYS_ROTATED
      InputParameters:
        maxAccessKeyAge: 90
`,
    terraform: `resource "aws_config_config_rule" "iam_3_access_keys_rotated" {
  name = "access-keys-rotated"

  source {
    owner             = "AWS"
    source_identifier = "ACCESS_KEYS_ROTATED"
  }

  input_parameters = jsonencode({
    maxAccessKeyAge = "90"
  })
}
`,
    cdk: `import * as config from "aws-cdk-lib/aws-config";

new config.ManagedRule(this, "AccessKeysRotated", {
  identifier: config.ManagedRuleIdentifiers.ACCESS_KEYS_ROTATED,
  inputParameters: { maxAccessKeyAge: 90 },
});
`,
  },
  'EC2.1': {
    cloudformation: `AWSTemplateFormatVersion: "2010-09-09"
Description: Enable EBS default encryption
Resources:
  EBSDefaultEncryption:
    Type: AWS::EC2::EncryptionByDefault
    Properties:
      Enabled: true
`,
    terraform: `resource "aws_ebs_encryption_by_default" "ec2_1_remediation" {
  enabled = true
}
`,
    cdk: `import * as ec2 from "aws-cdk-lib/aws-ec2";

new ec2.CfnEncryptionByDefault(this, "EBSDefaultEncryption", {
  enabled: true,
});
`,
  },
};

export class MockResolver implements TemplateResolver {
  async resolve(sanitizedControlId: string, templateType: TemplateType): Promise<string | undefined> {
    return templates[sanitizedControlId]?.[templateType];
  }
}
