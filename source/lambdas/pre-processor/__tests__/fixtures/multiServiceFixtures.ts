// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/** Shared test fixtures for multi-service OCSF findings used across pre-processor tests */

export const mockVulnerabilityFinding = {
  class_uid: 2002,
  activity_id: 1,
  category_uid: 2,
  type_uid: 200201,
  time: 1672531200,
  severity: 'High',
  cloud: { account: { uid: '123456789012' }, region: 'us-east-1' },
  finding_info: {
    uid: 'inspector-finding-1',
    types: ['Software and Configuration Checks/Vulnerabilities/CVE'],
    title: 'CVE-2024-1234',
  },
  resources: [{ type: 'AWS::EC2::Instance', uid: 'i-abc' }],
  metadata: { product: { name: 'Inspector', uid: 'arn:aws:securityhub:us-east-1::product/aws/inspector' } },
};

export const mockDetectionFinding = {
  class_uid: 2004,
  activity_id: 1,
  category_uid: 2,
  type_uid: 200401,
  time: 1672531200,
  severity: 'High',
  cloud: { account: { uid: '123456789012' }, region: 'us-east-1' },
  finding_info: {
    uid: 'guardduty-finding-1',
    types: ['TTPs/Initial Access/UnauthorizedAccess:IAMUser-ConsoleLoginSuccess.B'],
    title: 'Compromised IAM credentials',
  },
  resources: [{ type: 'AWS::IAM::AccessKey', uid: 'AKIA...' }],
  metadata: { product: { name: 'GuardDuty', uid: 'arn:aws:securityhub:us-east-1::product/aws/guardduty' } },
};

/**
 * Shape of a real IAM Access Analyzer `External Access Granted` finding as
 * delivered to Security Hub. IAA findings reach ASR as ASFF (not OCSF) and
 * do NOT carry a `Compliance` block — IAA findings are not wrapped by a
 * Security Hub managed control. The PreProcessor must accept this shape and
 * route via the multi-service mapping to `IAMAccessAnalyzer.ExternalAccess`.
 */
export const mockIamAccessAnalyzerAsffFinding = {
  SchemaVersion: '2018-10-08',
  Id: 'arn:aws:access-analyzer:us-east-1:123456789012:analyzer/test-analyzer/arn:aws:kms:us-east-1:123456789012:key/00000000-0000-0000-0000-000000000000',
  ProductArn: 'arn:aws:securityhub:us-east-1::product/aws/access-analyzer',
  ProductName: 'IAM Access Analyzer',
  CompanyName: 'AWS',
  Region: 'us-east-1',
  GeneratorId: 'aws/access-analyzer',
  AwsAccountId: '123456789012',
  Types: ['Software and Configuration Checks/AWS Security Best Practices/External Access Granted'],
  CreatedAt: '2026-06-19T18:37:47.247Z',
  UpdatedAt: '2026-06-19T18:37:48.625Z',
  Severity: { Label: 'MEDIUM', Normalized: 40, Product: 40 },
  Title: 'AwsKmsKey/arn:aws:kms:us-east-1:123456789012:key/00000000-0000-0000-0000-000000000000/ allows public access',
  Description:
    'AWS::KMS::Key/arn:aws:kms:us-east-1:123456789012:key/00000000-0000-0000-0000-000000000000/ allows public access',
  ProductFields: {
    ResourceOwnerAccount: '123456789012',
    'aws/securityhub/ProductName': 'IAM Access Analyzer',
  },
  Resources: [
    {
      Partition: 'aws',
      Type: 'AwsKmsKey',
      Id: 'arn:aws:kms:us-east-1:123456789012:key/00000000-0000-0000-0000-000000000000',
    },
  ],
  // Note: no Compliance block — this is the real-world shape that previously
  // caused the PreProcessor's schema-detection step to fail.
  Workflow: { Status: 'NEW' },
  RecordState: 'ACTIVE',
};

/**
 * Account-scoped default product ARN — the ARN any non-AWS-service caller is limited to
 * (a custom/partner integration, or an attacker using BatchImportFindings). It carries a
 * non-empty account id and a non-"aws" owner, so it can never match the reserved
 * arn:<partition>:securityhub:<region>::product/aws/<service> form. Findings carrying it
 * must be dropped, never routed to a multi-service remediation.
 */
export const SPOOFED_DEFAULT_PRODUCT_ARN = 'arn:aws:securityhub:us-east-1:123456789012:product/123456789012/default';

/** GuardDuty-shaped OCSF detection finding whose product uid is the default product ARN. */
export const mockSpoofedGuardDutyDetectionFinding = {
  ...mockDetectionFinding,
  finding_info: { ...mockDetectionFinding.finding_info, uid: 'guardduty-spoof-1' },
  metadata: { product: { name: 'GuardDuty', uid: SPOOFED_DEFAULT_PRODUCT_ARN } },
};

/** IAA-shaped ASFF finding with the default product ARN and no Compliance block. */
export const mockSpoofedIamAccessAnalyzerAsffFinding = {
  ...mockIamAccessAnalyzerAsffFinding,
  Id: 'arn:aws:securityhub:us-east-1:123456789012:finding/iaa-spoof-no-compliance',
  ProductArn: SPOOFED_DEFAULT_PRODUCT_ARN,
};

/**
 * Keystone bypass case (IAA): same as above but ALSO carries a crafted
 * Compliance.SecurityControlId equal to the multi-service remediation id. Before the drop,
 * this fell through to standard SecurityControlId routing and was recorded/remediated as
 * IAMAccessAnalyzer.ExternalAccess. It must now be dropped before reaching that path.
 */
export const mockSpoofedIamAccessAnalyzerAsffFindingWithControlId = {
  ...mockIamAccessAnalyzerAsffFinding,
  Id: 'arn:aws:securityhub:us-east-1:123456789012:finding/iaa-spoof-with-controlid',
  ProductArn: SPOOFED_DEFAULT_PRODUCT_ARN,
  Compliance: { Status: 'FAILED', SecurityControlId: 'IAMAccessAnalyzer.ExternalAccess' },
};

/**
 * Keystone bypass case (GuardDuty via ASFF): a GuardDuty-named ASFF finding with an IAM
 * access key resource, the default product ARN, and a crafted Compliance.SecurityControlId.
 */
export const mockSpoofedGuardDutyAsffFindingWithControlId = {
  SchemaVersion: '2018-10-08',
  Id: 'arn:aws:securityhub:us-east-1:123456789012:finding/guardduty-spoof-with-controlid',
  ProductArn: SPOOFED_DEFAULT_PRODUCT_ARN,
  ProductName: 'GuardDuty',
  CompanyName: 'AWS',
  Region: 'us-east-1',
  GeneratorId: 'arn:aws:guardduty:us-east-1:123456789012:detector/abc',
  AwsAccountId: '123456789012',
  Types: ['TTPs/Initial Access/UnauthorizedAccess:IAMUser-ConsoleLoginSuccess.B'],
  CreatedAt: '2026-06-24T00:00:00.000Z',
  UpdatedAt: '2026-06-24T00:00:00.000Z',
  Severity: { Label: 'HIGH', Normalized: 70 },
  Title: 'Spoofed GuardDuty IAMUser finding',
  Resources: [{ Type: 'AwsIamAccessKey', Id: 'AKIAIOSFODNN7EXAMPLE', Region: 'us-east-1' }],
  Compliance: { Status: 'FAILED', SecurityControlId: 'GuardDuty.IAMUser' },
  Workflow: { Status: 'NEW' },
  RecordState: 'ACTIVE',
};
