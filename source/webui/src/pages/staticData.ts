// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * Static mock data for the Control Panel pages.
 * Used as initial state for local CRUD operations — no API integration.
 */

import { SecurityControl, ResourceFilter } from '@data-models';

const staticControl = (
  controlId: string,
  description: string,
  automatedRemediationEnabled: boolean,
): SecurityControl => ({
  controlId,
  description,
  automatedRemediationEnabled,
  filters: [],
  filterMode: 'include',
  version: 1,
  lastModified: '2024-01-01T00:00:00Z',
  modifiedBy: 'system',
});

export const STATIC_CONTROLS: SecurityControl[] = [
  staticControl('S3.1', 'S3 Block Public Access setting should be enabled', true),
  staticControl('S3.2', 'S3 buckets should prohibit public read access', true),
  staticControl('S3.3', 'S3 buckets should prohibit public write access', false),
  staticControl('S3.4', 'S3 buckets should have server-side encryption enabled', true),
  staticControl('S3.5', 'S3 buckets should require requests to use SSL', true),
  staticControl('S3.6', 'S3 permissions granted to other AWS accounts should be restricted', false),
  staticControl('S3.7', 'S3 buckets should have cross-region replication enabled', true),
  staticControl('S3.8', 'S3 Block Public Access setting should be enabled at the bucket level', true),
  staticControl('EC2.1', 'EBS snapshots should not be publicly restorable', true),
  staticControl('EC2.2', 'VPC default security group should not allow inbound and outbound traffic', true),
  staticControl('EC2.3', 'Attached EBS volumes should be encrypted at rest', false),
  staticControl('EC2.8', 'EC2 instances should use IMDSv2', true),
  staticControl('EC2.9', 'EC2 instances should not have a public IP address', true),
  staticControl('IAM.1', 'IAM policies should not allow full "*" administrative privileges', true),
  staticControl('IAM.2', 'IAM users should not have IAM policies attached', true),
  staticControl('IAM.3', 'IAM users access keys should be rotated every 90 days or less', true),
  staticControl('IAM.4', 'IAM root user access key should not exist', false),
  staticControl('IAM.5', 'MFA should be enabled for all IAM users that have a console password', true),
  staticControl('RDS.1', 'RDS snapshots should be private', true),
  staticControl('RDS.2', 'RDS DB instances should prohibit public access', true),
  staticControl('RDS.3', 'RDS DB instances should have encryption at rest enabled', false),
  staticControl(
    'CloudTrail.1',
    'CloudTrail should be enabled and configured with at least one multi-Region trail',
    true,
  ),
  staticControl('CloudTrail.2', 'CloudTrail should have encryption at rest enabled', true),
  staticControl('Lambda.1', 'Lambda functions should prohibit public access', true),
  staticControl('Lambda.2', 'Lambda functions should use supported runtimes', true),
  staticControl('KMS.1', 'IAM customer managed policies should not allow decryption actions on all KMS keys', true),
  staticControl('KMS.4', 'AWS KMS key rotation should be enabled', true),
  staticControl('ELB.1', 'Application Load Balancer should be configured to redirect all HTTP requests to HTTPS', true),
  staticControl('VPC.1', 'VPC flow logging should be enabled in all VPCs', true),
  staticControl('SNS.1', 'SNS topics should be encrypted at rest using AWS KMS', true),
];

export const STATIC_FILTERS: ResourceFilter[] = [
  {
    filterId: '00000000-0000-4000-8000-000000000001',
    name: 'Production Accounts',
    accountIds: ['123456789012', '234567890123', '345678901234'],
    organizationalUnits: [],
    tags: [{ key: 'Environment', value: 'Production' }],
    arnPatterns: [],
    version: 1,
    createdAt: '2024-01-15T10:30:00Z',
    createdBy: 'system',
    lastModified: '2024-01-15T10:30:00Z',
    modifiedBy: 'system',
  },
  {
    filterId: '00000000-0000-4000-8000-000000000002',
    name: 'Development Environment',
    accountIds: ['456789012345'],
    organizationalUnits: ['ou-dev0-12345abc'],
    tags: [
      { key: 'Environment', value: 'Development' },
      { key: 'Team', value: 'Engineering' },
    ],
    arnPatterns: [],
    version: 1,
    createdAt: '2024-01-20T14:15:00Z',
    createdBy: 'system',
    lastModified: '2024-01-20T14:15:00Z',
    modifiedBy: 'system',
  },
  {
    filterId: '00000000-0000-4000-8000-000000000003',
    name: 'Critical Resources',
    accountIds: [],
    organizationalUnits: [],
    tags: [
      { key: 'Criticality', value: 'High' },
      { key: 'Compliance', value: 'Required' },
    ],
    arnPatterns: ['arn:aws:s3:::*'],
    version: 1,
    createdAt: '2024-02-01T09:00:00Z',
    createdBy: 'system',
    lastModified: '2024-02-01T09:00:00Z',
    modifiedBy: 'system',
  },
  {
    filterId: '00000000-0000-4000-8000-000000000004',
    name: 'Finance OU',
    accountIds: [],
    organizationalUnits: ['ou-fin0-67890abc', 'ou-fina-11111abc'],
    tags: [],
    arnPatterns: [],
    version: 1,
    createdAt: '2024-02-10T11:45:00Z',
    createdBy: 'system',
    lastModified: '2024-02-10T11:45:00Z',
    modifiedBy: 'system',
  },
  {
    filterId: '00000000-0000-4000-8000-000000000005',
    name: 'Test Accounts',
    accountIds: ['567890123456', '678901234567'],
    organizationalUnits: ['ou-test-22222abc'],
    tags: [{ key: 'Environment', value: 'Test' }],
    arnPatterns: [],
    version: 1,
    createdAt: '2024-02-15T16:20:00Z',
    createdBy: 'system',
    lastModified: '2024-02-15T16:20:00Z',
    modifiedBy: 'system',
  },
];
