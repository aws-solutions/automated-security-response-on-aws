// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * A Security Hub V2 Coverage finding as delivered to the pre-processor (GuardDuty
 * Foundational Coverage, captured from a live account with identifiers genericized).
 * Coverage findings are class_uid 2003 with compliance.assessments but no
 * compliance.control or compliance.standards, so they match no accepted schema.
 */
export const mockSecurityHubCoverageFinding = {
  activity_id: 2,
  activity_name: 'Update',
  category_name: 'Findings',
  category_uid: 2,
  class_name: 'Compliance Finding',
  class_uid: 2003,
  cloud: {
    account: {
      uid: '123456789012',
    },
    provider: 'AWS',
    region: 'us-east-1',
  },
  compliance: {
    assessments: [
      {
        category: 'Coverage',
        meets_criteria: true,
        name: 'GuardDuty Foundational Coverage',
      },
    ],
    status: 'Pass',
    status_id: 1,
  },
  finding_info: {
    created_time: 1777482308532,
    created_time_dt: '2026-04-29T17:05:08.532Z',
    desc: 'This Coverage finding checks if Amazon GuardDuty is enabled in this account.',
    last_seen_time: 1789662681756,
    last_seen_time_dt: '2026-09-17T16:31:21.756Z',
    modified_time: 1789662681756,
    modified_time_dt: '2026-09-17T16:31:21.756Z',
    title: 'GuardDuty Foundational Coverage Finding',
    types: ['Coverage'],
    uid: '8c4b7f689d35377f5ac8d5f317c620058b54029ee4a56a644e6e88c87ac19a60',
  },
  metadata: {
    product: {
      feature: {
        uid: 'security-hub/Coverage',
      },
      name: 'Security Hub Coverage',
      uid: 'arn:aws:securityhub:us-east-1::productv2/aws/securityhub-coverage',
      vendor_name: 'AWS',
    },
    profiles: ['cloud', 'datetime'],
    uid: '9c61582bf7ff7b62af762d7521dd1a5de9832ff951a6c1130976a3c18d289250',
    version: '1.9.0',
  },
  remediation: {
    desc: 'To enable GuardDuty, see Getting started with GuardDuty in the Amazon GuardDuty User Guide.',
    references: ['https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_settingup.html'],
  },
  resources: [
    {
      cloud_partition: 'aws',
      name: 'GuardDuty',
      owner: {
        account: {
          uid: '123456789012',
        },
      },
      provider: 'AWS',
      region: 'us-east-1',
      tags: [
        {
          name: 'SO0111-ASR-GuardDutyFilter',
          value: '',
        },
      ],
      type: 'AWS::::Account',
      uid: '123456789012',
      uid_alt: 'arn:aws:guardduty:us-east-1:123456789012:detector/00000000000000000000000000000000',
    },
  ],
  severity: 'Informational',
  severity_id: 1,
  status: 'New',
  status_id: 1,
  time: 1789662681756,
  time_dt: '2026-09-17T16:31:21.756Z',
  type_name: 'Compliance Finding: Update',
  type_uid: 200302,
  vendor_attributes: {
    severity: 'Informational',
    severity_id: 1,
  },
};
