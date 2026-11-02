// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { Effect, PolicyStatement } from 'aws-cdk-lib/aws-iam';

// OCSF status_id for "Suppressed", the value Security Hub v2 stores for ASFF Workflow.Status SUPPRESSED.
const OCSF_SUPPRESSED_STATUS_ID = '3';

// Grants BatchUpdateFindings and denies setting a finding to SUPPRESSED (ASFF v1 and OCSF v2 requests).
export function createSecurityHubFindingUpdateStatements(): PolicyStatement[] {
  return [
    new PolicyStatement({
      effect: Effect.ALLOW,
      actions: ['securityhub:BatchUpdateFindings'],
      resources: ['*'],
    }),
    new PolicyStatement({
      sid: 'DenySuppressingFindingsAsff',
      effect: Effect.DENY,
      actions: ['securityhub:BatchUpdateFindings'],
      resources: ['*'],
      conditions: { StringEquals: { 'securityhub:ASFFSyntaxPath/Workflow.Status': 'SUPPRESSED' } },
    }),
    new PolicyStatement({
      sid: 'DenySuppressingFindingsOcsf',
      effect: Effect.DENY,
      actions: ['securityhub:BatchUpdateFindings'],
      resources: ['*'],
      conditions: { StringEquals: { 'securityhub:OCSFSyntaxPath/StatusId': OCSF_SUPPRESSED_STATUS_ID } },
    }),
  ];
}
