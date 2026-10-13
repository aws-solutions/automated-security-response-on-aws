// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { ASFFFinding, ConfigId, FindingId, ResolvedFindingType } from '@asr/data-models';
import { AwsSecurityFinding, WorkflowStatus } from '@aws-sdk/client-securityhub';

/** Cast a string to FindingId for use in tests */
export const asFindingId = (id: string): FindingId => id as FindingId;

/** Cast a string to ConfigId for use in tests */
export const asConfigId = (id: string): ConfigId => id as ConfigId;

/** Cast a string to ResolvedFindingType for use in tests. Production code must obtain the value
 * from `resolveFindingType` or `resolveControlId`, which are the only places that brand it. */
export const asResolvedFindingType = (findingType: string): ResolvedFindingType => findingType as ResolvedFindingType;

/** Shape an ASFF test finding as a Security Hub CSPM GetFindings result, optionally overriding its workflow status. */
export const asSecurityHubCspmFinding = (
  finding: ASFFFinding,
  workflowStatus: WorkflowStatus | undefined = finding.Workflow?.Status,
): AwsSecurityFinding => ({
  SchemaVersion: finding.SchemaVersion,
  Id: finding.Id,
  ProductArn: finding.ProductArn,
  GeneratorId: finding.GeneratorId,
  AwsAccountId: finding.AwsAccountId,
  CreatedAt: finding.CreatedAt,
  UpdatedAt: finding.UpdatedAt,
  Title: finding.Title,
  Description: finding.Description ?? '',
  Resources: finding.Resources.map((resource) => ({ Type: resource.Type, Id: resource.Id })),
  Workflow: { Status: workflowStatus },
});
