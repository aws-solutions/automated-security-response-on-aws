// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * Names that other components resolve as literals rather than by CloudFormation reference, so
 * they must use the DEV-stripped prefix. They live here rather than inline in the CDK app entry
 * point so the production wiring and the regression tests derive them from one expression.
 */

export function buildStatusTopicName(resourceNamePrefix: string): string {
  return `${resourceNamePrefix}-ASR_Topic`;
}

export function buildOrchestratorLogGroupName(resourceNamePrefix: string): string {
  return `${resourceNamePrefix}-ASR-Orchestrator`;
}

/** The Region suffix keeps this account-global IAM name unique when the member stack deploys to several Regions. */
export function buildEventProcessorRoleName(resourceNamePrefix: string, region: string): string {
  return `${resourceNamePrefix}-ASR-EventProcessor-${region}`;
}

/** Matches every member EventProcessor role name, for the hub Action Log writer role trust. */
export function buildEventProcessorRoleNamePattern(resourceNamePrefix: string): string {
  return buildEventProcessorRoleName(resourceNamePrefix, '*');
}
