// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * Shared metadata for multi-service remediations (Amazon Inspector, Amazon
 * GuardDuty, Amazon Macie, and IAM Access Analyzer).
 *
 * This is the single source of truth for which remediation identifiers are
 * multi-service and, for each, which finding resource types they can act on.
 * Both the Pre-Processor (ingest-time routing/gating) and the API (manual
 * remediation from the Web UI) import from here so the two paths cannot drift.
 *
 * Supported resource types are defined by the ASR v4 design:
 *   - IAM Access Analyzer External Access → S3 buckets, KMS keys
 *   - Amazon Inspector Instance Vulnerability → EC2 instances (SSM-managed)
 *   - Amazon GuardDuty IAM credential compromise → IAM access keys
 *   - Amazon Macie sensitive data → S3 objects
 * Additional resource types (for example Amazon Inspector's Lambda function and
 * ECR container image findings) are intentionally out of scope for this release
 * and must not be routed to these remediations.
 */

/** Remediation identifiers handled by the multi-service (non-Config-control) path. */
export const MULTI_SERVICE_REMEDIATION_IDS: ReadonlySet<string> = new Set<string>([
  'IAMAccessAnalyzer.ExternalAccess',
  'Inspector.InstanceVulnerability',
  'GuardDuty.IAMUser',
  'Macie.SensitiveDataS3Object',
]);

/**
 * Resource types (ASFF form, e.g. `AwsEc2Instance`) each multi-service
 * remediation supports. A finding whose resource type is not listed here for
 * its remediation must not be remediated.
 */
export const REMEDIATION_SUPPORTED_RESOURCE_TYPES: Readonly<Record<string, readonly string[]>> = {
  'IAMAccessAnalyzer.ExternalAccess': ['AwsS3Bucket', 'AwsKmsKey'],
  'Inspector.InstanceVulnerability': ['AwsEc2Instance'],
  'GuardDuty.IAMUser': ['AwsIamAccessKey'],
  'Macie.SensitiveDataS3Object': ['AwsS3Object'],
};

/**
 * Normalizes a finding resource type to ASFF form. AWS CloudFormation form
 * (`AWS::EC2::Instance`) is converted to ASFF form (`AwsEc2Instance`); values
 * already in ASFF form pass through unchanged.
 */
export function normalizeResourceTypeToAsff(resourceType: string): string {
  if (!resourceType.includes('::')) return resourceType;
  return resourceType
    .split('::')
    .map((part) => (/^[A-Z0-9]+$/.test(part) ? part.charAt(0).toUpperCase() + part.slice(1).toLowerCase() : part))
    .join('');
}

/** Whether the given remediation identifier is a multi-service remediation. */
export function isMultiServiceRemediation(remediationId: string): boolean {
  return MULTI_SERVICE_REMEDIATION_IDS.has(remediationId);
}

/** The supported resource types for a remediation, or undefined if it has no resource-type constraint. */
export function getSupportedResourceTypes(remediationId: string): readonly string[] | undefined {
  return REMEDIATION_SUPPORTED_RESOURCE_TYPES[remediationId];
}

/**
 * Whether a finding's resource type is supported by the given remediation.
 *
 * Remediations without a resource-type constraint (Config/Security Hub control
 * remediations, which are not in the map) return `true` — this gate applies
 * only to multi-service remediations. Multi-service remediations require a
 * resource type that is present in their supported list; a missing resource
 * type is treated as unsupported.
 */
export function isResourceTypeSupportedForRemediation(
  remediationId: string,
  resourceType: string | undefined,
): boolean {
  const supported = REMEDIATION_SUPPORTED_RESOURCE_TYPES[remediationId];
  if (!supported) return true;
  if (!resourceType) return false;
  return supported.includes(normalizeResourceTypeToAsff(resourceType));
}
