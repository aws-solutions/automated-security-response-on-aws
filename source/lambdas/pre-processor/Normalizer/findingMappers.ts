// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import {
  ASFFFinding,
  OCSFComplianceFinding,
  OCSFVulnerabilityFinding,
  OCSFDetectionFinding,
  OCSFDataSecurityFinding,
  NormalizedFinding,
  NormalizedResource,
  ASFFSeverity,
  ASFFComplianceStatus,
  ASFFRecordState,
  ASFFWorkflowStatus,
} from '@asr/data-models';
import { FindingTypeMapping } from '../findingTypeMapper';
import { Clock, getClock } from '../../common/utils/clock';
import { getControlIdFromFindingId } from '../../common/utils/findingUtils';

/**
 * Maps a validated ASFF finding to NormalizedFinding.
 *
 * Compliance-first (different from `resolveControlId` in findingUtils): the
 * output feeds `getRemediationIdentifier` → remediation config lookup, which
 * is keyed on the bare control id (`S3.1`). ARN fallback only handles
 * multi-service ASFF findings (e.g. IAA) whose value the caller re-stamps
 * immediately after.
 */
export function asffToNormalized(finding: ASFFFinding): NormalizedFinding {
  const controlIdFromArn = getControlIdFromFindingId(finding.Id);
  const securityControlId = finding.Compliance?.SecurityControlId ?? controlIdFromArn ?? '';
  return {
    id: finding.Id,
    productArn: finding.ProductArn,
    findingTypeIdentifier: {
      type: 'securityControl',
      value: securityControlId,
    },
    accountId: finding.AwsAccountId,
    region: finding.Region ?? 'us-east-1',
    severity: (finding.Severity?.Label as ASFFSeverity) ?? 'INFORMATIONAL',
    complianceStatus: (finding.Compliance?.Status as ASFFComplianceStatus) ?? 'NOT_AVAILABLE',
    recordState: (finding.RecordState as ASFFRecordState) ?? 'ACTIVE',
    workflowStatus: (finding.Workflow?.Status as ASFFWorkflowStatus) ?? 'NEW',
    resources: finding.Resources.map(
      (r): NormalizedResource => ({
        type: r.Type,
        id: r.Id,
        region: r.Region,
        tags: r.Tags,
        details: r.Details,
      }),
    ),
    title: finding.Title,
    description: finding.Description ?? '',
    createdAt: finding.CreatedAt,
    updatedAt: finding.UpdatedAt,
    firstObservedAt: finding.FirstObservedAt,
    productFields: finding.ProductFields,
    format: 'ASFF',
    raw: finding as unknown as Record<string, unknown>,
  };
}

/**
 * Maps a validated OCSF Compliance finding (class_uid 2003) to NormalizedFinding.
 * Used for Security Hub CSPM compliance findings that get normalized to ASFF
 * for the standard pipeline. The ASFF-normalized version is stored in `raw`.
 */
export function ocsfComplianceToNormalized(
  finding: OCSFComplianceFinding,
  asffNormalized: ASFFFinding,
  clock: Clock = getClock(),
): NormalizedFinding {
  return {
    id: finding.finding_info.uid,
    productArn: finding.metadata?.product?.uid ?? '',
    findingTypeIdentifier: {
      type: 'securityControl',
      value: finding.compliance.control,
    },
    accountId: finding.cloud.account.uid,
    region: finding.cloud.region ?? 'us-east-1',
    severity: mapOcsfSeverity(finding.severity),
    complianceStatus: mapOcsfComplianceStatus(finding.compliance.status),
    recordState: mapOcsfRecordState(finding.activity_id, finding.status_id),
    workflowStatus: mapOcsfWorkflowStatus(finding.status_id),
    resources: (finding.resources ?? []).map(
      (r): NormalizedResource => ({
        type: r.type,
        id: r.uid_alt ?? r.uid ?? r.name ?? '',
        region: r.region,
        tags: convertOcsfTags(r.tags),
        details: r.data,
      }),
    ),
    title: finding.finding_info.title ?? '',
    description: finding.finding_info.desc ?? '',
    createdAt: finding.finding_info.created_time_dt ?? clock.now().toISOString(),
    updatedAt: finding.finding_info.modified_time_dt ?? clock.now().toISOString(),
    firstObservedAt: finding.finding_info.first_seen_time_dt,
    productFields: asffNormalized.ProductFields,
    format: 'ASFF', // OCSF Compliance findings are normalized to ASFF for the standard pipeline
    raw: asffNormalized as unknown as Record<string, unknown>,
  };
}

/**
 * Maps a validated OCSF Vulnerability finding (class_uid 2002) to NormalizedFinding.
 * Used for Amazon Inspector EC2 instance vulnerability findings.
 */
export function ocsfVulnerabilityToNormalized(
  finding: OCSFVulnerabilityFinding,
  mapping: FindingTypeMapping,
  clock: Clock = getClock(),
): NormalizedFinding {
  const fallbackNow = clock.now().toISOString();
  return {
    id: finding.finding_info.uid,
    productArn: finding.metadata?.product?.uid ?? '',
    findingTypeIdentifier: {
      type: 'multiService',
      value: mapping.remediationId,
    },
    accountId: finding.cloud.account.uid,
    region: finding.cloud.region ?? 'us-east-1',
    severity: mapOcsfSeverity(finding.severity),
    complianceStatus: 'FAILED', // Vulnerability findings are always actionable
    recordState: 'ACTIVE',
    workflowStatus: mapOcsfWorkflowStatus(finding.status_id),
    resources: (finding.resources ?? []).map(
      (r): NormalizedResource => ({
        type: r.type,
        id: r.uid_alt ?? r.uid ?? '',
        region: r.region,
        tags: convertOcsfTags(r.tags),
        details: r.data,
      }),
    ),
    title: finding.finding_info.title ?? '',
    description: finding.finding_info.desc ?? '',
    createdAt: finding.finding_info.created_time_dt ?? fallbackNow,
    updatedAt: finding.finding_info.modified_time_dt ?? fallbackNow,
    firstObservedAt: finding.finding_info.first_seen_time_dt,
    productFields: {
      'aws/securityhub/ProductName': finding.metadata?.product?.name ?? 'unknown',
      'aws/securityhub/findingId': finding.finding_info.uid,
    },
    format: 'OCSF',
    raw: finding as unknown as Record<string, unknown>,
  };
}

/**
 * Maps a validated OCSF Detection finding (class_uid 2004) or Data Security
 * finding (class_uid 2006) to NormalizedFinding. Used for Amazon GuardDuty
 * (IAM credential compromise) and Amazon Macie (sensitive data) — distinct
 * OCSF classes that share the common finding envelope this mapper reads.
 */
export function ocsfDetectionToNormalized(
  finding: OCSFDetectionFinding | OCSFDataSecurityFinding,
  mapping: FindingTypeMapping,
  clock: Clock = getClock(),
): NormalizedFinding {
  const fallbackNow = clock.now().toISOString();
  return {
    id: finding.finding_info.uid,
    productArn: finding.metadata?.product?.uid ?? '',
    findingTypeIdentifier: {
      type: 'multiService',
      value: mapping.remediationId,
    },
    accountId: finding.cloud.account.uid,
    region: finding.cloud.region ?? 'us-east-1',
    severity: mapOcsfSeverity(finding.severity),
    complianceStatus: 'FAILED',
    recordState: 'ACTIVE',
    workflowStatus: mapOcsfWorkflowStatus(finding.status_id),
    resources: (finding.resources ?? []).map(
      (r): NormalizedResource => ({
        type: r.type,
        id: r.uid ?? r.uid_alt ?? '',
        region: r.region,
        tags: convertOcsfTags(r.tags),
        details: r.data,
      }),
    ),
    title: finding.finding_info.title ?? '',
    description: finding.finding_info.desc ?? '',
    createdAt: finding.finding_info.created_time_dt ?? fallbackNow,
    updatedAt: finding.finding_info.modified_time_dt ?? fallbackNow,
    firstObservedAt: finding.finding_info.first_seen_time_dt,
    productFields: {
      'aws/securityhub/ProductName': finding.metadata?.product?.name ?? 'unknown',
      'aws/securityhub/findingId': finding.finding_info.uid,
    },
    format: 'OCSF',
    raw: finding as unknown as Record<string, unknown>,
  };
}

// --- Shared OCSF mapping utilities ---

function convertOcsfTags(
  tags: Array<{ name: string; value?: string }> | undefined,
): Record<string, string | undefined> | undefined {
  return tags ? Object.fromEntries(tags.map((t) => [t.name, t.value])) : undefined;
}

// --- Shared OCSF → ASFF mapping helpers ---

function mapOcsfSeverity(ocsfSeverity: string | undefined): ASFFSeverity {
  if (typeof ocsfSeverity !== 'string' || !ocsfSeverity) return 'INFORMATIONAL';
  const map: Record<string, ASFFSeverity> = {
    low: 'LOW',
    medium: 'MEDIUM',
    high: 'HIGH',
    critical: 'CRITICAL',
    fatal: 'CRITICAL',
  };
  return map[ocsfSeverity.toLowerCase()] ?? 'INFORMATIONAL';
}

function mapOcsfComplianceStatus(status: string | undefined): ASFFComplianceStatus {
  if (!status) return 'NOT_AVAILABLE';
  const map: Record<string, ASFFComplianceStatus> = { pass: 'PASSED', fail: 'FAILED', warning: 'WARNING' };
  return map[status.toLowerCase()] ?? 'NOT_AVAILABLE';
}

function mapOcsfRecordState(activityId: number, statusId?: number): ASFFRecordState {
  return activityId === 3 || statusId === 5 ? 'ARCHIVED' : 'ACTIVE';
}

function mapOcsfWorkflowStatus(statusId: number | undefined): ASFFWorkflowStatus {
  if (statusId === undefined) return 'NEW';
  const map: Record<number, ASFFWorkflowStatus> = { 0: 'NEW', 1: 'NEW', 2: 'NOTIFIED', 3: 'SUPPRESSED' };
  return map[statusId] ?? 'RESOLVED';
}
