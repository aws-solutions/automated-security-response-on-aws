// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { ASFFFinding, NormalizedFinding, ResolvedFindingType } from '@asr/data-models';
import { resolveControlId } from '../../common/utils/findingUtils';

/**
 * Converts a NormalizedFinding to a minimal ASFFFinding shape for the
 * FindingDataService which persists findings in ASFF format to DynamoDB.
 *
 * This adapter exists because FindingDataService is shared across multiple
 * lambdas (pre-processor, API, synchronization) and its DynamoDB schema
 * (key derivation, findingJSON compression) is inherently ASFF-shaped.
 * Refactoring FindingDataService to accept NormalizedFinding would require
 * changing the DynamoDB storage format.
 *
 * Service-specific fields (e.g. Vulnerabilities for Inspector) are
 * passed through from `normalized.raw` because the control runbooks need
 * them on the API replay path. Without this, the stored ASFF loses the
 * Inspector Vulnerabilities[] array and the runbook (which patches based
 * on VulnerablePackages) cannot remediate. The pre-processor's auto-
 * trigger path sends `normalized.raw` directly to the orchestrator so
 * keeps the full original; this passthrough makes the API replay path
 * symmetric.
 */
export function toAsffShape(normalized: NormalizedFinding): ASFFFinding {
  const controlId = normalized.findingTypeIdentifier.value;
  const raw = normalized.raw;

  const asff: ASFFFinding = {
    SchemaVersion: '2018-10-08',
    Id: normalized.id,
    ProductArn: normalized.productArn,
    GeneratorId: controlId,
    AwsAccountId: normalized.accountId,
    Region: normalized.region,
    Types: [],
    CreatedAt: normalized.createdAt,
    UpdatedAt: normalized.updatedAt,
    ...(normalized.firstObservedAt !== undefined && { FirstObservedAt: normalized.firstObservedAt }),
    Severity: { Label: normalized.severity },
    Title: normalized.title,
    Description: normalized.description,
    Resources: normalized.resources.map((r) => ({
      Type: r.type,
      Id: r.id,
      Region: r.region,
      Tags: r.tags,
      Details: r.details,
    })),
    Compliance: { Status: normalized.complianceStatus, SecurityControlId: controlId },
    ProductFields: normalized.productFields,
    RecordState: normalized.recordState,
    Workflow: { Status: normalized.workflowStatus },
  };

  // Pass through Inspector's Vulnerabilities[] from the original finding.
  // Inspector.InstanceVulnerability runbook drives patching off
  // Vulnerabilities[0].VulnerablePackages[] (package name + architecture),
  // so the stored ASFF must carry them for the API replay path (UI click
  // Remediate, batch processor) to work. The auto-trigger path passes
  // normalized.raw directly and is unaffected.
  const rawVulnerabilities = raw.Vulnerabilities;
  if (Array.isArray(rawVulnerabilities)) {
    asff.Vulnerabilities = rawVulnerabilities.filter(
      (v): v is Record<string, unknown> => typeof v === 'object' && v !== null && !Array.isArray(v),
    );
  }

  return asff;
}

/** Gets the remediation identifier from a NormalizedFinding.
 * For Security Hub controls this is the control ID (e.g. "AutoScaling.1").
 * For multi-service findings this is the remediation identifier (e.g. "Inspector.InstanceVulnerability").
 */
export function getRemediationIdentifier(normalized: NormalizedFinding): string {
  return normalized.findingTypeIdentifier.value;
}

/**
 * Resolves the findings-table partition key (`findingType`) for a finding.
 *
 * This is the one place a finding's key source is chosen, and it is the last point at which the
 * choice can be made correctly: `findingTypeIdentifier` is a discriminated union that says which
 * family the finding belongs to, and `toAsffShape` flattens it into an untyped
 * `Compliance.SecurityControlId` string where a multi-service remediation id and a bare control id
 * become indistinguishable. Resolving here, before that erasure, is why nothing downstream has to
 * guess.
 *
 * The two families have separate key sources and neither is a fallback for the other:
 *
 * - Multi-service (GuardDuty / Inspector / Macie / IAM Access Analyzer): `findingTypeIdentifier.value`
 *   is the remediation id the mapper resolved, and that IS the partition key. It is never a substring
 *   of the finding id, so the mapper is the only authoritative source.
 * - Security Hub control: `findingTypeIdentifier.value` is the bare control id (`S3.1`), which is NOT
 *   a partition key. The prefixed form is, and only the finding ARN carries it, so this defers to
 *   `resolveControlId`, which throws if the id is not a parseable Security Hub ARN.
 *
 * See ADR 0010.
 */
export function resolveFindingType(normalized: NormalizedFinding): ResolvedFindingType {
  if (normalized.findingTypeIdentifier.type === 'multiService') {
    return normalized.findingTypeIdentifier.value as ResolvedFindingType;
  }
  return resolveControlId({ Id: normalized.id });
}
