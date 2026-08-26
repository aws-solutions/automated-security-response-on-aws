// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { FindingId, FindingKey, ResolvedFindingType } from '@asr/data-models';

/**
 * The multi-service remediation ids, which double as the findings-table partition key
 * (`findingType`) for findings from those sources.
 *
 * Named here rather than written as literals because two tables need them and must not drift: the
 * ingestion mapper's `MULTI_SERVICE_MAPPING` (which remediation a finding routes to) and
 * {@link NATIVE_ARN_FINDING_TYPES} below (how a read reconstructs the key from a native ARN).
 * Sharing the constants makes a spelling drift between those tables impossible; a missing
 * `NATIVE_ARN_FINDING_TYPES` entry is still possible and is caught by a build-time test. See ADR 0010.
 */
export const IAM_ACCESS_ANALYZER_EXTERNAL_ACCESS_FINDING_TYPE = 'IAMAccessAnalyzer.ExternalAccess';
export const GUARDDUTY_IAM_USER_FINDING_TYPE = 'GuardDuty.IAMUser';
export const INSPECTOR_INSTANCE_VULNERABILITY_FINDING_TYPE = 'Inspector.InstanceVulnerability';
export const MACIE_SENSITIVE_DATA_S3_OBJECT_FINDING_TYPE = 'Macie.SensitiveDataS3Object';

/**
 * Maps native (non-Security-Hub) finding ARN service prefixes to the
 * multi-service remediation id under which findings from that source are
 * persisted. The mapping mirrors what `findingTypeMapper.ts` produces at
 * ingestion: when the multi-service mapper recognizes a finding from
 * GuardDuty / Inspector / Macie, the multi-service id (e.g. `GuardDuty.IAMUser`)
 * becomes the partition key for that row in the findings table.
 *
 * Read-side callers reverse this mapping to derive the partition key from
 * the persisted findingId (the native ARN). Today there is exactly one
 * multi-service remediation per source service, so the prefix is sufficient.
 */
const NATIVE_ARN_FINDING_TYPES: ReadonlyArray<{ prefix: RegExp; findingType: string }> = [
  { prefix: /^arn:(?:aws|aws-cn|aws-us-gov):guardduty:/, findingType: GUARDDUTY_IAM_USER_FINDING_TYPE },
  { prefix: /^arn:(?:aws|aws-cn|aws-us-gov):inspector2:/, findingType: INSPECTOR_INSTANCE_VULNERABILITY_FINDING_TYPE },
  { prefix: /^arn:(?:aws|aws-cn|aws-us-gov):macie2:/, findingType: MACIE_SENSITIVE_DATA_S3_OBJECT_FINDING_TYPE },
  {
    prefix: /^arn:(?:aws|aws-cn|aws-us-gov):access-analyzer:/,
    findingType: IAM_ACCESS_ANALYZER_EXTERNAL_ACCESS_FINDING_TYPE,
  },
];

/**
 * The multi-service remediation ids persisted verbatim as the findings table
 * partition key (`findingType`). Used by {@link controlIdToFindingType} to
 * distinguish a multi-service control id (stored as-is) from a Security Hub
 * security control id (stored under the `security-control/` prefix).
 *
 * Exported so a build-time test can assert the ingestion mapper's remediation ids are a subset of
 * this set. That agreement is what lets a read reconstruct a multi-service key from a native ARN,
 * since the key is never a substring of the id — {@link getControlIdFromFindingId} matches the ARN's
 * service prefix and returns the constant from this table. See ADR 0010.
 */
export const MULTI_SERVICE_FINDING_TYPES: ReadonlySet<string> = new Set(
  NATIVE_ARN_FINDING_TYPES.map(({ findingType }) => findingType),
);

/**
 * Returns the persisted findingType (DynamoDB partition key) for a finding ID.
 *
 * Two ARN families are recognized:
 *
 * - Security Hub ARNs (consolidated and unconsolidated) — the control id is
 *   embedded in the ARN and captured via regex.
 * - Native ARNs from multi-service ingestion (GuardDuty / Inspector / Macie)
 *   — the control id is not in the ARN, so we map the ARN service prefix
 *   to the multi-service remediation id used at write time. This mirrors the
 *   write path, where {@link resolveControlId} derives the same value from the
 *   same ARN, ensuring read-side lookups match what was persisted.
 *
 * Returns undefined when the findingId is neither a recognized Security Hub
 * ARN nor a known multi-service native ARN.
 */
export function getControlIdFromFindingId(findingId: string): string | undefined {
  // Security Hub ARN structure depends on consolidation settings —
  // https://aws.amazon.com/blogs/security/consolidating-controls-in-security-hub-the-new-controls-view-and-consolidated-findings/
  const UNCONSOLIDATED_FINDING_ID_REGEX =
    /^arn:(?:aws|aws-cn|aws-us-gov):securityhub:[a-z]{2}(?:-gov)?-[a-z]+-\d:\d{12}:subscription\/(.+)\/finding\/.+$/g;
  const CONSOLIDATED_FINDING_ID_REGEX =
    /^arn:(?:aws|aws-cn|aws-us-gov):securityhub:[a-z]{2}(?:-gov)?-[a-z]+-\d:\d{12}:(.+)\/finding\/.+$/g;

  const unconsolidatedMatch = UNCONSOLIDATED_FINDING_ID_REGEX.exec(findingId);
  if (unconsolidatedMatch) return unconsolidatedMatch[1]; // example: 'aws-foundational-security-best-practices/v/1.0.0/S3.1'

  const consolidatedMatch = CONSOLIDATED_FINDING_ID_REGEX.exec(findingId);
  if (consolidatedMatch) return consolidatedMatch[1]; // example: 'security-control/Lambda.3'

  for (const { prefix, findingType } of NATIVE_ARN_FINDING_TYPES) {
    if (prefix.test(findingId)) return findingType;
  }

  return undefined;
}

/** Thrown when the findings-table partition key cannot be resolved: the finding
 * id does not encode it and no explicit findingType was supplied. Writing an
 * empty key to DynamoDB would be rejected with a `ValidationException`; failing
 * here gives the caller a typed error with the offending finding id instead. */
export class UnresolvableControlIdError extends Error {
  constructor(findingId: string) {
    super(
      `Cannot resolve control id for finding ${findingId}: the finding id does not match a known finding-source ARN and no explicit findingType was supplied.`,
    );
    this.name = 'UnresolvableControlIdError';
  }
}

/** Returns a best-effort control id for an ASFF finding, for use as a metric
 * dimension or log field. ARN-first, then `Compliance.SecurityControlId`, then
 * undefined. Never throws, so it is safe inside error handlers.
 *
 * NOT a partition key, and not interchangeable with {@link resolveControlId}.
 * `Compliance.SecurityControlId` holds the bare control id (`S3.1`), which is not
 * the form the findings table partitions on, and it is not embedded in `finding.Id`,
 * so a value from that branch is neither a valid key nor recoverable from the id.
 * The looser contract is acceptable here only because the value is a label that
 * nothing reads back. Write paths must use {@link resolveControlId}, which refuses
 * to guess. See ADR 0010. */
export function tryResolveControlId(finding: {
  Id: string;
  Compliance?: { SecurityControlId?: string };
}): string | undefined {
  return getControlIdFromFindingId(finding.Id) ?? finding.Compliance?.SecurityControlId;
}

/**
 * Resolves the findings-table partition key for a Security Hub control finding from its ARN,
 * throwing {@link UnresolvableControlIdError} rather than guessing when the id does not carry one.
 *
 * Scope: Security Hub control findings only. Their control id is a literal substring of the finding
 * ARN, so the ARN is both the source of the key and the reason a point read can reconstruct it. The
 * value is the prefixed form `controlIdToFindingType` produces.
 *
 * Multi-service findings do NOT come through here. Their key is the remediation id the ingestion
 * mapper resolved, and it is not present in the finding id at all — `getControlIdFromFindingId`
 * recognizes those ARNs by service prefix and returns a hardcoded constant rather than extracting
 * anything. `resolveFindingType` in `normalizedFindingAdapter.ts` is where a finding's key source is
 * chosen, and it hands multi-service findings their key directly instead of calling this.
 *
 * This deliberately does not read `Compliance.SecurityControlId`. For a control finding that field
 * holds the bare `S3.1`, which is not a partition key: the prefixed `security-control/S3.1` or the
 * unconsolidated standard-and-version form is required, and only the ARN says which. See ADR 0010.
 *
 * For the bare control id (`S3.1`) used in the remediation config lookup,
 * see `asffToNormalized` in findingMappers.ts — that path is Compliance-first.
 *
 * Returns a branded {@link ResolvedFindingType}: this is one of only two places that brand, so a
 * write signature taking that type cannot be reached with an unresolved string. See ADR 0006.
 */
export function resolveControlId(finding: { Id: string }): ResolvedFindingType {
  const controlId = getControlIdFromFindingId(finding.Id);
  if (!controlId) {
    throw new UnresolvableControlIdError(finding.Id);
  }
  return controlId as ResolvedFindingType;
}

/**
 * Sanitizes control ID to ensure it matches expected format
 * @param controlId - The control ID to sanitize
 * @returns The sanitized control ID
 */
export function sanitizeControlId(controlId: string): string {
  const NON_ALPHANUMERIC_OR_DOT_SLASH = /[^a-zA-Z0-9/.-]/g;
  return controlId.replace(NON_ALPHANUMERIC_OR_DOT_SLASH, '');
}

/**
 * Builds the full findings-table key for a finding id, or undefined when the partition key cannot
 * be derived from the id. Only Security Hub ARNs and recognized native service ARNs encode it; a
 * bare id such as Macie's Security Hub V2 `FindingInfoUid` does not. See ADR 0010.
 */
export function tryFindingKeyFromFindingId(findingId: FindingId): FindingKey | undefined {
  const findingType = getControlIdFromFindingId(findingId);
  return findingType ? { findingId, findingType: sanitizeControlId(findingType) } : undefined;
}

/**
 * Splits finding ids into keys that could be derived and ids that could not.
 *
 * Point-read callers need this distinction: an id with no derivable key was never queried, which is
 * not the same as an id that was queried and not found. Callers holding a non-derivable id must
 * obtain the key another way (an explicit `findingKeys` request field) or fall back to the findingId
 * GSI. See ADR 0010.
 */
export function partitionFindingIdsByKeyDerivability(findingIds: readonly FindingId[]): {
  keys: FindingKey[];
  nonDerivableIds: FindingId[];
} {
  const keys: FindingKey[] = [];
  const nonDerivableIds: FindingId[] = [];

  for (const findingId of findingIds) {
    const key = tryFindingKeyFromFindingId(findingId);
    if (key) {
      keys.push(key);
    } else {
      nonDerivableIds.push(findingId);
    }
  }

  return { keys, nonDerivableIds };
}

/**
 * Maps a notification configuration's control id to the findings table
 * `findingType` partition key under which its findings are persisted.
 *
 * Notification configs store the bare Security Hub control id (e.g. `S3.5`),
 * matching `Compliance.SecurityControlId` and the in-memory routing/eligibility
 * filters. The findings table, however, partitions on the prefixed form that
 * the write path derives from the finding ARN (e.g. `security-control/S3.5` for
 * consolidated findings). This function bridges the two so partition-keyed
 * reconciliation queries reach the right rows. The mapping mirrors the write
 * path's convention:
 *
 * - Values already in partition form (containing a `/`, e.g. `security-control/S3.5`
 *   or an unconsolidated `aws-foundational-security-best-practices/v/1.0.0/S3.5`)
 *   are passed through unchanged.
 * - Multi-service remediation ids (e.g. `Inspector.InstanceVulnerability`) are
 *   persisted verbatim as the partition key, so they pass through unchanged.
 * - Everything else is treated as a consolidated Security Hub security control
 *   id and prefixed with `security-control/`.
 *
 * NOTE: Unconsolidated Security Hub findings (partition keyed by standard and
 * version) are not reachable from a bare control id alone and are not covered
 * here; write-time stamping handles those when the finding changes.
 *
 * @param controlId - The control id as stored on a notification configuration
 * @returns The corresponding `findingType` partition key value
 */
export function controlIdToFindingType(controlId: string): string {
  const sanitized = sanitizeControlId(controlId);
  if (sanitized.includes('/') || MULTI_SERVICE_FINDING_TYPES.has(sanitized)) {
    return sanitized;
  }
  return `security-control/${sanitized}`;
}

/**
 * Sanitizes a finding ID to ensure it's safe for DynamoDB keys.
 * Replaces the embedded control ID with the sanitized version and strips control characters.
 * @param findingId - The raw finding ID
 * @param controlIdFromFindingId - The control ID extracted from the finding ID
 * @param sanitizedControlId - The sanitized control ID
 * @returns The sanitized finding ID branded as FindingId
 */
export function sanitizeFindingId(
  findingId: string,
  controlIdFromFindingId: string,
  sanitizedControlId: string,
): FindingId {
  const findingIdWithSanitizedControlId = findingId.replace(controlIdFromFindingId, sanitizedControlId);
  // eslint-disable-next-line no-control-regex
  const CONTROL_CHARS = /[#\x00-\x1F\x7F]/g; // NOSONAR - sanitizing control chars
  return findingIdWithSanitizedControlId.replace(CONTROL_CHARS, '') as FindingId;
}

/**
 * Derives the DynamoDB-safe findingId from a raw Security Hub finding ARN.
 * Combines getControlIdFromFindingId + sanitizeControlId + sanitizeFindingId
 * in one call — use when you have an ARN but no full ASFF object.
 * Returns undefined if the controlId cannot be extracted from the ARN.
 */
export function toDbFindingId(findingId: string): FindingId | undefined {
  const controlIdFromArn = getControlIdFromFindingId(findingId);
  if (!controlIdFromArn) return undefined;
  const sanitized = sanitizeControlId(controlIdFromArn);
  return sanitizeFindingId(findingId, controlIdFromArn, sanitized);
}

/**
 * Gets the appropriate console host based on AWS partition
 * @param partition - AWS partition (aws, aws-us-gov, aws-cn)
 * @returns Console host URL
 */
function getConsoleHost(partition: string): string {
  const consoleHosts = {
    aws: 'console.aws.amazon.com',
    'aws-us-gov': 'console.amazonaws-us-gov.com',
    'aws-cn': 'console.amazonaws.cn',
  };

  return consoleHosts[partition as keyof typeof consoleHosts] || consoleHosts.aws;
}

/**
 * Generates Security Hub finding console URL. If Security Hub V2 is enabled in the current account, this finding links to
 * the Security Hub console. Otherwise, it links to Security Hub CSPM.
 * @param findingId - The Security Hub finding ID
 * @param region - AWS region (optional, defaults to AWS_REGION env var) - Since the solution must be deployed in the Security Hub aggregation region, all findings should be available in the region where this Lambda function exists, meaning you likely do not want to pass a value for this parameter unless you require a region-specific console link.
 * @param partition - AWS partition (optional, defaults to AWS_PARTITION env var)
 * @returns Console URL for the Security Hub finding
 */
export function getSecurityHubConsoleUrl(findingId: string, region?: string, partition?: string): string {
  const securityHubV2Enabled = process.env.SECURITY_HUB_V2_ENABLED?.toLowerCase() === 'true';
  const awsRegion = region || process.env.AWS_REGION || 'us-east-1';
  const awsPartition = partition || process.env.AWS_PARTITION || 'aws';

  const host = getConsoleHost(awsPartition);

  const urlPattern =
    process.env.CONSOLE_URL_PATTERN ||
    (securityHubV2Enabled
      ? `/securityhub/v2/home?region=${awsRegion}#/findings?search=finding_info.uid%3D%255Coperator%255C%253AEQUALS%255C%253A${encodeURIComponent(findingId)}`
      : `/securityhub/home?region=${awsRegion}#/findings?search=Id%3D%255Coperator%255C%253AEQUALS%255C%253A${encodeURIComponent(findingId)}`);
  return `https://${awsRegion}.${host}${urlPattern}`;
}

/**
 * Generates Step Functions execution console URL
 * @param executionId - The Step Functions execution ID/ARN
 * @param region - AWS region (optional, defaults to AWS_REGION env var)
 * @param partition - AWS partition (optional, defaults to AWS_PARTITION env var)
 * @returns Console URL for the Step Functions execution
 */
export function getStepFunctionsConsoleUrl(executionId?: string, region?: string, partition?: string): string {
  if (!executionId) {
    return '';
  }

  const awsRegion = region || process.env.AWS_REGION || 'us-east-1';
  const awsPartition = partition || process.env.AWS_PARTITION || 'aws';

  const host = getConsoleHost(awsPartition);

  const urlPattern =
    process.env.EXECUTION_CONSOLE_URL_PATTERN ||
    `/states/home?region=${awsRegion}#/v2/executions/details/${encodeURIComponent(executionId)}`;

  return `https://${awsRegion}.${host}${urlPattern}`;
}
