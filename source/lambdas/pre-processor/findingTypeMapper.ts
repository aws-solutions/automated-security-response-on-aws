// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { REMEDIATION_SUPPORTED_RESOURCE_TYPES, normalizeResourceTypeToAsff } from '@asr/data-models';
import {
  GUARDDUTY_IAM_USER_FINDING_TYPE,
  IAM_ACCESS_ANALYZER_EXTERNAL_ACCESS_FINDING_TYPE,
  INSPECTOR_INSTANCE_VULNERABILITY_FINDING_TYPE,
  MACIE_SENSITIVE_DATA_S3_OBJECT_FINDING_TYPE,
} from '../common/utils/findingUtils';

// Re-exported for backwards compatibility with existing importers/tests.
export { normalizeResourceTypeToAsff };

/** Narrow logger interface so callers can pass any compatible logger without coupling to a concrete class */
export interface FindingLogger {
  info(message: string, extra?: Record<string, unknown>): void;
  warn(message: string, extra?: Record<string, unknown>): void;
  debug(message: string, extra?: Record<string, unknown>): void;
}

/**
 * Maps multi-service findings (Inspector, GuardDuty, Macie, IAM Access Analyzer)
 * to a remediation identifier. Matching is format-agnostic: it reads whichever
 * shape is present (ASFF or OCSF). The finding format is derived from the
 * detected schema downstream, not from this mapper.
 */
export interface FindingTypeMapping {
  /** Remediation identifier used for RemediationConfigTable lookup and runbook name construction */
  remediationId: string;
}

/**
 * Thrown when a finding matches a multi-service routing rule by ProductName/Types/resource
 * but its ProductArn is not the reserved AWS-service ARN we recognize for that product.
 *
 * This covers any unrecognized source — a third-party or custom integration that reports the
 * same product name, a missing ProductArn, or a deliberately spoofed finding. We can't confirm
 * the finding originated from the claimed AWS service, so we don't route it.
 *
 * It must be a hard stop, not a `null` return: `null` is indistinguishable from "not a
 * multi-service finding" and would let the caller fall through to standard
 * SecurityControlId-based routing. A finding that also carries a crafted
 * `Compliance.SecurityControlId` (e.g. "GuardDuty.IAMUser") could then reach the very
 * remediation the ProductArn check was meant to gate. Callers must drop the finding.
 */
export class UnverifiedProductArnError extends Error {
  readonly productName: string;
  readonly productArn: string;
  readonly expectedProductArnService: string;
  readonly remediationId: string;

  constructor(args: {
    productName: string;
    productArn: string;
    expectedProductArnService: string;
    remediationId: string;
  }) {
    super(
      `Finding claims product "${args.productName}" but ProductArn "${args.productArn}" ` +
        `is not the reserved AWS service ARN for "${args.expectedProductArnService}".`,
    );
    this.name = 'UnverifiedProductArnError';
    this.productName = args.productName;
    this.productArn = args.productArn;
    this.expectedProductArnService = args.expectedProductArnService;
    this.remediationId = args.remediationId;
  }
}

/** Fields accessed from an ASFF-format finding for type mapping */
interface AsffFindingFields {
  ProductName?: string;
  ProductArn?: string;
  ProductFields?: { 'aws/securityhub/ProductName'?: string; [key: string]: unknown };
  Types?: string[];
  Resources?: { Type: string; Id?: string }[];
}

/** Fields accessed from an OCSF-format finding for type mapping */
interface OcsfFindingFields {
  metadata?: { product?: { name?: string; uid?: string } };
  finding_info?: { types?: string[]; uid?: string };
  resources?: { type: string; uid?: string; owner?: { account?: { uid?: string } } }[];
}

/** Union of ASFF and OCSF finding shapes used by the mapper */
export type UnprocessedFinding = AsffFindingFields & OcsfFindingFields;

interface MappingRule {
  /** Match against finding Types array — at least one type must contain this substring */
  typesContains?: string;
  /**
   * The resulting remediation identifier. The finding's resource type must be
   * one of REMEDIATION_SUPPORTED_RESOURCE_TYPES[remediationId] (the shared
   * source of truth in @asr/data-models) for the rule to match, so a
   * remediation is never routed to a resource type it cannot act on (for
   * example an Amazon Inspector Lambda-function or ECR-image finding routed to
   * the EC2-only patch remediation).
   */
  remediationId: string;
  /**
   * AWS service slug in the reserved Security Hub product ARN
   * (arn:<partition>:securityhub:<region>::product/aws/<slug>). The finding's
   * ProductArn (ASFF) or metadata.product.uid (OCSF) must match this reserved
   * ARN before the finding is routed to remediation.
   *
   * ProductName and Types are free-form fields that any caller of
   * BatchImportFindings can set; ProductArn is authorization-bound (the
   * reserved aws/<service> namespace can only be written by the AWS service
   * itself). Pinning to it stops a spoofed ProductName from triggering
   * containment on behalf of a service the finding did not originate from.
   */
  productArnService: string;
}

/**
 * Static mapping rules for multi-service remediation finding types.
 *
 * These map ProductName + Types + resource type to a remediation identifier
 * that is used to look up the control in the RemediationConfigTable and
 * construct the runbook name (ASR-{remediationId}).
 *
 * The mapping is deterministic and based on AWS-defined ASFF/OCSF taxonomy
 * values that rarely change. Hardcoding provides fast lookup without
 * external dependencies.
 */
const MULTI_SERVICE_MAPPING: Record<string, MappingRule[]> = {
  'IAM Access Analyzer': [
    {
      typesContains: 'External Access Granted',
      remediationId: IAM_ACCESS_ANALYZER_EXTERNAL_ACCESS_FINDING_TYPE,
      productArnService: 'access-analyzer',
    },
  ],
  Inspector: [
    {
      typesContains: 'Software and Configuration Checks/Vulnerabilities/CVE',
      remediationId: INSPECTOR_INSTANCE_VULNERABILITY_FINDING_TYPE,
      productArnService: 'inspector',
    },
  ],
  GuardDuty: [
    {
      // GuardDuty records the actor access key as a resource on many finding
      // types (e.g. Policy:S3/BucketBlockPublicAccessDisabled), so the resource
      // type alone is not sufficient. Require the finding type to name the
      // IAMUser resource family — ':IAMUser-' in ASFF Types, ':IAMUser/' in
      // OCSF finding_info.types — so only credential findings route to
      // containment.
      typesContains: ':IAMUser',
      remediationId: GUARDDUTY_IAM_USER_FINDING_TYPE,
      productArnService: 'guardduty',
    },
  ],
  Macie: [
    {
      // Real findings carry the native Macie type: OCSF
      // finding_info.types 'SensitiveData:S3Object/Personal', ASFF Types
      // 'Sensitive Data Identifications/PII/SensitiveData:S3Object/Personal'.
      // Match the shared 'SensitiveData:S3Object' substring so both formats map.
      typesContains: 'SensitiveData:S3Object',
      remediationId: MACIE_SENSITIVE_DATA_S3_OBJECT_FINDING_TYPE,
      productArnService: 'macie',
    },
  ],
};

/**
 * Every remediation id the multi-service mapper can produce.
 *
 * Exported for the build-time invariant test that asserts each is a `MULTI_SERVICE_FINDING_TYPES`
 * member, so a multi-service findingType supplied explicitly to `resolveControlId` stays consistent
 * with what a native ARN would derive. See ADR 0010.
 */
export const MULTI_SERVICE_REMEDIATION_IDS: readonly string[] = Object.values(MULTI_SERVICE_MAPPING)
  .flat()
  .map((rule) => rule.remediationId);

/**
 * Attempts to map a finding to a multi-service remediation identifier.
 *
 * This is called before the standard SecurityControlId-based lookup.
 * If the finding matches a multi-service mapping rule, the returned
 * remediationId is used instead of SecurityControlId for the
 * RemediationConfigTable lookup.
 *
 * @param finding - The raw finding object (before normalization). Can be ASFF or OCSF format.
 * @param logger - Logger instance for observability
 * @returns The mapping result if matched, or null if this is a standard Config/Security Hub finding
 * @throws UnverifiedProductArnError when a rule matches but the finding's ProductArn
 *   is not the reserved AWS service ARN. Callers must drop the finding (not fall through).
 */
export function mapFindingType(finding: UnprocessedFinding, logger: FindingLogger): FindingTypeMapping | null {
  const productName = extractProductName(finding);
  if (!productName) return null;

  const rules = MULTI_SERVICE_MAPPING[productName];
  if (!rules) return null;

  const types = extractTypes(finding);
  const resourceType = extractFirstResourceType(finding);

  for (const rule of rules) {
    const { typesContains } = rule;
    if (typesContains && !types.some((t) => t.includes(typesContains))) {
      continue;
    }
    // Resource-type gate (shared source of truth in @asr/data-models). A
    // remediation is only routed to resource types it can act on, so an
    // out-of-scope resource (for example an Amazon Inspector Lambda-function or
    // ECR-image finding, or an IAM Access Analyzer finding on a resource other
    // than S3/KMS) is dropped at ingest rather than stored and later failing.
    const supportedResourceTypes = REMEDIATION_SUPPORTED_RESOURCE_TYPES[rule.remediationId];
    if (supportedResourceTypes && (!resourceType || !supportedResourceTypes.includes(resourceType))) {
      logger.debug('Multi-service routing skipped: resource type not supported for this remediation', {
        productName,
        remediationId: rule.remediationId,
        resourceType: resourceType ?? '(none)',
        supportedResourceTypes,
      });
      continue;
    }

    // Source-authenticity gate: ProductName/Types are free-form, so a matched
    // rule is only honored when the finding's ProductArn proves it actually
    // originated from the claimed AWS service. A spoofed finding is dropped via
    // a thrown error (not a null return) so the caller cannot fall through to
    // standard SecurityControlId-based routing with an attacker-crafted control id.
    const productArn = extractProductArn(finding);
    if (!isAuthenticServiceProductArn(productArn, rule.productArnService)) {
      logger.warn('Multi-service routing skipped: ProductArn is not the reserved ARN for the claimed AWS service', {
        productName,
        productArn: productArn ?? '(missing)',
        expectedProductArnService: rule.productArnService,
        remediationId: rule.remediationId,
        resourceType,
      });
      throw new UnverifiedProductArnError({
        productName,
        productArn: productArn ?? '(missing)',
        expectedProductArnService: rule.productArnService,
        remediationId: rule.remediationId,
      });
    }

    logger.info('Multi-service finding type mapped', {
      productName,
      remediationId: rule.remediationId,
      resourceType,
    });

    return {
      remediationId: rule.remediationId,
    };
  }

  logger.debug('Finding from multi-service product did not match any mapping rule', {
    productName,
    types,
    resourceType,
  });

  return null;
}

function extractProductName(finding: UnprocessedFinding): string | undefined {
  // ASFF format: ProductName field or ProductFields['aws/securityhub/ProductName']
  if (finding.ProductName) return finding.ProductName;
  if (finding.ProductFields?.['aws/securityhub/ProductName']) {
    return finding.ProductFields['aws/securityhub/ProductName'];
  }

  // OCSF format: metadata.product.name
  if (finding.metadata?.product?.name) return finding.metadata.product.name;

  return undefined;
}

/**
 * Reserved AWS-service product ARN, e.g.
 * arn:aws:securityhub:us-east-1::product/aws/guardduty. Per the ASFF spec the
 * format is arn:{partition}:securityhub:{region}:{account-id}:product/{company-id}/{product-id};
 * for AWS services the company-id is the literal "aws", the product-id is the
 * service's public name, and the account-id segment is empty (::). A custom or
 * partner integration always carries a non-empty account id and a non-aws
 * company-id, so it can never match. Both the "product" and "productv2"
 * (Security Hub V2) reserved paths are accepted, mirroring the orchestrator's
 * parse_input validator. The captured group is the service slug.
 *
 * The region is matched loosely ([a-z0-9-]+) rather than pinned to a specific
 * format: the security discriminators are the partition, the "securityhub"
 * service, the empty account segment, and the "aws" owner — not the region.
 * Constraining the region adds no protection (an attacker can't choose a region
 * to defeat the empty-account/aws-owner check) and would risk rejecting
 * legitimate findings from future or differently-shaped region names.
 */
const AWS_SERVICE_PRODUCT_ARN_PATTERN =
  /^arn:(?:aws|aws-cn|aws-us-gov):securityhub:[a-z0-9-]+::(?:product|productv2)\/aws\/([a-z-]+)$/;

function extractProductArn(finding: UnprocessedFinding): string | undefined {
  // ASFF carries it directly; OCSF carries it as metadata.product.uid.
  return finding.ProductArn ?? finding.metadata?.product?.uid;
}

function isAuthenticServiceProductArn(productArn: string | undefined, expectedService: string): boolean {
  if (!productArn) return false;
  const match = AWS_SERVICE_PRODUCT_ARN_PATTERN.exec(productArn);
  return match?.[1] === expectedService;
}

function extractTypes(finding: UnprocessedFinding): string[] {
  // ASFF format
  if (Array.isArray(finding.Types)) return finding.Types;

  // OCSF format
  if (Array.isArray(finding.finding_info?.types)) return finding.finding_info.types;

  return [];
}

function extractFirstResourceType(finding: UnprocessedFinding): string | undefined {
  // ASFF format — may be "AwsEc2Instance" or "AWS::EC2::Instance"
  if (finding.Resources?.[0]?.Type) {
    return normalizeResourceTypeToAsff(finding.Resources[0].Type);
  }

  // OCSF format — uses CloudFormation format (e.g., "AWS::S3::Bucket")
  if (finding.resources?.[0]?.type) {
    return normalizeResourceTypeToAsff(finding.resources[0].type);
  }

  return undefined;
}
