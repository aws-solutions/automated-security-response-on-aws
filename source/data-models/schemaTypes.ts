// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { z } from 'zod';
import { FindingId } from './finding';

/** Inferred type from Zod's built-in JSON schema — represents any valid JSON value. */
export type JsonValue = z.infer<ReturnType<typeof z.json>>;

// Enum types for ASFF
export type ASFFComplianceStatus = 'PASSED' | 'WARNING' | 'FAILED' | 'NOT_AVAILABLE';
export type ASFFSeverity = 'INFORMATIONAL' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
export type ASFFRecordState = 'ACTIVE' | 'ARCHIVED';
export type ASFFWorkflowStatus = 'NEW' | 'NOTIFIED' | 'RESOLVED' | 'SUPPRESSED';

// Severity mapping for numeric values
export const SEVERITY_MAPPING: Record<string, number> = {
  INFORMATIONAL: 0,
  LOW: 1,
  MEDIUM: 2,
  HIGH: 3,
  CRITICAL: 4,
};

/**
 * Maps an ASFF severity label to its numeric value, defaulting to 0 (INFORMATIONAL)
 * for missing or unrecognized labels. Case-insensitive.
 */
export const normalizeSeverity = (severity: string | undefined | null): number =>
  SEVERITY_MAPPING[severity?.toUpperCase() ?? ''] ?? 0;

// Zod schemas for runtime validation
export const ASFFSchema = z
  .object({
    SchemaVersion: z.literal('2018-10-08'),
    Id: z.string(),
    ProductArn: z.string(),
    ProductName: z.string().optional(),
    CompanyName: z.string().optional(),
    Region: z.string().optional(),
    GeneratorId: z.string(),
    AwsAccountId: z.string(),
    Types: z.array(z.string()),
    FirstObservedAt: z.string().optional(),
    LastObservedAt: z.string().optional(),
    CreatedAt: z.string(),
    UpdatedAt: z.string(),
    Severity: z.object({
      Label: z.enum(['INFORMATIONAL', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL']).optional(),
      Normalized: z.number().optional(),
      Original: z.string().optional(),
      Product: z.number().optional(),
    }),
    Confidence: z.number().optional(),
    Criticality: z.number().optional(),
    Title: z.string(),
    Description: z.string().optional(),
    Remediation: z
      .object({
        Recommendation: z
          .object({
            Text: z.string().optional(),
            Url: z.string().optional(),
          })
          .optional(),
      })
      .optional(),
    SourceUrl: z.string().optional(),
    ProductFields: z.record(z.string(), z.string()).optional(),
    UserDefinedFields: z.record(z.string(), z.string()).optional(),
    Malware: z.array(z.record(z.string(), z.any())).optional(),
    Network: z.record(z.string(), z.any()).optional(),
    NetworkPath: z.array(z.record(z.string(), z.any())).optional(),
    Process: z.record(z.string(), z.any()).optional(),
    ThreatIntelIndicators: z.array(z.record(z.string(), z.any())).optional(),
    Resources: z.array(
      z.object({
        Type: z.string(),
        Id: z.string(),
        Partition: z.string().optional(),
        Region: z.string().optional(),
        ResourceRole: z.string().optional(),
        Tags: z.record(z.string(), z.string().optional()).optional(),
        DataClassification: z
          .object({
            DetailedResultsLocation: z.string().optional(),
            Result: z.record(z.string(), z.any()).optional(),
          })
          .optional(),
        Details: z.record(z.string(), z.json()).optional(),
      }),
    ),
    // Compliance is present on Security Hub control findings (consolidated
    // and unconsolidated) and on findings from upstream services that the
    // consolidated-controls layer wraps with a SecurityControlId. It is
    // absent on raw product findings whose source is not mapped to a
    // managed Security Hub control — notably IAM Access Analyzer
    // `External Access Granted` findings. Consumers that need the control
    // id should fall back to deriving it from the finding ARN via
    // `getControlIdFromFindingId` and treat missing Compliance gracefully.
    Compliance: z
      .object({
        Status: z.enum(['PASSED', 'WARNING', 'FAILED', 'NOT_AVAILABLE']).optional(),
        RelatedRequirements: z.array(z.string()).optional(),
        StatusReasons: z
          .array(
            z.object({
              ReasonCode: z.string(),
              Description: z.string().optional(),
            }),
          )
          .optional(),
        SecurityControlId: z.string(),
        AssociatedStandards: z
          .array(
            z.object({
              StandardsId: z.string().optional(),
            }),
          )
          .optional(),
        SecurityControlParameters: z
          .array(
            z.object({
              Name: z.string().optional(),
              Value: z.array(z.string()).optional(),
            }),
          )
          .optional(),
      })
      .optional(),
    VerificationState: z.string().optional(),
    WorkflowState: z.string().optional(),
    Workflow: z
      .object({
        Status: z.enum(['NEW', 'NOTIFIED', 'RESOLVED', 'SUPPRESSED']).optional(),
      })
      .optional(),
    RecordState: z.enum(['ACTIVE', 'ARCHIVED']).optional(),
    RelatedFindings: z
      .array(
        z.object({
          ProductArn: z.string(),
          Id: z.string(),
        }),
      )
      .optional(),
    Note: z
      .object({
        Text: z.string(),
        UpdatedBy: z.string(),
        UpdatedAt: z.string(),
      })
      .optional(),
    Vulnerabilities: z.array(z.record(z.string(), z.any())).optional(),
    PatchSummary: z.record(z.string(), z.any()).optional(),
    Action: z.record(z.string(), z.any()).optional(),
    FindingProviderFields: z
      .object({
        Confidence: z.number().optional(),
        Criticality: z.number().optional(),
        RelatedFindings: z
          .array(
            z.object({
              ProductArn: z.string(),
              Id: z.string(),
            }),
          )
          .optional(),
        Severity: z
          .object({
            Label: z.enum(['INFORMATIONAL', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL']).optional(),
            Original: z.string().optional(),
            Normalized: z.number().optional(),
          })
          .optional(),
        Types: z.array(z.string()).optional(),
      })
      .optional(),
    Sample: z.boolean().optional(),
    GeneratorDetails: z
      .object({
        Name: z.string().optional(),
        Description: z.string().optional(),
        Labels: z.array(z.string()).optional(),
      })
      .optional(),
    AwsAccountName: z.string().optional(),
  })
  .passthrough();

export const OCSFComplianceSchema = z
  .object({
    activity_id: z.union([z.literal(0), z.literal(1), z.literal(2), z.literal(3), z.literal(99)]),
    category_uid: z.number(),
    class_uid: z.literal(2003),
    severity_id: z.union([
      z.literal(0),
      z.literal(1),
      z.literal(2),
      z.literal(3),
      z.literal(4),
      z.literal(5),
      z.literal(6),
      z.literal(99),
    ]),
    type_uid: z.number(),
    end_time_dt: z.string().optional(),
    start_time_dt: z.string().optional(),
    time_dt: z.string().optional(),
    activity_name: z.enum(['Close', 'Update', 'Create', 'Unknown', 'Other']).optional(),
    category_name: z.string().optional(),
    class_name: z.string().optional(),
    severity: z.enum(['Unknown', 'Informational', 'Low', 'Medium', 'High', 'Critical', 'Fatal', 'Other']).optional(),
    type_name: z.string().optional(),
    time: z.number(),
    cloud: z.object({
      account: z.object({
        uid: z.string(),
      }),
      provider: z.string().optional(),
      region: z.string().optional(),
    }),
    finding_info: z.object({
      created_time: z.number().optional(),
      created_time_dt: z.string().optional(),
      desc: z.string().optional(),
      first_seen_time: z.number().optional(),
      first_seen_time_dt: z.string().optional(),
      last_seen_time: z.number().optional(),
      last_seen_time_dt: z.string().optional(),
      modified_time: z.number().optional(),
      modified_time_dt: z.string().optional(),
      product_uid: z.string().optional(),
      title: z.string().optional(),
      types: z.array(z.string()).optional(),
      analytic: z
        .object({
          category: z.string().optional(),
          name: z.string().optional(),
          type: z.string().optional(),
          type_id: z.number().optional(),
        })
        .optional(),
      uid: z.string(),
    }),
    compliance: z.object({
      requirements: z.array(z.string()).optional(),
      status: z.string().optional(),
      status_code: z.string().optional(),
      status_detail: z.string().optional(),
      status_id: z.number().optional(),
      control: z.string(),
      standards: z.array(z.string()),
    }),
    resources: z.array(
      z
        .object({
          cloud_partition: z.string().optional(),
          region: z.string().optional(),
          type: z.string(),
          uid: z.string().optional(),
          role_id: z.string().optional(),
          uid_alt: z.string().optional(),
          account_uid: z.string().optional(),
          labels: z.array(z.string()).optional(),
          name: z.string().optional(),
          namespace: z.string().optional(),
          tags: z
            .array(
              z.object({
                name: z.string(),
                value: z.string().optional(),
              }),
            )
            .optional(),
          owner: z.object({
            account: z.object({
              name: z.string().optional(),
              type: z.string().optional(),
              type_id: z.number().optional(),
              uid: z.string().optional(),
            }),
            credential_uid: z.string().optional(),
            domain: z.string().optional(),
            email_addr: z.string().optional(),
            full_name: z.string().optional(),
            name: z.string().optional(),
            org: z
              .object({
                name: z.string().optional(),
                ou_name: z.string().optional(),
                ou_uid: z.string().optional(),
                uid: z.string().optional(),
              })
              .optional(),
            type: z.string().optional(),
            type_id: z.number().optional(),
            uid: z.string().optional(),
          }),
          data: z.record(z.string(), z.json()).optional(),
        })
        .refine((resource) => resource.uid || resource.uid_alt || resource.name, {
          message: "At least one of 'uid', 'uid_alt', or 'name' must be defined",
        }),
    ),
    api: z
      .object({
        group: z.record(z.string(), z.any()).optional(),
        operation: z.string(),
        request: z
          .object({
            containers: z.array(z.record(z.string(), z.any())).optional(),
            data: z.record(z.string(), z.any()).optional(),
            flags: z.array(z.string()).optional(),
            uid: z.string(),
          })
          .optional(),
        response: z
          .object({
            code: z.number().optional(),
            containers: z.array(z.record(z.string(), z.any())).optional(),
            data: z.record(z.string(), z.any()).optional(),
            error: z.string().optional(),
            error_message: z.string().optional(),
            flags: z.array(z.string()).optional(),
            message: z.string().optional(),
          })
          .optional(),
        service: z.record(z.string(), z.any()).optional(),
        version: z.string().optional(),
      })
      .optional(),
    remediation: z
      .object({
        desc: z.string().optional(),
        kb_articles: z.array(z.string()).optional(),
      })
      .optional(),
    confidence: z.string().optional(),
    confidence_id: z.number().optional(),
    confidence_score: z.number().optional(),
    count: z.number().optional(),
    duration: z.number().optional(),
    end_time: z.number().optional(),
    message: z.string().optional(),
    raw_data: z.string().optional(),
    start_time: z.number().optional(),
    status: z.enum(['Unknown', 'New', 'In Progress', 'Suppressed', 'Resolved', 'Archived', 'Other']).optional(),
    status_code: z.string().optional(),
    status_detail: z.string().optional(),
    status_id: z.number().optional(),
    timezone_offset: z.number().optional(),
    metadata: z
      .object({
        correlation_uid: z.string().optional(),
        event_code: z.string().optional(),
        extension: z.record(z.string(), z.any()).optional(),
        labels: z.array(z.string()).optional(),
        logged_time: z.number().optional(),
        modified_time: z.number().optional(),
        original_time: z.string().optional(),
        processed_time: z.number().optional(),
        product: z
          .object({
            feature: z
              .object({
                name: z.string().optional(),
                uid: z.string().optional(),
                version: z.string().optional(),
              })
              .optional(),
            lang: z.string().optional(),
            name: z.string().optional(),
            path: z.string().optional(),
            uid: z.string().optional(),
            url_string: z.string().optional(),
            vendor_name: z.string().optional(),
            version: z.string().optional(),
          })
          .optional(),
        profiles: z.array(z.string()).optional(),
        sequence: z.number().optional(),
        uid: z.string().optional(),
        version: z.string().optional(),
      })
      .optional(),
    observables: z
      .array(
        z.object({
          name: z.string().optional(),
          reputation: z
            .object({
              base_score: z.number().optional(),
              provider: z.string().optional(),
              score: z.string().optional(),
              score_id: z.number().optional(),
            })
            .optional(),
          type: z.string().optional(),
          type_id: z.number().optional(),
          value: z.string().optional(),
        }),
      )
      .optional(),
    enrichments: z
      .array(
        z.object({
          data: z.record(z.string(), z.any()).optional(),
          name: z.string().optional(),
          provider: z.string().optional(),
          type: z.string().optional(),
          value: z.string().optional(),
        }),
      )
      .optional(),
    vendor_attributes: z
      .object({
        severity: z
          .enum(['Unknown', 'Informational', 'Low', 'Medium', 'High', 'Critical', 'Fatal', 'Other'])
          .optional(),
        severity_id: z
          .union([
            z.literal(0),
            z.literal(1),
            z.literal(2),
            z.literal(3),
            z.literal(4),
            z.literal(5),
            z.literal(6),
            z.literal(99),
          ])
          .optional(),
      })
      .optional(),
  })
  .passthrough();

/**
 * Common OCSF resource shape shared by all non-compliance finding classes.
 * Looser than OCSFComplianceSchema resources — no owner.account required.
 */
const OCSFResourceSchema = z
  .object({
    type: z.string(),
    uid: z.string().optional(),
    uid_alt: z.string().optional(),
    region: z.string().optional(),
    cloud_partition: z.string().optional(),
    owner: z
      .object({
        account: z
          .object({
            uid: z.string().optional(),
          })
          .optional(),
      })
      .optional(),
    tags: z
      .array(
        z.object({
          name: z.string(),
          value: z.string().optional(),
        }),
      )
      .optional(),
    data: z.record(z.string(), z.json()).optional(),
  })
  .passthrough();

/** Common OCSF envelope fields shared by Vulnerability Finding and Detection Finding classes */
const OCSFBaseFindingFields = {
  activity_id: z.number(),
  category_uid: z.literal(2), // Findings category
  severity_id: z.number().optional(),
  type_uid: z.number(),
  time: z.number(),
  severity: z.string().optional(),
  cloud: z.object({
    account: z.object({ uid: z.string() }),
    region: z.string().optional(),
    provider: z.string().optional(),
  }),
  finding_info: z.object({
    uid: z.string(),
    title: z.string().optional(),
    desc: z.string().optional(),
    types: z.array(z.string()).optional(),
    created_time_dt: z.string().optional(),
    modified_time_dt: z.string().optional(),
    first_seen_time_dt: z.string().optional(),
    last_seen_time_dt: z.string().optional(),
  }),
  resources: z.array(OCSFResourceSchema),
  metadata: z
    .object({
      product: z
        .object({
          name: z.string().optional(),
          uid: z.string().optional(),
          vendor_name: z.string().optional(),
          version: z.string().optional(),
        })
        .optional(),
    })
    .optional(),
  status_id: z.number().optional(),
};

/**
 * OCSF Vulnerability Finding schema (class_uid 2002).
 * Used by Amazon Inspector for EC2 instance package vulnerability findings.
 * Ref: https://schema.ocsf.io/1.1.0/classes/vulnerability_finding
 */
export const OCSFVulnerabilityFindingSchema = z
  .object({
    ...OCSFBaseFindingFields,
    class_uid: z.literal(2002),
    vulnerabilities: z
      .array(
        z
          .object({
            cve: z
              .object({
                uid: z.string().optional(),
                cvss: z.array(z.record(z.string(), z.unknown())).optional(), // OCSF CVSS structure varies by version (2.0/3.0/3.1); z.unknown() is intentional
              })
              .optional(),
            kb_articles: z.array(z.string()).optional(),
            packages: z
              .array(
                z
                  .object({
                    name: z.string().optional(),
                    version: z.string().optional(),
                    architecture: z.string().optional(),
                  })
                  .passthrough(),
              )
              .optional(),
            severity: z.string().optional(),
          })
          .passthrough(),
      )
      .optional(),
  })
  .passthrough();

export type OCSFVulnerabilityFinding = z.infer<typeof OCSFVulnerabilityFindingSchema>;

/**
 * OCSF Detection Finding schema (class_uid 2004) — Amazon GuardDuty
 * (IAM credential compromise).
 * Ref: https://schema.ocsf.io/1.1.0/classes/detection_finding
 */
export const OCSFDetectionFindingSchema = z
  .object({
    ...OCSFBaseFindingFields,
    class_uid: z.literal(2004),
    attacks: z
      .array(
        z
          .object({
            // MITRE ATT&CK tactic/technique objects have variable structure across services; z.unknown() is intentional
            tactic: z.record(z.string(), z.unknown()).optional(),
            technique: z.record(z.string(), z.unknown()).optional(),
          })
          .passthrough(),
      )
      .optional(),
  })
  .passthrough();

export type OCSFDetectionFinding = z.infer<typeof OCSFDetectionFindingSchema>;

/**
 * OCSF Data Security Finding schema (class_uid 2006) — Amazon Macie
 * (sensitive data). This is a distinct OCSF class from Detection Finding, not
 * a Detection subtype; it shares the common finding envelope, so it reuses the
 * shared base fields with its own class_uid literal. ASR routes both through
 * the multi-service OCSF path, but the schemas are kept separate so each
 * class is validated against its own discriminator.
 * Ref: https://schema.ocsf.io/1.1.0/classes/data_security_finding
 */
export const OCSFDataSecurityFindingSchema = z
  .object({
    ...OCSFBaseFindingFields,
    class_uid: z.literal(2006),
  })
  .passthrough();

export type OCSFDataSecurityFinding = z.infer<typeof OCSFDataSecurityFindingSchema>;

export const RemediationStatusEnum = z.enum([
  'NOT_STARTED',
  'SUCCESS',
  'IN_PROGRESS',
  'FAILED',
  // Rollback lifecycle. ROLLBACK_IN_PROGRESS doubles as the optimistic lock on
  // the findings-table row; the terminal states release it.
  'ROLLBACK_IN_PROGRESS',
  'ROLLBACK_SUCCESS',
  'ROLLBACK_FAILED',
]);

// Generate remediation status type from Zod schema
export type remediationStatus = z.infer<typeof RemediationStatusEnum>;

export interface FindingAbstractData {
  findingType: string;
  findingId: FindingId;
  /**
   * The account that owns the resource this finding reports on — i.e. where the
   * resource resides, and where remediation runs. This is NOT always the ASFF
   * `AwsAccountId`: for IAM Access Analyzer organization-analyzer findings the
   * ASFF `AwsAccountId` is the delegated-administrator account, so the value
   * here is taken from `ProductFields.ResourceOwnerAccount` instead (see
   * `FindingDataService.resolveAccountId` on the write path). The stored
   * DynamoDB attribute and the API field keep the name `accountId` for backwards
   * compatibility (it is also the partition key of the
   * `accountId-securityHubUpdatedAtTime` GSI).
   */
  accountId: string;
  resourceId: string;
  resourceType: string;
  resourceTypeNormalized: string;
  severity: string;
  region: string;
  remediationStatus: remediationStatus;
  lastUpdatedTime: string;
  error?: string;
  executionId?: string;
}
// Base interface for fields that should be in API response
export interface FindingBaseData extends FindingAbstractData {
  findingDescription: string;
  securityHubUpdatedAtTime: string;
  suppressed: boolean;
  creationTime: string;
}

// API response
export interface FindingApiResponse extends FindingBaseData {
  consoleLink: string;
}

export interface FindingTableItem extends FindingBaseData {
  // Table-specific fields that shouldn't be exposed in API
  'securityHubUpdatedAtTime#findingId': string;
  'severityNormalized#securityHubUpdatedAtTime#findingId': string;
  findingJSON: Uint8Array<ArrayBufferLike>;
  findingIdControl: string;
  FINDING_CONSTANT: 'finding';
  lastUpdatedBy?: string;
  expireAt: number;
  severityNormalized: number;
  remediationStatusDetail?: string;
  // When Security Hub first observed the underlying issue (ASFF `FirstObservedAt`
  // / OCSF `finding_info.first_seen_time_dt`). Absent when the finding source did
  // not populate it. Read by the Orchestrator to report Mean Time To Remediate.
  firstDetectedTime?: string;
  // Metric-enrichment flags captured at ingestion: whether an enabled finding-type
  // notification config matches this finding (hasFindingNotificationsEnabled) and
  // whether any matching config configures a remediation deadline
  // (hasFindingRemediationDeadlineConfigured). Read by the Orchestrator on successful
  // remediation. Absent for findings ingested before these flags existed.
  hasFindingNotificationsEnabled?: boolean;
  hasFindingRemediationDeadlineConfigured?: boolean;
  remediationDueBy?: string;
  // Number of times auto-remediation has been triggered for this finding.
  // Incremented atomically each time the pre-processor launches a remediation
  // and read back by the retry-cap gate to bound retries on a
  // deterministically-failing finding (prevents auto-remediation re-trigger
  // storms). Absent means zero.
  remediationAttempts?: number;
  // ISO 8601 timestamp of the most recent auto-remediation trigger. Paired with
  // remediationAttempts to enforce a cooldown between retries so retries are
  // spaced out rather than fired back-to-back. Absent means no attempt recorded.
  lastRemediationAttemptTime?: string;
  // ISO 8601 timestamp set when a rollback acquires the optimistic lock
  // (status -> ROLLBACK_IN_PROGRESS). Used only for the stale-lock timeout; not
  // part of any index. Absent means no active rollback lock.
  rollbackStartedAt?: string;
  // S3 object key of the IAM config backup from a successful GuardDuty Contain.
  // Optionally populated from history data (buildFindingTableItemFromHistoryEntry)
  // onto the rollback finding so the API can pass it as BackupS3KeyName to the
  // runbook. Absent when there is no captured backup key.
  rollbackBackupKey?: string;
  // Stored as DynamoDB String Set (SS). Must be converted to Array before JSON serialization.
  enforcementConfigIds?: Set<string>;
}

// Custom error for invalid finding schemas
export class InvalidFindingSchemaError extends Error {
  constructor(supportedSchemas: string[]) {
    super(`Finding schema is not ${supportedSchemas.join(' or ')}.`);
    this.name = 'InvalidFindingSchemaError';
  }
}

// Remediation History schema and types
export interface RemediationHistoryBaseData extends FindingAbstractData {
  lastUpdatedBy: string;
  error?: string;
  findingJSON?: Uint8Array;
  // S3 object key of the IAM config backup written by a successful GuardDuty
  // Contain. Read on rollback to supply BackupS3KeyName to the runbook.
  rollbackBackupKey?: string;
}

// API response for remediation history
export interface RemediationHistoryApiResponse extends RemediationHistoryBaseData {
  consoleLink: string;
  isRollbackEligible?: boolean;
}

// Table item for remediation history
export interface RemediationHistoryTableItem extends RemediationHistoryBaseData {
  // Table-specific fields
  'findingId#executionId': string;
  'lastUpdatedTime#findingId': string;
  REMEDIATION_CONSTANT: 'remediation';
  expireAt: number;
}

// Generate TypeScript types from Zod schemas
export type ASFFFinding = z.infer<typeof ASFFSchema>;
export type OCSFComplianceFinding = z.infer<typeof OCSFComplianceSchema>;
