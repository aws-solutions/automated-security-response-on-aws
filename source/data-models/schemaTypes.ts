// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { z } from 'zod';

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
    ProductFields: z.record(z.string()).optional(),
    UserDefinedFields: z.record(z.string()).optional(),
    Malware: z.array(z.record(z.any())).optional(),
    Network: z.record(z.any()).optional(),
    NetworkPath: z.array(z.record(z.any())).optional(),
    Process: z.record(z.any()).optional(),
    ThreatIntelIndicators: z.array(z.record(z.any())).optional(),
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
            Result: z.record(z.any()).optional(),
          })
          .optional(),
        Details: z.record(z.any()).optional(),
      }),
    ),
    Compliance: z.object({
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
    }),
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
    Vulnerabilities: z.array(z.record(z.any())).optional(),
    PatchSummary: z.record(z.any()).optional(),
    Action: z.record(z.any()).optional(),
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
          data: z.record(z.any()).optional(),
        })
        .refine((resource) => resource.uid || resource.uid_alt || resource.name, {
          message: "At least one of 'uid', 'uid_alt', or 'name' must be defined",
        }),
    ),
    api: z
      .object({
        group: z.record(z.any()).optional(),
        operation: z.string(),
        request: z
          .object({
            containers: z.array(z.record(z.any())).optional(),
            data: z.record(z.any()).optional(),
            flags: z.array(z.string()).optional(),
            uid: z.string(),
          })
          .optional(),
        response: z
          .object({
            code: z.number().optional(),
            containers: z.array(z.record(z.any())).optional(),
            data: z.record(z.any()).optional(),
            error: z.string().optional(),
            error_message: z.string().optional(),
            flags: z.array(z.string()).optional(),
            message: z.string().optional(),
          })
          .optional(),
        service: z.record(z.any()).optional(),
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
        extension: z.record(z.any()).optional(),
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
          data: z.record(z.any()).optional(),
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

const RemediationStatusEnum = z.enum(['NOT_STARTED', 'SUCCESS', 'IN_PROGRESS', 'FAILED']);

// Generate remediation status type from Zod schema
export type remediationStatus = z.infer<typeof RemediationStatusEnum>;

export interface FindingAbstractData {
  findingType: string;
  findingId: string;
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
}

// API response for remediation history
export interface RemediationHistoryApiResponse extends RemediationHistoryBaseData {
  consoleLink: string;
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
