// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * Finding format indicator for downstream components (Orchestrator, control runbooks).
 * - ASFF: AWS Security Finding Format (Config, IAM Access Analyzer from Security Hub CSPM)
 * - OCSF: Open Cybersecurity Schema Framework (Inspector, GuardDuty, Macie from Security Hub v2)
 */
export type FindingFormat = 'ASFF' | 'OCSF';

/**
 * Discriminated union for finding type identifiers.
 * Standard Security Hub controls use SecurityControlId (e.g. "EC2.1").
 * Multi-service findings use a remediation identifier (e.g. "GuardDuty.IAMUser").
 */
export interface SecurityControlId {
  type: 'securityControl';
  value: string;
}

export interface MultiServiceIdentifier {
  type: 'multiService';
  value: string;
}

export type FindingTypeIdentifier = SecurityControlId | MultiServiceIdentifier;

/** Re-use existing types from schemaTypes for consistency */
import type { ASFFSeverity, ASFFComplianceStatus, ASFFRecordState, ASFFWorkflowStatus, JsonValue } from './schemaTypes';

export interface NormalizedResource {
  type: string;
  id: string;
  region?: string;
  tags?: Record<string, string | undefined>;
  details?: Record<string, JsonValue>;
}

/**
 * Schema-agnostic finding representation used throughout the Pre-Processor pipeline.
 *
 * Created by parsing the raw finding against its Zod schema and mapping to this
 * common shape. All downstream methods (filters, persistence, notifications,
 * orchestrator) work with this interface instead of ASFFFinding directly.
 *
 * The `raw` field preserves the original payload so the Orchestrator receives
 * the finding in its native format (ASFF or OCSF).
 */
export interface NormalizedFinding {
  id: string;
  productArn: string;
  findingTypeIdentifier: FindingTypeIdentifier;
  accountId: string;
  region: string;
  severity: ASFFSeverity;
  complianceStatus: ASFFComplianceStatus;
  recordState: ASFFRecordState;
  workflowStatus: ASFFWorkflowStatus;
  resources: NormalizedResource[];
  title: string;
  description: string;
  createdAt: string;
  updatedAt: string;
  /**
   * When Security Hub first observed the underlying issue (ASFF `FirstObservedAt`
   * / OCSF `finding_info.first_seen_time_dt`). Optional because not every finding
   * source populates it. Persisted to the Findings table as `firstDetectedTime`
   * and used to compute Mean Time To Remediate.
   */
  firstObservedAt?: string;
  productFields?: Record<string, string>;
  format: FindingFormat;
  raw: Record<string, unknown>;
}
