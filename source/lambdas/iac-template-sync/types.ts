// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { z } from 'zod';

/** The known IaC template formats supported by the solution. */
export type IaCTemplateFormat = 'cloudformation' | 'terraform' | 'cdk';

const iacTemplateFormatSchema = z.enum(['cloudformation', 'terraform', 'cdk']);

const templateEntrySchema = z.object({
  controlId: z.string(),
  iacFormat: iacTemplateFormatSchema,
  s3Key: z.string(),
  sha256: z.string(),
});

/** Zod schema for runtime validation of manifest JSON. */
export const manifestSchema = z.object({
  schemaVersion: z.literal('1.0'),
  generatedAt: z.string(),
  solutionVersion: z.string(),
  templates: z.array(templateEntrySchema),
});

/**
 * A single entry in the manifest's templates array, representing one IaC
 * remediation template with its location and integrity checksum.
 */
export interface TemplateEntry {
  controlId: string;
  iacFormat: IaCTemplateFormat;
  s3Key: string;
  sha256: string;
}

/**
 * The manifest schema written to `.metadata/manifest.json` in the customer
 * bucket. Matches the output of `generate-iac-manifest.js` at build time.
 */
export interface Manifest {
  schemaVersion: '1.0';
  generatedAt: string;
  solutionVersion: string;
  templates: TemplateEntry[];
}

/**
 * Result of diffing an existing manifest against an incoming manifest.
 * The four categories partition all unique s3Keys without overlap.
 */
export interface DiffResult {
  added: TemplateEntry[];
  updated: TemplateEntry[];
  unchanged: TemplateEntry[];
  deprecated: TemplateEntry[];
}

/** Resource properties passed from CloudFormation via event.ResourceProperties. */
export interface ResourceProperties {
  SolutionsBucketName: string;
  CustomerBucketName: string;
  ManifestKey: string;
  SolutionVersion: string;
  TemplatePrefix: string;
}

/** The result returned by each handler method (CREATE, UPDATE, DELETE). */
export interface SyncResult {
  status: 'SUCCESS' | 'FAILED';
  data: { Message: string };
}
