// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { deflate } from 'pako';
import { ASFFFinding, FindingTableItem } from '@asr/data-models';
import { buildOrchestratorInput, extractASFFFinding } from '../utils/findingExtraction';
import type { Clock } from '../utils/clock';
import type { IdGenerator } from '../utils/idGenerator';

describe('buildOrchestratorInput', () => {
  const FIXED_TIME = new Date('2026-01-02T03:04:05.000Z');
  const idGenerator: IdGenerator = { randomUUID: () => 'fixed-uuid' };
  const clock: Clock = { now: () => FIXED_TIME };

  const asffFinding = {
    AwsAccountId: '111111111111',
    Region: 'us-east-1',
    Id: 'finding-1',
  } as unknown as ASFFFinding;

  const parse = (s: string) => JSON.parse(s);

  it('builds the base Security Hub API-action envelope', () => {
    const result = parse(buildOrchestratorInput('S3.1', asffFinding, 'Remediate', idGenerator, clock));

    expect(result).toMatchObject({
      version: '0',
      id: 'fixed-uuid',
      'detail-type': 'Security Hub Findings - API Action',
      source: 'aws.securityhub',
      account: '111111111111',
      region: 'us-east-1',
      time: FIXED_TIME.toISOString(),
    });
    expect(result.resources).toEqual(['arn:aws:securityhub:us-east-1:111111111111:action/custom/api-remediate']);
    expect(result.detail.actionName).toBe('Remediate with ASR');
    expect(result.detail.actionDescription).toBe('API-triggered Remediate');
    expect(result.detail.findings).toEqual([asffFinding]);
  });

  it('omits the multi-service envelope for a non-multi-service remediation id', () => {
    const { detail } = parse(buildOrchestratorInput('S3.1', asffFinding, 'Remediate', idGenerator, clock));
    expect(detail.findingType).toBeUndefined();
    expect(detail.remediationId).toBeUndefined();
    expect(detail.findingFormat).toBeUndefined();
    expect(detail.docParameters).toBeUndefined();
  });

  it('adds the multi-service routing envelope for a multi-service remediation id', () => {
    const { detail } = parse(buildOrchestratorInput('GuardDuty.IAMUser', asffFinding, 'Remediate', idGenerator, clock));
    expect(detail.findingType).toBe('multiService');
    expect(detail.remediationId).toBe('GuardDuty.IAMUser');
    expect(detail.findingFormat).toBe('ASFF');
  });

  it('adds Restore docParameters with the backup key for a Rollback action', () => {
    const { detail } = parse(
      buildOrchestratorInput('GuardDuty.IAMUser', asffFinding, 'Rollback', idGenerator, clock, 'backups/key-1.json'),
    );
    expect(detail.actionName).toBe('ASR:Rollback');
    expect(detail.docParameters).toEqual({ Action: 'Restore', BackupS3KeyName: 'backups/key-1.json' });
  });

  it('adds Restore docParameters without a backup key when none is provided', () => {
    const { detail } = parse(buildOrchestratorInput('GuardDuty.IAMUser', asffFinding, 'Rollback', idGenerator, clock));
    expect(detail.docParameters).toEqual({ Action: 'Restore' });
  });
});

describe('extractASFFFinding (Property 13: remediation extraction round-trip)', () => {
  const buildItemFromAsff = (asffFinding: ASFFFinding): FindingTableItem =>
    ({ findingJSON: deflate(JSON.stringify(asffFinding)) }) as unknown as FindingTableItem;

  const minimalAsffFinding: ASFFFinding = {
    SchemaVersion: '2018-10-08',
    Id: 'arn:aws:securityhub:us-east-1:111111111111:finding/minimal',
    ProductArn: 'arn:aws:securityhub:us-east-1::product/aws/securityhub',
    GeneratorId: 'security-control/S3.1',
    AwsAccountId: '111111111111',
    Types: [],
    CreatedAt: '2025-01-01T00:00:00Z',
    UpdatedAt: '2025-01-01T00:00:00Z',
    Severity: {},
    Title: 'Minimal Finding',
    Resources: [],
    Compliance: { SecurityControlId: 'S3.1' },
  };

  it('round-trips a minimal ASFF finding', () => {
    // ARRANGE
    const item = buildItemFromAsff(minimalAsffFinding);

    // ACT
    const extracted = extractASFFFinding(item);

    // ASSERT
    expect(extracted).toEqual(minimalAsffFinding);
  });

  it('round-trips an ASFF finding populated with the full set of fields', () => {
    // ARRANGE
    const fullAsffFinding: ASFFFinding = {
      ...minimalAsffFinding,
      Id: 'arn:aws:securityhub:us-east-1:111111111111:finding/full',
      ProductName: 'Security Hub',
      CompanyName: 'AWS',
      Region: 'us-east-1',
      Types: ['Software and Configuration Checks/Industry and Regulatory Standards'],
      FirstObservedAt: '2025-01-01T00:00:00Z',
      LastObservedAt: '2025-01-02T00:00:00Z',
      Severity: { Label: 'HIGH', Normalized: 70, Original: 'HIGH' },
      Title: 'Full Finding',
      Description: 'A finding populated with every commonly used field',
      Remediation: { Recommendation: { Text: 'Fix it', Url: 'https://example.com/fix' } },
      ProductFields: { 'aws/securityhub/ProductName': 'Security Hub' },
      UserDefinedFields: { owner: 'team-security' },
      Resources: [
        {
          Type: 'AwsS3Bucket',
          Id: 'arn:aws:s3:::my-bucket',
          Partition: 'aws',
          Region: 'us-east-1',
          Tags: { Environment: 'production', Team: 'security' },
        },
      ],
      Compliance: {
        Status: 'FAILED',
        RelatedRequirements: ['PCI DSS 3.2.1'],
        SecurityControlId: 'S3.1',
        AssociatedStandards: [{ StandardsId: 'standards/aws-foundational-security-best-practices/v/1.0.0' }],
      },
      Workflow: { Status: 'NEW' },
      RecordState: 'ACTIVE',
    };
    const item = buildItemFromAsff(fullAsffFinding);

    // ACT
    const extracted = extractASFFFinding(item);

    // ASSERT
    expect(extracted).toEqual(fullAsffFinding);
  });

  it('round-trips an ASFF finding containing special and unicode characters', () => {
    // ARRANGE
    const specialCharactersFinding: ASFFFinding = {
      ...minimalAsffFinding,
      Id: 'arn:aws:securityhub:us-east-1:111111111111:finding/special-"quotes"-&-<tags>',
      Title: 'Finding with "quotes", \\backslashes\\, newlines\n and emoji 🔐',
      Description: 'Unicode: Ñoño, 日本語, 🚀 — and control text: tab\tend',
      Resources: [{ Type: 'AwsS3Bucket', Id: 'arn:aws:s3:::bucket-with-Ünïcödé' }],
    };
    const item = buildItemFromAsff(specialCharactersFinding);

    // ACT
    const extracted = extractASFFFinding(item);

    // ASSERT
    expect(extracted).toEqual(specialCharactersFinding);
    expect(extracted.Title).toContain('🔐');
  });

  it('throws when findingJSON is missing', () => {
    // ARRANGE
    const item = {} as unknown as FindingTableItem;

    // ACT / ASSERT
    expect(() => extractASFFFinding(item)).toThrow(/Failed to extract ASFF finding/);
  });

  it('throws when findingJSON is corrupted', () => {
    // ARRANGE: bytes that are not valid zlib-compressed data
    const item = { findingJSON: new Uint8Array([1, 2, 3, 4, 5]) } as unknown as FindingTableItem;

    // ACT / ASSERT
    expect(() => extractASFFFinding(item)).toThrow(/Failed to extract ASFF finding/);
  });
});
