// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { toAsffShape, getRemediationIdentifier, resolveFindingType } from '../Normalizer/normalizedFindingAdapter';
import { UnresolvableControlIdError } from '../../common/utils/findingUtils';
import { NormalizedFinding } from '@asr/data-models';

const createNormalizedFinding = (overrides: Partial<NormalizedFinding> = {}): NormalizedFinding => ({
  id: 'arn:aws:securityhub:us-east-1:123456789012:security-control/S3.1/finding/abc-123',
  productArn: 'arn:aws:securityhub:us-east-1::product/aws/securityhub',
  findingTypeIdentifier: { type: 'securityControl', value: 'S3.1' },
  accountId: '123456789012',
  region: 'us-east-1',
  severity: 'HIGH',
  complianceStatus: 'FAILED',
  recordState: 'ACTIVE',
  workflowStatus: 'NEW',
  resources: [{ type: 'AwsS3Bucket', id: 'arn:aws:s3:::test-bucket', region: 'us-east-1' }],
  title: 'S3 buckets should have server-side encryption enabled',
  description: 'This control checks...',
  createdAt: '2024-01-01T00:00:00Z',
  updatedAt: '2024-01-01T00:00:00Z',
  format: 'ASFF',
  raw: {},
  ...overrides,
});

describe('normalizedFindingAdapter', () => {
  describe('toAsffShape', () => {
    it('should include ProductFields when present', () => {
      // Arrange
      const normalized = createNormalizedFinding({
        productFields: {
          StandardsControlArn: 'arn:aws:securityhub:us-east-1:123456789012:control/afsbp/v/1.0.0/S3.1',
          'aws/securityhub/ProductName': 'Security Hub',
        },
      });

      // Act
      const result = toAsffShape(normalized);

      // Assert
      expect(result.ProductFields).toEqual({
        StandardsControlArn: 'arn:aws:securityhub:us-east-1:123456789012:control/afsbp/v/1.0.0/S3.1',
        'aws/securityhub/ProductName': 'Security Hub',
      });
    });

    it('should set ProductFields to undefined when not present', () => {
      // Arrange
      const normalized = createNormalizedFinding();

      // Act
      const result = toAsffShape(normalized);

      // Assert
      expect(result.ProductFields).toBeUndefined();
    });

    it('should include resource Details when present', () => {
      // Arrange
      const normalized = createNormalizedFinding({
        resources: [
          {
            type: 'AwsS3Bucket',
            id: 'arn:aws:s3:::test-bucket',
            region: 'us-east-1',
            details: { AwsS3Bucket: { BucketName: 'test-bucket' } },
          },
        ],
      });

      // Act
      const result = toAsffShape(normalized);

      // Assert
      expect(result.Resources[0].Details).toEqual({ AwsS3Bucket: { BucketName: 'test-bucket' } });
    });

    it('should set resource Details to undefined when not present', () => {
      // Arrange
      const normalized = createNormalizedFinding();

      // Act
      const result = toAsffShape(normalized);

      // Assert
      expect(result.Resources[0].Details).toBeUndefined();
    });

    it('maps firstObservedAt to FirstObservedAt when present and omits it otherwise', () => {
      // ARRANGE / ACT
      const withFirstObserved = toAsffShape(createNormalizedFinding({ firstObservedAt: '2024-01-05T00:00:00Z' }));
      const withoutFirstObserved = toAsffShape(createNormalizedFinding());

      // ASSERT
      expect(withFirstObserved.FirstObservedAt).toBe('2024-01-05T00:00:00Z');
      expect(withoutFirstObserved.FirstObservedAt).toBeUndefined();
    });

    it('should pass through Vulnerabilities[] from raw for Inspector findings', () => {
      // The Inspector control runbook drives patching from
      // Vulnerabilities[0].VulnerablePackages[] (Name + Architecture). The API
      // replay path reads from DDB-stored ASFF, so this passthrough is what
      // makes the UI "Remediate" button actually patch instead of failing
      // with "No vulnerabilities found in finding".
      const inspectorVulnerabilities = [
        {
          Id: 'CVE-2025-14524',
          FixAvailable: 'YES',
          VulnerablePackages: [
            {
              Name: 'curl',
              Architecture: 'X86_64',
              Version: '8.3.0',
              FixedInVersion: '0:8.3.0-1.amzn2.0.12',
            },
            {
              Name: 'libcurl',
              Architecture: 'X86_64',
              Version: '8.3.0',
              FixedInVersion: '0:8.3.0-1.amzn2.0.12',
            },
          ],
        },
      ];
      const normalized = createNormalizedFinding({
        findingTypeIdentifier: { type: 'multiService', value: 'Inspector.InstanceVulnerability' },
        raw: { Vulnerabilities: inspectorVulnerabilities } as Record<string, unknown>,
      });

      const result = toAsffShape(normalized);

      expect(result.Vulnerabilities).toEqual(inspectorVulnerabilities);
    });

    it('should leave Vulnerabilities undefined when raw has none (non-Inspector findings)', () => {
      const normalized = createNormalizedFinding({ raw: {} });
      const result = toAsffShape(normalized);
      expect(result.Vulnerabilities).toBeUndefined();
    });

    it('should ignore non-array Vulnerabilities in raw (defensive)', () => {
      // The passthrough is an Array.isArray check, so a malformed raw payload
      // with Vulnerabilities as a string/object/null doesn't pollute the
      // stored ASFF or trip downstream consumers that expect a list.
      const normalized = createNormalizedFinding({
        raw: { Vulnerabilities: 'not-an-array' } as Record<string, unknown>,
      });
      const result = toAsffShape(normalized);
      expect(result.Vulnerabilities).toBeUndefined();
    });
  });

  describe('getRemediationIdentifier', () => {
    it('should return the finding type identifier value', () => {
      // Arrange
      const normalized = createNormalizedFinding();

      // Act
      const result = getRemediationIdentifier(normalized);

      // Assert
      expect(result).toBe('S3.1');
    });
  });

  describe('resolveFindingType', () => {
    it('returns the remediation id for a multi-service finding', () => {
      // Arrange
      const normalized = createNormalizedFinding({
        id: '9f8e7d6c5b4a392817060f1e2d3c4b5a',
        findingTypeIdentifier: { type: 'multiService', value: 'Macie.SensitiveDataS3Object' },
      });

      // Act
      const result = resolveFindingType(normalized);

      // Assert — the mapper's id IS the key, and it is the only source: the bare-hash finding id
      // carries nothing to derive from
      expect(result).toBe('Macie.SensitiveDataS3Object');
    });

    it('derives the prefixed form from the ARN for a Security Hub control finding', () => {
      // Arrange — findingTypeIdentifier.value here is the bare `S3.1`, which is NOT a partition key
      const normalized = createNormalizedFinding();

      // Act
      const result = resolveFindingType(normalized);

      // Assert
      expect(result).toBe('security-control/S3.1');
    });

    it('throws for a control finding whose id is not a parseable Security Hub ARN', () => {
      // Arrange
      const normalized = createNormalizedFinding({ id: 'not-an-arn' });

      // Act / Assert — refuses to fall back to the bare control id
      expect(() => resolveFindingType(normalized)).toThrow(UnresolvableControlIdError);
    });
  });
});
