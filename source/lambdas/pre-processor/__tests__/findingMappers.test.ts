// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import {
  asffToNormalized,
  ocsfComplianceToNormalized,
  ocsfVulnerabilityToNormalized,
  ocsfDetectionToNormalized,
} from '../Normalizer/findingMappers';
import { ASFFFinding, OCSFComplianceFinding, OCSFVulnerabilityFinding, OCSFDetectionFinding } from '@asr/data-models';

const createAsffFinding = (overrides: Partial<ASFFFinding> = {}): ASFFFinding =>
  ({
    SchemaVersion: '2018-10-08',
    Id: 'arn:aws:securityhub:us-east-1:123456789012:finding/test-1',
    ProductArn: 'arn:aws:securityhub:us-east-1::product/aws/securityhub',
    GeneratorId: 'security-control/S3.1',
    AwsAccountId: '123456789012',
    Types: ['Software and Configuration Checks'],
    Region: 'us-east-1',
    CreatedAt: '2024-01-01T00:00:00Z',
    UpdatedAt: '2024-01-01T00:00:00Z',
    Title: 'Test Finding',
    Severity: { Label: 'HIGH' },
    Compliance: { Status: 'FAILED', SecurityControlId: 'S3.1' },
    RecordState: 'ACTIVE',
    Workflow: { Status: 'NEW' },
    Resources: [{ Type: 'AwsS3Bucket', Id: 'arn:aws:s3:::test-bucket' }],
    ...overrides,
  }) as ASFFFinding;

const createOcsfComplianceFinding = (overrides: Partial<OCSFComplianceFinding> = {}): OCSFComplianceFinding =>
  ({
    class_uid: 2003,
    activity_id: 1,
    category_uid: 2,
    severity_id: 4,
    type_uid: 200301,
    time: 1704067200,
    severity: 'High',
    cloud: { account: { uid: '123456789012' }, region: 'us-east-1' },
    finding_info: { uid: 'ocsf-finding-1', title: 'Test', created_time_dt: '2024-01-01T00:00:00Z' },
    compliance: { control: 'S3.1', status: 'fail', standards: ['AWS Foundational Security Best Practices'] },
    resources: [
      {
        type: 'AWS::S3::Bucket',
        uid: 'test-bucket',
        uid_alt: 'arn:aws:s3:::test-bucket',
        owner: { account: { uid: '123456789012' } },
      },
    ],
    metadata: { product: { name: 'Security Hub' } },
    ...overrides,
  }) as OCSFComplianceFinding;

const createOcsfVulnerabilityFinding = (overrides: Partial<OCSFVulnerabilityFinding> = {}): OCSFVulnerabilityFinding =>
  ({
    class_uid: 2002,
    activity_id: 1,
    category_uid: 2,
    type_uid: 200201,
    time: 1704067200,
    severity: 'High',
    cloud: { account: { uid: '123456789012' }, region: 'us-east-1' },
    finding_info: {
      uid: 'inspector-finding-1',
      types: ['Software and Configuration Checks/Vulnerabilities/CVE'],
      title: 'CVE-2024-1234',
      created_time_dt: '2024-01-01T00:00:00Z',
    },
    resources: [{ type: 'AWS::EC2::Instance', uid: 'i-1234567890abcdef0' }],
    metadata: { product: { name: 'Inspector' } },
    ...overrides,
  }) as OCSFVulnerabilityFinding;

const createOcsfDetectionFinding = (overrides: Partial<OCSFDetectionFinding> = {}): OCSFDetectionFinding =>
  ({
    class_uid: 2004,
    activity_id: 1,
    category_uid: 2,
    type_uid: 200401,
    time: 1704067200,
    severity: 'High',
    cloud: { account: { uid: '123456789012' }, region: 'us-east-1' },
    finding_info: {
      uid: 'guardduty-finding-1',
      types: ['TTPs/Initial Access'],
      title: 'Compromised IAM credentials',
      created_time_dt: '2024-01-01T00:00:00Z',
    },
    resources: [{ type: 'AWS::IAM::AccessKey', uid: 'AKIAIOSFODNN7EXAMPLE' }],
    metadata: { product: { name: 'GuardDuty' } },
    ...overrides,
  }) as OCSFDetectionFinding;

describe('findingMappers', () => {
  describe('asffToNormalized', () => {
    it('should extract tags from ASFF resources', () => {
      // Arrange
      const finding = createAsffFinding({
        Resources: [
          {
            Type: 'AwsS3Bucket',
            Id: 'arn:aws:s3:::test-bucket',
            Region: 'us-east-1',
            Tags: { Environment: 'production', Team: 'security' },
          },
        ],
      });

      // Act
      const result = asffToNormalized(finding);

      // Assert
      expect(result.resources[0].tags).toEqual({ Environment: 'production', Team: 'security' });
    });

    it('should handle ASFF resources without tags', () => {
      // Arrange
      const finding = createAsffFinding();

      // Act
      const result = asffToNormalized(finding);

      // Assert
      expect(result.resources[0].tags).toBeUndefined();
    });

    it('should pass through ProductFields from ASFF finding', () => {
      // Arrange
      const finding = createAsffFinding({
        ProductFields: {
          StandardsControlArn:
            'arn:aws:securityhub:us-east-1:123456789012:control/aws-foundational-security-best-practices/v/1.0.0/S3.1',
          'aws/securityhub/ProductName': 'Security Hub',
        },
      });

      // Act
      const result = asffToNormalized(finding);

      // Assert
      expect(result.productFields).toEqual({
        StandardsControlArn:
          'arn:aws:securityhub:us-east-1:123456789012:control/aws-foundational-security-best-practices/v/1.0.0/S3.1',
        'aws/securityhub/ProductName': 'Security Hub',
      });
    });

    it('should handle ASFF finding without ProductFields', () => {
      // Arrange
      const finding = createAsffFinding();

      // Act
      const result = asffToNormalized(finding);

      // Assert
      expect(result.productFields).toBeUndefined();
    });

    it('should extract Details from ASFF resources', () => {
      // Arrange
      const finding = createAsffFinding({
        Resources: [
          {
            Type: 'AwsS3Bucket',
            Id: 'arn:aws:s3:::test-bucket',
            Details: { AwsS3Bucket: { BucketName: 'test-bucket', CreatedAt: '2024-01-01' } },
          },
        ],
      });

      // Act
      const result = asffToNormalized(finding);

      // Assert
      expect(result.resources[0].details).toEqual({
        AwsS3Bucket: { BucketName: 'test-bucket', CreatedAt: '2024-01-01' },
      });
    });

    it('should handle ASFF resources without Details', () => {
      // Arrange
      const finding = createAsffFinding();

      // Act
      const result = asffToNormalized(finding);

      // Assert
      expect(result.resources[0].details).toBeUndefined();
    });

    it('should handle ASFF finding without Compliance by deriving controlId from native ARN', () => {
      // Real IAM Access Analyzer findings reach ASR without a Compliance block.
      // The mapper must fall back to deriving the controlId from the finding ARN
      // and default the compliance status to NOT_AVAILABLE. The caller overrides
      // findingTypeIdentifier with the multi-service mapping immediately after,
      // so the value populated here is best-effort but must not throw.
      const finding = createAsffFinding({
        Id: 'arn:aws:access-analyzer:us-east-1:123456789012:analyzer/test-analyzer/arn:aws:kms:us-east-1:123456789012:key/00000000-0000-0000-0000-000000000000',
        ProductArn: 'arn:aws:securityhub:us-east-1::product/aws/access-analyzer',
        GeneratorId: 'aws/access-analyzer',
        Compliance: undefined,
        Resources: [
          {
            Type: 'AwsKmsKey',
            Id: 'arn:aws:kms:us-east-1:123456789012:key/00000000-0000-0000-0000-000000000000',
          },
        ],
      });

      const result = asffToNormalized(finding);

      expect(result.findingTypeIdentifier).toEqual({
        type: 'securityControl',
        value: 'IAMAccessAnalyzer.ExternalAccess',
      });
      expect(result.complianceStatus).toBe('NOT_AVAILABLE');
    });

    it('should default findingTypeIdentifier value to empty string when controlId cannot be derived', () => {
      // Defensive: if a finding lacks both Compliance and a recognizable native
      // ARN prefix, the mapper must still produce a NormalizedFinding rather
      // than throwing. The downstream remediation lookup will reject it.
      const finding = createAsffFinding({
        Id: 'arn:aws:cloudtrail:us-east-1:123456789012:trail/unknown-source',
        Compliance: undefined,
      });

      const result = asffToNormalized(finding);

      expect(result.findingTypeIdentifier.value).toBe('');
      expect(result.complianceStatus).toBe('NOT_AVAILABLE');
    });

    it('maps ASFF FirstObservedAt to firstObservedAt and leaves it undefined when absent', () => {
      // ARRANGE / ACT
      const withFirstObserved = asffToNormalized(createAsffFinding({ FirstObservedAt: '2024-01-05T00:00:00Z' }));
      const withoutFirstObserved = asffToNormalized(createAsffFinding());

      // ASSERT
      expect(withFirstObserved.firstObservedAt).toBe('2024-01-05T00:00:00Z');
      expect(withoutFirstObserved.firstObservedAt).toBeUndefined();
    });
  });

  describe('ocsfComplianceToNormalized', () => {
    it('should convert OCSF tags array to Record format', () => {
      // Arrange
      const finding = createOcsfComplianceFinding({
        resources: [
          {
            type: 'AWS::S3::Bucket',
            uid: 'test-bucket',
            uid_alt: 'arn:aws:s3:::test-bucket',
            owner: { account: { uid: '123456789012' } },
            tags: [
              { name: 'Environment', value: 'staging' },
              { name: 'CostCenter', value: '12345' },
            ],
          },
        ],
      });
      const asffNormalized = {} as ASFFFinding;

      // Act
      const result = ocsfComplianceToNormalized(finding, asffNormalized);

      // Assert
      expect(result.resources[0].tags).toEqual({ Environment: 'staging', CostCenter: '12345' });
    });

    it('should handle OCSF compliance resources without tags', () => {
      // Arrange
      const finding = createOcsfComplianceFinding();
      const asffNormalized = {} as ASFFFinding;

      // Act
      const result = ocsfComplianceToNormalized(finding, asffNormalized);

      // Assert
      expect(result.resources[0].tags).toBeUndefined();
    });

    it('should pass through ProductFields from ASFF-normalized finding', () => {
      // Arrange
      const finding = createOcsfComplianceFinding();
      const asffNormalized = createAsffFinding({
        ProductFields: {
          'aws/securityhub/ProductName': 'Security Hub',
          'aws/securityhub/findingId': 'ocsf-finding-1',
        },
      });

      // Act
      const result = ocsfComplianceToNormalized(finding, asffNormalized);

      // Assert
      expect(result.productFields).toEqual({
        'aws/securityhub/ProductName': 'Security Hub',
        'aws/securityhub/findingId': 'ocsf-finding-1',
      });
    });

    it('should extract resource data as details', () => {
      // Arrange
      const finding = createOcsfComplianceFinding({
        resources: [
          {
            type: 'AWS::S3::Bucket',
            uid: 'test-bucket',
            uid_alt: 'arn:aws:s3:::test-bucket',
            owner: { account: { uid: '123456789012' } },
            data: { BucketLifecycleConfiguration: { Rules: [] } },
          },
        ],
      });
      const asffNormalized = createAsffFinding();

      // Act
      const result = ocsfComplianceToNormalized(finding, asffNormalized);

      // Assert
      expect(result.resources[0].details).toEqual({ BucketLifecycleConfiguration: { Rules: [] } });
    });

    it('should handle OCSF compliance resources without data', () => {
      // Arrange
      const finding = createOcsfComplianceFinding();
      const asffNormalized = createAsffFinding();

      // Act
      const result = ocsfComplianceToNormalized(finding, asffNormalized);

      // Assert
      expect(result.resources[0].details).toBeUndefined();
    });

    it('maps OCSF first_seen_time_dt to firstObservedAt and leaves it undefined when absent', () => {
      // ARRANGE / ACT
      const asffNormalized = createAsffFinding();
      const withFirstObserved = ocsfComplianceToNormalized(
        createOcsfComplianceFinding({
          finding_info: {
            uid: 'ocsf-finding-1',
            created_time_dt: '2024-01-01T00:00:00Z',
            first_seen_time_dt: '2024-01-05T00:00:00Z',
          },
        }),
        asffNormalized,
      );
      const withoutFirstObserved = ocsfComplianceToNormalized(createOcsfComplianceFinding(), asffNormalized);

      // ASSERT
      expect(withFirstObserved.firstObservedAt).toBe('2024-01-05T00:00:00Z');
      expect(withoutFirstObserved.firstObservedAt).toBeUndefined();
    });
  });

  describe('ocsfVulnerabilityToNormalized', () => {
    it('should extract tags from OCSF vulnerability resources', () => {
      // Arrange
      const finding = createOcsfVulnerabilityFinding({
        resources: [
          {
            type: 'AWS::EC2::Instance',
            uid: 'i-1234567890abcdef0',
            tags: [
              { name: 'Name', value: 'web-server-1' },
              { name: 'Environment', value: 'production' },
            ],
          },
        ],
      });
      const mapping = { remediationId: 'Inspector.InstanceVulnerability', findingFormat: 'OCSF' as const };

      // Act
      const result = ocsfVulnerabilityToNormalized(finding, mapping);

      // Assert
      expect(result.resources[0].tags).toEqual({ Name: 'web-server-1', Environment: 'production' });
    });

    it('should handle OCSF vulnerability resources without tags', () => {
      // Arrange
      const finding = createOcsfVulnerabilityFinding();
      const mapping = { remediationId: 'Inspector.InstanceVulnerability', findingFormat: 'OCSF' as const };

      // Act
      const result = ocsfVulnerabilityToNormalized(finding, mapping);

      // Assert
      expect(result.resources[0].tags).toBeUndefined();
    });

    it('should handle empty tags array', () => {
      // Arrange
      const finding = createOcsfVulnerabilityFinding({
        resources: [{ type: 'AWS::EC2::Instance', uid: 'i-abc', tags: [] }],
      });
      const mapping = { remediationId: 'Inspector.InstanceVulnerability', findingFormat: 'OCSF' as const };

      // Act
      const result = ocsfVulnerabilityToNormalized(finding, mapping);

      // Assert
      expect(result.resources[0].tags).toEqual({});
    });

    it('should populate productFields with product name and finding ID', () => {
      // Arrange
      const finding = createOcsfVulnerabilityFinding();
      const mapping = { remediationId: 'Inspector.InstanceVulnerability', findingFormat: 'OCSF' as const };

      // Act
      const result = ocsfVulnerabilityToNormalized(finding, mapping);

      // Assert
      expect(result.productFields).toEqual({
        'aws/securityhub/ProductName': 'Inspector',
        'aws/securityhub/findingId': 'inspector-finding-1',
      });
    });

    it('should extract resource data as details', () => {
      // Arrange
      const finding = createOcsfVulnerabilityFinding({
        resources: [{ type: 'AWS::EC2::Instance', uid: 'i-1234567890abcdef0', data: { InstanceType: 't3.micro' } }],
      });
      const mapping = { remediationId: 'Inspector.InstanceVulnerability', findingFormat: 'OCSF' as const };

      // Act
      const result = ocsfVulnerabilityToNormalized(finding, mapping);

      // Assert
      expect(result.resources[0].details).toEqual({ InstanceType: 't3.micro' });
    });

    it('should handle vulnerability resources without data', () => {
      // Arrange
      const finding = createOcsfVulnerabilityFinding();
      const mapping = { remediationId: 'Inspector.InstanceVulnerability', findingFormat: 'OCSF' as const };

      // Act
      const result = ocsfVulnerabilityToNormalized(finding, mapping);

      // Assert
      expect(result.resources[0].details).toBeUndefined();
    });

    it('maps OCSF first_seen_time_dt to firstObservedAt and leaves it undefined when absent', () => {
      // ARRANGE
      const mapping = { remediationId: 'Inspector.InstanceVulnerability', findingFormat: 'OCSF' as const };

      // ACT
      const withFirstObserved = ocsfVulnerabilityToNormalized(
        createOcsfVulnerabilityFinding({
          finding_info: {
            uid: 'inspector-finding-1',
            types: [],
            title: 'CVE',
            created_time_dt: '2024-01-01T00:00:00Z',
            first_seen_time_dt: '2024-01-05T00:00:00Z',
          },
        }),
        mapping,
      );
      const withoutFirstObserved = ocsfVulnerabilityToNormalized(createOcsfVulnerabilityFinding(), mapping);

      // ASSERT
      expect(withFirstObserved.firstObservedAt).toBe('2024-01-05T00:00:00Z');
      expect(withoutFirstObserved.firstObservedAt).toBeUndefined();
    });
  });

  describe('ocsfDetectionToNormalized', () => {
    it('should extract tags from OCSF detection resources', () => {
      // Arrange
      const finding = createOcsfDetectionFinding({
        resources: [
          {
            type: 'AWS::IAM::AccessKey',
            uid: 'AKIAIOSFODNN7EXAMPLE',
            tags: [
              { name: 'Owner', value: 'security-team' },
              { name: 'Application', value: 'backend-api' },
            ],
          },
        ],
      });
      const mapping = { remediationId: 'GuardDuty.IAMUser', findingFormat: 'OCSF' as const };

      // Act
      const result = ocsfDetectionToNormalized(finding, mapping);

      // Assert
      expect(result.resources[0].tags).toEqual({ Owner: 'security-team', Application: 'backend-api' });
    });

    it('should handle OCSF detection resources without tags', () => {
      // Arrange
      const finding = createOcsfDetectionFinding();
      const mapping = { remediationId: 'GuardDuty.IAMUser', findingFormat: 'OCSF' as const };

      // Act
      const result = ocsfDetectionToNormalized(finding, mapping);

      // Assert
      expect(result.resources[0].tags).toBeUndefined();
    });

    it('should handle empty tags array', () => {
      // Arrange
      const finding = createOcsfDetectionFinding({
        resources: [{ type: 'AWS::IAM::AccessKey', uid: 'AKIA...', tags: [] }],
      });
      const mapping = { remediationId: 'GuardDuty.IAMUser', findingFormat: 'OCSF' as const };

      // Act
      const result = ocsfDetectionToNormalized(finding, mapping);

      // Assert
      expect(result.resources[0].tags).toEqual({});
    });

    it('should populate productFields with product name and finding ID', () => {
      // Arrange
      const finding = createOcsfDetectionFinding();
      const mapping = { remediationId: 'GuardDuty.IAMUser', findingFormat: 'OCSF' as const };

      // Act
      const result = ocsfDetectionToNormalized(finding, mapping);

      // Assert
      expect(result.productFields).toEqual({
        'aws/securityhub/ProductName': 'GuardDuty',
        'aws/securityhub/findingId': 'guardduty-finding-1',
      });
    });

    it('should extract resource data as details', () => {
      // Arrange
      const finding = createOcsfDetectionFinding({
        resources: [{ type: 'AWS::IAM::AccessKey', uid: 'AKIAIOSFODNN7EXAMPLE', data: { PrincipalId: 'AIDA...' } }],
      });
      const mapping = { remediationId: 'GuardDuty.IAMUser', findingFormat: 'OCSF' as const };

      // Act
      const result = ocsfDetectionToNormalized(finding, mapping);

      // Assert
      expect(result.resources[0].details).toEqual({ PrincipalId: 'AIDA...' });
    });

    it('should handle detection resources without data', () => {
      // Arrange
      const finding = createOcsfDetectionFinding();
      const mapping = { remediationId: 'GuardDuty.IAMUser', findingFormat: 'OCSF' as const };

      // Act
      const result = ocsfDetectionToNormalized(finding, mapping);

      // Assert
      expect(result.resources[0].details).toBeUndefined();
    });

    it('maps OCSF first_seen_time_dt to firstObservedAt and leaves it undefined when absent', () => {
      // ARRANGE
      const mapping = { remediationId: 'GuardDuty.IAMUser', findingFormat: 'OCSF' as const };

      // ACT
      const withFirstObserved = ocsfDetectionToNormalized(
        createOcsfDetectionFinding({
          finding_info: {
            uid: 'guardduty-finding-1',
            types: [],
            title: 'Compromised',
            created_time_dt: '2024-01-01T00:00:00Z',
            first_seen_time_dt: '2024-01-05T00:00:00Z',
          },
        }),
        mapping,
      );
      const withoutFirstObserved = ocsfDetectionToNormalized(createOcsfDetectionFinding(), mapping);

      // ASSERT
      expect(withFirstObserved.firstObservedAt).toBe('2024-01-05T00:00:00Z');
      expect(withoutFirstObserved.firstObservedAt).toBeUndefined();
    });
  });
});
