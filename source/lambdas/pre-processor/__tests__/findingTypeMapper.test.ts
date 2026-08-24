// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import {
  FindingLogger,
  mapFindingType,
  normalizeResourceTypeToAsff,
  UnverifiedProductArnError,
  UnprocessedFinding,
  MULTI_SERVICE_REMEDIATION_IDS,
} from '../findingTypeMapper';
import { MULTI_SERVICE_FINDING_TYPES } from '../../common/utils/findingUtils';

const logger: FindingLogger = { info: jest.fn(), warn: jest.fn(), debug: jest.fn() };

/** Reserved Security Hub product ARNs per AWS service (region-qualified, account-less). */
const PRODUCT_ARN: Record<string, string> = {
  'IAM Access Analyzer': 'arn:aws:securityhub:us-east-1::product/aws/access-analyzer',
  Inspector: 'arn:aws:securityhub:us-east-1::product/aws/inspector',
  GuardDuty: 'arn:aws:securityhub:us-east-1::product/aws/guardduty',
  Macie: 'arn:aws:securityhub:us-east-1::product/aws/macie',
  'Security Hub': 'arn:aws:securityhub:us-east-1::product/aws/securityhub',
  Config: 'arn:aws:securityhub:us-east-1::product/aws/config',
};

/** Helper to build an ASFF-shaped finding for tests */
function asffFinding(overrides: Partial<UnprocessedFinding> = {}): UnprocessedFinding {
  const productName = overrides.ProductName ?? 'Security Hub';
  return {
    ProductName: 'Security Hub',
    // A valid reserved ARN matching ProductName is injected by default so
    // behavior-focused tests exercise the realistic (authentic) path. Tests
    // that target the source-authenticity gate override ProductArn explicitly.
    ProductArn: PRODUCT_ARN[productName],
    Types: ['Software and Configuration Checks'],
    Resources: [{ Type: 'AwsS3Bucket', Id: 'arn:aws:s3:::default-bucket' }],
    ...overrides,
  };
}

/** Helper to build an OCSF-shaped finding for tests */
function ocsfFinding(overrides: Partial<UnprocessedFinding> = {}): UnprocessedFinding {
  return {
    metadata: { product: { name: 'Inspector', uid: PRODUCT_ARN['Inspector'] } },
    finding_info: { types: [], uid: 'test-uid' },
    resources: [{ type: 'AWS::EC2::Instance', uid: 'i-default', owner: { account: { uid: '123456789012' } } }],
    ...overrides,
  };
}

describe('findingTypeMapper', () => {
  describe('IAM Access Analyzer', () => {
    it('should map ASFF finding with "Effects/Data Exposure/External Access Granted" type', () => {
      const finding = asffFinding({
        ProductName: 'IAM Access Analyzer',
        Types: ['Effects/Data Exposure/External Access Granted'],
        Resources: [{ Type: 'AwsS3Bucket', Id: 'arn:aws:s3:::my-bucket' }],
      });

      const result = mapFindingType(finding, logger);

      expect(result).toEqual({
        remediationId: 'IAMAccessAnalyzer.ExternalAccess',
      });
    });

    it('should map ASFF finding with "Software and Configuration Checks/.../External Access Granted" type', () => {
      const finding = asffFinding({
        ProductName: 'IAM Access Analyzer',
        Types: ['Software and Configuration Checks/AWS Security Best Practices/External Access Granted'],
        Resources: [{ Type: 'AwsKmsKey', Id: 'arn:aws:kms:us-east-1:123456789012:key/abc' }],
      });

      const result = mapFindingType(finding, logger);

      expect(result).toEqual({
        remediationId: 'IAMAccessAnalyzer.ExternalAccess',
      });
    });

    it('should not map IAM Access Analyzer finding without External Access Granted type', () => {
      const finding = asffFinding({
        ProductName: 'IAM Access Analyzer',
        Types: ['Software and Configuration Checks/Some Other Type'],
        Resources: [{ Type: 'AwsS3Bucket', Id: 'arn:aws:s3:::my-bucket' }],
      });

      const result = mapFindingType(finding, logger);
      expect(result).toBeNull();
    });

    it('should not map IAM Access Analyzer finding on an unsupported resource type', () => {
      // ExternalAccess remediation supports S3 buckets and KMS keys only. A
      // finding on any other resource type must not be routed.
      const finding = asffFinding({
        ProductName: 'IAM Access Analyzer',
        Types: ['Effects/Data Exposure/External Access Granted'],
        Resources: [{ Type: 'AwsEc2Instance', Id: 'arn:aws:ec2:us-east-1:123456789012:instance/i-abc' }],
      });

      const result = mapFindingType(finding, logger);
      expect(result).toBeNull();
    });
  });

  describe('Inspector', () => {
    it('should map OCSF finding with CVE type and EC2 instance resource', () => {
      const finding = ocsfFinding({
        metadata: { product: { name: 'Inspector', uid: PRODUCT_ARN['Inspector'] } },
        finding_info: {
          types: ['Software and Configuration Checks/Vulnerabilities/CVE'],
          uid: 'test-finding-id',
        },
        resources: [
          { type: 'AWS::EC2::Instance', uid: 'i-1234567890abcdef0', owner: { account: { uid: '123456789012' } } },
        ],
      });

      const result = mapFindingType(finding, logger);

      // The mapper returns only a remediationId — it no longer carries a finding
      // format. Format is derived from the detected schema downstream
      // (preProcessor: ASFF branch -> 'ASFF', OCSF branches -> 'OCSF'), so it
      // always matches the actual payload shape.
      expect(result).toEqual({
        remediationId: 'Inspector.InstanceVulnerability',
      });
    });

    it('should map ASFF-normalized Inspector finding with CVE type and EC2 instance', () => {
      const finding = asffFinding({
        ProductName: 'Inspector',
        Types: ['Software and Configuration Checks/Vulnerabilities/CVE'],
        Resources: [{ Type: 'AwsEc2Instance', Id: 'arn:aws:ec2:us-east-1:123456789012:instance/i-abc' }],
      });

      const result = mapFindingType(finding, logger);

      expect(result).toEqual({
        remediationId: 'Inspector.InstanceVulnerability',
      });
    });

    it('should not map Inspector finding with non-EC2 resource type', () => {
      const finding = asffFinding({
        ProductName: 'Inspector',
        Types: ['Software and Configuration Checks/Vulnerabilities/CVE'],
        Resources: [{ Type: 'AwsEcrContainerImage', Id: 'arn:aws:ecr:us-east-1:123456789012:repository/my-repo' }],
      });

      const result = mapFindingType(finding, logger);
      expect(result).toBeNull();
    });

    it('should not map Inspector finding on a Lambda function resource', () => {
      // Amazon Inspector Lambda code scanning (e.g. CWE-798 hardcoded credentials)
      // is out of scope for this release; the EC2-only patch remediation cannot
      // act on a Lambda function, so the finding must not be routed.
      const finding = asffFinding({
        ProductName: 'Inspector',
        Types: ['Software and Configuration Checks/Vulnerabilities/CVE'],
        Resources: [
          { Type: 'AwsLambdaFunction', Id: 'arn:aws:lambda:us-east-1:123456789012:function:my-func:$LATEST' },
        ],
      });

      const result = mapFindingType(finding, logger);
      expect(result).toBeNull();
    });

    it('should not map Inspector finding on a Lambda function resource (OCSF)', () => {
      const finding = ocsfFinding({
        metadata: { product: { name: 'Inspector', uid: PRODUCT_ARN['Inspector'] } },
        finding_info: { types: ['Software and Configuration Checks/Vulnerabilities/CVE'], uid: 'lambda-uid' },
        resources: [
          {
            type: 'AWS::Lambda::Function',
            uid: 'arn:aws:lambda:us-east-1:123456789012:function:my-func:$LATEST',
            owner: { account: { uid: '123456789012' } },
          },
        ],
      });

      const result = mapFindingType(finding, logger);
      expect(result).toBeNull();
    });

    it('should not map Inspector finding without CVE type', () => {
      const finding = asffFinding({
        ProductName: 'Inspector',
        Types: ['Software and Configuration Checks/Other'],
        Resources: [{ Type: 'AwsEc2Instance', Id: 'arn:aws:ec2:us-east-1:123456789012:instance/i-abc' }],
      });

      const result = mapFindingType(finding, logger);
      expect(result).toBeNull();
    });
  });

  describe('GuardDuty', () => {
    it('should map OCSF finding with IAM access key resource', () => {
      const finding = ocsfFinding({
        metadata: { product: { name: 'GuardDuty', uid: PRODUCT_ARN['GuardDuty'] } },
        finding_info: { types: ['UnauthorizedAccess:IAMUser/MaliciousIPCaller'], uid: 'test-uid' },
        resources: [
          { type: 'AWS::IAM::AccessKey', uid: 'AKIAIOSFODNN7EXAMPLE', owner: { account: { uid: '123456789012' } } },
        ],
      });

      const result = mapFindingType(finding, logger);

      expect(result).toEqual({
        remediationId: 'GuardDuty.IAMUser',
      });
    });

    it('should map ASFF-format GuardDuty finding with AwsIamAccessKey resource', () => {
      const finding = asffFinding({
        ProductName: 'GuardDuty',
        Types: ['TTPs/Initial Access/UnauthorizedAccess:IAMUser-ConsoleLoginSuccess.B'],
        Resources: [{ Type: 'AwsIamAccessKey', Id: 'AKIAIOSFODNN7EXAMPLE' }],
      });

      const result = mapFindingType(finding, logger);

      expect(result).toEqual({
        remediationId: 'GuardDuty.IAMUser',
      });
    });

    it('should not map GuardDuty finding with non-IAM resource type', () => {
      const finding = asffFinding({
        ProductName: 'GuardDuty',
        Types: ['TTPs/Command and Control'],
        Resources: [{ Type: 'AwsEc2Instance', Id: 'i-1234567890abcdef0' }],
      });

      const result = mapFindingType(finding, logger);
      expect(result).toBeNull();
    });

    it('should not map a non-IAMUser GuardDuty finding that carries the actor access key as a resource (ASFF)', () => {
      // Policy:S3/BucketBlockPublicAccessDisabled records the actor access key
      // as Resources[0], but it is an S3 finding, not credential compromise.
      const finding = asffFinding({
        ProductName: 'GuardDuty',
        Types: ['Effects/Data Exposure/Policy:S3-BucketBlockPublicAccessDisabled'],
        Resources: [{ Type: 'AwsIamAccessKey', Id: 'AKIASFY23E3HPKJZ3GSH' }],
      });

      const result = mapFindingType(finding, logger);
      expect(result).toBeNull();
    });

    it('should not map a non-IAMUser GuardDuty finding that carries the actor access key as a resource (OCSF)', () => {
      const finding = ocsfFinding({
        metadata: { product: { name: 'GuardDuty' } },
        finding_info: { types: ['Threats', 'Policy:S3/BucketBlockPublicAccessDisabled'], uid: 'gd-s3-uid' },
        resources: [
          { type: 'AWS::IAM::AccessKey', uid: 'AKIASFY23E3HPKJZ3GSH', owner: { account: { uid: '123456789012' } } },
        ],
      });

      const result = mapFindingType(finding, logger);
      expect(result).toBeNull();
    });
  });

  describe('Macie', () => {
    it('should map OCSF finding with sensitive data type and S3 object resource', () => {
      const finding = ocsfFinding({
        metadata: { product: { name: 'Macie', uid: PRODUCT_ARN['Macie'] } },
        finding_info: { types: ['SensitiveData:S3Object/Personal', 'Sensitive Data'], uid: 'test-finding-id' },
        resources: [{ type: 'AWS::S3::Object', uid: 'my-bucket/my-key', owner: { account: { uid: '123456789012' } } }],
      });

      const result = mapFindingType(finding, logger);

      expect(result).toEqual({
        remediationId: 'Macie.SensitiveDataS3Object',
      });
    });

    it('should map ASFF-format Macie finding', () => {
      const finding = asffFinding({
        ProductName: 'Macie',
        Types: ['Sensitive Data Identifications/PII/SensitiveData:S3Object/Personal'],
        Resources: [{ Type: 'AwsS3Object', Id: 'arn:aws:s3:::my-bucket/my-key' }],
      });

      const result = mapFindingType(finding, logger);

      expect(result).toEqual({
        remediationId: 'Macie.SensitiveDataS3Object',
      });
    });

    it('should not map Macie finding without sensitive data type', () => {
      const finding = asffFinding({
        ProductName: 'Macie',
        Types: ['Software and Configuration Checks'],
        Resources: [{ Type: 'AwsS3Object', Id: 'arn:aws:s3:::my-bucket/my-key' }],
      });

      const result = mapFindingType(finding, logger);
      expect(result).toBeNull();
    });

    it('should not map Macie finding with non-S3 object resource', () => {
      const finding = asffFinding({
        ProductName: 'Macie',
        Types: ['Sensitive Data Identifications/PII/SensitiveData:S3Object/Personal'],
        Resources: [{ Type: 'AwsS3Bucket', Id: 'arn:aws:s3:::my-bucket' }],
      });

      const result = mapFindingType(finding, logger);
      expect(result).toBeNull();
    });
  });

  describe('non-multi-service findings', () => {
    it('should return null for standard Security Hub finding', () => {
      const finding = asffFinding({
        ProductName: 'Security Hub',
        Types: ['Software and Configuration Checks/AWS Security Best Practices'],
        Resources: [{ Type: 'AwsS3Bucket', Id: 'arn:aws:s3:::test-bucket' }],
      });

      const result = mapFindingType(finding, logger);
      expect(result).toBeNull();
    });

    it('should return null for Config finding', () => {
      const finding = asffFinding({
        ProductName: 'Config',
        Types: ['Software and Configuration Checks'],
        Resources: [{ Type: 'AwsEc2SecurityGroup', Id: 'sg-12345' }],
      });

      const result = mapFindingType(finding, logger);
      expect(result).toBeNull();
    });

    it('should return null for finding without ProductName', () => {
      const finding: UnprocessedFinding = {
        Types: ['Software and Configuration Checks'],
        Resources: [{ Type: 'AwsS3Bucket', Id: 'test' }],
      };

      const result = mapFindingType(finding, logger);
      expect(result).toBeNull();
    });

    it('should return null for empty finding', () => {
      const finding: UnprocessedFinding = {};
      const result = mapFindingType(finding, logger);
      expect(result).toBeNull();
    });
  });

  describe('ProductName extraction', () => {
    it('should extract ProductName from ASFF ProductFields', () => {
      const finding: UnprocessedFinding = {
        ProductFields: { 'aws/securityhub/ProductName': 'GuardDuty' },
        Types: ['TTPs/Initial Access/UnauthorizedAccess:IAMUser-ConsoleLoginSuccess.B'],
        ProductArn: PRODUCT_ARN['GuardDuty'],
        Resources: [{ Type: 'AwsIamAccessKey', Id: 'AKIAIOSFODNN7EXAMPLE' }],
      };

      const result = mapFindingType(finding, logger);

      expect(result).toEqual({
        remediationId: 'GuardDuty.IAMUser',
      });
    });

    it('should extract ProductName from OCSF metadata.product.name', () => {
      const finding = ocsfFinding({
        metadata: { product: { name: 'GuardDuty', uid: PRODUCT_ARN['GuardDuty'] } },
        finding_info: { types: ['UnauthorizedAccess:IAMUser/MaliciousIPCaller'], uid: 'test-uid' },
        resources: [
          { type: 'AWS::IAM::AccessKey', uid: 'AKIAIOSFODNN7EXAMPLE', owner: { account: { uid: '123456789012' } } },
        ],
      });

      const result = mapFindingType(finding, logger);

      expect(result).toEqual({
        remediationId: 'GuardDuty.IAMUser',
      });
    });
  });

  describe('OCSF resource type normalization', () => {
    it('should normalize AWS::EC2::Instance to AwsEc2Instance', () => {
      const finding = ocsfFinding({
        metadata: { product: { name: 'Inspector', uid: PRODUCT_ARN['Inspector'] } },
        finding_info: { types: ['Software and Configuration Checks/Vulnerabilities/CVE'], uid: 'test' },
        resources: [{ type: 'AWS::EC2::Instance', uid: 'i-abc', owner: { account: { uid: '123456789012' } } }],
      });

      const result = mapFindingType(finding, logger);
      expect(result?.remediationId).toBe('Inspector.InstanceVulnerability');
    });

    it('should normalize AWS::IAM::AccessKey to AwsIamAccessKey', () => {
      const finding = ocsfFinding({
        metadata: { product: { name: 'GuardDuty', uid: PRODUCT_ARN['GuardDuty'] } },
        finding_info: { types: ['UnauthorizedAccess:IAMUser/MaliciousIPCaller'], uid: 'test-uid' },
        resources: [{ type: 'AWS::IAM::AccessKey', uid: 'AKIA...', owner: { account: { uid: '123456789012' } } }],
      });

      const result = mapFindingType(finding, logger);
      expect(result?.remediationId).toBe('GuardDuty.IAMUser');
    });

    it('should normalize AWS::S3::Object to AwsS3Object', () => {
      const finding = ocsfFinding({
        metadata: { product: { name: 'Macie', uid: PRODUCT_ARN['Macie'] } },
        finding_info: { types: ['SensitiveData:S3Object/Personal', 'Sensitive Data'], uid: 'test' },
        resources: [{ type: 'AWS::S3::Object', uid: 'bucket/key', owner: { account: { uid: '123456789012' } } }],
      });

      const result = mapFindingType(finding, logger);
      expect(result?.remediationId).toBe('Macie.SensitiveDataS3Object');
    });
  });

  describe('normalizeResourceTypeToAsff', () => {
    it.each([
      ['AWS::EC2::Instance', 'AwsEc2Instance'],
      ['AWS::IAM::AccessKey', 'AwsIamAccessKey'],
      ['AWS::S3::Object', 'AwsS3Object'],
      ['AWS::S3::Bucket', 'AwsS3Bucket'],
      ['AWS::RDS::DBInstance', 'AwsRdsDBInstance'],
      ['AWS::ECS::Cluster', 'AwsEcsCluster'],
      ['AWS::Lambda::Function', 'AwsLambdaFunction'],
    ])('should normalize %s to %s', (input, expected) => {
      expect(normalizeResourceTypeToAsff(input)).toBe(expected);
    });

    it('should pass through already-ASFF format unchanged', () => {
      expect(normalizeResourceTypeToAsff('AwsEc2Instance')).toBe('AwsEc2Instance');
      expect(normalizeResourceTypeToAsff('AwsS3Bucket')).toBe('AwsS3Bucket');
    });
  });

  describe('multi-service findingType invariant', () => {
    // resolveControlId keys a multi-service row on the remediation id the caller supplies, not on
    // the ARN. That is only safe because the mapper's remediation ids are exactly the values a
    // native ARN would derive via NATIVE_ARN_FINDING_TYPES, so the key stays recoverable by a point
    // read. If a new remediation id is added without a matching NATIVE_ARN_FINDING_TYPES entry, this
    // fails the build rather than letting an unreachable row be written. See ADR 0010.
    it('every mapper remediation id is a persisted multi-service findingType', () => {
      // ARRANGE / ACT
      const missing = MULTI_SERVICE_REMEDIATION_IDS.filter((id) => !MULTI_SERVICE_FINDING_TYPES.has(id));

      // ASSERT
      expect(missing).toEqual([]);
    });
  });
});
