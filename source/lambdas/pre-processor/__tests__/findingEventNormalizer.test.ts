// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { FindingEventNormalizer } from '../Normalizer/findingEventNormalizer';
import { OCSFComplianceFinding } from '@asr/data-models';
import nock from 'nock';
import { mockClient } from 'aws-sdk-client-mock';
import { SSMClient, GetParameterCommand } from '@aws-sdk/client-ssm';
import { getLogger } from '../../common/utils/logger';

const ssmMock = mockClient(SSMClient);
const mockLogger = getLogger('test');

describe('FindingEventNormalizer', () => {
  beforeEach(() => {
    // Mock metrics endpoint
    nock('https://metrics.awssolutionsbuilder.com').post('/generic').reply(200, { status: 'success' }).persist();

    // Mock SSM client
    ssmMock.on(GetParameterCommand).resolves({
      Parameter: { Value: 'Yes' },
    });
  });

  afterEach(async () => {
    await new Promise((resolve) => setImmediate(resolve));
    nock.cleanAll();
    ssmMock.reset();
  });
  const mockOCSFFinding: OCSFComplianceFinding = {
    class_uid: 2003,
    activity_id: 1,
    category_uid: 1,
    severity_id: 3,
    type_uid: 1,
    time: 1672531200,
    status_id: 0,
    severity: 'High',
    cloud: {
      account: { uid: '123456789012' },
      region: 'us-east-1',
    },
    finding_info: {
      uid: 'arn:aws:securityhub:us-east-1:123456789012:subscription/aws-foundational-security-best-practices/v/1.0.0/S3.1/finding/test',
      created_time: 1672531200,
      created_time_dt: '2023-01-01T00:00:00Z',
      first_seen_time_dt: '2023-01-01T00:00:00Z',
      last_seen_time_dt: '2023-01-01T00:00:00Z',
      modified_time_dt: '2023-01-01T00:00:00Z',
      title: 'Test Finding',
      desc: 'Test description',
      types: ['test-type'],
      analytic: {
        name: 'test-rule',
        category: 'AWS::Config::ConfigRule',
      },
    },
    compliance: {
      status: 'fail',
      control: 'S3.1',
      requirements: ['req1', 'req2'],
      standards: ['standard1', 'standard2'],
    },
    resources: [
      {
        type: 'AWS::S3::Bucket',
        role_id: 'role',
        uid: 'test-bucket',
        uid_alt: 'arn:aws:s3:::test-bucket',
        region: 'us-east-1',
        cloud_partition: 'aws',
        tags: [{ name: 'Environment', value: 'test' }],
        owner: { account: { uid: '123456789012' } },
      },
    ],
    metadata: {
      product: {
        uid: 'arn:aws:securityhub:us-east-1::product/aws/securityhub',
        name: 'Security Hub',
        vendor_name: 'AWS',
      },
    },
    remediation: {
      desc: 'Fix the issue',
    },
  };

  const mockASFFFinding = {
    SchemaVersion: '2018-10-08',
    Id: 'test-id',
    ProductArn: 'test-arn',
    GeneratorId: 'test-generator',
    AwsAccountId: '123456789012',
    Types: ['test-type'],
    CreatedAt: '2023-01-01T00:00:00Z',
    UpdatedAt: '2023-01-01T00:00:00Z',
    Severity: { Label: 'HIGH' },
    Title: 'Test Finding',
    Compliance: {
      SecurityControlId: 'S3.1',
    },
    Resources: [{ Type: 'AWS::S3::Bucket', Id: 'test-bucket' }],
  };

  describe('constructor', () => {
    it('should initialize with logger', () => {
      const normalizer = new FindingEventNormalizer(mockLogger);
      expect(normalizer).toBeInstanceOf(FindingEventNormalizer);
    });
  });

  describe('normalizeFinding', () => {
    it('should return ASFF finding unchanged', async () => {
      const normalizer = new FindingEventNormalizer(mockLogger);
      const result = await normalizer.normalizeFinding(mockASFFFinding);
      expect(result).toEqual(mockASFFFinding);
    });

    it('should normalize OCSF finding to ASFF', async () => {
      const normalizer = new FindingEventNormalizer(mockLogger);
      const result = await normalizer.normalizeFinding(mockOCSFFinding);

      expect(result.SchemaVersion).toBe('2018-10-08');
      expect(result.Id).toBe(mockOCSFFinding.finding_info.uid);
      expect(result.AwsAccountId).toBe(mockOCSFFinding.cloud.account.uid);
      expect(result.Region).toBe(mockOCSFFinding.cloud.region);
    });

    it('should handle OCSF finding with security-control in ID', async () => {
      const securityControlFinding = {
        ...mockOCSFFinding,
        finding_info: {
          ...mockOCSFFinding.finding_info,
          uid: 'arn:aws:securityhub:us-east-1:123456789012:security-control/S3.1/finding/test',
        },
      };

      const normalizer = new FindingEventNormalizer(mockLogger);
      const result = await normalizer.normalizeFinding(securityControlFinding);

      expect(result.ProductFields?.StandardsControlArn).toBeUndefined();
    });

    it('should throw error for unknown schema', async () => {
      const normalizer = new FindingEventNormalizer(mockLogger);
      await expect(normalizer.normalizeFinding({})).rejects.toThrow('Finding schema is not OCSF or ASFF.');
    });

    it('should throw error for null finding', async () => {
      const normalizer = new FindingEventNormalizer(mockLogger);
      await expect(normalizer.normalizeFinding(null as any)).rejects.toThrow('Finding schema is not OCSF or ASFF.');
    });
  });

  describe('severity mapping', () => {
    const testCases = [
      { input: 'Low', expected: 'LOW' },
      { input: 'Medium', expected: 'MEDIUM' },
      { input: 'High', expected: 'HIGH' },
      { input: 'Critical', expected: 'CRITICAL' },
      { input: 'Fatal', expected: 'CRITICAL' },
      { input: undefined, expected: 'INFORMATIONAL' },
    ];

    testCases.forEach(({ input, expected }) => {
      it(`should map severity "${input}" to "${expected}"`, async () => {
        const finding = { ...mockOCSFFinding, severity: input };
        const normalizer = new FindingEventNormalizer(mockLogger);
        const result = await normalizer.normalizeFinding(finding);
        expect(result.Severity?.Label).toBe(expected);
      });
    });

    it('should throw error for invalid severity', async () => {
      const finding = { ...mockOCSFFinding, severity: 'invalid' };
      const normalizer = new FindingEventNormalizer(mockLogger);
      await expect(normalizer.normalizeFinding(finding)).rejects.toThrow('Finding schema is not OCSF or ASFF.');
    });
  });

  describe('compliance status mapping', () => {
    const testCases = [
      { input: 'pass', expected: 'PASSED' },
      { input: 'fail', expected: 'FAILED' },
      { input: 'warning', expected: 'WARNING' },
      { input: 'PASS', expected: 'PASSED' },
      { input: 'unknown', expected: 'NOT_AVAILABLE' },
      { input: '', expected: 'NOT_AVAILABLE' },
      { input: undefined, expected: 'NOT_AVAILABLE' },
    ];

    testCases.forEach(({ input, expected }) => {
      it(`should map compliance status "${input}" to "${expected}"`, async () => {
        const finding = {
          ...mockOCSFFinding,
          compliance: { ...mockOCSFFinding.compliance, status: input },
        };
        const normalizer = new FindingEventNormalizer(mockLogger);
        const result = await normalizer.normalizeFinding(finding);
        expect(result.Compliance?.Status).toBe(expected);
      });
    });
  });

  describe('record state mapping', () => {
    it('should map activity_id 3 to ARCHIVED', async () => {
      const finding = { ...mockOCSFFinding, activity_id: 3 as const };
      const normalizer = new FindingEventNormalizer(mockLogger);
      const result = await normalizer.normalizeFinding(finding);
      expect(result.RecordState).toBe('ARCHIVED');
    });

    it('should map status_id 5 to ARCHIVED', async () => {
      const finding = { ...mockOCSFFinding, status_id: 5 as const };
      const normalizer = new FindingEventNormalizer(mockLogger);
      const result = await normalizer.normalizeFinding(finding);
      expect(result.RecordState).toBe('ARCHIVED');
    });

    it('should map other activity_id to ACTIVE', async () => {
      for (const activityId of [0, 1, 2, 99]) {
        const finding = { ...mockOCSFFinding, activity_id: activityId as 0 | 1 | 2 | 99 };
        const normalizer = new FindingEventNormalizer(mockLogger);
        const result = await normalizer.normalizeFinding(finding);
        expect(result.RecordState).toBe('ACTIVE');
      }
    });
  });

  describe('workflow status mapping', () => {
    const testCases = [
      { input: 0, expected: 'NEW' },
      { input: 1, expected: 'NEW' },
      { input: 2, expected: 'NOTIFIED' },
      { input: 3, expected: 'SUPPRESSED' },
      { input: 4, expected: 'RESOLVED' },
      { input: undefined, expected: 'NEW' },
    ];

    testCases.forEach(({ input, expected }) => {
      it(`should map status_id ${input} to "${expected}"`, async () => {
        const finding = { ...mockOCSFFinding, status_id: input };
        const normalizer = new FindingEventNormalizer(mockLogger);
        const result = await normalizer.normalizeFinding(finding);
        expect(result.Workflow?.Status).toBe(expected);
      });
    });
  });

  describe('finding standard ID extraction', () => {
    it('should extract standard ID from consolidated finding', async () => {
      const finding = {
        ...mockOCSFFinding,
        finding_info: {
          ...mockOCSFFinding.finding_info,
          uid: 'arn:aws:securityhub:us-east-1:123456789012:security-control/S3.1/finding/test',
        },
      };
      const normalizer = new FindingEventNormalizer(mockLogger);
      const result = await normalizer.normalizeFinding(finding);
      expect(result.GeneratorId).toBe('security-control/S3.1');
    });

    it('should extract standard ID from unconsolidated finding', async () => {
      const normalizer = new FindingEventNormalizer(mockLogger);
      const result = await normalizer.normalizeFinding(mockOCSFFinding);
      expect(result.GeneratorId).toBe('aws-foundational-security-best-practices/v/1.0.0/S3.1');
    });

    it('should throw error for invalid finding ID format', async () => {
      const finding = {
        ...mockOCSFFinding,
        finding_info: {
          ...mockOCSFFinding.finding_info,
          uid: 'invalid-format',
        },
      };
      const normalizer = new FindingEventNormalizer(mockLogger);
      await expect(normalizer.normalizeFinding(finding)).rejects.toThrow('Failed to parse security standard ID');
    });
  });

  describe('edge cases', () => {
    it('should handle missing optional fields', async () => {
      const minimalFinding = {
        ...mockOCSFFinding,
        metadata: undefined,
        remediation: undefined,
        finding_info: {
          ...mockOCSFFinding.finding_info,
          types: undefined,
          analytic: undefined,
          modified_time_dt: undefined,
          created_time_dt: undefined,
          title: undefined,
          desc: undefined,
        },
      };
      const normalizer = new FindingEventNormalizer(mockLogger);
      const result = await normalizer.normalizeFinding(minimalFinding);

      expect(result.ProductArn).toBe('');
      expect(result.Types).toEqual(['']);
      expect(result.Title).toBe('');
      expect(result.CreatedAt).toBe('');
      expect(result.UpdatedAt).toBeDefined();
    });

    it('should handle resources without tags', async () => {
      const finding = {
        ...mockOCSFFinding,
        resources: [
          {
            ...mockOCSFFinding.resources[0],
            tags: undefined,
          },
        ],
      };
      const normalizer = new FindingEventNormalizer(mockLogger);
      const result = await normalizer.normalizeFinding(finding);

      expect(result.Resources[0].Tags).toBeUndefined();
    });
  });
});
