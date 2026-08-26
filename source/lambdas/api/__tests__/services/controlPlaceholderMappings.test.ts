// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import {
  buildPlaceholderMap,
  extractResourceName,
  CONTROL_PLACEHOLDER_MAPPINGS,
} from '../../services/controlPlaceholderMappings';

describe('controlPlaceholderMappings', () => {
  describe('extractResourceName', () => {
    it('extracts bucket name from S3 ARN', () => {
      const asff = {
        Resources: [{ Id: 'arn:aws:s3:::my-bucket-name' }],
      };

      expect(extractResourceName(asff)).toBe('my-bucket-name');
    });

    it('extracts VPC ID from EC2 VPC ARN', () => {
      const asff = {
        Resources: [{ Id: 'arn:aws:ec2:us-east-1:123456789012:vpc/vpc-0abc123' }],
      };

      expect(extractResourceName(asff)).toBe('vpc-0abc123');
    });

    it('returns full ID when not an ARN', () => {
      const asff = {
        Resources: [{ Id: 'my-resource-id' }],
      };

      expect(extractResourceName(asff)).toBe('my-resource-id');
    });

    it('returns undefined when Resources array is empty', () => {
      const asff = { Resources: [] };

      expect(extractResourceName(asff)).toBeUndefined();
    });

    it('returns undefined when Resources is missing', () => {
      const asff = {};

      expect(extractResourceName(asff)).toBeUndefined();
    });

    it('returns undefined when asff is undefined', () => {
      expect(extractResourceName(undefined)).toBeUndefined();
    });

    it('handles ARN with colon-separated resource', () => {
      const asff = {
        Resources: [{ Id: 'arn:aws:iam::123456789012:role/my-role-name' }],
      };

      expect(extractResourceName(asff)).toBe('my-role-name');
    });
  });

  describe('VPC extraction via EC2.6 mapping', () => {
    it('extracts VPC ID from AwsEc2Vpc details', () => {
      const asff = {
        Resources: [
          {
            Id: 'arn:aws:ec2:us-east-1:123456789012:vpc/vpc-0abc123',
            Details: { AwsEc2Vpc: { VpcId: 'vpc-0abc123' } },
          },
        ],
      };

      const result = buildPlaceholderMap('EC2.6', asff);
      expect(result.vpcId).toBe('vpc-0abc123');
    });

    it('extracts VPC ID from AwsEc2SecurityGroup details', () => {
      const asff = {
        Resources: [
          {
            Id: 'arn:aws:ec2:us-east-1:123456789012:security-group/sg-123',
            Details: { AwsEc2SecurityGroup: { GroupId: 'sg-123', VpcId: 'vpc-0def456' } },
          },
        ],
      };

      const result = buildPlaceholderMap('EC2.6', asff);
      expect(result.vpcId).toBe('vpc-0def456');
    });

    it('falls back to parsing VPC ARN when details are missing', () => {
      const asff = {
        Resources: [
          {
            Id: 'arn:aws:ec2:us-east-1:123456789012:vpc/vpc-0abc123',
            Details: {},
          },
        ],
      };

      const result = buildPlaceholderMap('EC2.6', asff);
      expect(result.vpcId).toBe('vpc-0abc123');
    });

    it('returns empty map when no VPC info is available', () => {
      const asff = {
        Resources: [
          {
            Id: 'arn:aws:s3:::my-bucket',
            Details: { AwsS3Bucket: { Name: 'my-bucket' } },
          },
        ],
      };

      const result = buildPlaceholderMap('EC2.6', asff);
      expect(result).toEqual({});
    });

    it('returns empty map when Resources is empty', () => {
      const asff = { Resources: [] };

      const result = buildPlaceholderMap('EC2.6', asff);
      expect(result).toEqual({});
    });

    it('returns empty map when asff is undefined', () => {
      const result = buildPlaceholderMap('EC2.6', undefined);
      expect(result).toEqual({});
    });
  });

  describe('buildPlaceholderMap', () => {
    it('builds S3.4 placeholder map with bucket name from details', () => {
      const asff = {
        Resources: [
          {
            Id: 'arn:aws:s3:::my-production-bucket',
            Type: 'AwsS3Bucket',
            Details: { AwsS3Bucket: { Name: 'my-production-bucket' } },
          },
        ],
      };

      const result = buildPlaceholderMap('S3.4', asff);

      expect(result).toEqual({ bucketName: 'my-production-bucket' });
    });

    it('builds S3.4 placeholder map falling back to ARN resource name', () => {
      const asff = {
        Resources: [
          {
            Id: 'arn:aws:s3:::my-bucket-from-arn',
            Type: 'AwsS3Bucket',
            Details: {},
          },
        ],
      };

      const result = buildPlaceholderMap('S3.4', asff);

      expect(result).toEqual({ bucketName: 'my-bucket-from-arn' });
    });

    it('builds EC2.6 placeholder map with VPC ID and derived values', () => {
      const asff = {
        Resources: [
          {
            Id: 'arn:aws:ec2:us-east-1:123456789012:vpc/vpc-0abc123',
            Type: 'AwsEc2Vpc',
            Details: { AwsEc2Vpc: { VpcId: 'vpc-0abc123' } },
          },
        ],
      };

      const result = buildPlaceholderMap('EC2.6', asff);

      expect(result).toEqual({
        vpcId: 'vpc-0abc123',
        flowLogGroup: 'VPCFlowLogs/vpc-0abc123',
        flowLog: 'vpc-0abc123-flow-log',
        flowLogRole: 'vpc-0abc123-flow-log-role',
      });
    });

    it('returns empty map for unknown controlId', () => {
      const asff = {
        Resources: [{ Id: 'arn:aws:s3:::some-bucket', Details: {} }],
      };

      const result = buildPlaceholderMap('UNKNOWN.99', asff);

      expect(result).toEqual({});
    });

    it('omits entries when ASFF fields are missing', () => {
      const asff = {
        Resources: [
          {
            Id: 'arn:aws:ec2:us-east-1:123456789012:instance/i-12345',
            Type: 'AwsEc2Instance',
            Details: {},
          },
        ],
      };

      // EC2.6 expects VPC data — none available here
      const result = buildPlaceholderMap('EC2.6', asff);

      expect(result).toEqual({});
    });

    it('does not throw when asff is null', () => {
      const result = buildPlaceholderMap('S3.4', null);

      expect(result).toEqual({});
    });

    it('does not throw when asff is undefined', () => {
      const result = buildPlaceholderMap('S3.4', undefined);

      expect(result).toEqual({});
    });
  });

  describe('CONTROL_PLACEHOLDER_MAPPINGS', () => {
    it('has mappings defined for S3.4', () => {
      expect(CONTROL_PLACEHOLDER_MAPPINGS['S3.4']).toBeDefined();
      expect(CONTROL_PLACEHOLDER_MAPPINGS['S3.4'].length).toBe(1);
      expect(CONTROL_PLACEHOLDER_MAPPINGS['S3.4'][0].placeholder).toBe('bucketName');
    });

    it('has mappings defined for EC2.6', () => {
      expect(CONTROL_PLACEHOLDER_MAPPINGS['EC2.6']).toBeDefined();
      expect(CONTROL_PLACEHOLDER_MAPPINGS['EC2.6'].length).toBe(4);
      expect(CONTROL_PLACEHOLDER_MAPPINGS['EC2.6'].map((m) => m.placeholder)).toEqual([
        'vpcId',
        'flowLogGroup',
        'flowLog',
        'flowLogRole',
      ]);
    });

    it('has mappings defined for EC2.10 including region', () => {
      expect(CONTROL_PLACEHOLDER_MAPPINGS['EC2.10']).toBeDefined();
      expect(CONTROL_PLACEHOLDER_MAPPINGS['EC2.10'].map((m) => m.placeholder)).toEqual([
        'vpcEndpoint',
        'vpcId',
        'region',
      ]);
    });
  });

  describe('EC2.10 region extraction', () => {
    it('extracts region from Resources[0].Region', () => {
      const asff = {
        Resources: [
          {
            Id: 'arn:aws:ec2:eu-west-1:111111111111:vpc/vpc-abc123',
            Type: 'AwsEc2Vpc',
            Region: 'eu-west-1',
            Details: { AwsEc2Vpc: { VpcId: 'vpc-abc123' } },
          },
        ],
      };

      const result = buildPlaceholderMap('EC2.10', asff);

      expect(result).toEqual({ vpcEndpoint: 'vpc-abc123', vpcId: 'vpc-abc123', region: 'eu-west-1' });
    });

    it('omits region when Resources[0].Region is missing', () => {
      const asff = {
        Resources: [
          {
            Id: 'arn:aws:ec2:us-east-1:111111111111:vpc/vpc-abc123',
            Type: 'AwsEc2Vpc',
            Details: { AwsEc2Vpc: { VpcId: 'vpc-abc123' } },
          },
        ],
      };

      const result = buildPlaceholderMap('EC2.10', asff);

      // Region falls back to ARN segment when Resources[0].Region is absent
      expect(result).toEqual({ vpcEndpoint: 'vpc-abc123', vpcId: 'vpc-abc123', region: 'us-east-1' });
    });
  });
});

describe('controlPlaceholderMappings — edge cases', () => {
  it('EC2.6 flowLogGroup derives from vpcId', () => {
    const asff = { Resources: [{ Id: 'arn:aws:ec2:us-east-1:123456789012:vpc/vpc-abc123' }] };
    const result = buildPlaceholderMap('EC2.6', asff);
    expect(result.flowLogGroup).toBe('VPCFlowLogs/vpc-abc123');
    expect(result.flowLog).toBe('vpc-abc123-flow-log');
    expect(result.flowLogRole).toBe('vpc-abc123-flow-log-role');
  });

  it('EC2.6 returns empty when vpc cannot be extracted', () => {
    const result = buildPlaceholderMap('EC2.6', { Resources: [{ Id: 'not-a-vpc-arn' }] });
    expect(result.flowLogGroup).toBeUndefined();
  });

  it('fromDetails falls back to extractResourceName when property missing', () => {
    const asff = { Resources: [{ Id: 'arn:aws:s3:::my-bucket', Details: { AwsS3Bucket: {} } }] };
    const result = buildPlaceholderMap('S3.2', asff);
    expect(result.bucketName).toBe('my-bucket');
  });

  it('buildPlaceholderMap returns empty for unknown controlId', () => {
    expect(buildPlaceholderMap('Unknown.99', {})).toEqual({});
  });

  it('catch block handles null finding gracefully', () => {
    const result = buildPlaceholderMap('EC2.6', null);
    expect(result).toEqual({});
  });
});

describe('controlPlaceholderMappings — extractor branch coverage', () => {
  describe('RDS.6 accountId placeholder', () => {
    it('prefers the finding AwsAccountId', () => {
      const asff = {
        AwsAccountId: '999988887777',
        Resources: [
          {
            Id: 'arn:aws:rds:us-east-1:123456789012:db:my-db',
            Details: { AwsRdsDbInstance: { DBInstanceIdentifier: 'my-db' } },
          },
        ],
      };

      const result = buildPlaceholderMap('RDS.6', asff);

      expect(result).toEqual({ dbInstance: 'my-db', accountId: '999988887777' });
    });

    it('falls back to the account id segment of the resource ARN', () => {
      const asff = {
        Resources: [
          {
            Id: 'arn:aws:rds:us-east-1:123456789012:db:my-db',
            Details: { AwsRdsDbInstance: { DBInstanceIdentifier: 'my-db' } },
          },
        ],
      };

      const result = buildPlaceholderMap('RDS.6', asff);

      expect(result.accountId).toBe('123456789012');
    });

    it('omits accountId when neither AwsAccountId nor an ARN is present', () => {
      const asff = {
        Resources: [{ Id: 'plain-db-id', Details: { AwsRdsDbInstance: { DBInstanceIdentifier: 'plain-db-id' } } }],
      };

      const result = buildPlaceholderMap('RDS.6', asff);

      expect(result.accountId).toBeUndefined();
      expect(result.dbInstance).toBe('plain-db-id');
    });
  });

  describe('EC2.10 region placeholder ARN fallback', () => {
    it('derives region from the ARN when Resources[0].Region is absent', () => {
      const asff = {
        Resources: [{ Id: 'arn:aws:ec2:ap-south-1:111111111111:vpc/vpc-xyz', Details: {} }],
      };

      const result = buildPlaceholderMap('EC2.10', asff);

      expect(result).toEqual({ vpcEndpoint: 'vpc-xyz', vpcId: 'vpc-xyz', region: 'ap-south-1' });
    });

    it('omits region when neither Region nor a parseable ARN is present', () => {
      const asff = { Resources: [{ Id: 'vpc-xyz' }] };

      const result = buildPlaceholderMap('EC2.10', asff);

      expect(result.region).toBeUndefined();
    });
  });

  describe('EC2.2 default security group + vpc', () => {
    it('extracts the security group id from details and the vpc id from the SG block', () => {
      const asff = {
        Resources: [
          {
            Id: 'arn:aws:ec2:us-east-1:123456789012:security-group/sg-default',
            Details: { AwsEc2SecurityGroup: { GroupId: 'sg-default', VpcId: 'vpc-from-sg' } },
          },
        ],
      };

      const result = buildPlaceholderMap('EC2.2', asff);

      expect(result).toEqual({ defaultSecurityGroup: 'sg-default', vpcId: 'vpc-from-sg' });
    });

    it('falls back to extractResourceName for the security group when details are absent', () => {
      const asff = {
        Resources: [{ Id: 'arn:aws:ec2:us-east-1:123456789012:security-group/sg-fallback' }],
      };

      const result = buildPlaceholderMap('EC2.2', asff);

      expect(result.defaultSecurityGroup).toBe('sg-fallback');
    });
  });

  describe('EC2.15 subnet extraction', () => {
    it('parses the subnet id from the ARN segment', () => {
      const asff = {
        Resources: [{ Id: 'arn:aws:ec2:us-east-1:123456789012:subnet/subnet-123' }],
      };

      const result = buildPlaceholderMap('EC2.15', asff);

      expect(result.subnet).toBe('subnet-123');
    });
  });

  describe('extraction error handling', () => {
    it('omits a placeholder and does not throw when an extractor throws', () => {
      // A getter that throws simulates an extractor bug / unexpected ASFF shape.
      const hostile = {
        Resources: [
          {
            get Id(): string {
              throw new TypeError('boom');
            },
          },
        ],
      } as unknown as Parameters<typeof buildPlaceholderMap>[1];

      const result = buildPlaceholderMap('S3.2', hostile);

      expect(result).toEqual({});
    });
  });

  describe('static-value extractors', () => {
    it('S3.1 returns the account public access block sentinel', () => {
      expect(buildPlaceholderMap('S3.1', {})).toEqual({ accountPublicAccessBlock: 'accountPublicAccessBlock' });
    });

    it('IAM.18 returns the support role sentinel', () => {
      expect(buildPlaceholderMap('IAM.18', {})).toEqual({ supportRole: 'aws_incident_support_role' });
    });
  });

  describe('extractResourceName ARN edge cases', () => {
    it('returns the full id for an ARN with fewer than 6 segments', () => {
      expect(extractResourceName({ Resources: [{ Id: 'arn:aws:s3' }] })).toBe('arn:aws:s3');
    });

    it('returns undefined when the trailing resource segment is empty', () => {
      expect(extractResourceName({ Resources: [{ Id: 'arn:aws:ec2:us-east-1:123456789012:vpc/' }] })).toBeUndefined();
    });
  });
});

describe('CONTROL_PLACEHOLDER_MAPPINGS — every control extractor executes', () => {
  // A generic ASFF finding rich enough that most extractors resolve a value.
  // The goal is to drive every inline extract() arrow (derived values, static
  // sentinels, ARN/segment parsers) at least once so a regression in any single
  // control mapping surfaces as a failure rather than silently losing coverage.
  const richFinding = {
    AwsAccountId: '123456789012',
    Resources: [
      {
        Id: 'arn:aws:ec2:us-east-1:123456789012:vpc/vpc-generic',
        Region: 'us-east-1',
        Details: {
          AwsS3Bucket: { Name: 'generic-bucket' },
          AwsEc2Vpc: { VpcId: 'vpc-generic' },
          AwsEc2SecurityGroup: { GroupId: 'sg-generic', VpcId: 'vpc-generic' },
          AwsEc2Instance: { InstanceId: 'i-generic' },
          AwsRdsDbInstance: { DBInstanceIdentifier: 'db-generic' },
          AwsRdsDbCluster: { DbClusterIdentifier: 'dbcluster-generic' },
          AwsCloudTrailTrail: { Name: 'trail-generic' },
          AwsDynamoDbTable: { TableName: 'table-generic' },
          AwsLambdaFunction: { FunctionName: 'fn-generic' },
          AwsRedshiftCluster: { ClusterIdentifier: 'redshift-generic' },
          AwsSecretsManagerSecret: { Name: 'secret-generic' },
          AwsSqsQueue: { QueueName: 'queue-generic' },
          AwsKmsKey: { KeyId: 'key-generic' },
          AwsEcrRepository: { RepositoryName: 'repo-generic' },
          AwsElbv2LoadBalancer: { Name: 'alb-generic' },
          AwsCodeBuildProject: { Name: 'cb-generic' },
          AwsAutoScalingAutoScalingGroup: { AutoScalingGroupName: 'asg-generic' },
          AwsElastiCacheReplicationGroup: { ReplicationGroupId: 'ecrg-generic' },
        },
      },
    ],
  };

  it.each(Object.keys(CONTROL_PLACEHOLDER_MAPPINGS))(
    '%s: resolves a value for every declared placeholder',
    (controlId) => {
      const result = buildPlaceholderMap(controlId, richFinding);
      const declared = CONTROL_PLACEHOLDER_MAPPINGS[controlId].map((m) => m.placeholder);

      // Every placeholder this control declares should resolve to a non-empty
      // string given the rich finding above — this drives each inline extractor.
      for (const placeholder of declared) {
        expect(typeof result[placeholder]).toBe('string');
        expect(result[placeholder].length).toBeGreaterThan(0);
      }
    },
  );
});
