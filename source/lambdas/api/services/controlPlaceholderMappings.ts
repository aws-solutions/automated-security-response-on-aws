// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { getLogger } from '../../common/utils/logger';

const logger = getLogger('controlPlaceholderMappings');

/** Map of placeholder names to their replacement values */
export type PlaceholderMap = Record<string, string>;

/**
 * Minimal interface for the ASFF finding data shape used by placeholder extraction.
 * We access Resources[0].Id, Resources[0].Details, Resources[0].Region, and AwsAccountId.
 */
export interface SecurityFindingData {
  AwsAccountId?: string;
  Resources?: Array<{
    Id?: string;
    Region?: string;
    Details?: Record<string, Record<string, unknown>>;
  }>;
}

/**
 * Extracts the resource name from the first resource in an ASFF finding.
 * Parses the ARN to get the last segment (resource name), or returns the full ID
 * if it is not an ARN format.
 */
export function extractResourceName(securityFinding: SecurityFindingData | null | undefined): string | undefined {
  const resourceId: string | undefined = securityFinding?.Resources?.[0]?.Id;
  if (!resourceId) {
    return undefined;
  }

  if (resourceId.startsWith('arn:')) {
    const arnParts = resourceId.split(':');
    if (arnParts.length >= 6) {
      const resourcePart = arnParts.slice(5).join(':');
      const segments = resourcePart.split(/[/:]/);
      return segments.at(-1) || undefined;
    }
  }

  return resourceId;
}

/**
 * Generic extractor: looks up a property in the first resource's Details object,
 * falling back to extractResourceName.
 */
function fromDetails(
  detailsKey: string,
  property: string,
): (securityFinding: SecurityFindingData | null | undefined) => string | undefined {
  return (securityFinding) => {
    const value = securityFinding?.Resources?.[0]?.Details?.[detailsKey]?.[property];
    if (typeof value === 'string' && value) return value;
    return extractResourceName(securityFinding);
  };
}

/**
 * Extracts a value from an ARN segment pattern (e.g., ":vpc/vpc-123" → "vpc-123").
 * Checks Details keys first, then parses the ARN. Does NOT fall back to extractResourceName.
 */
function fromArnSegment(
  segment: string,
  ...detailsFallbacks: Array<{ key: string; property: string }>
): (securityFinding: SecurityFindingData | null | undefined) => string | undefined {
  return (securityFinding) => {
    const resource = securityFinding?.Resources?.[0];
    if (!resource) return undefined;

    for (const { key, property } of detailsFallbacks) {
      const value = resource.Details?.[key]?.[property];
      if (typeof value === 'string' && value) return value;
    }

    const resourceId: string | undefined = resource.Id;
    if (resourceId?.includes(`:${segment}/`)) {
      const extracted = resourceId.split(`:${segment}/`)[1];
      if (extracted) return extracted;
    }

    return undefined;
  };
}

/** Placeholder definition: name used in templates + how to extract the value */
interface PlaceholderDef {
  placeholder: string;
  extract: (securityFinding: SecurityFindingData | null | undefined) => string | undefined;
}

/**
 * Reusable {region} placeholder. Templates that compose ARNs or service names
 * (e.g. com.amazonaws.<region>.ec2) include this so the rendered code shows
 * the customer's real region instead of a 'REGION' literal they'd hand-edit.
 */
const REGION_PLACEHOLDER: PlaceholderDef = {
  placeholder: 'region',
  extract: (securityFinding) => {
    const region = securityFinding?.Resources?.[0]?.Region;
    if (region) return region;
    const resourceId = securityFinding?.Resources?.[0]?.Id;
    if (resourceId?.startsWith('arn:')) return resourceId.split(':')[3] || undefined;
    return undefined;
  },
};

/**
 * Reusable {accountId} placeholder. Pulled from the finding's AwsAccountId so
 * customer-account-scoped ARNs render with the real value at preview time.
 */
const ACCOUNT_ID_PLACEHOLDER: PlaceholderDef = {
  placeholder: 'accountId',
  extract: (securityFinding) => {
    if (securityFinding?.AwsAccountId) return securityFinding.AwsAccountId;
    const resourceId = securityFinding?.Resources?.[0]?.Id;
    return resourceId?.startsWith('arn:') ? resourceId.split(':')[4] : undefined;
  },
};

/** Reusable VPC ID extractor — shared across EC2.6 and EC2.10 mappings. */
const extractVpcId = fromArnSegment(
  'vpc',
  { key: 'AwsEc2Vpc', property: 'VpcId' },
  { key: 'AwsEc2SecurityGroup', property: 'VpcId' },
);

/** Reusable security group ID extractor — shared across EC2.2, EC2.13, EC2.18, EC2.19. */
const extractSecurityGroupId = (securityFinding: SecurityFindingData | null | undefined): string | undefined =>
  fromArnSegment('security-group', { key: 'AwsEc2SecurityGroup', property: 'GroupId' })(securityFinding) ||
  extractResourceName(securityFinding);

const extractBucketName = fromDetails('AwsS3Bucket', 'Name');
const extractDbInstanceId = fromDetails('AwsRdsDbInstance', 'DBInstanceIdentifier');

/**
 * Maps controlId → placeholder extraction definitions.
 * Uses generic helpers to avoid repetitive per-service extractor functions.
 */
export const CONTROL_PLACEHOLDER_MAPPINGS: Record<string, PlaceholderDef[]> = {
  // ─── S3 ────────────────────────────────────────────────────────────────────────
  'S3.1': [{ placeholder: 'accountPublicAccessBlock', extract: () => 'accountPublicAccessBlock' }],
  'S3.2': [{ placeholder: 'bucketName', extract: extractBucketName }],
  'S3.4': [{ placeholder: 'bucketName', extract: extractBucketName }],
  'S3.5': [{ placeholder: 'bucketName', extract: extractBucketName }],
  'S3.6': [{ placeholder: 'bucketName', extract: extractBucketName }],
  'S3.9': [{ placeholder: 'bucketName', extract: extractBucketName }],
  'S3.11': [{ placeholder: 'bucketName', extract: extractBucketName }],
  'S3.13': [{ placeholder: 'bucketName', extract: extractBucketName }],
  'S3.14': [{ placeholder: 'bucketName', extract: extractBucketName }],

  // ─── EC2 ───────────────────────────────────────────────────────────────────────
  'EC2.1': [{ placeholder: 'snapshotBlockPublicAccess', extract: () => 'snapshotBlockPublicAccess' }],
  'EC2.2': [
    { placeholder: 'defaultSecurityGroup', extract: extractSecurityGroupId },
    {
      placeholder: 'vpcId',
      extract: fromArnSegment('vpc', { key: 'AwsEc2SecurityGroup', property: 'VpcId' }),
    },
  ],
  // EC2.4 — operational only (terminate stopped instances); no IaC placeholders
  'EC2.6': [
    { placeholder: 'vpcId', extract: extractVpcId },
    {
      placeholder: 'flowLogGroup',
      extract: (securityFinding) => {
        const vpcId = extractVpcId(securityFinding);
        return vpcId ? `VPCFlowLogs/${vpcId}` : undefined;
      },
    },
    {
      placeholder: 'flowLog',
      extract: (securityFinding) => {
        const vpcId = extractVpcId(securityFinding);
        return vpcId ? `${vpcId}-flow-log` : undefined;
      },
    },
    {
      placeholder: 'flowLogRole',
      extract: (securityFinding) => {
        const vpcId = extractVpcId(securityFinding);
        return vpcId ? `${vpcId}-flow-log-role` : undefined;
      },
    },
  ],
  'EC2.7': [{ placeholder: 'ebsEncryption', extract: () => 'ebsEncryption' }],
  'EC2.8': [{ placeholder: 'instanceId', extract: fromDetails('AwsEc2Instance', 'InstanceId') }],
  'EC2.10': [
    { placeholder: 'vpcEndpoint', extract: extractVpcId },
    { placeholder: 'vpcId', extract: extractVpcId },
    // Region needed to compose the VPC endpoint service name
    // (com.amazonaws.<region>.ec2).
    REGION_PLACEHOLDER,
  ],
  'EC2.13': [{ placeholder: 'securityGroup', extract: extractSecurityGroupId }],
  'EC2.15': [
    {
      placeholder: 'subnet',
      extract: (securityFinding) => fromArnSegment('subnet')(securityFinding) || extractResourceName(securityFinding),
    },
  ],
  'EC2.18': [{ placeholder: 'securityGroup', extract: extractSecurityGroupId }],
  'EC2.19': [{ placeholder: 'securityGroup', extract: extractSecurityGroupId }],
  'EC2.23': [{ placeholder: 'transitGateway', extract: extractResourceName }],

  // ─── RDS ───────────────────────────────────────────────────────────────────────
  'RDS.1': [
    { placeholder: 'dbInstance', extract: extractDbInstanceId },
    { placeholder: 'dbSnapshot', extract: extractDbInstanceId },
  ],
  'RDS.2': [{ placeholder: 'dbInstance', extract: extractDbInstanceId }],
  'RDS.4': [{ placeholder: 'dbInstance', extract: extractDbInstanceId }],
  'RDS.5': [{ placeholder: 'dbInstance', extract: extractDbInstanceId }],
  // RDS.6 references the customer's monitoring role ARN, which contains their
  // account id. Populating {accountId} from the finding lets the rendered
  // template show a real ARN rather than an 'ACCOUNT_ID' literal.
  'RDS.6': [{ placeholder: 'dbInstance', extract: extractDbInstanceId }, ACCOUNT_ID_PLACEHOLDER],
  'RDS.7': [{ placeholder: 'dbCluster', extract: fromDetails('AwsRdsDbCluster', 'DbClusterIdentifier') }],
  'RDS.8': [{ placeholder: 'dbInstance', extract: extractDbInstanceId }],
  'RDS.13': [{ placeholder: 'dbInstance', extract: extractDbInstanceId }],
  'RDS.16': [{ placeholder: 'dbCluster', extract: fromDetails('AwsRdsDbCluster', 'DbClusterIdentifier') }],

  // ─── CloudTrail ────────────────────────────────────────────────────────────────
  'CloudTrail.1': [{ placeholder: 'trailName', extract: fromDetails('AwsCloudTrailTrail', 'Name') }],
  'CloudTrail.2': [{ placeholder: 'trailName', extract: fromDetails('AwsCloudTrailTrail', 'Name') }],
  'CloudTrail.4': [{ placeholder: 'trailName', extract: fromDetails('AwsCloudTrailTrail', 'Name') }],
  'CloudTrail.5': [{ placeholder: 'trailName', extract: fromDetails('AwsCloudTrailTrail', 'Name') }],
  'CloudTrail.6': [{ placeholder: 'cloudTrailBucket', extract: extractBucketName }],
  'CloudTrail.7': [{ placeholder: 'cloudTrailBucket', extract: extractBucketName }],

  // ─── IAM ───────────────────────────────────────────────────────────────────────
  // IAM.3, IAM.8, IAM.22 — operational only (rotate/revoke credentials); no IaC placeholders.
  'IAM.7': [{ placeholder: 'accountPasswordPolicy', extract: () => 'accountPasswordPolicy' }],
  'IAM.18': [{ placeholder: 'supportRole', extract: () => 'aws_incident_support_role' }],

  // ─── DynamoDB ──────────────────────────────────────────────────────────────────
  'DynamoDB.1': [{ placeholder: 'tableName', extract: fromDetails('AwsDynamoDbTable', 'TableName') }],
  'DynamoDB.5': [{ placeholder: 'tableName', extract: fromDetails('AwsDynamoDbTable', 'TableName') }],
  'DynamoDB.6': [{ placeholder: 'tableName', extract: fromDetails('AwsDynamoDbTable', 'TableName') }],

  // ─── Lambda ────────────────────────────────────────────────────────────────────
  'Lambda.1': [{ placeholder: 'functionName', extract: fromDetails('AwsLambdaFunction', 'FunctionName') }],

  // ─── Redshift ──────────────────────────────────────────────────────────────────
  'Redshift.1': [{ placeholder: 'redshiftCluster', extract: fromDetails('AwsRedshiftCluster', 'ClusterIdentifier') }],
  'Redshift.3': [{ placeholder: 'redshiftCluster', extract: fromDetails('AwsRedshiftCluster', 'ClusterIdentifier') }],
  'Redshift.4': [{ placeholder: 'redshiftCluster', extract: fromDetails('AwsRedshiftCluster', 'ClusterIdentifier') }],
  'Redshift.6': [{ placeholder: 'redshiftCluster', extract: fromDetails('AwsRedshiftCluster', 'ClusterIdentifier') }],

  // ─── SecretsManager ────────────────────────────────────────────────────────────
  'SecretsManager.1': [{ placeholder: 'secret', extract: fromDetails('AwsSecretsManagerSecret', 'Name') }],
  'SecretsManager.4': [{ placeholder: 'secret', extract: fromDetails('AwsSecretsManagerSecret', 'Name') }],

  // ─── SNS ───────────────────────────────────────────────────────────────────────
  'SNS.1': [{ placeholder: 'snsTopic', extract: extractResourceName }],
  'SNS.2': [{ placeholder: 'snsTopic', extract: extractResourceName }],

  // ─── SQS ───────────────────────────────────────────────────────────────────────
  'SQS.1': [{ placeholder: 'sqsQueue', extract: fromDetails('AwsSqsQueue', 'QueueName') }],

  // ─── KMS ───────────────────────────────────────────────────────────────────────
  'KMS.4': [{ placeholder: 'kmsKey', extract: fromDetails('AwsKmsKey', 'KeyId') }],

  // ─── ECR ───────────────────────────────────────────────────────────────────────
  'ECR.1': [{ placeholder: 'repository', extract: fromDetails('AwsEcrRepository', 'RepositoryName') }],

  // ─── ECS ───────────────────────────────────────────────────────────────────────
  'ECS.5': [{ placeholder: 'taskDefinition', extract: extractResourceName }],

  // ─── ELB ───────────────────────────────────────────────────────────────────────
  'ELB.1': [{ placeholder: 'applicationLoadBalancer', extract: fromDetails('AwsElbv2LoadBalancer', 'Name') }],

  // ─── CodeBuild ─────────────────────────────────────────────────────────────────
  'CodeBuild.2': [{ placeholder: 'codeBuildProject', extract: fromDetails('AwsCodeBuildProject', 'Name') }],
  'CodeBuild.5': [{ placeholder: 'codeBuildProject', extract: fromDetails('AwsCodeBuildProject', 'Name') }],

  // ─── CloudWatch ────────────────────────────────────────────────────────────────
  'CloudWatch.1': [{ placeholder: 'logGroup', extract: extractResourceName }],
  'CloudWatch.16': [{ placeholder: 'logGroup', extract: extractResourceName }],

  // ─── CloudFront ────────────────────────────────────────────────────────────────
  'CloudFront.1': [{ placeholder: 'distribution', extract: extractResourceName }],
  'CloudFront.12': [{ placeholder: 'distribution', extract: extractResourceName }],

  // ─── AutoScaling ───────────────────────────────────────────────────────────────
  'AutoScaling.1': [
    { placeholder: 'autoScalingGroup', extract: fromDetails('AwsAutoScalingAutoScalingGroup', 'AutoScalingGroupName') },
  ],
  'AutoScaling.3': [{ placeholder: 'launchConfiguration', extract: extractResourceName }],
  // Codebase + iac-templates dir use 'Autoscaling.5' (lowercase s); matches
  // playbooks/SC/ssmdocs/SC_Autoscaling.5.ts. Keep mapping key consistent so
  // iacTemplatePlaceholderCoverage (mapping↔template-dir) passes.
  'Autoscaling.5': [{ placeholder: 'launchConfiguration', extract: extractResourceName }],

  // ─── ElastiCache ───────────────────────────────────────────────────────────────
  'ElastiCache.1': [
    { placeholder: 'replicationGroup', extract: fromDetails('AwsElastiCacheReplicationGroup', 'ReplicationGroupId') },
  ],
  'ElastiCache.2': [{ placeholder: 'cacheCluster', extract: extractResourceName }],
  'ElastiCache.3': [
    { placeholder: 'replicationGroup', extract: fromDetails('AwsElastiCacheReplicationGroup', 'ReplicationGroupId') },
  ],

  // ─── Config ────────────────────────────────────────────────────────────────────
  'Config.1': [{ placeholder: 'configRecorder', extract: () => 'configRecorder' }],

  // ─── CloudFormation ────────────────────────────────────────────────────────────
  'CloudFormation.1': [{ placeholder: 'stack', extract: extractResourceName }],
  'CloudFormation.3': [{ placeholder: 'stack', extract: extractResourceName }],

  // ─── APIGateway ────────────────────────────────────────────────────────────────
  'APIGateway.1': [{ placeholder: 'ApiStage', extract: extractResourceName }],
  'APIGateway.5': [{ placeholder: 'ApiStage', extract: extractResourceName }],

  // ─── Athena ────────────────────────────────────────────────────────────────────
  'Athena.4': [{ placeholder: 'AthenaWorkGroup', extract: extractResourceName }],

  // ─── GuardDuty ─────────────────────────────────────────────────────────────────
  'GuardDuty.1': [{ placeholder: 'detector', extract: () => 'detector' }],
  'GuardDuty.2': [{ placeholder: 'filter', extract: extractResourceName }],

  // ─── Macie ─────────────────────────────────────────────────────────────────────
  'Macie.1': [{ placeholder: 'macieSession', extract: () => 'macieSession' }],

  // ─── SSM ───────────────────────────────────────────────────────────────────────
  'SSM.1': [{ placeholder: 'instanceId', extract: fromDetails('AwsEc2Instance', 'InstanceId') }],
  'SSM.4': [{ placeholder: 'document', extract: extractResourceName }],
};

/**
 * Builds a placeholder map for a given control by extracting values from the ASFF finding.
 * Only includes entries where the extraction returns a non-empty value.
 */
export function buildPlaceholderMap(
  controlId: string,
  securityFinding: SecurityFindingData | null | undefined,
): PlaceholderMap {
  const mappings = CONTROL_PLACEHOLDER_MAPPINGS[controlId];
  if (!mappings) {
    return {};
  }

  const result: PlaceholderMap = {};
  for (const mapping of mappings) {
    try {
      const value = mapping.extract(securityFinding);
      if (value) {
        result[mapping.placeholder] = value;
      }
    } catch (error) {
      // warn (not debug): an extractor throwing indicates either a code bug or
      // an unexpected ASFF shape — both worth surfacing in normal operation.
      logger.warn('Placeholder extraction failed', { controlId, placeholder: mapping.placeholder, error });
    }
  }
  return result;
}
