// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { CustomResource, Duration, RemovalPolicy, Stack } from 'aws-cdk-lib';
import {
  Effect,
  ManagedPolicy,
  PolicyDocument,
  PolicyStatement,
  AccountPrincipal,
  Role,
  ServicePrincipal,
} from 'aws-cdk-lib/aws-iam';
import { IKey } from 'aws-cdk-lib/aws-kms';
import { Runtime } from 'aws-cdk-lib/aws-lambda';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import { BlockPublicAccess, Bucket, BucketEncryption, EventType, ObjectOwnership } from 'aws-cdk-lib/aws-s3';
import { SnsDestination } from 'aws-cdk-lib/aws-s3-notifications';
import { Topic } from 'aws-cdk-lib/aws-sns';
import { StringParameter } from 'aws-cdk-lib/aws-ssm';
import { Construct } from 'constructs';
import { addCfnGuardSuppression } from '../cdk-helper/add-cfn-guard-suppression';
import { createLogGroup } from '../cdk-helper/log-group';
import { getLambdaCode } from '../cdk-helper/lambda-code-manifest';

// Fixed name for the customer-managed policy that grants read-only access to the
// remediation configuration bucket. The Inspector.InstanceVulnerability remediation
// role attaches this policy (by ARN, under an iam:PolicyARN condition) to the target
// instance's IAM role, instead of holding an unconditioned iam:PutRolePolicy. The name
// is fixed so both the remediation role's condition and the runbook script can derive
// the same ARN at deploy time and at runtime.
export const REMEDIATION_CONFIG_BUCKET_ACCESS_POLICY_NAME = 'ASR-RemediationConfigBucketAccess';

export interface RemediationConfigurationBucketProps {
  readonly solutionId: string;
  readonly solutionVersion: string;
  readonly solutionTMN: string;
  readonly solutionDistBucket: string;
  readonly runtimePython: Runtime;
  readonly kmsKey: IKey;
}

export class RemediationConfigurationBucket extends Construct {
  public readonly bucket: Bucket;

  constructor(scope: Construct, id: string, props: RemediationConfigurationBucketProps) {
    super(scope, id);

    const stack = Stack.of(this);

    // Create all resources at `scope` scope rather than `this` to maintain logical IDs

    // Access logging bucket for the remediation configuration bucket
    const accessLogsBucket = new Bucket(scope, 'RemediationConfigAccessLogs', {
      objectOwnership: ObjectOwnership.OBJECT_WRITER,
      removalPolicy: RemovalPolicy.RETAIN,
      encryption: BucketEncryption.S3_MANAGED,
      enforceSSL: true,
      versioned: true,
      blockPublicAccess: BlockPublicAccess.BLOCK_ALL,
      lifecycleRules: [{ id: 'ExpireAccessLogs', expiration: Duration.days(90), enabled: true }],
    });
    addCfnGuardSuppression(accessLogsBucket, 'S3_BUCKET_LOGGING_ENABLED');

    const bucket = new Bucket(scope, 'RemediationConfigurationBucket', {
      bucketName: `so0111-asr-remediation-${stack.region}-${stack.account}`,
      versioned: true,
      encryption: BucketEncryption.S3_MANAGED,
      enforceSSL: true,
      publicReadAccess: false,
      blockPublicAccess: BlockPublicAccess.BLOCK_ALL,
      removalPolicy: RemovalPolicy.RETAIN,
      serverAccessLogsBucket: accessLogsBucket,
      serverAccessLogsPrefix: 'remediation-config-access-logs/',
      lifecycleRules: [
        {
          id: 'GuardDutyBackupRetention',
          prefix: 'guardduty-backups/',
          expiration: Duration.days(90),
          enabled: true,
        },
        {
          // Safety net: expire orphaned InstallOverrideList files if _delete_override_list
          // fails silently. Normal cleanup happens explicitly after patching completes.
          id: 'InstallOverrideListExpiration',
          prefix: 'install-overrides/',
          expiration: Duration.days(7),
          enabled: true,
        },
      ],
    });
    this.bucket = bucket;

    // Operators subscribe to this topic to detect unauthorized object tampering or deletions
    const monitoringTopic = new Topic(scope, 'RemediationConfigMonitoringTopic', {
      displayName: 'ASR Remediation Config Bucket Monitoring',
      masterKey: props.kmsKey,
    });
    monitoringTopic.addToResourcePolicy(
      new PolicyStatement({
        effect: Effect.ALLOW,
        principals: [new ServicePrincipal('s3.amazonaws.com')],
        actions: ['sns:Publish'],
        resources: [monitoringTopic.topicArn],
        conditions: { ArnLike: { 'aws:SourceArn': bucket.bucketArn } },
      }),
    );

    const monitoredPrefixes = ['guardduty-backups/', 'install-overrides/', 'baseline-overrides/'];
    for (const prefix of monitoredPrefixes) {
      bucket.addEventNotification(EventType.OBJECT_CREATED, new SnsDestination(monitoringTopic), { prefix });
      bucket.addEventNotification(EventType.OBJECT_REMOVED, new SnsDestination(monitoringTopic), { prefix });
    }

    // Suppress CFN Guard rules on CDK-generated BucketNotificationsHandler singleton Lambda.
    // This is an internal CDK resource that runs only during deployments - VPC and concurrency are unnecessary.
    const handlerNodes = stack.node.findAll().filter((node) => node.node.id.includes('BucketNotificationsHandler'));
    for (const handler of handlerNodes) {
      addCfnGuardSuppression(handler, 'LAMBDA_INSIDE_VPC');
      addCfnGuardSuppression(handler, 'LAMBDA_CONCURRENCY_CHECK');
    }

    // Allow EC2 instances (via SSM) to read install-overrides and baseline-overrides
    bucket.addToResourcePolicy(
      new PolicyStatement({
        sid: 'AllowEC2ReadForPatching',
        effect: Effect.ALLOW,
        actions: ['s3:GetObject'],
        principals: [new AccountPrincipal(stack.account)],
        resources: [bucket.arnForObjects('install-overrides/*'), bucket.arnForObjects('baseline-overrides/*')],
        conditions: {
          StringEquals: {
            'aws:PrincipalAccount': stack.account,
          },
        },
      }),
    );

    bucket.addToResourcePolicy(
      new PolicyStatement({
        sid: 'AllowListBucket',
        effect: Effect.ALLOW,
        actions: ['s3:ListBucket'],
        principals: [new AccountPrincipal(stack.account)],
        resources: [bucket.bucketArn],
        conditions: {
          StringLike: {
            's3:prefix': ['install-overrides/*', 'baseline-overrides/*'],
          },
        },
      }),
    );

    // Customer-managed policy granting read-only access to the patch/baseline override
    // objects in this bucket. The Inspector.InstanceVulnerability remediation attaches
    // this fixed policy to the target EC2 instance's IAM role. Because the policy content
    // is deploy-time-known, the remediation role can be granted iam:AttachRolePolicy under
    // an iam:PolicyARN condition scoped to this exact policy — removing the need for an
    // unconditioned iam:PutRolePolicy on role/* (which was a privilege-escalation primitive).
    const remediationConfigBucketAccessPolicy = new ManagedPolicy(scope, 'RemediationConfigBucketAccessPolicy', {
      managedPolicyName: REMEDIATION_CONFIG_BUCKET_ACCESS_POLICY_NAME,
      description:
        'Read-only access to the ASR remediation configuration bucket (patch and baseline overrides). ' +
        'Attached by the Inspector.InstanceVulnerability remediation to the target EC2 instance role.',
      document: new PolicyDocument({
        statements: [
          new PolicyStatement({
            effect: Effect.ALLOW,
            actions: ['s3:GetObject'],
            resources: [bucket.arnForObjects('install-overrides/*'), bucket.arnForObjects('baseline-overrides/*')],
          }),
          new PolicyStatement({
            effect: Effect.ALLOW,
            actions: ['s3:ListBucket'],
            resources: [bucket.bucketArn],
          }),
        ],
      }),
    });
    addCfnGuardSuppression(remediationConfigBucketAccessPolicy, 'IAM_POLICYDOCUMENT_NO_WILDCARD_RESOURCE');
    // Explicit managedPolicyName is required: the Inspector.InstanceVulnerability remediation role is
    // granted iam:AttachRolePolicy under an iam:PolicyARN condition scoped to this exact policy ARN, so
    // the name must be deterministic/known at deploy time.
    addCfnGuardSuppression(remediationConfigBucketAccessPolicy, 'CFN_NO_EXPLICIT_RESOURCE_NAMES');

    // Store bucket name in SSM for use by control runbooks
    new StringParameter(scope, 'RemediationConfigurationBucketNameParam', {
      description: 'S3 bucket name for ASR remediation configuration files (patch overrides, GuardDuty backups)',
      parameterName: `/Solutions/${props.solutionId}/RemediationConfigurationBucket`,
      stringValue: bucket.bucketName,
    });

    // Custom resource Lambda to upload Windows BaselineOverride JSON at deployment time
    const solutionsBucket = Bucket.fromBucketName(
      scope,
      'BaselineConfigSolutionsBucket',
      `${props.solutionDistBucket}-${stack.region}`,
    );

    const baselineConfigRole = new Role(scope, 'BaselineConfigRole', {
      assumedBy: new ServicePrincipal('lambda.amazonaws.com'),
      inlinePolicies: {
        BaselineConfigPolicy: new PolicyDocument({
          statements: [
            new PolicyStatement({
              actions: ['s3:PutObject'],
              resources: [bucket.arnForObjects('baseline-overrides/*')],
            }),
            new PolicyStatement({
              actions: ['logs:CreateLogGroup', 'logs:CreateLogStream', 'logs:PutLogEvents'],
              resources: ['*'],
            }),
          ],
        }),
      },
    });
    addCfnGuardSuppression(baselineConfigRole, 'IAM_NO_INLINE_POLICY_CHECK');
    addCfnGuardSuppression(baselineConfigRole, 'IAM_POLICYDOCUMENT_NO_WILDCARD_RESOURCE');

    const baselineConfigFunction = new lambda.Function(scope, 'BaselineConfigFunction', {
      role: baselineConfigRole,
      runtime: Runtime.NODEJS_22_X,
      code: getLambdaCode(solutionsBucket, props.solutionTMN, props.solutionVersion, 'asr_lambdas.zip'),
      handler: 'baseline-configuration/baselineConfigurationHandler.handler',
      description: 'Uploads Windows security baseline configuration to the Remediation Configuration bucket',
      timeout: Duration.minutes(5),
      environment: {
        LOG_LEVEL: 'INFO',
        SOLUTION_TRADEMARKEDNAME: props.solutionTMN,
      },
      logGroup: createLogGroup(scope, 'BaselineConfigFunctionLogGroup'),
    });
    addCfnGuardSuppression(baselineConfigFunction, 'LAMBDA_CONCURRENCY_CHECK');
    addCfnGuardSuppression(baselineConfigFunction, 'LAMBDA_INSIDE_VPC');

    new CustomResource(scope, 'BaselineConfigurationResource', {
      serviceToken: baselineConfigFunction.functionArn,
      resourceType: 'Custom::BaselineConfiguration',
      properties: {
        BucketName: bucket.bucketName,
        // Use a timestamp to ensure the custom resource triggers on every deployment,
        // even during development under the same version string
        DeploymentTimestamp: new Date().toISOString(),
      },
    });
  }
}
