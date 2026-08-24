// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { CfnCondition, CfnResource, Stack } from 'aws-cdk-lib';
import { ServicePrincipal } from 'aws-cdk-lib/aws-iam';
import { IKey } from 'aws-cdk-lib/aws-kms';
import { EventType, IBucket } from 'aws-cdk-lib/aws-s3';
import { SnsDestination } from 'aws-cdk-lib/aws-s3-notifications';
import { ITopic } from 'aws-cdk-lib/aws-sns';
import { Construct, IConstruct } from 'constructs';
import { addCfnGuardSuppression } from './cdk-helper/add-cfn-guard-suppression';

export interface IaCTemplatesMonitoringProps {
  /** The IaC templates bucket whose deletes operators want notified about. */
  readonly bucket: IBucket;
  /** Existing SNS topic the notification publishes to. */
  readonly topic: ITopic;
  /**
   * KMS customer-managed key encrypting `topic`. S3 needs
   * `kms:GenerateDataKey*` + `kms:Decrypt` on this CMK to publish event
   * notifications to the topic; without the grant the publish fails with
   * KMSAccessDeniedException.
   */
  readonly topicEncryptionKey: IKey;
  /**
   * Bucket ARN used for the `aws:SourceArn` scoping on the S3->KMS grant.
   * Must be a literal/name-derived ARN (not the bucket's `Fn::GetAtt`/`Ref`):
   * when the same CMK encrypts the bucket, referencing the bucket resource here
   * creates a key<->bucket CloudFormation dependency cycle.
   */
  readonly bucketSourceArn: string;
  /**
   * Condition controlling whether `topic` is provisioned. Mirrored onto the
   * CDK-generated resources that wire the bucket notification to the topic
   * (BucketNotificationsHandler Lambda + IAM role/policy and the per-bucket
   * Custom::S3BucketNotifications custom resource), so all referenced
   * resources synthesize together.
   */
  readonly topicCondition: CfnCondition;
}

/**
 * Wires an S3 event notification on the IaC templates bucket to an existing
 * SNS topic. The topic is owned elsewhere (typically the operational alarm
 * topic from CloudWatchMetrics); this construct adds the notification
 * subscription, the KMS grant S3 needs to publish to the topic, and the CFN
 * condition gating on the CDK-generated bucket-notifications resources.
 *
 * The bucket holds customer-customizable IaC remediation snippets (CDK,
 * CloudFormation, Terraform) referenced in remediation notifications, so any
 * deletion activity here is unexpected and operators need to know.
 *
 * The bucket is versioned with a 90-day noncurrentVersionExpiration lifecycle
 * rule. We listen on OBJECT_REMOVED, which covers both:
 *
 * - DELETE — operator-driven hard deletes and the 90-day noncurrent cleanup.
 *   The 90-day cleanup is low-frequency baseline noise correlated with
 *   template churn; tolerated to keep the signal for hard deletes.
 * - DELETE_MARKER_CREATED — versioned-bucket soft deletes. Recoverable, but
 *   recovery requires a manual delete-marker removal — operators should know.
 */
export class IaCTemplatesMonitoringConstruct extends Construct {
  constructor(scope: Construct, id: string, props: IaCTemplatesMonitoringProps) {
    super(scope, id);

    // S3 needs kms:GenerateDataKey* + kms:Decrypt on the topic's CMK to
    // encrypt and publish event notifications. SnsDestination handles the
    // topic's resource policy; the KMS key policy is the bucket's
    // responsibility. Scope the grant to this bucket via aws:SourceArn so
    // the key cannot be used by S3 in other accounts.
    //
    // bucketSourceArn is a name-derived ARN rather than `bucket.bucketArn` (a
    // Fn::GetAtt): when the same CMK also encrypts the bucket, a GetAtt here
    // makes the key depend on the bucket while the bucket depends on the key,
    // producing a CloudFormation dependency cycle.
    props.topicEncryptionKey.grant(
      new ServicePrincipal('s3.amazonaws.com', {
        conditions: {
          ArnLike: { 'aws:SourceArn': props.bucketSourceArn },
        },
      }),
      'kms:GenerateDataKey*',
      'kms:Decrypt',
    );

    props.bucket.addEventNotification(EventType.OBJECT_REMOVED, new SnsDestination(props.topic));

    // addEventNotification synthesizes a stack-level singleton
    // BucketNotificationsHandler Lambda + IAM role, a per-bucket
    // Custom::S3BucketNotifications + IAM::Policy, and (via SnsDestination)
    // an AWS::SNS::TopicPolicy on `topic`. All five reference props.topic;
    // mirror its condition so they synthesize together.
    applyTopicConditionToBucketNotificationsResources(this, props.bucket, props.topicCondition);

    // SnsDestination calls addToResourcePolicy on the topic, which lazily
    // creates a TopicPolicy child at id 'Policy'. That policy resource also
    // references the conditional topic and must mirror the condition;
    // otherwise CFN tries to attach a policy to a non-existent topic when
    // alarms are disabled.
    const topicPolicy = props.topic.node.tryFindChild('Policy');
    if (topicPolicy) {
      applyConditionIfMissing(topicPolicy, props.topicCondition);
    }
  }
}

/**
 * Apply `condition` to the CDK-synthesized resources backing the bucket → SNS
 * notification, and add cfn-guard suppressions on the singleton handler
 * Lambda for rules it cannot satisfy (no VPC, no reserved concurrency,
 * internal logical IDs). See `source/lib/member/cloud-trail.ts` for the same
 * suppression pattern.
 *
 * Resource layout:
 * - stack-level singleton `BucketNotificationsHandler...`: defaultChild =
 *   Lambda, child `Role` = IAM Role.
 * - per-bucket (under the bucket node) `Notifications`
 *   (Custom::S3BucketNotifications) and sibling `HandlerPolicy`
 *   (AWS::IAM::Policy granting s3:PutBucketNotification on the bucket to
 *   the singleton role).
 *
 * The handler is stack-scoped because it is a singleton shared by every
 * bucket using addEventNotification in the same stack. The per-bucket
 * resources are scoped to `bucket.node` to avoid matching `Notifications`
 * children of unrelated constructs in the same stack.
 */
function applyTopicConditionToBucketNotificationsResources(
  scope: Construct,
  bucket: IBucket,
  condition: CfnCondition,
): void {
  const stack = Stack.of(scope);

  const handlerL2s = stack.node.findAll().filter((node) => node.node.id.includes('BucketNotificationsHandler'));
  if (handlerL2s.length === 0) {
    throw new Error('Expected at least one BucketNotificationsHandler-related node, found none');
  }
  for (const handler of handlerL2s) {
    addCfnGuardSuppression(handler, 'CFN_NO_EXPLICIT_RESOURCE_NAMES');
    addCfnGuardSuppression(handler, 'LAMBDA_CONCURRENCY_CHECK');
    addCfnGuardSuppression(handler, 'LAMBDA_INSIDE_VPC');
    applyConditionIfMissing(handler, condition); // Lambda (defaultChild)
    const role = handler.node.tryFindChild('Role');
    if (role) {
      applyConditionIfMissing(role, condition);
    }
  }

  const perBucketNotificationsL2s = bucket.node.findAll().filter((node) => node.node.id === 'Notifications');
  if (perBucketNotificationsL2s.length === 0) {
    throw new Error('Expected a per-bucket Notifications node under the bucket, found none');
  }
  for (const bucketNotifications of perBucketNotificationsL2s) {
    applyConditionIfMissing(bucketNotifications, condition); // Custom::S3BucketNotifications (defaultChild)
    const handlerPolicy = bucketNotifications.node.tryFindChild('HandlerPolicy');
    if (handlerPolicy) {
      applyConditionIfMissing(handlerPolicy, condition); // AWS::IAM::Policy
    }
  }
}

function applyConditionIfMissing(node: IConstruct, condition: CfnCondition): void {
  const cfn = resolveCfnResource(node);
  if (!cfn) {
    throw new Error(`Cannot apply condition: node ${node.node.path} did not resolve to a CfnResource`);
  }
  cfn.cfnOptions.condition ??= condition;
}

function resolveCfnResource(node: IConstruct): CfnResource | undefined {
  if (node instanceof CfnResource) {
    return node;
  }
  const child = node.node.defaultChild;
  return child instanceof CfnResource ? child : undefined;
}
