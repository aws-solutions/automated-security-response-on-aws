// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { CfnOutput, Duration, Stack, StackProps } from "aws-cdk-lib";
import { Key } from "aws-cdk-lib/aws-kms";
import { Secret } from "aws-cdk-lib/aws-secretsmanager";
import { Queue, QueueEncryption } from "aws-cdk-lib/aws-sqs";
import {
  BlockPublicAccess,
  Bucket,
  BucketEncryption,
} from "aws-cdk-lib/aws-s3";
import { Code, Function, Runtime } from "aws-cdk-lib/aws-lambda";

/**
 * Stack which creates the resources necessary to trigger the following Security Hub findings:
 * - [S3.9, KMS.4, SecretsManager.1, SQS.1]
 * Deploy this stack on its own, or nested within the TestStack for automatic test data generation.
 */
export class RemediationResourcesStack extends Stack {
  private readonly kmsKey: Key;
  private readonly s3Bucket: Bucket;
  private readonly secret: Secret;
  private readonly sqsQueue: Queue;

  constructor(scope: Stack, id: string, props: StackProps) {
    super(scope, id, props);

    // Resources for KMS.4 Remediation https://docs.aws.amazon.com/securityhub/latest/userguide/kms-controls.html#kms-4
    const testingKMSKey = new Key(this, "TestingKMSKey", {
      enableKeyRotation: false, // intentional: triggers Security Hub finding
      enabled: true,
      description:
        "Created by the ASR Remediation Resources testing stack. Used only for testing KMS.4 remediation.",
    });

    // Resources for S3.9 Remediation https://docs.aws.amazon.com/securityhub/latest/userguide/s3-controls.html#s3-9
    const testingBucket = new Bucket(this, "TestingBucket", {
      blockPublicAccess: BlockPublicAccess.BLOCK_ALL,
      encryption: BucketEncryption.S3_MANAGED,
      enforceSSL: true,
      versioned: true,
    });

    // Secrets require a Lambda function to be attached in order to enable/disable automatic rotation.
    const dummyFunction = new Function(this, "DummyFunction", {
      runtime: Runtime.PYTHON_3_11,
      description:
        "Arbitrary function created by the ASR RemediationResourcesStack to be attached to the TestingSecret.",
      code: Code.fromInline(`
        def handler(_, __):
          print("hello world!")
      `),
      handler: "handler",
    });
    // Resources for SecretsManager.1 Remediation https://docs.aws.amazon.com/securityhub/latest/userguide/secretsmanager-controls.html#secretsmanager-1
    // Caveat: This Secret will not begin generating findings until the first execution of the reset reset_remediation_resources function.
    const testingSecret = new Secret(this, "TestingSecret", {});
    testingSecret.addRotationSchedule("rotation", {
      automaticallyAfter: Duration.days(0),
      rotationLambda: dummyFunction,
    });

    // Resources for SQS.1 Remediation https://docs.aws.amazon.com/securityhub/latest/userguide/sqs-controls.html#sqs-1
    const testingQueue = new Queue(this, "TestingQueue", {
      encryption: QueueEncryption.UNENCRYPTED, // intentional: triggers Security Hub finding
    });

    this.secret = testingSecret;
    this.s3Bucket = testingBucket;
    this.kmsKey = testingKMSKey;
    this.sqsQueue = testingQueue;

    new CfnOutput(this, "KMS Key for KMS.4", {
      value: testingKMSKey.keyArn,
    });
    new CfnOutput(this, "S3 Bucket for S3.9", {
      value: testingBucket.bucketArn,
    });
    new CfnOutput(this, "SecretsManager Secret for SecretsManager.1", {
      value: testingSecret.secretArn,
    });
    new CfnOutput(this, "SQS Queue for SQS.1", {
      value: testingQueue.queueArn,
    });
  }

  getKmsKey() {
    return this.kmsKey;
  }

  getS3Bucket() {
    return this.s3Bucket;
  }

  getSecret() {
    return this.secret;
  }

  getSqsQueue() {
    return this.sqsQueue;
  }
}
