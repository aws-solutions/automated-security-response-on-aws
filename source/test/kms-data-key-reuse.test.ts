// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { App, DefaultStackSynthesizer, Stack } from 'aws-cdk-lib';
import { Runtime } from 'aws-cdk-lib/aws-lambda';
import { Template } from 'aws-cdk-lib/assertions';
import { AdministratorStack } from '../lib/administrator-stack';
import { PreProcessorConstruct } from '../lib/pre-processor-construct';
import { Bucket } from 'aws-cdk-lib/aws-s3';
import { Key } from 'aws-cdk-lib/aws-kms';
import * as dynamodb from 'aws-cdk-lib/aws-dynamodb';
import { Table } from 'aws-cdk-lib/aws-dynamodb';

describe('KMS Data Key Reuse Configuration', () => {
  test('Administrator Stack SQS queues have data key reuse enabled', () => {
    const app = new App();
    const stack = new AdministratorStack(app, 'TestStack', {
      synthesizer: new DefaultStackSynthesizer({ generateBootstrapVersionRule: false }),
      env: { account: '111111111111', region: 'us-east-1' },
      solutionId: 'SO0111',
      solutionVersion: 'v3.1.0',
      solutionDistBucket: 'solutions',
      solutionTMN: 'automated-security-response-on-aws',
      solutionName: 'AWS Security Hub Automated Response & Remediation',
      runtimePython: Runtime.PYTHON_3_11,
      orchestratorLogGroup: 'ORCH_LOG_GROUP',
      SNSTopicName: 'ASR_Topic',
      cloudTrailLogGroupName: 'cloudtrail-logs',
    });

    const template = Template.fromStack(stack);

    // Verify all KMS-encrypted queues have data key reuse set to 3600 seconds (1 hour)
    const queues = template.findResources('AWS::SQS::Queue', {
      Properties: {
        KmsMasterKeyId: {},
      },
    });

    const queueKeys = Object.keys(queues);
    expect(queueKeys.length).toBeGreaterThan(0);

    queueKeys.forEach((queueKey) => {
      const queue = queues[queueKey];
      expect(queue.Properties.KmsDataKeyReusePeriodSeconds).toBe(3600);
    });
  });

  test('PreProcessor SQS queues have data key reuse enabled', () => {
    const app = new App();
    const stack = new Stack(app, 'TestStack');

    const testTable = new Table(stack, 'testTable', {
      partitionKey: { name: 'findingType', type: dynamodb.AttributeType.STRING },
    });

    const resourceFiltersTable = new Table(stack, 'resourceFiltersTable', {
      partitionKey: { name: 'filterId', type: dynamodb.AttributeType.STRING },
    });

    new PreProcessorConstruct(stack, 'PreProcessor', {
      solutionId: 'SO0111',
      solutionVersion: 'v3.1.0',
      resourceNamePrefix: 'SO0111',
      solutionTMN: 'automated-security-response-on-aws',
      solutionsBucket: new Bucket(stack, 'test-bucket', {}),
      findingsTable: testTable,
      remediationHistoryTable: testTable,
      functionName: 'test-function',
      kmsKey: new Key(stack, 'test-key', {}),
      orchestratorArn: 'arn:aws:states:us-east-1:111111111111:stateMachine:test',
      remediationConfigTable: testTable,
      resourceFiltersTable: resourceFiltersTable,
      notificationConfigTable: testTable,
      findingsTTL: '8',
      historyTTL: '365',
      notificationQueueUrl: 'https://sqs.us-east-1.amazonaws.com/123456789012/test-notification-queue',
    });

    const template = Template.fromStack(stack);

    // Verify both PreProcessor queues have data key reuse enabled
    const queues = template.findResources('AWS::SQS::Queue');
    const queueKeys = Object.keys(queues);

    expect(queueKeys.length).toBe(2); // PreProcessorQueue and PreProcessorDLQ

    queueKeys.forEach((queueKey) => {
      const queue = queues[queueKey];
      expect(queue.Properties.KmsDataKeyReusePeriodSeconds).toBe(3600);
    });
  });
});
