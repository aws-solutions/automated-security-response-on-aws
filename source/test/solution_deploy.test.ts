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

// Mock Date to return consistent timestamp
beforeAll(() => {
  jest.useFakeTimers();
  jest.setSystemTime(new Date('2025-01-01T00:00:00.000Z'));
});

afterAll(() => {
  jest.useRealTimers();
});

function getTestStack(): Stack {
  const envEU = { account: '111111111111', region: 'eu-west-1' };
  const app = new App();

  return new AdministratorStack(app, 'stack', {
    synthesizer: new DefaultStackSynthesizer({ generateBootstrapVersionRule: false }),
    env: envEU,
    solutionId: 'SO0111',
    solutionVersion: 'v1.0.0',
    solutionDistBucket: 'solutions',
    solutionTMN: 'automated-security-response-on-aws',
    solutionName: 'AWS Security Hub Automated Response & Remediation',
    runtimePython: Runtime.PYTHON_3_11,
    orchestratorLogGroup: 'ORCH_LOG_GROUP',
    SNSTopicName: 'ASR_Topic',
    cloudTrailLogGroupName: 'some-loggroup-name',
  });
}

test('Test if the Stack has all the resources.', () => {
  process.env.DIST_OUTPUT_BUCKET = 'solutions';
  process.env.SOLUTION_NAME = 'AWS Security Hub Automated Response & Remediation';
  process.env.DIST_VERSION = 'v1.0.0';
  process.env.SOLUTION_ID = 'SO0111111';
  process.env.SOLUTION_TRADEMARKEDNAME = 'automated-security-response-on-aws';
  expect(Template.fromStack(getTestStack())).toMatchSnapshot();
});

test('PreProcessorConstruct creates expected resources', () => {
  // Create a test stack
  const app = new App();
  const stack = new Stack(app, 'TestStack');

  const testTable = new Table(stack, 'testTable', {
    partitionKey: { name: 'findingType', type: dynamodb.AttributeType.STRING },
  });

  // Create the PreProcessorConstruct
  new PreProcessorConstruct(stack, 'PreProcessor', {
    solutionId: 'SO0111',
    solutionVersion: 'v1.0.0',
    resourceNamePrefix: 'SO0111',
    solutionTMN: 'automated-security-response-on-aws',
    solutionsBucket: new Bucket(stack, 'test-bucket', {}),
    findingsTable: testTable.tableArn,
    remediationHistoryTable: testTable.tableArn,
    functionName: 'findings-table-name',
    kmsKey: new Key(stack, 'test-key', {}),
    orchestratorArn: 'arn:aws:states:region:account-id:stateMachine:myStateMachine',
    remediationConfigTable: testTable.tableArn,
    findingsTTL: '8',
    historyTTL: '365',
  });

  const template = Template.fromStack(stack);

  template.resourceCountIs('AWS::SQS::Queue', 2);

  template.hasResourceProperties('AWS::SQS::Queue', {
    VisibilityTimeout: 900, // 15 minutes
  });

  template.hasResourceProperties('AWS::SQS::Queue', {
    MessageRetentionPeriod: 1209600, // 14 days
  });

  template.hasResourceProperties('AWS::Lambda::Function', {
    Runtime: 'nodejs22.x',
    Handler: 'pre-processor/preProcessor.handler',
    Timeout: 900,
    MemorySize: 512,
    Environment: {
      Variables: {
        SOLUTION_TRADEMARKEDNAME: 'automated-security-response-on-aws',
        POWERTOOLS_LOG_LEVEL: 'INFO',
      },
    },
    TracingConfig: {
      Mode: 'Active',
    },
  });

  template.hasResourceProperties('AWS::Lambda::EventSourceMapping', {
    BatchSize: 10,
    MaximumBatchingWindowInSeconds: 5,
    FunctionResponseTypes: ['ReportBatchItemFailures'],
  });
});

test('Synchronization handler supports both scheduled and custom resource events', () => {
  const template = Template.fromStack(getTestStack());

  template.hasResourceProperties('AWS::DynamoDB::Table', {
    TimeToLiveSpecification: {
      AttributeName: 'TTL',
      Enabled: true,
    },
  });

  template.hasResourceProperties('AWS::Events::Rule', {
    ScheduleExpression: 'cron(0 2 ? * SAT *)',
    Description: 'Weekly full synchronization of Security Hub findings - always performs complete sync',
  });

  template.hasResourceProperties('AWS::Lambda::Function', {
    FunctionName: 'SO0111-ASR-SynchronizationTriggerProvider',
    Handler: 'synchronization/customResourceHandler.handler',
    Runtime: 'nodejs22.x',
    Timeout: 300,
    MemorySize: 128,
  });

  template.hasResourceProperties('AWS::Lambda::Function', {
    FunctionName: 'SO0111-ASR-SynchronizationFindingsLambda',
    Handler: 'synchronization/synchronizationHandler.handler',
    Runtime: 'nodejs22.x',
    Timeout: 900,
    MemorySize: 512,
  });

  template.hasResourceProperties('AWS::CloudFormation::CustomResource', {
    TriggerReason: 'WebUI deployment completed',
  });
});
