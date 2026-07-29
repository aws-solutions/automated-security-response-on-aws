// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { App, DefaultStackSynthesizer, Stack } from 'aws-cdk-lib';
import { Runtime } from 'aws-cdk-lib/aws-lambda';
import { Match, Template } from 'aws-cdk-lib/assertions';
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

test('Synchronization sweep state machine syncs accounts sequentially with a per-account circuit breaker', () => {
  const template = Template.fromStack(getTestStack());

  // The sweep is driven by a Step Functions state machine with a scoped execution role.
  template.hasResourceProperties('AWS::StepFunctions::StateMachine', {
    StateMachineName: 'SO0111-ASR-SynchronizationSweep',
    TracingConfiguration: { Enabled: true },
    LoggingConfiguration: {
      IncludeExecutionData: true,
      Level: 'ALL',
    },
  });

  template.hasResourceProperties('AWS::Logs::LogGroup', {
    LogGroupName: 'SO0111-ASR-SynchronizationSweep-Logs',
    RetentionInDays: 3653,
  });

  template.hasResourceProperties('AWS::IAM::Role', {
    RoleName: 'SO0111-ASR-SynchronizationSweep',
    AssumeRolePolicyDocument: {
      Statement: [
        Match.objectLike({
          Principal: { Service: 'states.amazonaws.com' },
        }),
      ],
    },
  });

  // The circuit-breaker attempt cap is a tunable stack parameter (default 5).
  template.hasParameter('*', {
    Type: 'Number',
    Default: 5,
    MinValue: 1,
    MaxValue: 100,
  });

  // The state machine definition drives the enumerate -> map -> mark-done flow via the sync Lambda.
  const stateMachines = template.findResources('AWS::StepFunctions::StateMachine', {
    Properties: { StateMachineName: 'SO0111-ASR-SynchronizationSweep' },
  });
  // The definition is an Fn::Join of literal fragments and CFN refs; join the literals so the state
  // graph structure (not just the task names) can be asserted, guarding the highest-risk logic.
  const definitionParts = Object.values(stateMachines)[0].Properties.DefinitionString['Fn::Join'][1] as unknown[];
  const definitionString = definitionParts.filter((part) => typeof part === 'string').join('');
  expect(definitionString).toContain('enumerate-accounts');
  expect(definitionString).toContain('sync-account-slice');
  expect(definitionString).toContain('mark-sweep-done');
  // The Map walks accounts strictly one at a time so concurrent GetFindings cannot exceed the Security
  // Hub rate limit the slice Lambda is paced against.
  expect(definitionString).toContain('"Type":"Map"');
  expect(definitionString).toContain('"MaxConcurrency":1');
  expect(definitionString).toContain('"ItemsPath":"$.accountIds"');
  // The circuit breaker is enforced by the state machine itself: a Pass decrements the per-account
  // attempt counter with a pure Step Functions intrinsic (no Lambda involvement).
  expect(definitionString).toContain('States.MathAdd($.attemptsRemaining, -1)');
  // The per-account resume loop: a Choice that completes when done, trips the breaker when attempts run
  // out, otherwise loops the same slice while it makes progress.
  expect(definitionString).toContain('"Type":"Choice"');
  expect(definitionString).toContain('"Variable":"$.slice.done","BooleanEquals":true');
  expect(definitionString).toContain('"Variable":"$.attemptsRemaining","NumericLessThanEquals":0');
  expect(definitionString).toContain('"Variable":"$.slice.madeProgress","BooleanEquals":true,"Next":"RunAccountSlice"');
  expect(definitionString).toContain('AccountSliceExhausted');
  // A per-account failure is tolerated (caught into a success Pass), so one bad account cannot fail the
  // whole Map / sweep — the inline-Map equivalent of ToleratedFailurePercentage 100.
  expect(definitionString).toContain('"Catch"');
  expect(definitionString).toContain('AccountSliceTolerated');
  expect(definitionString).not.toContain('"Type":"Fail"');
});

test('Synchronization trigger and weekly schedule start the sweep state machine', () => {
  const template = Template.fromStack(getTestStack());

  // The custom-resource trigger role can start exactly the sweep state machine (scoped, not '*').
  template.hasResourceProperties('AWS::IAM::Policy', {
    PolicyName: 'SO0111-ASR_SynchronizationTrigger',
    PolicyDocument: {
      Statement: Match.arrayWith([
        Match.objectLike({
          Action: 'states:StartExecution',
          Resource: Match.anyValue(),
        }),
      ]),
    },
  });
  // No lambda:InvokeFunction remains on the trigger role — it starts the state machine instead.
  const triggerPolicies = template.findResources('AWS::IAM::Policy', {
    Properties: { PolicyName: 'SO0111-ASR_SynchronizationTrigger' },
  });
  const triggerPolicyJson = JSON.stringify(Object.values(triggerPolicies)[0].Properties.PolicyDocument);
  expect(triggerPolicyJson).toContain('states:StartExecution');
  expect(triggerPolicyJson).not.toContain('lambda:InvokeFunction');

  // The sync Lambda no longer invokes itself, so its own role must not carry lambda:InvokeFunction; it
  // keeps only the ListMembers enumeration grant. The state machine drives every invocation.
  const syncPolicies = template.findResources('AWS::IAM::Policy', {
    Properties: { PolicyName: 'SO0111-ASR_Synchronization' },
  });
  const syncPolicyJson = JSON.stringify(Object.values(syncPolicies)[0].Properties.PolicyDocument);
  expect(syncPolicyJson).toContain('securityhub:ListMembers');
  expect(syncPolicyJson).not.toContain('lambda:InvokeFunction');

  // The weekly rule targets the state machine, not the Lambda.
  template.hasResourceProperties('AWS::Events::Rule', {
    ScheduleExpression: 'cron(0 2 ? * SAT *)',
    Targets: Match.arrayWith([
      Match.objectLike({
        Arn: { Ref: Match.stringLikeRegexp('SynchronizationSweepStateMachine') },
      }),
    ]),
  });
});
