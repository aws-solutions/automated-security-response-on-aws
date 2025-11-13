// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { App, DefaultStackSynthesizer, Stack } from 'aws-cdk-lib';
import { PolicyStatement, PolicyDocument, ServicePrincipal, AccountRootPrincipal } from 'aws-cdk-lib/aws-iam';
import { Key } from 'aws-cdk-lib/aws-kms';
import { StringParameter } from 'aws-cdk-lib/aws-ssm';
import { Template, Match } from 'aws-cdk-lib/assertions';
import { OrchestratorConstruct } from '../lib/common-orchestrator-construct';
import * as sqs from 'aws-cdk-lib/aws-sqs';

function createTestStack() {
  const app = new App();
  const stack = new Stack(app, 'testStack', {
    synthesizer: new DefaultStackSynthesizer({ generateBootstrapVersionRule: false }),
    stackName: 'testStack',
  });

  const kmsKeyPolicy: PolicyDocument = new PolicyDocument();

  const kmsServicePolicy = new PolicyStatement({
    principals: [new ServicePrincipal('sns.amazonaws.com'), new ServicePrincipal(`logs.${stack.urlSuffix}`)],
    actions: ['kms:Encrypt*', 'kms:Decrypt*', 'kms:ReEncrypt*', 'kms:GenerateDataKey*', 'kms:Describe*'],
    resources: ['*'],
  });
  kmsKeyPolicy.addStatements(kmsServicePolicy);

  const kmsRootPolicy = new PolicyStatement({
    principals: [new AccountRootPrincipal()],
    actions: ['kms:*'],
    resources: ['*'],
  });
  kmsKeyPolicy.addStatements(kmsRootPolicy);

  const kmsKey = new Key(stack, 'SHARR-key', {
    enableKeyRotation: true,
    alias: 'TO0111-SHARR-Key',
    policy: kmsKeyPolicy,
  });

  const kmsKeyParm = new StringParameter(stack, 'SHARR_Key', {
    description: 'KMS Customer Managed Key that SHARR will use to encrypt data',
    parameterName: `/Solutions/SO0111/CMK_ARN`,
    stringValue: kmsKey.keyArn,
  });

  const schedulingQueue = new sqs.Queue(stack, 'SchedulingQueue', {
    encryption: sqs.QueueEncryption.KMS,
    enforceSSL: true,
    encryptionMasterKey: kmsKey,
  });

  new OrchestratorConstruct(stack, 'Orchestrator', {
    roleArn: 'arn:aws-test:iam::111122223333:role/TestRole',
    ssmDocStateLambda: 'arn:aws:lambda:us-east-1:111122223333:function/foobar',
    ssmExecDocLambda: 'arn:aws:lambda:us-east-1:111122223333:function/foobar',
    ssmExecMonitorLambda: 'arn:aws:lambda:us-east-1:111122223333:function/foobar',
    notifyLambda: 'arn:aws:lambda:us-east-1:111122223333:function/foobar',
    getApprovalRequirementLambda: 'arn:aws:lambda:us-east-1:111122223333:function/foobar',
    solutionId: 'bbb',
    solutionName: 'This is a test',
    solutionVersion: '1.1.1',
    orchLogGroup: 'ORCH_LOG_GROUP',
    kmsKeyParm: kmsKeyParm,
    sqsQueue: schedulingQueue,
    timeoutHours: 23,
  });

  return { app, stack };
}

test('test App Orchestrator Construct', () => {
  const { stack } = createTestStack();
  expect(Template.fromStack(stack)).toMatchSnapshot();
});

describe('Orchestrator Error Handling', () => {
  let stack: Stack;
  let template: Template;

  beforeEach(() => {
    const testStack = createTestStack();
    stack = testStack.stack;
    template = Template.fromStack(stack);
  });

  test('orchestratorFailed state should exist with proper structure', () => {
    const stateMachines = template.findResources('AWS::StepFunctions::StateMachine');
    const stateMachineKeys = Object.keys(stateMachines);
    expect(stateMachineKeys.length).toBeGreaterThan(0);

    const stateMachine = stateMachines[stateMachineKeys[0]];
    const definitionString = JSON.stringify(stateMachine.Properties.DefinitionString);

    expect(definitionString).toContain('Orchestrator Failed');
    expect(definitionString).toContain('Payload.$');
  });

  test('orchestratorFailed state should have Payload field for error context', () => {
    const stateMachines = template.findResources('AWS::StepFunctions::StateMachine');
    const stateMachineKeys = Object.keys(stateMachines);
    const stateMachine = stateMachines[stateMachineKeys[0]];
    const definitionString = JSON.stringify(stateMachine.Properties.DefinitionString);

    expect(definitionString).toContain('Payload.$');
  });

  test('orchestratorFailed state should preserve Notification structure', () => {
    const stateMachines = template.findResources('AWS::StepFunctions::StateMachine');
    const stateMachineKeys = Object.keys(stateMachines);
    const stateMachine = stateMachines[stateMachineKeys[0]];
    const definitionString = JSON.stringify(stateMachine.Properties.DefinitionString);

    expect(definitionString).toContain('Notification');
    expect(definitionString).toContain('Message.$');
    expect(definitionString).toContain('State.$');
    expect(definitionString).toContain('Details.$');
    expect(definitionString).toContain('StepFunctionsExecutionId.$');
    expect(definitionString).toContain('LAMBDA_ERROR');
  });

  test('globalErrorNotification should handle timeout and global errors', () => {
    const stateMachines = template.findResources('AWS::StepFunctions::StateMachine');
    const stateMachineKeys = Object.keys(stateMachines);
    const stateMachine = stateMachines[stateMachineKeys[0]];
    const definitionString = JSON.stringify(stateMachine.Properties.DefinitionString);

    expect(definitionString).toContain('Orchestrator Failed');

    expect(definitionString).toContain('LAMBDA_ERROR');
    expect(definitionString).toContain('Payload.$');
    expect(definitionString).toContain('Notification');
  });

  test('error handlers should have consistent structure', () => {
    const stateMachines = template.findResources('AWS::StepFunctions::StateMachine');
    const stateMachineKeys = Object.keys(stateMachines);
    const stateMachine = stateMachines[stateMachineKeys[0]];
    const definitionString = JSON.stringify(stateMachine.Properties.DefinitionString);

    const errorStates = [
      'Orchestrator Failed',
      'Automation Document is not Active',
      'No Runbook for Control',
      'Assume Role Failure',
      'Playbook is not enabled',
    ];

    errorStates.forEach((errorState) => {
      expect(definitionString).toContain(errorState);
    });
  });

  test('state machine should have proper catch blocks for Lambda invocations', () => {
    const stateMachines = template.findResources('AWS::StepFunctions::StateMachine');
    const stateMachineKeys = Object.keys(stateMachines);
    const stateMachine = stateMachines[stateMachineKeys[0]];
    const definitionString = JSON.stringify(stateMachine.Properties.DefinitionString);

    expect(definitionString).toContain('Get Automation Document State');
    expect(definitionString).toContain('Execute Remediation');
    expect(definitionString).toContain('execMonitor');
    expect(definitionString).toContain('Catch');
  });

  test('remediation flow should handle success and failure paths', () => {
    const stateMachines = template.findResources('AWS::StepFunctions::StateMachine');
    const stateMachineKeys = Object.keys(stateMachines);
    const stateMachine = stateMachines[stateMachineKeys[0]];
    const definitionString = JSON.stringify(stateMachine.Properties.DefinitionString);

    expect(definitionString).toContain('Remediation Succeeded');
    expect(definitionString).toContain('Remediation Failed');
    expect(definitionString).toContain('Remediation Queued');

    expect(definitionString).toContain('Remediation completed?');
  });

  test('Parallel wrapper should catch global timeout and errors', () => {
    const stateMachines = template.findResources('AWS::StepFunctions::StateMachine');
    const stateMachineKeys = Object.keys(stateMachines);
    const stateMachine = stateMachines[stateMachineKeys[0]];
    const definitionString = JSON.stringify(stateMachine.Properties.DefinitionString);

    expect(definitionString).toContain('Process Findings');
    expect(definitionString).toContain('Catch');
    expect(definitionString).toContain('Orchestrator Failed');
  });
});

describe('Orchestrator State Machine Configuration', () => {
  let stack: Stack;
  let template: Template;

  beforeEach(() => {
    const testStack = createTestStack();
    stack = testStack.stack;
    template = Template.fromStack(stack);
  });

  test('state machine should have proper timeout configuration', () => {
    const stateMachines = template.findResources('AWS::StepFunctions::StateMachine');
    const stateMachineKeys = Object.keys(stateMachines);
    expect(stateMachineKeys.length).toBeGreaterThan(0);

    const stateMachine = stateMachines[stateMachineKeys[0]];
    const definitionString = JSON.stringify(stateMachine.Properties.DefinitionString);

    expect(definitionString).toContain('TimeoutSeconds');
    expect(definitionString).toContain('82800');
  });

  test('state machine should have tracing enabled', () => {
    const stateMachines = template.findResources('AWS::StepFunctions::StateMachine');
    const stateMachineKeys = Object.keys(stateMachines);
    expect(stateMachineKeys.length).toBeGreaterThan(0);

    const stateMachine = stateMachines[stateMachineKeys[0]];

    expect(stateMachine.Properties.TracingConfiguration).toBeDefined();
    expect(stateMachine.Properties.TracingConfiguration.Enabled).toBe(true);
  });

  test('state machine should have logging configuration', () => {
    const stateMachines = template.findResources('AWS::StepFunctions::StateMachine');
    const stateMachineKeys = Object.keys(stateMachines);
    const stateMachine = stateMachines[stateMachineKeys[0]];

    expect(stateMachine.Properties.LoggingConfiguration).toBeDefined();
    expect(stateMachine.Properties.LoggingConfiguration.IncludeExecutionData).toBe(true);
    expect(stateMachine.Properties.LoggingConfiguration.Level).toBe('ALL');
  });

  test('state machine should depend on nested log stack', () => {
    const stateMachines = template.findResources('AWS::StepFunctions::StateMachine');
    const stateMachineKeys = Object.keys(stateMachines);
    expect(stateMachineKeys.length).toBeGreaterThan(0);

    const stateMachine = stateMachines[stateMachineKeys[0]];

    expect(stateMachine.DependsOn).toBeDefined();
    expect(Array.isArray(stateMachine.DependsOn)).toBe(true);

    const dependsOnArray = stateMachine.DependsOn as string[];
    const hasNestedStackDependency = dependsOnArray.some((dep: string) => dep.includes('NestedLogStack'));
    expect(hasNestedStackDependency).toBe(true);
  });
});

describe('Orchestrator Ticketing Integration', () => {
  let stack: Stack;
  let template: Template;

  beforeEach(() => {
    const testStack = createTestStack();
    stack = testStack.stack;
    template = Template.fromStack(stack);
  });

  test('ticketing Lambda should use proper ARN format', () => {
    const roles = template.findResources('AWS::IAM::Role', {
      Properties: {
        AssumeRolePolicyDocument: {
          Statement: Match.arrayWith([
            Match.objectLike({
              Principal: {
                Service: 'states.amazonaws.com',
              },
            }),
          ]),
        },
      },
    });

    const roleKeys = Object.keys(roles);
    expect(roleKeys.length).toBeGreaterThan(0);

    const role = roles[roleKeys[0]];
    const policyDocument = JSON.stringify(role.Properties.Policies);

    expect(policyDocument).toContain('lambda');
    expect(policyDocument).toContain('function');
  });

  test('ticketing condition should be properly configured', () => {
    const conditions = template.toJSON().Conditions;

    const ticketingConditionKey = Object.keys(conditions).find((key) =>
      key.startsWith('OrchestratorTicketingEnabledCondition'),
    );

    expect(ticketingConditionKey).toBeDefined();

    const condition = conditions[ticketingConditionKey!];
    expect(condition).toEqual({
      'Fn::Not': [
        {
          'Fn::Equals': [
            {
              Ref: 'TicketGenFunctionName',
            },
            '',
          ],
        },
      ],
    });
  });

  test('ticketing parameter should have proper validation', () => {
    const parameters = template.toJSON().Parameters;

    expect(parameters.TicketGenFunctionName).toBeDefined();
    expect(parameters.TicketGenFunctionName.Type).toBe('String');
    expect(parameters.TicketGenFunctionName.Default).toBe('');
    expect(parameters.TicketGenFunctionName.AllowedPattern).toMatch(/^\^/); // Starts with ^
  });

  test('Generate Ticket state should exist in state machine', () => {
    const stateMachines = template.findResources('AWS::StepFunctions::StateMachine');
    const stateMachineKeys = Object.keys(stateMachines);
    const stateMachine = stateMachines[stateMachineKeys[0]];
    const definitionString = JSON.stringify(stateMachine.Properties.DefinitionString);

    expect(definitionString).toContain('Generate Ticket');
    expect(definitionString).toContain('TicketURL');
    expect(definitionString).toContain('ResponseCode');
    expect(definitionString).toContain('ResponseReason');
  });

  test('custom action trigger should route to ticketing when enabled', () => {
    const stateMachines = template.findResources('AWS::StepFunctions::StateMachine');
    const stateMachineKeys = Object.keys(stateMachines);
    const stateMachine = stateMachines[stateMachineKeys[0]];
    const definitionString = JSON.stringify(stateMachine.Properties.DefinitionString);

    expect(definitionString).toContain('Which custom action triggered this workflow?');
    expect(definitionString).toContain('ASR:Remediate&Ticket');
  });
});
