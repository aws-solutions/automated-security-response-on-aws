// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { App, DefaultStackSynthesizer, Stack } from 'aws-cdk-lib';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as sqs from 'aws-cdk-lib/aws-sqs';
import * as lambdaEventSources from 'aws-cdk-lib/aws-lambda-event-sources';
import { Template } from 'aws-cdk-lib/assertions';
import { removeEventSourceMappingTags } from '../lib/tags/applyTag';

describe('applyTag', () => {
  let app: App;
  let stack: Stack;

  beforeEach(() => {
    app = new App();
    stack = new Stack(app, 'TestStack', {
      synthesizer: new DefaultStackSynthesizer({ generateBootstrapVersionRule: false }),
      stackName: 'TestStack',
    });
  });

  test('removeEventSourceMappingTags removes tags from EventSourceMapping', () => {
    const testLambda = new lambda.Function(stack, 'TestLambda', {
      runtime: lambda.Runtime.PYTHON_3_9,
      handler: 'index.handler',
      code: lambda.Code.fromInline('print("test")'),
    });

    const testQueue = new sqs.Queue(stack, 'TestQueue');

    const eventSource = new lambdaEventSources.SqsEventSource(testQueue, {
      batchSize: 1,
    });

    testLambda.addEventSource(eventSource);

    removeEventSourceMappingTags(testLambda);

    const template = Template.fromStack(stack);

    template.hasResourceProperties('AWS::Lambda::EventSourceMapping', {
      BatchSize: 1,
    });

    const rawTemplate = template.toJSON();
    const eventSourceMappings = Object.entries(rawTemplate.Resources).filter(
      ([_, resource]: [string, any]) => resource.Type === 'AWS::Lambda::EventSourceMapping',
    );

    expect(eventSourceMappings).toHaveLength(1);

    const [_, eventSourceMapping] = eventSourceMappings[0] as [string, any];
    expect(eventSourceMapping.Properties).not.toHaveProperty('Tags');

    expect(eventSourceMapping.Properties).toHaveProperty('BatchSize', 1);
    expect(eventSourceMapping.Properties).toHaveProperty('EventSourceArn');
    expect(eventSourceMapping.Properties).toHaveProperty('FunctionName');
  });

  test('removeEventSourceMappingTags handles Lambda with no EventSourceMappings', () => {
    const testLambda = new lambda.Function(stack, 'TestLambda', {
      runtime: lambda.Runtime.PYTHON_3_9,
      handler: 'index.handler',
      code: lambda.Code.fromInline('print("test")'),
    });

    expect(() => {
      removeEventSourceMappingTags(testLambda);
    }).not.toThrow();

    const template = Template.fromStack(stack);

    const rawTemplate = template.toJSON();
    const eventSourceMappings = Object.entries(rawTemplate.Resources).filter(
      ([_, resource]: [string, any]) => resource.Type === 'AWS::Lambda::EventSourceMapping',
    );

    expect(eventSourceMappings).toHaveLength(0);
  });

  test('removeEventSourceMappingTags handles Lambda with multiple EventSourceMappings', () => {
    const testLambda = new lambda.Function(stack, 'TestLambda', {
      runtime: lambda.Runtime.PYTHON_3_9,
      handler: 'index.handler',
      code: lambda.Code.fromInline('print("test")'),
    });

    const testQueue1 = new sqs.Queue(stack, 'TestQueue1');
    const testQueue2 = new sqs.Queue(stack, 'TestQueue2');

    const eventSource1 = new lambdaEventSources.SqsEventSource(testQueue1, {
      batchSize: 1,
    });
    const eventSource2 = new lambdaEventSources.SqsEventSource(testQueue2, {
      batchSize: 2,
    });

    testLambda.addEventSource(eventSource1);
    testLambda.addEventSource(eventSource2);

    removeEventSourceMappingTags(testLambda);

    const template = Template.fromStack(stack);

    const rawTemplate = template.toJSON();
    const eventSourceMappings = Object.entries(rawTemplate.Resources).filter(
      ([_, resource]: [string, any]) => resource.Type === 'AWS::Lambda::EventSourceMapping',
    );

    expect(eventSourceMappings).toHaveLength(2);

    eventSourceMappings.forEach(([_, eventSourceMapping]: [string, any]) => {
      expect(eventSourceMapping.Properties).not.toHaveProperty('Tags');
    });
  });
});
