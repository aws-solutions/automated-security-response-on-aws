// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { Stack, App, CfnParameter, CfnOutput } from 'aws-cdk-lib';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as cdk from 'aws-cdk-lib';
import { BlueprintProps, BlueprintStack } from '../../cdk/blueprint-stack';
import { getLambdaCode } from '../../../lib/cdk-helper/lambda-code-manifest';

export class JiraBlueprintStack extends BlueprintStack {
  constructor(scope: App, id: string, props: BlueprintProps) {
    super(scope, id, props);
    const stack = Stack.of(this);

    const solutionsBucket = super.getSolutionsBucket();

    const jiraInstanceURIParam = super.getInstanceURIParam();

    const jiraProjectKeyParam = new CfnParameter(this, 'JiraProjectKey', {
      type: 'String',
      description: 'The key of your Jira project where tickets will be created.',
    });

    const secretArnParam = super.getSecretArnParam();

    Stack.of(this).templateOptions.metadata = {
      'AWS::CloudFormation::Interface': {
        ParameterGroups: [
          {
            Label: { default: 'Jira Project Information' },
            Parameters: [jiraInstanceURIParam.logicalId, jiraProjectKeyParam.logicalId],
          },
          {
            Label: { default: 'Jira API Credentials' },
            Parameters: [secretArnParam.logicalId],
          },
        ],
      },
    };

    const ticketGeneratorFunction = new lambda.Function(this, 'JiraTicketGenerator', {
      functionName: props.functionName,
      handler: 'jira_ticket_generator.lambda_handler',
      runtime: props.solutionInfo.runtimePython,
      description: 'Creates a ticket in the provided Jira project with remediation details.',
      code: getLambdaCode(
        solutionsBucket,
        props.solutionInfo.solutionTMN,
        props.solutionInfo.solutionVersion,
        'blueprints/jira_ticket_generator.zip',
      ), // Modify this configuration to build a local version of the ticket generator lambda
      environment: {
        POWERTOOLS_LOG_LEVEL: 'INFO',
        POWERTOOLS_SERVICE_NAME: 'jira_ticket_generator',
        POWERTOOLS_LOGGER_LOG_EVENT: 'false',
        POWERTOOLS_TRACER_CAPTURE_RESPONSE: 'true',
        POWERTOOLS_TRACER_CAPTURE_ERROR: 'true',
        SOLUTION_ID: props.solutionInfo.solutionId,
        INSTANCE_URI: jiraInstanceURIParam.valueAsString,
        PROJECT_NAME: jiraProjectKeyParam.valueAsString,
        SECRET_ARN: secretArnParam.valueAsString,
        AWS_ACCOUNT_ID: stack.account,
        STACK_ID: stack.stackId,
        DISABLE_ACCOUNT_ALIAS_LOOKUP: 'false',
      },
      memorySize: 256,
      timeout: cdk.Duration.seconds(15),
      reservedConcurrentExecutions: 2,
      role: super.getTicketGeneratorRole(),
      tracing: lambda.Tracing.ACTIVE,
      layers: [super.getBlueprintLayer()],
    });

    {
      const childToMod = ticketGeneratorFunction.node.findChild('Resource') as lambda.CfnFunction;

      childToMod.cfnOptions.metadata = {
        cfn_nag: {
          rules_to_suppress: [
            {
              id: 'W58',
              reason: 'False positive. Access is provided via a policy',
            },
            {
              id: 'W89',
              reason: 'There is no need to run this lambda in a VPC',
            },
            {
              id: 'W92',
              reason: 'There is no need for Reserved Concurrency',
            },
          ],
        },
      };
    }

    new CfnOutput(this, 'Ticket Generator Lambda Function', {
      description: 'ARN of the ticket generator lambda function.',
      value: ticketGeneratorFunction.functionArn,
    });
  }
}
