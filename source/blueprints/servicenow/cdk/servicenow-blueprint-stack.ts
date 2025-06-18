// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { Stack, App, CfnParameter, CfnOutput } from 'aws-cdk-lib';
import { Function, Tracing } from 'aws-cdk-lib/aws-lambda';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as cdk from 'aws-cdk-lib';
import { BlueprintProps, BlueprintStack } from '../../cdk/blueprint-stack';

export class ServiceNowBlueprintStack extends BlueprintStack {
  constructor(scope: App, id: string, props: BlueprintProps) {
    super(scope, id, props);

    const solutionsBucket = super.getSolutionsBucket();

    const serviceNowTableName = new CfnParameter(this, 'ServiceNowTableName', {
      type: 'String',
      description: 'Enter the name of your ServiceNow Table where tickets should be created.',
      default: 'incident',
    });

    const secretArnParam = super.getSecretArnParam();
    const serviceNowInstanceURIParam = super.getInstanceURIParam();

    Stack.of(this).templateOptions.metadata = {
      'AWS::CloudFormation::Interface': {
        ParameterGroups: [
          {
            Label: { default: 'ServiceNow Project Information' },
            Parameters: [serviceNowInstanceURIParam.logicalId, serviceNowTableName.logicalId],
          },
          {
            Label: { default: 'ServiceNow API Credentials' },
            Parameters: [secretArnParam.logicalId],
          },
        ],
      },
    };

    const ticketGeneratorFunction = new Function(this, 'ServiceNowTicketGenerator', {
      functionName: props.functionName,
      handler: 'servicenow_ticket_generator.lambda_handler',
      runtime: props.solutionInfo.runtimePython,
      description: 'Creates a ticket in the provided ServiceNow table with remediation details.',
      code: lambda.Code.fromBucket(
        solutionsBucket,
        props.solutionInfo.solutionTMN +
          '/' +
          props.solutionInfo.solutionVersion +
          '/lambda/blueprints/servicenow_ticket_generator.py.zip',
      ), // Modify this configuration to build a local version of the ticket generator lambda
      environment: {
        POWERTOOLS_LOG_LEVEL: 'INFO',
        POWERTOOLS_SERVICE_NAME: props.solutionInfo.solutionTMN,
        SOLUTION_ID: props.solutionInfo.solutionId,
        INSTANCE_URI: serviceNowInstanceURIParam.valueAsString,
        TABLE_NAME: serviceNowTableName.valueAsString,
        SECRET_ARN: secretArnParam.valueAsString,
      },
      memorySize: 256,
      timeout: cdk.Duration.seconds(15),
      reservedConcurrentExecutions: 2,
      role: super.getTicketGeneratorRole(),
      tracing: Tracing.ACTIVE,
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
