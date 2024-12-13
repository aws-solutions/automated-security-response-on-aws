// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { CfnParameter, Stack } from 'aws-cdk-lib';
import { Construct } from 'constructs';

export default class TicketingFunctionNameParam extends Construct {
  public readonly paramId: string;
  public readonly value: string;
  public readonly functionARN: string;

  constructor(scope: Construct, id: string) {
    super(scope, id);
    const stack = Stack.of(this);

    const functionNameRegex = String.raw`^([a-zA-Z0-9\-_]{1,64})?$`;
    const param = new CfnParameter(this, 'Ticket Generator Function Name', {
      description:
        'Enter the name of the Lambda function you would like to use to generate tickets when remediations are successfully completed. This function must be in the same region where you are deploying this stack. ' +
        'Leave this field blank if you do not want to enable ticketing. ' +
        'The function you provide should be implemented to create a ticket in your service of choice based on input from the Orchestrator step function. ' +
        `To reference or use the provided Ticket Generator function for Jira or ServiceNow, see the Blueprint stacks in the solution's implementation guide.`,
      type: 'String',
      allowedPattern: functionNameRegex,
    });
    param.overrideLogicalId(`TicketGenFunctionName`);
    this.paramId = param.logicalId;
    this.value = param.valueAsString;
    this.functionARN = `arn:${stack.partition}:lambda:${stack.region}:${stack.account}:function:${param.valueAsString}`;
  }
}
