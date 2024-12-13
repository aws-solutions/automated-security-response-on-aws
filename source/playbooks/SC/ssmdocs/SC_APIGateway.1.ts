// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { Construct } from 'constructs';
import { ControlRunbookDocument, ControlRunbookProps, RemediationScope } from './control_runbook';
import { PlaybookProps } from '../lib/control_runbooks-construct';
import {
  AutomationStep,
  DataTypeEnum,
  Output,
  StringFormat,
  StringListVariable,
  StringVariable,
} from '@cdklabs/cdk-ssm-documents';

export function createControlRunbook(scope: Construct, id: string, props: PlaybookProps): ControlRunbookDocument {
  return new EnableAPIGatewayExecutionLogsDocument(scope, id, { ...props, controlId: 'APIGateway.1' });
}

export class EnableAPIGatewayExecutionLogsDocument extends ControlRunbookDocument {
  constructor(scope: Construct, id: string, props: ControlRunbookProps) {
    super(scope, id, {
      ...props,
      securityControlId: 'APIGateway.1',
      remediationName: 'EnableAPIGatewayExecutionLogs',
      scope: RemediationScope.REGIONAL,
      resourceIdName: 'APIGatewayStageArnSuffix',
      resourceIdRegex: String.raw`^arn:(?:aws|aws-cn|aws-us-gov):apigateway:(?:[a-z]{2}(?:-gov)?-[a-z]+-\d)::(\/restapis\/(.+)\/stages\/(.+)|\/apis\/(.+)\/stages\/(.+))$`,
      updateDescription: new StringFormat('Log level set to %s in Stage.', [
        StringVariable.of(`GetInputParams.loggingLevel`),
      ]),
    });
  }

  protected override getExtraSteps(): AutomationStep[] {
    return [
      super.getInputParamsStep({
        loggingLevel: 'INFO',
      }),
    ];
  }

  protected override getInputParamsStepOutput(): Output[] {
    const loggingLevel: Output = {
      name: 'loggingLevel',
      outputType: DataTypeEnum.STRING,
      selector: '$.Payload.loggingLevel',
    };

    return [loggingLevel];
  }

  protected override getRemediationParams(): Record<string, any> {
    const params: Record<string, any> = super.getRemediationParams();

    params.LoggingLevel = StringListVariable.of('GetInputParams.loggingLevel');

    return params;
  }
}
