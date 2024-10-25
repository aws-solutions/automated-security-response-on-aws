// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { Construct } from 'constructs';
import { ControlRunbookDocument, ControlRunbookProps, RemediationScope } from './control_runbook';
import { PlaybookProps } from '../lib/control_runbooks-construct';
import { HardCodedString, StringVariable, BooleanVariable, Input } from '@cdklabs/cdk-ssm-documents';

export function createControlRunbook(scope: Construct, id: string, props: PlaybookProps): ControlRunbookDocument {
  return new EnableStepFunctionsStateMachineLoggingDocument(scope, id, { ...props, controlId: 'StepFunctions.1' });
}

export class EnableStepFunctionsStateMachineLoggingDocument extends ControlRunbookDocument {
  constructor(scope: Construct, id: string, props: ControlRunbookProps) {
    const docInputs = [
        Input.ofTypeBoolean('IncludeExecutionData', {
            defaultValue: false,
        }),
        Input.ofTypeBoolean('TracingConfiguration', {
            defaultValue: false,
        }),
    ]
    super(scope, id, {
      ...props,
      docInputs,
      securityControlId: 'StepFunctions.1',
      remediationName: 'EnableStepFunctionsStateMachineLogging',
      scope: RemediationScope.REGIONAL,
      resourceIdName: 'LogGroupArn',
      resourceIdRegex: String.raw`^arn:aws[a-z0-9-]*:logs:[a-z0-9-]+:\d{12}:log-group:[A-Za-z0-9\.\-\_\#\/]{1,1024}\:\*$`,
      updateDescription: HardCodedString.of('This document enables or updates logging on the AWS Step Functions state machine you specify. The minimum logging level must be set to ALL, ERROR, or FATAL.'),
    });
  }
  /** @override */
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  protected getRemediationParams(): { [_: string]: any } {
    const params = super.getRemediationParams();

    params.Level = StringVariable.of('ParseInput.Level');
    params.LogGroupArn = StringVariable.of('ParseInput.LogGroupArn');
    params.StateMachineArn = StringVariable.of('ParseInput.StateMachineArn');
    params.IncludeExecutionData = BooleanVariable.of('IncludeExecutionData'); // optional (default False)
    params.TracingConfiguration = BooleanVariable.of('TracingConfiguration'); // optional (default False)

    return params;
  }
}