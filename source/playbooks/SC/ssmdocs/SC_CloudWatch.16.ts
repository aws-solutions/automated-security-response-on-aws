// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { Construct } from 'constructs';
import { ControlRunbookDocument, ParameterRunbookProps, RemediationScope } from './control_runbook';
import { PlaybookProps } from '../lib/control_runbooks-construct';
import { AutomationStep, DataTypeEnum, HardCodedString, NumberVariable, Output } from '@cdklabs/cdk-ssm-documents';

export function createControlRunbook(scope: Construct, id: string, props: PlaybookProps): ControlRunbookDocument {
  return new SetLogGroupRetentionDaysDocument(scope, id, {
    ...props,
    controlId: 'CloudWatch.16',
  });
}

export class SetLogGroupRetentionDaysDocument extends ControlRunbookDocument {
  constructor(scope: Construct, id: string, props: ParameterRunbookProps) {
    const remediationName = 'SetLogGroupRetentionDays';

    super(scope, id, {
      ...props,
      securityControlId: 'CloudWatch.16',
      remediationName,
      scope: RemediationScope.REGIONAL,
      resourceIdName: 'LogGroupArn',
      updateDescription: HardCodedString.of(`The retention period has been updated using ASR`),
    });
  }

  protected override getExtraSteps(): AutomationStep[] {
    return [
      super.getInputParamsStep({
        MinRetentionTime: 365,
      }),
    ];
  }

  protected override getInputParamsStepOutput(): Output[] {
    const retentionDays: Output = {
      name: 'RetentionDays',
      outputType: DataTypeEnum.INTEGER,
      selector: '$.Payload.MinRetentionTime',
    };

    const outputs: Output[] = [retentionDays];

    return outputs;
  }

  protected override getRemediationParams(): Record<string, any> {
    const params: Record<string, any> = super.getRemediationParams();

    params.RetentionDays = NumberVariable.of('GetInputParams.RetentionDays');

    return params;
  }
}
