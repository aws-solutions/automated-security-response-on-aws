// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { Construct } from 'constructs';
import { ControlRunbookDocument, ControlRunbookProps, RemediationScope } from './control_runbook';
import { PlaybookProps } from '../lib/control_runbooks-construct';
import { AutomationStep, DataTypeEnum, HardCodedString, Output, StringListVariable } from '@cdklabs/cdk-ssm-documents';

export function createControlRunbook(scope: Construct, id: string, props: PlaybookProps): ControlRunbookDocument {
  return new UpdateSecretRotationPeriodDocument(scope, id, { ...props, controlId: 'SecretsManager.4' });
}

export class UpdateSecretRotationPeriodDocument extends ControlRunbookDocument {
  constructor(scope: Construct, id: string, props: ControlRunbookProps) {
    super(scope, id, {
      ...props,
      securityControlId: 'SecretsManager.4',
      remediationName: 'UpdateSecretRotationPeriod',
      scope: RemediationScope.REGIONAL,
      resourceIdName: 'SecretARN',
      updateDescription: HardCodedString.of('Rotated secret and set rotation schedule to 90 days.'),
    });
  }

  /** @override */
  protected getExtraSteps(): AutomationStep[] {
    return [
      super.getInputParamsStep({
        maxDaysSinceRotation: 90,
      }),
    ];
  }

  /** @override */
  protected getInputParamsStepOutput(): Output[] {
    const EventTypes: Output = {
      name: 'MaxDaysSinceRotation',
      outputType: DataTypeEnum.STRING_LIST,
      selector: '$.Payload.maxDaysSinceRotation',
    };

    const outputs: Output[] = [EventTypes];

    return outputs;
  }

  /** @override */
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  protected getRemediationParams(): { [_: string]: any } {
    const params = super.getRemediationParams();

    params.MaxDaysSinceRotation = StringListVariable.of('GetInputParams.MaxDaysSinceRotation');

    return params;
  }
}
