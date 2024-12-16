// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { Construct } from 'constructs';
import { ControlRunbookDocument, ControlRunbookProps, RemediationScope } from './control_runbook';
import { PlaybookProps } from '../lib/control_runbooks-construct';
import { AutomationStep, DataTypeEnum, HardCodedString, Output, NumberVariable } from '@cdklabs/cdk-ssm-documents';

export function createControlRunbook(scope: Construct, id: string, props: PlaybookProps): ControlRunbookDocument {
  return new EnableAutoSecretRotationDocument(scope, id, { ...props, controlId: 'SecretsManager.1' });
}

export class EnableAutoSecretRotationDocument extends ControlRunbookDocument {
  constructor(scope: Construct, id: string, props: ControlRunbookProps) {
    super(scope, id, {
      ...props,
      securityControlId: 'SecretsManager.1',
      remediationName: 'EnableAutoSecretRotation',
      scope: RemediationScope.REGIONAL,
      resourceIdName: 'SecretARN',
      updateDescription: HardCodedString.of('Enabled automatic rotation on secret and set schedule to 90 days.'),
    });
  }

  protected override getExtraSteps(): AutomationStep[] {
    return [
      super.getInputParamsStep({
        maximumAllowedRotationFrequency: 90,
      }),
    ];
  }

  protected override getInputParamsStepOutput(): Output[] {
    const MaximumAllowedRotationFrequency: Output = {
      name: 'maximumAllowedRotationFrequency',
      outputType: DataTypeEnum.INTEGER,
      selector: '$.Payload.maximumAllowedRotationFrequency',
    };

    const outputs: Output[] = [MaximumAllowedRotationFrequency];

    return outputs;
  }

  protected override getRemediationParams(): Record<string, any> {
    const params: Record<string, any> = super.getRemediationParams();

    params.MaximumAllowedRotationFrequency = NumberVariable.of('GetInputParams.maximumAllowedRotationFrequency');

    return params;
  }
}
