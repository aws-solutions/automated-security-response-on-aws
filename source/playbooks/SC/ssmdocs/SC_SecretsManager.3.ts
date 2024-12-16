// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { Construct } from 'constructs';
import { ControlRunbookDocument, ControlRunbookProps, RemediationScope } from './control_runbook';
import { PlaybookProps } from '../lib/control_runbooks-construct';
import { AutomationStep, DataTypeEnum, HardCodedString, Output, StringListVariable } from '@cdklabs/cdk-ssm-documents';

export function createControlRunbook(scope: Construct, id: string, props: PlaybookProps): ControlRunbookDocument {
  return new RemoveUnusedSecretDocument(scope, id, { ...props, controlId: 'SecretsManager.3' });
}

export class RemoveUnusedSecretDocument extends ControlRunbookDocument {
  constructor(scope: Construct, id: string, props: ControlRunbookProps) {
    super(scope, id, {
      ...props,
      securityControlId: 'SecretsManager.3',
      remediationName: 'RemoveUnusedSecret',
      scope: RemediationScope.REGIONAL,
      resourceIdName: 'SecretARN',
      updateDescription: HardCodedString.of('Removed the unused secret.'),
    });
  }

  protected override getExtraSteps(): AutomationStep[] {
    return [
      super.getInputParamsStep({
        unusedForDays: 90,
      }),
    ];
  }

  protected override getInputParamsStepOutput(): Output[] {
    const EventTypes: Output = {
      name: 'UnusedForDays',
      outputType: DataTypeEnum.STRING_LIST,
      selector: '$.Payload.unusedForDays',
    };

    const outputs: Output[] = [EventTypes];

    return outputs;
  }

  protected override getRemediationParams(): Record<string, any> {
    const params = super.getRemediationParams();

    params.UnusedForDays = StringListVariable.of('GetInputParams.UnusedForDays');

    return params;
  }
}
