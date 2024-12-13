// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { Construct } from 'constructs';
import { ControlRunbookDocument, ControlRunbookProps, RemediationScope } from './control_runbook';
import { PlaybookProps } from '../lib/control_runbooks-construct';
import { AutomationStep, DataTypeEnum, HardCodedString, Output, StringListVariable } from '@cdklabs/cdk-ssm-documents';

export function createControlRunbook(scope: Construct, id: string, props: PlaybookProps): ControlRunbookDocument {
  return new TagGuardDutyResource(scope, id, { ...props, controlId: 'GuardDuty.2', otherControlIds: ['GuardDuty.4'] });
}

export class TagGuardDutyResource extends ControlRunbookDocument {
  constructor(scope: Construct, id: string, props: ControlRunbookProps) {
    super(scope, id, {
      ...props,
      securityControlId: 'GuardDuty.2',
      remediationName: 'TagGuardDutyResource',
      scope: RemediationScope.REGIONAL,
      resourceIdName: 'ResourceArn',
      updateDescription: HardCodedString.of('Guard Duty filter tagged'),
    });
  }

  protected override getExtraSteps(): AutomationStep[] {
    return [
      super.getInputParamsStep({
        requiredTagKeys: 'SO0111-GuardDutyFilter',
      }),
    ];
  }

  protected override getInputParamsStepOutput(): Output[] {
    const requiredTagKeys: Output = {
      name: 'requiredTagKeys',
      outputType: DataTypeEnum.STRING_LIST,
      selector: '$.Payload.requiredTagKeys',
    };

    return [requiredTagKeys];
  }

  protected override getRemediationParams(): Record<string, any> {
    const params: Record<string, any> = super.getRemediationParams();

    params.RequiredTagKeys = StringListVariable.of('GetInputParams.requiredTagKeys');

    return params;
  }
}
