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
  return new TagDynamoDBTableResource(scope, id, { ...props, controlId: 'DynamoDB.5' });
}

export class TagDynamoDBTableResource extends ControlRunbookDocument {
  constructor(scope: Construct, id: string, props: ControlRunbookProps) {
    super(scope, id, {
      ...props,
      securityControlId: 'DynamoDB.5',
      remediationName: 'TagDynamoDBTableResource',
      scope: RemediationScope.REGIONAL,
      resourceIdName: 'ResourceArn',
      updateDescription: new StringFormat('DynamoDB Table %s has been tagged.', [
        StringVariable.of(`ParseInput.ResourceArn`),
      ]),
    });
  }

  protected override getExtraSteps(): AutomationStep[] {
    return [
      super.getInputParamsStep({
        requiredTagKeys: 'SO0111-ASR-DynamoDBTable',
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
