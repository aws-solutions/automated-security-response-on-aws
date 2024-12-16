// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { Construct } from 'constructs';
import { ControlRunbookDocument, ControlRunbookProps, RemediationScope } from './control_runbook';
import { PlaybookProps } from '../lib/control_runbooks-construct';
import {
  BooleanVariable,
  DataTypeEnum,
  HardCodedNumber,
  HardCodedString,
  IGenericVariable,
  Output,
  StringVariable,
} from '@cdklabs/cdk-ssm-documents';

export function createControlRunbook(scope: Construct, id: string, props: PlaybookProps): ControlRunbookDocument {
  return new MakeEBSSnapshotsPrivateDocument(scope, id, { ...props, controlId: 'EC2.1' });
}

export class MakeEBSSnapshotsPrivateDocument extends ControlRunbookDocument {
  constructor(scope: Construct, id: string, props: ControlRunbookProps) {
    super(scope, id, {
      ...props,
      securityControlId: 'EC2.1',
      remediationName: 'MakeEBSSnapshotsPrivate',
      scope: RemediationScope.GLOBAL,
      updateDescription: HardCodedString.of('EBS Snapshot modified to private'),
    });
  }

  protected override getParseInputStepInputs(): { [_: string]: IGenericVariable } {
    const inputs: { [_: string]: IGenericVariable } = super.getParseInputStepInputs();

    inputs.resource_index = HardCodedNumber.of(2);

    return inputs;
  }

  protected override getParseInputStepOutputs(): Output[] {
    const outputs: Output[] = super.getParseInputStepOutputs();

    outputs.push({
      name: 'RemediationAccount',
      outputType: DataTypeEnum.STRING,
      selector: '$.Payload.account_id',
    });

    outputs.push({
      name: 'TestMode',
      outputType: DataTypeEnum.BOOLEAN,
      selector: '$.Payload.testmode',
    });

    return outputs;
  }

  protected override getRemediationParams(): Record<string, any> {
    const params: Record<string, any> = super.getRemediationParams();

    params.AccountId = StringVariable.of('ParseInput.RemediationAccount');
    params.TestMode = BooleanVariable.of('ParseInput.TestMode');

    return params;
  }
}
