// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { Construct } from 'constructs';
import { ControlRunbookDocument, ControlRunbookProps, RemediationScope } from './control_runbook';
import { PlaybookProps } from '../lib/control_runbooks-construct';
import { DataTypeEnum, HardCodedString, Output, StringVariable } from '@cdklabs/cdk-ssm-documents';

export function createControlRunbook(scope: Construct, id: string, props: PlaybookProps): ControlRunbookDocument {
  return new DisablePublicAccessToRDSInstanceDocument(scope, id, { ...props, controlId: 'RDS.2' });
}

export class DisablePublicAccessToRDSInstanceDocument extends ControlRunbookDocument {
  constructor(scope: Construct, id: string, props: ControlRunbookProps) {
    super(scope, id, {
      ...props,
      securityControlId: 'RDS.2',
      remediationName: 'DisablePublicAccessToRDSInstance',
      scope: RemediationScope.REGIONAL,
      updateDescription: HardCodedString.of('Disabled public access to RDS instance'),
    });
  }

  protected override getParseInputStepOutputs(): Output[] {
    const outputs = super.getParseInputStepOutputs();

    outputs.push({
      name: 'RDSInstanceARN',
      outputType: DataTypeEnum.STRING,
      selector: '$.Payload.resource.Id',
    });

    return outputs;
  }

  protected override getRemediationParams(): Record<string, any> {
    const params = super.getRemediationParams();

    params.RDSInstanceARN = StringVariable.of('ParseInput.RDSInstanceARN');

    return params;
  }
}
