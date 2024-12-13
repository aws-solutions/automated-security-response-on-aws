// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { Construct } from 'constructs';
import { ControlRunbookDocument, ControlRunbookProps, RemediationScope } from './control_runbook';
import { PlaybookProps } from '../lib/control_runbooks-construct';
import { DataTypeEnum, HardCodedBoolean, HardCodedString, Output, StringVariable } from '@cdklabs/cdk-ssm-documents';

export function createControlRunbook(scope: Construct, id: string, props: PlaybookProps): ControlRunbookDocument {
  return new EnableMultiAZOnRDSInstanceDocument(scope, id, { ...props, controlId: 'RDS.5' });
}

export class EnableMultiAZOnRDSInstanceDocument extends ControlRunbookDocument {
  constructor(scope: Construct, id: string, props: ControlRunbookProps) {
    super(scope, id, {
      ...props,
      securityControlId: 'RDS.5',
      remediationName: 'EnableMultiAZOnRDSInstance',
      scope: RemediationScope.REGIONAL,
      updateDescription: HardCodedString.of('Configured RDS cluster for multiple Availability Zones'),
    });
  }

  protected override getParseInputStepOutputs(): Output[] {
    const outputs = super.getParseInputStepOutputs();

    outputs.push({
      name: 'DbiResourceId',
      outputType: DataTypeEnum.STRING,
      selector: '$.Payload.resource.Details.AwsRdsDbInstance.DbiResourceId',
    });

    return outputs;
  }

  protected override getRemediationParams(): Record<string, any> {
    const params = super.getRemediationParams();

    params.DbiResourceId = StringVariable.of('ParseInput.DbiResourceId');
    params.ApplyImmediately = HardCodedBoolean.TRUE;

    return params;
  }
}
