// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { Construct } from 'constructs';
import { ControlRunbookDocument, ControlRunbookProps, RemediationScope } from './control_runbook';
import { PlaybookProps } from '../lib/control_runbooks-construct';
import { DataTypeEnum, HardCodedString, Output, StringVariable } from '@cdklabs/cdk-ssm-documents';

export function createControlRunbook(scope: Construct, id: string, props: PlaybookProps): ControlRunbookDocument {
  return new EnableRDSClusterDeletionProtectionDocument(scope, id, { ...props, controlId: 'RDS.7' });
}

export class EnableRDSClusterDeletionProtectionDocument extends ControlRunbookDocument {
  constructor(scope: Construct, id: string, props: ControlRunbookProps) {
    super(scope, id, {
      ...props,
      securityControlId: 'RDS.7',
      remediationName: 'EnableRDSClusterDeletionProtection',
      scope: RemediationScope.REGIONAL,
      updateDescription: HardCodedString.of('Deletion protection enabled on RDS DB cluster'),
    });
  }

  protected override getParseInputStepOutputs(): Output[] {
    const outputs = super.getParseInputStepOutputs();

    outputs.push({
      name: 'RDSClusterARN',
      outputType: DataTypeEnum.STRING,
      selector: '$.Payload.resource.Id',
    });

    return outputs;
  }

  protected override getRemediationParams(): Record<string, any> {
    const params = super.getRemediationParams();

    params.RDSClusterARN = StringVariable.of('ParseInput.RDSClusterARN');

    return params;
  }
}
