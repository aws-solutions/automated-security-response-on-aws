// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { Construct } from 'constructs';
import { ControlRunbookDocument, ControlRunbookProps, RemediationScope } from './control_runbook';
import { PlaybookProps } from '../lib/control_runbooks-construct';
import { DataTypeEnum, HardCodedString, Output, StringVariable } from '@cdklabs/cdk-ssm-documents';

export function createControlRunbook(scope: Construct, id: string, props: PlaybookProps): ControlRunbookDocument {
  return new RDS_13_ControlRunbookDocument(scope, id, { ...props, controlId: 'RDS.13' });
}

class RDS_13_ControlRunbookDocument extends ControlRunbookDocument {
  constructor(scope: Construct, id: string, props: ControlRunbookProps) {
    super(scope, id, {
      ...props,
      securityControlId: 'RDS.13',
      remediationName: 'EnableMinorVersionUpgradeOnRDSDBInstance',
      scope: RemediationScope.REGIONAL,
      updateDescription: HardCodedString.of('Minor Version enabled on the RDS Instance.'),
    });
  }

  /** @override */
  protected getParseInputStepOutputs(): Output[] {
    const outputs = super.getParseInputStepOutputs();

    outputs.push({
      name: 'DbiResourceId',
      outputType: DataTypeEnum.STRING,
      selector: '$.Payload.resource.Details.AwsRdsDbInstance.DbiResourceId',
    });

    return outputs;
  }

  /** @override */
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  protected getRemediationParams(): { [_: string]: any } {
    const params = super.getRemediationParams();

    params.DbiResourceId = StringVariable.of('ParseInput.DbiResourceId');

    return params;
  }
}
