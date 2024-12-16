// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { Construct } from 'constructs';
import { ControlRunbookDocument, ControlRunbookProps, RemediationScope } from './control_runbook';
import { PlaybookProps } from '../lib/control_runbooks-construct';
import { DataTypeEnum, HardCodedString, Output, StringVariable } from '@cdklabs/cdk-ssm-documents';

export function createControlRunbook(scope: Construct, id: string, props: PlaybookProps): ControlRunbookDocument {
  return new EnableMinorVersionUpgradeOnRDSDBInstanceDocument(scope, id, { ...props, controlId: 'RDS.13' });
}

export class EnableMinorVersionUpgradeOnRDSDBInstanceDocument extends ControlRunbookDocument {
  constructor(scope: Construct, id: string, props: ControlRunbookProps) {
    super(scope, id, {
      ...props,
      securityControlId: 'RDS.13',
      remediationName: 'EnableMinorVersionUpgradeOnRDSDBInstance',
      scope: RemediationScope.REGIONAL,
      updateDescription: HardCodedString.of('Minor Version enabled on the RDS Instance or Multi-AZ RDS Cluster.'),
    });
  }

  protected override getParseInputStepOutputs(): Output[] {
    const outputs = super.getParseInputStepOutputs();

    outputs.push({
      name: 'DBInstanceIdentifier',
      outputType: DataTypeEnum.STRING,
      selector: '$.Payload.resource.Details.AwsRdsDbInstance.DBInstanceIdentifier',
    });

    return outputs;
  }

  protected override getRemediationParams(): Record<string, any> {
    const params = super.getRemediationParams();

    params.DBInstanceIdentifier = StringVariable.of('ParseInput.DBInstanceIdentifier');

    return params;
  }
}
