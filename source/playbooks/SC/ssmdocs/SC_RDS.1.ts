// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { Construct } from 'constructs';
import { ControlRunbookDocument, ControlRunbookProps, RemediationScope } from './control_runbook';
import { PlaybookProps } from '../lib/control_runbooks-construct';
import {
  DataTypeEnum,
  HardCodedNumber,
  HardCodedString,
  IGenericVariable,
  Output,
  StringVariable,
} from '@cdklabs/cdk-ssm-documents';

export function createControlRunbook(scope: Construct, id: string, props: PlaybookProps): ControlRunbookDocument {
  return new MakeRDSSnapshotPrivateDocument(scope, id, { ...props, controlId: 'RDS.1' });
}

export class MakeRDSSnapshotPrivateDocument extends ControlRunbookDocument {
  constructor(scope: Construct, id: string, props: ControlRunbookProps) {
    super(scope, id, {
      ...props,
      securityControlId: 'RDS.1',
      remediationName: 'MakeRDSSnapshotPrivate',
      scope: RemediationScope.REGIONAL,
      resourceIdName: 'DBSnapshotId',
      resourceIdRegex: String.raw`^arn:(?:aws|aws-cn|aws-us-gov):rds:(?:[a-z]{2}(?:-gov)?-[a-z]+-\d):\d{12}:(cluster-snapshot|snapshot):([a-zA-Z][0-9a-zA-Z]*(?:-[0-9a-zA-Z]+)*)$`,
      updateDescription: HardCodedString.of('RDS DB Snapshot modified to private'),
    });
  }

  protected override getParseInputStepInputs(): { [_: string]: IGenericVariable } {
    const inputs = super.getParseInputStepInputs();

    inputs.resource_index = HardCodedNumber.of(2);

    return inputs;
  }

  protected override getParseInputStepOutputs(): Output[] {
    const outputs = super.getParseInputStepOutputs();

    outputs.push({
      name: 'DBSnapshotType',
      outputType: DataTypeEnum.STRING,
      selector: '$.Payload.matches[0]',
    });

    return outputs;
  }

  protected override getRemediationParams(): Record<string, any> {
    const params = super.getRemediationParams();

    params.DBSnapshotType = StringVariable.of('ParseInput.DBSnapshotType');

    return params;
  }
}
