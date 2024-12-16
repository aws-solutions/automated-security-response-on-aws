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
  Input,
  Output,
  StringFormat,
  StringVariable,
} from '@cdklabs/cdk-ssm-documents';

export function createControlRunbook(scope: Construct, id: string, props: PlaybookProps): ControlRunbookDocument {
  return new EncryptRDSSnapshotDocument(scope, id, { ...props, controlId: 'RDS.4' });
}

export class EncryptRDSSnapshotDocument extends ControlRunbookDocument {
  constructor(scope: Construct, id: string, props: ControlRunbookProps) {
    const docInputs: Input[] = [
      Input.ofTypeString('KMSKeyId', {
        description:
          '(Optional) ID, ARN or Alias for the AWS KMS Customer-Managed Key (CMK) to use to encrypt the snapshot.',
        defaultValue: 'alias/aws/rds',
        allowedPattern: String.raw`^(?:arn:(?:aws|aws-us-gov|aws-cn):kms:(?:[a-z]{2}(?:-gov)?-[a-z]+-\d):\d{12}:)?(?:(?:alias\/[A-Za-z0-9/_-]+)|(?:key\/(?:[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12})))$`,
      }),
    ];

    super(scope, id, {
      ...props,
      docInputs,
      securityControlId: 'RDS.4',
      remediationName: 'EncryptRDSSnapshot',
      scope: RemediationScope.REGIONAL,
      resourceIdRegex: String.raw`^arn:(?:aws|aws-cn|aws-us-gov):rds:(?:[a-z]{2}(?:-gov)?-[a-z]+-\d):\d{12}:((?:cluster-)?snapshot|dbclustersnapshot):((?:rds:|awsbackup:)?((?!.*--.*)(?!.*-$)[a-zA-Z][a-zA-Z0-9-]{0,254}))$`,
      updateDescription: HardCodedString.of('Encrypted RDS snapshot'),
    });
  }

  protected override getParseInputStepInputs(): { [_: string]: IGenericVariable } {
    const inputs = super.getParseInputStepInputs();

    inputs.resource_index = HardCodedNumber.of(2);

    return inputs;
  }

  protected override getParseInputStepOutputs(): Output[] {
    const outputs = super.getParseInputStepOutputs();

    outputs.push(
      {
        name: 'SourceDBSnapshotIdentifier',
        outputType: DataTypeEnum.STRING,
        selector: '$.Payload.matches[1]',
      },
      {
        name: 'SourceDBSnapshotIdentifierNoPrefix',
        outputType: DataTypeEnum.STRING,
        selector: '$.Payload.matches[2]',
      },
      {
        name: 'DBSnapshotType',
        outputType: DataTypeEnum.STRING,
        selector: '$.Payload.matches[0]',
      },
    );

    return outputs;
  }

  protected override getRemediationParams(): Record<string, any> {
    const params = super.getRemediationParams();

    params.SourceDBSnapshotIdentifier = StringVariable.of('ParseInput.SourceDBSnapshotIdentifier');
    params.TargetDBSnapshotIdentifier = new StringFormat('%s-encrypted', [
      StringVariable.of('ParseInput.SourceDBSnapshotIdentifierNoPrefix'),
    ]);
    params.DBSnapshotType = StringVariable.of('ParseInput.DBSnapshotType');
    params.KmsKeyId = StringVariable.of('KMSKeyId');

    return params;
  }
}
