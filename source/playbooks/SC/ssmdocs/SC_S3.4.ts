// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { Construct } from 'constructs';
import { ControlRunbookDocument, ControlRunbookProps, RemediationScope } from './control_runbook';
import { PlaybookProps } from '../lib/control_runbooks-construct';
import { DataTypeEnum, Input, Output, StringFormat, StringVariable } from '@cdklabs/cdk-ssm-documents';

export function createControlRunbook(scope: Construct, id: string, props: PlaybookProps): ControlRunbookDocument {
  return new EnableDefaultEncryptionS3Document(scope, id, { ...props, controlId: 'S3.4' });
}

export class EnableDefaultEncryptionS3Document extends ControlRunbookDocument {
  constructor(scope: Construct, id: string, props: ControlRunbookProps) {
    const docInputs: Input[] = [
      Input.ofTypeString('KmsKeyAlias', {
        description:
          '(Required) KMS Customer-Managed Key (CMK) alias or the default value which is created in the SSM parameter at solution deployment (default-s3-encryption) is used to identify that the s3 bucket encryption value should be set to AES-256.',
        defaultValue: '{{ssm:/Solutions/SO0111/afsbp/1.0.0/S3.4/KmsKeyAlias}}',
        allowedPattern: String.raw`^$|^[a-zA-Z0-9/_-]{1,256}$`,
      }),
    ];

    const resourceIdName = 'BucketName';

    super(scope, id, {
      ...props,
      docInputs,
      securityControlId: 'S3.4',
      remediationName: 'EnableDefaultEncryptionS3',
      scope: RemediationScope.GLOBAL,
      resourceIdName,
      resourceIdRegex: String.raw`^arn:(?:aws|aws-cn|aws-us-gov):s3:::([A-Za-z0-9.-]{3,63})$`,
      updateDescription: new StringFormat('Enabled default encryption for %s', [
        StringVariable.of(`ParseInput.${resourceIdName}`),
      ]),
    });
  }

  protected override getParseInputStepOutputs(): Output[] {
    const outputs = super.getParseInputStepOutputs();

    outputs.push({
      name: 'RemediationAccount',
      outputType: DataTypeEnum.STRING,
      selector: '$.Payload.account_id',
    });

    return outputs;
  }

  protected override getRemediationParams(): Record<string, any> {
    const params = super.getRemediationParams();

    params.AccountId = StringVariable.of('ParseInput.RemediationAccount');
    params.KmsKeyAlias = StringVariable.of('KmsKeyAlias');

    return params;
  }
}
