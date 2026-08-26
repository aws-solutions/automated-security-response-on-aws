// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
// AIGenerated: true
import { Construct } from 'constructs';
import { ControlRunbookDocument, ControlRunbookProps, RemediationScope } from './control_runbook';
import { PlaybookProps } from '../lib/control_runbooks-construct';
import { DataTypeEnum, Output, StringFormat, StringVariable } from '@cdklabs/cdk-ssm-documents';

export function createControlRunbook(scope: Construct, id: string, props: PlaybookProps): ControlRunbookDocument {
  return new EnableS3BucketVersioning(scope, id, { ...props, controlId: 'S3.14' });
}

export class EnableS3BucketVersioning extends ControlRunbookDocument {
  constructor(scope: Construct, id: string, props: ControlRunbookProps) {
    const resourceIdName = 'BucketName';

    super(scope, id, {
      ...props,
      securityControlId: 'S3.14',
      remediationName: 'EnableS3BucketVersioning',
      scope: RemediationScope.GLOBAL,
      resourceIdName,
      resourceIdRegex: String.raw`^arn:(?:aws|aws-cn|aws-us-gov):s3:::([A-Za-z0-9.-]{3,63})$`,
      updateDescription: new StringFormat('Enabled versioning for S3 bucket %s.', [
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
    return params;
  }
}
