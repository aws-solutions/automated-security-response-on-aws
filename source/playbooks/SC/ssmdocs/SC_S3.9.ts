// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { Construct } from 'constructs';
import { ControlRunbookDocument, ControlRunbookProps, RemediationScope } from './control_runbook';
import { PlaybookProps } from '../lib/control_runbooks-construct';
import { DataTypeEnum, Input, Output, StringFormat, StringVariable } from '@cdklabs/cdk-ssm-documents';

export function createControlRunbook(scope: Construct, id: string, props: PlaybookProps): ControlRunbookDocument {
  return new EnableServerAccessLoggingS3Document(scope, id, { ...props, controlId: 'S3.9' });
}

export class EnableServerAccessLoggingS3Document extends ControlRunbookDocument {
  constructor(scope: Construct, id: string, props: ControlRunbookProps) {
    const docInputs: Input[] = [
      Input.ofTypeString('TargetBucketName', {
        description:
          'The target bucket must be in the same AWS Region as the source bucket and must not have a default retention period configuration.',
        defaultValue: 'so0111-server-access-logs',
        allowedPattern: String.raw`(?=^.{3,63}$)(?!^(\d+\.)+\d+$)(^(([a-z0-9]|[a-z0-9][a-z0-9\-]*[a-z0-9])\.)*([a-z0-9]|[a-z0-9][a-z0-9\-]*[a-z0-9])$)`,
      }),
    ];

    const resourceIdName = 'BucketName';

    super(scope, id, {
      ...props,
      docInputs,
      securityControlId: 'S3.9',
      remediationName: 'EnableServerAccessLoggingS3',
      scope: RemediationScope.GLOBAL,
      resourceIdName,
      resourceIdRegex: String.raw`^arn:(?:aws|aws-cn|aws-us-gov):s3:::([A-Za-z0-9.-]{3,63})$`,
      updateDescription: new StringFormat('Enabled server access logging for %s', [
        StringVariable.of(`ParseInput.${resourceIdName}`),
      ]),
    });
  }

  /** @override */
  protected getParseInputStepOutputs(): Output[] {
    const outputs = super.getParseInputStepOutputs();

    outputs.push({
      name: 'RemediationAccount',
      outputType: DataTypeEnum.STRING,
      selector: '$.Payload.account_id',
    });

    return outputs;
  }

  /** @override */
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  protected getRemediationParams(): { [_: string]: any } {
    const params = super.getRemediationParams();

    params.TargetBucketName = StringVariable.of('TargetBucketName');

    return params;
  }
}
