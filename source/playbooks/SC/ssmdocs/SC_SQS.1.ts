// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { Construct } from 'constructs';
import { ControlRunbookDocument, ControlRunbookProps, RemediationScope } from './control_runbook';
import { PlaybookProps } from '../lib/control_runbooks-construct';
import { HardCodedString, Input, StringVariable } from '@cdklabs/cdk-ssm-documents';

export function createControlRunbook(scope: Construct, id: string, props: PlaybookProps): ControlRunbookDocument {
  return new EnableEncryptionForSQSQueueDocument(scope, id, { ...props, controlId: 'SQS.1' });
}

export class EnableEncryptionForSQSQueueDocument extends ControlRunbookDocument {
  constructor(scope: Construct, id: string, props: ControlRunbookProps) {
    const docInputs = [
      Input.ofTypeString('KmsKeyArn', {
        allowedPattern: String.raw`^arn:(?:aws|aws-us-gov|aws-cn):kms:(?:[a-z]{2}(?:-gov)?-[a-z]+-\d):\d{12}:(?:(?:alias\/[A-Za-z0-9/-_])|(?:key\/(?:[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12})))$`,
        defaultValue: '{{ssm:/Solutions/SO0111/CMK_REMEDIATION_ARN}}',
      }),
    ];

    super(scope, id, {
      ...props,
      docInputs,
      securityControlId: 'SQS.1',
      remediationName: 'EnableEncryptionForSQSQueue',
      scope: RemediationScope.REGIONAL,
      resourceIdName: 'SQSQueueName',
      resourceIdRegex: String.raw`^arn:(?:aws|aws-us-gov|aws-cn):sqs:(?:[a-z]{2}(?:-gov)?-[a-z]+-\d):\d{12}:([a-zA-Z0-9_-]{1,80}(?:\.fifo)?)$`,
      updateDescription: HardCodedString.of('Encryption enabled on SQS Topic'),
    });
  }

  protected override getRemediationParams(): Record<string, any> {
    const params = super.getRemediationParams();

    params.KmsKeyArn = StringVariable.of('KmsKeyArn');

    return params;
  }
}
