// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { Construct } from 'constructs';
import { ControlRunbookDocument, ControlRunbookProps, RemediationScope } from './control_runbook';
import { PlaybookProps } from '../lib/control_runbooks-construct';
import { HardCodedString, Input, StringVariable } from '@cdklabs/cdk-ssm-documents';

export function createControlRunbook(scope: Construct, id: string, props: PlaybookProps): ControlRunbookDocument {
  return new EnableEncryptionForSNSTopicDocument(scope, id, { ...props, controlId: 'SNS.1' });
}

export class EnableEncryptionForSNSTopicDocument extends ControlRunbookDocument {
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
      securityControlId: 'SNS.1',
      remediationName: 'EnableEncryptionForSNSTopic',
      scope: RemediationScope.REGIONAL,
      resourceIdName: 'TopicArn',
      updateDescription: HardCodedString.of('Encryption enabled on SNS Topic'),
    });
  }

  protected override getRemediationParams(): Record<string, any> {
    const params = super.getRemediationParams();
    params.KmsKeyArn = StringVariable.of('KmsKeyArn');
    params.TopicArn = StringVariable.of('ParseInput.TopicArn');
    return params;
  }
}
