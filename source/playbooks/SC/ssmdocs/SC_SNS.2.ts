// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { Construct } from 'constructs';
import { ControlRunbookDocument, ControlRunbookProps, RemediationScope } from './control_runbook';
import { PlaybookProps } from '../lib/control_runbooks-construct';
import { HardCodedString, Input, StringVariable } from '@cdklabs/cdk-ssm-documents';

export function createControlRunbook(scope: Construct, id: string, props: PlaybookProps): ControlRunbookDocument {
  return new EnableDeliveryLoggingForSNSTopicDocument(scope, id, { ...props, controlId: 'SNS.2' });
}

export class EnableDeliveryLoggingForSNSTopicDocument extends ControlRunbookDocument {
  constructor(scope: Construct, id: string, props: ControlRunbookProps) {
    const docInputs = [
      Input.ofTypeString('LoggingRole', {
        allowedPattern: String.raw`^arn:(?:aws|aws-us-gov|aws-cn):iam::\d{12}:role/[\w+=,.@-]+$`,
        defaultValue: '{{ssm:/Solutions/SO0111/DeliveryStatusLoggingRole}}',
      }),
    ];

    super(scope, id, {
      ...props,
      docInputs,
      securityControlId: 'SNS.2',
      remediationName: 'EnableDeliveryLoggingForSNSTopic',
      scope: RemediationScope.REGIONAL,
      resourceIdName: 'SNSTopicArn',
      updateDescription: HardCodedString.of('Delivery Status Logging enabled on SNS Topic'),
    });
  }

  /** @override */
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  protected getRemediationParams(): { [_: string]: any } {
    const params = super.getRemediationParams();
    params.SNSTopicArn = StringVariable.of('ParseInput.SNSTopicArn');
    params.LoggingRole = StringVariable.of('LoggingRole');
    return params;
  }
}
