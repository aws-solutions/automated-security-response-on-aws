// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { Construct } from 'constructs';
import { ControlRunbookDocument, ControlRunbookProps, RemediationScope } from './control_runbook';
import { PlaybookProps } from '../lib/control_runbooks-construct';
import { HardCodedString, StringFormat, StringVariable } from '@cdklabs/cdk-ssm-documents';

export function createControlRunbook(scope: Construct, id: string, props: PlaybookProps): ControlRunbookDocument {
  return new EnableDeliveryLoggingForSNSTopicDocument(scope, id, { ...props, controlId: 'SNS.2' });
}

export class EnableDeliveryLoggingForSNSTopicDocument extends ControlRunbookDocument {
  constructor(scope: Construct, id: string, props: ControlRunbookProps) {
    super(scope, id, {
      ...props,
      securityControlId: 'SNS.2',
      remediationName: 'EnableDeliveryStatusLoggingForSNSTopic',
      scope: RemediationScope.REGIONAL,
      resourceIdName: 'SNSTopicArn',
      updateDescription: HardCodedString.of('Delivery Status Logging enabled on SNS Topic'),
    });
  }

  protected override getRemediationParams(): Record<string, any> {
    const params = super.getRemediationParams();
    params.SNSTopicArn = StringVariable.of('ParseInput.SNSTopicArn');

    params.LoggingRole = new StringFormat(
      `arn:%s:iam::%s:role/${this.solutionId}-SNS2DeliveryStatusLogging-remediationRole-${this.namespace}`,
      [StringVariable.of('global:AWS_PARTITION'), StringVariable.of('global:ACCOUNT_ID')],
    );

    return params;
  }
}
