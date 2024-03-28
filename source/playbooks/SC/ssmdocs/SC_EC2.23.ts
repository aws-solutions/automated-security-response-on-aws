// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { Construct } from 'constructs';
import { PlaybookProps } from '../lib/control_runbooks-construct';
import { ControlRunbookDocument, ControlRunbookProps, RemediationScope } from './control_runbook';
import { HardCodedString } from '@cdklabs/cdk-ssm-documents';

export function createControlRunbook(stage: Construct, id: string, props: PlaybookProps): ControlRunbookDocument {
  return new DisableTGWAutoAcceptSharedAttachmentsDocument(stage, id, { ...props, controlId: 'EC2.23' });
}

export class DisableTGWAutoAcceptSharedAttachmentsDocument extends ControlRunbookDocument {
  constructor(stage: Construct, id: string, props: ControlRunbookProps) {
    super(stage, id, {
      ...props,
      securityControlId: 'EC2.23',
      remediationName: 'DisableTGWAutoAcceptSharedAttachments',
      scope: RemediationScope.GLOBAL,
      resourceIdName: 'TransitGatewayId',
      resourceIdRegex: String.raw`^arn:(?:aws|aws-cn|aws-us-gov):ec2:[a-z]{2}-[a-z]+-\d{1}:\d{12}:transit-gateway\/(tgw-[a-z0-9\-]+)$`,
      updateDescription: HardCodedString.of(
        'Disabling Transit Gateway from automatically accepting VPC attachment requests.',
      ),
    });
  }
}
