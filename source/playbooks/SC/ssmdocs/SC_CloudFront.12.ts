// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { Construct } from 'constructs';
import { ControlRunbookDocument, ControlRunbookProps, RemediationScope } from './control_runbook';
import { PlaybookProps } from '../lib/control_runbooks-construct';
import { HardCodedString } from '@cdklabs/cdk-ssm-documents';

export function createControlRunbook(scope: Construct, id: string, props: PlaybookProps): ControlRunbookDocument {
  return new SetCloudFrontOriginDomainDocument(scope, id, { ...props, controlId: 'CloudFront.12' });
}

export class SetCloudFrontOriginDomainDocument extends ControlRunbookDocument {
  constructor(stage: Construct, id: string, props: ControlRunbookProps) {
    super(stage, id, {
      ...props,
      securityControlId: 'CloudFront.12',
      remediationName: 'SetCloudFrontOriginDomain',
      scope: RemediationScope.GLOBAL,
      resourceIdName: 'DistributionId',
      resourceIdRegex: String.raw`^arn:(?:aws|aws-cn|aws-us-gov):cloudfront::[0-9]{12}:distribution\/([A-Z0-9]*)$`,
      updateDescription: HardCodedString.of('Set CloudFront origin domain to safe value.'),
    });
  }
}
