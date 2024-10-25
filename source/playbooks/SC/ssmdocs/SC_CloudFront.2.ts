// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { Construct } from 'constructs';
import { ControlRunbookDocument, ControlRunbookProps, RemediationScope } from './control_runbook';
import { PlaybookProps } from '../lib/control_runbooks-construct';
import { HardCodedString, StringVariable } from '@cdklabs/cdk-ssm-documents';

export function createControlRunbook(scope: Construct, id: string, props: PlaybookProps): ControlRunbookDocument {
  return new EnableCloudFrontOriginAccessIdentityDocument(scope, id, { ...props, controlId: 'CloudFront.2' });
}

export class EnableCloudFrontOriginAccessIdentityDocument extends ControlRunbookDocument {
  constructor(stage: Construct, id: string, props: ControlRunbookProps) {
    super(stage, id, {
      ...props,
      securityControlId: 'CloudFront.2',
      remediationName: 'EnableCloudFrontOriginAccessIdentity',
      scope: RemediationScope.REGIONAL,
      resourceIdName: 'CloudFrontDistributionId',
      resourceIdRegex: String.raw`^[A-Z0-9]+$`,
      updateDescription: HardCodedString.of('Enables origin access identity for the CloudFront distribution you specify in the CloudFrontDistributionId parameter, and verifies the origin access identity was assigned.'),
    });
  }

  /** @override */
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  protected getRemediationParams(): { [_: string]: any } {
    const params = super.getRemediationParams();

    params.CloudFrontDistributionId = StringVariable.of('ParseInput.CloudFrontDistributionId');
    params.OriginAccessIdentityId = StringVariable.of('ParseInput.OriginAccessIdentityId');
  
    return params;
  }
}