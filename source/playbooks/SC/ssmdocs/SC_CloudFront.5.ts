// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { Construct } from 'constructs';
import { ControlRunbookDocument, ControlRunbookProps, RemediationScope } from './control_runbook';
import { PlaybookProps } from '../lib/control_runbooks-construct';
import { HardCodedString, StringVariable } from '@cdklabs/cdk-ssm-documents';

export function createControlRunbook(scope: Construct, id: string, props: PlaybookProps): ControlRunbookDocument {
  return new EnableCloudFrontAccessLogsDocument(scope, id, { ...props, controlId: 'CloudFront.5' });
}

export class EnableCloudFrontAccessLogsDocument extends ControlRunbookDocument {
  constructor(stage: Construct, id: string, props: ControlRunbookProps) {
    super(stage, id, {
      ...props,
      securityControlId: 'CloudFront.5',
      remediationName: 'EnableCloudFrontAccessLogsDocument',
      scope: RemediationScope.REGIONAL,
      resourceIdName: 'BucketName',
      resourceIdRegex: String.raw`^arn:(?:aws|aws-cn|aws-us-gov):s3:::([A-Za-z0-9.-]{3,63})$`,
      updateDescription: HardCodedString.of('Enables access logging for the CloudFront distribution you specify in the CloudFrontDistributionId parameter.'),
    });
  }

  /** @override */
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  protected getRemediationParams(): { [_: string]: any } {
    const params = super.getRemediationParams();

    params.CloudFrontId = StringVariable.of('ParseInput.CloudFrontId');
    params.BucketName = StringVariable.of('ParseInput.BucketName');
    params.Prefix = StringVariable.of('ParseInput.Prefix'); // optional
    params.IncludeCookies = StringVariable.of('ParseInput.IncludeCookies');
  
    return params;
  }
}